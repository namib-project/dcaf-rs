/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use ciborium::value::Value;
use coset::cwt::{ClaimsSetBuilder, Timestamp};
use coset::iana::EllipticCurve::P_256;
use coset::iana::{Algorithm, CwtClaimName};
use coset::{iana, CoseKey, CoseKeyBuilder, Header, HeaderBuilder, Label, ProtectedHeader};
use rand::{CryptoRng, Error, RngCore};

use dcaf::common::cbor_map::ToCborMap;
use dcaf::common::cbor_values::ProofOfPossessionKey::PlainCoseKey;
use dcaf::common::scope::TextEncodedScope;
use dcaf::endpoints::creation_hint::AuthServerRequestCreationHint;
use dcaf::endpoints::token_req::{
    AccessTokenRequest, AccessTokenResponse, AceProfile, ErrorCode, ErrorResponse, GrantType,
    TokenType,
};
use dcaf::error::CoseCipherError;
use dcaf::token::CoseCipher;
use dcaf::{sign_access_token, verify_access_token, CoseSignCipher};

fn get_x_y_from_key(key: &CoseKey) -> (Vec<u8>, Vec<u8>) {
    const X_PARAM: i64 = iana::Ec2KeyParameter::X as i64;
    const Y_PARAM: i64 = iana::Ec2KeyParameter::Y as i64;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (label, value) in key.params.iter() {
        if let Label::Int(X_PARAM) = label {
            if let Value::Bytes(x_val) = value {
                x = Some(x_val.clone());
            }
        } else if let Label::Int(Y_PARAM) = label {
            if let Value::Bytes(y_val) = value {
                y = Some(y_val.clone());
            }
        }
    }
    let test = x.and_then(|a| y.map(|b| (a, b)));
    test.expect("X and Y value must be present in key!")
}

#[derive(Clone, Copy)]
pub(crate) struct FakeRng;

impl RngCore for FakeRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        dest.fill(0);
        Ok(())
    }
}

impl CryptoRng for FakeRng {}

fn example_headers() -> (Header, Header) {
    let unprotected_header = HeaderBuilder::new()
        .iv(vec![
            0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC, 0x7B, 0xFC, 0xF6, 0xD3, 0xF9, 0x5B,
        ])
        .build();
    let protected_header = HeaderBuilder::new().build();
    (unprotected_header, protected_header)
}

fn example_aad() -> Vec<u8> {
    vec![0x10, 0x12, 0x13, 0x14, 0x15]
}

#[derive(Copy, Clone)]
pub(crate) struct FakeCrypto {}

impl CoseCipher for FakeCrypto {
    type Error = String;

    fn set_headers<RNG: RngCore + CryptoRng>(
        _key: &CoseKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
        _rng: RNG,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        // We have to later verify these headers really are used.
        if let Some(label) = unprotected_header
            .rest
            .iter()
            .find(|x| x.0 == Label::Int(47))
        {
            return Err(CoseCipherError::existing_header_label(&label.0));
        }
        if protected_header.alg != None {
            return Err(CoseCipherError::existing_header("alg"));
        }
        unprotected_header.rest.push((Label::Int(47), Value::Null));
        protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::Direct));
        Ok(())
    }
}

/// Implements basic operations from the [`CoseSign1Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseSignCipher for FakeCrypto {
    fn sign(
        key: &CoseKey,
        target: &[u8],
        _unprotected_header: &Header,
        _protected_header: &Header,
    ) -> Vec<u8> {
        // We simply append the key behind the data.
        let mut signature = target.to_vec();
        let (mut x, mut y) = get_x_y_from_key(key);
        signature.append(&mut x);
        signature.append(&mut y);
        signature
    }

    fn verify(
        key: &CoseKey,
        signature: &[u8],
        signed_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
        _unprotected_signature_header: Option<&Header>,
        _protected_signature_header: Option<&ProtectedHeader>,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        if signature
            == Self::sign(
                key,
                signed_data,
                unprotected_header,
                &protected_header.header,
            )
        {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }
}

/// We assume the following scenario here:
/// 1. The client tries to access a protected resource. Since it's still unauthorized,
///    this is an Unauthorized Resource Request message. The RS replies with an error response
///    which contains proper creation hints, which we will create, "send" (i.e. serialize) and
///    "receive" (deserialize) here.
/// 2. The client then sends an AccessTokenRequest to the AS based on the creation hints.
///    It also requests that the AS reply with the `ace_profile` attached.
/// 3. The AS replies with an AccessTokenResponse, containing the signed token_req as well as all
///    other necessary fields.
/// 4. Finally, the client tries to send an invalid request, which is met by an ErrorResponse.
#[test]
fn test_scenario() -> Result<(), String> {
    let nonce = vec![0xDC, 0xAF];
    let auth_server = "as.example.org";
    let resource_server = "rs.example.org";
    let client_id = "test client";
    let scope = TextEncodedScope::try_from("first second").map_err(|x| x.to_string())?;
    assert!(scope.elements().eq(["first", "second"]));
    // Taken from RFC 8747, section 3.2.
    let key = CoseKeyBuilder::new_ec2_pub_key(
        P_256,
        hex::decode("d7cc072de2205bdc1537a543d53c60a6acb62eccd890c7fa27c9e354089bbe13")
            .map_err(|x| x.to_string())?,
        hex::decode("f95e1d4b851a2cc80fff87d8e23f22afb725d535e515d020731e79a3b4e47120")
            .map_err(|x| x.to_string())?,
    )
    .build();

    let (unprotected_headers, protected_headers) = example_headers();
    let aad = example_aad();

    let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder()
        .auth_server(auth_server)
        .scope(scope.clone())
        .build()
        .map_err(|x| x.to_string())?;
    let result = pseudo_send_receive(hint.clone())?;
    assert_eq!(hint, result);

    // TODO: cnf & Access Token
    let request = AccessTokenRequest::builder()
        .grant_type(GrantType::ClientCredentials)
        .scope(scope.clone())
        .audience(resource_server)
        .client_nonce(nonce)
        .ace_profile()
        .client_id(client_id)
        .req_cnf(PlainCoseKey(key.clone()))
        .build()
        .map_err(|x| x.to_string())?;
    let result = pseudo_send_receive(request.clone())?;

    assert_eq!(request, result);
    let expires_in: u32 = 3600;
    let rng = FakeRng;
    let token = sign_access_token::<FakeCrypto, FakeRng>(
        &key,
        ClaimsSetBuilder::new()
            .audience(resource_server.to_string())
            .issuer(auth_server.to_string())
            .issued_at(Timestamp::WholeSeconds(47))
            .claim(
                CwtClaimName::Cnf,
                PlainCoseKey(key.clone()).to_ciborium_value(),
            )
            .build(),
        // TODO: Proper headers
        Some(aad.as_slice()),
        Some(unprotected_headers),
        Some(protected_headers),
        rng,
    )
    .map_err(|x| x.to_string())?;
    let response = AccessTokenResponse::builder()
        .access_token(token)
        .ace_profile(AceProfile::CoapDtls)
        .expires_in(expires_in)
        .scope(scope)
        .token_type(TokenType::ProofOfPossession)
        .build()
        .map_err(|x| x.to_string())?;
    let result = pseudo_send_receive(response.clone())?;
    assert_eq!(response, result);

    verify_access_token::<FakeCrypto>(&key, &response.access_token, Some(aad.as_slice()))
        .map_err(|x| x.to_string())?;

    let error = ErrorResponse::builder()
        .error(ErrorCode::InvalidRequest)
        .description("You sent an invalid request.")
        .uri("https://example.org/400")
        .build()
        .map_err(|x| x.to_string())?;
    let result = pseudo_send_receive(error.clone())?;
    assert_eq!(error, result);
    Ok(())
}

fn pseudo_send_receive<T>(input: T) -> Result<T, String>
where
    T: ToCborMap + PartialEq + Clone,
{
    let mut serialized: Vec<u8> = Vec::new();
    input
        .serialize_into(&mut serialized)
        .map_err(|x| x.to_string())?;
    T::deserialize_from(serialized.as_slice()).map_err(|x| x.to_string())
}
