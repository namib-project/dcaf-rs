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
use base64::Engine;
use ciborium::value::Value;
use coset::cwt::{ClaimsSetBuilder, Timestamp};
use coset::iana::CwtClaimName;
use coset::iana::EllipticCurve::P_256;
use coset::{iana, CoseKey, CoseKeyBuilder, Header, HeaderBuilder, Label};
use dcaf::common::cbor_map::ToCborMap;
use dcaf::token::cose::CoseCipher;
use dcaf::ProofOfPossessionKey::PlainCoseKey;
use dcaf::{
    sign_access_token, verify_access_token, AccessTokenRequest, AccessTokenResponse, AceProfile,
    AuthServerRequestCreationHint, CoseSignCipher, ErrorCode, ErrorResponse, GrantType,
    TextEncodedScope, TokenType,
};
use rand::{CryptoRng, Error, RngCore};
use rstest::rstest;

#[cfg(feature = "openssl")]
use dcaf::token::cose::crypto_impl::openssl::OpensslContext;

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
#[cfg(feature = "openssl")]
#[rstest]
fn test_scenario<B: CoseCipher + CoseSignCipher>(
    #[values(OpensslContext::new())] mut backend: B,
) -> Result<(), String> {
    let nonce = vec![0xDC, 0xAF];
    let auth_server = "as.example.org";
    let resource_server = "rs.example.org";
    let client_id = "test client";
    let scope = TextEncodedScope::try_from("first second").map_err(|x| x.to_string())?;
    assert!(scope.elements().eq(["first", "second"]));
    // Key taken from the COSE examples repository
    // (https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-01.json)
    let key = CoseKeyBuilder::new_ec2_priv_key(
        P_256,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
            .map_err(|x| x.to_string())?,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
            .map_err(|x| x.to_string())?,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
            .map_err(|x| x.to_string())?,
    )
    .algorithm(iana::Algorithm::ES256)
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
    let token = sign_access_token::<B>(
        &mut backend,
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

    verify_access_token::<B, _>(
        &mut backend,
        &mut &key,
        false,
        &response.access_token,
        Some(aad.as_slice()),
    )
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
