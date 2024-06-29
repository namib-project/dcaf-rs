/*
 * Copyright (c) 2022-2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(feature = "openssl")]
use crate::error::CoseCipherError;
use crate::token::cose::encrypt::CoseEncryptCipher;
use crate::token::cose::header_util::find_param_by_label;
use crate::token::cose::key::{CoseEc2Key, CoseSymmetricKey, EllipticCurve};
use crate::token::cose::sign::CoseSignCipher;
use alloc::vec::Vec;
use ciborium::value::Value;
use core::ops::Deref;
use coset::iana::EnumI64;
use coset::{iana, Algorithm, CoseKey, Header, Label, ProtectedHeader};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use std::convert::Infallible;
use strum_macros::Display;

#[derive(Debug, Clone, Display)]
#[non_exhaustive]
pub enum CoseOpensslCipherError {
    OpensslError(ErrorStack),
    Other(&'static str),
}

impl From<ErrorStack> for CoseOpensslCipherError {
    fn from(value: ErrorStack) -> Self {
        CoseOpensslCipherError::OpensslError(value)
    }
}

impl<T: Into<CoseOpensslCipherError>> From<T> for CoseCipherError<CoseOpensslCipherError> {
    fn from(value: T) -> Self {
        CoseCipherError::Other(value.into())
    }
}

pub struct OpensslContext {}

impl CoseSignCipher for OpensslContext {
    type Error = CoseOpensslCipherError;

    fn sign_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = get_ecdsa_hash_function(alg)?;

        sign_ecdsa(&group, pad_size as i32, hash, key, target)
    }

    fn verify_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        signature: &[u8],
        target: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = get_ecdsa_hash_function(alg)?;

        verify_ecdsa(&group, pad_size, hash, key, signature, target)
    }
}

fn get_ecdsa_group_params(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
) -> Result<(usize, EcGroup), CoseCipherError<CoseOpensslCipherError>> {
    match &key.crv {
        EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
            // ECDSA using P-256 curve, coordinates are padded to 256 bits
            Ok((32, EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()))
        }
        EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
            // ECDSA using P-384 curve, coordinates are padded to 384 bits
            Ok((48, EcGroup::from_curve_name(Nid::SECP384R1).unwrap()))
        }
        EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
            // ECDSA using P-384 curve, coordinates are padded to 528 bits (521 bits rounded up
            // to the nearest full bytes).
            Ok((66, EcGroup::from_curve_name(Nid::SECP521R1).unwrap()))
        }
        v => return Err(CoseCipherError::UnsupportedCurve(v.clone())),
    }
}

fn get_ecdsa_hash_function(
    alg: Algorithm,
) -> Result<MessageDigest, CoseCipherError<CoseOpensslCipherError>> {
    match alg {
        Algorithm::Assigned(iana::Algorithm::ES256) => Ok(MessageDigest::sha256()),
        Algorithm::Assigned(iana::Algorithm::ES384) => Ok(MessageDigest::sha384()),
        Algorithm::Assigned(iana::Algorithm::ES512) => Ok(MessageDigest::sha512()),
        v => return Err(CoseCipherError::UnsupportedAlgorithm(v)),
    }
}

fn sign_ecdsa(
    group: &EcGroup,
    pad_size: i32,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    target: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let private_key = cose_ec2_to_ec_private_key(key, &group).map_err(CoseCipherError::from)?;

    let mut signer = Signer::new(
        hash,
        PKey::from_ec_key(private_key)
            .map_err(CoseOpensslCipherError::from)?
            .deref(),
    )
    .map_err(CoseOpensslCipherError::from)?;

    // generated signature is of DER format, need to convert it to COSE key format
    let der_signature = signer
        .sign_oneshot_to_vec(target)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;

    let ecdsa_sig = EcdsaSig::from_der(der_signature.as_slice())
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;

    // See RFC 8152, section 8.1
    let mut sig = ecdsa_sig
        .r()
        .to_vec_padded(pad_size)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    let mut s_vec = ecdsa_sig
        .s()
        .to_vec_padded(pad_size)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    sig.append(&mut s_vec);

    Ok(sig)
}

fn verify_ecdsa(
    group: &EcGroup,
    pad_size: usize,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    signature: &[u8],
    signed_data: &[u8],
) -> Result<(), CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, &group).map_err(CoseCipherError::from)?;
    let pkey = PKey::from_ec_key(public_key).map_err(CoseOpensslCipherError::from)?;

    let mut verifier = Verifier::new(hash, &pkey).map_err(CoseOpensslCipherError::from)?;

    // signature is in COSE format, need to convert to DER format.
    let r = BigNum::from_slice(&signature[..pad_size]).map_err(CoseOpensslCipherError::from)?;
    let s = BigNum::from_slice(&signature[pad_size..]).map_err(CoseOpensslCipherError::from)?;
    let signature =
        EcdsaSig::from_private_components(r, s).map_err(CoseOpensslCipherError::from)?;
    // Note: EcdsaSig has its own "verify" method, but it is deprecated since OpenSSL
    // 3.0, which is why it's not used here.
    let der_signature = signature.to_der().map_err(CoseOpensslCipherError::from)?;

    verifier
        .verify_oneshot(der_signature.as_slice(), signed_data)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)
        .and_then(|verification_successful| match verification_successful {
            true => Ok(()),
            false => Err(CoseCipherError::VerificationFailure),
        })
}

fn cose_ec2_to_ec_private_key(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    group: &EcGroup,
) -> Result<EcKey<Private>, CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, group)?;

    EcKey::<Private>::from_private_components(
        group,
        &BigNum::from_slice(
            // According to the contract of the trait, this should be ensured by the caller, so it's
            // fine to panic here.
            key.d
                .expect("key provided to backend has no private component"),
        )
        .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?
        .deref(),
        public_key.public_key(),
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}

fn cose_ec2_to_ec_public_key(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    group: &EcGroup,
) -> Result<EcKey<Public>, CoseCipherError<CoseOpensslCipherError>> {
    // TODO X and Y can be recomputed and are not strictly required if D is known
    //      (RFC 8152, Section 13.1.1)
    if key.x.is_none() || key.y.is_none() {
        return Err(CoseCipherError::UnsupportedKeyDerivation);
    }

    EcKey::<Public>::from_public_key_affine_coordinates(
        &group,
        &BigNum::from_slice(key.x.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?
            .deref(),
        &BigNum::from_slice(key.y.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?
            .deref(),
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}

const AES_GCM_TAG_LEN: usize = 16;

impl CoseEncryptCipher for OpensslContext {
    type Error = CoseOpensslCipherError;

    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>> {
        openssl::rand::rand_bytes(buf).map_err(CoseCipherError::from)
    }

    fn encrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = get_aes_gcm_cipher(&algorithm)?;
        let mut auth_tag = vec![0; AES_GCM_TAG_LEN];
        let mut ciphertext = encrypt_aead(cipher, key.k, Some(iv), aad, plaintext, &mut auth_tag)
            .map_err(CoseCipherError::from)?;

        ciphertext.append(&mut auth_tag);
        Ok(ciphertext)
    }

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = get_aes_gcm_cipher(&algorithm)?;

        let auth_tag = &ciphertext_with_tag[(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)..];
        let ciphertext = &ciphertext_with_tag[..(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)];

        decrypt_aead(cipher, key.k, Some(iv), aad, ciphertext, auth_tag)
            .map_err(CoseCipherError::from)
    }
}

fn get_aes_gcm_cipher(
    algorithm: &Algorithm,
) -> Result<Cipher, CoseCipherError<CoseOpensslCipherError>> {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::A128GCM) => Ok(Cipher::aes_128_gcm()),
        Algorithm::Assigned(iana::Algorithm::A192GCM) => Ok(Cipher::aes_192_gcm()),
        Algorithm::Assigned(iana::Algorithm::A256GCM) => Ok(Cipher::aes_256_gcm()),
        v => return Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
    }
}
