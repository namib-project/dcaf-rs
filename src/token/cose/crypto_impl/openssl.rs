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
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher};
use crate::token::cose::header_util::HeaderParam;
use crate::token::cose::key::{CoseEc2Key, CoseSymmetricKey, EllipticCurve};
use crate::token::cose::mac::CoseMacCipher;
use crate::token::cose::sign::CoseSignCipher;
use crate::token::cose::CoseCipher;
use alloc::vec::Vec;
use ciborium::value::Value;
use coset::{iana, Algorithm};
use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use strum_macros::Display;

#[derive(Debug, Display)]
#[non_exhaustive]
pub enum CoseOpensslCipherError {
    OpensslError(ErrorStack),
    AesKeyError(openssl::aes::KeyError),
    Other(&'static str),
}

impl From<ErrorStack> for CoseOpensslCipherError {
    fn from(value: ErrorStack) -> Self {
        CoseOpensslCipherError::OpensslError(value)
    }
}

impl From<openssl::aes::KeyError> for CoseOpensslCipherError {
    fn from(value: openssl::aes::KeyError) -> Self {
        CoseOpensslCipherError::AesKeyError(value)
    }
}

impl<T: Into<CoseOpensslCipherError>> From<T> for CoseCipherError<CoseOpensslCipherError> {
    fn from(value: T) -> Self {
        CoseCipherError::Other(value.into())
    }
}

pub struct OpensslContext {}

impl CoseCipher for OpensslContext {
    type Error = CoseOpensslCipherError;

    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>> {
        openssl::rand::rand_bytes(buf).map_err(CoseCipherError::from)
    }
}

impl CoseSignCipher for OpensslContext {
    fn sign_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = get_algorithm_hash_function(&alg)?;

        // Possible truncation is fine, the key size will never exceed the size of an i32.
        #[allow(clippy::cast_possible_truncation)]
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
        let hash = get_algorithm_hash_function(&alg)?;

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
        v => Err(CoseCipherError::UnsupportedCurve(v.clone())),
    }
}

fn get_algorithm_hash_function(
    alg: &Algorithm,
) -> Result<MessageDigest, CoseCipherError<CoseOpensslCipherError>> {
    match alg {
        Algorithm::Assigned(iana::Algorithm::ES256) => Ok(MessageDigest::sha256()),
        Algorithm::Assigned(iana::Algorithm::ES384) => Ok(MessageDigest::sha384()),
        Algorithm::Assigned(iana::Algorithm::ES512) => Ok(MessageDigest::sha512()),
        Algorithm::Assigned(iana::Algorithm::HMAC_256_64) => Ok(MessageDigest::sha256()),
        Algorithm::Assigned(iana::Algorithm::HMAC_256_256) => Ok(MessageDigest::sha256()),
        Algorithm::Assigned(iana::Algorithm::HMAC_384_384) => Ok(MessageDigest::sha384()),
        Algorithm::Assigned(iana::Algorithm::HMAC_512_512) => Ok(MessageDigest::sha512()),
        v => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
    }
}

fn sign_ecdsa(
    group: &EcGroup,
    pad_size: i32,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    target: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let private_key = cose_ec2_to_ec_private_key(key, group).map_err(CoseCipherError::from)?;

    let mut signer = Signer::new(
        hash,
        &*PKey::from_ec_key(private_key).map_err(CoseOpensslCipherError::from)?,
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
    let public_key = cose_ec2_to_ec_public_key(key, group).map_err(CoseCipherError::from)?;
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
        &*BigNum::from_slice(
            // According to the contract of the trait, this should be ensured by the caller, so it's
            // fine to panic here.
            key.d
                .expect("key provided to backend has no private component"),
        )
        .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
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
        group,
        &*BigNum::from_slice(key.x.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
        &*BigNum::from_slice(key.y.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}

const AES_GCM_TAG_LEN: usize = 16;

impl CoseEncryptCipher for OpensslContext {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = algorithm_to_cipher(&algorithm)?;
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
        let cipher = algorithm_to_cipher(&algorithm)?;

        let auth_tag = &ciphertext_with_tag[(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)..];
        let ciphertext = &ciphertext_with_tag[..(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)];

        decrypt_aead(cipher, key.k, Some(iv), aad, ciphertext, auth_tag)
            .map_err(|_e| CoseCipherError::DecryptionFailure)
    }
}

fn algorithm_to_cipher(
    algorithm: &Algorithm,
) -> Result<Cipher, CoseCipherError<CoseOpensslCipherError>> {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::A128GCM) => Ok(Cipher::aes_128_gcm()),
        Algorithm::Assigned(iana::Algorithm::A192GCM) => Ok(Cipher::aes_192_gcm()),
        Algorithm::Assigned(iana::Algorithm::A256GCM) => Ok(Cipher::aes_256_gcm()),
        Algorithm::Assigned(iana::Algorithm::A128KW) => Ok(Cipher::aes_128_ecb()),
        Algorithm::Assigned(iana::Algorithm::A192KW) => Ok(Cipher::aes_192_ecb()),
        Algorithm::Assigned(iana::Algorithm::A256KW) => Ok(Cipher::aes_256_ecb()),
        v => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
    }
}

impl CoseKeyDistributionCipher for OpensslContext {
    fn aes_key_wrap(
        &mut self,
        _algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let key = AesKey::new_encrypt(key.k)?;
        let iv: [u8; 8] = iv.try_into().map_err(|_e| {
            CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.to_vec()),
            )
        })?;
        let mut output = vec![0u8; plaintext.len() + 8];
        let output_len = wrap_key(&key, Some(iv), output.as_mut_slice(), plaintext)?;
        output.truncate(output_len);
        Ok(output)
    }

    fn aes_key_unwrap(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let key = AesKey::new_decrypt(key.k)?;
        let iv: [u8; 8] = iv.try_into().map_err(|e| {
            CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.to_vec()),
            )
        })?;
        let mut output = vec![0u8; ciphertext.len() - 8];
        let output_len = unwrap_key(&key, Some(iv), output.as_mut_slice(), ciphertext)?;
        output.truncate(output_len);
        Ok(output)
    }
}

fn compute_hmac(
    algorithm: Algorithm,
    key: CoseSymmetricKey<'_, CoseOpensslCipherError>,
    input: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let hash = get_algorithm_hash_function(&algorithm)?;
    let hmac_key = PKey::hmac(key.k)?;
    let mut signer = Signer::new(hash, &hmac_key)?;
    signer
        .sign_oneshot_to_vec(input)
        .map_err(CoseCipherError::from)
}

impl CoseMacCipher for OpensslContext {
    fn compute_hmac(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        data: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        compute_hmac(algorithm, key, data)
    }

    fn verify_hmac(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let hmac = compute_hmac(algorithm, key, data)?;
        // Use openssl::memcmp::eq to prevent timing attacks.
        match openssl::memcmp::eq(hmac.as_slice(), tag) {
            true => Ok(()),
            false => Err(CoseCipherError::VerificationFailure),
        }
    }
}
