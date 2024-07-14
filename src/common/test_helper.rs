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

//! Contains a few helper functions intended purely for tests.
//! Not intended to be used outside of this crate.

use core::convert::identity;
use core::fmt::{Debug, Display};

use coset::CoseKey;
use rand::{CryptoRng, Rng};

use crate::common::cbor_map::ToCborMap;
use crate::error::{AccessTokenError, CoseCipherError, MultipleCoseError};
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher};
use crate::token::cose::key::{CoseEc2Key, CoseSymmetricKey};
use crate::token::cose::CoseCipher;
use crate::CoseSignCipher;
use alloc::collections::BTreeMap;
use core::convert::Infallible;
use {
    alloc::string::{String, ToString},
    alloc::vec::Vec,
};
//use crate::token::MultipleEncryptCipher;
//use crate::{CoseEncryptCipher, CoseMacCipher, CoseSignCipher};

/// Helper function for tests which ensures that [`value`] serializes to the hexadecimal bytestring
/// [expected_hex] and deserializes back to [`value`].
///
/// If [`transform_value`] is given, it will be applied to the deserialized value before comparing it
/// to [`value`]. `assert` statements are used to validate post-conditions.
///
/// ## Post-conditions
/// If no error occurred:
/// - The serialized [`value`] is equal to the bytestring given in [`expected_hex`].
/// - The deserialized value is equal to [`value`], with [`transform_value`] applied to it.
///   If [`transform_value`] is `None`, it will be equal to the identity function.
///
/// # Errors
/// This will return an error message if any of the following is true:
/// - Serialization of [`value`] failed.
/// - Deserializing of the serialized [`value`] failed.
/// - Deserializing of the serialized [`value`] does not result in a CBOR map.
/// - Given [`expected_hex`] is not valid hexadecimal.
///
/// # Panics
/// If any of the post-conditions (verified as assertions) fail.
pub(crate) fn expect_ser_de<T>(
    value: T,
    transform_value: Option<fn(T) -> T>,
    expected_hex: &str,
) -> Result<(), String>
where
    T: ToCborMap + Clone + Debug + PartialEq,
{
    let copy = value.clone();
    let mut result = Vec::new();
    value
        .serialize_into(&mut result)
        .map_err(|x| x.to_string())?;
    #[cfg(feature = "std")]
    println!("Result: {:?}, Original: {:?}", hex::encode(&result), &copy);
    assert_eq!(
        &result,
        &hex::decode(expected_hex).map_err(|x| x.to_string())?
    );
    let decoded = T::deserialize_from(result.as_slice()).map_err(|x| x.to_string());
    if let Ok(decoded_value) = decoded {
        let decoded_value = transform_value.unwrap_or(identity)(decoded_value);
        assert_eq!(copy, decoded_value);
        Ok(())
    } else if let Err(e) = decoded {
        Err(e)
    } else {
        Err("Invalid value: Not a CBOR map!".to_string())
    }
}

// Makes the tests easier later on, as we use String as the error type in there.
impl<C, K> From<CoseCipherError<MultipleCoseError<C, K>>> for CoseCipherError<String>
where
    C: Display,
    K: Display,
{
    fn from(x: CoseCipherError<MultipleCoseError<C, K>>) -> Self {
        match x {
            CoseCipherError::HeaderAlreadySet {
                existing_header_name,
            } => CoseCipherError::HeaderAlreadySet {
                existing_header_name,
            },
            CoseCipherError::VerificationFailure => CoseCipherError::VerificationFailure,
            CoseCipherError::DecryptionFailure => CoseCipherError::DecryptionFailure,
            CoseCipherError::Other(x) => CoseCipherError::Other(x.to_string()),
            CoseCipherError::UnsupportedKeyType(v) => CoseCipherError::UnsupportedKeyType(v),
            CoseCipherError::UnsupportedCurve(v) => CoseCipherError::UnsupportedCurve(v),
            CoseCipherError::UnsupportedAlgorithm(v) => CoseCipherError::UnsupportedAlgorithm(v),
            CoseCipherError::UnsupportedKeyDerivation => CoseCipherError::UnsupportedKeyDerivation,
            CoseCipherError::NoAlgorithmDeterminable => CoseCipherError::NoAlgorithmDeterminable,
            CoseCipherError::KeyOperationNotPermitted(v, w) => {
                CoseCipherError::KeyOperationNotPermitted(v, w)
            }
            CoseCipherError::KeyTypeCurveMismatch(v, w) => {
                CoseCipherError::KeyTypeCurveMismatch(v, w)
            }
            CoseCipherError::KeyTypeAlgorithmMismatch(v, w) => {
                CoseCipherError::KeyTypeAlgorithmMismatch(v, w)
            }
            CoseCipherError::KeyAlgorithmMismatch(v, w) => {
                CoseCipherError::KeyAlgorithmMismatch(v, w)
            }
            CoseCipherError::DuplicateHeaders(v) => CoseCipherError::DuplicateHeaders(v),
            CoseCipherError::InvalidKeyId(v) => CoseCipherError::InvalidKeyId(v),
            CoseCipherError::MissingKeyParam(v) => CoseCipherError::MissingKeyParam(v),
            CoseCipherError::InvalidKeyParam(v, w) => CoseCipherError::InvalidKeyParam(v, w),
            CoseCipherError::TypeMismatch(v) => CoseCipherError::TypeMismatch(v),
            CoseCipherError::NoKeyFound => CoseCipherError::NoKeyFound,
            CoseCipherError::IvRequired => CoseCipherError::IvRequired,
            CoseCipherError::MissingHeaderParam(v) => CoseCipherError::MissingHeaderParam(v),
            CoseCipherError::InvalidHeaderParam(v, w) => CoseCipherError::InvalidHeaderParam(v, w),
            CoseCipherError::AadUnsupported => CoseCipherError::AadUnsupported,
        }
    }
}

impl<C, K> From<AccessTokenError<MultipleCoseError<C, K>>> for AccessTokenError<String>
where
    C: Display,
    K: Display,
{
    fn from(x: AccessTokenError<MultipleCoseError<C, K>>) -> Self {
        match x {
            AccessTokenError::CoseError(x) => AccessTokenError::CoseError(x),
            AccessTokenError::CoseCipherError(x) => {
                AccessTokenError::CoseCipherError(CoseCipherError::from(x))
            }
            AccessTokenError::UnknownCoseStructure => AccessTokenError::UnknownCoseStructure,
            AccessTokenError::NoMatchingRecipient => AccessTokenError::NoMatchingRecipient,
            AccessTokenError::MultipleMatchingRecipients => {
                AccessTokenError::MultipleMatchingRecipients
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MockCipherAeadParams {
    key: Vec<u8>,
    algorithm: coset::Algorithm,
    aad: Vec<u8>,
    iv: Vec<u8>,
}

impl MockCipherAeadParams {
    fn new_with_aes_params<E: Display + Debug>(
        algorithm: coset::Algorithm,
        key: &CoseSymmetricKey<'_, E>,
        aad: &[u8],
        iv: &[u8],
    ) -> MockCipherAeadParams {
        MockCipherAeadParams {
            key: key.k.to_vec(),
            algorithm,
            aad: aad.to_vec(),
            iv: iv.to_vec(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct MockCipherEcdsaParams {
    key: CoseKey,
    algorithm: coset::Algorithm,
    target: Vec<u8>,
}

impl MockCipherEcdsaParams {
    fn new_with_ecdsa_params<E: Display + Debug>(
        alg: coset::Algorithm,
        key: &CoseEc2Key<'_, E>,
        target: &[u8],
    ) -> MockCipherEcdsaParams {
        MockCipherEcdsaParams {
            key: key.as_ref().clone(),
            algorithm: alg,
            target: target.to_vec(),
        }
    }
}

pub struct MockCipher<R: CryptoRng + Rng> {
    rng: R,
    aes_gcm_inputs: BTreeMap<Vec<u8>, (MockCipherAeadParams, Vec<u8>)>,
    aes_kw_inputs: BTreeMap<Vec<u8>, (MockCipherAeadParams, Vec<u8>)>,
    ecdsa_inputs: BTreeMap<Vec<u8>, MockCipherEcdsaParams>,
}

impl<R: CryptoRng + Rng> MockCipher<R> {
    pub fn new(rng: R) -> MockCipher<R> {
        MockCipher {
            rng,
            aes_gcm_inputs: BTreeMap::default(),
            aes_kw_inputs: BTreeMap::default(),
            ecdsa_inputs: BTreeMap::default(),
        }
    }
}

impl<R: CryptoRng + Rng> CoseCipher for MockCipher<R> {
    type Error = Infallible;

    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>> {
        self.rng.fill_bytes(buf);
        Ok(())
    }
}

impl<R: CryptoRng + Rng> CoseEncryptCipher for MockCipher<R> {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: coset::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let mut lookup_key = vec![0u8; 64];
        self.rng.fill_bytes(lookup_key.as_mut_slice());
        self.aes_gcm_inputs.insert(
            lookup_key.clone(),
            (
                MockCipherAeadParams::new_with_aes_params(algorithm, &key, aad, iv),
                plaintext.to_vec(),
            ),
        );
        Ok(lookup_key)
    }

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: coset::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (expected_input, plaintext) = self
            .aes_gcm_inputs
            .get(ciphertext_with_tag)
            .ok_or(CoseCipherError::DecryptionFailure)?;
        if expected_input.eq(&MockCipherAeadParams::new_with_aes_params(
            algorithm, &key, aad, iv,
        )) {
            return Ok(plaintext.clone());
        }
        Err(CoseCipherError::DecryptionFailure)
    }
}

impl<R: CryptoRng + Rng> CoseSignCipher for MockCipher<R> {
    fn sign_ecdsa(
        &mut self,
        alg: coset::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let mut lookup_key = vec![0u8; 64];
        self.rng.fill_bytes(lookup_key.as_mut_slice());
        self.ecdsa_inputs.insert(
            lookup_key.clone(),
            MockCipherEcdsaParams::new_with_ecdsa_params(alg, key, target),
        );
        Ok(lookup_key)
    }

    fn verify_ecdsa(
        &mut self,
        alg: coset::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        signature: &[u8],
        target: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let expected_input = self
            .ecdsa_inputs
            .get(signature)
            .ok_or(CoseCipherError::VerificationFailure)?;
        if expected_input.eq(&MockCipherEcdsaParams::new_with_ecdsa_params(
            alg, key, target,
        )) {
            return Ok(());
        }
        Err(CoseCipherError::VerificationFailure)
    }
}

impl<R: Rng + CryptoRng> CoseKeyDistributionCipher for MockCipher<R> {
    fn aes_key_wrap(
        &mut self,
        algorithm: coset::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let mut lookup_key = vec![0u8; 64];
        self.rng.fill_bytes(lookup_key.as_mut_slice());
        self.aes_kw_inputs.insert(
            lookup_key.clone(),
            (
                MockCipherAeadParams::new_with_aes_params(algorithm, &key, &[] as &[u8], iv),
                plaintext.to_vec(),
            ),
        );
        Ok(lookup_key)
    }

    fn aes_key_unwrap(
        &mut self,
        algorithm: coset::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (expected_input, plaintext) = self
            .aes_kw_inputs
            .get(ciphertext)
            .ok_or(CoseCipherError::DecryptionFailure)?;
        if expected_input.eq(&MockCipherAeadParams::new_with_aes_params(
            algorithm,
            &key,
            &[] as &[u8],
            iv,
        )) {
            return Ok(plaintext.clone());
        }
        Err(CoseCipherError::DecryptionFailure)
    }
}
