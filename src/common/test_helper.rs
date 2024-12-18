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

//! Contains a few helper functions intended purely for tests.
//! Not intended to be used outside of this crate.

use core::convert::identity;
use core::fmt::{Debug, Display};

use coset::{iana, CoseKey};
use rand::{CryptoRng, Rng};

use crate::common::cbor_map::ToCborMap;
use crate::error::CoseCipherError;
use crate::token::cose::EncryptCryptoBackend;
use crate::token::cose::SignCryptoBackend;
use crate::token::cose::{CoseEc2Key, CoseSymmetricKey};
use crate::token::cose::{CryptoBackend, KeyDistributionCryptoBackend};
use alloc::collections::BTreeMap;
use core::convert::Infallible;
use {
    alloc::string::{String, ToString},
    alloc::vec::Vec,
};

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

/// Parameters used for a [`MockCipher`] AEAD operation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MockCipherAeadParams {
    key: Vec<u8>,
    algorithm: iana::Algorithm,
    aad: Vec<u8>,
    iv: Vec<u8>,
}

impl MockCipherAeadParams {
    fn new_with_aes_params<E: Display + Debug>(
        algorithm: iana::Algorithm,
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

/// Parameters used for a [`MockCipher`] ECDSA operation.
#[derive(Clone, Debug, PartialEq)]
struct MockCipherEcdsaParams {
    key: CoseKey,
    algorithm: iana::Algorithm,
    target: Vec<u8>,
}

impl MockCipherEcdsaParams {
    fn new_with_ecdsa_params<E: Display + Debug>(
        alg: iana::Algorithm,
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

/// "Mocked" Implementation of a cryptographic backend that does not actually perform cryptographic
/// operations.
///
/// Instead, it stores the parameters passed to it during the creation of COSE objects and performs
/// a lookup of those parameters (alongside a random value returned during creation) when attempting
/// to authenticate or decrypt the object.
///
/// Due to the way this cryptographic backend works, created COSE objects can only be
/// "authenticated" by the `MockCipher` instance they were created with.
pub(crate) struct MockCipher<R: CryptoRng + Rng> {
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

impl<R: CryptoRng + Rng> CryptoBackend for MockCipher<R> {
    type Error = Infallible;

    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill_bytes(buf);
        Ok(())
    }
}

impl<R: CryptoRng + Rng> EncryptCryptoBackend for MockCipher<R> {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
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
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (expected_input, plaintext) = self
            .aes_gcm_inputs
            .get(ciphertext_with_tag)
            .ok_or(CoseCipherError::VerificationFailure)?;
        if expected_input.eq(&MockCipherAeadParams::new_with_aes_params(
            algorithm, &key, aad, iv,
        )) {
            return Ok(plaintext.clone());
        }
        Err(CoseCipherError::VerificationFailure)
    }
}

impl<R: CryptoRng + Rng> SignCryptoBackend for MockCipher<R> {
    fn sign_ecdsa(
        &mut self,
        alg: iana::Algorithm,
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
        alg: iana::Algorithm,
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

impl<R: Rng + CryptoRng> KeyDistributionCryptoBackend for MockCipher<R> {
    fn aes_key_wrap(
        &mut self,
        algorithm: iana::Algorithm,
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
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (expected_input, plaintext) = self
            .aes_kw_inputs
            .get(ciphertext)
            .ok_or(CoseCipherError::VerificationFailure)?;
        if expected_input.eq(&MockCipherAeadParams::new_with_aes_params(
            algorithm,
            &key,
            &[] as &[u8],
            iv,
        )) {
            return Ok(plaintext.clone());
        }
        Err(CoseCipherError::VerificationFailure)
    }
}
