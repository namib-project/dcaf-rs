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
use core::fmt::Debug;

use ciborium::value::Value;
use coset::{CoseKey, CoseKeyBuilder, Header, Label, ProtectedHeader};
use coset::iana::Algorithm;
use rand::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use {
    alloc::string::{String, ToString},
    alloc::vec,
    alloc::vec::Vec,
};

use crate::{CoseEncryptCipher, CoseMacCipher, CoseSignCipher};
use crate::common::cbor_map::ToCborMap;
use crate::error::CoseCipherError;
use crate::token::{MultipleEncryptCipher, MultipleSignCipher};

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

/// Used to implement a basic `CipherProvider` for tests (obviously not secure in any way).
#[derive(Copy, Clone)]
pub(crate) struct FakeCrypto {}

impl FakeCrypto {
    fn set_headers_common<RNG: RngCore + CryptoRng>(key: &[u8; 5], unprotected_header: &mut Header, protected_header: &mut Header, rng: RNG) -> Result<(), CoseCipherError<String>> {
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

struct Key([u8; 5]);

impl AsRef<CoseKey> for Key {
    fn as_ref(&self) -> &CoseKey {
        &CoseKeyBuilder::new_symmetric_key(self.0.to_vec()).build()
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let key: [u8; 5] = value.try_into().map_err(|_| "Invalid input size")?;
        Ok(Key(key))
    }
}

impl From<Key> for Vec<u8> {
    fn from(k: Key) -> Self {
        k.0.to_vec()
    }
}

/// Implements basic operations from the [`CoseEncryptCipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseEncryptCipher for FakeCrypto {
    type EncryptKey = Key;
    type DecryptKey = Self::EncryptKey;
    type Error = String;

    fn encrypt(key: &Self::EncryptKey, plaintext: &[u8], aad: &[u8], protected_header: &Header, unprotected_header: &Header) -> Vec<u8> {
        // We put the key before and the AAD behind the data.
        // Again, this obviously isn't secure in any sane definition of the word.
        let mut result: Vec<u8> = vec![];
        result.append(&mut key.0.to_vec());
        result.append(&mut plaintext.to_vec());
        result.append(&mut aad.to_vec());
        result
    }

    fn decrypt(key: &Self::DecryptKey, ciphertext: &[u8], aad: &[u8], unprotected_header: &Header, protected_header: &ProtectedHeader) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        // Now we just split off the AAD and key we previously put at the end of the data.
        // We return an error if it does not match.
        if ciphertext.len() < (aad.len() + key.0.len()) {
            return Err(CoseCipherError::Other(
                "Encrypted data has invalid length!".to_string(),
            ));
        }
        let mut result: Vec<u8> = ciphertext.to_vec();
        let aad_result = result.split_off(ciphertext.len() + key.0.len());
        let plaintext = result.split_off(key.0.len());
        if aad == aad_result && key.0 == result.as_slice() {
            Ok(plaintext)
        } else {
            Err(CoseCipherError::Other("AADs don't match!".to_string()))
        }
    }

    fn set_headers<RNG: RngCore + CryptoRng>(key: &Self::EncryptKey, unprotected_header: &mut Header, protected_header: &mut Header, rng: RNG) -> Result<(), CoseCipherError<Self::Error>> {
        Self::set_headers_common(&key.0, unprotected_header, protected_header, rng)
    }
}

/// Implements basic operations from the [`CoseSign1Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseSignCipher for FakeCrypto {
    type SignKey = Key;
    type VerifyKey = Self::SignKey;
    type Error = String;

    fn sign(key: &Self::SignKey, target: &[u8], unprotected_header: &Header, protected_header: &Header) -> Vec<u8> {
        // We simply append the key behind the data.
        let mut signature = target.to_vec();
        signature.append(&mut key.0.to_vec());
        signature
    }

    fn verify(key: &Self::VerifyKey, signature: &[u8], signed_data: &[u8], unprotected_header: &Header, protected_header: &ProtectedHeader, unprotected_signature_header: Option<&Header>, protected_signature_header: Option<&ProtectedHeader>) -> Result<(), CoseCipherError<Self::Error>> {
        if signature == Self::sign(key, signed_data, unprotected_header, &protected_header.header) {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }

    fn set_headers<RNG: RngCore + CryptoRng>(key: &Self::SignKey, unprotected_header: &mut Header, protected_header: &mut Header, rng: RNG) -> Result<(), CoseCipherError<Self::Error>> {
        Self::set_headers_common(&key.0, unprotected_header, protected_header, rng)
    }
}

/// Implements basic operations from the [`CoseMac0Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseMacCipher for FakeCrypto {
    type ComputeKey = Key;
    type VerifyKey = Self::ComputeKey;
    type Error = String;

    fn compute(key: &Self::ComputeKey, target: &[u8], unprotected_header: &Header, protected_header: &Header) -> Vec<u8> {
        // We simply append the key behind the data.
        let mut tag = target.to_vec();
        tag.append(&mut key.0.to_vec());
        tag
    }

    fn verify(key: &Self::VerifyKey, tag: &[u8], maced_data: &[u8], unprotected_header: &Header, protected_header: &ProtectedHeader) -> Result<(), CoseCipherError<Self::Error>> {
        if tag == Self::compute(key, maced_data, unprotected_header, &protected_header.header) {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }

    fn set_headers<RNG: RngCore + CryptoRng>(key: &Self::ComputeKey, unprotected_header: &mut Header, protected_header: &mut Header, rng: RNG) -> Result<(), CoseCipherError<Self::Error>> {
        Self::set_headers_common(&key.0, unprotected_header, protected_header, rng)
    }
}

impl MultipleEncryptCipher for FakeCrypto {
    fn generate_cek<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self::EncryptKey {
        let mut key = [0; 5];
        rng.fill_bytes(&mut key);
        Key(key)
    }
}

impl MultipleSignCipher for FakeCrypto {}