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

use ciborium::value::Value;
use coset::{CoseKey, CoseKeyBuilder, Header, Label, ProtectedHeader};
use coset::iana::Algorithm;
use rand::{CryptoRng, Error, RngCore};

#[cfg(not(feature = "std"))]
use {
    alloc::string::{String, ToString},
    alloc::vec,
    alloc::vec::Vec,
};

use crate::{CoseEncryptCipher, CoseMacCipher, CoseSignCipher};
use crate::common::cbor_map::ToCborMap;
use crate::error::{AccessTokenError, CoseCipherError, MultipleCoseError};
use crate::token::{MultipleEncryptCipher, MultipleSignCipher, ToCoseKey};

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
    fn set_headers_common(
        key: &FakeKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
    ) -> Result<(), CoseCipherError<String>> {
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
        if !protected_header.key_id.is_empty() {
            return Err(CoseCipherError::existing_header("key_id"));
        }
        unprotected_header.rest.push((Label::Int(47), Value::Null));
        protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::Direct));
        protected_header.key_id = key.kid.to_vec();
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct FakeKey {
    key: [u8; 5],
    kid: [u8; 2],
}

impl ToCoseKey for FakeKey {
    fn to_cose_key(&self) -> CoseKey {
        CoseKeyBuilder::new_symmetric_key(self.key.to_vec())
            .key_id(self.kid.to_vec())
            .build()
    }
}

impl TryFrom<Vec<u8>> for FakeKey {
    type Error = String;

    // Should be 5 bytes of key + 2 bytes of kid
    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        let kid_value = value.split_off(5);
        let key: [u8; 5] = value.try_into().map_err(|_| "Invalid input size")?;
        let kid: [u8; 2] = kid_value.try_into().map_err(|_| "Invalid input size")?;
        Ok(FakeKey { key, kid })
    }
}

impl From<FakeKey> for Vec<u8> {
    fn from(k: FakeKey) -> Self {
        let mut key = k.key.to_vec();
        key.append(&mut k.kid.to_vec());
        key
    }
}

/// Implements basic operations from the [`CoseEncryptCipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseEncryptCipher for FakeCrypto {
    type EncryptKey = FakeKey;
    type DecryptKey = Self::EncryptKey;
    type Error = String;

    fn encrypt(
        key: &Self::EncryptKey,
        plaintext: &[u8],
        aad: &[u8],
        protected_header: &Header,
        unprotected_header: &Header,
    ) -> Vec<u8> {
        // We put the key and the AAD before the data.
        // Again, this obviously isn't secure in any sane definition of the word.
        let mut result: Vec<u8> = key.key.to_vec();
        result.append(&mut aad.to_vec());
        result.append(&mut plaintext.to_vec());
        result
    }

    fn decrypt(
        key: &Self::DecryptKey,
        ciphertext: &[u8],
        aad: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        // Now we just split off the AAD and key we previously put at the end of the data.
        // We return an error if it does not match.
        if key.kid.to_vec() != protected_header.header.key_id {
            // Mismatching key
            return Err(CoseCipherError::DecryptionFailure);
        }
        if ciphertext.len() < (aad.len() + key.key.len()) {
            return Err(CoseCipherError::Other(
                "Encrypted data has invalid length!".to_string(),
            ));
        }
        let mut result: Vec<u8> = ciphertext.to_vec();
        let plaintext = result.split_off(aad.len() + key.key.len());
        let aad_result = result.split_off(key.key.len());
        if aad == aad_result && key.key == result.as_slice() {
            Ok(plaintext)
        } else {
            Err(CoseCipherError::DecryptionFailure)
        }
    }

    fn set_headers<RNG: RngCore + CryptoRng>(
        key: &Self::EncryptKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
        rng: RNG,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::set_headers_common(key, unprotected_header, protected_header)
    }
}

/// Implements basic operations from the [`CoseSign1Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseSignCipher for FakeCrypto {
    type SignKey = FakeKey;
    type VerifyKey = Self::SignKey;
    type Error = String;

    fn sign(
        key: &Self::SignKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8> {
        // We simply append the key behind the data.
        let mut signature = target.to_vec();
        signature.append(&mut key.key.to_vec());
        signature
    }

    fn verify(
        key: &Self::VerifyKey,
        signature: &[u8],
        signed_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
        unprotected_signature_header: Option<&Header>,
        protected_signature_header: Option<&ProtectedHeader>,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let matching_kid = if let Some(protected) = protected_signature_header {
            protected.header.key_id == key.kid
        } else {
            protected_header.header.key_id == key.kid
        };
        let signed_again = Self::sign(key, signed_data, unprotected_header, &protected_header.header);
        if matching_kid && signed_again == signature
        {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }

    fn set_headers<RNG: RngCore + CryptoRng>(
        key: &Self::SignKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
        rng: RNG,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::set_headers_common(&key, unprotected_header, protected_header)
    }
}

/// Implements basic operations from the [`CoseMac0Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseMacCipher for FakeCrypto {
    type ComputeKey = FakeKey;
    type VerifyKey = Self::ComputeKey;
    type Error = String;

    fn compute(
        key: &Self::ComputeKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8> {
        // We simply append the key behind the data.
        let mut tag = target.to_vec();
        tag.append(&mut key.key.to_vec());
        tag
    }

    fn verify(
        key: &Self::VerifyKey,
        tag: &[u8],
        maced_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        if protected_header.header.key_id == key.kid
            && tag
            == Self::compute(
            key,
            maced_data,
            unprotected_header,
            &protected_header.header,
        )
        {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }

    fn set_headers<RNG: RngCore + CryptoRng>(
        key: &Self::ComputeKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
        rng: RNG,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::set_headers_common(&key, unprotected_header, protected_header)
    }
}

impl MultipleEncryptCipher for FakeCrypto {
    fn generate_cek<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self::EncryptKey {
        let mut key = [0; 5];
        let mut kid = [0; 2];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut kid);
        FakeKey { key, kid }
    }
}

impl MultipleSignCipher for FakeCrypto {}

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
        Ok(dest.fill(0))
    }
}

impl CryptoRng for FakeRng {}

// Makes the tests easier later on, as we use String as the error type in there.
impl<C, K> From<CoseCipherError<MultipleCoseError<C, K>>> for CoseCipherError<String> where C: Display, K: Display {
    fn from(x: CoseCipherError<MultipleCoseError<C, K>>) -> Self {
        match x {
            CoseCipherError::HeaderAlreadySet { existing_header_name } => CoseCipherError::HeaderAlreadySet { existing_header_name },
            CoseCipherError::VerificationFailure => CoseCipherError::VerificationFailure,
            CoseCipherError::DecryptionFailure => CoseCipherError::DecryptionFailure,
            CoseCipherError::Other(x) => CoseCipherError::Other(x.to_string())
        }
    }
}

impl<C, K> From<AccessTokenError<MultipleCoseError<C, K>>> for AccessTokenError<String> where C: Display, K: Display {
    fn from(x: AccessTokenError<MultipleCoseError<C, K>>) -> Self {
        match x {
            AccessTokenError::CoseError(x) => AccessTokenError::CoseError(x),
            AccessTokenError::CoseCipherError(x) => AccessTokenError::CoseCipherError(CoseCipherError::from(x)),
            AccessTokenError::UnknownCoseStructure => AccessTokenError::UnknownCoseStructure,
            AccessTokenError::NoMatchingKey => AccessTokenError::NoMatchingKey,
            AccessTokenError::MultipleMatchingKeys => AccessTokenError::MultipleMatchingKeys
        }
    }
}