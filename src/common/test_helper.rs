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

use crate::common::cbor_map::AsCborMap;
use core::fmt::Debug;
use core::convert::identity;
use ciborium::value::Value;
use coset::{Header, Label};
use coset::iana::Algorithm;
use crate::{CoseEncrypt0Cipher, CoseMac0Cipher, CoseSign1Cipher};
use crate::error::CoseCipherError;
use crate::token::CoseCipherCommon;

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
        T: AsCborMap + Clone + Debug + PartialEq
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

/// Used to implement a basic [`CipherProvider`] for tests (obviously not secure in any way).
#[derive(Copy, Clone)]
pub(crate) struct FakeCrypto {}

impl CoseCipherCommon for FakeCrypto {
    type Error = String;

    fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
        // We have to later verify these headers really are used.
        if let Some(label) = unprotected_header.rest.iter().find(|x| x.0 == Label::Int(47)) {
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

/// Implements basic operations from the [`CoseEncrypt0Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseEncrypt0Cipher for FakeCrypto {
    fn encrypt(&mut self, data: &[u8], aad: &[u8]) -> Vec<u8> {
        // We simply put AAD behind the data and call it a day.
        let mut result: Vec<u8> = vec![];
        result.append(&mut data.to_vec());
        result.append(&mut aad.to_vec());
        result
    }

    fn decrypt(&mut self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        // Now we just split off the AAD we previously put at the end of the data.
        // We return an error if it does not match.
        if data.len() < aad.len() {
            return Err(CoseCipherError::Other("Encrypted data must be at least as long as AAD!".to_string()));
        }
        let mut result: Vec<u8> = data.to_vec();
        let aad_result = result.split_off(data.len() - aad.len());
        if aad != aad_result {
            Err(CoseCipherError::Other("AADs don't match!".to_string()))
        } else {
            Ok(result)
        }
    }
}

/// Implements basic operations from the [`CoseSign1Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseSign1Cipher for FakeCrypto {
    fn generate_signature(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn verify_signature(&mut self, sig: &[u8], data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
        if sig != self.generate_signature(data) {
            Err(CoseCipherError::VerificationFailure)
        } else {
            Ok(())
        }
    }
}

/// Implements basic operations from the [`CoseMac0Cipher`] trait without actually using any
/// "real" cryptography.
/// This is purely to be used for testing and obviously offers no security at all.
impl CoseMac0Cipher for FakeCrypto {
    fn generate_tag(&mut self, target: &[u8]) -> Vec<u8> {
        target.to_vec()
    }

    fn verify_tag(&mut self, tag: &[u8], maced_data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
        if tag != self.generate_tag(maced_data) {
            Err(CoseCipherError::VerificationFailure)
        } else {
            Ok(())
        }
    }
}