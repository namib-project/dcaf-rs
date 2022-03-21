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

//! Contains various helper values for CBOR structures.
//!
//! For example, this contains a struct representing a [`ByteString`] and an enum representing
//! a [`ProofOfPossessionKey`].
//!
//! # Example
//! One of the main use cases of both the [`ByteString`] and the [`ProofOfPossessionKey`]
//! is for representing an access token and a key in the `cnf` claim, respectively:
//! ```
//! # use dcaf::AccessTokenResponse;
//! # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
//! # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! let response: AccessTokenResponse = AccessTokenResponse::builder()
//!     .access_token(ByteString::from(vec![0xDC, 0xAF, 0xDC, 0xAF]))
//!     .cnf(ProofOfPossessionKey::KeyId(ByteString::from(vec![0x42]))).build()?;
//! # Ok::<(), AccessTokenResponseBuilderError>(())
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;

use coset::{CoseEncrypt0, CoseKey};
use serde::{Deserialize, Serialize};

/// Value of a [`ByteString`], represented as a vector of bytes.
pub(crate) type ByteStringValue = Vec<u8>;

/// A Key ID, represented as a [`ByteString`].
pub(crate) type KeyId = ByteString;

/// A string of bytes.
///
/// Can be treated like a regular [`Vec<u8>`] due to a corresponding [`Deref`] implementation.
///
/// # Example
/// To create a ByteString from a `Vec<u8>` and turn it back again:
/// ```
/// # use dcaf::common::cbor_values::ByteString;
/// let bs = ByteString::from(vec![0xDC, 0x00, 0xAF]);
/// assert_eq!(bs.to_vec(), vec![0xDC, 0x00, 0xAF]);
/// ```
/// ByteStrings are used in various places, but one of its main usages in `dcaf-rs` is that it
/// represents an encoded access token:
/// ```
/// # use dcaf::AccessTokenResponse;
/// # use dcaf::common::cbor_values::ByteString;
/// # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
/// // This is just an example, the token is obviously not well-formed.
/// let encoded_token = ByteString::from("example".as_bytes());
/// let response: AccessTokenResponse = AccessTokenResponse::builder()
///     .access_token(encoded_token).build()?;
/// # Ok::<(), AccessTokenResponseBuilderError>(())
/// ```
#[derive(Debug, Deserialize, PartialEq, Eq, Default, Hash, Clone)]
pub struct ByteString(pub(crate) ByteStringValue);

/// Wrapper around a type `T` which can be created from and turned into an [`i32`].
pub(crate) struct CborMapValue<T>(pub(crate) T)
    where
        i32: Into<T>,
        T: Into<i32> + Copy;


/// A type which can either be a [`String`] or a [`ByteString`].
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
enum TextOrByteString {
    // TODO: Unused for now. Do we really need this in the future?

    /// A text string, represented as a [`String`].
    TextString(String),

    /// A byte string, represented as a [`ByteString`].
    ByteString(ByteString),
}

/// A proof-of-possession key as specified by
/// [RFC 8747, section 3.1](https://datatracker.ietf.org/doc/html/rfc8747#section-3.1).
///
/// Can either be a COSE key, an encrypted COSE key, or simply a key ID.
/// As described in [`draft-ietf-ace-oauth-params-16`](https://datatracker.ietf.org/doc/html/draft-ietf-ace-oauth-params-16),
/// PoP keys are used for the `req_cnf` parameter in [`AccessTokenRequest`](crate::AccessTokenRequest),
/// as well as for the `cnf` and `rs_cnf` parameters in [`AccessTokenResponse`](crate::AccessTokenResponse).
///
/// # Example
/// We showcase creation of an [`AccessTokenRequest`](crate::AccessTokenRequest) in which we set `req_cnf` to a PoP key
/// with an ID of 0xDCAF which the access token shall be bound to:
/// ```
/// # use dcaf::AccessTokenRequest;
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::endpoints::token_req::AccessTokenRequestBuilderError;
/// let key = ProofOfPossessionKey::KeyId(ByteString::from(vec![0xDC, 0xAF]));
/// let request: AccessTokenRequest = AccessTokenRequest::builder().client_id("test_client").req_cnf(key).build()?;
/// assert_eq!(request.req_cnf.unwrap().key_id().to_vec(), vec![0xDC, 0xAF]);
/// # Ok::<(), AccessTokenRequestBuilderError>(())
/// ```
#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::large_enum_variant)]  // size difference of ~300 bytes is acceptable
pub enum ProofOfPossessionKey {
    PlainCoseKey(CoseKey),
    EncryptedCoseKey(CoseEncrypt0),
    KeyId(KeyId),
}

impl ProofOfPossessionKey {
    /// Returns the key ID of this PoP key, cloning it if necessary.
    /// Note that the returned key ID may be empty if no key ID was present in the key.
    ///
    /// # Example
    /// ```
    /// # use coset::CoseKeyBuilder;
    /// # use dcaf::common::cbor_values::ProofOfPossessionKey;
    /// let key = CoseKeyBuilder::new_symmetric_key(vec![0; 5]).key_id(vec![0xDC, 0xAF]).build();
    /// let pop_key = ProofOfPossessionKey::from(key);
    /// assert_eq!(pop_key.key_id().to_vec(), vec![0xDC, 0xAF]);
    /// ```
    pub fn key_id(&self) -> KeyId {
        match self {
            ProofOfPossessionKey::PlainCoseKey(k) => KeyId::from(k.key_id.clone()),
            ProofOfPossessionKey::KeyId(k) => k.clone(),
            ProofOfPossessionKey::EncryptedCoseKey(k) => {
                if !k.protected.header.key_id.is_empty() {
                    KeyId::from(k.protected.header.key_id.clone())
                } else {
                    KeyId::from(k.unprotected.key_id.clone())
                }
            }
        }
    }
}

impl Deref for ByteString {
    type Target = ByteStringValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Deref for CborMapValue<T>
    where
        T: From<i32> + Into<i32> + Copy,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for TextOrByteString {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            TextOrByteString::TextString(s) => write!(f, "{}", s),
            TextOrByteString::ByteString(s) => write!(f, "{}", s),
        }
    }
}

impl Display for ByteString {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{:02X?}", self.0)
    }
}

impl<T> Display for CborMapValue<T>
    where
        i32: Into<T>,
        T: Into<i32> + Copy + Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Contains various `From`, `TryFrom` and other conversion methods for types of the parent module.
mod conversion {
    use ciborium::value::Value;
    use coset::{AsCborValue, CoseEncrypt0, CoseKey};
    use erased_serde::Serialize as ErasedSerialize;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::de::Error;
    use crate::common::cbor_map::AsCborMap;

    use crate::error::{TryFromCborMapError, WrongSourceTypeError};

    use super::*;

    impl<T> Serialize for CborMapValue<T>
        where
            T: From<i32> + Into<i32> + Copy,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
        {
            let cbor_value: i32 = self.0.into();
            Value::from(cbor_value).serialize(serializer)
        }
    }

    impl<'de, T> Deserialize<'de> for CborMapValue<T>
        where
            T: From<i32> + Into<i32> + Copy,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
        {
            if let Ok(Value::Integer(i)) = Value::deserialize(deserializer) {
                Ok(CborMapValue(
                    i32::try_from(i)
                        .map_err(|_| D::Error::custom("CBOR map key too high for i32"))?
                        .into(),
                ))
            } else {
                Err(D::Error::custom("CBOR map value must be an Integer"))
            }
        }
    }

    impl Serialize for ByteString {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
        {
            Value::serialize(&self.into(), serializer)
        }
    }

    impl<T> From<T> for ByteString where T: Into<ByteStringValue> {
        fn from(x: T) -> Self {
            ByteString(x.into())
        }
    }

    impl From<String> for TextOrByteString {
        fn from(s: String) -> Self {
            TextOrByteString::TextString(s)
        }
    }

    impl From<ByteStringValue> for TextOrByteString {
        fn from(s: ByteStringValue) -> Self {
            TextOrByteString::ByteString(ByteString(s))
        }
    }

    impl AsCborMap for ProofOfPossessionKey {
        fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            // The fact that we have to clone this is a little unfortunate.
            match self {
                Self::PlainCoseKey(key) => {
                    let x: i128 = 1;
                    vec![(
                        x,
                        Some(Box::new(key.clone().to_cbor_value().expect("Invalid key"))),
                    )]
                }
                Self::EncryptedCoseKey(enc) => {
                    let x: i128 = 2;
                    vec![(
                        x,
                        Some(Box::new(
                            (*enc).clone().to_cbor_value().expect("Invalid key"),
                        )),
                    )]
                }
                Self::KeyId(kid) => {
                    let x: i128 = 3;
                    vec![(x, Some(Box::new(kid)))]
                }
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
            where
                Self: Sized + AsCborMap,
        {
            if map.len() != 1 {
                Err(TryFromCborMapError::from_message(
                    "given CBOR map must contain exactly one element",
                ))
            } else if let Some(entry) = map.into_iter().next() {
                match entry {
                    (1, x) => CoseKey::from_cbor_value(x)
                        .map(ProofOfPossessionKey::PlainCoseKey)
                        .map_err(|x| {
                            TryFromCborMapError::from_message(format!(
                                "couldn't create CoseKey from CBOR value: {x}"
                            ))
                        }),
                    (2, x) => CoseEncrypt0::from_cbor_value(x)
                        .map(ProofOfPossessionKey::EncryptedCoseKey)
                        .map_err(|x| {
                            TryFromCborMapError::from_message(format!(
                                "couldn't create CoseEncrypt0 from CBOR value: {x}"
                            ))
                        }),
                    (3, Value::Bytes(x)) => Ok(ProofOfPossessionKey::KeyId(ByteString::from(x))),
                    (x, _) => Err(TryFromCborMapError::unknown_field(x as u8)),
                }
            } else {
                unreachable!("we have previously verified that map.len() == 1, so map.into_iter().next() must return a next element")
            }
        }
    }

    impl From<CoseKey> for ProofOfPossessionKey {
        fn from(key: CoseKey) -> Self {
            ProofOfPossessionKey::PlainCoseKey(key)
        }
    }

    impl From<ByteString> for ProofOfPossessionKey {
        fn from(kid: ByteString) -> Self {
            ProofOfPossessionKey::KeyId(kid)
        }
    }

    impl From<CoseEncrypt0> for ProofOfPossessionKey {
        fn from(enc: CoseEncrypt0) -> Self {
            ProofOfPossessionKey::EncryptedCoseKey(enc)
        }
    }

    impl From<&ByteString> for Value {
        fn from(bytestring: &ByteString) -> Self {
            Value::Bytes(bytestring.to_vec())
        }
    }

    impl TryFrom<TextOrByteString> for String {
        type Error = WrongSourceTypeError<TextOrByteString>;

        fn try_from(value: TextOrByteString) -> Result<Self, Self::Error> {
            if let TextOrByteString::TextString(s) = value {
                Ok(s)
            } else {
                Err(WrongSourceTypeError::new("TextString"))
            }
        }
    }

    impl TryFrom<TextOrByteString> for ByteString {
        type Error = WrongSourceTypeError<TextOrByteString>;

        fn try_from(value: TextOrByteString) -> Result<Self, Self::Error> {
            if let TextOrByteString::ByteString(s) = value {
                Ok(s)
            } else {
                Err(WrongSourceTypeError::new("ByteString"))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for CoseKey {
        type Error = WrongSourceTypeError<ProofOfPossessionKey>;

        fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
            if let ProofOfPossessionKey::PlainCoseKey(key) = value {
                Ok(key)
            } else {
                Err(WrongSourceTypeError::new("PlainCoseKey"))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for CoseEncrypt0 {
        type Error = WrongSourceTypeError<ProofOfPossessionKey>;

        fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
            if let ProofOfPossessionKey::EncryptedCoseKey(key) = value {
                Ok(key)
            } else {
                Err(WrongSourceTypeError::new(
                    "EncryptedCoseKey",
                ))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for KeyId {
        type Error = WrongSourceTypeError<ProofOfPossessionKey>;

        fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
            if let ProofOfPossessionKey::KeyId(kid) = value {
                Ok(kid)
            } else {
                Err(WrongSourceTypeError::new("KeyId"))
            }
        }
    }
}