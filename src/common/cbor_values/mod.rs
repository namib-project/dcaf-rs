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
//! For example, this contains an enum representing a [`ProofOfPossessionKey`].
//!
//! # Example
//! One of the main use cases of the [`ProofOfPossessionKey`]
//! is for representing a key in the `cnf` claim:
//! ```
//! # use dcaf::AccessTokenResponse;
//! # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
//! # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! let response: AccessTokenResponse = AccessTokenResponse::builder()
//!     .access_token(vec![0xDC, 0xAF, 0xDC, 0xAF])
//!     .cnf(ProofOfPossessionKey::KeyId(vec![0x42])).build()?;
//! # Ok::<(), AccessTokenResponseBuilderError>(())
//! ```

use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;

use coset::{CoseEncrypt0, CoseKey};
use strum_macros::IntoStaticStr;

use {alloc::boxed::Box, alloc::format, alloc::vec, alloc::vec::Vec};

#[cfg(test)]
mod tests;

/// A type intended to be used as a CBOR bytestring, represented as a vector of bytes.
pub type ByteString = Vec<u8>;

/// A Key ID, represented as a [`ByteString`].
pub(crate) type KeyId = ByteString;

/// Wrapper around a type `T` which can be created from and turned into an [`i32`].
pub(crate) struct CborMapValue<T>(pub(crate) T)
where
    i32: Into<T>,
    T: Into<i32> + Copy;

/// A proof-of-possession key as specified by
/// [RFC 8747, section 3.1](https://datatracker.ietf.org/doc/html/rfc8747#section-3.1).
///
/// Can either be a COSE key, an encrypted COSE key, or simply a key ID.
/// As described in [RFC 9201](https://www.rfc-editor.org/rfc/rfc9201),
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
/// let key = ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]);
/// let request: AccessTokenRequest = AccessTokenRequest::builder().client_id("test_client").req_cnf(key).build()?;
/// assert_eq!(request.req_cnf.unwrap().key_id().to_vec(), vec![0xDC, 0xAF]);
/// # Ok::<(), AccessTokenRequestBuilderError>(())
/// ```
#[derive(Debug, PartialEq, Clone, IntoStaticStr)]
#[allow(clippy::large_enum_variant)] // size difference of ~300 bytes is acceptable
pub enum ProofOfPossessionKey {
    /// An unencrypted [`CoseKey`](CoseKey) used to represent an asymmetric public key or
    /// (if the CWT it's contained in is encrypted) a symmetric key.
    ///
    /// For details, see [section 3.2 of RFC 8747](https://datatracker.ietf.org/doc/html/rfc8747#section-3.2).
    PlainCoseKey(CoseKey),

    /// An encrypted [`CoseKey`](CoseKey) used to represent a symmetric key.
    ///
    /// For details, see [section 3.3 of RFC 8747](https://datatracker.ietf.org/doc/html/rfc8747#section-3.3).
    EncryptedCoseKey(CoseEncrypt0),

    /// Key ID of the actual proof-of-possession key.
    ///
    /// Note that as described in [section 6 of RFC 8747](https://datatracker.ietf.org/doc/html/rfc8747#section-6),
    /// certain caveats apply when choosing to represent a proof-of-possession key by its Key ID.
    ///
    /// For details, see [section 3.4 of RFC 8747](https://datatracker.ietf.org/doc/html/rfc8747#section-3.4).
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
    #[must_use]
    pub fn key_id(&self) -> &KeyId {
        match self {
            ProofOfPossessionKey::PlainCoseKey(k) => &k.key_id,
            ProofOfPossessionKey::KeyId(k) => k,
            ProofOfPossessionKey::EncryptedCoseKey(k) => {
                if k.protected.header.key_id.is_empty() {
                    &k.unprotected.key_id
                } else {
                    &k.protected.header.key_id
                }
            }
        }
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
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::common::cbor_map::ToCborMap;
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
                        .map_err(|_| Error::custom("CBOR map key too high for i32"))?
                        .into(),
                ))
            } else {
                Err(Error::custom("CBOR map value must be an Integer"))
            }
        }
    }

    impl ToCborMap for ProofOfPossessionKey {
        fn to_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
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
                    vec![(x, Some(Box::new(Value::Bytes(kid.clone()))))]
                }
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + ToCborMap,
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
                    (3, Value::Bytes(x)) => Ok(ProofOfPossessionKey::KeyId(x)),
                    (x, _) => Err(TryFromCborMapError::unknown_field(u8::try_from(x)?)),
                }
            } else {
                unreachable!(
                    "we have previously verified that map.len() == 1, \
                so map.into_iter().next() must return a next element"
                )
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

    impl TryFrom<ProofOfPossessionKey> for CoseKey {
        type Error = WrongSourceTypeError<ProofOfPossessionKey>;

        fn try_from(
            value: ProofOfPossessionKey,
        ) -> Result<Self, WrongSourceTypeError<ProofOfPossessionKey>> {
            if let ProofOfPossessionKey::PlainCoseKey(key) = value {
                Ok(key)
            } else {
                Err(WrongSourceTypeError::new("PlainCoseKey", value.into()))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for CoseEncrypt0 {
        type Error = WrongSourceTypeError<ProofOfPossessionKey>;

        fn try_from(
            value: ProofOfPossessionKey,
        ) -> Result<Self, WrongSourceTypeError<ProofOfPossessionKey>> {
            if let ProofOfPossessionKey::EncryptedCoseKey(key) = value {
                Ok(key)
            } else {
                Err(WrongSourceTypeError::new("EncryptedCoseKey", value.into()))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for KeyId {
        type Error = WrongSourceTypeError<ProofOfPossessionKey>;

        fn try_from(
            value: ProofOfPossessionKey,
        ) -> Result<Self, WrongSourceTypeError<ProofOfPossessionKey>> {
            if let ProofOfPossessionKey::KeyId(kid) = value {
                Ok(kid)
            } else {
                Err(WrongSourceTypeError::new("KeyId", value.into()))
            }
        }
    }
}
