use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;

use coset::{CoseEncrypt0, CoseKey};
use serde::{Deserialize, Serialize};

pub(crate) type ByteStringValue = Vec<u8>;

pub(crate) type KeyId = ByteString;

#[derive(Debug, Deserialize, PartialEq, Eq, Default, Hash, Clone)]
pub struct ByteString(pub(crate) ByteStringValue);

pub struct CborMapValue<T>(pub T)
    where
        i32: Into<T>,
        T: Into<i32> + Copy;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum TextOrByteString {
    TextString(String),
    ByteString(ByteString),
}

/// A proof-of-possession key as specified by RFC 8747, section 3.1.
#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ProofOfPossessionKey {
    PlainCoseKey(CoseKey),
    EncryptedCoseKey(CoseEncrypt0),
    KeyId(KeyId),
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

mod conversion {
    use ciborium::value::Value;
    use coset::{AsCborValue, CoseEncrypt0, CoseKey};
    use erased_serde::Serialize as ErasedSerialize;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::de::Error;

    use crate::common::AsCborMap;
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

    impl From<ByteStringValue> for ByteString {
        fn from(x: ByteStringValue) -> Self {
            ByteString(x)
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
        type Error = WrongSourceTypeError;

        fn try_from(value: TextOrByteString) -> Result<Self, Self::Error> {
            if let TextOrByteString::TextString(s) = value {
                Ok(s)
            } else {
                Err(WrongSourceTypeError::new("TextOrByteString", "ByteString"))
            }
        }
    }

    impl TryFrom<TextOrByteString> for ByteString {
        type Error = WrongSourceTypeError;

        fn try_from(value: TextOrByteString) -> Result<Self, Self::Error> {
            if let TextOrByteString::ByteString(s) = value {
                Ok(s)
            } else {
                Err(WrongSourceTypeError::new("TextOrByteString", "ByteString"))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for CoseKey {
        type Error = WrongSourceTypeError;

        fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
            if let ProofOfPossessionKey::PlainCoseKey(key) = value {
                Ok(key)
            } else {
                Err(WrongSourceTypeError::new("ProofOfPossessionKey", "CoseKey"))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for CoseEncrypt0 {
        type Error = WrongSourceTypeError;

        fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
            if let ProofOfPossessionKey::EncryptedCoseKey(key) = value {
                Ok(key)
            } else {
                Err(WrongSourceTypeError::new(
                    "ProofOfPossessionKey",
                    "CoseEncrypt0",
                ))
            }
        }
    }

    impl TryFrom<ProofOfPossessionKey> for KeyId {
        type Error = WrongSourceTypeError;

        fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
            if let ProofOfPossessionKey::KeyId(kid) = value {
                Ok(kid)
            } else {
                Err(WrongSourceTypeError::new("ProofOfPossessionKey", "KeyId"))
            }
        }
    }
}