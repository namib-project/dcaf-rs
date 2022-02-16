use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::Deref;

use ciborium::value::Value;
use coset::{AsCborValue, CoseEncrypt0, CoseKey};
use erased_serde::Serialize as ErasedSerialize;
use serde::{Deserialize, Serialize, Serializer};

use crate::model::cbor_map::AsCborMap;

type ByteStringValue = Vec<u8>;

#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
pub struct ByteString(ByteStringValue);

impl ByteString {
    fn as_value(&self) -> Value {
        Value::Bytes(self.to_vec())
    }
}

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // The fact that we have to clone this is a little unfortunate.
        Value::serialize(&self.as_value(), serializer)
    }
}

impl Deref for ByteString {
    type Target = ByteStringValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ByteStringValue> for ByteString {
    fn from(x: ByteStringValue) -> Self {
        ByteString(x)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TextOrByteString {
    TextString(String),
    ByteString(ByteString),
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

impl TextOrByteString {
    pub fn try_as_text_string(&self) -> Option<&str> {
        if let TextOrByteString::TextString(s) = self {
            Option::Some(s)
        } else {
            Option::None
        }
    }

    pub fn try_as_byte_string(&self) -> Option<&ByteString> {
        if let TextOrByteString::ByteString(s) = self {
            Option::Some(s)
        } else {
            Option::None
        }
    }
}

/// A proof-of-possession key as specified by RFC 8747, section 3.1.
#[derive(Debug, PartialEq)]
pub enum ProofOfPossessionKey {
    CoseKey(CoseKey),
    EncryptedCoseKey(Box<CoseEncrypt0>),
    KeyId(ByteString),
}

impl AsCborMap for ProofOfPossessionKey {
    fn as_cbor_map(&self) -> Vec<(u16, Option<Box<dyn ErasedSerialize + '_>>)> {
        // The fact that we have to clone this is a little unfortunate.
        match self {
            Self::CoseKey(key) => {
                let x: u16 = 1;
                vec![(
                    x,
                    Some(Box::new(key.clone().to_cbor_value().expect("Invalid key"))),
                )]
            }
            Self::EncryptedCoseKey(enc) => {
                let x: u16 = 2;
                vec![(
                    x,
                    Some(Box::new(
                        (*enc).clone().to_cbor_value().expect("Invalid key"),
                    )),
                )]
            }
            Self::KeyId(kid) => {
                let x: u16 = 3;
                vec![(x, Some(Box::new(kid)))]
            }
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        if map.len() != 1 {
            None
        } else {
            match map.into_iter().next() {
                Some((1, x)) => {
                    if let Ok(key) = CoseKey::from_cbor_value(x) {
                        Some(ProofOfPossessionKey::CoseKey(key))
                    } else {
                        None
                    }
                }
                Some((2, x)) => {
                    if let Ok(enc) = CoseEncrypt0::from_cbor_value(x) {
                        Some(ProofOfPossessionKey::EncryptedCoseKey(Box::new(enc)))
                    } else {
                        None
                    }
                }
                Some((3, Value::Bytes(x))) => {
                    Some(ProofOfPossessionKey::KeyId(ByteString::from(x)))
                }
                _ => None,
            }
        }
    }
}

impl From<CoseKey> for ProofOfPossessionKey {
    fn from(key: CoseKey) -> Self {
        ProofOfPossessionKey::CoseKey(key)
    }
}

impl From<ByteString> for ProofOfPossessionKey {
    fn from(kid: ByteString) -> Self {
        ProofOfPossessionKey::KeyId(kid)
    }
}

impl From<CoseEncrypt0> for ProofOfPossessionKey {
    fn from(enc: CoseEncrypt0) -> Self {
        ProofOfPossessionKey::EncryptedCoseKey(Box::new(enc))
    }
}

impl ProofOfPossessionKey {
    pub fn try_as_cose_key(&self) -> Option<&CoseKey> {
        if let ProofOfPossessionKey::CoseKey(key) = self {
            Some(key)
        } else {
            None
        }
    }

    pub fn try_as_encrypted_cose_key(&self) -> Option<&CoseEncrypt0> {
        if let ProofOfPossessionKey::EncryptedCoseKey(key) = self {
            Some(key)
        } else {
            None
        }
    }

    pub fn try_as_key_id(&self) -> Option<&ByteString> {
        if let ProofOfPossessionKey::KeyId(key) = self {
            Some(key)
        } else {
            None
        }
    }
}
