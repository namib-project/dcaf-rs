use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::Deref;

use ciborium::value::Value;
use coset::{CoseEncrypt0, CoseKey};
use serde::{Deserialize, Serialize};

mod conversion;

type ByteStringValue = Vec<u8>;

#[derive(Debug, Deserialize, PartialEq, Eq, Default, Hash)]
pub struct ByteString(ByteStringValue);

pub struct CborMapValue<T>(pub T) where i32: Into<T>, T: Into<i32> + Copy;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum TextOrByteString {
    TextString(String),
    ByteString(ByteString),
}

/// A proof-of-possession key as specified by RFC 8747, section 3.1.
#[derive(Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ProofOfPossessionKey {
    CoseKey(CoseKey),
    EncryptedCoseKey(CoseEncrypt0),
    KeyId(ByteString),
}

impl ByteString {
    fn as_value(&self) -> Value {
        Value::Bytes(self.to_vec())
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

impl Deref for ByteString {
    type Target = ByteStringValue;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Deref for CborMapValue<T> where T: From<i32> + Into<i32> + Copy
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
