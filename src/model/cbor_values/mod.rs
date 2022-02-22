use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::Deref;

use coset::{CoseEncrypt0, CoseKey};
use serde::{Deserialize, Serialize};

mod conversion;

type ByteStringValue = Vec<u8>;

type KeyId = ByteString;

#[derive(Debug, Deserialize, PartialEq, Eq, Default, Hash)]
pub struct ByteString(ByteStringValue);

pub struct CborMapValue<T>(pub T)
    where
        i32: Into<T>,
        T: Into<i32> + Copy;

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
