use ciborium::value::Value;
use coset::{AsCborValue, CoseEncrypt0, CoseKey};
use erased_serde::Serialize as ErasedSerialize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error;

use crate::cbor_values::{ByteString, ByteStringValue, CborMapValue, KeyId, ProofOfPossessionKey, TextOrByteString};
use crate::model::cbor_map::AsCborMap;

impl<T> Serialize for CborMapValue<T> where T: From<i32> + Into<i32> + Copy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let cbor_value: i32 = self.0.into();
        Value::from(cbor_value).serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for CborMapValue<T> where T: From<i32> + Into<i32> + Copy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        if let Ok(Value::Integer(i)) = Value::deserialize(deserializer) {
            Ok(CborMapValue(i32::try_from(i)
                .map_err(|x| D::Error::custom(x.to_string()))?.into()))
        } else {
            Err(D::Error::custom("CBOR map value must be an Integer!"))
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
            Self::CoseKey(key) => {
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
                        Some(ProofOfPossessionKey::EncryptedCoseKey(enc))
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
        ProofOfPossessionKey::EncryptedCoseKey(enc)
    }
}

impl From<&ByteString> for Value {
    fn from(bytestring: &ByteString) -> Self {
        Value::Bytes(bytestring.to_vec())
    }
}

impl TryFrom<TextOrByteString> for String {
    type Error = ();

    fn try_from(value: TextOrByteString) -> Result<Self, Self::Error> {
        if let TextOrByteString::TextString(s) = value {
            Ok(s)
        } else {
            Err(())
        }
    }
}

impl TryFrom<TextOrByteString> for ByteString {
    type Error = ();

    fn try_from(value: TextOrByteString) -> Result<Self, Self::Error> {
        if let TextOrByteString::ByteString(s) = value {
            Ok(s)
        } else {
            Err(())
        }
    }
}

impl TryFrom<ProofOfPossessionKey> for CoseKey {
    type Error = ();

    fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
        if let ProofOfPossessionKey::CoseKey(key) = value {
            Ok(key)
        } else {
            Err(())
        }
    }
}

impl TryFrom<ProofOfPossessionKey> for CoseEncrypt0 {
    type Error = ();

    fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
        if let ProofOfPossessionKey::EncryptedCoseKey(key) = value {
            Ok(key)
        } else {
            Err(())
        }
    }
}

/// Converts from
impl TryFrom<ProofOfPossessionKey> for KeyId {
    type Error = ();

    fn try_from(value: ProofOfPossessionKey) -> Result<Self, Self::Error> {
        if let ProofOfPossessionKey::KeyId(kid) = value {
            Ok(kid)
        } else {
            Err(())
        }
    }
}


