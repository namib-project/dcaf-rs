use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Deref;

use ciborium::value::Value;
use erased_serde::Serialize as ErasedSerialize;
use serde::de::{Error, Unexpected};
use serde::Deserialize;
use serde::{Deserializer, Serialize, Serializer};

pub trait AsCborMap {
    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)>;

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap;

    fn to_ciborium_map(&self) -> Value {
        Value::Map(
            self.as_cbor_map()
                .into_iter()
                .filter(|x| x.1.is_some())
                .map(|x| {
                    (
                        Value::Integer(x.0.try_into().expect("CBOR map value too high")),
                        Value::serialized(&x.1).expect("Invalid CBOR map value"),
                    )
                })
                .collect(),
        )
    }

    fn cbor_map_from_int(map: Vec<(Value, Value)>) -> Result<Vec<(i128, Value)>, String> {
        // We want to convert (Value, Value) to (i128, Value), assuming that the first
        // Value is always a Value::Integer.
        map.into_iter()
            .map(|x| (x.0.as_integer().map(i128::from), x.1))
            .map(|x| match x {
                (None, _) => Err("CBOR map key needs to be integer".to_string()),
                (Some(x), y) => Ok((x, y)),
            })
            .collect::<Result<Vec<(i128, Value)>, String>>()
    }
}

/// Convenience struct so we can implement a foreign trait on all structs we intend to
/// (de)serialize as CBOR maps.
#[derive(Debug)]
pub struct CborMap<T>(pub T)
where
    T: AsCborMap;

impl<T> Deref for CborMap<T>
where
    T: AsCborMap,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Serialize for CborMap<T>
where
    T: AsCborMap,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&self.to_ciborium_map(), serializer)
    }
}

impl<'de, T> Deserialize<'de> for CborMap<T>
where
    T: AsCborMap,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::Map(map) => {
                let map: Vec<(i128, Value)> =
                    T::cbor_map_from_int(map).map_err(D::Error::custom)?;
                AsCborMap::try_from_cbor_map(map)
                    .map(CborMap)
                    .ok_or_else(|| D::Error::custom("unknown field in CBOR map encountered"))
            }
            _ => Err(D::Error::invalid_type(
                Unexpected::Other("unknown type"),
                &"a CBOR map",
            )),
        }
    }
}
