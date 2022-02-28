use alloc::vec::Vec;

use ciborium::value::Value;
use serde::{Deserializer, Serialize, Serializer};
use serde::de::{Error, Unexpected};
use serde::Deserialize;

use crate::model::cbor_map::{AsCborMap, CborMap};

impl<T> From<T> for CborMap<T>
    where
        T: AsCborMap,
{
    fn from(value: T) -> Self {
        CborMap(value)
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
                    .map_err(D::Error::custom)
            }
            _ => Err(D::Error::invalid_type(
                Unexpected::Other("unknown type"),
                &"a CBOR map",
            )),
        }
    }
}
