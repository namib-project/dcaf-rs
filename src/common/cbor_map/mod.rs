use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{Debug, Display, Formatter};
use std::any::type_name;
use ciborium::de::from_reader;
use ciborium::ser::{into_writer};

use ciborium::value::{Integer, Value};
use ciborium_io::{Read, Write};
use erased_serde::Serialize as ErasedSerialize;

use crate::common::scope::Scope;
use crate::error::{TryFromCborMapError, ValueIsNotIntegerError};

// Macro adapted from https://github.com/enarx/ciborium/blob/main/ciborium/tests/macro.rs#L13
macro_rules! cbor_map_vec {
    ($($key:expr => $val:expr),* $(,)*) => {
         vec![$(
             (
                 $key as i128,
                 $val.map(|x| {
                         // `Box::<dyn ErasedSerialize>` would not work, see
                         // here for an explanation: https://stackoverflow.com/a/63550684
                         let a_box: Box<dyn ErasedSerialize> = Box::new(x);
                         a_box
                     })
             )
         ),*]
     };
     }

#[rustfmt::skip]
pub(crate) use cbor_map_vec;


pub trait AsCborMap: private::Sealed {
    fn serialize_into<W>(self, writer: W) -> Result<(), ciborium::ser::Error<W::Error>> where Self: Sized, W: Write, W::Error: Debug {
        into_writer(&CborMap(self), writer)
    }

    fn deserialize_from<R>(reader: R) -> Result<Self, ciborium::de::Error<R::Error>> where Self: Sized, R: Read, R::Error: Debug {
        from_reader(reader).map(|x: CborMap<Self>| x.0)
    }

    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)>;

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + AsCborMap;

    // TODO: Document panics
    fn as_ciborium_value(&self) -> Value {
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

    fn cbor_map_from_int(map: Vec<(Value, Value)>) -> Result<Vec<(i128, Value)>, ValueIsNotIntegerError> {
        // We want to convert (Value, Value) to (i128, Value), assuming that the first
        // Value is always a Value::Integer.
        map.into_iter()
            .map(|x| (x.0.as_integer().map(i128::from), x.1))
            .map(|x| match x {
                (None, _) => Err(ValueIsNotIntegerError),
                (Some(x), y) => Ok((x, y)),
            })
            .collect::<Result<Vec<(i128, Value)>, ValueIsNotIntegerError>>()
    }
}

pub(crate) fn decode_scope<T, S>(scope: T) -> Result<Option<Scope>, TryFromCborMapError>
    where
        S: TryFrom<T>,
        Scope: From<S>,
        S::Error: Display,
{
    match S::try_from(scope) {
        Ok(scope) => Ok(Some(Scope::from(scope))),
        Err(e) => {
            return Err(TryFromCborMapError::from_message(format!(
                "couldn't decode scope: {e}"
            )));
        }
    }
}

pub(crate) fn decode_number<T>(number: Integer, name: &str) -> Result<T, TryFromCborMapError> where T: TryFrom<Integer> {
    match T::try_from(number) {
        Ok(i) => Ok(i),
        Err(_) => {
            return Err(TryFromCborMapError::from_message(
                format!("{name} must be a valid {}", type_name::<T>()),
            ));
        }
    }
}

pub(crate) fn decode_int_map<T>(map: Vec<(Value, Value)>, name: &str) -> Result<Vec<(i128, Value)>, TryFromCborMapError> where T: AsCborMap {
    T::cbor_map_from_int(map).map_err(|_|
        TryFromCborMapError::from_message(format!(
            "{name} is not a valid CBOR map"
        ))
    )
}

/// Convenience struct so we can implement a foreign trait on all structs we intend to
/// (de)serialize as CBOR maps.
#[derive(Debug, PartialEq, Eq, Hash)]
struct CborMap<T>(T) where T: AsCborMap;

impl<T> Display for CborMap<T>
    where
        T: AsCborMap + Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

mod private {
    use crate::common::ProofOfPossessionKey;
    use crate::endpoints::creation_hint::AuthServerRequestCreationHint;
    use crate::endpoints::token_req::{AccessTokenRequest, AccessTokenResponse, ErrorResponse};

    /// Sealed trait according to C-SEALED.
    pub trait Sealed {}

    impl Sealed for AuthServerRequestCreationHint {}

    impl Sealed for AccessTokenRequest {}

    impl Sealed for AccessTokenResponse {}

    impl Sealed for ErrorResponse {}

    impl Sealed for ProofOfPossessionKey {}
}

mod conversion {
    use ciborium::value::Value;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::de::{Error, Unexpected};

    use crate::common::{AsCborMap};
    use crate::common::cbor_map::CborMap;

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
            Serialize::serialize(&self.0.as_ciborium_value(), serializer)
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
}