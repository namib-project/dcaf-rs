use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use core::ops::Deref;

use ciborium::value::Value;
use erased_serde::Serialize as ErasedSerialize;

use crate::error::{TryFromCborMapError, ValueIsNotIntegerError};

mod conversion;

pub trait AsCborMap: private::Sealed {
    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)>;

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + AsCborMap;

    // TODO: Document panics
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

/// Convenience struct so we can implement a foreign trait on all structs we intend to
/// (de)serialize as CBOR maps.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CborMap<T>(pub T)
    where
        T: AsCborMap;

impl<T> Display for CborMap<T>
    where
        T: AsCborMap + Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> Deref for CborMap<T>
    where
        T: AsCborMap,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

mod private {
    use crate::ace::{AccessTokenRequest, AccessTokenResponse, AuthServerRequestCreationHint, ErrorResponse};
    use crate::cbor_values::ProofOfPossessionKey;

    /// Sealed trait according to C-SEALED.
    pub trait Sealed {}

    impl Sealed for AuthServerRequestCreationHint {}

    impl Sealed for AccessTokenRequest {}

    impl Sealed for AccessTokenResponse {}

    impl Sealed for ErrorResponse {}

    impl Sealed for ProofOfPossessionKey {}
}