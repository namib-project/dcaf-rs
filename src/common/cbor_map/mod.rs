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

//! Contains the [`ToCborMap`] trait with which data types from this crate can be (de)serialized.
//!
//! # Example
//! Let's say we want to serialize an [`AccessTokenRequest`]:
//! ```
//! # use std::error::Error;
//! # use ciborium_io::Write;
//! # use ciborium_io::Read;
//! # use dcaf::{AccessTokenRequest, ToCborMap};
//! # use dcaf::endpoints::token_req::AccessTokenRequestBuilderError;
//! # use crate::dcaf::constants::cbor_abbreviations::token::CLIENT_ID;
//! let request: AccessTokenRequest = AccessTokenRequest::builder().client_id("test").build()?;
//! let mut serialized = Vec::new();
//! request.serialize_into(&mut serialized)?;
//!
//! assert_eq!(serialized, vec![
//! 0xA1, // map(1)
//! 0x18, 0x18, // unsigned(24), where 24 is the constant identifying the "client_id" label
//! 0x64, // text(4)
//! 0x74, 0x65, 0x73, 0x74 // "test"
//! ]);
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! If we then want to deserialize it again:
//! ```
//! # use ciborium_io::Read;
//! # use serde::de::value::Error;
//! # use dcaf::{AccessTokenRequest, ToCborMap};
//! let serialized = vec![0xA1, 0x18, 0x18, 0x64, 0x74, 0x65, 0x73, 0x74];
//! let request = AccessTokenRequest::deserialize_from(serialized.as_slice())?;
//! assert_eq!(request.client_id, Some("test".to_string()));
//! # Ok::<(), ciborium::de::Error<<&[u8] as Read>::Error>>(())
//! ```
//!
//! [`AccessTokenRequest`]: crate::AccessTokenRequest

use alloc::boxed::Box;
use alloc::vec::Vec;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use core::fmt::{Debug, Display, Formatter};
use std::any::type_name;

use ciborium::value::{Integer, Value};
use ciborium_io::{Read, Write};
use erased_serde::Serialize as ErasedSerialize;

use crate::common::scope::Scope;
use crate::error::{TryFromCborMapError, ValueIsNotIntegerError};

/// Creates a CBOR map from integer keys to values, where the given values must have a `map`
/// method available (e.g. [`Option`]).
///
/// The macro has been adapted from
/// [a macro in ciborium's tests](https://github.com/enarx/ciborium/blob/main/ciborium/tests/macro.rs#L13)
///
/// # Example
/// The following code:
/// ```
/// let map = cbor_map_vec! {
///     0 => Some("Test"),
///     1 => Some(42)
/// };
/// ```
/// Would create the following map (written in CBOR diagnostic notation):
/// ```text
/// {
///    0: "Test",
///    1: 42
/// }
/// ```
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

/// Provides methods to serialize a type into a CBOR map bytestring and back.
///
/// This provides methods to [`serialize_into`](ToCborMap::serialize_into) and
/// [`deserialize_from`](ToCborMap::deserialize_from) CBOR, which is the
/// recommended way to serialize and deserialize any types implementing [`ToCborMap`] in this crate.
/// *While other methods are provided as well, it's recommended for clients of this library not to
/// use them, as they are mostly intended for internal use and as such may have an unstable API.*
///
/// # Example
/// The following showcases how to serialize a type implementing `ToCborMap`
/// using the example of an [`AuthServerRequestCreationHint`](crate::AuthServerRequestCreationHint):
/// ```
/// # use ciborium_io::Write;
/// # use dcaf::AuthServerRequestCreationHint;
/// # use dcaf::common::cbor_map::ToCborMap;
/// let hint = AuthServerRequestCreationHint::default();
/// let mut serialized: Vec<u8> = Vec::new();
/// hint.serialize_into(&mut serialized)?;
/// # Ok::<(), ciborium::ser::Error<<Vec<u8> as Write>::Error>>(())
/// ```
/// From the serialized bytestring, just call [`deserialize_from`](ToCborMap::deserialize_from)
/// on the struct you want to deserialize into:
/// ```
/// # use ciborium_io::Read;
/// # use dcaf::AuthServerRequestCreationHint;
/// # use dcaf::common::cbor_map::ToCborMap;
/// # let hint = AuthServerRequestCreationHint::default();
/// # let mut serialized: Vec<u8> = Vec::new();
/// # hint.clone().serialize_into(&mut serialized).expect("couldn't serialize hint");
/// let deserialized = AuthServerRequestCreationHint::deserialize_from(serialized.as_slice())?;
/// assert_eq!(hint, deserialized);
/// # Ok::<(), ciborium::de::Error<<&[u8] as Read>::Error>>(())
/// ```
pub trait ToCborMap: private::Sealed {
    /// Serializes this type as a CBOR map bytestring into the given `writer`.
    ///
    /// # Example
    /// The following showcases how to serialize a type implementing `ToCborMap`
    /// using the example of an [`AuthServerRequestCreationHint`](crate::AuthServerRequestCreationHint):
    /// ```
    /// # use ciborium_io::Write;
    /// # use dcaf::AuthServerRequestCreationHint;
    /// # use dcaf::common::cbor_map::ToCborMap;
    /// let hint = AuthServerRequestCreationHint::default();
    /// let mut serialized: Vec<u8> = Vec::new();
    /// hint.serialize_into(&mut serialized)?;
    /// assert_eq!(serialized, vec![0xA0]);  // 0xA0 == Empty CBOR map.
    /// # Ok::<(), ciborium::ser::Error<<Vec<u8> as Write>::Error>>(())
    /// ```
    ///
    /// # Errors
    /// - When serialization of this value failed, e.g. due to malformed input.
    /// - When the output couldn't be put inside the given `writer`.
    fn serialize_into<W>(self, writer: W) -> Result<(), ciborium::ser::Error<W::Error>>
    where
        Self: Sized,
        W: Write,
        W::Error: Debug,
    {
        into_writer(&CborMap(self), writer)
    }

    /// Deserializes from the given `reader` --- which is expected to be an instance of this type,
    /// represented as a CBOR map bytestring --- into an instance of this type.
    ///
    /// # Example
    /// Assuming `serialized` holds an empty CBOR map, we expect it to deserialize to the default
    /// value of a type (this obviously only holds for types which implement [`Default`].)
    /// Here, we show this using [`AuthServerRequestCreationHint`](crate::AuthServerRequestCreationHint) as an example:
    /// ```
    /// # use ciborium_io::Read;
    /// # use dcaf::AuthServerRequestCreationHint;
    /// # use dcaf::common::cbor_map::ToCborMap;
    /// let serialized = vec![0xA0];
    /// let deserialized = AuthServerRequestCreationHint::deserialize_from(serialized.as_slice())?;
    /// assert_eq!(deserialized, AuthServerRequestCreationHint::default());
    /// # Ok::<(), ciborium::de::Error<<&[u8] as Read>::Error>>(())
    /// ```
    ///
    /// # Errors
    /// - When deserialization of the bytestring failed, e.g. when the given `reader` does not
    ///   contain a valid CBOR map or deserializes to a different type than this one.
    /// - When the input couldn't be read from the given `reader`.
    fn deserialize_from<R>(reader: R) -> Result<Self, ciborium::de::Error<R::Error>>
    where
        Self: Sized,
        R: Read,
        R::Error: Debug,
    {
        from_reader(reader).map(|x: CborMap<Self>| x.0)
    }

    /// Converts this type into a CBOR map from integer keys to serializable values
    /// (which may be empty).
    ///
    /// **NOTE: This is not intended for users of this crate!**
    #[doc(hidden)]
    fn to_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)>;

    /// Tries to create an instance of this type from the given vector, which represents a CBOR map
    /// from integers to CBOR values.
    ///
    /// **NOTE: This is not intended for users of this crate!**
    ///
    /// # Errors
    /// - When the given CBOR map can't be converted to this trait.
    #[doc(hidden)]
    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
    where
        Self: Sized + ToCborMap;

    /// Converts this type to a CBOR serializable [`Value`] using [`to_cbor_map`](ToCborMap::to_cbor_map).
    ///
    /// # Panics
    /// - When the integers in the map from [`to_cbor_map`](ToCborMap::to_cbor_map) are too high to fit into a
    ///   [`Value::Integer`].
    /// - When a CBOR map value can't be serialized.
    ///
    /// Note that both of these would imply a programming mistake on account of `dcaf-rs`,
    /// not its users.
    ///
    /// # Example
    /// For example, to serialize a proof-of-possession key into a [`Value`] so we can then
    /// represent it inside a [`ClaimsSet`](coset::cwt::ClaimsSet) (to use it in an access token):
    /// ```
    /// # use coset::cwt::ClaimsSetBuilder;
    /// # use coset::iana::CwtClaimName;
    /// # use dcaf::ToCborMap;
    /// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
    /// let key = ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]);
    /// let claims = ClaimsSetBuilder::new()
    ///     .claim(CwtClaimName::Cnf, key.to_ciborium_value())
    ///     .build();
    /// ```
    fn to_ciborium_value(&self) -> Value {
        Value::Map(
            self.to_cbor_map()
                .into_iter()
                .filter(|x| x.1.is_some())
                .map(|x| {
                    (
                        Value::Integer(x.0.try_into().expect("CBOR key value too high")),
                        Value::serialized(&x.1).expect("Invalid CBOR map value"),
                    )
                })
                .collect(),
        )
    }

    /// Converts the given vector representing
    /// "a CBOR map from serializable keys to serializable values" (`Vec<(Value, Value)>`)
    /// into a similar vector which represents
    /// "a CBOR map from integer keys to serializable values" (`Vec<(i128, Value)>`).
    ///
    /// This obviously requires that the given `map` is such a CBOR map with integer keys,
    /// otherwise an error will be returned.
    ///
    /// **NOTE: This is not intended for users of this crate!**
    ///
    /// # Errors
    /// - When a key from the given CBOR `map` is not an integer.
    #[doc(hidden)]
    fn cbor_map_from_int(
        map: Vec<(Value, Value)>,
    ) -> Result<Vec<(i128, Value)>, ValueIsNotIntegerError> {
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

/// Decodes the given specific `scope` of type `T` into the general [`Scope`] type.
///
/// # Errors
/// - If `scope` is not a valid scope.
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

/// Decodes the given `number` Integer into a more specific integer of type `T`.
///
/// # Errors
/// - If `number` can't be a valid instance of type `T`.
pub(crate) fn decode_number<T>(number: Integer, name: &str) -> Result<T, TryFromCborMapError>
where
    T: TryFrom<Integer>,
{
    match T::try_from(number) {
        Ok(i) => Ok(i),
        Err(_) => {
            return Err(TryFromCborMapError::from_message(format!(
                "{name} must be a valid {}",
                type_name::<T>()
            )));
        }
    }
}

/// Decodes the given general CBOR `map` into a CBOR map from integers to values.
/// See [`ToCborMap::cbor_map_from_int`] for details.
///
/// # Errors
/// - If `map` is not a valid CBOR map with integer keys.
pub(crate) fn decode_int_map<T>(
    map: Vec<(Value, Value)>,
    name: &str,
) -> Result<Vec<(i128, Value)>, TryFromCborMapError>
where
    T: ToCborMap,
{
    T::cbor_map_from_int(map).map_err(|_| {
        TryFromCborMapError::from_message(format!(
            "{name} is not a valid CBOR map with integer keys"
        ))
    })
}

/// Convenience struct so we can implement a foreign trait on all structs we intend to
/// (de)serialize as CBOR maps.
///
/// This should always be invisible to clients of this crate.
#[derive(Debug, PartialEq, Eq, Hash)]
struct CborMap<T>(T)
where
    T: ToCborMap;

impl<T> Display for CborMap<T>
where
    T: ToCborMap + Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Contains definitions according to C-SEALED, which turns [`ToCborMap`] into a sealed trait.
mod private {
    use crate::common::cbor_values::ProofOfPossessionKey;
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

/// Contains methods to convert `CborMap` structs (so actually, types implementing `ToCborMap`)
/// into CBOR and back.
mod conversion {
    use ciborium::value::Value;
    use serde::de::{Error, Unexpected};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::common::cbor_map::{CborMap, ToCborMap};

    impl<T> From<T> for CborMap<T>
    where
        T: ToCborMap,
    {
        fn from(value: T) -> Self {
            CborMap(value)
        }
    }

    impl<T> Serialize for CborMap<T>
    where
        T: ToCborMap,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Serialize::serialize(&self.0.to_ciborium_value(), serializer)
        }
    }

    impl<'de, T> Deserialize<'de> for CborMap<T>
    where
        T: ToCborMap,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            match Value::deserialize(deserializer)? {
                Value::Map(map) => {
                    let map: Vec<(i128, Value)> =
                        T::cbor_map_from_int(map).map_err(D::Error::custom)?;
                    ToCborMap::try_from_cbor_map(map)
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
