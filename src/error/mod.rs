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

//! Contains error types used across this crate.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::any::type_name;
use core::fmt::{Display, Formatter};

use ciborium::value::Value;
use coset::{Algorithm, CoseError, CoseKey, KeyOperation, KeyType, Label};
use strum_macros::IntoStaticStr;

use {alloc::format, alloc::string::String, alloc::string::ToString};

use crate::token::cose::header_util::HeaderParam;
use crate::token::cose::key::{EllipticCurve, KeyParam};
use core::{marker::PhantomData, num::TryFromIntError};

/// Error type used when the parameter of the type `T` couldn't be
/// converted into [`expected_type`](WrongSourceTypeError::expected_type) because the received
/// type was [`actual_type`](WrongSourceTypeError::actual_type) instead.
///
/// `T` is the general type taken in the [`TryFrom`] conversion.
/// Used for [`TryFrom`] conversions from a general enum type to a specific member type.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct WrongSourceTypeError<T> {
    /// The name of the specific type which [`TryFrom`] tried to convert to.
    pub expected_type: &'static str,
    /// The name of the actual type which [`TryFrom`] received.
    pub actual_type: &'static str,
    /// The general type taken in the [`TryFrom`] conversion.
    pub general_type: PhantomData<T>,
}

impl<T> Display for WrongSourceTypeError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the given {} is a {} variant (expected {} variant)",
            type_name::<T>(),
            self.actual_type,
            self.expected_type
        )
    }
}

impl<T> WrongSourceTypeError<T> {
    /// Creates a new instance of the error, taking `T` as the general type from which
    /// the conversion was tried and the `expected_type` as the target type which it was tried to
    /// convert it into, but failed because it was actually of the type named by `actual_type`.
    #[must_use]
    pub fn new(expected_type: &'static str, actual_type: &'static str) -> WrongSourceTypeError<T> {
        WrongSourceTypeError {
            expected_type,
            actual_type,
            general_type: PhantomData,
        }
    }
}

/// Error type used when a given CBOR map can't be converted to a specific type which implements
/// the [`ToCborMap`](crate::ToCborMap) trait.
///
/// **Note: This error type is not expected to be used by library clients!**
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct TryFromCborMapError {
    /// Error message describing why the conversion failed.
    message: String,
}

impl Display for TryFromCborMapError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl TryFromCborMapError {
    /// Creates a new error with the given custom `message`.
    #[must_use]
    pub(crate) fn from_message<T>(message: T) -> TryFromCborMapError
    where
        T: Into<String>,
    {
        TryFromCborMapError {
            message: message.into(),
        }
    }

    /// Creates a new error with a message describing that an unknown field in
    /// the CBOR map with the given `key` was encountered.
    #[must_use]
    pub(crate) fn unknown_field(key: u8) -> TryFromCborMapError {
        TryFromCborMapError {
            message: format!("unknown field with key {key} encountered"),
        }
    }

    /// Creates a new error with a message describing that the target type could not be built,
    /// either due to a missing field or due to a validation error in the builder.
    #[must_use]
    pub(crate) fn build_failed<T>(name: &'static str, builder_error: T) -> TryFromCborMapError
    where
        T: Display,
    {
        TryFromCborMapError {
            message: format!("couldn't build {name}: {builder_error}"),
        }
    }
}

impl From<TryFromIntError> for TryFromCborMapError {
    fn from(e: TryFromIntError) -> Self {
        TryFromCborMapError::from_message(e.to_string())
    }
}

/// Error type used when a CBOR map does not use integers as its key type, but was expected to.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ValueIsNotIntegerError;

impl Display for ValueIsNotIntegerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "CBOR map key must be an integer")
    }
}

/// Error type used when a [`TextEncodedScope`](crate::common::scope::TextEncodedScope)
/// does not conform to the specification given in RFC 6749.
#[derive(Debug, PartialEq, Eq, Clone, Hash, IntoStaticStr)]
pub enum InvalidTextEncodedScopeError {
    /// The scope starts with a separator (i.e. space).
    StartsWithSeparator,
    /// The scope ends with a separator (i.e. space).
    EndsWithSeparator,
    /// The scope contains two separators (i.e. spaces).
    ConsecutiveSeparators,
    /// The scope contains an empty element.
    EmptyElement,
    /// The scope is empty.
    EmptyScope,
    /// The scope contains illegal characters (i.e. a backslash (`\\`) or double-quote (`"`)).
    IllegalCharacters,
    /// The scope is invalid for another reason, which is specified in the message contained here.
    Other(&'static str),
}

impl Display for InvalidTextEncodedScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            InvalidTextEncodedScopeError::StartsWithSeparator => "must not start with space",
            InvalidTextEncodedScopeError::EndsWithSeparator => "must not end with space",
            InvalidTextEncodedScopeError::ConsecutiveSeparators => {
                "must not contain consecutive spaces"
            }
            InvalidTextEncodedScopeError::EmptyElement => "must not contain empty elements",
            InvalidTextEncodedScopeError::EmptyScope => "must not be empty",
            InvalidTextEncodedScopeError::IllegalCharacters => {
                "must not contain illegal character '\\' or '\"'"
            }
            InvalidTextEncodedScopeError::Other(s) => s,
        };
        write!(
            f,
            "text-encoded scope must follow format specified in RFC 6749 ({message})"
        )
    }
}

/// Error type used when a [`BinaryEncodedScope`](crate::common::scope::BinaryEncodedScope)
/// does not conform to the specification given in RFC 6749 and RFC 9200.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum InvalidBinaryEncodedScopeError {
    /// Scope starts with a separator, which is contained in the field here.
    StartsWithSeparator(u8),
    /// Scope ends with a separator, which is contained in the field here.
    EndsWithSeparator(u8),
    /// Scope contains two consecutive separators, which is contained in the field here.
    ConsecutiveSeparators(u8),
    /// Scope is empty.
    EmptyScope,
}

impl Display for InvalidBinaryEncodedScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            InvalidBinaryEncodedScopeError::StartsWithSeparator(s) => {
                write!(f, "scope may not start with separator '{s:#x}'")
            }
            InvalidBinaryEncodedScopeError::EndsWithSeparator(s) => {
                write!(f, "scope may not end with separator '{s:#x}'")
            }
            InvalidBinaryEncodedScopeError::ConsecutiveSeparators(s) => {
                write!(f, "scope may not contain separator '{s:#x}' twice in a row")
            }
            InvalidBinaryEncodedScopeError::EmptyScope => write!(f, "scope may not be empty"),
        }
    }
}

/// Error type used when an [`AifEncodedScope`](crate::common::scope::AifEncodedScope)
/// does not conform to the specification given in [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) and
/// [RFC 9237](https://www.rfc-editor.org/rfc/rfc9237).
///
/// This is also used when a [`LibdcafEncodedScope`](crate::common::scope::LibdcafEncodedScope)
/// does not conform to the format specified in its documentation.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[non_exhaustive]
pub enum InvalidAifEncodedScopeError {
    /// Scope's bitflags, representing an [AifRestMethodSet](crate::common::scope::AifRestMethodSet)
    /// were not valid, i.e., did not represent a valid combination of REST methods.
    InvalidRestMethodSet,

    /// Scope contained a malformed array, i.e., didn't conform to the specification.
    MalformedArray,
}

impl Display for InvalidAifEncodedScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            InvalidAifEncodedScopeError::InvalidRestMethodSet => {
                write!(f, "given REST method bitfield is invalid")
            }
            InvalidAifEncodedScopeError::MalformedArray => {
                write!(f, "given AIF CBOR array is malformed")
            }
        }
    }
}

/// Error type used when a [`CoseEncryptCipher`](crate::CoseEncryptCipher),
/// [`CoseSignCipher`](crate::CoseSignCipher), or [`CoseMacCipher`](crate::CoseMacCipher).
/// fails to perform an operation.
///
/// `T` is the type of the nested error represented by the [`Other`](CoseCipherError::Other) variant.
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum CoseCipherError<T>
where
    T: Display,
{
    /// The given encrypted, signed or MAC-ed structure could not be verified and/or decrypted.
    VerificationFailure,
    /// Key type is not supported.
    UnsupportedKeyType(KeyType),
    /// Curve is not supported by coset or the chosen cryptographic backend.
    UnsupportedCurve(EllipticCurve),
    /// Algorithm is not supported by coset, the chosen cryptographic backend or dcaf-rs itself.
    UnsupportedAlgorithm(Algorithm),
    /// The cryptographic backend does not support deriving the public key from the private key, and
    /// the provided key does not provide the public key parts even though it is required for this
    /// operation.
    UnsupportedKeyDerivation,
    /// The algorithm has not explicitly been specified anywhere (protected headers, unprotected
    /// headers or the key itself).
    NoAlgorithmDeterminable,
    /// The provided key does not support the given operation.
    KeyOperationNotPermitted(BTreeSet<KeyOperation>, KeyOperation),
    /// Key in given curve must be in different format.
    KeyTypeCurveMismatch(KeyType, EllipticCurve),
    /// Provided algorithm requires a different key type.
    KeyTypeAlgorithmMismatch(KeyType, Algorithm),
    /// Algorithm provided in key does not match algorithm selected for operation.
    KeyAlgorithmMismatch(Algorithm, Algorithm),
    /// At least one header was provided both in the protected and the unprotected bucket
    /// simultaneously.
    DuplicateHeaders(Vec<Label>),
    /// A key parameter that is required for this type of key and/or algorithm is missing.
    ///
    /// If multiple key parameters are provided, at least one of them (but possibly more than one)
    /// is required (e.g. for EC keys, either D or (X and Y) must be set).
    MissingKeyParam(Vec<KeyParam>),
    /// A key parameter for this key has an invalid value.
    InvalidKeyParam(KeyParam, Value),
    /// A header parameter that is required for the selected algorithm is missing.
    MissingHeaderParam(HeaderParam),
    /// A header parameter has an invalid value.
    InvalidHeaderParam(HeaderParam, Value),
    /// Provided algorithm does not support additional authenticated data, but AAD was provided
    /// (either directly or the protected header bucket is not empty).
    AadUnsupported,
    /// No suitable key for verifying this structure was found.
    ///
    /// Either no matching key was provided or all provided keys had an error while attempting to
    /// verify.
    ///
    /// In the latter case, the error field will contain a list of all attempted keys and the
    /// corresponding error.
    NoMatchingKeyFound(Vec<(CoseKey, CoseCipherError<T>)>),
    /// A different error has occurred. Details are provided in the contained error.
    Other(T),
}

impl<T> CoseCipherError<T>
where
    T: Display,
{
    /// Creates a new [`CoseCipherError`] of type
    /// [`Other`](CoseCipherError::Other) (i.e., an error type that doesn't fit any other
    /// [`CoseCipherError`] variant) containing the given nested error `other`.
    #[must_use]
    pub fn other_error(other: T) -> CoseCipherError<T> {
        CoseCipherError::Other(other)
    }
}

impl<T> Display for CoseCipherError<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            // TODO (#14): this can probably be done better (use thiserror instead as soon as std::error::Error has been moved to core?)
            CoseCipherError::VerificationFailure => {
                write!(f, "data verification and/or decryption failed")
            }
            CoseCipherError::Other(s) => write!(f, "{s}"),
            CoseCipherError::UnsupportedKeyType(_) => write!(f, "unsupported key type"),
            CoseCipherError::UnsupportedCurve(_) => write!(f, "unsupported curve"),
            CoseCipherError::UnsupportedAlgorithm(_) => write!(f, "unsupported alorithm"),
            CoseCipherError::UnsupportedKeyDerivation => write!(
                f,
                "backend does not support public key derivation from private key"
            ),
            CoseCipherError::NoAlgorithmDeterminable => {
                write!(f, "no algorithm was provided in headers or key")
            }
            CoseCipherError::KeyOperationNotPermitted(_, _) => {
                write!(f, "key does not permit the requested operation")
            }
            CoseCipherError::KeyTypeCurveMismatch(_, _) => {
                write!(f, "key type is not supported for the given curve")
            }
            CoseCipherError::KeyTypeAlgorithmMismatch(_, _) => {
                write!(f, "key type is not supported for the given algorithm")
            }
            CoseCipherError::KeyAlgorithmMismatch(_, _) => {
                write!(f, "key does not support the given algorithm")
            }
            CoseCipherError::DuplicateHeaders(_) => write!(f, "duplicate headers"),
            CoseCipherError::MissingKeyParam(_) => write!(f, "required key parameter missing"),
            CoseCipherError::InvalidKeyParam(_, _) => write!(f, "key parameter has invalid value"),
            CoseCipherError::NoMatchingKeyFound(_) => {
                write!(f, "no suitable key was found for this operation")
            }
            CoseCipherError::MissingHeaderParam(_) => {
                write!(f, "header parameter missing")
            }
            CoseCipherError::InvalidHeaderParam(_, _) => {
                write!(f, "header parameter invalid")
            }
            CoseCipherError::AadUnsupported => {
                write!(
                    f,
                    "algorithm does not support additional authenticated data"
                )
            }
        }
    }
}

/// Error type when a [`Value`] can't be converted to a Scope.
///
/// This can be because it isn't a scope, or because the scope is invalid.
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum ScopeFromValueError {
    /// The binary scope contained in the [`Value`] is invalid.
    ///
    /// Details are provided in the given [`InvalidBinaryEncodedScopeError`].
    InvalidBinaryEncodedScope(InvalidBinaryEncodedScopeError),

    /// The textual scope contained in the [`Value`] is invalid.
    ///
    /// Details are provided in the given [`InvalidTextEncodedScopeError`].
    InvalidTextEncodedScope(InvalidTextEncodedScopeError),

    /// The AIF-encoded scope contained in the [`Value`] is invalid.
    ///
    /// Details are provided in the given [`InvalidAifEncodedScopeError`].
    InvalidAifEncodedScope(InvalidAifEncodedScopeError),

    /// The [`Value`] isn't a scope, but something else.
    ///
    /// Details are provided in the given [`WrongSourceTypeError`].
    InvalidType(WrongSourceTypeError<Value>),
}

fn to_variant_name(value: &Value) -> &'static str {
    match value {
        Value::Integer(_) => "Integer",
        Value::Bytes(_) => "Bytes",
        Value::Float(_) => "Float",
        Value::Text(_) => "Text",
        Value::Bool(_) => "Bool",
        Value::Null => "Null",
        Value::Tag(_, _) => "Tag",
        Value::Array(_) => "Array",
        Value::Map(_) => "Map",
        _ => "Unknown",
    }
}

impl ScopeFromValueError {
    /// Creates a new [`InvalidType`](ScopeFromValueError::InvalidType) error from the given
    /// `actual` [`Value`].
    ///
    /// Should be used when a given [`Value`] is not a text or byte string.
    #[must_use]
    pub fn invalid_type(actual: &Value) -> ScopeFromValueError {
        ScopeFromValueError::from(WrongSourceTypeError::new(
            "Text or Bytes",
            to_variant_name(actual),
        ))
    }
}

impl From<InvalidTextEncodedScopeError> for ScopeFromValueError {
    fn from(err: InvalidTextEncodedScopeError) -> Self {
        ScopeFromValueError::InvalidTextEncodedScope(err)
    }
}

impl From<InvalidBinaryEncodedScopeError> for ScopeFromValueError {
    fn from(err: InvalidBinaryEncodedScopeError) -> Self {
        ScopeFromValueError::InvalidBinaryEncodedScope(err)
    }
}

impl From<InvalidAifEncodedScopeError> for ScopeFromValueError {
    fn from(err: InvalidAifEncodedScopeError) -> Self {
        ScopeFromValueError::InvalidAifEncodedScope(err)
    }
}

impl From<WrongSourceTypeError<Value>> for ScopeFromValueError {
    fn from(err: WrongSourceTypeError<Value>) -> Self {
        ScopeFromValueError::InvalidType(err)
    }
}

impl Display for ScopeFromValueError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ScopeFromValueError::InvalidBinaryEncodedScope(s) => {
                write!(f, "invalid binary-encoded scope: {s}")
            }
            ScopeFromValueError::InvalidTextEncodedScope(s) => {
                write!(f, "invalid text-encoded scope: {s}")
            }
            ScopeFromValueError::InvalidType(t) => write!(f, "invalid type: {t}"),
            ScopeFromValueError::InvalidAifEncodedScope(a) => {
                write!(f, "invalid AIF-encoded scope: {a}")
            }
        }
    }
}

/// Error type used when an operation creating or receiving an access token failed.
///
/// `T` is the type of the nested error possibly contained by the
/// [`CoseCipherError`](AccessTokenError::CoseCipherError) variant.
#[derive(Debug)]
#[non_exhaustive]
pub enum AccessTokenError<T>
where
    T: Display,
{
    /// A COSE specific error occurred.
    ///
    /// Details are contained in this field using coset's [`CoseError`].
    CoseError(CoseError),
    /// A cryptographic CoseCipher operation has failed.
    ///
    /// Details are contained in this field, represented by a [`CoseCipherError`].
    CoseCipherError(CoseCipherError<T>),
    /// Headers can't be extracted because the input data is neither a
    /// [`CoseEncrypt0`](coset::CoseEncrypt0), [`CoseSign1`](coset::CoseSign1),
    /// nor [`CoseMac0`](coset::CoseMac0).
    UnknownCoseStructure,
}

impl<T> Display for AccessTokenError<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            AccessTokenError::CoseError(e) => write!(f, "{e}"),
            AccessTokenError::CoseCipherError(e) => write!(f, "cipher error: {e}"),
            AccessTokenError::UnknownCoseStructure => write!(
                f,
                "input is either invalid or none of CoseEncrypt0, CoseSign1 nor CoseMac0"
            ),
        }
    }
}

impl<T> From<CoseCipherError<T>> for AccessTokenError<T>
where
    T: Display,
{
    #[must_use]
    fn from(error: CoseCipherError<T>) -> Self {
        AccessTokenError::CoseCipherError(error)
    }
}

impl<T> From<CoseError> for AccessTokenError<T>
where
    T: Display,
{
    #[must_use]
    fn from(error: CoseError) -> Self {
        AccessTokenError::CoseError(error)
    }
}

#[cfg(feature = "std")]
mod std_error {
    use core::fmt::Debug;
    use std::error::Error;

    use crate::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
    use crate::endpoints::token_req::AccessTokenRequestBuilderError;
    use crate::endpoints::token_req::AccessTokenResponseBuilderError;
    use crate::endpoints::token_req::ErrorResponseBuilderError;

    use super::*;

    impl<T> Error for WrongSourceTypeError<T> where T: Debug {}

    impl Error for TryFromCborMapError {}

    impl Error for ValueIsNotIntegerError {}

    impl Error for InvalidTextEncodedScopeError {}

    impl Error for InvalidBinaryEncodedScopeError {}

    impl Error for InvalidAifEncodedScopeError {}

    impl Error for ScopeFromValueError {}

    impl<T> Error for CoseCipherError<T> where T: Debug + Display {}

    impl<T> Error for AccessTokenError<T> where T: Debug + Display {}

    impl Error for AccessTokenRequestBuilderError {}

    impl Error for AccessTokenResponseBuilderError {}

    impl Error for ErrorResponseBuilderError {}

    impl Error for AuthServerRequestCreationHintBuilderError {}
}
