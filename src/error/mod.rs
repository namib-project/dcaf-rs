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

use core::any::type_name;
use core::fmt::{Display, Formatter};

use ciborium::value::Value;
use coset::{CoseError, Label};
use strum_macros::IntoStaticStr;

#[cfg(feature = "std")]
use {std::marker::PhantomData, std::num::TryFromIntError};
#[cfg(not(feature = "std"))]
use {
    alloc::format, alloc::string::String, alloc::string::ToString, core::num::TryFromIntError,
    derive_builder::export::core::marker::PhantomData,
};

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
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[non_exhaustive]
pub enum CoseCipherError<T>
where
    T: Display,
{
    /// A header which the cipher is supposed to set has already been set.
    HeaderAlreadySet {
        /// The name of the header which has already been set.
        existing_header_name: String,
    },
    /// The given signature or MAC tag is either invalid or does not match the given data.
    VerificationFailure,
    /// The given ciphertext could not be decrypted.
    DecryptionFailure,
    /// A different error has occurred. Details are provided in the contained error.
    Other(T),
}

impl<T> CoseCipherError<T>
where
    T: Display,
{
    /// Creates a new [`CoseCipherError`] of type
    /// [`HeaderAlreadySet`](CoseCipherError::HeaderAlreadySet) where the header
    /// that was already set has the name of the given `label`.
    #[must_use]
    pub fn existing_header_label(label: &Label) -> CoseCipherError<T> {
        let existing_header_name = match label {
            Label::Int(i) => i.to_string(),
            Label::Text(s) => s.to_string(),
        };
        CoseCipherError::HeaderAlreadySet {
            existing_header_name,
        }
    }

    /// Creates a new [`CoseCipherError`] of type
    /// [`HeaderAlreadySet`](CoseCipherError::HeaderAlreadySet) where the header
    /// that was already set has the given `name`.
    #[must_use]
    pub fn existing_header<S>(name: S) -> CoseCipherError<T>
    where
        S: Into<String>,
    {
        CoseCipherError::HeaderAlreadySet {
            existing_header_name: name.into(),
        }
    }

    /// Creates a new [`CoseCipherError`] of type
    /// [`Other`](CoseCipherError::Other) (i.e., an error type that doesn't fit any other
    /// [`CoseCipherError`] variant) containing the given nested error `other`.
    #[must_use]
    pub fn other_error(other: T) -> CoseCipherError<T> {
        CoseCipherError::Other(other)
    }

    // TODO: Maybe there's a better way to do the below, parts of this are redundant and duplicated.
    pub(crate) fn from_kek_error<C: Display>(error: CoseCipherError<T>) -> CoseCipherError<MultipleCoseError<T, C>> {
        match error {
            CoseCipherError::Other(x) => CoseCipherError::Other(MultipleCoseError::KekError(x)),
            CoseCipherError::HeaderAlreadySet { existing_header_name } => CoseCipherError::HeaderAlreadySet {
                existing_header_name
            },
            CoseCipherError::VerificationFailure => CoseCipherError::VerificationFailure,
            CoseCipherError::DecryptionFailure => CoseCipherError::DecryptionFailure
        }
    }

    pub(crate) fn from_cek_error<K: Display>(error: CoseCipherError<T>) -> CoseCipherError<MultipleCoseError<K, T>> {
        match error {
            CoseCipherError::Other(x) => CoseCipherError::Other(MultipleCoseError::CekError(x)),
            CoseCipherError::HeaderAlreadySet { existing_header_name } => CoseCipherError::HeaderAlreadySet {
                existing_header_name
            },
            CoseCipherError::VerificationFailure => CoseCipherError::VerificationFailure,
            CoseCipherError::DecryptionFailure => CoseCipherError::DecryptionFailure
        }
    }
}

impl<T> Display for CoseCipherError<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CoseCipherError::HeaderAlreadySet {
                existing_header_name,
            } => write!(
                f,
                "cipher-defined header '{existing_header_name}' already set"
            ),
            CoseCipherError::VerificationFailure => write!(f, "data verification failed"),
            CoseCipherError::DecryptionFailure => write!(f, "decryption failed"),
            CoseCipherError::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Error type used when a token for multiple recipients (i.e., `CoseEncrypt`) is decrypted.
///
/// In that case, the recipients may be encrypted with a different cipher (`K`) than the
/// actual content (`C`); hence, this error type differentiates between the two.
#[derive(Debug)]
pub enum MultipleCoseError<K, C> where K: Display, C: Display {
    /// Used when an error occurred in the Key Encryption Key's cipher.
    KekError(K),

    /// Used when an error occurred in the Content Encryption Key's cipher.
    CekError(C),
}

impl<K, C> Display for MultipleCoseError<K, C> where K: Display, C: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            MultipleCoseError::KekError(k) => k.fmt(f),
            MultipleCoseError::CekError(c) => c.fmt(f)
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
    /// No matching recipient was found in the list of COSE_Recipient structures.
    /// This means that the given Key Encryption Key could not be used to decrypt any of the
    /// recipients, which means no Content Encryption Key could be extracted.
    NoMatchingRecipient,
    /// Multiple matching recipients were found in the list of COSE_Recipient structures.
    /// This means that the given Key Encryption Key could be used to decrypt multiple of the
    /// recipients, which means the token is malformed.
    MultipleMatchingRecipients
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
            AccessTokenError::NoMatchingRecipient => write!(f, "given KEK doesn't match any recipient"),
            AccessTokenError::MultipleMatchingRecipients => write!(f, "given KEK matches multiple recipients")
        }
    }
}

impl<T> From<CoseCipherError<T>> for AccessTokenError<T> where T: Display {
    #[must_use]
    fn from(error: CoseCipherError<T>) -> Self {
        AccessTokenError::CoseCipherError(error)
    }
}

impl<T> From<CoseError> for AccessTokenError<T> where T: Display {
    #[must_use]
    fn from(error: CoseError) -> Self {
        AccessTokenError::CoseError(error)
    }
}

#[allow(dead_code)]
impl<T> AccessTokenError<T>
where
    T: Display {

    // TODO: Again, as in CoseCipherError, maybe there's a better way to do the below.

    pub(crate) fn from_kek_error<C: Display>(error: AccessTokenError<T>) -> AccessTokenError<MultipleCoseError<T, C>> {
        match error {
            AccessTokenError::CoseCipherError(x) => AccessTokenError::CoseCipherError(CoseCipherError::from_kek_error(x)),
            AccessTokenError::CoseError(x) => AccessTokenError::CoseError(x),
            AccessTokenError::UnknownCoseStructure => AccessTokenError::UnknownCoseStructure,
            AccessTokenError::NoMatchingRecipient => AccessTokenError::NoMatchingRecipient,
            AccessTokenError::MultipleMatchingRecipients => AccessTokenError::MultipleMatchingRecipients,
        }
    }

    pub(crate) fn from_cek_error<K: Display>(error: AccessTokenError<T>) -> AccessTokenError<MultipleCoseError<K, T>> {
        match error {
            AccessTokenError::CoseCipherError(x) => AccessTokenError::CoseCipherError(CoseCipherError::from_cek_error(x)),
            AccessTokenError::CoseError(x) => AccessTokenError::CoseError(x),
            AccessTokenError::UnknownCoseStructure => AccessTokenError::UnknownCoseStructure,
            AccessTokenError::NoMatchingRecipient => AccessTokenError::NoMatchingRecipient,
            AccessTokenError::MultipleMatchingRecipients => AccessTokenError::MultipleMatchingRecipients,
        }
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
