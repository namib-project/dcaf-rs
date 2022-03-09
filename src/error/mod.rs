//! This module contains common error types used across this crate.

use core::fmt::{Display, Formatter};

use coset::CoseError;

// TODO: Check which errors need to be public

/// Error type used when the parameter of the [`given_type`] couldn't be converted into [`expected_type`].
///
/// Used for [`TryFrom`] conversions from a general enum type to a specific member type.
#[derive(Debug)]
pub struct WrongSourceTypeError {
    /// The general type taken in the [`TryFrom`] conversion.
    given_type: String,

    /// The specific type which [`TryFrom`] tried to convert to.
    expected_type: String,
}

impl Display for WrongSourceTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the given {} is not a {}",
            self.given_type, self.expected_type
        )
    }
}

impl WrongSourceTypeError {
    /// Creates a new instance of the error, taking the `given_type` as the general type from which
    /// the conversion was tried and the `expected_type` as the target type which it was tried to
    /// convert it into, but failed.
    pub fn new<T>(given_type: T, expected_type: T) -> WrongSourceTypeError
        where
            T: Into<String>,
    {
        WrongSourceTypeError {
            given_type: given_type.into(),
            expected_type: expected_type.into(),
        }
    }
}

/// Error type used when a given CBOR map can't be converted to a specific type which implements
/// the [`AsCborMap`] trait.
#[derive(Debug)]
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
    pub fn from_message<T>(message: T) -> TryFromCborMapError
        where
            T: Into<String>,
    {
        TryFromCborMapError {
            message: message.into(),
        }
    }

    /// Creates a new error with a message describing that an unknown field in 
    /// the CBOR map with the given `key` was encountered.
    pub fn unknown_field(key: u8) -> TryFromCborMapError {
        TryFromCborMapError {
            message: format!("unknown field with key {key} encountered"),
        }
    }

    /// Creates a new error with a message describing that a required field for
    /// the target type with the given `name` was missing from the CBOR map.
    pub fn missing_field(name: &str) -> TryFromCborMapError {
        TryFromCborMapError {
            message: format!("required field {name} is missing"),
        }
    }
}

/// Error type used when a CBOR map does not use integers as its key type, but was expected to.
#[derive(Debug)]
pub struct ValueIsNotIntegerError;

impl Display for ValueIsNotIntegerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "CBOR map key must be an integer")
    }
}

/// Error type used when a [`TextEncodedScope`] does not conform to the specification given
/// in RFC 6749.
#[derive(Debug)]
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
    Other(String),
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

/// Error type used when a [`BinaryEncodedScope`] does not conform to the specification given
/// in RFC 6749 and `draft-ietf-ace-oauth-authz`.
#[derive(Debug)]
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

// TODO: Rename to VerificationError

/// Error type used when an operation creating or receiving an access token failed.
#[derive(Debug)]
pub enum AccessTokenError {
    /// A COSE specific error occurred. 
    ///
    /// Details are contained in this field using coset's [`CoseError`].
    CoseError(CoseError),
    /// Validation of an access token failed.
    ///
    /// An optional message containing details is contained in this field.
    ValidationError(Option<String>),
}

impl Display for AccessTokenError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            AccessTokenError::CoseError(e) => write!(f, "{e}"),
            AccessTokenError::ValidationError(e) => {
                if let Some(s) = e {
                    write!(f, "validation failed: {s}")
                } else {
                    write!(f, "validation failed")
                }
            }
        }
    }
}

impl AccessTokenError {
    /// Creates a new COSE error with the given `error`.
    pub fn from_cose_error(error: CoseError) -> AccessTokenError {
        AccessTokenError::CoseError(error)
    }

    /// Creates a new validation error without any details.
    pub fn new_validation_error() -> AccessTokenError {
        AccessTokenError::ValidationError(None)
    }

    /// Creates a new validation error with `details` given as an error message.
    pub fn with_validation_error_details<T>(details: T) -> AccessTokenError
        where
            T: Into<String>,
    {
        AccessTokenError::ValidationError(Some(details.into()))
    }
}

#[cfg(feature = "std")]
mod std_error {
    use std::error::Error;

    use super::*;

    impl Error for WrongSourceTypeError {}

    impl Error for TryFromCborMapError {}

    impl Error for ValueIsNotIntegerError {}

    impl Error for InvalidTextEncodedScopeError {}

    impl Error for InvalidBinaryEncodedScopeError {}

    impl Error for AccessTokenError {}
}
