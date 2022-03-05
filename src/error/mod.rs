//! This module contains common error types used across this crate.

use core::fmt::{Display, Formatter};

use coset::CoseError;

// TODO: Check which errors need to be public

#[derive(Debug)]
pub struct WrongSourceTypeError {
    target_type: String,
    expected_type: String,
}

impl Display for WrongSourceTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the given {} is not a {}",
            self.target_type, self.expected_type
        )
    }
}

impl WrongSourceTypeError {
    pub fn new<T>(target_type: T, expected_type: T) -> WrongSourceTypeError
        where
            T: Into<String>,
    {
        WrongSourceTypeError {
            target_type: target_type.into(),
            expected_type: expected_type.into(),
        }
    }
}

#[derive(Debug)]
pub struct TryFromCborMapError {
    message: String,
}

impl Display for TryFromCborMapError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl TryFromCborMapError {
    pub fn from_message<T>(message: T) -> TryFromCborMapError
        where
            T: Into<String>,
    {
        TryFromCborMapError {
            message: message.into(),
        }
    }

    pub fn unknown_field(key: u8) -> TryFromCborMapError {
        TryFromCborMapError {
            message: format!("unknown field with key {key} encountered"),
        }
    }

    pub fn missing_field(name: &str) -> TryFromCborMapError {
        TryFromCborMapError {
            message: format!("required field {name} is missing"),
        }
    }
}

#[derive(Debug)]
pub struct ValueIsNotIntegerError;

impl Display for ValueIsNotIntegerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "CBOR map key must be an integer")
    }
}

#[derive(Debug)]
pub struct BuilderValidationError {
    pub(crate) message: String,
}

impl Display for BuilderValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug)]
pub enum InvalidTextEncodedScopeError {
    StartsWithSeparator,
    EndsWithSeparator,
    ConsecutiveSeparators,
    EmptyElement,
    EmptyScope,
    IllegalCharacters,
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
                "must not contain illegal characters '\\' and '\"'"
            }
            InvalidTextEncodedScopeError::Other(s) => s,
        };
        write!(
            f,
            "text-encoded scope must follow format specified in RFC 6749 ({message})"
        )
    }
}

#[derive(Debug)]
pub enum InvalidBinaryEncodedScopeError {
    StartsWithSeparator(u8),
    EndsWithSeparator(u8),
    ConsecutiveSeparators(u8),
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

#[derive(Debug)]
pub enum AccessTokenError {
    CoseError(CoseError),
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
    pub fn from_cose_error(error: CoseError) -> AccessTokenError {
        AccessTokenError::CoseError(error)
    }

    pub fn new_validation_error() -> AccessTokenError {
        AccessTokenError::ValidationError(None)
    }

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

    impl Error for BuilderValidationError {}

    impl Error for InvalidTextEncodedScopeError {}

    impl Error for InvalidBinaryEncodedScopeError {}

    impl Error for AccessTokenError {}
}
