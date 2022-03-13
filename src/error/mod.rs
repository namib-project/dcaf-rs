//! Contains common error types used across this crate.

use core::fmt::{Display, Formatter};

use coset::{CoseError, Label};

// TODO: Check which errors need to be public

/// Error type used when the parameter of the [`given_type`] couldn't be converted into [`expected_type`].
///
/// Used for [`TryFrom`] conversions from a general enum type to a specific member type.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
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
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ValueIsNotIntegerError;

impl Display for ValueIsNotIntegerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "CBOR map key must be an integer")
    }
}

/// Error type used when a [`TextEncodedScope`] does not conform to the specification given
/// in RFC 6749.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
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

// TODO: Replace all instances of validation with verification

/// Error type used when a [`CoseEncrypt0Cipher`], [`CoseSign1Cipher`], or [`CoseMac0Cipher`]
/// fails to perform an operation.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum CoseCipherError<T> where T: Display {
    /// A header which the cipher is supposed to set has already been set.
    HeaderAlreadySet {
        /// The name of the header which has already been set.
        existing_header_name: String,
    },
    /// The given signature or MAC tag is either invalid or does not match the given data.
    VerificationFailure,
    /// A different error has occurred. Details are provided in the contained error.
    Other(T),
}

impl<T> CoseCipherError<T> where T: Display {
    pub fn existing_header_label(label: &Label) -> CoseCipherError<T> {
        let existing_header_name;
        match label {
            Label::Int(i) => existing_header_name = i.to_string(),
            Label::Text(s) => existing_header_name = s.to_string(),
        }
        CoseCipherError::HeaderAlreadySet {
            existing_header_name,
        }
    }

    pub fn existing_header(name: &str) -> CoseCipherError<T> {
        CoseCipherError::HeaderAlreadySet {
            existing_header_name: name.to_string(),
        }
    }

    pub fn other_error(other: T) -> CoseCipherError<T> {
        CoseCipherError::Other(other)
    }
}

impl<T> Display for CoseCipherError<T> where T: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            CoseCipherError::HeaderAlreadySet {
                existing_header_name,
            } => write!(
                f,
                "cipher-defined header '{existing_header_name}' already set"
            ),
            CoseCipherError::VerificationFailure => write!(f, "data verification failed"),
            CoseCipherError::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Error type used when an operation creating or receiving an access token failed.
#[derive(Debug)]
pub enum AccessTokenError<T> where T: Display {
    /// A COSE specific error occurred.
    ///
    /// Details are contained in this field using coset's [`CoseError`].
    CoseError(CoseError),
    /// A cryptographic CoseCipher operation has failed.
    ///
    /// Details are contained in this field.
    CoseCipherError(CoseCipherError<T>),
    /// Headers can't be extracted because the input data is neither a
    /// [`CoseEncrypt0`], [`CoseSign1`], nor [`CoseMac0`].
    UnknownCoseStructure,
}

impl<T> Display for AccessTokenError<T> where T: Display {
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

impl<T> AccessTokenError<T> where T: Display {
    /// Creates a new COSE error with the given `error`.
    pub fn from_cose_error(error: CoseError) -> AccessTokenError<T> {
        AccessTokenError::CoseError(error)
    }

    pub fn from_cose_cipher_error(error: CoseCipherError<T>) -> AccessTokenError<T> {
        AccessTokenError::CoseCipherError(error)
    }
}

#[cfg(feature = "std")]
mod std_error {
    use core::fmt::Debug;
    use std::error::Error;

    use super::*;

    impl Error for WrongSourceTypeError {}

    impl Error for TryFromCborMapError {}

    impl Error for ValueIsNotIntegerError {}

    impl Error for InvalidTextEncodedScopeError {}

    impl Error for InvalidBinaryEncodedScopeError {}

    impl<T> Error for CoseCipherError<T> where T: Debug + Display {}

    impl<T> Error for AccessTokenError<T> where T: Debug + Display {}
}
