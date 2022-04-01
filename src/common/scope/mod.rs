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

//! Contains data types and methods for working with OAuth scopes.
//!
//! The main use case of this module is creating [Scope] instances for either text- or
//! binary-encoded scopes, whose elements can then be extracted using the `elements()` method.
//!
//! # Example
//! For example, you could first create a text or binary encoded scope:
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{BinaryEncodedScope, TextEncodedScope};
//! # use dcaf::error::{InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError};
//! # use dcaf::Scope;
//! // Will be encoded with a space-separator.
//! let text_scope = TextEncodedScope::try_from(vec!["first_client", "second_client"])?;
//! assert_eq!(text_scope.to_string(), "first_client second_client");
//! assert!(text_scope.elements().eq(vec!["first_client", "second_client"]));
//! // Separator is only specified upon `elements` call.
//! let binary_scope = BinaryEncodedScope::try_from(vec![1, 2, 0, 3, 4].as_slice())?;
//! assert!(binary_scope.elements(Some(0))?.eq(&vec![vec![1, 2], vec![3, 4]]));
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! And then you could wrap it in the [Scope] type and use it in a field,
//! e.g. in an [`AuthServerRequestCreationHint`](crate::AuthServerRequestCreationHint):
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{BinaryEncodedScope, TextEncodedScope};
//! # use dcaf::{AuthServerRequestCreationHint, Scope};
//! # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
//! # let text_scope = TextEncodedScope::try_from(vec!["first_client", "second_client"])?;
//! # let original_scope = text_scope.clone();
//! # let binary_scope = BinaryEncodedScope::try_from(vec![1, 2, 0, 3, 4].as_slice())?;
//! let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder().scope(Scope::from(text_scope)).build()?;
//! # assert_eq!(hint.scope, Some(Scope::from(original_scope)));
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! This works with the binary encoded scope too, of course:
//! ```
//! # use std::error::Error;
//! # use dcaf::common::scope::{BinaryEncodedScope, TextEncodedScope};
//! # use dcaf::{AuthServerRequestCreationHint, Scope};
//! # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
//! # let binary_scope = BinaryEncodedScope::try_from(vec![1, 2, 0, 3, 4].as_slice())?;
//! # let original_scope = binary_scope.clone();
//! let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder().scope(Scope::from(binary_scope)).build()?;
//! # assert_eq!(hint.scope, Some(Scope::from(original_scope)));
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//! # Sources
//! For the original OAuth 2.0 standard, scopes are defined in
//! [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3),
//! while for ACE-OAuth, they're specified in
//! [`draft-ietf-ace-oauth-authz`, section 5.8.1](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.1-2.4).

use alloc::string::String;
use core::fmt::{Display, Formatter};
use strum_macros::IntoStaticStr;

use crate::common::cbor_values::ByteString;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// A scope encoded as a space-delimited list of strings, as defined in
/// [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3).
///
/// Note that the syntax specified in the RFC has to be followed:
/// ```text
/// scope       = scope-token *( SP scope-token )
/// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
/// ```
///
/// # Example
///
/// You can create a `TextEncodedScope` from a space-separated string:
/// ```
/// # use dcaf::common::scope::TextEncodedScope;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// let scope = TextEncodedScope::try_from("first second third")?;
/// assert!(scope.elements().eq(["first", "second", "third"]));
/// # Ok::<(), InvalidTextEncodedScopeError>(())
/// ```
/// It's also possible to pass in a vector of strings:
/// ```
/// # use dcaf::common::scope::TextEncodedScope;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// let scope = TextEncodedScope::try_from(vec!["first", "second", "third"])?;
/// assert!(scope.elements().eq(["first", "second", "third"]));
/// assert!(TextEncodedScope::try_from(vec!["not allowed"]).is_err());
/// # Ok::<(), InvalidTextEncodedScopeError>(())
/// ```
///
/// But note that you have to follow the syntax from the RFC (which implicitly specifies
/// that given scopes can't be empty):
/// ```
/// # use dcaf::common::scope::TextEncodedScope;
/// assert!(TextEncodedScope::try_from("can't use \\ or \"").is_err());
/// assert!(TextEncodedScope::try_from("  no   weird spaces ").is_err());
/// assert!(TextEncodedScope::try_from(vec![]).is_err());
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct TextEncodedScope(String);

impl Display for TextEncodedScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A scope encoded using a custom binary encoding.
/// See [Scope] for more information.
///
/// # Example
///
/// Simply create a `BinaryEncodedScope` from a byte array (we're using the byte `0x21` as
/// a separator in this example):
/// ```
/// # use dcaf::common::scope::{BinaryEncodedScope};
/// # use dcaf::error::InvalidBinaryEncodedScopeError;
/// let scope = BinaryEncodedScope::try_from(vec![0x00, 0x21, 0xDC, 0xAF].as_slice())?;
/// assert!(scope.elements(Some(0x21))?.eq(&vec![vec![0x00], vec![0xDC, 0xAF]]));
/// # Ok::<(), InvalidBinaryEncodedScopeError>(())
/// ```
///
/// But note that the input array can't be empty:
/// ```
/// # use dcaf::common::scope::BinaryEncodedScope;
/// assert!(BinaryEncodedScope::try_from(vec![].as_slice()).is_err());
/// ```
///
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct BinaryEncodedScope(ByteString);

/// Scope of an access token as specified in
/// [`draft-ietf-ace-oauth-authz`, section 5.8.1](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.1-2.4).
///
/// May be used both for [AccessTokenRequest](crate::AccessTokenRequest)s and
/// [AccessTokenResponse](crate::AccessTokenResponse)s.
/// Note that you rarely need to create instances of this type for that purpose,
/// instead you can just pass in the concrete [TextEncodedScope] or [BinaryEncodedScope] directly
/// into the builder.
///
/// AIF (from [`draft-ietf-ace-aif`](https://datatracker.ietf.org/doc/html/draft-ietf-ace-aif))
/// support is planned, but not yet implemented.
///
/// # Example
///
/// You can create binary or text encoded scopes:
/// ```
/// # use std::error::Error;
/// # use dcaf::common::scope::{BinaryEncodedScope, Scope, TextEncodedScope};
/// # use dcaf::error::{InvalidTextEncodedScopeError, InvalidBinaryEncodedScopeError};
/// let text_scope = Scope::from(TextEncodedScope::try_from("dcaf rs")?);
/// let binary_scope = Scope::from(BinaryEncodedScope::try_from(vec![0xDC, 0xAF].as_slice())?);
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// For information on how to initialize [BinaryEncodedScope] and [TextEncodedScope],
/// or retrieve the individual elements inside them, see their respective documentation pages.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, IntoStaticStr)]
#[serde(untagged)]
pub enum Scope {
    /// Scope encoded using Text, as specified in
    /// [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3).
    ///
    /// # Example
    /// Creating a scope containing "device_alpha" and "device_beta" (note that spaces in their
    /// name wouldn't work):
    /// ```
    /// # use dcaf::common::scope::TextEncodedScope;
    /// # use dcaf::error::InvalidTextEncodedScopeError;
    /// let scope = TextEncodedScope::try_from(vec!["device_alpha", "device_beta"])?;
    /// assert_eq!(scope, TextEncodedScope::try_from("device_alpha device_beta")?);
    /// assert!(scope.elements().eq(vec!["device_alpha", "device_beta"]));
    /// assert!(TextEncodedScope::try_from(vec!["device alpha", "device beta"]).is_err());
    /// # Ok::<(), InvalidTextEncodedScopeError>(())
    /// ```
    TextEncoded(TextEncodedScope),

    /// Scope encoded using custom binary encoding.
    /// # Example
    /// Creating a scope containing 0xDCAF and 0xAFDC with a separator of 0x00:
    /// ```
    /// # use dcaf::common::scope::BinaryEncodedScope;
    /// # use dcaf::error::InvalidBinaryEncodedScopeError;
    /// let scope = BinaryEncodedScope::try_from(vec![0xDC, 0xAF, 0x00, 0xAF, 0xDC].as_slice())?;
    /// assert!(scope.elements(Some(0x00))?.eq(&vec![vec![0xDC, 0xAF], vec![0xAF, 0xDC]]));
    /// assert!(scope.elements(None)?.eq(&vec![vec![0xDC, 0xAF, 0x00, 0xAF, 0xDC]]));
    /// assert!(scope.elements(Some(0xDC)).is_err());  // no separators at the beginning or end
    /// # Ok::<(), InvalidBinaryEncodedScopeError>(())
    /// ```
    BinaryEncoded(BinaryEncodedScope),
    // TODO: Implement proper AIF support
}

/// Contains conversion methods for ACE-OAuth data types.
/// One part of this is converting enum types from and to their CBOR abbreviations in
/// [`cbor_abbreviations`](crate::constants::cbor_abbreviations),
/// another part is implementing the [`ToCborMap`](crate::ToCborMap) type for the
/// models which are represented as CBOR maps.
mod conversion {
    use crate::error::{
        InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError, ScopeFromValueError,
        WrongSourceTypeError,
    };
    use ciborium::value::Value;
    use serde::de::Error;
    use serde::Deserializer;

    use super::*;

    impl TextEncodedScope {
        /// Return the individual elements (i.e., access ranges) of this scope.
        ///
        /// Post-condition: The returned iterator will not be empty, and none of its elements
        /// may contain spaces (` `), double-quotes (`"`) or backslashes (`\\'`).
        ///
        /// # Example
        ///
        /// ```
        /// # use dcaf::common::scope::TextEncodedScope;
        /// # use dcaf::error::InvalidTextEncodedScopeError;
        /// let simple = TextEncodedScope::try_from("this is a test")?;
        /// assert!(simple.elements().eq(vec!["this", "is", "a", "test"]));
        /// # Ok::<(), InvalidTextEncodedScopeError>(())
        /// ```
        pub fn elements(&self) -> impl Iterator<Item = &str> {
            self.0.split(' ')
        }
    }

    impl TryFrom<&str> for TextEncodedScope {
        type Error = InvalidTextEncodedScopeError;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            if value.ends_with(' ') {
                Err(InvalidTextEncodedScopeError::EndsWithSeparator)
            } else if value.starts_with(' ') {
                Err(InvalidTextEncodedScopeError::StartsWithSeparator)
            } else if value.contains(['"', '\\']) {
                Err(InvalidTextEncodedScopeError::IllegalCharacters)
            } else if value.contains("  ") {
                Err(InvalidTextEncodedScopeError::ConsecutiveSeparators)
            } else if value.is_empty() {
                Err(InvalidTextEncodedScopeError::EmptyScope)
            } else {
                Ok(TextEncodedScope(value.into()))
            }
        }
    }

    impl TryFrom<Vec<&str>> for TextEncodedScope {
        type Error = InvalidTextEncodedScopeError;

        fn try_from(value: Vec<&str>) -> Result<Self, Self::Error> {
            if value.iter().any(|x| x.contains([' ', '\\', '"'])) {
                Err(InvalidTextEncodedScopeError::IllegalCharacters)
            } else if value.iter().any(|x| x.is_empty()) {
                Err(InvalidTextEncodedScopeError::EmptyElement)
            } else if value.is_empty() {
                Err(InvalidTextEncodedScopeError::EmptyScope)
            } else {
                // Fold the vec into a single string, using space as a separator
                Ok(TextEncodedScope(value.join(" ")))
            }
        }
    }

    impl BinaryEncodedScope {
        /// Return the individual elements (i.e., access ranges) of this scope.
        ///
        /// If no separator is given (i.e. it is `None`), it is assumed that the scope consists
        /// of a single element and will be returned as such.
        ///
        /// ## Pre-conditions
        /// - If a separator is given, it may neither be the first nor last element of the scope.
        /// - If a separator is given, it may not occur twice in a row in the scope.
        /// - The scope must not be empty.
        ///
        /// ## Post-conditions
        /// - The returned vector will not be empty.
        /// - None of its elements will be empty.
        /// - If a separator is given, none of its elements will contain it.
        /// - If no separator is given, the vector will consist of a single element, containing
        ///   the whole binary-encoded scope.
        ///
        /// # Example
        ///
        /// ```
        /// # use dcaf::common::scope::BinaryEncodedScope;
        /// # use dcaf::error::InvalidBinaryEncodedScopeError;
        /// let simple = BinaryEncodedScope::try_from(vec![0xDC, 0x21, 0xAF].as_slice())?;
        /// assert!(simple.elements(Some(0x21))?.eq(&vec![vec![0xDC], vec![0xAF]]));
        /// assert!(simple.elements(None)?.eq(&vec![vec![0xDC, 0x21, 0xAF]]));
        /// assert!(simple.elements(Some(0xDC)).is_err());
        /// # Ok::<(), InvalidBinaryEncodedScopeError>(())
        /// ```
        ///
        /// # Errors
        /// - If the binary encoded scope separated by the given `separator` is invalid in any way.
        ///   This may be the case if:
        ///   - The scope starts with a separator
        ///   - The scope ends with a separator
        ///   - The scope contains two separators in a row.
        ///
        /// # Panics
        /// If the pre-condition that the scope isn't empty is violated.
        /// This shouldn't occur, as it's an invariant of [BinaryEncodedScope].
        pub fn elements(
            &self,
            separator: Option<u8>,
        ) -> Result<Vec<&[u8]>, InvalidBinaryEncodedScopeError> {
            // We use an assert rather than an Error because the client is not expected to handle this.
            assert!(
                !self.0.is_empty(),
                "Invariant violated: Scope may not be empty"
            );
            if let Some(separator) = separator {
                let split = self.0.split(move |x| x == &separator);
                if self.0.first().filter(|x| **x != separator).is_none() {
                    Err(InvalidBinaryEncodedScopeError::StartsWithSeparator(
                        separator,
                    ))
                } else if self.0.last().filter(|x| **x != separator).is_none() {
                    Err(InvalidBinaryEncodedScopeError::EndsWithSeparator(separator))
                } else if self.0.windows(2).any(|x| x[0] == x[1] && x[1] == separator) {
                    Err(InvalidBinaryEncodedScopeError::ConsecutiveSeparators(
                        separator,
                    ))
                } else {
                    debug_assert!(
                        split.clone().all(|x| !x.is_empty()),
                        "Post-condition violated: Result may not contain empty slices"
                    );
                    Ok(split.collect())
                }
            } else {
                // no separator given
                Ok(vec![self.0.as_slice()])
            }
        }
    }

    impl TryFrom<&[u8]> for BinaryEncodedScope {
        type Error = InvalidBinaryEncodedScopeError;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            let vec = value.to_vec();
            if vec.is_empty() {
                Err(InvalidBinaryEncodedScopeError::EmptyScope)
            } else {
                Ok(BinaryEncodedScope(vec))
            }
        }
    }

    impl From<TextEncodedScope> for Scope {
        fn from(value: TextEncodedScope) -> Self {
            Scope::TextEncoded(value)
        }
    }

    impl TryFrom<Vec<&str>> for Scope {
        type Error = InvalidTextEncodedScopeError;

        fn try_from(value: Vec<&str>) -> Result<Self, InvalidTextEncodedScopeError> {
            Ok(Scope::from(TextEncodedScope::try_from(value)?))
        }
    }

    impl TryFrom<&[u8]> for Scope {
        type Error = InvalidBinaryEncodedScopeError;

        fn try_from(value: &[u8]) -> Result<Self, InvalidBinaryEncodedScopeError> {
            Ok(Scope::from(BinaryEncodedScope::try_from(value)?))
        }
    }

    impl From<BinaryEncodedScope> for Scope {
        fn from(value: BinaryEncodedScope) -> Self {
            Scope::BinaryEncoded(value)
        }
    }

    impl TryFrom<Scope> for BinaryEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::BinaryEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("BinaryEncoded", value.into()))
            }
        }
    }

    impl TryFrom<Scope> for TextEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::TextEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("TextEncoded", value.into()))
            }
        }
    }

    impl From<Scope> for Value {
        fn from(scope: Scope) -> Self {
            match scope {
                Scope::TextEncoded(text) => Value::Text(text.0),
                Scope::BinaryEncoded(binary) => Value::Bytes(binary.0),
            }
        }
    }

    impl TryFrom<Value> for Scope {
        type Error = ScopeFromValueError;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            match value {
                Value::Bytes(b) => Ok(Scope::BinaryEncoded(BinaryEncodedScope::try_from(
                    b.as_slice(),
                )?)),
                Value::Text(t) => Ok(Scope::TextEncoded(TextEncodedScope::try_from(t.as_str())?)),
                Value::Array(_) => Err(ScopeFromValueError::AifScopeIsUnsupported),
                v => Err(ScopeFromValueError::invalid_type(&v)),
            }
        }
    }

    impl<'de> Deserialize<'de> for Scope {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            Scope::try_from(Value::deserialize(deserializer)?)
                .map_err(|x| D::Error::custom(x.to_string()))
        }
    }
}
