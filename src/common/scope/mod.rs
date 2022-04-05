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
use bitflags::bitflags;
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

bitflags! {
    #[derive(Serialize)]
    pub struct AifRestMethodSet: u64 {
        const GET = u64::pow(2, 0);
        const POST = u64::pow(2, 1);
        const PUT = u64::pow(2, 2);
        const DELETE = u64::pow(2, 3);
        const FETCH = u64::pow(2, 4);
        const PATCH = u64::pow(2, 5);
        const IPATCH = u64::pow(2, 6);
        const DYNAMIC_GET = u64::pow(2, 32);
        const DYNAMIC_POST = u64::pow(2, 33);
        const DYNAMIC_PUT = u64::pow(2, 34);
        const DYNAMIC_DELETE = u64::pow(2, 35);
        const DYNAMIC_FETCH = u64::pow(2, 36);
        const DYNAMIC_PATCH = u64::pow(2, 37);
        const DYNAMIC_IPATCH = u64::pow(2, 38);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct AifEncodedScopeElement {
    pub path: String,
    pub permissions: AifRestMethodSet,
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct AifEncodedScope(Vec<AifEncodedScopeElement>);

#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize)]
pub struct LibdcafEncodedScope(AifEncodedScopeElement);

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
#[derive(Debug, PartialEq, Eq, Clone, Hash, IntoStaticStr)]
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

    // TODO: Docs & Tests
    AifEncoded(AifEncodedScope),
    LibdcafEncoded(LibdcafEncodedScope),
}

/// Contains conversion methods for ACE-OAuth data types.
/// One part of this is converting enum types from and to their CBOR abbreviations in
/// [`cbor_abbreviations`](crate::constants::cbor_abbreviations),
/// another part is implementing the [`ToCborMap`](crate::ToCborMap) type for the
/// models which are represented as CBOR maps.
mod conversion {
    use crate::error::{
        InvalidAifEncodedScopeError, InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError,
        ScopeFromValueError, WrongSourceTypeError,
    };
    use ciborium::value::{Integer, Value};
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

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

    impl AifEncodedScopeElement {
        #[must_use]
        pub fn new(path: String, permissions: AifRestMethodSet) -> AifEncodedScopeElement {
            AifEncodedScopeElement { path, permissions }
        }

        #[must_use]
        pub fn try_from_bits(
            path: String,
            permissions: u64,
        ) -> Result<AifEncodedScopeElement, InvalidAifEncodedScopeError> {
            AifRestMethodSet::from_bits(permissions)
                .ok_or(InvalidAifEncodedScopeError::InvalidRestMethodSet)
                .map(|permissions| AifEncodedScopeElement { path, permissions })
        }

        fn into_cbor_value(self) -> Value {
            Value::Array(vec![
                Value::Text(self.path),
                Value::Integer(Integer::from(self.permissions.bits)),
            ])
        }
    }

    impl AifEncodedScope {
        #[must_use]
        pub fn elements(&self) -> &Vec<AifEncodedScopeElement> {
            &self.0
        }

        #[must_use]
        pub fn to_elements(self) -> Vec<AifEncodedScopeElement> {
            self.0
        }

        #[must_use]
        pub fn new(elements: Vec<AifEncodedScopeElement>) -> AifEncodedScope {
            AifEncodedScope(elements)
        }
    }

    impl Serialize for AifEncodedScopeElement {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
            Value::Array(vec![Value::Text(self.path.clone()),
                              Value::Integer(Integer::from(self.permissions.bits))])
                .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for AifRestMethodSet {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
            if let Ok(Value::Integer(i)) = Value::deserialize(deserializer) {
                let number = u64::try_from(i).map_err(|_| D::Error::custom("invalid integer value"))?;
                AifRestMethodSet::from_bits(number).ok_or_else(|| D::Error::custom("invalid bitfield value"))
            } else {
                Err(D::Error::custom("AifRestMethodSet must be an integer".to_string()))
            }
        }
    }

    impl From<Vec<(String, AifRestMethodSet)>> for AifEncodedScope {
        fn from(value: Vec<(String, AifRestMethodSet)>) -> Self {
            AifEncodedScope::new(
                value
                    .into_iter()
                    .map(|(path, set)| AifEncodedScopeElement::new(path, set))
                    .collect(),
            )
        }
    }

    impl TryFrom<Vec<(String, u64)>> for AifEncodedScope {
        type Error = InvalidAifEncodedScopeError;

        fn try_from(value: Vec<(String, u64)>) -> Result<Self, Self::Error> {
            Ok(AifEncodedScope::new(
                value
                    .into_iter()
                    .map(|(path, rest)| AifEncodedScopeElement::try_from_bits(path, rest))
                    .collect::<Result<Vec<AifEncodedScopeElement>, InvalidAifEncodedScopeError>>()?,
            ))
        }
    }

    impl LibdcafEncodedScope {
        #[must_use]
        pub fn new(element: AifEncodedScopeElement) -> LibdcafEncodedScope {
            LibdcafEncodedScope(element)
        }

        #[must_use]
        pub fn elements(&self) -> Vec<&AifEncodedScopeElement> {
            vec![&self.0]
        }

        #[must_use]
        pub fn to_elements(self) -> Vec<AifEncodedScopeElement> {
            vec![self.0]
        }

        pub fn try_from_bits(
            path: String,
            permissions: u64,
        ) -> Result<LibdcafEncodedScope, InvalidAifEncodedScopeError> {
            Ok(LibdcafEncodedScope::new(
                AifEncodedScopeElement::try_from_bits(path, permissions)?,
            ))
        }
    }

    impl From<LibdcafEncodedScope> for Scope {
        fn from(value: LibdcafEncodedScope) -> Self {
            Scope::LibdcafEncoded(value)
        }
    }

    impl From<AifEncodedScope> for Scope {
        fn from(value: AifEncodedScope) -> Self {
            Scope::AifEncoded(value)
        }
    }

    impl From<TextEncodedScope> for Scope {
        fn from(value: TextEncodedScope) -> Self {
            Scope::TextEncoded(value)
        }
    }

    impl From<BinaryEncodedScope> for Scope {
        fn from(value: BinaryEncodedScope) -> Self {
            Scope::BinaryEncoded(value)
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

    impl TryFrom<Vec<(String, u64)>> for Scope {
        type Error = InvalidAifEncodedScopeError;

        fn try_from(value: Vec<(String, u64)>) -> Result<Self, Self::Error> {
            Ok(Scope::from(AifEncodedScope::try_from(value)?))
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

    impl TryFrom<Scope> for AifEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::AifEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("AifEncoded", value.into()))
            }
        }
    }

    impl TryFrom<Scope> for LibdcafEncodedScope {
        type Error = WrongSourceTypeError<Scope>;

        fn try_from(value: Scope) -> Result<Self, Self::Error> {
            if let Scope::LibdcafEncoded(scope) = value {
                Ok(scope)
            } else {
                Err(WrongSourceTypeError::new("LibdcafEncoded", value.into()))
            }
        }
    }

    impl From<Scope> for Value {
        fn from(scope: Scope) -> Self {
            match scope {
                Scope::TextEncoded(text) => Value::Text(text.0),
                Scope::BinaryEncoded(binary) => Value::Bytes(binary.0),
                Scope::AifEncoded(aif) => Value::Array(
                    aif.to_elements()
                        .into_iter()
                        .map(AifEncodedScopeElement::into_cbor_value)
                        .collect(),
                ),
                Scope::LibdcafEncoded(lib) => lib.0.into_cbor_value(),
            }
        }
    }

    impl TryFrom<Value> for Scope {
        type Error = ScopeFromValueError;

        fn try_from(value: Value) -> Result<Self, Self::Error> {
            fn value_to_aif_element(
                value: Value,
            ) -> Result<AifEncodedScopeElement, InvalidAifEncodedScopeError> {
                let values = value
                    .as_array()
                    .ok_or(InvalidAifEncodedScopeError::MalformedArray)?;
                let path = values
                    .first()
                    .and_then(Value::as_text)
                    .ok_or(InvalidAifEncodedScopeError::MalformedArray)?
                    .to_string();
                let permissions = values
                    .get(1)
                    .and_then(|x| {
                        x.as_integer().map(|x| {
                            u64::try_from(x)
                                .map(|x| AifRestMethodSet::from_bits(x))
                                .ok()
                        })
                    })
                    .flatten()
                    .flatten() // better than ???, I guess
                    .ok_or(InvalidAifEncodedScopeError::MalformedArray)?;
                Ok(AifEncodedScopeElement::new(path, permissions))
            }

            match value {
                Value::Bytes(b) => Ok(Scope::BinaryEncoded(BinaryEncodedScope::try_from(
                    b.as_slice(),
                )?)),
                Value::Text(t) => Ok(Scope::TextEncoded(TextEncodedScope::try_from(t.as_str())?)),
                Value::Array(a) => {
                    if a.first().filter(|x| x.is_text()).is_some() {
                        // Special handling for libdcaf
                        Ok(Scope::LibdcafEncoded(LibdcafEncodedScope(
                            value_to_aif_element(Value::Array(a))?,
                        )))
                    } else {
                        a.into_iter()
                            .map(value_to_aif_element)
                            .collect::<Result<Vec<AifEncodedScopeElement>, InvalidAifEncodedScopeError>>()
                            .map(|x| Scope::AifEncoded(AifEncodedScope::new(x)))
                            .map_err(|x| ScopeFromValueError::InvalidAifEncodedScope(x))
                    }
                }
                v => Err(ScopeFromValueError::invalid_type(&v)),
            }
        }
    }

    impl Serialize for Scope {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
            Value::from(self.clone()).serialize(serializer)
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
