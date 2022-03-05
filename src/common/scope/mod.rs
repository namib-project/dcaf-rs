use alloc::string::String;
use core::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::common::ByteString;

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
/// dbg!(&scope);
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
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
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
/// assert!(scope.elements(0x21)?.eq(vec![vec![0x00], vec![0xDC, 0xAF]]));
/// # Ok::<(), InvalidBinaryEncodedScopeError>(())
/// ```
///
/// But note that the input array can't be empty:
/// ```
/// # use dcaf::common::scope::BinaryEncodedScope;
/// assert!(BinaryEncodedScope::try_from(vec![].as_slice()).is_err());
/// ```
///
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
pub struct BinaryEncodedScope(ByteString);

/// Scope of an access token as specified in
/// [`draft-ietf-ace-oauth-authz`, section 5.8.1](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.1-2.4).
/// May be used both for [AccessTokenRequest]s and [AccessTokenResponse]s.
///
/// AIF (from [`draft-ietf-ace-aif`](https://datatracker.ietf.org/doc/html/draft-ietf-ace-aif))
/// support is planned, but not yet implemented.
///
/// # Example
///
/// You can create binary or text encoded scopes:
/// ```
/// # use dcaf::common::scope::{BinaryEncodedScope, Scope, TextEncodedScope};
/// # use dcaf::error::{InvalidTextEncodedScopeError, InvalidBinaryEncodedScopeError};
/// # // We need to trick around a little due to the different error types.
/// # fn main() -> Result<(), InvalidTextEncodedScopeError> {
/// let text_scope = Scope::from(TextEncodedScope::try_from("dcaf rs")?);
/// # fn binary() -> Result<(), InvalidBinaryEncodedScopeError> {
/// let binary_scope = Scope::from(BinaryEncodedScope::try_from(vec![0xDC, 0xAF].as_slice())?);
/// # Ok(())
/// # }
/// # binary().map_err(|x| InvalidTextEncodedScopeError::Other(x.to_string()))?;
/// # Ok(())
/// # }
/// ```
///
/// For information on how to initialize [BinaryEncodedScope] and [TextEncodedScope],
/// or retrieve the individual elements inside them, see their respective documentation pages.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scope {
    /// Scope encoded using Text, as specified in
    /// [RFC 6749, section 1.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3).
    TextEncoded(TextEncodedScope),

    /// Scope encoded using custom binary encoding.
    BinaryEncoded(BinaryEncodedScope),
    // TODO: Implement proper AIF support
}

mod conversion {
    //! Contains conversion methods for ACE-OAuth data types.
    //! One part of this is converting enum types from and to their CBOR abbreviations in
    //! [`cbor_abbreviations`], another part is implementing the [`AsCborMap`] type for the
    //! models which are represented as CBOR maps.

    use crate::error::{InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError};

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
        pub fn elements(&self) -> impl Iterator<Item=&str> {
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
        /// ## Pre-conditions
        /// - The given separator may neither be the first nor last element of the scope.
        /// - The given separator may not occur twice in a row in the scope.
        /// - The scope must not be empty.
        ///
        /// ## Post-conditions
        /// - The returned iterator will not be empty.
        /// - None of its elements will be empty.
        /// - None of its elements will contain the given separator.
        ///
        /// # Example
        ///
        /// ```
        /// # use dcaf::common::scope::BinaryEncodedScope;
        /// # use dcaf::error::InvalidBinaryEncodedScopeError;
        /// let simple = BinaryEncodedScope::try_from(vec![0xDC, 0x21, 0xAF].as_slice())?;
        /// assert!(simple.elements(0x21)?.eq(vec![vec![0xDC], vec![0xAF]]));
        /// assert!(simple.elements(0xDC).is_err());
        /// # Ok::<(), InvalidBinaryEncodedScopeError>(())
        /// ```
        ///
        /// # Panics
        /// If the pre-condition that the scope isn't empty is violated.
        /// This shouldn't occur, as it's an invariant of [BinaryEncodedScope].
        pub fn elements(
            &self,
            separator: u8,
        ) -> Result<impl Iterator<Item=&[u8]>, InvalidBinaryEncodedScopeError> {
            let split = self.0.split(move |x| x == &separator);
            // We use an assert rather than an Error because the client is not expected to handle this.
            assert!(
                !self.0.is_empty(),
                "Invariant violated: Scope may not be empty"
            );
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
                Ok(split)
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
                Ok(BinaryEncodedScope(ByteString::from(value.to_vec())))
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
            value.try_into()
        }
    }

    impl TryFrom<&[u8]> for Scope {
        type Error = InvalidBinaryEncodedScopeError;

        fn try_from(value: &[u8]) -> Result<Self, InvalidBinaryEncodedScopeError> {
            value.try_into()
        }
    }

    impl From<BinaryEncodedScope> for Scope {
        fn from(value: BinaryEncodedScope) -> Self {
            Scope::BinaryEncoded(value)
        }
    }
}

