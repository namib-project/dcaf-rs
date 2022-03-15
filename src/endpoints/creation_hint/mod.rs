//! Contains the data model for
//! [Authorization Server Request Creation Hints](self::AuthServerRequestCreationHint),
//! as described in [`draft-ietf-ace-oauth-authz-46`, section 5.3](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#name-as-request-creation-hints).
//!
//! See the documentation of [`AuthServerRequestCreationHint`] for details and an example.

use alloc::string::String;
use crate::common::cbor_values::ByteString;
use crate::Scope;

#[cfg(test)]
mod tests;

/// This message is sent by an RS as a response to an Unauthorized Resource Request Message
/// to help the sender of the Unauthorized Resource Request Message acquire a valid access token.
///
/// For more information, see [section 5.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3).
/// Use the [`AuthServerRequestCreationHintBuilder`] to create instances of this class.
///
/// # Example
/// Figure 3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-3)
/// gives us an example of a Request Creation Hint payload, given in CBOR diagnostic notation:
/// ```text
/// {
//      "AS" : "coaps://as.example.com/token",
//      "audience" : "coaps://rs.example.com"
//      "scope" : "rTempC",
//      "cnonce" : h'e0a156bb3f'
//  }
/// ```
///
/// This could be built and serialized as an [`AuthServerRequestCreationHint`] like so:
/// ```
/// # use std::error::Error;
/// # use ciborium_io::{Read, Write};
/// # use dcaf::{AsCborMap, AuthServerRequestCreationHint, Scope};
/// # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
/// # use dcaf::common::cbor_values::ByteString;
/// # use dcaf::common::scope::TextEncodedScope;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// # fn scope_gen() -> Result<Scope, InvalidTextEncodedScopeError> {
/// // Scope could be built from TextEncodedScope too,
/// // which also offers to take a space-separated string.
/// let scope = Scope::try_from(vec!["rTempC"])?;
/// # Ok(scope)
/// # }
/// # fn hint_gen(scope: Scope) -> Result<AuthServerRequestCreationHint, AuthServerRequestCreationHintBuilderError> {
/// let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder()
///     .auth_server("coaps://as.example.com/token")
///     .audience("coaps://rs.example.com")
///     .scope(scope)
///     .client_nonce(ByteString::from(vec![0xe0, 0xa1, 0x56, 0xbb, 0x3f]))
///     .build()?;
/// # Ok(hint)
/// }
/// # fn serialize(hint: AuthServerRequestCreationHint) -> Result<Vec<u8>, ciborium::ser::Error<<Vec<u8> as Write>::Error>> {
/// let mut serialized = Vec::new();
/// hint.serialize_into(&mut serialized)?;
/// # Ok(serialized)
/// # }
/// # fn deserialize(serialized: &Vec<u8>, hint: AuthServerRequestCreationHint) -> Result<(), ciborium::de::Error<<&[u8] as Read>::Error>> {
/// assert_eq!(AuthServerRequestCreationHint::deserialize_from(serialized.as_slice())?, hint);
/// # Ok(())
/// # }
/// # let scope = scope_gen().map_err(|x| x.to_string())?;
/// # let hint = hint_gen(scope).map_err(|x| x.to_string())?;
/// # let serialized = serialize(hint.clone()).map_err(|x| x.to_string())?;
/// # deserialize(&serialized, hint).map_err(|x| x.to_string())?;
/// #
/// # Ok::<(), String>(())
/// ```
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Builder)]
#[builder(
no_std,
setter(into, strip_option),
default,
derive(Debug, PartialEq, Eq),
build_fn(validate = "Self::validate")
)]
pub struct AuthServerRequestCreationHint {
    /// An absolute URI that identifies the appropriate AS for the RS.
    pub auth_server: Option<String>,

    /// The key identifier of a key used in an existing security association
    /// between the client and the RS.
    pub kid: Option<ByteString>,

    /// An identifier the client should request at the AS, as suggested by the RS.
    pub audience: Option<String>,

    /// The suggested scope that the client should request towards the AS.
    pub scope: Option<Scope>,

    /// A client nonce as described in [section 5.3.1 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3.1).
    pub client_nonce: Option<ByteString>,
}

mod builder {
    use super::*;

    impl AuthServerRequestCreationHint {
        /// Returns a new builder for this struct.
        pub fn builder() -> AuthServerRequestCreationHintBuilder {
            AuthServerRequestCreationHintBuilder::default()
        }
    }

    impl AuthServerRequestCreationHintBuilder {
        /// Validates this builder's fields for correctness.
        pub(crate) fn validate(&self) -> Result<(), AuthServerRequestCreationHintBuilderError> {
            // TODO: Check whether there are invariants to validate
            Ok(())
        }
    }
}

/// Contains conversion methods for ACE-OAuth data types.
///
/// One part of this is converting enum types from and to their CBOR abbreviations in
/// [`cbor_abbreviations`](crate::constants::cbor_abbreviations),
/// another part is implementing the [`AsCborMap`](crate::AsCborMap) type for the
/// models which are represented as CBOR maps.
mod conversion {

    use ciborium::value::Value;
    use erased_serde::Serialize as ErasedSerialize;
    use crate::common::cbor_map::{AsCborMap, cbor_map_vec, decode_scope};

    use crate::common::constants::cbor_abbreviations::creation_hint;
    use crate::error::{TryFromCborMapError};
    use crate::common::scope::{BinaryEncodedScope, TextEncodedScope};
    use crate::common::cbor_values::ByteString;

    use super::*;

    impl AsCborMap for AuthServerRequestCreationHint {
        fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            return cbor_map_vec! {
                creation_hint::AS => self.auth_server.as_ref(),
                creation_hint::KID => self.kid.as_ref(),
                creation_hint::AUDIENCE => self.audience.as_ref(),
                creation_hint::SCOPE => self.scope.as_ref(),
                creation_hint::CNONCE => self.client_nonce.as_ref()
            };
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
            where
                Self: Sized + AsCborMap,
        {
            let mut hint = AuthServerRequestCreationHint::default();
            for entry in map {
                match (entry.0 as u8, entry.1) {
                    (creation_hint::AS, Value::Text(x)) => hint.auth_server = Some(x),
                    (creation_hint::KID, Value::Bytes(x)) => hint.kid = Some(ByteString::from(x)),
                    (creation_hint::AUDIENCE, Value::Text(x)) => hint.audience = Some(x),
                    (creation_hint::SCOPE, Value::Text(x)) => {
                        hint.scope = decode_scope::<&str, TextEncodedScope>(x.as_str())?
                    }
                    (creation_hint::SCOPE, Value::Bytes(x)) => {
                        hint.scope = decode_scope::<&[u8], BinaryEncodedScope>(x.as_slice())?
                    }
                    (creation_hint::CNONCE, Value::Bytes(x)) => {
                        hint.client_nonce = Some(ByteString::from(x))
                    }
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                };
            }
            Ok(hint)
        }
    }
}

// TODO: Introspection data structures
