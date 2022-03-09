use alloc::string::String;
use crate::common::cbor_values::ByteString;
use crate::Scope;

#[cfg(test)]
mod tests;

/// This message is sent by an RS as a response to an Unauthorized Resource Request Message
/// to help the sender of the Unauthorized Resource Request Message acquire a valid access token.
/// For more information, see [section 5.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3).
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
    auth_server: Option<String>,

    /// The key identifier of a key used in an existing security association
    /// between the client and the RS.
    kid: Option<ByteString>,

    /// An identifier the client should request at the AS, as suggested by the RS.
    audience: Option<String>,

    /// The suggested scope that the client should request towards the AS.
    scope: Option<Scope>,

    /// A client nonce as described in [section 5.3.1 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3.1).
    client_nonce: Option<ByteString>,
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

mod conversion {
    //! Contains conversion methods for ACE-OAuth data types.
    //! One part of this is converting enum types from and to their CBOR abbreviations in
    //! [`cbor_abbreviations`], another part is implementing the [`AsCborMap`] type for the
    //! models which are represented as CBOR maps.

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
// TODO: Verify required fields
