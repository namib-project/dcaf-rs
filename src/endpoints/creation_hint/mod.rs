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

//! Contains the data model for
//! [Authorization Server Request Creation Hints](AuthServerRequestCreationHint),
//! as described in [RFC 9200, section 5.3](https://www.rfc-editor.org/rfc/rfc9200#name-as-request-creation-hints).
//!
//! See the documentation of [`AuthServerRequestCreationHint`] for details and an example.

use crate::common::cbor_values::ByteString;
use crate::Scope;

use {alloc::string::String, alloc::vec::Vec};

#[cfg(test)]
mod tests;

/// This is sent by an RS as a response to an Unauthorized Resource Request Message
/// to help the sender of the Unauthorized Resource Request Message acquire a valid access token.
///
/// For more information, see [section 5.3 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3).
///
/// Use the [`AuthServerRequestCreationHintBuilder`] (which you can access using the
/// [`builder()`](AuthServerRequestCreationHint::builder) method) to create an instance of this struct.
///
/// # Example
/// Figure 3 of [RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#figure-3)
/// gives us an example of a Request Creation Hint payload, given in CBOR diagnostic notation[^cbor]:
/// ```text
/// {
///     "AS" : "coaps://as.example.com/token",
///     "audience" : "coaps://rs.example.com"
///     "scope" : "rTempC",
///     "cnonce" : h'e0a156bb3f'
/// }
/// ```
///
/// This could be built and serialized as an [`AuthServerRequestCreationHint`] like so:
/// ```
/// # use std::error::Error;
/// # use ciborium_io::{Read, Write};
/// # use dcaf::{ToCborMap, AuthServerRequestCreationHint, Scope};
/// # use dcaf::endpoints::creation_hint::AuthServerRequestCreationHintBuilderError;
/// # use dcaf::common::cbor_values::ByteString;
/// # use dcaf::common::scope::TextEncodedScope;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// // Scope could be built from TextEncodedScope too,
/// // which also offers to take a space-separated string.
/// # #[cfg(feature = "std")] {
/// let scope = Scope::try_from(vec!["rTempC"])?;
/// let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder()
///     .auth_server("coaps://as.example.com/token")
///     .audience("coaps://rs.example.com")
///     .scope(scope)
///     .client_nonce(vec![0xe0, 0xa1, 0x56, 0xbb, 0x3f])
///     .build()?;
/// let mut serialized = Vec::new();
/// hint.clone().serialize_into(&mut serialized)?;
/// assert_eq!(AuthServerRequestCreationHint::deserialize_from(serialized.as_slice())?, hint);
/// # }
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// [^cbor]: Note that abbreviations aren't used here, so keep in mind that the labels are really
/// integers instead of strings.
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
    ///
    /// See the documentation of [`Scope`] for details.
    pub scope: Option<Scope>,

    /// A client nonce as described in [section 5.3.1 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3.1).
    pub client_nonce: Option<Vec<u8>>,
}

#[allow(clippy::unused_self, clippy::unnecessary_wraps)]
mod builder {
    use super::*;

    impl AuthServerRequestCreationHint {
        /// Returns a new builder for this struct.
        #[must_use]
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
/// another part is implementing the [`ToCborMap`](ToCborMap) type for the
/// models which are represented as CBOR maps.
mod conversion {
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;

    use ciborium::value::Value;
    use erased_serde::Serialize as ErasedSerialize;

    use crate::common::cbor_map::{cbor_map_vec, decode_scope, ToCborMap};
    use crate::common::constants::cbor_abbreviations::creation_hint;
    use crate::error::TryFromCborMapError;

    use super::*;

    impl ToCborMap for AuthServerRequestCreationHint {
        fn to_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            #[allow(clippy::cast_lossless)]
            {
                cbor_map_vec! {
                    creation_hint::AS => self.auth_server.as_ref(),
                    creation_hint::KID => self.kid.as_ref(),
                    creation_hint::AUDIENCE => self.audience.as_ref(),
                    creation_hint::SCOPE => self.scope.as_ref(),
                    creation_hint::CNONCE => self.client_nonce.as_ref().map(|v| Value::Bytes(v.clone()))
                }
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + ToCborMap,
        {
            let mut hint = AuthServerRequestCreationHint::builder();
            for entry in map {
                match (u8::try_from(entry.0)?, entry.1) {
                    (creation_hint::AS, Value::Text(x)) => hint.auth_server(x),
                    (creation_hint::KID, Value::Bytes(x)) => hint.kid(x),
                    (creation_hint::AUDIENCE, Value::Text(x)) => hint.audience(x),
                    (creation_hint::SCOPE, v) => hint.scope(decode_scope(v)?),
                    (creation_hint::CNONCE, Value::Bytes(x)) => hint.client_nonce(x),
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                };
            }
            hint.build()
                .map_err(|x| TryFromCborMapError::build_failed("AuthServerRequestCreationHint", x))
        }
    }
}
