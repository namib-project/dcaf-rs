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

//! Contains the data models for structures related to access token requests and responses,
//! as described in [`draft-ietf-ace-oauth-authz-46`, section 5.8](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8).
//!
//! The most important members of this module are [`AccessTokenRequest`], [`AccessTokenResponse`],
//! and [`ErrorResponse`]. Look at their documentation for usage examples.
//! Other members are mainly used as part of the aforementioned structures.

use crate::common::cbor_values::{ByteString, ProofOfPossessionKey};
use crate::Scope;
use alloc::string::String;
use coset::AsCborValue;

#[cfg(test)]
mod tests;

/// Type of the resource owner's authorization used by the client to obtain an access token.
/// For more information, see [section 1.3 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
///
/// Grant types are used in the [`AccessTokenRequest`].
///
/// # Example
/// For example, if you wish to indicate in your request that the resource owner's authorization
/// works via client credentials:
/// ```
/// # use dcaf::{AccessTokenRequest, GrantType};
/// # use dcaf::endpoints::token_req::AccessTokenRequestBuilderError;
/// let request = AccessTokenRequest::builder()
///     .client_id("test_client")
///     .grant_type(GrantType::ClientCredentials)
///     .build()?;
/// # Ok::<(), AccessTokenRequestBuilderError>(())
/// ```
/// It's also possible to use your own value for a custom grant type, as defined in
/// [section 8.5 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.5):
/// ```
/// # use dcaf::{AccessTokenRequest, GrantType};
/// # use dcaf::endpoints::token_req::AccessTokenRequestBuilderError;
/// let request = AccessTokenRequest::builder()
///     .client_id("test_client")
///     // values below -65536 marked for private use.
///     .grant_type(GrantType::Other(-99999))
///     .build()?;
/// # Ok::<(), AccessTokenRequestBuilderError>(())
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[non_exhaustive]
pub enum GrantType {
    /// Grant type intended for clients capable of obtaining the
    /// resource owner's credentials.
    ///
    /// Note that the authorization server should take special care when
    /// enabling this grant type and only allow it when other flows are not viable.
    ///
    /// See [section 4.3 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.3)
    /// for details.
    Password,

    /// Redirection-based flow optimized for confidential clients.
    ///
    /// See [section 4.1 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1)
    /// for details.
    AuthorizationCode,

    /// Used when the client authenticates with the authorization server in an unspecified way.
    ///
    /// Must only be used for confidential clients.
    ///
    /// See [section 4.4 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4)
    /// for details.
    ClientCredentials,

    /// Used for refreshing an existing access token.
    ///
    /// When using this, it's necessary that [`refresh_token`](AccessTokenResponse::refresh_token)
    /// is specified in the [`AccessTokenResponse`].
    ///
    /// See [section 6 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-6)
    /// for details.
    RefreshToken,

    /// Another authorization grant not listed here.
    ///
    /// See [section 8.5 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.5)
    /// for corresponding IANA registries.
    Other(i32),
}

/// Request for an access token, sent from the client, as defined in [section 5.8.1 of
/// `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.1).
///
/// Use the [`AccessTokenRequestBuilder`] (which you can access using the
/// [`AccessTokenRequest::builder()`] method) to create an instance of this struct.
///
/// # Example
/// Figure 5 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-5)
/// gives us an example of an access token request, given in CBOR diagnostic notation[^cbor]:
/// ```text
/// {
///     "client_id" : "myclient",
///     "audience" : "tempSensor4711"
/// }
/// ```
///
/// This could be built and serialized as an [`AccessTokenRequest`] like so:
/// ```
/// # use std::error::Error;
/// # use ciborium_io::{Read, Write};
/// # use dcaf::{ToCborMap, AccessTokenRequest, Scope};
/// # use dcaf::endpoints::token_req::AccessTokenRequestBuilderError;
/// # use dcaf::error::InvalidTextEncodedScopeError;
/// let request: AccessTokenRequest = AccessTokenRequest::builder()
///    .client_id("myclient")
///    .audience("tempSensor4711")
///    .build()?;
/// let mut serialized = Vec::new();
/// request.clone().serialize_into(&mut serialized)?;
/// assert_eq!(AccessTokenRequest::deserialize_from(serialized.as_slice())?, request);
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// [^cbor]: Note that abbreviations aren't used here, so keep in mind that the labels are really
/// integers instead of strings.
#[derive(Debug, Default, PartialEq, Clone, Builder)]
#[builder(
    no_std,
    setter(into, strip_option),
    derive(Debug, PartialEq),
    build_fn(validate = "Self::validate")
)]
pub struct AccessTokenRequest {
    // TODO: Certain grant types have certain required fields. These should be verified in the
    //       builder's `validate` method (only if the grant type is given! Otherwise, check spec.)
    /// The client identifier as described in section 2.2 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
    #[builder(default)]
    pub client_id: Option<String>,

    /// Grant type used for this request.
    ///
    /// Defaults to [`GrantType::ClientCredentials`].
    ///
    /// See also the documentation of [`GrantType`] for details.
    #[builder(default)]
    pub grant_type: Option<GrantType>,

    /// The logical name of the target service where the client intends to use the requested security token.
    #[builder(default)]
    pub audience: Option<String>,

    /// URI to redirect the client to after authorization is complete.
    #[builder(default)]
    pub redirect_uri: Option<String>,

    /// Client nonce to ensure the token is still fresh.
    #[builder(default)]
    pub client_nonce: Option<ByteString>,

    /// Scope of the access request as described by section 3.3 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
    ///
    /// See also the documentation of [`Scope`] for details.
    #[builder(default)]
    pub scope: Option<Scope>,

    /// Included in the request if the AS shall include the `ace_profile` parameter in its
    /// response.
    #[builder(setter(custom, strip_option), default = "None")]
    pub ace_profile: Option<()>,

    /// Contains information about the key the client would like to bind to the
    /// access token for proof-of-possession.
    ///
    /// See also the documentation of [`ProofOfPossessionKey`] for details.
    #[builder(default)]
    pub req_cnf: Option<ProofOfPossessionKey>,

    /// Issuer of the token.
    /// Note that this is only used by libdcaf and not present in the ACE-OAuth specification
    /// for access token requests.
    /// Instead, it is usually encoded as a claim in the access token itself.
    ///
    /// Defined in [section 3.1.1 of RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.1)
    /// and [Figure 16 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-16).
    #[builder(default)]
    pub issuer: Option<String>,
}

/// The type of the token issued as described in section 7.1 of
/// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1).
///
/// Token types are used in the [`AccessTokenResponse`].
///
/// # Example
/// For example, if you wish to indicate in your response that the token is of the
/// proof-of-possession type:
/// ```
/// # use dcaf::{AccessTokenResponse, GrantType, TokenType};
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
/// # use dcaf::TokenType::ProofOfPossession;
/// let request = AccessTokenResponse::builder()
///     .access_token(vec![1,2,3,4])
///     .token_type(TokenType::ProofOfPossession)
///     .cnf(ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]))
///     .build()?;
/// # Ok::<(), AccessTokenResponseBuilderError>(())
/// ```
/// It's also possible to use your own value for a custom token type, as defined in
/// [section 8.7 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.7):
/// ```
/// # use dcaf::{AccessTokenResponse, GrantType, TokenType};
/// # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
/// let request = AccessTokenResponse::builder()
///     .access_token(vec![1,2,3,4])
///     // values below -65536 marked for private use.
///     .token_type(TokenType::Other(-99999))
///     .build()?;
/// # Ok::<(), AccessTokenResponseBuilderError>(())
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[non_exhaustive]
pub enum TokenType {
    /// Bearer token type as defined in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750).
    Bearer,

    /// Proof-of-possession token type, as specified in
    /// [`draft-ietf-ace-oauth-params-16`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-params-16.html).
    ProofOfPossession,

    /// An unspecified token type along with its representation in CBOR.
    ///
    /// See [section 8.7 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.7)
    /// for details.
    Other(i32),
}

/// Profiles for ACE-OAuth as specified in [section 5.8.4.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.4.3).
///
/// ACE-OAuth profiles are used in the [`AccessTokenResponse`] if the client previously sent
/// an [`AccessTokenRequest`] with the `ace_profile` field set.
///
/// There are (to my awareness) at the moment two profiles for ACE-OAuth:
/// - The DTLS profile, specified in [`draft-ietf-ace-dtls-authorize`](https://www.ietf.org/archive/id/draft-ietf-ace-dtls-authorize-18.html).
/// - The OSCORE profile, defined in [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.html).
///   - Note that this is an expired Internet-Draft which does not have a specified CBOR
///     representation yet. Hence, this is not offered as an option in this enum.
///     If you wish to use it anyway, you need to specify a user-defined CBOR integer for it
///     using the [`Other`](AceProfile::Other) variant.
///
/// # Example
/// For example, if you wish to indicate in your response that the DTLS profile is used:
/// ```
/// # use dcaf::{AccessTokenResponse, AceProfile};
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
/// # use dcaf::TokenType::ProofOfPossession;
/// let request = AccessTokenResponse::builder()
///     .access_token(vec![1,2,3,4])
///     .ace_profile(AceProfile::CoapDtls)
///     .build()?;
/// # Ok::<(), AccessTokenResponseBuilderError>(())
/// ```
/// It's also possible to use your own value for a custom profile, as defined in
/// [section 8.8 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.8):
/// ```
/// # use dcaf::{AccessTokenResponse, AceProfile};
/// # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
/// let request = AccessTokenResponse::builder()
///     .access_token(vec![1,2,3,4])
///     // values below -65536 marked for private use.
///     .ace_profile(AceProfile::Other(-99999))
///     .build()?;
/// # Ok::<(), AccessTokenResponseBuilderError>(())
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[non_exhaustive]
pub enum AceProfile {
    /// Profile for ACE-OAuth using Datagram Transport Layer Security, specified in
    /// [`draft-ietf-ace-dtls-authorize`](https://www.ietf.org/archive/id/draft-ietf-ace-dtls-authorize-18.html).
    CoapDtls,

    // The below is commented out because no CBOR value has been specified yet for this profile.
    // /// Profile for ACE-OAuth using OSCORE, specified in
    // /// [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.html).
    // CoapOscore,
    /// An unspecified ACE-OAuth profile along with its representation in CBOR.
    ///
    /// See [section 8.8 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.8)
    /// for details.
    Other(i32),
}

/// Response to an [`AccessTokenRequest`] containing the Access Token among additional information,
/// as defined in [section 5.8.2 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.2).
///
/// Use the [`AccessTokenResponseBuilder`] (which you can access using the
/// [`AccessTokenResponse::builder()`] method) to create an instance of this struct.
///
/// # Example
/// Figure 9 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-9)
/// gives us an example of an access token response, given in CBOR diagnostic notation[^cbor]:
/// ```text
/// {
///   "access_token" : b64'SlAV32hkKG ...
///    (remainder of CWT omitted for brevity;
///    CWT contains COSE_Key in the "cnf" claim)',
///   "ace_profile" : "coap_dtls",
///   "expires_in" : "3600",
///   "cnf" : {
///     "COSE_Key" : {
///       "kty" : "Symmetric",
///       "kid" : b64'39Gqlw',
///       "k" : b64'hJtXhkV8FJG+Onbc6mxCcQh'
///     }
///   }
/// }
/// ```
///
/// This could be built and serialized as an [`AccessTokenResponse`] like so:
/// ```
/// # use std::error::Error;
/// # use ciborium_io::{Read, Write};
/// # use coset::CoseKeyBuilder;
/// # use dcaf::{ToCborMap, AccessTokenResponse, AceProfile};
/// # use dcaf::endpoints::token_req::AccessTokenResponseBuilderError;
/// let key = CoseKeyBuilder::new_symmetric_key(
///    // Omitted for brevity.
/// #   vec![ 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c,
/// #         0x42, 0x71, 0x08]
/// ).key_id(vec![0xDF, 0xD1, 0xAA, 0x97]).build();
/// let expires_in: u32 = 3600;  // this needs to be done so Rust doesn't think of it as an i32
/// let response: AccessTokenResponse = AccessTokenResponse::builder()
///    .access_token(
///       // Omitted for brevity, this is a CWT whose `cnf` claim contains
///       // the COSE_Key used in the `cnf` field from this `AccessTokenResponse`.
/// # // TODO: Actually have it be that.
/// # vec![0xDC, 0xAF]
///    )
///    .ace_profile(AceProfile::CoapDtls)
///    .expires_in(expires_in)
///    .cnf(key)
///    .build()?;
/// let mut serialized = Vec::new();
/// response.clone().serialize_into(&mut serialized)?;
/// assert_eq!(AccessTokenResponse::deserialize_from(serialized.as_slice())?, response);
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// [^cbor]: Note that abbreviations aren't used here, so keep in mind that the labels are really
/// integers instead of strings.
///
#[derive(Debug, PartialEq, Default, Clone, Builder)]
#[builder(
    no_std,
    setter(into, strip_option),
    derive(Debug, PartialEq),
    build_fn(validate = "Self::validate")
)]
pub struct AccessTokenResponse {
    /// The access token issued by the authorization server.
    ///
    /// Must be included.
    pub access_token: ByteString,

    /// The lifetime in seconds of the access token.
    #[builder(default)]
    pub expires_in: Option<u32>,

    /// The scope of the access token as described by
    /// section 3.3 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
    ///
    /// See the documentation of [`Scope`] for details.
    #[builder(default)]
    pub scope: Option<Scope>,

    /// The type of the token issued as described in [section 7.1 of
    /// RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1) and [section 5.8.4.2
    /// of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-5.8.4.2).
    ///
    /// See the documentation of [`TokenType`] for details.
    #[builder(default)]
    pub token_type: Option<TokenType>,

    /// The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in [section 6 of
    /// RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-6).
    #[builder(default)]
    pub refresh_token: Option<ByteString>,

    /// This indicates the profile that the client must use towards the RS.
    ///
    /// See the documentation of [`AceProfile`] for details.
    #[builder(default)]
    pub ace_profile: Option<AceProfile>,

    /// The proof-of-possession key that the AS selected for the token.
    ///
    /// See the documentation of [`ProofOfPossessionKey`] for details.
    #[builder(default)]
    pub cnf: Option<ProofOfPossessionKey>,

    /// Information about the public key used by the RS to authenticate.
    ///
    /// See the documentation of [`ProofOfPossessionKey`] for details.
    #[builder(default)]
    pub rs_cnf: Option<ProofOfPossessionKey>,

    /// Timestamp when the token was issued.
    /// Note that this is only used by libdcaf and not present in the ACE-OAuth specification
    /// for access token responses.
    /// It is instead usually encoded as a claim in the access token itself.
    ///
    /// Defined in [section 3.1.6 of RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.6)
    /// and [Figure 16 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#figure-16).
    #[builder(default)]
    pub issued_at: Option<coset::cwt::Timestamp>,
}

/// Error code specifying what went wrong for a token request, as specified in
/// [section 5.2 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2) and
/// [section 5.8.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.3).
///
/// An error code is used in the [`ErrorResponse`].
///
/// # Example
/// For example, if you wish to indicate in your error response that the client is not authorized:
/// ```
/// # use dcaf::{ErrorResponse, AceProfile, ErrorCode};
/// # use dcaf::endpoints::token_req::ErrorResponseBuilderError;
/// let request = ErrorResponse::builder()
///     .error(ErrorCode::UnauthorizedClient)
///     .build()?;
/// # Ok::<(), ErrorResponseBuilderError>(())
/// ```
/// It's also possible to use your own value for a custom error code, as defined in
/// [section 8.4 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.4):
/// ```
/// # use dcaf::{ErrorResponse, AceProfile, ErrorCode};
/// # use dcaf::endpoints::token_req::ErrorResponseBuilderError;
/// let request = ErrorResponse::builder()
///     // Values less than 65536 marked as private use.
///     .error(ErrorCode::Other(-99999))
///     .build()?;
/// # Ok::<(), ErrorResponseBuilderError>(())
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request is missing a required parameter, includes an unsupported parameter value (other
    /// than grant type), repeats a parameter, includes multiple credentials, utilizes
    /// more than one mechanism for authenticating the client, or is otherwise malformed.
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client authentication included, or
    /// unsupported authentication method)
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code, resource owner credentials) or
    /// refresh token is invalid, expired, revoked, does not match the redirection URI used in the
    /// authorization request, or was issued to another client.
    InvalidGrant,

    /// The authenticated client is not authorized to use this authorization grant type.
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization server.
    UnsupportedGrantType,

    /// The authorization grant type is not supported by the authorization server.
    InvalidScope,

    /// The client submitted an asymmetric key in the token request that the RS cannot process.
    UnsupportedPopKey,

    /// The client and the RS it has requested an access token for do not share a common profile.
    IncompatibleAceProfiles,

    /// An unspecified error code along with its representation in CBOR.
    ///
    /// See [section 8.4 of `draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-8.4)
    /// for details.
    Other(i32),
}

/// Details about an error which occurred for an access token request.
///
/// For more information, see [section 5.8.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.8.3).
///
/// Use the [`ErrorResponseBuilder`] (which you can access using the
/// [`ErrorResponse::builder()`] method) to create an instance of this struct.
///
/// # Example
/// For example, let us use the example from [section 5.2 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2):
/// ```text
/// {
///       "error":"invalid_request"
/// }
///
/// ```
/// Creating and serializing a simple error response telling the client their request was invalid
/// would look like the following:
/// ```
/// # use std::error::Error;
/// # use ciborium_io::{Read, Write};
/// # use dcaf::{ToCborMap, ErrorCode, ErrorResponse};
/// # use dcaf::endpoints::token_req::ErrorResponseBuilderError;
/// let error: ErrorResponse = ErrorResponse::builder()
///     .error(ErrorCode::InvalidRequest)
///     .build()?;
/// let mut serialized = Vec::new();
/// error.clone().serialize_into(&mut serialized)?;
/// assert_eq!(ErrorResponse::deserialize_from(serialized.as_slice())?, error);
/// # Ok::<(), Box<dyn Error>>(())
/// ```
///
/// [^cbor]: Note that abbreviations aren't used here, so keep in mind that the labels are really
/// integers instead of strings.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Builder)]
#[builder(
    no_std,
    setter(into, strip_option),
    derive(Debug, PartialEq),
    build_fn(validate = "Self::validate")
)]
pub struct ErrorResponse {
    /// Error code for this error.
    ///
    /// Must be included.
    ///
    /// See the documentation of [`ErrorCode`] for details.
    pub error: ErrorCode,

    /// Human-readable ASCII text providing additional information, used to assist the
    /// client developer in understanding the error that occurred.
    #[builder(default)]
    pub description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error, used to
    /// provide the client developer with additional information about the error.
    #[builder(default)]
    pub uri: Option<String>,
}

impl AccessTokenRequest {
    /// Initializes and returns a new [`AccessTokenRequestBuilder`].
    #[must_use]
    pub fn builder() -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder::default()
    }
}

#[allow(clippy::unused_self, clippy::unnecessary_wraps)]
mod builder {
    use super::*;

    impl AccessTokenRequestBuilder {
        pub(crate) fn validate(&self) -> Result<(), AccessTokenRequestBuilderError> {
            // TODO: Check whether there are invariants to validate
            Ok(())
        }

        /// Sets the [`ace_profile`](AccessTokenRequest::ace_profile) field to an empty value,
        /// which indicates a request for the Authorization Server to respond with the
        /// `ace_profile` field in the response.
        pub fn ace_profile(&mut self) -> &mut Self {
            self.ace_profile = Some(Some(()));
            self
        }
    }

    impl AccessTokenResponse {
        /// Initializes and returns a new [`AccessTokenResponseBuilder`].
        #[must_use]
        pub fn builder() -> AccessTokenResponseBuilder {
            AccessTokenResponseBuilder::default()
        }
    }

    impl AccessTokenResponseBuilder {
        pub(crate) fn validate(&self) -> Result<(), AccessTokenResponseBuilderError> {
            // TODO: Check whether there are invariants to validate
            Ok(())
        }
    }

    impl ErrorResponse {
        /// Initializes and returns a new [`ErrorResponseBuilder`].
        #[must_use]
        pub fn builder() -> ErrorResponseBuilder {
            ErrorResponseBuilder::default()
        }
    }

    impl ErrorResponseBuilder {
        pub(crate) fn validate(&self) -> Result<(), ErrorResponseBuilderError> {
            // TODO: Check whether there are invariants to validate
            Ok(())
        }
    }
}

mod conversion {
    use crate::common::cbor_map::{
        cbor_map_vec, decode_int_map, decode_number, decode_scope, ToCborMap,
    };
    use crate::common::cbor_values::{CborMapValue, ProofOfPossessionKey};
    use crate::constants::cbor_abbreviations::{
        ace_profile, error, grant_types, introspection, token, token_types,
    };
    use ciborium::value::Value;
    use coset::cwt::Timestamp;
    use erased_serde::Serialize as ErasedSerialize;

    use crate::endpoints::token_req::AceProfile::CoapDtls;
    use crate::error::TryFromCborMapError;

    use super::*;

    impl From<i32> for GrantType {
        fn from(value: i32) -> Self {
            match value {
                grant_types::PASSWORD => GrantType::Password,
                grant_types::AUTHORIZATION_CODE => GrantType::AuthorizationCode,
                grant_types::CLIENT_CREDENTIALS => GrantType::ClientCredentials,
                grant_types::REFRESH_TOKEN => GrantType::RefreshToken,
                x => GrantType::Other(x),
            }
        }
    }

    impl From<GrantType> for i32 {
        fn from(grant: GrantType) -> Self {
            match grant {
                GrantType::Password => grant_types::PASSWORD,
                GrantType::AuthorizationCode => grant_types::AUTHORIZATION_CODE,
                GrantType::ClientCredentials => grant_types::CLIENT_CREDENTIALS,
                GrantType::RefreshToken => grant_types::REFRESH_TOKEN,
                GrantType::Other(x) => x.to_owned(),
            }
        }
    }

    impl From<i32> for TokenType {
        fn from(value: i32) -> Self {
            match value {
                token_types::BEARER => TokenType::Bearer,
                token_types::POP => TokenType::ProofOfPossession,
                x => TokenType::Other(x),
            }
        }
    }

    impl From<TokenType> for i32 {
        fn from(token: TokenType) -> Self {
            match token {
                TokenType::Bearer => token_types::BEARER,
                TokenType::ProofOfPossession => token_types::POP,
                TokenType::Other(x) => x,
            }
        }
    }

    impl From<i32> for AceProfile {
        fn from(value: i32) -> Self {
            match value {
                ace_profile::COAP_DTLS => CoapDtls,
                x => AceProfile::Other(x),
            }
        }
    }

    impl From<AceProfile> for i32 {
        fn from(profile: AceProfile) -> Self {
            match profile {
                CoapDtls => ace_profile::COAP_DTLS,
                AceProfile::Other(x) => x,
            }
        }
    }

    impl From<i32> for ErrorCode {
        fn from(value: i32) -> Self {
            match value {
                error::INVALID_REQUEST => ErrorCode::InvalidRequest,
                error::INVALID_CLIENT => ErrorCode::InvalidClient,
                error::INVALID_GRANT => ErrorCode::InvalidGrant,
                error::UNAUTHORIZED_CLIENT => ErrorCode::UnauthorizedClient,
                error::UNSUPPORTED_GRANT_TYPE => ErrorCode::UnsupportedGrantType,
                error::INVALID_SCOPE => ErrorCode::InvalidScope,
                error::UNSUPPORTED_POP_KEY => ErrorCode::UnsupportedPopKey,
                error::INCOMPATIBLE_ACE_PROFILES => ErrorCode::IncompatibleAceProfiles,
                x => ErrorCode::Other(x),
            }
        }
    }

    impl From<ErrorCode> for i32 {
        fn from(code: ErrorCode) -> Self {
            match code {
                ErrorCode::InvalidRequest => error::INVALID_REQUEST,
                ErrorCode::InvalidClient => error::INVALID_CLIENT,
                ErrorCode::InvalidGrant => error::INVALID_GRANT,
                ErrorCode::UnauthorizedClient => error::UNAUTHORIZED_CLIENT,
                ErrorCode::UnsupportedGrantType => error::UNSUPPORTED_GRANT_TYPE,
                ErrorCode::InvalidScope => error::INVALID_SCOPE,
                ErrorCode::UnsupportedPopKey => error::UNSUPPORTED_POP_KEY,
                ErrorCode::IncompatibleAceProfiles => error::INCOMPATIBLE_ACE_PROFILES,
                ErrorCode::Other(x) => x,
            }
        }
    }

    impl ToCborMap for AccessTokenRequest {
        fn to_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let grant_type: Option<CborMapValue<GrantType>> = self.grant_type.map(CborMapValue);
            cbor_map_vec! {
                introspection::ISSUER => self.issuer.as_ref(),
                token::REQ_CNF => self.req_cnf.as_ref().map(ToCborMap::to_ciborium_value),
                token::AUDIENCE => self.audience.as_ref(),
                token::SCOPE => self.scope.as_ref(),
                token::CLIENT_ID => self.client_id.as_ref(),
                token::REDIRECT_URI => self.redirect_uri.as_ref(),
                token::GRANT_TYPE => grant_type,
                token::ACE_PROFILE => self.ace_profile.as_ref(),
                token::CNONCE => self.client_nonce.as_ref().map(|v| Value::Bytes(v.clone()))
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + ToCborMap,
        {
            let mut request = AccessTokenRequest::builder();
            for entry in map {
                match (u8::try_from(entry.0)?, entry.1) {
                    (token::REQ_CNF, Value::Map(x)) => {
                        request.req_cnf(ProofOfPossessionKey::try_from_cbor_map(decode_int_map::<
                            Self,
                        >(
                            x, "req_cnf",
                        )?)?)
                    }
                    (token::AUDIENCE, Value::Text(x)) => request.audience(x),
                    (token::SCOPE, v) => request.scope(decode_scope(v)?),
                    (token::CLIENT_ID, Value::Text(x)) => request.client_id(x),
                    (token::REDIRECT_URI, Value::Text(x)) => request.redirect_uri(x),
                    (token::GRANT_TYPE, Value::Integer(x)) => {
                        request.grant_type(GrantType::from(decode_number::<i32>(x, "grant_type")?))
                    }
                    (token::ACE_PROFILE, Value::Null) => request.ace_profile(),
                    (token::CNONCE, Value::Bytes(x)) => request.client_nonce(x),
                    (introspection::ISSUER, Value::Text(x)) => request.issuer(x),
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                };
            }
            request
                .build()
                .map_err(|x| TryFromCborMapError::build_failed("AccessTokenRequest", x))
        }
    }

    impl ToCborMap for AccessTokenResponse {
        fn to_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let token_type: Option<CborMapValue<TokenType>> = self.token_type.map(CborMapValue);
            let ace_profile: Option<CborMapValue<AceProfile>> = self.ace_profile.map(CborMapValue);
            cbor_map_vec! {
                token::ACCESS_TOKEN => Some(Value::Bytes(self.access_token.clone())),
                token::EXPIRES_IN => self.expires_in,
                introspection::ISSUED_AT => self.issued_at.as_ref().map(|x| x.clone().to_cbor_value().expect("serialization of issued_at failed")),
                token::CNF => self.cnf.as_ref().map(ToCborMap::to_ciborium_value),
                token::SCOPE => self.scope.as_ref(),
                token::TOKEN_TYPE => token_type,
                token::REFRESH_TOKEN => self.refresh_token.as_ref().map(|v| Value::Bytes(v.clone())),
                token::ACE_PROFILE => ace_profile,
                token::RS_CNF => self.rs_cnf.as_ref().map(ToCborMap::to_ciborium_value)
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + ToCborMap,
        {
            let mut response = AccessTokenResponse::builder();
            for entry in map {
                match (u8::try_from(entry.0)?, entry.1) {
                    (token::ACCESS_TOKEN, Value::Bytes(x)) => response.access_token(x),
                    (token::EXPIRES_IN, Value::Integer(x)) => {
                        response.expires_in(decode_number::<u32>(x, "expires_in")?)
                    }
                    (introspection::ISSUED_AT, v) => response.issued_at(
                        Timestamp::from_cbor_value(v)
                            .map_err(|x| TryFromCborMapError::from_message(x.to_string()))?,
                    ),
                    (token::CNF, Value::Map(x)) => {
                        response.cnf(ProofOfPossessionKey::try_from_cbor_map(decode_int_map::<
                            Self,
                        >(
                            x, "cnf",
                        )?)?)
                    }
                    (token::SCOPE, v) => response.scope(decode_scope(v)?),
                    (token::TOKEN_TYPE, Value::Integer(x)) => {
                        response.token_type(TokenType::from(decode_number::<i32>(x, "token_type")?))
                    }
                    (token::REFRESH_TOKEN, Value::Bytes(x)) => response.refresh_token(x),
                    (token::ACE_PROFILE, Value::Integer(x)) => response
                        .ace_profile(AceProfile::from(decode_number::<i32>(x, "ace_profile")?)),
                    (token::RS_CNF, Value::Map(x)) => {
                        response.rs_cnf(ProofOfPossessionKey::try_from_cbor_map(decode_int_map::<
                            Self,
                        >(
                            x, "rs_cnf",
                        )?)?)
                    }
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                };
            }
            response
                .build()
                .map_err(|x| TryFromCborMapError::build_failed("AccessTokenResponse", x))
        }
    }

    impl ToCborMap for ErrorResponse {
        fn to_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let error = CborMapValue(self.error);
            cbor_map_vec! {
                token::ERROR => Some(error),
                token::ERROR_DESCRIPTION => self.description.as_ref(),
                token::ERROR_URI => self.uri.as_ref()
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
        where
            Self: Sized + ToCborMap,
        {
            let mut error = ErrorResponse::builder();
            for entry in map {
                match (u8::try_from(entry.0)?, entry.1) {
                    (token::ERROR, Value::Integer(x)) => {
                        error.error(ErrorCode::from(decode_number::<i32>(x, "error")?))
                    }
                    (token::ERROR_URI, Value::Text(x)) => error.uri(x),
                    (token::ERROR_DESCRIPTION, Value::Text(x)) => error.description(x),
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                };
            }
            error
                .build()
                .map_err(|x| TryFromCborMapError::build_failed("ErrorResponse", x))
        }
    }
}
