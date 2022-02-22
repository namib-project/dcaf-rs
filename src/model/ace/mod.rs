use alloc::string::String;
use core::fmt::Debug;

use crate::model::cbor_values::ProofOfPossessionKey;

use super::cbor_values::{ByteString, TextOrByteString};

#[cfg(test)]
mod tests;

mod conversion;

/// This message is sent by an RS as a response to an Unauthorized Resource Request Message
/// to help the sender of the Unauthorized Resource Request Message acquire a valid access token.
/// For more information, see [section 5.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3).
#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub struct AuthServerRequestCreationHint {
    /// An absolute URI that identifies the appropriate AS for the RS.
    auth_server: Option<String>,

    /// The key identifier of a key used in an existing security association
    /// between the client and the RS.
    kid: Option<ByteString>,

    /// An identifier the client should request at the AS, as suggested by the RS.
    audience: Option<String>,

    /// The suggested scope that the client should request towards the AS.
    scope: Option<TextOrByteString>,

    /// A client nonce as described in [section 5.3.1 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3.1).
    client_nonce: Option<ByteString>,
}

/// Type of the resource owner's authorization used by the client to obtain an access token.
/// For more information, see [section 1.3 of RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub enum GrantType {
    Password,
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    Other(i32),
}

/// Request for an access token, sent from the client.
#[derive(Debug, Default, PartialEq)]
pub struct AccessTokenRequest {
    /// Grant type used for this request. Defaults to `client_credentials`.
    grant_type: Option<GrantType>,

    /// The logical name of the target service where the client intends to use the requested security token.
    audience: Option<String>,

    /// URI to redirect the client to after authorization is complete.
    redirect_uri: Option<String>,

    /// Client nonce to ensure the token is still fresh.
    client_nonce: Option<ByteString>,

    /// Scope of the access request as described by section 3.3 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
    scope: Option<TextOrByteString>,

    /// Included in the request if the AS shall include the `ace_profile` parameter in its
    /// response.
    ace_profile: Option<()>,

    /// Contains information about the key the client would like to bind to the
    /// access token for proof-of-possession.
    req_cnf: Option<ProofOfPossessionKey>,

    /// The client identifier as described in section 2.2 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
    client_id: String,
}

/// The type of the token issued as described in section 7.1 of
/// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1).
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub enum TokenType {
    /// Bearer token type as defined in [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750).
    Bearer,

    /// Proof-of-possession token type, as specified in
    /// [`draft-ietf-ace-oauth-params-16`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-params-16.txt).
    ProofOfPossession,

    /// An unspecified token type along with its representation in CBOR.
    Other(i32),
}

/// Profiles for ACE-OAuth as specified in section 5.8.4.3 of `draft-ietf-ace-oauth-authz`.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub enum AceProfile {
    /// Profile for ACE-OAuth using Datagram Transport Layer Security, specified in
    /// [`draft-ietf-ace-dtls-authorize`](https://www.ietf.org/archive/id/draft-ietf-ace-dtls-authorize-18.html).
    CoapDtls,

    // The below is commented out because no CBOR value has been specified yet for this profile.
    // /// Profile for ACE-OAuth using OSCORE, specified in
    // /// [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.txt).
    // CoapOscore,
    /// An unspecified ACE-OAuth profile along with its representation in CBOR.
    Other(i32),
}

/// Response to an AccessTokenRequest containing the Access Information.
#[derive(Debug, PartialEq, Default)]
pub struct AccessTokenResponse {
    /// The access token issued by the authorization server.
    access_token: ByteString,

    /// The lifetime in seconds of the access token.
    expires_in: Option<u32>,

    /// The scope of the access token as described by
    /// section 3.3 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
    scope: Option<TextOrByteString>,

    /// The type of the token issued as described in section 7.1 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1) and section 5.8.4.2
    /// of `draft-ietf-ace-oauth-authz-46`.
    token_type: Option<TokenType>,

    /// The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in section 6 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html)
    refresh_token: Option<ByteString>,

    /// This indicates the profile that the client must use towards the RS.
    ace_profile: Option<AceProfile>,

    /// The proof-of-possession key that the AS selected for the token.
    cnf: Option<ProofOfPossessionKey>,

    /// Information about the public key used by the RS to authenticate.
    rs_cnf: Option<ProofOfPossessionKey>,
}

/// Error code specifying what went wrong for a token request.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
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
    Other(i32)
}

/// Details about an error which occurred for an access token request.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ErrorResponse {
    /// Error code for this error.
    error: ErrorCode,

    /// Human-readable ASCII text providing additional information, used to assist the
    /// client developer in understanding the error that occurred.
    error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error, used to
    /// provide the client developer with additional information about the error.
    error_uri: Option<String>,
}


// TODO: Introspection data structures
// TODO: Verify required fields
