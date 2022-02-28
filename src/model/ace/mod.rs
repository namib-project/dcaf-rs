use alloc::string::String;
use core::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::model::cbor_values::ProofOfPossessionKey;

use super::cbor_values::ByteString;

mod builder;
mod conversion;
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
/// # use dcaf::ace::TextEncodedScope;
/// # use dcaf::InvalidTextEncodedScopeError;
/// let scope = TextEncodedScope::try_from("first second third")?;
/// assert!(scope.elements().eq(["first", "second", "third"]));
/// # Ok::<(), InvalidTextEncodedScopeError>(())
/// ```
/// It's also possible to pass in a vector of strings:
/// ```
/// # use dcaf::ace::TextEncodedScope;
/// # use dcaf::InvalidTextEncodedScopeError;
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
/// # use dcaf::ace::TextEncodedScope;
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
/// # use dcaf::ace::BinaryEncodedScope;
/// # use dcaf::InvalidBinaryEncodedScopeError;
/// let scope = BinaryEncodedScope::try_from(vec![0x00, 0x21, 0xDC, 0xAF].as_slice())?;
/// assert!(scope.elements(0x21)?.eq(vec![vec![0x00], vec![0xDC, 0xAF]]));
/// # Ok::<(), InvalidBinaryEncodedScopeError>(())
/// ```
///
/// But note that the input array can't be empty:
/// ```
/// # use dcaf::ace::BinaryEncodedScope;
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
/// # use dcaf::ace::{BinaryEncodedScope, Scope, TextEncodedScope};
/// # use dcaf::InvalidTextEncodedScopeError;
/// # use dcaf::InvalidBinaryEncodedScopeError;
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

/// This message is sent by an RS as a response to an Unauthorized Resource Request Message
/// to help the sender of the Unauthorized Resource Request Message acquire a valid access token.
/// For more information, see [section 5.3 of `draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html#section-5.3).
#[derive(Debug, Default, PartialEq, Eq, Hash, Builder)]
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
#[derive(Debug, Default, PartialEq, Builder)]
#[builder(
    no_std,
    setter(into, strip_option),
    derive(Debug, PartialEq),
    build_fn(validate = "Self::validate")
)]
pub struct AccessTokenRequest {
    /// Grant type used for this request. Defaults to `client_credentials`.
    #[builder(default)]
    grant_type: Option<GrantType>,

    /// The logical name of the target service where the client intends to use the requested security token.
    #[builder(default)]
    audience: Option<String>,

    /// URI to redirect the client to after authorization is complete.
    #[builder(default)]
    redirect_uri: Option<String>,

    /// Client nonce to ensure the token is still fresh.
    #[builder(default)]
    client_nonce: Option<ByteString>,

    /// Scope of the access request as described by section 3.3 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
    #[builder(default)]
    scope: Option<Scope>,

    /// Included in the request if the AS shall include the `ace_profile` parameter in its
    /// response.
    #[builder(setter(custom, strip_option), default = "None")]
    ace_profile: Option<()>,

    /// Contains information about the key the client would like to bind to the
    /// access token for proof-of-possession.
    #[builder(default)]
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
#[derive(Debug, PartialEq, Default, Builder)]
#[builder(
    no_std,
    setter(into, strip_option),
    derive(Debug, PartialEq),
    build_fn(validate = "Self::validate")
)]
pub struct AccessTokenResponse {
    /// The access token issued by the authorization server.
    access_token: ByteString,

    /// The lifetime in seconds of the access token.
    #[builder(default)]
    expires_in: Option<u32>,

    /// The scope of the access token as described by
    /// section 3.3 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
    #[builder(default)]
    scope: Option<Scope>,

    /// The type of the token issued as described in section 7.1 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html#section-7.1) and section 5.8.4.2
    /// of `draft-ietf-ace-oauth-authz-46`.
    #[builder(default)]
    token_type: Option<TokenType>,

    /// The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in section 6 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html)
    #[builder(default)]
    refresh_token: Option<ByteString>,

    /// This indicates the profile that the client must use towards the RS.
    #[builder(default)]
    ace_profile: Option<AceProfile>,

    /// The proof-of-possession key that the AS selected for the token.
    #[builder(default)]
    cnf: Option<ProofOfPossessionKey>,

    /// Information about the public key used by the RS to authenticate.
    #[builder(default)]
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
    Other(i32),
}

/// Details about an error which occurred for an access token request.
#[derive(Debug, PartialEq, Eq, Hash, Builder)]
#[builder(
    no_std,
    setter(into, strip_option),
    derive(Debug, PartialEq),
    build_fn(validate = "Self::validate")
)]
pub struct ErrorResponse {
    /// Error code for this error.
    error: ErrorCode,

    /// Human-readable ASCII text providing additional information, used to assist the
    /// client developer in understanding the error that occurred.
    #[builder(default)]
    error_description: Option<String>,

    /// A URI identifying a human-readable web page with information about the error, used to
    /// provide the client developer with additional information about the error.
    #[builder(default)]
    error_uri: Option<String>,
}


// TODO: Introspection data structures
// TODO: Verify required fields
