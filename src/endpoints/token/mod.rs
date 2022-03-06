use alloc::string::String;

use crate::common::{ByteString, ProofOfPossessionKey};
use crate::common::scope::Scope;

#[cfg(test)]
mod tests;

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
#[derive(Debug, Default, PartialEq, Clone, Builder)]
#[builder(
no_std,
setter(into, strip_option),
derive(Debug, PartialEq),
build_fn(validate = "Self::validate")
)]
pub struct AccessTokenRequest {
    /// Grant type used for this request. Defaults to `client_credentials`.
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
    #[builder(default)]
    pub scope: Option<Scope>,

    /// Included in the request if the AS shall include the `ace_profile` parameter in its
    /// response.
    #[builder(setter(custom, strip_option), default = "None")]
    pub ace_profile: Option<()>,

    /// Contains information about the key the client would like to bind to the
    /// access token for proof-of-possession.
    #[builder(default)]
    pub req_cnf: Option<ProofOfPossessionKey>,

    /// The client identifier as described in section 2.2 of
    /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
    pub client_id: String,
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
#[derive(Debug, PartialEq, Default, Clone, Builder)]
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

impl AccessTokenRequest {
    /// Returns a new builder for this struct.
    pub fn builder() -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder::default()
    }
}

impl AccessTokenRequestBuilder {
    pub(crate) fn validate(&self) -> Result<(), AccessTokenRequestBuilderError> {
        // TODO: Check whether there are invariants to validate
        Ok(())
    }

    /// Sets the [ace_profile] field to an empty value, which indicates a request for the
    /// Authorization Server to respond with the ace_profile field in the response.
    pub fn ace_profile(&mut self) -> &mut Self {
        self.ace_profile = Some(Some(()));
        self
    }
}

impl AccessTokenResponse {
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

mod conversion {
    use ciborium::value::Value;
    use erased_serde::Serialize as ErasedSerialize;

    use crate::common::{AsCborMap, cbor_map_vec, CborMapValue, decode_int_map, decode_number, decode_scope, scope::{BinaryEncodedScope, TextEncodedScope}};
    use crate::common::constants::cbor_abbreviations::{ace_profile, error, grant_types, token, token_types};
    use crate::endpoints::token::AceProfile::CoapDtls;
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

    impl AsCborMap for AccessTokenRequest {
        fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let grant_type: Option<CborMapValue<GrantType>> = self.grant_type.map(CborMapValue);
            cbor_map_vec! {
                token::REQ_CNF => self.req_cnf.as_ref().map(|x| x.to_ciborium_map()),
                token::AUDIENCE => self.audience.as_ref(),
                token::SCOPE => self.scope.as_ref(),
                token::CLIENT_ID => Some(&self.client_id),
                token::REDIRECT_URI => self.redirect_uri.as_ref(),
                token::GRANT_TYPE => grant_type,
                token::ACE_PROFILE => self.ace_profile.as_ref(),
                token::CNONCE => self.client_nonce.as_ref(),
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
            where
                Self: Sized + AsCborMap,
        {
            let mut request = AccessTokenRequest::default();
            for entry in map {
                match (entry.0 as u8, entry.1) {
                    (token::REQ_CNF, Value::Map(x)) => {
                        request.req_cnf = Some(ProofOfPossessionKey::try_from_cbor_map(decode_int_map::<Self>(x, "req_cnf")?)?)
                    }
                    (token::AUDIENCE, Value::Text(x)) => request.audience = Some(x),
                    (token::SCOPE, Value::Text(x)) => {
                        request.scope = decode_scope::<&str, TextEncodedScope>(x.as_str())?
                    }
                    (token::SCOPE, Value::Bytes(x)) => {
                        request.scope = decode_scope::<&[u8], BinaryEncodedScope>(x.as_slice())?
                        // TODO: Handle AIF
                    }
                    (token::CLIENT_ID, Value::Text(x)) => request.client_id = x,
                    (token::REDIRECT_URI, Value::Text(x)) => request.redirect_uri = Some(x),
                    (token::GRANT_TYPE, Value::Integer(x)) => {
                        request.grant_type = Some(GrantType::from(decode_number::<i32>(x, "grant_type")?));
                    }
                    (token::ACE_PROFILE, Value::Null) => request.ace_profile = Some(()),
                    (token::CNONCE, Value::Bytes(x)) => {
                        request.client_nonce = Some(ByteString::from(x))
                    }
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                };
            }
            Ok(request)
        }
    }

    impl AsCborMap for AccessTokenResponse {
        fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let token_type: Option<CborMapValue<TokenType>> = self.token_type.map(CborMapValue);
            let ace_profile: Option<CborMapValue<AceProfile>> = self.ace_profile.map(CborMapValue);
            cbor_map_vec! {
                token::ACCESS_TOKEN => Some(&self.access_token),
                token::EXPIRES_IN => self.expires_in,
                token::CNF => self.cnf.as_ref().map(|x| x.to_ciborium_map()),
                token::SCOPE => self.scope.as_ref(),
                token::TOKEN_TYPE => token_type,
                token::REFRESH_TOKEN => self.refresh_token.as_ref(),
                token::ACE_PROFILE => ace_profile,
                token::RS_CNF => self.rs_cnf.as_ref().map(|x| x.to_ciborium_map())
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
            where
                Self: Sized + AsCborMap,
        {
            let mut response = AccessTokenResponse::default();
            for entry in map {
                match (entry.0 as u8, entry.1) {
                    (token::ACCESS_TOKEN, Value::Bytes(x)) => {
                        response.access_token = ByteString::from(x)
                    }
                    (token::EXPIRES_IN, Value::Integer(x)) => {
                        response.expires_in = Some(decode_number::<u32>(x, "expires_in")?);
                    }
                    (token::CNF, Value::Map(x)) => {
                        response.cnf = Some(ProofOfPossessionKey::try_from_cbor_map(decode_int_map::<Self>(x, "cnf")?)?);
                    }
                    (token::SCOPE, Value::Bytes(x)) => {
                        response.scope = decode_scope::<&[u8], BinaryEncodedScope>(x.as_slice())?
                        // TODO: Handle AIF
                    }
                    (token::SCOPE, Value::Text(x)) => {
                        response.scope = decode_scope::<&str, TextEncodedScope>(x.as_str())?
                    }
                    (token::TOKEN_TYPE, Value::Integer(x)) => {
                        response.token_type = Some(TokenType::from(decode_number::<i32>(x, "token_type")?));
                    }
                    (token::REFRESH_TOKEN, Value::Bytes(x)) => {
                        response.refresh_token = Some(ByteString::from(x))
                    }
                    (token::ACE_PROFILE, Value::Integer(x)) => {
                        response.ace_profile = Some(AceProfile::from(decode_number::<i32>(x, "ace_profile")?));
                    }
                    (token::RS_CNF, Value::Map(x)) => {
                        response.rs_cnf = Some(ProofOfPossessionKey::try_from_cbor_map(decode_int_map::<Self>(x, "rs_cnf")?)?);
                    }
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                }
            }
            Ok(response)
        }
    }

    impl AsCborMap for ErrorResponse {
        fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let error = CborMapValue(self.error);
            cbor_map_vec! {
                token::ERROR => Some(error),
                token::ERROR_DESCRIPTION => self.error_description.as_ref(),
                token::ERROR_URI => self.error_uri.as_ref()
            }
        }

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Result<Self, TryFromCborMapError>
            where
                Self: Sized + AsCborMap,
        {
            let mut maybe_error: Option<ErrorCode> = None;
            let mut error_description: Option<String> = None;
            let mut error_uri: Option<String> = None;
            for entry in map {
                match (entry.0 as u8, entry.1) {
                    (token::ERROR, Value::Integer(x)) => {
                        maybe_error = Some(ErrorCode::from(decode_number::<i32>(x, "error")?));
                    }
                    (token::ERROR_URI, Value::Text(x)) => error_description = Some(x),
                    (token::ERROR_DESCRIPTION, Value::Text(x)) => error_uri = Some(x),
                    (key, _) => return Err(TryFromCborMapError::unknown_field(key)),
                }
            }
            maybe_error.map(|error| ErrorResponse {
                error,
                error_uri,
                error_description,
            }).ok_or_else(|| TryFromCborMapError::missing_field("error"))
        }
    }
}
