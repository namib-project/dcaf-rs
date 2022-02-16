use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use ciborium::value::Value;
use erased_serde::Serialize as ErasedSerialize;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::model::cbor_values::ProofOfPossessionKey;
use crate::model::constants::cbor_abbreviations::token::REQ_CNF;

use super::cbor_map::AsCborMap;
use super::cbor_values::{ByteString, TextOrByteString};
use super::constants::cbor_abbreviations::{creation_hint, error, grant_types, token};

#[cfg(test)]
mod tests;

// Macro adapted from https://github.com/enarx/ciborium/blob/main/ciborium/tests/macro.rs#L13
macro_rules! cbor_map_vec {
   ($($key:expr => $val:expr),* $(,)*) => {
        vec![$(
            (
                $key,
                $val.map(|x| {
                        // It's unclear to me why `Box::<dyn ErasedSerialize>` doesn't work.
                        let a_box: Box<dyn ErasedSerialize> = Box::new(x);
                        a_box
                        // Box::<dyn ErasedSerialize>::new(x)
                    })
            )
        ),*]
    };
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct AuthServerRequestCreationHint {
    auth_server: Option<String>,
    kid: Option<ByteString>,
    audience: Option<String>,
    scope: Option<TextOrByteString>,
    client_nonce: Option<ByteString>,
}

impl AsCborMap for AuthServerRequestCreationHint {
    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            creation_hint::AS => self.auth_server.as_ref(),
            creation_hint::KID => self.kid.as_ref(),
            creation_hint::AUDIENCE => self.audience.as_ref(),
            creation_hint::SCOPE => self.scope.as_ref(),
            creation_hint::CNONCE => self.client_nonce.as_ref()
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut hint = AuthServerRequestCreationHint::default();
        for entry in map {
            match (entry.0, entry.1) {
                (creation_hint::AS, Value::Text(x)) => hint.auth_server = Some(x),
                (creation_hint::KID, Value::Bytes(x)) => hint.kid = Some(ByteString::from(x)),
                (creation_hint::AUDIENCE, Value::Text(x)) => hint.audience = Some(x),
                (creation_hint::SCOPE, Value::Text(x)) => {
                    hint.scope = Some(TextOrByteString::from(x))
                }
                (creation_hint::SCOPE, Value::Bytes(x)) => {
                    hint.scope = Some(TextOrByteString::from(x))
                }
                (creation_hint::CNONCE, Value::Bytes(x)) => {
                    hint.client_nonce = Some(ByteString::from(x))
                }
                (_, _) => return None,
            };
        }
        Some(hint)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GrantType {
    Password,
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    Other(u8),
}

impl From<u8> for GrantType {
    fn from(value: u8) -> Self {
        match value {
            grant_types::PASSWORD => GrantType::Password,
            grant_types::AUTHORIZATION_CODE => GrantType::AuthorizationCode,
            grant_types::CLIENT_CREDENTIALS => GrantType::ClientCredentials,
            grant_types::REFRESH_TOKEN => GrantType::RefreshToken,
            x => GrantType::Other(x),
        }
    }
}

impl From<&GrantType> for u8 {
    fn from(grant: &GrantType) -> Self {
        match grant {
            GrantType::Password => grant_types::PASSWORD,
            GrantType::AuthorizationCode => grant_types::AUTHORIZATION_CODE,
            GrantType::ClientCredentials => grant_types::CLIENT_CREDENTIALS,
            GrantType::RefreshToken => grant_types::REFRESH_TOKEN,
            GrantType::Other(x) => x.to_owned(),
        }
    }
}

impl Serialize for GrantType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Value::from(u8::from(self)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GrantType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if let Ok(Value::Integer(i)) = Value::deserialize(deserializer) {
            Ok(u8::try_from(i)
                .map_err(|x| D::Error::custom(x.to_string()))?
                .into())
        } else {
            Err(D::Error::custom("Grant type must be an Integer!"))
        }
    }
}

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

    /// Scope of the access request as described by section 3.3 of RFC 6749.
    scope: Option<TextOrByteString>,

    /// Included in the request if the AS shall include the `ace_profile` parameter in its
    /// response.
    ace_profile: Option<()>,

    /// Contains information about the key the client would like to bind to the
    /// access token for proof-of-possession.
    req_cnf: Option<ProofOfPossessionKey>,

    /// The client identifier as described in section 2.2 of RFC 6749.
    client_id: String,
}

impl AsCborMap for AccessTokenRequest {
    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            token::REQ_CNF => self.req_cnf.as_ref().map(|x| x.to_ciborium_map()),
            token::AUDIENCE => self.audience.as_ref(),
            token::SCOPE => self.scope.as_ref(),
            token::CLIENT_ID => Some(&self.client_id),
            token::REDIRECT_URI => self.redirect_uri.as_ref(),
            token::GRANT_TYPE => self.grant_type.as_ref(),
            token::ACE_PROFILE => self.ace_profile.as_ref(),
            token::CNONCE => self.client_nonce.as_ref(),
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut request = AccessTokenRequest::default();
        for entry in map {
            match (entry.0, entry.1) {
                (token::REQ_CNF, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        request.req_cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None;
                    }
                }
                (token::AUDIENCE, Value::Text(x)) => request.audience = Some(x),
                (token::SCOPE, Value::Text(x)) => {
                    request.scope = Some(TextOrByteString::TextString(x))
                }
                (token::SCOPE, Value::Bytes(x)) => {
                    request.scope = Some(TextOrByteString::ByteString(ByteString::from(x)))
                }
                (token::CLIENT_ID, Value::Text(x)) => request.client_id = x,
                (token::REDIRECT_URI, Value::Text(x)) => request.redirect_uri = Some(x),
                (token::GRANT_TYPE, Value::Integer(x)) => {
                    if let Ok(i) = u8::try_from(x) {
                        request.grant_type = Some(GrantType::from(i))
                    } else {
                        return None;
                    }
                }
                (token::ACE_PROFILE, Value::Null) => request.ace_profile = Some(()),
                (token::CNONCE, Value::Bytes(x)) => {
                    request.client_nonce = Some(ByteString::from(x))
                }
                (_, _) => return None,
            };
        }
        Some(request)
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct AccessTokenResponse {
    access_token: ByteString,

    expires_in: Option<u32>,

    scope: Option<TextOrByteString>,

    token_type: Option<i32>,

    refresh_token: Option<ByteString>,

    ace_profile: Option<i32>,

    cnf: Option<ProofOfPossessionKey>,

    rs_cnf: Option<ProofOfPossessionKey>,
}

impl AsCborMap for AccessTokenResponse {
    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            token::ACCESS_TOKEN => Some(&self.access_token),
            token::EXPIRES_IN => self.expires_in,
            token::CNF => self.cnf.as_ref().map(|x| x.to_ciborium_map()),
            token::SCOPE => self.scope.as_ref(),
            token::TOKEN_TYPE => self.token_type,
            token::REFRESH_TOKEN => self.refresh_token.as_ref(),
            token::ACE_PROFILE => self.ace_profile,
            token::RS_CNF => self.rs_cnf.as_ref().map(|x| x.to_ciborium_map())
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut response = AccessTokenResponse::default();
        for entry in map {
            match (entry.0, entry.1) {
                (token::ACCESS_TOKEN, Value::Bytes(x)) => {
                    response.access_token = ByteString::from(x)
                }
                (token::EXPIRES_IN, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        response.expires_in = Some(i)
                    } else {
                        return None;
                    }
                }
                (token::CNF, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        response.cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None;
                    }
                }
                (token::SCOPE, Value::Bytes(x)) => response.scope = Some(TextOrByteString::from(x)),
                (token::SCOPE, Value::Text(x)) => response.scope = Some(TextOrByteString::from(x)),
                (token::TOKEN_TYPE, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        response.token_type = Some(i)
                    } else {
                        return None;
                    }
                }
                (token::REFRESH_TOKEN, Value::Bytes(x)) => {
                    response.refresh_token = Some(ByteString::from(x))
                }
                (token::ACE_PROFILE, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        response.ace_profile = Some(i)
                    } else {
                        return None;
                    }
                }
                (token::RS_CNF, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        response.rs_cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        Some(response)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    UnsupportedPopKey,
    IncompatibleAceProfiles,
}

impl TryFrom<u8> for ErrorCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            error::INVALID_REQUEST => Ok(ErrorCode::InvalidRequest),
            error::INVALID_CLIENT => Ok(ErrorCode::InvalidClient),
            error::INVALID_GRANT => Ok(ErrorCode::InvalidGrant),
            error::UNAUTHORIZED_CLIENT => Ok(ErrorCode::UnauthorizedClient),
            error::UNSUPPORTED_GRANT_TYPE => Ok(ErrorCode::UnsupportedGrantType),
            error::INVALID_SCOPE => Ok(ErrorCode::InvalidScope),
            error::UNSUPPORTED_POP_KEY => Ok(ErrorCode::UnsupportedPopKey),
            error::INCOMPATIBLE_ACE_PROFILES => Ok(ErrorCode::IncompatibleAceProfiles),
            _ => Err(()),
        }
    }
}

impl TryFrom<i128> for ErrorCode {
    type Error = ();

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        u8::try_from(value).map_err(|_| ())?.try_into()
    }
}

impl From<&ErrorCode> for u8 {
    fn from(code: &ErrorCode) -> Self {
        match code {
            ErrorCode::InvalidRequest => error::INVALID_REQUEST,
            ErrorCode::InvalidClient => error::INVALID_CLIENT,
            ErrorCode::InvalidGrant => error::INVALID_GRANT,
            ErrorCode::UnauthorizedClient => error::UNAUTHORIZED_CLIENT,
            ErrorCode::UnsupportedGrantType => error::UNSUPPORTED_GRANT_TYPE,
            ErrorCode::InvalidScope => error::INVALID_SCOPE,
            ErrorCode::UnsupportedPopKey => error::UNSUPPORTED_POP_KEY,
            ErrorCode::IncompatibleAceProfiles => error::INCOMPATIBLE_ACE_PROFILES,
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Value::from(u8::from(self)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if let Ok(Value::Integer(i)) = Value::deserialize(deserializer) {
            i128::from(i)
                .try_into()
                .map_err(|_| D::Error::custom("Invalid value"))
        } else {
            Err(D::Error::custom("Error code must be an Integer!"))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    error: ErrorCode,

    error_description: Option<String>,

    error_uri: Option<String>,
}

impl AsCborMap for ErrorResponse {
    fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            token::ERROR => Some(u8::from(&self.error)),
            token::ERROR_DESCRIPTION => self.error_description.as_ref(),
            token::ERROR_URI => self.error_uri.as_ref()
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut maybe_error: Option<ErrorCode> = None;
        let mut error_description: Option<String> = None;
        let mut error_uri: Option<String> = None;
        for entry in map {
            match (entry.0, entry.1) {
                (token::ERROR, Value::Integer(x)) => {
                    if let Ok(i) = u8::try_from(x) {
                        maybe_error = ErrorCode::try_from(i).ok();
                    } else {
                        return None;
                    }
                }
                (token::ERROR_URI, Value::Text(x)) => error_description = Some(x),
                (token::ERROR_DESCRIPTION, Value::Text(x)) => error_uri = Some(x),
                _ => return None,
            }
        }
        maybe_error.map(|error| ErrorResponse {
            error,
            error_uri,
            error_description,
        })
    }
}

// TODO: Introspection data structures
// TODO: Verify required fields
