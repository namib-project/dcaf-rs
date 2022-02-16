use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use ciborium::ser;

use ciborium::value::{Integer, Value};
use erased_serde::Serialize as ErasedSerialize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error;

use crate::model::cbor_values::ProofOfPossessionKey;

use super::cbor_map::AsCborMap;
use super::cbor_values::{ByteString, TextOrByteString};

#[cfg(test)]
mod tests;

// TODO: CBOR map keys as constants instead of magic numbers

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
    fn as_cbor_map(&self) -> Vec<(u16, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            1 => self.auth_server.as_ref(),
            2 => self.kid.as_ref(),
            5 => self.audience.as_ref(),
            9 => self.scope.as_ref(),
            39 => self.client_nonce.as_ref()
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut hint = AuthServerRequestCreationHint::default();
        for entry in map {
            match (entry.0, entry.1) {
                (1, Value::Text(x)) => hint.auth_server = Some(x),
                (2, Value::Bytes(x)) => hint.kid = Some(ByteString::from(x)),
                (5, Value::Text(x)) => hint.audience = Some(x),
                (9, Value::Text(x)) => hint.scope = Some(TextOrByteString::from(x)),
                (9, Value::Bytes(x)) => hint.scope = Some(TextOrByteString::from(x)),
                (39, Value::Bytes(x)) => hint.client_nonce = Some(ByteString::from(x)),
                (_, _) => return None,
            };
        }
        Some(hint)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct AccessTokenRequest {
    /// Grant type used for this request. Defaults to `client_credentials`.
    grant_type: Option<u32>,

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
    fn as_cbor_map(&self) -> Vec<(u16, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            4 => self.req_cnf.as_ref().map(|x| x.to_ciborium_map()),
            5 => self.audience.as_ref(),
            9 => self.scope.as_ref(),
            24 => Some(&self.client_id),
            27 => self.redirect_uri.as_ref(),
            33 => self.grant_type.as_ref(),
            38 => self.ace_profile.as_ref(),
            39 => self.client_nonce.as_ref(),
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut request = AccessTokenRequest::default();
        for entry in map {
            match (entry.0, entry.1) {
                (4, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        request.req_cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None;
                    }
                }
                (5, Value::Text(x)) => request.audience = Some(x),
                (9, Value::Text(x)) => request.scope = Some(TextOrByteString::TextString(x)),
                (9, Value::Bytes(x)) => {
                    request.scope = Some(TextOrByteString::ByteString(ByteString::from(x)))
                }
                (24, Value::Text(x)) => request.client_id = x,
                (27, Value::Text(x)) => request.redirect_uri = Some(x),
                (33, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        request.grant_type = Some(i)
                    } else {
                        return None;
                    }
                }
                (38, Value::Null) => request.ace_profile = Some(()),
                (39, Value::Bytes(x)) => request.client_nonce = Some(ByteString::from(x)),
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

    rs_cnf: Option<ProofOfPossessionKey>
}

impl AsCborMap for AccessTokenResponse {
    fn as_cbor_map(&self) -> Vec<(u16, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            1 => Some(&self.access_token),
            2 => self.expires_in,
            8 => self.cnf.as_ref().map(|x| x.to_ciborium_map()),
            9 => self.scope.as_ref(),
            34 => self.token_type,
            37 => self.refresh_token.as_ref(),
            38 => self.ace_profile,
            41 => self.rs_cnf.as_ref().map(|x| x.to_ciborium_map())
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self> where Self: Sized + AsCborMap {
        let mut response = AccessTokenResponse::default();
        for entry in map {
            match (entry.0, entry.1) {
                (1, Value::Bytes(x)) => response.access_token = ByteString::from(x),
                (2, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        response.expires_in = Some(i)
                    } else {
                        return None
                    }
                },
                (8, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        response.cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None;
                    }
                },
                (9, Value::Bytes(x)) => response.scope = Some(TextOrByteString::from(x)),
                (9, Value::Text(x)) => response.scope = Some(TextOrByteString::from(x)),
                (34, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        response.token_type = Some(i)
                    } else {
                        return None
                    }
                },
                (37, Value::Bytes(x)) => response.refresh_token = Some(ByteString::from(x)),
                (38, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        response.ace_profile = Some(i)
                    } else {
                        return None
                    }
                },
                (41, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        response.rs_cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None
                    }
                }
                _ => return None
            }
        }
        Some(response)
    }
}

// TODO: Introspection data structures
