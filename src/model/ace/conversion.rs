//! Contains conversion methods for ACE-OAuth data types.
//! One part of this is converting enum types from and to their CBOR abbreviations in
//! [`cbor_abbreviations`], another part is implementing the [`AsCborMap`] type for the
//! models which are represented as CBOR maps.

mod cbor_abbreviations {
    use crate::ace::{AceProfile, ErrorCode, GrantType, TokenType};
    use crate::ace::AceProfile::{CoapDtls, Other};
    use crate::model::constants::cbor_abbreviations::{
        ace_profile, error, grant_types, token_types,
    };

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
                x => Other(x),
            }
        }
    }

    impl From<AceProfile> for i32 {
        fn from(profile: AceProfile) -> Self {
            match profile {
                CoapDtls => ace_profile::COAP_DTLS,
                Other(x) => x,
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
}

mod cbor_map {
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;

    use ciborium::value::Value;
    use erased_serde::Serialize as ErasedSerialize;

    use crate::ace::{AccessTokenRequest, AccessTokenResponse, AceProfile, AuthServerRequestCreationHint, ErrorCode, ErrorResponse, GrantType, TokenType};
    use crate::cbor_values::{ByteString, TextOrByteString};
    use crate::model::cbor_map::AsCborMap;
    use crate::model::cbor_values::{CborMapValue, ProofOfPossessionKey};
    use crate::model::constants::cbor_abbreviations::{creation_hint, token};

    // Macro adapted from https://github.com/enarx/ciborium/blob/main/ciborium/tests/macro.rs#L13
    macro_rules! cbor_map_vec {
    ($($key:expr => $val:expr),* $(,)*) => {
         vec![$(
             (
                 $key as i128,
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
                match (entry.0 as u8, entry.1) {
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

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
            where
                Self: Sized + AsCborMap,
        {
            let mut request = AccessTokenRequest::default();
            for entry in map {
                match (entry.0 as u8, entry.1) {
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
                        if let Ok(i) = i32::try_from(x) {
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

        fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
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
                    (token::SCOPE, Value::Bytes(x)) => {
                        response.scope = Some(TextOrByteString::from(x))
                    }
                    (token::SCOPE, Value::Text(x)) => {
                        response.scope = Some(TextOrByteString::from(x))
                    }
                    (token::TOKEN_TYPE, Value::Integer(x)) => {
                        if let Ok(i) = i32::try_from(x) {
                            response.token_type = Some(TokenType::from(i))
                        } else {
                            return None;
                        }
                    }
                    (token::REFRESH_TOKEN, Value::Bytes(x)) => {
                        response.refresh_token = Some(ByteString::from(x))
                    }
                    (token::ACE_PROFILE, Value::Integer(x)) => {
                        if let Ok(i) = i32::try_from(x) {
                            response.ace_profile = Some(AceProfile::from(i))
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

    impl AsCborMap for ErrorResponse {
        fn as_cbor_map(&self) -> Vec<(i128, Option<Box<dyn ErasedSerialize + '_>>)> {
            let error = CborMapValue(self.error);
            cbor_map_vec! {
                token::ERROR => Some(error),
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
                match (entry.0 as u8, entry.1) {
                    (token::ERROR, Value::Integer(x)) => {
                        if let Ok(i) = i32::try_from(x) {
                            maybe_error = Some(ErrorCode::from(i));
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
}
