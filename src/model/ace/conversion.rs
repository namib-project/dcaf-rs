//! Contains conversion methods for ACE-OAuth data types.
//! One part of this is converting enum types from and to their CBOR abbreviations in
//! [`cbor_abbreviations`], another part is implementing the [`AsCborMap`] type for the
//! models which are represented as CBOR maps.

use crate::ace::{BinaryEncodedScope, Scope, TextEncodedScope};
use crate::cbor_values::ByteString;
use crate::error::{InvalidBinaryEncodedScopeError, InvalidTextEncodedScopeError};

impl TextEncodedScope {
    /// Return the individual elements (i.e., access ranges) of this scope.
    /// Post-condition: The returned iterator will not be empty, and none of its elements
    /// may contain spaces (` `), double-quotes (`"`) or backslashes (`\\'`).
    ///
    /// # Example
    ///
    /// ```
    /// # use dcaf::ace::TextEncodedScope;
    /// # use dcaf::InvalidTextEncodedScopeError;
    /// let simple = TextEncodedScope::try_from("this is a test")?;
    /// assert!(simple.elements().eq(vec!["this", "is", "a", "test"]));
    /// # Ok::<(), InvalidTextEncodedScopeError>(())
    /// ```
    pub fn elements(&self) -> impl Iterator<Item=&str> {
        self.0.split(' ')
    }
}

impl TryFrom<&str> for TextEncodedScope {
    type Error = InvalidTextEncodedScopeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.ends_with(' ') {
            Err(InvalidTextEncodedScopeError::EndsWithSeparator)
        } else if value.starts_with(' ') {
            Err(InvalidTextEncodedScopeError::StartsWithSeparator)
        } else if value.contains(['"', '\\']) {
            Err(InvalidTextEncodedScopeError::IllegalCharacters)
        } else if value.contains("  ") {
            Err(InvalidTextEncodedScopeError::ConsecutiveSeparators)
        } else if value.is_empty() {
            Err(InvalidTextEncodedScopeError::EmptyScope)
        } else {
            Ok(TextEncodedScope(value.into()))
        }
    }
}

impl TryFrom<Vec<&str>> for TextEncodedScope {
    type Error = InvalidTextEncodedScopeError;

    fn try_from(value: Vec<&str>) -> Result<Self, Self::Error> {
        if value.iter().any(|x| x.contains([' ', '\\', '"'])) {
            Err(InvalidTextEncodedScopeError::IllegalCharacters)
        } else if value.iter().any(|x| x.is_empty()) {
            Err(InvalidTextEncodedScopeError::EmptyElement)
        } else if value.is_empty() {
            Err(InvalidTextEncodedScopeError::EmptyScope)
        } else {
            // Fold the vec into a single string, using space as a separator
            Ok(TextEncodedScope(value.join(" ")))
        }
    }
}

impl BinaryEncodedScope {
    /// Return the individual elements (i.e., access ranges) of this scope.
    ///
    /// ## Pre-conditions
    /// - The given separator may neither be the first nor last element of the scope.
    /// - The given separator may not occur twice in a row in the scope.
    /// - The scope must not be empty.
    ///
    /// ## Post-conditions
    /// - The returned iterator will not be empty
    /// - None of its elements will be empty
    /// - None of its elements will contain the given separator.
    ///
    /// # Example
    ///
    /// ```
    /// # use dcaf::ace::BinaryEncodedScope;
    /// # use dcaf::InvalidBinaryEncodedScopeError;
    /// let simple = BinaryEncodedScope::try_from(vec![0xDC, 0x21, 0xAF].as_slice())?;
    /// assert!(simple.elements(0x21)?.eq(vec![vec![0xDC], vec![0xAF]]));
    /// assert!(simple.elements(0xDC).is_err());
    /// # Ok::<(), InvalidBinaryEncodedScopeError>(())
    /// ```
    ///
    /// # Panics
    /// If the pre-condition that the scope isn't empty is violated.
    /// This shouldn't occur, as it's an invariant of [BinaryEncodedScope].
    pub fn elements(
        &self,
        separator: u8,
    ) -> Result<impl Iterator<Item=&[u8]>, InvalidBinaryEncodedScopeError> {
        let split = self.0.split(move |x| x == &separator);
        // We use an assert rather than an Error because the client is not expected to handle this.
        assert!(
            !self.0.is_empty(),
            "Invariant violated: Scope may not be empty"
        );
        if self.0.first().filter(|x| **x != separator).is_none() {
            Err(InvalidBinaryEncodedScopeError::StartsWithSeparator(
                separator,
            ))
        } else if self.0.last().filter(|x| **x != separator).is_none() {
            Err(InvalidBinaryEncodedScopeError::EndsWithSeparator(separator))
        } else if self.0.windows(2).any(|x| x[0] == x[1] && x[1] == separator) {
            Err(InvalidBinaryEncodedScopeError::ConsecutiveSeparators(
                separator,
            ))
        } else {
            debug_assert!(
                split.clone().all(|x| !x.is_empty()),
                "Post-condition violated: Result may not contain empty slices"
            );
            Ok(split)
        }
    }
}

impl TryFrom<&[u8]> for BinaryEncodedScope {
    type Error = InvalidBinaryEncodedScopeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let vec = value.to_vec();
        if vec.is_empty() {
            Err(InvalidBinaryEncodedScopeError::EmptyScope)
        } else {
            Ok(BinaryEncodedScope(ByteString::from(value.to_vec())))
        }
    }
}

impl From<TextEncodedScope> for Scope {
    fn from(value: TextEncodedScope) -> Self {
        Scope::TextEncoded(value)
    }
}

impl TryFrom<Vec<&str>> for Scope {
    type Error = InvalidTextEncodedScopeError;

    fn try_from(value: Vec<&str>) -> Result<Self, InvalidTextEncodedScopeError> {
        value.try_into()
    }
}

impl TryFrom<&[u8]> for Scope {
    type Error = InvalidBinaryEncodedScopeError;

    fn try_from(value: &[u8]) -> Result<Self, InvalidBinaryEncodedScopeError> {
        value.try_into()
    }
}

impl From<BinaryEncodedScope> for Scope {
    fn from(value: BinaryEncodedScope) -> Self {
        Scope::BinaryEncoded(value)
    }
}

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
    use core::any::type_name;
    use core::fmt::Display;

    use ciborium::value::{Integer, Value};
    use erased_serde::Serialize as ErasedSerialize;

    use crate::ace::{
        AccessTokenRequest, AccessTokenResponse, AceProfile, AuthServerRequestCreationHint,
        BinaryEncodedScope, ErrorCode, ErrorResponse, GrantType, Scope, TextEncodedScope,
        TokenType,
    };
    use crate::cbor_values::ByteString;
    use crate::error::TryFromCborMapError;
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

    fn decode_scope<T, S>(scope: T) -> Result<Option<Scope>, TryFromCborMapError>
        where
            S: TryFrom<T>,
            Scope: From<S>,
            S::Error: Display,
    {
        match S::try_from(scope) {
            Ok(scope) => Ok(Some(Scope::from(scope))),
            Err(e) => {
                return Err(TryFromCborMapError::from_message(format!(
                    "couldn't decode scope: {e}"
                )))
            }
        }
    }

    fn decode_number<T>(number: Integer, name: &str) -> Result<T, TryFromCborMapError> where T: TryFrom<Integer> {
        match T::try_from(number) {
            Ok(i) => Ok(i),
            Err(_) => {
                return Err(TryFromCborMapError::from_message(
                    format!("{name} must be a valid {}", type_name::<T>()),
                ))
            }
        }
    }

    fn decode_int_map<T>(map: Vec<(Value, Value)>, name: &str) -> Result<Vec<(i128, Value)>, TryFromCborMapError> where T: AsCborMap {
        T::cbor_map_from_int(map).map_err(|_|
            TryFromCborMapError::from_message(format!(
                "{name} is not a valid CBOR map"
            ))
        )
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
