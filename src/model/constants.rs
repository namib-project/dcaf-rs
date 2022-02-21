/// Constants which abbreviate string values as integers in CBOR.
pub(crate) mod cbor_abbreviations {

    /// Constants for CBOR map keys in AS Request Creation Hints,
    /// as specified in `draft-ietf-ace-oauth-authz-46`, Figure 2.
    pub mod creation_hint {

        /// See section 5.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const AS: u8 = 1;

        /// See section 5.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const KID: u8 = 2;

        /// See section 5.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const AUDIENCE: u8 = 5;

        /// See section 5.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const SCOPE: u8 = 9;

        /// See section 5.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const CNONCE: u8 = 39;
    }

    /// Constants for CBOR map keys in token requests and responses,
    /// as specified in `draft-ietf-ace-oauth-authz-46`, Figure 12
    /// and `draft-ietf-ace-oauth-params`, Figure 5.
    pub mod token {
        /// See section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const ACCESS_TOKEN: u8 = 1;

        /// See section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const EXPIRES_IN: u8 = 2;

        /// See section 3.1 of `draft-ietf-ace-oauth-params-16`.
        pub const REQ_CNF: u8 = 4;

        /// See section 2.1 of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html).
        pub const AUDIENCE: u8 = 5;

        /// See section 3.2 of `draft-ietf-ace-oauth-params-16`.
        pub const CNF: u8 = 8;

        /// See section 4.4.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html)
        /// and section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const SCOPE: u8 = 9;

        /// See section 2.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const CLIENT_ID: u8 = 24;

        /// See section 2.3.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const CLIENT_SECRET: u8 = 25;

        /// See section 3.1.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const RESPONSE_TYPE: u8 = 26;

        /// See section 3.1.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const REDIRECT_URI: u8 = 27;

        /// See section 4.1.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const STATE: u8 = 28;

        /// See section 4.1.3 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const CODE: u8 = 29;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const ERROR: u8 = 30;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const ERROR_DESCRIPTION: u8 = 31;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const ERROR_URI: u8 = 32;

        /// See section 4.4.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const GRANT_TYPE: u8 = 33;

        /// See section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const TOKEN_TYPE: u8 = 34;

        /// See section 4.3.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const USERNAME: u8 = 35;

        /// See section 4.3.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const PASSWORD: u8 = 36;

        /// See section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const REFRESH_TOKEN: u8 = 37;

        /// See section 5.8.4.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const ACE_PROFILE: u8 = 38;

        /// See section 5.8.4.4 of `draft-ietf-ace-oauth-authz-46`.
        pub const CNONCE: u8 = 39;

        /// See section 3.2 of `draft-ietf-ace-oauth-params-16`.
        pub const RS_CNF: u8 = 41;
    }

    /// Constants for CBOR abbreviations in grant types,
    /// as specified in `draft-ietf-ace-oauth-authz-46`, Figure 11.
    pub mod grant_types {

        /// See section 4.3.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const PASSWORD: u8 = 0;

        /// See section 4.1.3 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const AUTHORIZATION_CODE: u8 = 1;

        /// See section 4.4.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const CLIENT_CREDENTIALS: u8 = 2;

        /// See section 6 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const REFRESH_TOKEN: u8 = 3;
    }

    /// Constants for CBOR abbreviations in token types,
    /// as specified in `draft-ietf-ace-oauth-authz-46`, Section 8.7.
    pub mod token_types {
        /// Bearer token type, as specified in
        /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const BEARER: u8 = 1;

        /// Proof-of-possession token type, as specified in
        /// `draft-ietf-ace-oauth-authz-46`.
        pub const POP: u8 = 2;
    }


    /// Constants for CBOR abbreviations in error codes,
    /// as specified in `draft-ietf-ace-oauth-authz-46`, Figure 10.
    pub mod error {
        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_REQUEST: u8 = 1;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_CLIENT: u8 = 2;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_GRANT: u8 = 3;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const UNAUTHORIZED_CLIENT: u8 = 4;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const UNSUPPORTED_GRANT_TYPE: u8 = 5;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_SCOPE: u8 = 6;

        /// See section 5.8.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const UNSUPPORTED_POP_KEY: u8 = 7;

        /// See section 5.8.3 of `draft-ietf-ace-oauth-authz-46`.
        pub const INCOMPATIBLE_ACE_PROFILES: u8 = 8;
    }
}