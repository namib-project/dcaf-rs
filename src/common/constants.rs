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

//! Contains various constants defined in the standards and drafts related to ACE-OAuth.
//!
//! # Sources
//! - [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html)
//! - [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! - [`draft-ietf-ace-oauth-params-16`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-params-16.html)
//! - [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.txt)
//! - [`draft-ietf-ace-dtls-authorize`](https://www.ietf.org/archive/id/draft-ietf-ace-dtls-authorize-18.html)

/// Constants which abbreviate string values as integers in CBOR.
pub mod cbor_abbreviations {
    /// Constants for CBOR map keys in AS Request Creation Hints,
    /// as specified in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html), Figure 2.
    pub mod creation_hint {
        /// See section 5.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const AS: u8 = 1;

        /// See section 5.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const KID: u8 = 2;

        /// See section 5.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const AUDIENCE: u8 = 5;

        /// See section 5.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const SCOPE: u8 = 9;

        /// See section 5.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const CNONCE: u8 = 39;
    }

    /// Constants for CBOR map keys in token requests and responses,
    /// as specified in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html), Figure 12
    /// and `draft-ietf-ace-oauth-params`, Figure 5.
    pub mod token {
        /// See section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const ACCESS_TOKEN: u8 = 1;

        /// See section 5.1 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const EXPIRES_IN: u8 = 2;

        /// See section 3.1 of [`draft-ietf-ace-oauth-params-16`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-params-16.html).
        pub const REQ_CNF: u8 = 4;

        /// See section 2.1 of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html).
        pub const AUDIENCE: u8 = 5;

        /// See section 3.2 of [`draft-ietf-ace-oauth-params-16`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-params-16.html).
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

        /// See section 5.8.4.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const ACE_PROFILE: u8 = 38;

        /// See section 5.8.4.4 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const CNONCE: u8 = 39;

        /// See section 3.2 of [`draft-ietf-ace-oauth-params-16`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-params-16.html).
        pub const RS_CNF: u8 = 41;
    }

    /// Constants for CBOR map keys in token introspections,
    /// as specified in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html), Figure 16
    /// and [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html).
    ///
    /// Some of these constants are also used by libdcaf for additional fields which are required
    /// according to [DCAF](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf/).
    ///
    /// **NOTE: This is currently incomplete!**
    /// Only libdcaf-required parameters are in here for now.
    pub mod introspection {
        /// See [section 3.1.1 of RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.1).
        pub const ISSUER: u8 = 1;

        /// See [section 3.1.6 of RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.6).
        pub const ISSUED_AT: u8 = 6;
    }

    /// Constants for CBOR abbreviations in grant types,
    /// as specified in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html), Figure 11.
    pub mod grant_types {
        /// See section 4.3.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const PASSWORD: i32 = 0;

        /// See section 4.1.3 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const AUTHORIZATION_CODE: i32 = 1;

        /// See section 4.4.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const CLIENT_CREDENTIALS: i32 = 2;

        /// See section 6 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const REFRESH_TOKEN: i32 = 3;
    }

    /// Constants for CBOR abbreviations in token types,
    /// as specified in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html), Section 8.7.
    pub mod token_types {
        /// Bearer token type, as specified in
        /// [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const BEARER: i32 = 1;

        /// Proof-of-possession token type, as specified in
        /// [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const POP: i32 = 2;
    }

    /// Constants for CBOR abbreviations in token types, as specified in:
    /// - `draft-ietf-ace-oauth-authz`, section 8.8.
    /// - [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.txt),
    ///   section 9.1.
    /// - [`draft-ietf-ace-dtls-authorize`](https://www.ietf.org/archive/id/draft-ietf-ace-dtls-authorize-18.html),
    ///   section 9.
    pub mod ace_profile {
        /// DTLS profile specified in
        /// [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.txt).
        ///
        /// **Note: The actual value is still TBD, this is just what's suggested in the draft above.**
        pub const COAP_DTLS: i32 = 1;

        // The below is commented out because no CBOR value has been set in the specification yet.
        // /// OSCORE profile specified in
        // /// [`draft-ietf-ace-oscore-profile`](https://www.ietf.org/archive/id/draft-ietf-ace-oscore-profile-19.txt).
        // // pub const COAP_OSCORE: i32;
    }

    /// Constants for CBOR abbreviations in error codes,
    /// as specified in [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html), Figure 10.
    pub mod error {
        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_REQUEST: i32 = 1;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_CLIENT: i32 = 2;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_GRANT: i32 = 3;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const UNAUTHORIZED_CLIENT: i32 = 4;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const UNSUPPORTED_GRANT_TYPE: i32 = 5;

        /// See section 5.2 of [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html).
        pub const INVALID_SCOPE: i32 = 6;

        /// See section 5.8.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const UNSUPPORTED_POP_KEY: i32 = 7;

        /// See section 5.8.3 of [`draft-ietf-ace-oauth-authz-46`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
        pub const INCOMPATIBLE_ACE_PROFILES: i32 = 8;
    }
}
