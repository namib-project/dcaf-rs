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

//! An implementation of the [ACE-OAuth framework (RFC 9200)](https://www.rfc-editor.org/rfc/rfc9200).
//!
//! This crate implements the ACE-OAuth
//! (Authentication and Authorization for Constrained Environments using the OAuth 2.0 Framework)
//! framework as defined in [RFC 9200](https://www.rfc-editor.org/rfc/rfc9200).
//! Key features include CBOR-(de-)serializable data models such as [`AccessTokenRequest`],
//! as well as the possibility to create COSE encrypted/signed access tokens
//! (as described in the standard) along with decryption/verification functions.
//! Implementations of the cryptographic functions must be provided by the user by implementing
//! [`EncryptCryptoBackend`](token::cose::EncryptCryptoBackend) or
//! [`SignCryptoBackend`](token::cose::SignCryptoBackend).
//!
//! Note that actually transmitting the serialized values (e.g., via CoAP) or providing more complex
//! features not mentioned in the ACE-OAuth RFC (e.g., a permission management system for
//! the Authorization Server) is *out of scope* for this crate.
//! This also applies to cryptographic functions, as mentioned in the previous paragraph.
//!
//! The name DCAF was chosen because eventually, it's planned for this crate to support
//! functionality from the [Delegated CoAP Authentication and Authorization Framework (DCAF)](https://dcaf.science/)
//! specified in [`draft-gerdes-ace-dcaf-authorize`](https://datatracker.ietf.org/doc/html/draft-gerdes-ace-dcaf-authorize-04)
//! (which was specified prior to ACE-OAuth and inspired many design choices in it)---
//! specifically, it's planned to support using a CAM (Client Authorization Manager)
//! instead of just a SAM (Server Authorization Manager), as is done in ACE-OAuth.
//! Compatibility with the existing [DCAF implementation in C](https://gitlab.informatik.uni-bremen.de/DCAF/dcaf)
//! (which we'll call `libdcaf` to disambiguate from `dcaf` referring to this crate) is also an
//! additional design goal, though the primary objective is still to support ACE-OAuth.
//!
//! As one of the possible use-cases for this crate is usage on constrained IoT devices,
//! requirements are minimal---as such, while `alloc` is still needed, this crate offers
//! `no_std` support by omitting the default `std` feature.
//!
//! # Usage
//! ```toml
//! [dependencies]
//! dcaf = { version = "^0.4" }
//! ```
//! Or, if you plan to use this crate in a `no_std` environment:
//! ```toml
//! [dependencies]
//! dcaf = { version = "^0.4", default-features = false }
//! ```
//!
//! # Example
//! As mentioned, the main features of this crate are ACE-OAuth data models and
//! token creation/verification functions. We'll quickly introduce both of these here.
//!
//! ## Data models
//! [For example](https://www.rfc-editor.org/rfc/rfc9200#figure-6),
//! let's assume you (the client) want to request an access token from an Authorization Server.
//! For this, you'd need to create an [`AccessTokenRequest`], which has to include at least a
//! `client_id`. We'll also specify an audience, a scope (using [`TextEncodedScope`]---note that
//! [binary-encoded scopes](BinaryEncodedScope) or [AIF-encoded scopes](AifEncodedScope) would also work), as well as a
//! [`ProofOfPossessionKey`] (the key the access token should be bound to) in the `req_cnf` field.
//!
//! Creating, serializing and then de-serializing such a structure would look like this:
//! ```
//! # use std::error::Error;
//! use dcaf::{AccessTokenRequest, ToCborMap, ProofOfPossessionKey, TextEncodedScope};
//!
//! # #[cfg(feature = "std")] {
//! let request = AccessTokenRequest::builder()
//!    .client_id("myclient")
//!    .audience("valve242")
//!    .scope(TextEncodedScope::try_from("read")?)
//!    .req_cnf(ProofOfPossessionKey::KeyId(hex::decode("ea483475724cd775")?))
//!    .build()?;
//! let mut encoded = Vec::new();
//! request.clone().serialize_into(&mut encoded)?;
//! assert_eq!(AccessTokenRequest::deserialize_from(encoded.as_slice())?, request);
//! # }
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//!
//! # Provided Data Models
//!
//! ## Token Endpoint
//! The most commonly used models will probably be the token endpoint's
//! [`AccessTokenRequest`] and [`AccessTokenResponse`] described in
//! [section 5.8 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8).
//! In case of an error, an [`ErrorResponse`] should be used.
//!
//! After an initial Unauthorized Resource Request Message, an
//! [`AuthServerRequestCreationHint`]
//! can be used to provide additional information to the client, as described in
//! [section 5.3 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3).
//!
//! ## Common Data Types
//! Some types used across multiple scenarios include:
//! - [`Scope`] (as described in
//!   [section 5.8.1 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1)),
//!   either as a [`TextEncodedScope`], a [`BinaryEncodedScope`] or an [`AifEncodedScope`].
//! - [`ProofOfPossessionKey`] as specified in
//!   [section 3.1 of RFC 8747](https://www.rfc-editor.org/rfc/rfc8747#section-3.1).
//!   For example, this will be used in the access token's `cnf` claim.
//! - While not really a data type, various constants representing values used in ACE-OAuth
//!   are provided in the [`constants`] module.
//!
//! # Token handling
//!
//! This crate also provides some functionality regarding the encoding and decoding of access
//! tokens, especially of CBOR Web Tokens.
//!
//! See the [token] module-level documentation for more information.

#![deny(
    rustdoc::broken_intra_doc_links,
    clippy::pedantic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
// These ones are a little too eager
#![allow(
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::wildcard_imports,
    clippy::type_complexity
)]
#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate derive_builder;
extern crate core;

#[doc(inline)]
pub use common::cbor_map::ToCborMap;
#[doc(inline)]
pub use common::cbor_values::{ByteString, ProofOfPossessionKey};
#[doc(inline)]
pub use common::constants;
#[doc(inline)]
pub use common::scope::{
    AifEncodedScope, BinaryEncodedScope, LibdcafEncodedScope, Scope, TextEncodedScope,
};
#[doc(inline)]
pub use endpoints::creation_hint::AuthServerRequestCreationHint;
#[doc(inline)]
pub use endpoints::token_req::{
    AccessTokenRequest, AccessTokenResponse, AceProfile, ErrorCode, ErrorResponse, GrantType,
    TokenType,
};
#[doc(inline)]
pub use token::{
    decrypt_access_token, decrypt_access_token_multiple, encrypt_access_token,
    encrypt_access_token_multiple, get_token_headers, sign_access_token,
    sign_access_token_multiple, verify_access_token, verify_access_token_multiple,
};

pub mod common;
pub mod endpoints;
pub mod error;
pub mod token;
