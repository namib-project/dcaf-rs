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
//! Key features include CBOR-(de-)serializable data models such as [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenRequest.html),
//! as well as the possibility to create COSE encrypted/signed access tokens
//! (as described in the standard) along with decryption/verification functions.
//! Implementations of the cryptographic functions must be provided by the user by implementing
//! [`EncryptCryptoBackend`](https://docs.rs/dcaf/latest/dcaf/token/cose/trait.EncryptCryptoBackend.html)
//! or [`SignCryptoBackend`](https://docs.rs/dcaf/latest/dcaf/token/cose/trait.SignCryptoBackend.html).
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
//! For this, you'd need to create an [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenRequest.html),
//! which has to include at least a `client_id`. We'll also specify an audience, a scope (using
//! [`TextEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.TextEncodedScope.html)---note that
//! [binary-encoded scopes](https://docs.rs/dcaf/latest/dcaf/struct.BinaryEncodedScope.html) or
//! [AIF-encoded scopes](https://docs.rs/dcaf/latest/dcaf/struct.AifEncodedScope.html) would also
//! work), as well as a [`ProofOfPossessionKey`](https://docs.rs/dcaf/latest/dcaf/enum.ProofOfPossessionKey.html)
//! (the key the access token should be bound to) in the `req_cnf` field.
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
//! ## Access Tokens
//! Following up from the previous example, let's assume we now want to create a signed
//! access token containing the existing `key`, as well as claims about the audience and issuer
//! of the token, using the `openssl` cryptographic backend and the signing key `sign_key`:
//!
//! ```
//! # use base64::Engine;
//! use coset::{AsCborValue, CoseKeyBuilder, HeaderBuilder, iana};
//! use coset::cwt::ClaimsSetBuilder;
//! use coset::iana::CwtClaimName;
//! use dcaf::{sign_access_token, verify_access_token};
//! use dcaf::error::{AccessTokenError, CoseCipherError};
//! use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
//! use dcaf::token::cose::{CryptoBackend, HeaderBuilderExt};
//!
//! let mut backend = OpensslContext::new();
//!
//! # let cose_ec2_key_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
//! # let cose_ec2_key_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
//! # let cose_ec2_key_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
//! let sign_key = CoseKeyBuilder::new_ec2_priv_key(
//!                             iana::EllipticCurve::P_256,
//!                             cose_ec2_key_x, // X component of elliptic curve key
//!                             cose_ec2_key_y, // Y component of elliptic curve key
//!                             cose_ec2_key_d  // D component of elliptic curve key
//!                 )
//!                 .key_id("sign_key".as_bytes().to_vec())
//!                 .build();
//!
//! let mut key_data = vec![0; 32];
//! backend.generate_rand(key_data.as_mut_slice()).map_err(CoseCipherError::from)?;
//! let key = CoseKeyBuilder::new_symmetric_key(key_data).build();
//!
//! let unprotected_header = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();
//!
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
//!      .build();
//!
//! let token = sign_access_token(&mut backend, &sign_key, claims, &None, Some(unprotected_header), None)?;
//! assert!(verify_access_token(&mut backend, &sign_key, &token, &None).is_ok());
//! # Ok::<(), AccessTokenError<<OpensslContext as CryptoBackend>::Error>>(())
//! ```
//!
//! # Provided Data Models
//!
//! ## Token Endpoint
//! The most commonly used models will probably be the token endpoint's
//! [`AccessTokenRequest`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenRequest.html) and
//! [`AccessTokenResponse`](https://docs.rs/dcaf/latest/dcaf/struct.AccessTokenResponse.html)
//! described in [section 5.8 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8).
//! In case of an error, an [`ErrorResponse`] should be used.
//!
//! After an initial Unauthorized Resource Request Message, an
//! [`AuthServerRequestCreationHint`](https://docs.rs/dcaf/latest/dcaf/struct.AuthServerRequestCreationHint.html)
//! can be used to provide additional information to the client, as described in
//! [section 5.3 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3).
//!
//! ## Common Data Types
//! Some types used across multiple scenarios include:
//! - [`Scope`](https://docs.rs/dcaf/latest/dcaf/enum.Scope.html) (as described in
//!   [section 5.8.1 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1)),
//!   either as a [`TextEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.TextEncodedScope.html),
//!   a [`BinaryEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.BinaryEncodedScope.html) or
//!   an [`AifEncodedScope`](https://docs.rs/dcaf/latest/dcaf/struct.AifEncodedScope.html).
//! - [`ProofOfPossessionKey`](https://docs.rs/dcaf/latest/dcaf/enum.ProofOfPossessionKey.html) as
//!   specified in [section 3.1 of RFC 8747](https://www.rfc-editor.org/rfc/rfc8747#section-3.1).
//!   For example, this will be used in the access token's `cnf` claim.
//! - While not really a data type, various constants representing values used in ACE-OAuth
//!   are provided in the [`constants`](https://docs.rs/dcaf/latest/dcaf/constants/index.html) module.
//!
//! # Token handling
//!
//! This crate also provides some functionality regarding the encoding and decoding of access
//! tokens, especially of CBOR Web Tokens (CWTs, [RFC 8392](https://datatracker.ietf.org/doc/html/rfc8392)),
//! which are based on the COSE specification ([RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052)).
//!
//! Generation and validation of CWTs is supported for CWTs based on signed and encrypted
//! COSE objects. Additionally, helper methods are provided to more easily create and validate
//! COSE objects that are encrypted, signed or authenticated using MACs.   
//!
//! See the [token](https://docs.rs/dcaf/latest/dcaf/token/index.html) module-level documentation
//! for more information.

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
