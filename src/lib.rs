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
//! Key features include CBOR-(de-)serializable data models such as [`AccessTokenRequest`](crate::endpoints::token_req::AccessTokenRequest),
//! as well as the possibility to create COSE encrypted/signed access tokens
//! (as described in the standard) along with decryption/verification functions.
//! Implementations of the cryptographic functions must be provided by the user by implementing
//! [`CoseEncryptCipher`](crate::token::CoseEncryptCipher) or [`CoseSignCipher`](crate::token::CoseSignCipher).
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
//! For this, you'd need to create an [`AccessTokenRequest`](crate::endpoints::token_req::AccessTokenRequest), which has to include at least a
//! `client_id`. We'll also specify an audience, a scope (using [`TextEncodedScope`](crate::common::scope::TextEncodedScope)---note that
//! [binary-encoded scopes](crate::common::scope::BinaryEncodedScope) or [AIF-encoded scopes](crate::common::scope::AifEncodedScope) would also work), as well as a
//! [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey) (the key the access token should be bound to) in the `req_cnf` field.
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
//! of the token, using an existing cipher of type `FakeCrypto`[^cipher]:
//! ```ignore
//! # use ciborium::value::Value;
//! # use coset::{AsCborValue, CoseKey, CoseKeyBuilder, Header, iana, Label, ProtectedHeader};
//! # use coset::cwt::{ClaimsSetBuilder, Timestamp};
//! # use coset::iana::{Algorithm, CwtClaimName};
//! # use rand::{CryptoRng, RngCore};
//! # use dcaf::{ToCborMap, sign_access_token, verify_access_token, CoseSignCipher};
//! # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! # use dcaf::common::cbor_values::ProofOfPossessionKey::PlainCoseKey;
//! # use dcaf::error::{AccessTokenError, CoseCipherError};
//! use dcaf::token::CoseCipher;
//!
//! # struct FakeCrypto {}
//! #
//! # #[derive(Clone, Copy)]
//! # pub(crate) struct FakeRng;
//! #
//! # fn get_k_from_key(key: &CoseKey) -> Option<Vec<u8>> {
//! #     const K_PARAM: i64 = iana::SymmetricKeyParameter::K as i64;
//! #     for (label, value) in key.params.iter() {
//! #         if let Label::Int(K_PARAM) = label {
//! #             if let Value::Bytes(k_val) = value {
//! #                 return Some(k_val.clone());
//! #             }
//! #         }
//! #     }
//! #     None
//! # }
//! #
//! # impl RngCore for FakeRng {
//! #     fn next_u32(&mut self) -> u32 {
//! #         0
//! #     }
//! #
//! #     fn next_u64(&mut self) -> u64 {
//! #         0
//! #     }
//! #
//! #     fn fill_bytes(&mut self, dest: &mut [u8]) {
//! #         dest.fill(0);
//! #     }
//! #
//! #     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
//! #         dest.fill(0);
//! #         Ok(())
//! #     }
//! # }
//! #
//! # impl CryptoRng for FakeRng {}
//! #
//! # impl CoseCipher for FakeCrypto {
//! #     type Error = String;
//! #
//! #     fn set_headers<RNG: RngCore + CryptoRng>(key: &CoseKey, unprotected_header: &mut Header, protected_header: &mut Header, rng: RNG) -> Result<(), CoseCipherError<Self::Error>> {
//! #         // We have to later verify these headers really are used.
//! #         if let Some(label) = unprotected_header
//! #             .rest
//! #             .iter()
//! #             .find(|x| x.0 == Label::Int(47))
//! #         {
//! #             return Err(CoseCipherError::existing_header_label(&label.0));
//! #         }
//! #         if protected_header.alg != None {
//! #             return Err(CoseCipherError::existing_header("alg"));
//! #         }
//! #         unprotected_header.rest.push((Label::Int(47), Value::Null));
//! #         protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::Direct));
//! #         Ok(())
//! #     }
//! # }
//! #
//! # /// Implements basic operations from the [`CoseSignCipher`](crate::token::CoseSignCipher) trait
//! # /// without actually using any "real" cryptography.
//! # /// This is purely to be used for testing and obviously offers no security at all.
//! # impl CoseSignCipher for FakeCrypto {
//! #     fn sign(
//! #         key: &CoseKey,
//! #         target: &[u8],
//! #         unprotected_header: &Header,
//! #         protected_header: &Header,
//! #     ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
//! #         // We simply append the key behind the data.
//! #         let mut signature = target.to_vec();
//! #         let k = get_k_from_key(key);
//! #         signature.append(&mut k.expect("k must be present in key!"));
//! #         Ok(signature)
//! #     }
//! #
//! #     fn verify(
//! #         key: &CoseKey,
//! #         signature: &[u8],
//! #         signed_data: &[u8],
//! #         unprotected_header: &Header,
//! #         protected_header: &ProtectedHeader,
//! #         unprotected_signature_header: Option<&Header>,
//! #         protected_signature_header: Option<&ProtectedHeader>,
//! #     ) -> Result<(), CoseCipherError<Self::Error>> {
//! #         if signature
//! #             == Self::sign(
//! #             key,
//! #             signed_data,
//! #             unprotected_header,
//! #             &protected_header.header,
//! #         )?
//! #         {
//! #             Ok(())
//! #         } else {
//! #             Err(CoseCipherError::VerificationFailure)
//! #         }
//! #     }
//! # }
//!
//! let rng = FakeRng;
//! let key = CoseKeyBuilder::new_symmetric_key(vec![1,2,3,4,5]).key_id(vec![0xDC, 0xAF]).build();
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
//!      .build();
//! let token = sign_access_token::<FakeCrypto, FakeRng>(&key, claims, None, None, None, rng)?;
//! assert!(verify_access_token::<FakeCrypto>(&key, &token, None).is_ok());
//! # Ok::<(), AccessTokenError<String>>(())
//! ```
//!
//! [^cipher]: Note that we are deliberately omitting details about the implementation of the
//! `cipher` here, since such implementations won't be in the scope of this crate.
//!
//! # Provided Data Models
//!
//! ## Token Endpoint
//! The most commonly used models will probably be the token endpoint's
//! [`AccessTokenRequest`](crate::endpoints::token_req::AccessTokenRequest) and
//! [`AccessTokenResponse`](crate::endpoints::token_req::AccessTokenResponse)
//! described in [section 5.8 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8).
//! In case of an error, an [`ErrorResponse`](crate::endpoints::token_req::ErrorResponse)
//! should be used.
//!
//! After an initial Unauthorized Resource Request Message, an
//! [`AuthServerRequestCreationHint`](crate::endpoints::creation_hint::AuthServerRequestCreationHint)
//! can be used to provide additional information to the client, as described in
//! [section 5.3 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.3).
//!
//! ## Common Data Types
//! Some types used across multiple scenarios include:
//! - [`Scope`](crate::common::scope::Scope) (as described in
//!   [section 5.8.1 of RFC 9200](https://www.rfc-editor.org/rfc/rfc9200#section-5.8.1)),
//!   either as a [`TextEncodedScope`](crate::common::scope::TextEncodedScope),
//!   a [`BinaryEncodedScope`](crate::common::scope::BinaryEncodedScope) or
//!   an [`AifEncodedScope`](crate::common::scope::AifEncodedScope).
//! - [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey) as specified in
//!   [section 3.1 of RFC 8747](https://www.rfc-editor.org/rfc/rfc8747#section-3.1).
//!   For example, this will be used in the access token's `cnf` claim.
//! - While not really a data type, various constants representing values used in ACE-OAuth
//!   are provided in the [`constants`](crate::common::constants) module.
//!
//! # Creating Access Tokens
//! In order to create access tokens, you can use either [`encrypt_access_token`](crate::token::encrypt_access_token)
//! or [`sign_access_token`](crate::token::sign_access_token),
//! depending on whether you want the access token to be wrapped in a
//! `COSE_Encrypt0` or `COSE_Sign1` structure. Support for a combination of both is planned for the
//! future. In case you want to create a token intended for multiple recipients (each with their
//! own key), you can use [`encrypt_access_token_multiple`](crate::token::encrypt_access_token_multiple)
//! or [`sign_access_token_multiple`](crate::token::sign_access_token_multiple).
//!
//! Both functions take a [`ClaimsSet`](coset::cwt::ClaimsSet) containing the claims that
//! shall be part of the access token, a key used to encrypt or sign the token,
//! optional `aad` (additional authenticated data), un-/protected headers and a cipher (explained
//! further below) identified by type parameter `T`.
//! Note that if the headers you pass in set fields which the cipher wants to set as well,
//! the function will fail with a `HeaderAlreadySet` error.
//! The function will return a [`Result`](::core::result::Result) of the opaque
//! [`ByteString`](crate::common::cbor_values::ByteString) containing the access token.
//!
//! # Verifying and Decrypting Access Tokens
//! In order to verify or decrypt existing access tokens represented as [`ByteString`](crate::common::cbor_values::ByteString)s,
//! use [`verify_access_token`](crate::token::verify_access_token) or
//! [`decrypt_access_token`](crate::token::decrypt_access_token) respectively.
//! In case the token was created for multiple recipients (each with their own key),
//! use [`verify_access_token_multiple`](crate::token::verify_access_token_multiple)
//! or [`decrypt_access_token_multiple`](crate::token::decrypt_access_token_multiple).
//!
//! Both functions take the access token, a `key` used to decrypt or verify, optional `aad`
//! (additional authenticated data) and a cipher implementing cryptographic operations identified
//! by type parameter `T`.
//!
//! [`decrypt_access_token`](crate::token::decrypt_access_token) will return a result containing
//! the decrypted [`ClaimsSet`](coset::cwt::ClaimsSet).
//! [`verify_access_token`](crate::token::verify_access_token) will return an empty result which
//! indicates that the token was successfully verified---an [`Err`](::core::result::Result)
//! would indicate failure.
//!
//! # Extracting Headers from an Access Token
//! Regardless of whether a token was signed, encrypted, or MAC-tagged, you can extract its
//! headers using [`get_token_headers`](crate::token::get_token_headers),
//! which will return an option containing both
//! unprotected and protected headers (or which will be [`None`](core::option::Option::None) in case
//! the token is invalid).
//!
//! # COSE Cipher
//! As mentioned before, cryptographic functions are outside the scope of this crate.
//! For this reason, the various COSE cipher traits exist; namely,
//! [`CoseEncryptCipher`](token::CoseEncryptCipher), [`CoseSignCipher`](token::CoseSignCipher),
//! and [`CoseMacCipher`](token::CoseMacCipher), each implementing
//! a corresponding COSE operation as specified in sections 4, 5, and 6 of
//! [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152).
//! There are also the traits [`MultipleEncryptCipher`](token::MultipleEncryptCipher),
//! [`MultipleSignCipher`](token::MultipleSignCipher), and
//! [`MultipleMacCipher`](token::MultipleMacCipher),
//! which are used for creating tokens intended for multiple recipients.
//!
//! Note that these ciphers *don't* need to wrap their results in, e.g.,
//! a `Cose_Encrypt0` structure, as this part is already handled by this library
//! (which uses [`coset`](coset))---only the cryptographic algorithms themselves need to be implemented
//! (e.g., step 4 of "how to decrypt a message" in [section 5.3 of RFC 8152](https://www.rfc-editor.org/rfc/rfc8152#section-5.3)).
//!
//! When implementing any of the specific COSE ciphers, you'll also need to specify the type
//! of the key (which must be convertible to a `CoseKey`) and implement a method which sets
//! headers for the token, for example, the used algorithm, the key ID, an IV, and so on.

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
    //decrypt_access_token, decrypt_access_token_multiple, encrypt_access_token,
    //encrypt_access_token_multiple,
    get_token_headers,
    sign_access_token,
    sign_access_token_multiple,
    verify_access_token,
    verify_access_token_multiple,
    //CoseEncryptCipher,
    //CoseMacCipher,
    CoseSignCipher,
    //MultipleEncryptCipher,
    //MultipleMacCipher,
};

pub mod common;
pub mod endpoints;
pub mod error;
pub mod token;
