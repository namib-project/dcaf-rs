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

//! TODO: Crate-level documentation!

#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
extern crate core;
#[macro_use]
extern crate derive_builder;

#[doc(inline)]
pub use common::constants;
#[doc(inline)]
pub use common::scope::Scope;
#[doc(inline)]
pub use common::cbor_map::AsCborMap;
#[doc(inline)]
pub use endpoints::creation_hint::{AuthServerRequestCreationHint};
#[doc(inline)]
pub use endpoints::token_req::{
    AccessTokenRequest, AccessTokenResponse, ErrorResponse,
    AceProfile, ErrorCode, GrantType, TokenType,
};
#[doc(inline)]
pub use token::{
    decrypt_access_token, encrypt_access_token, sign_access_token, verify_access_token,
    CoseEncrypt0Cipher, CoseSign1Cipher, CoseMac0Cipher, CoseCipherCommon,
};

/// Contains common data types used across the crate.
pub mod common;
pub mod endpoints;
pub mod error;
pub mod token;
