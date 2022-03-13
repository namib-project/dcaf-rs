#![allow(rustdoc::broken_intra_doc_links)]
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
    AccessTokenRequest, AccessTokenResponse, AceProfile, ErrorCode, ErrorResponse, GrantType,
    TokenType,
};
#[doc(inline)]
pub use token::{
    decrypt_access_token, encrypt_access_token, sign_access_token, verify_access_token,
    CoseEncrypt0Cipher, CoseSign1Cipher, CoseMac0Cipher,
};

pub mod common;
pub mod endpoints;
pub mod error;
pub mod token;
