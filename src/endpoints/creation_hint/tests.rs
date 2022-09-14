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

#[cfg(not(feature = "std"))]
use alloc::string::ToString;

use enumflags2::{make_bitflags, BitFlags};

use crate::common::scope::{AifRestMethod, TextEncodedScope};
use crate::common::test_helper::expect_ser_de;
use crate::{AifEncodedScope, BinaryEncodedScope, LibdcafEncodedScope};

use super::*;

/// Example data taken from RFC 9200, Figure 2 and 3.
#[test]
fn test_creation_hint_text_scope() -> Result<(), String> {
    let hint = AuthServerRequestCreationHintBuilder::default()
        .auth_server("coaps://as.example.com/token")
        .audience("coaps://rs.example.com")
        .scope(TextEncodedScope::try_from("rTempC").map_err(|x| x.to_string())?)
        .client_nonce(hex::decode("e0a156bb3f").map_err(|x| x.to_string())?)
        .build()
        .map_err(|x| x.to_string())?;
    expect_ser_de(hint, None, "a401781c636f6170733a2f2f61732e6578616d706c652e636f6d2f746f6b656e0576636f6170733a2f2f72732e6578616d706c652e636f6d09667254656d7043182745e0a156bb3f")
}

#[test]
fn test_creation_hint_binary_scope() -> Result<(), String> {
    let hint = AuthServerRequestCreationHintBuilder::default()
        .auth_server("coaps://as.example.com/token")
        .audience("coaps://rs.example.com")
        .scope(
            BinaryEncodedScope::try_from(vec![0xDC, 0xAF].as_slice()).map_err(|x| x.to_string())?,
        )
        .client_nonce(hex::decode("e0a156bb3f").map_err(|x| x.to_string())?)
        .build()
        .map_err(|x| x.to_string())?;
    expect_ser_de(hint, None, "A401781C636F6170733A2F2F61732E6578616D706C652E636F6D2F746F6B656E0576636F6170733A2F2F72732E6578616D706C652E636F6D0942DCAF182745E0A156BB3F")
}

#[test]
fn test_creation_hint_aif_scope() -> Result<(), String> {
    let hint = AuthServerRequestCreationHintBuilder::default()
        .auth_server("coaps://as.example.com/token")
        .audience("coaps://rs.example.com")
        .scope(AifEncodedScope::from(vec![
            ("/s/temp", make_bitflags!(AifRestMethod::{Get})),
            ("/a/led", make_bitflags!(AifRestMethod::{Get | Put})),
        ]))
        .client_nonce(hex::decode("e0a156bb3f").map_err(|x| x.to_string())?)
        .build()
        .map_err(|x| x.to_string())?;
    expect_ser_de(hint, None, "A401781C636F6170733A2F2F61732E6578616D706C652E636F6D2F746F6B656E0576636F6170733A2F2F72732E6578616D706C652E636F6D098282672F732F74656D700182662F612F6C656405182745E0A156BB3F")
}

#[test]
fn test_creation_hint_libdcaf_scope() -> Result<(), String> {
    let hint = AuthServerRequestCreationHintBuilder::default()
        .auth_server("coaps://as.example.com/token")
        .audience("coaps://rs.example.com")
        .scope(LibdcafEncodedScope::new("/x/none", BitFlags::empty()))
        .client_nonce(hex::decode("e0a156bb3f").map_err(|x| x.to_string())?)
        .build()
        .map_err(|x| x.to_string())?;
    expect_ser_de(hint, None, "A401781C636F6170733A2F2F61732E6578616D706C652E636F6D2F746F6B656E0576636F6170733A2F2F72732E6578616D706C652E636F6D0982672F782F6E6F6E6500182745E0A156BB3F")
}
