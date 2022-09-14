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

//! Contains CBOR-serializable data types for the endpoints of ACE-OAuth.
//!
//! These endpoints are described in section 5 of
//! [RFC 9200](https://www.rfc-editor.org/rfc/rfc9200).
//!
//! Support for the introspection endpoint is planned.
//!
//! # Layout
//! - [`creation_hint`]: Contains the data model for Authorization Server Request Creation Hints.
//! - [`token_req`]: Contains the data models for structures related to access token requests and responses.

pub mod creation_hint;
pub mod token_req;

// TODO: Introspection data structures
