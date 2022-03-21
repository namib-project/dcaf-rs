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
//! [`draft-ietf-ace-oauth-authz`](https://www.ietf.org/archive/id/draft-ietf-ace-oauth-authz-46.html).
//!
//! # Layout
//! - [`creation_hint`]: Contains the data model for Authorization Server Request Creation Hints.
//! - [`token_req`]: Contains the data models for structures related to access token requests and responses.

pub mod creation_hint;
pub mod token_req;

