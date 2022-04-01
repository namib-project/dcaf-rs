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

//! Common types used throughout the crate.
//!
//! # Layout
//! - [`constants`] contains various constants defined in the standards and drafts related to
//!   ACE-OAuth.
//! - [`cbor_map`] contains the [`ToCborMap`](crate::common::cbor_map::ToCborMap) trait with which
//!   data types from this crate can be (de)serialized.
//! - [`cbor_values`] contains various helper values for CBOR structures.
//! - [`scope`] contains data types and methods for working with OAuth scopes.
//!
//! Read the respective module-level documentation for details and examples.
//!
//! [`constants`]: crate::common::constants
//! [`cbor_map`]: crate::common::cbor_map
//! [`cbor_values`]: crate::common::cbor_values
//! [`scope`]: crate::common::scope

pub mod cbor_map;
pub mod cbor_values;
pub mod constants;
pub mod scope;

#[cfg(test)]
pub(crate) mod test_helper;
