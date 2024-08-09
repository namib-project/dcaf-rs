/*
 * Copyright (c) 2022, 2024 The NAMIB Project Developers.
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
//! - [`constants`] contains various constants defined in the standards related to ACE-OAuth.
//! - [`cbor_map`] contains the [`ToCborMap`](cbor_map::ToCborMap) trait with which
//!   data types from this crate can be (de)serialized.
//! - [`cbor_values`] contains various helper values for CBOR structures.
//! - [`scope`] contains data types and methods for working with OAuth scopes.
//!
//! Read the respective module-level documentation for details and examples.
//!
//! [`constants`]: constants
//! [`cbor_map`]: cbor_map
//! [`cbor_values`]: cbor_values
//! [`scope`]: scope

pub mod cbor_map;
pub mod cbor_values;
pub mod constants;
pub mod scope;

#[cfg(test)]
pub(crate) mod test_helper;
