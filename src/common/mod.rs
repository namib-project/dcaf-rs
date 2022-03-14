//! Common types used throughout the crate.
//!
//! # Layout
//! - [`constants`] contains various constants defined in the standards and drafts related to
//!   ACE-OAuth.
//! - [`cbor_map`] contains the [`AsCborMap`] trait with which data types from this crate can be
//!   (de)serialized.
//! - [`cbor_values`] contains various helper values for CBOR structures.
//! - [`scope`] contains data types and methods for working with OAuth scopes.
//!
//! Read the respective module-level documentation for details and examples.
//!
//! [`constants`]: crate::common::constants
//! [`cbor_map`]: crate::common::cbor_map
//! [`cbor_values`]: crate::common::cbor_values
//! [`scope`]: crate::common::scope

pub mod constants;
pub mod cbor_map;
pub mod cbor_values;
pub mod scope;

#[cfg(test)]
pub(crate) mod test_helper;
