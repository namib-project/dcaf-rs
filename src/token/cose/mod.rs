/*
 * Copyright (c) 2022-2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
//! Extensions to [`coset`] for easier cryptographic operations.
//!
//! This module is intended to abstract away most of the complexities regarding cryptographic
//! operations for COSE structures, i.e. they allow you to encrypt/sign/compute/decrypt/verify COSE
//! structures without manually defining callbacks that actually perform the cryptographic
//! computations.
//!
//! # Key providers
//!
//! Cryptographic operations require one or more keys to be provided to the library.
//! Usually, you may do so by simply providing a reference to a key or [`Vec`] of keys, optionally
//! restricting the returned keys to those with matching key IDs to the COSE structure using the
//! [`KeyProviderFilterMatchingKeyId`] wrapper.
//!
//! For more advanced use cases (e.g. retrieving keys on demand from a database), you might want to
//! consider implementing the [`KeyProvider`] trait yourself.
//!
//! # AAD providers
//!
//! Similarly to key providers, AAD providers provide the additional authenticated data for COSE
//! structures.
//!
//! In almost all cases you will probably just provide a slice of bytes here.
//!
//! In cases where you need to provide multiple sets of AAD at once, e.g. for nested COSE recipient
//! structures where different recipients have different AAD, you may look at either implementing
//! [`AadProvider`] yourself or using the predefined operations defined in the [`aad`] module.
//!
//! # COSE Cipher
//! This crate does not implement the basic cryptographic functions used for encrypting/signing or
//! decrypting/verifying itself.
//! Instead, we rely on cryptographic backends that perform the basic operations for us.
//! These backends implement the [`CryptoBackend`] trait as well as the [`EncryptCryptoBackend`],
//! [`SignCryptoBackend`], [`MacCryptoBackend`], and [`KeyDistributionCryptoBackend`] traits for
//! specific subsets of operations.
//!
//! Implementations of such backends and documentation regarding their supported features can be
//! found in the [`crypto_impl`] module.
//! Currently, only one cryptographic backend is implemented, which uses the [`openssl`] crate under
//! the hood.
//!
//! If you wish to provide your own cryptographic backend, have a look at the documentation of the
//! aforementioned traits, which describe exactly what such a backend needs to provide.
//!
//! # Constructing COSE Structures
//!
//! Most operations do not allow you to specify the algorithms and parameters for algorithms to use
//! directly.
//! Instead, they will read those parameters from the provided headers, and return an error if an
//! invalid combination of values is detected.
//!
//! Here are some guidelines on things that you should ensure when constructing COSE structures in
//! order to avoid errors.
//!
//! ## Header fields must only be specified once
//! Setting the same header field in both the protected and unprotected header buckets will result
//! in an error.
//!
//! ```
//! use coset::{CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana};
//! use dcaf::error::CoseCipherError;
//! use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
//! use dcaf::token::cose::{CoseEncrypt0BuilderExt, CryptoBackend};
//!
//! let mut backend = OpensslContext::new();
//!
//! let mut key_data = vec![0; 32];
//! backend.generate_rand(key_data.as_mut_slice())?;
//! let key = CoseKeyBuilder::new_symmetric_key(key_data).build();
//!
//! let unprotected = HeaderBuilder::new().algorithm(iana::Algorithm::A256GCM).build();
//! let protected = HeaderBuilder::new().algorithm(iana::Algorithm::A256GCM).build();
//!
//!
//! assert!(
//!     matches!(
//!         CoseEncrypt0Builder::new().try_encrypt(
//!             &mut backend,
//!             &key,
//!             Some(protected),
//!             Some(unprotected),
//!             "payload".as_bytes(),
//!             &[] as &[u8]
//!         ),
//!         Err(CoseCipherError::DuplicateHeaders(_))
//!     )
//! );
//!
//! # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
//! ```
//!
//! ## Specifying the Algorithm
//!
//! You *must* provide a way for the library to identify the algorithm to use.
//! This can either be done in the provided [`key`](coset::CoseKey) or in the unprotected or
//! protected header buckets.
//!
//! ```
//! use coset::{CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana};
//! use dcaf::error::CoseCipherError;
//! use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
//! use dcaf::token::cose::{CoseEncrypt0BuilderExt, CryptoBackend};
//!
//! let mut backend = OpensslContext::new();
//!
//! let mut key_data = vec![0; 32];
//! backend.generate_rand(key_data.as_mut_slice())?;
//! let key = CoseKeyBuilder::new_symmetric_key(key_data).build();
//!
//! let unprotected = HeaderBuilder::new().build();
//! let protected = HeaderBuilder::new().build();
//!
//!
//! assert!(
//!     matches!(
//!         CoseEncrypt0Builder::new().try_encrypt(
//!             &mut backend,
//!             &key,
//!             Some(protected),
//!             Some(unprotected),
//!             "payload".as_bytes(),
//!             &[] as &[u8]
//!         ),
//!         Err(CoseCipherError::NoMatchingKeyFound(_))
//!     )
//! );
//!
//! # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
//! ```
//!
//! Note that if you don't set the algorithm in the headers, the recipient of the message must be
//! able to infer the algorithm to use from somewhere else.
//!
//! Setting the algorithm in the headers to a different value than the one specified in the key will
//! also result in an error.
//!
//!
//! ```
//! use coset::{Algorithm, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana};
//! use dcaf::error::CoseCipherError;
//! use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
//! use dcaf::token::cose::{CoseEncrypt0BuilderExt, CryptoBackend};
//!
//! let mut backend = OpensslContext::new();
//!
//! let mut key_data = vec![0; 32];
//! backend.generate_rand(key_data.as_mut_slice())?;
//! let key = CoseKeyBuilder::new_symmetric_key(key_data).algorithm(iana::Algorithm::A256GCM).build();
//!
//! let unprotected = HeaderBuilder::new().algorithm(iana::Algorithm::A128GCM).build();
//! let protected = HeaderBuilder::new().build();
//!
//!
//! assert!(
//!     matches!(
//!         CoseEncrypt0Builder::new().try_encrypt(
//!             &mut backend,
//!             &key,
//!             Some(protected),
//!             Some(unprotected),
//!             "payload".as_bytes(),
//!             &[] as &[u8]
//!         ),
//!         Err(CoseCipherError::NoMatchingKeyFound(_))
//!     )
//! );
//!
//! # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
//! ```
//!
//! ## Ensure that the Key can be used for the Algorithm
//!
//! Most algorithms only work with specific types of keys.
//! For instance, ECDSA algorithms obviously only allow elliptic curve keys.
//!
//! Failing to provide the right type of key will result in a
//! [`CoseCipherError::KeyTypeAlgorithmMismatch`](crate::error::CoseCipherError::KeyTypeAlgorithmMismatch).
//!
//! Additional restrictions may also apply, e.g. regarding key length, required parameters and/or
//! elliptic curves used.
//! See the appropriate RFC for more information on those restrictions.
//!
//! ## Ensure that required Headers are set
//!
//! Some algorithms may require specific header parameters to be set.
//! For instance, some of the AES variants require the initialization vector to be set.
//!
//! Failure to do so will result in a
//! [`CoseCipherError::MissingHeaderParam`](crate::error::CoseCipherError::MissingHeaderParam)
//! error.
//!
//! ## Payload restrictions
//!
//! Some algorithms (e.g. AES key wrap) only accept payloads of specific lengths (most don't,
//! though).

use core::fmt::{Debug, Display};

pub mod crypto_impl;
mod encrypted;
mod key;
mod signed;

mod maced;
mod recipient;

/// AAD providers and operations for those.
pub mod aad;

pub use aad::AadProvider;
pub use encrypted::*;
pub use key::*;
pub use maced::*;
pub use recipient::*;
pub use signed::*;
pub use util::*;

#[cfg(all(test, feature = "std"))]
pub(crate) mod test_helper;
pub mod util;

/// Trait for implementations of cryptographic functions that can be used for COSE structures.
pub trait CryptoBackend {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;

    /// Fill the given buffer with random bytes.
    ///
    /// Mainly used for IV or key generation.
    ///
    /// # Errors
    ///
    /// Implementations may return errors if the generation of random bytes fails for any reason.
    /// If errors can occur, implementors should add the possible errors and the situations under
    /// which they occur to their documentation.
    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}
