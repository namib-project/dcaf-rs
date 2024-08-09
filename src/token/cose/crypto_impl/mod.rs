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

//! Implementations of the traits required for token handling (
//! [`EncryptCryptoBackend`](super::EncryptCryptoBackend), [`SignCryptoBackend`](super::SignCryptoBackend),
//! [`MacCryptoBackend`](super::MacCryptoBackend),
//! [`KeyDistributionCryptoBackend`](super::KeyDistributionCryptoBackend)) for different
//! cryptographic libraries.

/// Cryptographic backend based on the OpenSSL library (accessed using the `openssl` crate).
#[cfg(feature = "openssl")]
pub mod openssl;

/// Cryptographic backend based on the RustCrypto collection of crates.
#[cfg(rustcrypto_base)]
pub mod rustcrypto;
