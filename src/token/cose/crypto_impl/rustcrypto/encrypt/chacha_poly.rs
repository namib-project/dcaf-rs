/*
 * Copyright (c) 2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};
use alloc::vec::Vec;
use chacha20poly1305::ChaCha20Poly1305;
use rand::CryptoRng;
use rand::RngCore;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Perform a ChaCha20/Poly1305 encryption operation on `plaintext` and the additional
    /// authenticated data `aad` using the given `iv` and `key`.
    pub(super) fn encrypt_chacha20_poly1305(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        Self::encrypt_aead::<ChaCha20Poly1305>(key, plaintext, aad, iv)
    }

    /// Perform a ChaCha20/Poly1305 decryption operation on `ciphertext_with_tag` and the additional
    /// authenticated data `aad` using the given `iv` and `key`.
    pub(super) fn decrypt_chacha20_poly1305(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        Self::decrypt_aead::<ChaCha20Poly1305>(key, ciphertext_with_tag, aad, iv)
    }
}
