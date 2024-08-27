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
use coset::iana;
use rand::{CryptoRng, RngCore};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, EncryptCryptoBackend};
use alloc::vec::Vec;

#[cfg(feature = "rustcrypto-aes-gcm")]
mod aes_gcm;

#[cfg(feature = "rustcrypto-aes-ccm")]
mod aes_ccm;

#[cfg(feature = "rustcrypto-chacha20-poly1305")]
mod chacha_poly;

#[cfg(any(
    feature = "rustcrypto-aes-gcm",
    feature = "rustcrypto-aes-ccm",
    feature = "rustcrypto-chacha20-poly1305"
))]
mod aead;

impl<RNG: RngCore + CryptoRng> EncryptCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-aes-gcm")]
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::encrypt_aes_gcm(algorithm, &key, plaintext, aad, iv)
    }

    #[cfg(feature = "rustcrypto-aes-gcm")]
    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::decrypt_aes_gcm(algorithm, &key, ciphertext_with_tag, aad, iv)
    }

    #[cfg(feature = "rustcrypto-aes-ccm")]
    fn encrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::encrypt_aes_ccm(algorithm, &key, plaintext, aad, iv)
    }

    #[cfg(feature = "rustcrypto-aes-ccm")]
    fn decrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::decrypt_aes_ccm(algorithm, &key, ciphertext_with_tag, aad, iv)
    }

    #[cfg(feature = "rustcrypto-chacha20-poly1305")]
    fn encrypt_chacha20_poly1305(
        &mut self,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::encrypt_chacha20_poly1305(&key, plaintext, aad, iv)
    }

    #[cfg(feature = "rustcrypto-chacha20-poly1305")]
    fn decrypt_chacha20_poly1305(
        &mut self,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::decrypt_chacha20_poly1305(&key, ciphertext_with_tag, aad, iv)
    }
}
