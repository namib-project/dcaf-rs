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
use aes::{Aes128, Aes256};
use ccm::Ccm;
use coset::{iana, Algorithm};
use rand::CryptoRng;
use rand::RngCore;
use typenum::consts::{U13, U16, U7, U8};

use crate::error::CoseCipherError;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};

use super::RustCryptoContext;
use alloc::vec::Vec;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Perform an AES-CCM encryption operation on `plaintext` and the additional authenticated
    /// data `aad` using the given `iv` and `key` with the given `algorithm` variant of AES-GCM.
    pub(super) fn encrypt_aes_ccm(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::AES_CCM_16_64_128 => {
                Self::encrypt_aead::<Ccm<Aes128, U8, U13>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_16_64_256 => {
                Self::encrypt_aead::<Ccm<Aes256, U8, U13>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_64_128 => {
                Self::encrypt_aead::<Ccm<Aes128, U8, U7>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_64_256 => {
                Self::encrypt_aead::<Ccm<Aes256, U8, U7>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_16_128_128 => {
                Self::encrypt_aead::<Ccm<Aes128, U16, U13>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_16_128_256 => {
                Self::encrypt_aead::<Ccm<Aes256, U16, U13>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_128_128 => {
                Self::encrypt_aead::<Ccm<Aes128, U16, U7>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_128_256 => {
                Self::encrypt_aead::<Ccm<Aes256, U16, U7>>(key, plaintext, aad, iv)
            }
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }

    /// Perform an AES-CCM decryption operation on `ciphertext` and the additional authenticated
    /// data `aad` using the given `iv` and `key` with the given `algorithm` variant of AES-GCM.
    pub(super) fn decrypt_aes_ccm(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::AES_CCM_16_64_128 => {
                Self::decrypt_aead::<Ccm<Aes128, U8, U13>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_16_64_256 => {
                Self::decrypt_aead::<Ccm<Aes256, U8, U13>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_64_128 => {
                Self::decrypt_aead::<Ccm<Aes128, U8, U7>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_64_256 => {
                Self::decrypt_aead::<Ccm<Aes256, U8, U7>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_16_128_128 => {
                Self::decrypt_aead::<Ccm<Aes128, U16, U13>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_16_128_256 => {
                Self::decrypt_aead::<Ccm<Aes256, U16, U13>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_128_128 => {
                Self::decrypt_aead::<Ccm<Aes128, U16, U7>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::AES_CCM_64_128_256 => {
                Self::decrypt_aead::<Ccm<Aes256, U16, U7>>(key, ciphertext_with_tag, aad, iv)
            }
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }
}
