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
use aead::{Aead, AeadCore, Key, KeyInit, Nonce, Payload};
use rand::CryptoRng;
use rand::RngCore;

use crate::error::CoseCipherError;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};

use super::RustCryptoContext;
use alloc::vec::Vec;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Perform an AEAD encryption operation on `plaintext` and the additional authenticated
    /// data `aad` using the given `iv` and `key`.
    pub(super) fn encrypt_aead<AEAD: Aead + AeadCore + KeyInit>(
        key: &CoseSymmetricKey<'_, <RustCryptoContext<RNG> as CryptoBackend>::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        let aes_key = Key::<AEAD>::from_slice(key.k);
        let cipher = AEAD::new(aes_key);
        let nonce = Nonce::<AEAD>::from_slice(iv);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(CoseCipherError::from)
    }

    /// Perform an AEAD decryption operation on `ciphertext` and the additional authenticated
    /// data `aad` using the given `iv` and `key`.
    pub(super) fn decrypt_aead<AEAD: Aead + AeadCore + KeyInit>(
        key: &CoseSymmetricKey<'_, <RustCryptoContext<RNG> as CryptoBackend>::Error>,
        ciphertext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        let aes_key = Key::<AEAD>::from_slice(key.k);
        let cipher = AEAD::new(aes_key);
        let nonce = Nonce::<AEAD>::from_slice(iv);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(CoseCipherError::from)
    }
}
