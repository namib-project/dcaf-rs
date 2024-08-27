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
use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser};
use aes::{Aes128, Aes192, Aes256};
use aes_kw::Kek;
use coset::{iana, Algorithm};
use crypto_common::{Key, KeyInit};
use rand::{CryptoRng, RngCore};
use typenum::consts::U16;

use crate::error::CoseCipherError;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};

use super::RustCryptoContext;
use alloc::vec::Vec;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Perform an AES key wrap operation on the key contained in `plaintext` which is wrapped
    /// using the key encryption key `key` using the AES variant provided as `AES`.
    fn aes_key_wrap_with_alg<
        AES: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    >(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        let key = Key::<AES>::from_slice(key.k);
        let key_wrap = Kek::<AES>::new(key);
        key_wrap.wrap_vec(plaintext).map_err(CoseCipherError::from)
    }

    /// Perform an AES key unwrap operation on the key contained in `ciphertext` which is wrapped
    /// using the key encryption key `key` using the AES variant provided as `AES`.
    fn aes_key_unwrap_with_alg<
        AES: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    >(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        let key = Key::<AES>::from_slice(key.k);
        let key_wrap = Kek::<AES>::new(key);
        key_wrap
            .unwrap_vec(ciphertext)
            .map_err(CoseCipherError::from)
    }

    /// Perform an AES key wrap operation on the key contained in `plaintext` which is wrapped
    /// using the key encryption key `key` using the AES variant specified for the given
    /// `algorithm`.
    pub(super) fn aes_key_wrap(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        if iv != aes_kw::IV {
            // IV for AES key wrap is not set by user, but by dcaf-rs.
            // This indicates some weird/unknown variation of an AES-KW algorithm, or something went
            // really wrong.
            return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                algorithm,
            )));
        }
        match algorithm {
            iana::Algorithm::A128KW => Self::aes_key_wrap_with_alg::<Aes128>(key, plaintext),
            iana::Algorithm::A192KW => Self::aes_key_wrap_with_alg::<Aes192>(key, plaintext),
            iana::Algorithm::A256KW => Self::aes_key_wrap_with_alg::<Aes256>(key, plaintext),
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }

    /// Perform an AES key unwrap operation on the key contained in `ciphertext` which is wrapped
    /// using the key encryption key `key` using the AES variant specified for the given
    /// `algorithm`.
    pub(super) fn aes_key_unwrap(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        if iv != aes_kw::IV {
            // IV for AES key wrap is not set by user, but by dcaf-rs.
            // This indicates some weird/unknown variation of an AES-KW algorithm, or something went
            // really wrong.
            return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                algorithm,
            )));
        }
        match algorithm {
            iana::Algorithm::A128KW => Self::aes_key_unwrap_with_alg::<Aes128>(key, ciphertext),
            iana::Algorithm::A192KW => Self::aes_key_unwrap_with_alg::<Aes192>(key, ciphertext),
            iana::Algorithm::A256KW => Self::aes_key_unwrap_with_alg::<Aes256>(key, ciphertext),
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }
}
