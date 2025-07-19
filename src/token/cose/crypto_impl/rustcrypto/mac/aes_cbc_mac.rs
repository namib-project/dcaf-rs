/*
 * Copyright (c) 2025 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use coset::{iana, Algorithm};
use crypto_common::BlockSizeUser;
use digest::Mac;
use rand::{CryptoRng, RngCore};
use typenum::{IsLess, U256};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};
use aes::cipher::{BlockCipher, BlockEncryptMut};
use aes::{Aes128, Aes256};
use alloc::vec::Vec;
use cbc_mac::CbcMac;
use crypto_common::KeyInit;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Compute the CBC-MAC of `payload` using the given `key` with the HMAC function
    /// `MAC`.
    fn compute_cbc_mac_using_block_cipher<
        C: BlockCipher + BlockEncryptMut + Clone,
        const TAG_LEN: usize,
    >(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Vec<u8>
    where
        CbcMac<C>: KeyInit + Mac,
        <C as BlockSizeUser>::BlockSize: typenum::IsLess<U256>,
        <<C as BlockSizeUser>::BlockSize as IsLess<U256>>::Output: typenum::NonZero,
    {
        let mut cbc_mac = <CbcMac<C> as Mac>::new_from_slice(&key.k).unwrap();
        cbc_mac.update(payload);
        let mut result = cbc_mac.finalize().into_bytes().to_vec();
        result.truncate(TAG_LEN);
        result
    }

    /// Verify the CBC-MAC of `payload` using the given `key` with the HMAC function `MAC`.
    fn verify_cbc_mac_using_block_cipher<
        C: BlockCipher + BlockEncryptMut + Clone,
        const TAG_LEN: usize,
    >(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
        tag: &[u8],
    ) -> Result<(), CoseCipherError<<Self as CryptoBackend>::Error>>
    where
        CbcMac<C>: KeyInit + Mac,
        <C as BlockSizeUser>::BlockSize: typenum::IsLess<U256>,
        <<C as BlockSizeUser>::BlockSize as IsLess<U256>>::Output: typenum::NonZero,
    {
        let mut cbc_mac = <CbcMac<C> as Mac>::new_from_slice(&key.k).unwrap();
        cbc_mac.update(payload);

        // Validate length of tag as verify_truncated_left() does not know the expected length.
        if tag.len() != TAG_LEN {
            return Err(CoseCipherError::VerificationFailure);
        }

        cbc_mac
            .verify_truncated_left(tag)
            .map_err(CoseCipherError::from)
    }

    /// Compute the CBC-MAC of `payload` using the given `key` with the CBC-MAC function
    /// specified in the `algorithm`.
    pub(super) fn compute_cbc_mac(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::AES_MAC_128_64 => Ok(Self::compute_cbc_mac_using_block_cipher::<
                Aes128,
                8,
            >(key, payload)),
            iana::Algorithm::AES_MAC_128_128 => Ok(Self::compute_cbc_mac_using_block_cipher::<
                Aes128,
                16,
            >(key, payload)),
            iana::Algorithm::AES_MAC_256_64 => Ok(Self::compute_cbc_mac_using_block_cipher::<
                Aes256,
                8,
            >(key, payload)),
            iana::Algorithm::AES_MAC_256_128 => Ok(Self::compute_cbc_mac_using_block_cipher::<
                Aes256,
                16,
            >(key, payload)),
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }

    /// Verify the CBC-MAC `tag` of `payload` using the given `key` with the CBC-MAC
    /// function specified in the `algorithm`.
    pub(super) fn verify_cbc_mac(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        tag: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::AES_MAC_128_64 => {
                Self::verify_cbc_mac_using_block_cipher::<Aes128, 8>(key, payload, tag)
            }
            iana::Algorithm::AES_MAC_128_128 => {
                Self::verify_cbc_mac_using_block_cipher::<Aes128, 16>(key, payload, tag)
            }
            iana::Algorithm::AES_MAC_256_64 => {
                Self::verify_cbc_mac_using_block_cipher::<Aes256, 8>(key, payload, tag)
            }
            iana::Algorithm::AES_MAC_256_128 => {
                Self::verify_cbc_mac_using_block_cipher::<Aes256, 16>(key, payload, tag)
            }
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }
}
