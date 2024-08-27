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
use coset::{iana, Algorithm};
use digest::{FixedOutput, Mac, MacMarker, Update};
use hmac::Hmac;
use rand::{CryptoRng, RngCore};
use sha2::{Sha256, Sha384, Sha512};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};
use alloc::vec::Vec;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Compute the HMAC of `payload` using the given `key` with the HMAC function
    /// `MAC`.
    fn compute_hmac_using_mac<MAC: hmac::digest::KeyInit + Update + FixedOutput + MacMarker>(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Vec<u8> {
        let key_size = key.k.len();
        let mut hmac_key = hmac::digest::Key::<MAC>::default();
        hmac_key.as_mut_slice()[..key_size].copy_from_slice(key.k);
        let mut hmac = MAC::new(&hmac_key);
        hmac.update(payload);
        hmac.finalize().into_bytes().to_vec()
    }

    /// Verify the HMAC of `payload` using the given `key` with the HMAC function `MAC`.
    fn verify_hmac_using_mac<MAC: hmac::digest::KeyInit + Update + FixedOutput + MacMarker>(
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
        tag: &[u8],
    ) -> Result<(), CoseCipherError<<Self as CryptoBackend>::Error>> {
        let key_size = key.k.len();
        let mut hmac_key = hmac::digest::Key::<MAC>::default();
        hmac_key.as_mut_slice()[..key_size].copy_from_slice(key.k);
        let mut hmac = MAC::new(&hmac_key);
        hmac.update(payload);
        hmac.verify_slice(tag).map_err(CoseCipherError::from)
    }

    /// Compute the HMAC of `payload` using the given `key` with the HMAC function
    /// specified in the `algorithm`.
    pub(super) fn compute_hmac(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::HMAC_256_256 => Ok(
                Self::compute_hmac_using_mac::<Hmac<sha2::Sha256>>(key, payload),
            ),
            iana::Algorithm::HMAC_384_384 => Ok(
                Self::compute_hmac_using_mac::<Hmac<sha2::Sha384>>(key, payload),
            ),
            iana::Algorithm::HMAC_512_512 => Ok(
                Self::compute_hmac_using_mac::<Hmac<sha2::Sha512>>(key, payload),
            ),
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }

    /// Verify the HMAC `tag` of `payload` using the given `key` with the HMAC
    /// function specified in the `algorithm`.
    pub(super) fn verify_hmac(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        tag: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::HMAC_256_256 => {
                Self::verify_hmac_using_mac::<Hmac<Sha256>>(key, payload, tag)
            }
            iana::Algorithm::HMAC_384_384 => {
                Self::verify_hmac_using_mac::<Hmac<Sha384>>(key, payload, tag)
            }
            iana::Algorithm::HMAC_512_512 => {
                Self::verify_hmac_using_mac::<Hmac<Sha512>>(key, payload, tag)
            }
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }
}
