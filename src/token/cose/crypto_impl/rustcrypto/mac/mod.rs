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

use crate::token::cose::crypto_impl::rustcrypto::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::CoseSymmetricKey;
use crate::token::cose::MacCryptoBackend;
use alloc::vec::Vec;
use coset::iana;
use rand::{CryptoRng, RngCore};

#[cfg(feature = "rustcrypto-hmac")]
mod hmac;

impl<RNG: RngCore + CryptoRng> MacCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-hmac")]
    fn compute_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::compute_hmac(algorithm, &key, payload)
    }

    #[cfg(feature = "rustcrypto-hmac")]
    fn verify_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::verify_hmac(algorithm, &key, tag, payload)
    }
}
