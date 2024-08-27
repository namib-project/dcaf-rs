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
use crate::token::cose::CoseEc2Key;
use coset::iana;
use rand::{CryptoRng, RngCore};

use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::SignCryptoBackend;
use alloc::vec::Vec;

#[cfg(feature = "rustcrypto-ecdsa")]
mod ecdsa;

impl<RNG: RngCore + CryptoRng> SignCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-ecdsa")]
    fn sign_ecdsa(
        &mut self,
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::sign_ecdsa(algorithm, key, payload)
    }

    #[cfg(feature = "rustcrypto-ecdsa")]
    fn verify_ecdsa(
        &mut self,
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        sig: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::verify_ecdsa(algorithm, key, sig, payload)
    }
}
