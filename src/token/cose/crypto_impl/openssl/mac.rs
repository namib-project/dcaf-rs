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

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::openssl::{CoseOpensslCipherError, OpensslContext};
use crate::token::cose::{CoseSymmetricKey, MacCryptoBackend};
use alloc::vec::Vec;
use coset::iana;
use openssl::pkey::PKey;
use openssl::sign::Signer;

/// Computes an HMAC for `input` using the given `algorithm` and `key`.
fn compute_hmac(
    algorithm: iana::Algorithm,
    key: &CoseSymmetricKey<'_, CoseOpensslCipherError>,
    input: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let hash = super::get_algorithm_hash_function(algorithm)?;
    let hmac_key = PKey::hmac(key.k)?;
    let mut signer = Signer::new(hash, &hmac_key)?;
    signer
        .sign_oneshot_to_vec(input)
        .map_err(CoseCipherError::from)
}

impl MacCryptoBackend for OpensslContext {
    fn compute_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        data: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        compute_hmac(algorithm, &key, data)
    }

    fn verify_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let hmac = compute_hmac(algorithm, &key, data)?;
        // Use openssl::memcmp::eq to prevent timing attacks.
        if openssl::memcmp::eq(hmac.as_slice(), tag) {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }
}
