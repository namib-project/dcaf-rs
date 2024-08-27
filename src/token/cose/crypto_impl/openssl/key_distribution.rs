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
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::{CoseSymmetricKey, HeaderParam, KeyDistributionCryptoBackend};
use alloc::vec::Vec;
use ciborium::Value;
use coset::iana;
use openssl::aes::{unwrap_key, wrap_key, AesKey};

impl KeyDistributionCryptoBackend for OpensslContext {
    fn aes_key_wrap(
        &mut self,
        _algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let key = AesKey::new_encrypt(key.k)?;
        let iv: [u8; 8] = iv.try_into().map_err(|_e| {
            CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.to_vec()),
            )
        })?;
        let mut output = vec![0u8; plaintext.len() + 8];
        let output_len = wrap_key(&key, Some(iv), output.as_mut_slice(), plaintext)?;
        output.truncate(output_len);
        Ok(output)
    }

    fn aes_key_unwrap(
        &mut self,
        _algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let key = AesKey::new_decrypt(key.k)?;
        let iv: [u8; 8] = iv.try_into().map_err(|_e| {
            CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.to_vec()),
            )
        })?;
        let mut output = vec![0u8; ciphertext.len() - 8];
        let output_len = unwrap_key(&key, Some(iv), output.as_mut_slice(), ciphertext)?;
        output.truncate(output_len);
        Ok(output)
    }
}
