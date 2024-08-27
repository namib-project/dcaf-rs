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
use crate::error::CoseCipherError;
use crate::token::cose::{CoseParsedKey, CoseSymmetricKey, KeyParam};
use ciborium::Value;
use core::fmt::Display;
use coset::{iana, Algorithm};

/// Attempts to parse the given `parsed_key` as an HMAC key.
///
/// Performs the checks required for symmetric keys suitable for HMAC according to
/// [RFC 9053, Section 3.1](https://datatracker.ietf.org/doc/html/rfc9053#section-3.1).
pub(crate) fn ensure_valid_hmac_key<BE: Display>(
    algorithm: iana::Algorithm,
    parsed_key: CoseParsedKey<BE>,
) -> Result<CoseSymmetricKey<BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 3.1.

    // Key type must be symmetric.
    let symm_key = if let CoseParsedKey::Symmetric(symm_key) = parsed_key {
        symm_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            Algorithm::Assigned(algorithm),
        ));
    };

    // Algorithm in key must match algorithm to use.
    if let Some(key_alg) = &symm_key.as_ref().alg {
        if key_alg != &Algorithm::Assigned(algorithm) {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                key_alg.clone(),
                Algorithm::Assigned(algorithm),
            ));
        }
    }

    // For algorithms that we know, check the key length (would lead to a cipher error later on).
    let key_len = match algorithm {
        iana::Algorithm::HMAC_256_256 | iana::Algorithm::HMAC_256_64 => Some(32),
        iana::Algorithm::HMAC_384_384 => Some(48),
        iana::Algorithm::HMAC_512_512 => Some(64),
        _ => None,
    };

    if let Some(key_len) = key_len {
        if symm_key.k.len() != key_len {
            return Err(CoseCipherError::InvalidKeyParam(
                KeyParam::Symmetric(iana::SymmetricKeyParameter::K),
                Value::Bytes(symm_key.k.to_vec()),
            ));
        }
    }

    Ok(symm_key)
}
