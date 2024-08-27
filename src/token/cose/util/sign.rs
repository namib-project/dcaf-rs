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
use crate::token::cose::{CoseEc2Key, CoseParsedKey};
use core::fmt::Display;
use coset::{iana, Algorithm};

/// Attempts to parse the given `parsed_key` as an ECDSA key.
///
/// Performs the checks required for ECDSA keys according to
/// [RFC 9053, Section 2.1](https://datatracker.ietf.org/doc/html/rfc9053#section-2.1) and/or
/// [RFC 8812, Section 3.2](https://datatracker.ietf.org/doc/html/rfc8812#section-3.2).
pub(crate) fn ensure_valid_ecdsa_key<BE: Display>(
    algorithm: iana::Algorithm,
    parsed_key: CoseParsedKey<BE>,
    key_should_be_private: bool,
) -> Result<CoseEc2Key<BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 2.1 or RFC 8812, Section 3.2.

    // Key type must be EC2
    let ec2_key = if let CoseParsedKey::Ec2(ec2_key) = parsed_key {
        ec2_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            Algorithm::Assigned(algorithm),
        ));
    };

    // If algorithm in key is set, it must match our algorithm
    if let Some(key_alg) = &ec2_key.as_ref().alg {
        if key_alg != &Algorithm::Assigned(algorithm) {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                key_alg.clone(),
                Algorithm::Assigned(algorithm),
            ));
        }
    }

    // Key must contain private key information to perform signature, and either D or X and Y to
    // verify a signature.
    if key_should_be_private && ec2_key.d.is_none() {
        return Err(CoseCipherError::MissingKeyParam(vec![
            iana::Ec2KeyParameter::D.into(),
        ]));
    } else if !key_should_be_private && ec2_key.d.is_none() {
        if ec2_key.x.is_none() {
            return Err(CoseCipherError::MissingKeyParam(vec![
                iana::Ec2KeyParameter::X.into(),
                iana::Ec2KeyParameter::D.into(),
            ]));
        }
        if ec2_key.y.is_none() {
            return Err(CoseCipherError::MissingKeyParam(vec![
                iana::Ec2KeyParameter::Y.into(),
                iana::Ec2KeyParameter::D.into(),
            ]));
        }
    }

    Ok(ec2_key)
}
