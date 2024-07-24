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
use alloc::collections::BTreeSet;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Display;

use ciborium::Value;
use coset::{iana, Algorithm, Header, KeyOperation};

pub use mac::{CoseMacBuilderExt, CoseMacExt};
pub use mac0::{CoseMac0BuilderExt, CoseMac0Ext};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey, KeyParam, KeyProvider};
use crate::token::cose::{header_util, CryptoBackend};

mod mac;
mod mac0;

/// Trait for cryptographic backends that can perform Message Authentication Code (MAC) computation
/// and verification operations for algorithms used in COSE structures.
pub trait MacCryptoBackend: CryptoBackend {
    /// Computes an HMAC for the given `payload` using the given `alg`orithm and `key`.
    ///
    /// The MAC should be computed with the padding specified in RFC 2104 (as described in RFC 9053,
    /// Section 3.1).
    ///
    /// # Arguments
    ///
    /// * `alg` - The HMAC variant to use (determines the hash function).
    ///           If unsupported by the backend, a [CoseCipherError::UnsupportedAlgorithm] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [CoseCipherError::UnsupportedAlgorithm] (in case
    ///           additional variants of HMAC are ever added).
    ///           If the algorithm is not an HMAC algorithm, the implementation may return
    ///           [CoseCipherError::UnsupportedAlgorithm] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `payload` - Data for which the MAC should be calculated.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is a MAC conforming to RFC 9053, Section 3.1, i.e. the
    /// return value should be the computed MAC bytes as a `Vec`.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [CoseCipherError].
    /// For backend-specific errors, [CoseCipherError::Other] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an HMAC algorithm, the
    /// provided key is not of the right length for the provided algorithm or if an unrecoverable
    /// backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [CoseCipherError::UnsupportedAlgorithm] instead (in case new HMAC variants are ever
    /// defined).
    fn compute_hmac(
        &mut self,
        alg: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    /// Verifies the HMAC provided as `tag` for the given `payload` using the given `alg`orithm and
    /// `key`.
    ///
    /// The MAC should be computed with the padding specified in RFC 2104 (as described in RFC 9053,
    /// Section 3.1).
    ///
    /// The HMAC comparison must be performed using a comparison function that is resistant to
    /// timing attacks.
    ///
    /// # Arguments
    ///
    /// * `alg` - The HMAC variant to use (determines the hash function).
    ///           If unsupported by the backend, a [CoseCipherError::UnsupportedAlgorithm] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [CoseCipherError::UnsupportedAlgorithm] (in case
    ///           additional variants of HMAC are ever added).
    ///           If the algorithm is not an HMAC algorithm, the implementation may return
    ///           [CoseCipherError::UnsupportedAlgorithm] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `payload` - Data for which the MAC should be calculated.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is `Ok(())` if the computed MAC matches the one
    /// provided, or a [CoseCipherError::VerificationFailure] if it doesn't even though MAC
    /// computation was successful.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [CoseCipherError].
    /// For backend-specific errors, [CoseCipherError::Other] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an HMAC algorithm, the
    /// provided key is not of the right length for the provided algorithm or if an unrecoverable
    /// backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [CoseCipherError::UnsupportedAlgorithm] instead (in case new HMAC variants are ever
    /// defined).
    fn verify_hmac(
        &mut self,
        alg: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

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

fn try_compute<B: MacCryptoBackend, CKP: KeyProvider>(
    backend: &mut B,
    key_provider: &CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    input: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    header_util::try_cose_crypto_operation(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacCreate)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;

            match alg {
                iana::Algorithm::HMAC_256_256 => {
                    let symm_key = ensure_valid_hmac_key(alg, parsed_key)?;
                    backend.compute_hmac(alg, symm_key, input)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}

pub(crate) fn try_verify<B: MacCryptoBackend, CKP: KeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &CKP,
    protected: &Header,
    unprotected: &Header,
    tag: &[u8],
    data: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    header_util::try_cose_crypto_operation(
        key_provider,
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacVerify)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;

            match alg {
                iana::Algorithm::HMAC_256_256 => {
                    let symm_key = ensure_valid_hmac_key(alg, parsed_key)?;
                    (*backend.borrow_mut()).verify_hmac(alg, symm_key, tag, data)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
