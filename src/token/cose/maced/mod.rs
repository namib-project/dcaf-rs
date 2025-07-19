/*
 * Copyright (c) 2024-2025 The NAMIB Project Developers.
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

use coset::{iana, Algorithm, Header, KeyOperation};

pub use mac::{CoseMacBuilderExt, CoseMacExt};
pub use mac0::{CoseMac0BuilderExt, CoseMac0Ext};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey, KeyProvider};
use crate::token::cose::util::{ensure_valid_hmac_key, try_cose_crypto_operation};
use crate::token::cose::CryptoBackend;

mod mac;
mod mac0;

/// Trait for cryptographic backends that can perform Message Authentication Code (MAC) computation
/// and verification operations for algorithms used in COSE structures.
pub trait MacCryptoBackend: CryptoBackend {
    /// Computes an HMAC for the given `payload` using the given `algorithm` and `key`.
    ///
    /// The MAC should be computed with the padding specified in RFC 2104 (as described in RFC 9053,
    /// Section 3.1).
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The HMAC variant to use (determines the hash function).
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of HMAC are ever added).
    ///           If the algorithm is not an HMAC algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
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
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
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
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new HMAC variants are ever
    /// defined).
    #[allow(unused_variables)]
    fn compute_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }

    /// Verifies the HMAC provided as `tag` for the given `payload` using the given `algorithm` and
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
    /// * `algorithm` - The HMAC variant to use (determines the hash function).
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of HMAC are ever added).
    ///           If the algorithm is not an HMAC algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `payload` - Data for which the MAC should be calculated.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is `Ok(())` if the computed MAC matches the one
    /// provided, or a [`CoseCipherError::VerificationFailure`] if it doesn't even though MAC
    /// computation was successful.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
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
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new HMAC variants are ever
    /// defined).
    #[allow(unused_variables)]
    fn verify_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }
}

/// Attempts to perform a COSE HMAC computation operation for a [`CoseMac`](coset::CoseMac) or
/// [`CoseMac0`](coset::CoseMac0) structure with the given `protected` and `unprotected`
/// headers and `payload` using the given `backend` and `key_provider`.
///
/// Also performs checks that ensure that the given parameters (esp. headers and keys) are valid and
/// are coherent with each other.
///
/// If the `key_provider` returns multiple keys, all will be tried until one can be successfully
/// used for the given operation.
fn try_compute<B: MacCryptoBackend, CKP: KeyProvider>(
    backend: &mut B,
    key_provider: &CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    payload: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    try_cose_crypto_operation(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacCreate)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;

            match alg {
                iana::Algorithm::HMAC_256_64
                | iana::Algorithm::HMAC_256_256
                | iana::Algorithm::HMAC_384_384
                | iana::Algorithm::HMAC_512_512 => {
                    let symm_key = ensure_valid_hmac_key(alg, parsed_key)?;
                    backend.compute_hmac(alg, symm_key, payload)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}

/// Attempts to perform a COSE HMAC verification operation for a [`CoseMac`](coset::CoseMac) or
/// [`CoseMac0`](coset::CoseMac0) structure with the given `protected` and `unprotected`
/// headers and `payload` using the given `backend` and `key_provider`.
///
/// Also performs checks that ensure that the given parameters (esp. headers and keys) are valid and
/// are coherent with each other.
///
/// If the `key_provider` returns multiple keys, all will be tried until one can be successfully
/// used for the given operation.
pub(crate) fn try_verify<B: MacCryptoBackend, CKP: KeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &CKP,
    protected: &Header,
    unprotected: &Header,
    tag: &[u8],
    payload: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    try_cose_crypto_operation(
        key_provider,
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacVerify)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;

            match alg {
                iana::Algorithm::HMAC_256_64
                | iana::Algorithm::HMAC_256_256
                | iana::Algorithm::HMAC_384_384
                | iana::Algorithm::HMAC_512_512 => {
                    let symm_key = ensure_valid_hmac_key(alg, parsed_key)?;
                    (*backend.borrow_mut()).verify_hmac(alg, symm_key, tag, payload)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
