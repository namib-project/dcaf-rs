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
use alloc::vec::Vec;

use coset::{iana, Algorithm, Header, KeyOperation};

pub use sign::{CoseSignBuilderExt, CoseSignExt};
pub use sign1::{CoseSign1BuilderExt, CoseSign1Ext};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseEc2Key, CoseParsedKey, KeyProvider};
use crate::token::cose::util::{ensure_valid_ecdsa_key, try_cose_crypto_operation};
use crate::token::cose::CryptoBackend;

mod sign;
mod sign1;

/// Provides basic operations for signing and verifying COSE structures.
pub trait SignCryptoBackend: CryptoBackend {
    /// Cryptographically signs the `payload` value with the `key` using ECDSA and returns the
    /// signature.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The variant of ECDSA to use (determines the hash function).
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of ECDSA are ever added).
    ///           If the algorithm is not an ECDSA algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Elliptic curve key that should be used.
    ///           Implementations may assume that if the [`CoseEc2Key::crv`] field is an IANA-assigned
    ///           value, it will always be a curve feasible for ECDSA.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of ECDSA are ever added). If the algorithm is not an ECDSA
    ///           algorithm, the implementation may return [`CoseCipherError::UnsupportedAlgorithm`]
    ///           or panic.
    ///           Note that curve and hash bit sizes do not necessarily match.
    ///           Implementations may assume the struct field `d` (the private key) to always be set
    ///           and panic if this is not the case.
    ///           The fields `x` and (`y` or `sign`) (the public key) may be used by implementations
    ///           if they are set. If they are not, implementations may either derive the public key
    ///           from `d` or return a [`CoseCipherError::UnsupportedKeyDerivation`] if this
    ///           derivation is unsupported.
    ///           If calculation of the public key from the `x` coordinate and `sign` is not
    ///           supported, a [`CoseCipherError::UnsupportedKeyDerivation`] may be returned as well.
    /// * `payload` - Data to be signed.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is a signature conforming to RFC 9053, Section 2.1,
    /// i.e. the return value should consist of the `r` and `s` values of the signature, which are
    /// each padded (at the beginning) with zeros to the key size (rounded up to the next full
    /// byte).
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an ECDSA algorithm, the
    /// provided key is not part of a curve suitable for ECDSA, the `d` field of the key is not set
    /// or if an unrecoverable backend error occurs that necessitates a panic (at their own
    /// discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new ECDSA variants are defined).
    #[allow(unused_variables)]
    fn sign_ecdsa(
        &mut self,
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }

    /// Verifies the `signature` using the given `key` and `payload` (plaintext) using ECDSA.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The variant of ECDSA to use (determines the hash function).
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of ECDSA are ever added).
    ///           If the algorithm is not an ECDSA algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Elliptic curve key that should be used.
    ///           Implementations may assume that if the [`CoseEc2Key::crv`] field is an IANA-assigned
    ///           value, it will always be a curve feasible for ECDSA.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of ECDSA are ever added). If the algorithm is not an ECDSA
    ///           algorithm, the implementation may return [`CoseCipherError::UnsupportedAlgorithm`]
    ///           or panic.
    ///           Note that curve and hash bit sizes do not necessarily match.
    ///           Implementations may assume that either `d` or (`x` and (`y` xor `sign`)) are set.
    ///           The fields x and (y or sign) (the public key) may be used by implementations if
    ///           they are set.
    ///           If they are not, but the private key `d` is present, implementations may either
    ///           derive the public key from `d` (if present) or return a
    ///           [`CoseCipherError::UnsupportedKeyDerivation`] if this derivation is unsupported.
    ///           If calculation of the public key from the `x` coordinate and `sign` is not
    ///           supported, a [`CoseCipherError::UnsupportedKeyDerivation`] may be returned as well.
    /// * `sig` - the signature to verify. This signature should be a valid signature
    ///           conforming to RFC 9053, Section 2.1 (i.e. the `r` and `s` values of the signature
    ///           are each padded with zeros at the beginning to the key size rounded up to the next
    ///           full byte), but as this is user-provided input, the implementation must not rely
    ///           on this being the case.
    /// * `payload` - Data that was presumably signed using the signature.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is Ok(()) if the provided signature is a valid ECDSA
    /// signature for the provided key.
    ///
    /// # Errors
    ///
    /// If the signature is not malformed, but not valid for the given `algorithm`, `key`,
    /// and `payload`, a [`CoseCipherError::VerificationFailure`] must be returned.
    ///
    /// In case of other errors, the implementation may return any valid [`CoseCipherError`]
    /// (including [`CoseCipherError::VerificationFailure`]).
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an ECDSA algorithm, the
    /// provided key is not part of a curve suitable for ECDSA, neither the `x` and (`y` or `sign`)
    /// fields nor the `d` field of the provided key are set or if an unrecoverable backend error
    /// occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new ECDSA variants are defined).
    #[allow(unused_variables)]
    fn verify_ecdsa(
        &mut self,
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        sig: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }
}

/// Attempts to perform a COSE signing operation for a [`CoseSign`](coset::CoseSign) or
/// [`CoseSign1`](coset::CoseSign1) structure with the given `protected` and `unprotected`
/// headers and `payload` using the given `backend` and `key_provider`.
///
/// Also performs checks that ensure that the given parameters (esp. headers and keys) are valid and
/// are coherent with each other.
///
/// If the `key_provider` returns multiple keys, all will be tried until one can be successfully
/// used for the given operation.
fn try_sign<B: SignCryptoBackend, CKP: KeyProvider>(
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
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Sign)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;
            match alg {
                iana::Algorithm::ES256
                | iana::Algorithm::ES384
                | iana::Algorithm::ES512
                | iana::Algorithm::ES256K => {
                    // Check if this is a valid ECDSA key.
                    let ec2_key = ensure_valid_ecdsa_key::<B::Error>(alg, parsed_key, true)?;

                    // Perform signing operation using backend.
                    backend.sign_ecdsa(alg, &ec2_key, payload)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}

/// Attempts to perform a COSE signature verification operation for a [`CoseSign`](coset::CoseSign)
/// or [`CoseSign1`](coset::CoseSign1) structure with the given `protected` and `unprotected`
/// headers and `payload` using the given `backend` and `key_provider`.
///
/// Also performs checks that ensure that the given parameters (esp. headers and keys) are valid and
/// are coherent with each other.
///
/// If the `key_provider` returns multiple keys, all will be tried until one can be successfully
/// used for the given operation.
fn try_verify<B: SignCryptoBackend, CKP: KeyProvider>(
    backend: &mut B,
    key_provider: &CKP,
    protected: &Header,
    unprotected: &Header,

    signature: &[u8],
    toverify: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    try_cose_crypto_operation(
        key_provider,
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Verify)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;
            match alg {
                iana::Algorithm::ES256
                | iana::Algorithm::ES384
                | iana::Algorithm::ES512
                | iana::Algorithm::ES256K => {
                    // Check if this is a valid ECDSA key.
                    let ec2_key = ensure_valid_ecdsa_key::<B::Error>(alg, parsed_key, false)?;

                    backend.verify_ecdsa(alg, &ec2_key, signature, toverify)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
