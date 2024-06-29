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
mod sign;
mod sign1;

use crate::error::CoseCipherError;
use crate::token::cose::key::{
    CoseAadProvider, CoseEc2Key, CoseKeyProvider, CoseParsedKey, KeyParam,
};
use core::borrow::BorrowMut;
use core::fmt::{Debug, Display};
use coset::iana::{Ec2KeyParameter, EnumI64};
use coset::{iana, Algorithm, CoseKey, Header, KeyOperation, RegisteredLabel};

use crate::token::cose::header_util::{determine_algorithm, determine_key_candidates};
pub use sign::{CoseSignBuilderExt, CoseSignExt};
pub use sign1::{CoseSign1BuilderExt, CoseSign1Ext};

/// Provides basic operations for signing and verifying COSE structures.
///
/// This will be used by [`sign_access_token`] and [`verify_access_token`] (as well as the
/// equivalents for multiple recipients: [`sign_access_token_multiple`] and
/// [`verify_access_token_multiple`]) to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// The [`set_headers` method](CoseCipher::set_headers) can be used to set parameters
/// this cipher requires to be set.
pub trait CoseSignCipher {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;

    /// Cryptographically signs the `target` value with the `key` using ECDSA and returns the
    /// signature.
    ///
    /// # Arguments
    ///
    /// * `alg` - The variant of ECDSA to use (determines the hash function).
    ///
    ///           If unsupported by the backend, a [CoseCipherError::UnsupportedAlgorithm] error
    ///           should be returned.
    ///
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [CoseCipherError::UnsupportedAlgorithm] (in case
    ///           additional variants of ECDSA are ever added).
    ///
    ///           If the algorithm is not an ECDSA algorithm, the implementation may return
    ///           [CoseCipherError::UnsupportedAlgorithm] or panic.
    /// * `key` - Elliptic curve key that should be used.
    ///
    ///           Implementations may assume that if the [CoseEc2Key::crv] field is an IANA-assigned
    ///           value, it will always be a curve feasible for ECDSA.
    ///
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [CoseCipherError::UnsupportedAlgorithm] (in case
    ///           additional variants of ECDSA are ever added). If the algorithm is not an ECDSA
    ///           algorithm, the implementation may return [CoseCipherError::UnsupportedAlgorithm]
    ///           or panic.
    ///
    ///           Note that curve and hash bit sizes do not necessarily match.
    ///
    ///           Implementations may assume the struct field `d` (the private key) to always be set
    ///           and panic if this is not the case.
    ///
    ///           The fields x and y (the public key) may be used by implementations if they are
    ///           set. If they are not, implementations may either derive the public key from `d` or
    ///           return a [CoseCipherError::UnsupportedKeyDerivation] if this derivation is
    ///           unsupported.
    /// * `target` - Data to be signed.
    ///
    /// # Return Value
    ///
    /// It is expected that the return value is a signature conforming to RFC 9053, Section 2.1,
    /// i.e. the return value should consist of the `r` and `s` values of the signature, which are
    /// each padded (at the beginning) with zeros to the key size (rounded up to the next full
    /// byte).
    ///
    /// In case of errors, the implementation may return any valid [CoseCipherError].
    /// For backend-specific errors, [CoseCipherError::Other] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an ECDSA algorithm, the
    /// provided key is not part of a curve suitable for ECDSA or if an unrecoverable backend error
    /// occurs that necessitates a panic (at their own discretion).
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [CoseCipherError::UnsupportedAlgorithm] instead (in case new ECDSA variants are defined).
    fn sign_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    /// Verifies the `signature` using the given `key` and `target` (plaintext) using ECDSA.
    ///
    /// # Arguments
    ///
    /// * `alg` - The variant of ECDSA to use (determines the hash function).
    ///
    ///           If unsupported by the backend, a [CoseCipherError::UnsupportedAlgorithm] error
    ///           should be returned.
    ///
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [CoseCipherError::UnsupportedAlgorithm] (in case
    ///           additional variants of ECDSA are ever added).
    ///
    ///           If the algorithm is not an ECDSA algorithm, the implementation may return
    ///           [CoseCipherError::UnsupportedAlgorithm] or panic.
    /// * `key` - Elliptic curve key that should be used.
    ///
    ///           Implementations may assume that if the [CoseEc2Key::crv] field is an IANA-assigned
    ///           value, it will always be a curve feasible for ECDSA.
    ///
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [CoseCipherError::UnsupportedAlgorithm] (in case
    ///           additional variants of ECDSA are ever added). If the algorithm is not an ECDSA
    ///           algorithm, the implementation may return [CoseCipherError::UnsupportedAlgorithm]
    ///           or panic.
    ///
    ///           Note that curve and hash bit sizes do not necessarily match.
    ///
    ///           Implementations may assume the struct field `d` (the private key) to always be set
    ///           and panic if this is not the case.
    ///
    ///           The fields x and y (the public key) may be used by implementations if they are
    ///           set. If they are not, implementations may either derive the public key from `d` or
    ///           return a [CoseCipherError::UnsupportedKeyDerivation] if this derivation is
    ///           unsupported.
    /// * `signature` - the signature to verify.
    /// * `target` - Data that was presumably signed using the signature.
    ///
    /// # Return Value
    ///
    /// It is expected that the return value is a signature conforming to RFC 9053, Section 2.1,
    /// i.e. the return value should consist of the `r` and `s` values of the signature, which are
    /// each padded (at the beginning) with zeros to the key size (rounded up to the next full
    /// byte).
    ///
    /// In case of errors, the implementation may return any valid [CoseCipherError].
    /// For backend-specific errors, [CoseCipherError::Other] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an ECDSA algorithm, the
    /// provided key is not part of a curve suitable for ECDSA or if an unrecoverable backend error
    /// occurs that necessitates a panic (at their own discretion).
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [CoseCipherError::UnsupportedAlgorithm] instead (in case new ECDSA variants are defined).
    fn verify_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        signature: &[u8],
        target: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

fn is_valid_ecdsa_key<'a, BE: Display>(
    algorithm: &Algorithm,
    parsed_key: CoseParsedKey<'a, BE>,
    key_should_be_private: bool,
) -> Result<CoseEc2Key<'a, BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 2.1 or RFC 8812, Section 3.2.

    // Key type must be EC2
    let ec2_key = if let CoseParsedKey::Ec2(ec2_key) = parsed_key {
        ec2_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            algorithm.clone(),
        ));
    };

    // If algorithm in key is set, it must match our algorithm
    if let Some(alg) = &ec2_key.as_ref().alg {
        if alg != algorithm {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                alg.clone(),
                algorithm.clone(),
            ));
        }
    }

    // Key must contain private key information to perform signature.
    if key_should_be_private && ec2_key.d.is_none() {
        return Err(CoseCipherError::MissingKeyParam(KeyParam::Ec2(
            Ec2KeyParameter::D,
        )));
    } else if ec2_key.x.is_none() || ec2_key.y.is_none() {
        return Err(CoseCipherError::MissingKeyParam(KeyParam::Ec2(
            Ec2KeyParameter::X,
        )));
    }

    Ok(ec2_key)
}

fn try_sign<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    tosign: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    let parsed_key = determine_key_candidates(
        key_provider,
        protected,
        unprotected,
        &KeyOperation::Assigned(iana::KeyOperation::Sign),
        false,
    )?
    .into_iter()
    .next()
    .ok_or(CoseCipherError::NoKeyFound)?;
    let algorithm = determine_algorithm(&parsed_key, protected, unprotected)?;

    let sign_fn = match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::ES256
            | iana::Algorithm::ES384
            | iana::Algorithm::ES512
            | iana::Algorithm::ES256K,
        ) => {
            // Check if this is a valid ECDSA key.
            let ec2_key = is_valid_ecdsa_key::<B::Error>(&algorithm, parsed_key, true)?;

            // Perform signing operation using backend.
            move |tosign| return backend.sign_ecdsa(algorithm, &ec2_key, tosign)
        }
        v @ (Algorithm::Assigned(_)) => {
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    };

    sign_fn(tosign)
}

fn try_verify_with_key<B: CoseSignCipher>(
    backend: &mut B,
    key: CoseParsedKey<B::Error>,
    protected: &Header,
    unprotected: &Header,
    signature: &[u8],
    toverify: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    let algorithm = determine_algorithm(&key, Some(protected), Some(unprotected))?;

    match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::ES256
            | iana::Algorithm::ES384
            | iana::Algorithm::ES512
            | iana::Algorithm::ES256K,
        ) => {
            // Check if this is a valid ECDSA key.
            let ec2_key = is_valid_ecdsa_key::<B::Error>(&algorithm, key, false)?;

            backend.verify_ecdsa(algorithm, &ec2_key, signature, toverify)
        }
        v @ (Algorithm::Assigned(_)) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    }
}

fn try_verify<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: &'b Header,
    unprotected: &'b Header,
    try_all_keys: bool,
    signature: &[u8],
    toverify: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    for key in determine_key_candidates(
        key_provider,
        Some(protected),
        Some(unprotected),
        &KeyOperation::Assigned(iana::KeyOperation::Verify),
        try_all_keys,
    )? {
        match try_verify_with_key(backend, key, protected, unprotected, signature, toverify) {
            Ok(()) => return Ok(()),
            Err(e) => {
                dbg!(e);
            }
        }
    }

    Err(CoseCipherError::NoKeyFound)
}
