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
use crate::error::CoseCipherError;
use crate::token::cose::util::determine_header_param;
use crate::token::cose::{CoseParsedKey, CoseSymmetricKey, CryptoBackend, HeaderParam, KeyParam};
use alloc::vec::Vec;
use ciborium::Value;
use core::fmt::Display;
use coset::{iana, Algorithm, Header};

/// Generates a random content encryption key for the given `algorithm` using the given `backend`.
pub(crate) fn generate_cek_for_alg<B: CryptoBackend>(
    backend: &mut B,
    algorithm: iana::Algorithm,
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    let key_len = symmetric_key_size(algorithm)?;
    let mut key = vec![0u8; key_len];
    backend.generate_rand(key.as_mut_slice())?;
    Ok(key)
}

/// Attempts to parse the given `parsed_key` as a symmetric key.
///
/// Performs the checks required for symmetric keys suitable for the algorithms specified in
/// [RFC 9053, Section 4](https://datatracker.ietf.org/doc/html/rfc9053#section-4) and
/// [RFC 9053, Section 3.2](https://datatracker.ietf.org/doc/html/rfc9053#section-3.2), *except for
/// the key_ops check, which must be performed by the caller based on the operation it intends to
/// perform with the key*.
pub(crate) fn ensure_valid_symmetric_key<BE: Display>(
    algorithm: iana::Algorithm,
    parsed_key: CoseParsedKey<BE>,
) -> Result<CoseSymmetricKey<BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Sections 3.2, 4.1 and 4.2.

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
    let key_len = symmetric_key_size(algorithm)?;
    if symm_key.k.len() != key_len {
        return Err(CoseCipherError::InvalidKeyParam(
            KeyParam::Symmetric(iana::SymmetricKeyParameter::K),
            Value::Bytes(symm_key.k.to_vec()),
        ));
    }

    Ok(symm_key)
}

/// Determines the key size that a symmetric key for the given `algorithm` should have.
fn symmetric_key_size<BE: Display>(
    algorithm: iana::Algorithm,
) -> Result<usize, CoseCipherError<BE>> {
    match algorithm {
        iana::Algorithm::A128GCM
        | iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_64_128_128
        | iana::Algorithm::AES_MAC_128_64
        | iana::Algorithm::AES_MAC_128_128
        | iana::Algorithm::A128KW => Ok(16),
        iana::Algorithm::A192GCM | iana::Algorithm::A192KW => Ok(24),
        iana::Algorithm::A256GCM
        | iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_64_64_256
        | iana::Algorithm::AES_CCM_16_128_256
        | iana::Algorithm::AES_CCM_64_128_256
        | iana::Algorithm::AES_MAC_256_64
        | iana::Algorithm::AES_MAC_256_128
        | iana::Algorithm::A256KW
        | iana::Algorithm::ChaCha20Poly1305
        | iana::Algorithm::HMAC_256_256
        | iana::Algorithm::HMAC_256_64 => Ok(32),
        iana::Algorithm::HMAC_384_384 => Ok(48),
        iana::Algorithm::HMAC_512_512 => Ok(64),
        _ => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        ))),
    }
}

/// Returns the IV length expected for the symmetric algorithm given as `alg`.
///
/// # Errors
///
/// Returns [CoseCipherError::UnsupportedAlgorithm] if the provided algorithm is not a supported
/// symmetric algorithm.
pub const fn symmetric_algorithm_iv_len<BE: Display>(
    alg: iana::Algorithm,
) -> Result<usize, CoseCipherError<BE>> {
    match alg {
        // AES-GCM: Nonce is fixed at 96 bits (RFC 9053, Section 4.1).
        // ChaCha20/Poly1305: Nonce is fixed at 96 bits (RFC 9053, Section 4.3).
        iana::Algorithm::A128GCM
        | iana::Algorithm::A192GCM
        | iana::Algorithm::A256GCM
        | iana::Algorithm::ChaCha20Poly1305 => Ok(12),
        // AES-CCM: Nonce length is parameterized (RFC 9053, Section 4.2).
        iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_16_128_256 => Ok(13),
        iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_64_128_128
        | iana::Algorithm::AES_CCM_64_64_256
        | iana::Algorithm::AES_CCM_64_128_256 => Ok(7),
        v => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            v,
        ))),
    }
}

/// Returns the authentication tag length expected for the symmetric algorithm given as `alg`.
///
/// # Errors
///
/// Returns [CoseCipherError::UnsupportedAlgorithm] if the provided algorithm is not a supported
/// symmetric algorithm.
pub const fn symmetric_algorithm_tag_len<BE: Display>(
    algorithm: iana::Algorithm,
) -> Result<usize, CoseCipherError<BE>> {
    match algorithm {
        // AES-CCM: Tag length is parameterized (RFC 9053, Section 4.2).
        iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_64_64_256 => Ok(8),
        iana::Algorithm::AES_CCM_16_128_256
        | iana::Algorithm::AES_CCM_64_128_256
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_64_128_128
        // AES-GCM: Tag length is fixed to 128 bits (RFC 9053, Section 4.1).
        | iana::Algorithm::A128GCM
        | iana::Algorithm::A192GCM
        | iana::Algorithm::A256GCM
        // ChaCha20/Poly1305: Tag length is fixed to 128 bits (RFC 9053, Section 4.3).
        | iana::Algorithm::ChaCha20Poly1305 => Ok(16),
        v => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            v,
        ))),
    }
}

/// Determines the key and IV for an AEAD operation using the provided `protected` and
/// `unprotected` headers, ensuring that the provided `parsed_key` is a valid symmetric key in the
/// process.
pub(crate) fn determine_and_check_symmetric_params<'a, BE: Display>(
    alg: iana::Algorithm,
    parsed_key: CoseParsedKey<'a, BE>,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
) -> Result<(CoseSymmetricKey<'a, BE>, Vec<u8>), CoseCipherError<BE>> {
    let symm_key = ensure_valid_symmetric_key::<BE>(alg, parsed_key)?;

    let iv = determine_header_param(protected, unprotected, |v| {
        (!v.iv.is_empty()).then_some(&v.iv)
    });

    let partial_iv = determine_header_param(protected, unprotected, |v| {
        (!v.partial_iv.is_empty()).then_some(&v.partial_iv)
    });

    let expected_iv_len = symmetric_algorithm_iv_len(alg)?;

    let iv = match (iv, partial_iv) {
        // IV and partial IV must not be set at the same time.
        (Some(_iv), Some(partial_iv)) => Err(CoseCipherError::InvalidHeaderParam(
            HeaderParam::Generic(iana::HeaderParameter::PartialIv),
            Value::Bytes(partial_iv.clone()),
        )),
        (Some(iv), None) => Ok(iv.clone()),
        // See https://datatracker.ietf.org/doc/html/rfc9052#section-3.1
        (None, Some(partial_iv)) => {
            let context_iv = (!symm_key.as_ref().base_iv.is_empty())
                .then(|| &symm_key.as_ref().base_iv)
                .ok_or(CoseCipherError::MissingKeyParam(vec![KeyParam::Common(
                    iana::KeyParameter::BaseIv,
                )]))?;

            if partial_iv.len() > expected_iv_len {
                return Err(CoseCipherError::InvalidHeaderParam(
                    HeaderParam::Generic(iana::HeaderParameter::PartialIv),
                    Value::Bytes(partial_iv.clone()),
                ));
            }

            if context_iv.len() > expected_iv_len {
                return Err(CoseCipherError::InvalidKeyParam(
                    KeyParam::Common(iana::KeyParameter::BaseIv),
                    Value::Bytes(context_iv.clone()),
                ));
            }

            let mut message_iv = vec![0u8; expected_iv_len];

            // Left-pad the Partial IV with zeros to the length of IV
            message_iv[(expected_iv_len - partial_iv.len())..].copy_from_slice(partial_iv);
            // XOR the padded Partial IV with the Context IV.
            message_iv
                .iter_mut()
                .zip(context_iv.iter().chain(core::iter::repeat(&0u8)))
                .for_each(|(b1, b2)| *b1 ^= *b2);
            Ok(message_iv)
        }
        (None, None) => Err(CoseCipherError::MissingHeaderParam(HeaderParam::Generic(
            iana::HeaderParameter::Iv,
        ))),
    }?;

    if iv.len() != expected_iv_len {
        return Err(CoseCipherError::InvalidHeaderParam(
            HeaderParam::Generic(iana::HeaderParameter::Iv),
            Value::Bytes(iv.clone()),
        ));
    }

    Ok((symm_key, iv))
}
