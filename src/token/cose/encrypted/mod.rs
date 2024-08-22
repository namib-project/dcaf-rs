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
use ciborium::Value;
use core::cell::RefCell;
use core::fmt::Display;
use coset::{iana, Algorithm, Header, KeyOperation};

use crate::error::CoseCipherError;
use crate::token::cose::header_util::HeaderParam;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey, KeyProvider};
use crate::token::cose::{header_util, key, CryptoBackend, KeyParam};

mod encrypt;
mod encrypt0;

pub use encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
pub use encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};

/// Authentication tag length to use for AES-GCM (fixed to 128 bits according to
/// [RFC 9053, section 4.1](https://datatracker.ietf.org/doc/html/rfc9053#section-4.1)).
pub const AES_GCM_TAG_LEN: usize = 16;

/// Nonce size used for AES-GCM (fixed to 96 bits according to
/// [RFC 9053, section 4.1](https://datatracker.ietf.org/doc/html/rfc9053#section-4.1)).
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Trait for cryptographic backends that can perform encryption and decryption operations for
/// algorithms used for COSE.
pub trait EncryptCryptoBackend: CryptoBackend {
    /// Encrypts the given `payload` using the AES-GCM variant provided as `algorithm` and the given
    /// `key`.
    ///
    /// Note that for all AES-GCM variants defined in RFC 9053, Section 4.1, the authentication tag
    /// should be 128 bits/16 bytes long.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AES-GCM variant to use.
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`]
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of AES-GCM are ever added).
    ///           If the algorithm is not an AES-GCM algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `plaintext` - Data that should be encrypted.
    /// * `aad` - additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the encryption process.
    ///           Implementations may assume that `iv` has the correct length for the given AES-GCM
    ///           variant and panic if this is not the case.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is the computed ciphertext concatenated with the
    /// authentication tag as a `Vec`.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an AES-GCM algorithm, the
    /// provided key or IV are not of the right length for the provided algorithm or if an
    /// unrecoverable backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new AES-GCM variants are ever
    /// defined).
    #[allow(unused_variables)]
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }

    /// Decrypts the given `payload` using the AES-GCM variant provided as `algorithm`, and the given
    /// `key` and `iv`.
    ///
    /// Note that for all AES-GCM variants defined in RFC 9053, Section 4.1, the authentication tag
    /// should be 128 bits/16 bytes long.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AES-GCM variant to use.
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of AES-GCM are ever added).
    ///           If the algorithm is not an AES-GCM algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `ciphertext_with_tag` - The ciphertext that should be decrypted concatenated with the
    ///           authentication tag that should be verified.
    ///           Is guaranteed to be at least as long as the authentication tag should be.
    /// * `aad` - additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the encryption process.
    ///           Implementations may assume that `iv` has the correct length for the given AES-GCM
    ///           variant and panic if this is not the case.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is either the computed plaintext if decryption and
    /// authentication are successful, or a [`CoseCipherError::VerificationFailure`] if one of these
    /// steps fails even though the input is well-formed.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an AES-GCM algorithm, the
    /// provided key or IV are not of the right length for the provided algorithm or if an
    /// unrecoverable backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new AES-GCM variants are ever
    /// defined).
    #[allow(unused_variables)]
    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }

    /// Encrypts the given `payload` using AES-CCM with the parameters L (size of length field)
    /// and M (size of authentication tag) specified for the given `algorithm` in
    /// [RFC 9053, section 4.2](https://datatracker.ietf.org/doc/html/rfc9053#section-4.2), the
    /// given `key`, and the provided `iv`.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AES-CCM variant to use.
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`]
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of AES-CCM are ever added).
    ///           If the algorithm is not an AES-CCM algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `plaintext` - Data that should be encrypted.
    /// * `aad` - additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the encryption process.
    ///           Implementations may assume that `iv` has the correct length for the given AES-CCM
    ///           variant and panic if this is not the case.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is the computed output of AES-CCM as specified in
    /// [RFC 3610, Section 2.4](https://datatracker.ietf.org/doc/html/rfc3610#section-2.4).
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an AES-CCM algorithm, the
    /// provided key or IV are not of the right length for the provided algorithm or if an
    /// unrecoverable backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new AES-CCM variants are ever
    /// defined).
    #[allow(unused_variables)]
    fn encrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }

    /// Decrypts the given `payload` using AES-CCM with the parameters L (size of length field)
    /// and M (size of authentication tag) specified for the given `algorithm` in
    /// [RFC 9053, section 4.2](https://datatracker.ietf.org/doc/html/rfc9053#section-4.2) and the
    /// given `key`.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AES-CCM variant to use.
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of AES-CCM are ever added).
    ///           If the algorithm is not an AES-CCM algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `ciphertext_with_tag` - The ciphertext that should be decrypted concatenated with the
    ///           authentication tag that should be verified (if valid, should be the output of a
    ///           previous encryption as specified in
    ///           [RFC 3610, Section 2.4](https://datatracker.ietf.org/doc/html/rfc3610#section-2.4)).
    ///           Is guaranteed to be at least as long as the authentication tag should be.
    /// * `aad` - additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the encryption process.
    ///           Implementations may assume that `iv` has the correct length for the given AES-CCM
    ///           variant and panic if this is not the case.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is either the computed plaintext if decryption and
    /// authentication are successful, or a [`CoseCipherError::VerificationFailure`] if one of these
    /// steps fails even though the input is well-formed.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an AES-CCM algorithm, the
    /// provided key or IV are not of the right length for the provided algorithm or if an
    /// unrecoverable backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new AES-CCM variants are ever
    /// defined).
    #[allow(unused_variables)]
    fn decrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        )))
    }
}

/// Returns the IV length expected for the AES variant given as `alg`.
///
/// # Errors
///
/// Returns [CoseCipherError::UnsupportedAlgorithm] if the provided algorithm is not a supported
/// AES algorithm.
pub fn aes_algorithm_iv_len<BE: Display>(
    alg: iana::Algorithm,
) -> Result<usize, CoseCipherError<BE>> {
    match alg {
        // AES-GCM: Nonce is fixed at 96 bits (RFC 9053, Section 4.1)
        iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM => {
            Ok(AES_GCM_NONCE_SIZE)
        }
        // AES-CCM: Nonce length is parameterized.
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

/// Returns the authentication tag length expected for the AES-CCM variant given as `alg`.
///
/// # Errors
///
/// Returns [CoseCipherError::UnsupportedAlgorithm] if the provided algorithm is not a supported
/// variant of AES-CCM.
pub fn aes_ccm_algorithm_tag_len<BE: Display>(
    algorithm: iana::Algorithm,
) -> Result<usize, CoseCipherError<BE>> {
    match algorithm {
        iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_64_64_256 => Ok(8),
        iana::Algorithm::AES_CCM_16_128_256
        | iana::Algorithm::AES_CCM_64_128_256
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_64_128_128 => Ok(16),
        v => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            v,
        ))),
    }
}

/// Determines the key and IV for an AES AEAD operation using the provided `protected` and
/// `unprotected` headers, ensuring that the provided `parsed_key` is a valid AES key in the
/// process.
fn determine_and_check_aes_params<'a, 'b, BE: Display>(
    alg: iana::Algorithm,
    parsed_key: CoseParsedKey<'a, BE>,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
) -> Result<(CoseSymmetricKey<'a, BE>, Vec<u8>), CoseCipherError<BE>> {
    let symm_key = key::ensure_valid_aes_key::<BE>(alg, parsed_key)?;

    let iv = header_util::determine_header_param(protected, unprotected, |v| {
        (!v.iv.is_empty()).then(|| &v.iv)
    });

    let partial_iv = header_util::determine_header_param(protected, unprotected, |v| {
        (!v.partial_iv.is_empty()).then(|| &v.partial_iv)
    });

    let expected_iv_len = aes_algorithm_iv_len(alg)?;

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
            message_iv[(expected_iv_len - partial_iv.len())..].copy_from_slice(&partial_iv);
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

/// Attempts to perform a COSE encryption operation for a [`CoseEncrypt`](coset::CoseEncrypt) or
/// [`CoseEncrypt0`](coset::CoseEncrypt0) structure with the given `protected` and `unprotected`
/// headers, `plaintext` and `enc_structure` using the given `backend` and `key_provider`.
///
/// Also performs checks that ensure that the given parameters (esp. headers and keys) are valid and
/// are coherent with each other.
///
/// If the `key_provider` returns multiple keys, all will be tried until one can be successfully
/// used for the given operation.
fn try_encrypt<B: EncryptCryptoBackend, CKP: KeyProvider>(
    backend: &mut B,
    key_provider: &CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    plaintext: &[u8],
    // NOTE: this should be treated as the AAD for the purposes of the cryptographic backend
    // (RFC 9052, Section 5.3).
    enc_structure: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    header_util::try_cose_crypto_operation(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Encrypt)]),
        |key, alg, protected, unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;
            match alg {
                iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM => {
                    // Check if this is a valid AES key, determine IV.
                    let (symm_key, iv) =
                        determine_and_check_aes_params(alg, parsed_key, protected, unprotected)?;

                    backend.encrypt_aes_gcm(alg, symm_key, plaintext, enc_structure, &iv)
                }
                iana::Algorithm::AES_CCM_16_64_128
                | iana::Algorithm::AES_CCM_64_64_128
                | iana::Algorithm::AES_CCM_16_128_128
                | iana::Algorithm::AES_CCM_64_128_128
                | iana::Algorithm::AES_CCM_16_64_256
                | iana::Algorithm::AES_CCM_64_64_256
                | iana::Algorithm::AES_CCM_16_128_256
                | iana::Algorithm::AES_CCM_64_128_256 => {
                    // Check if this is a valid AES key, determine IV.
                    let (symm_key, iv) =
                        determine_and_check_aes_params(alg, parsed_key, protected, unprotected)?;

                    backend.encrypt_aes_ccm(alg, symm_key, plaintext, enc_structure, &iv)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}

/// Attempts to perform a COSE decryption operation for a [`CoseEncrypt`](coset::CoseEncrypt) or
/// [`CoseEncrypt0`](coset::CoseEncrypt0) structure with the given `protected` and `unprotected`
/// headers, `plaintext` and `enc_structure` using the given `backend` and `key_provider`.
///
/// Also performs checks that ensure that the given parameters (esp. headers and keys) are valid and
/// are coherent with each other.
///
/// If the `key_provider` returns multiple keys, all will be tried until one can be successfully
/// used for the given operation.
pub(crate) fn try_decrypt<B: EncryptCryptoBackend, CKP: KeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &CKP,
    protected: &Header,
    unprotected: &Header,
    ciphertext: &[u8],
    // NOTE: this should be treated as the AAD for the purposes of the cryptographic backend
    // (RFC 9052, Section 5.3).
    enc_structure: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    header_util::try_cose_crypto_operation(
        key_provider,
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Decrypt)]),
        |key, alg, protected, unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;
            match alg {
                iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM => {
                    // Check if this is a valid AES key, determine IV.
                    let (symm_key, iv) =
                        determine_and_check_aes_params(alg, parsed_key, protected, unprotected)?;

                    // Authentication tag is 16 bytes long and should be included in the ciphertext.
                    // Empty payloads are allowed, therefore we check for ciphertext.len() < 16, not <= 16.
                    if ciphertext.len() < AES_GCM_TAG_LEN {
                        return Err(CoseCipherError::VerificationFailure);
                    }

                    (*backend.borrow_mut()).decrypt_aes_gcm(
                        alg,
                        symm_key,
                        ciphertext,
                        enc_structure,
                        &iv,
                    )
                }
                iana::Algorithm::AES_CCM_16_64_128
                | iana::Algorithm::AES_CCM_64_64_128
                | iana::Algorithm::AES_CCM_16_128_128
                | iana::Algorithm::AES_CCM_64_128_128
                | iana::Algorithm::AES_CCM_16_64_256
                | iana::Algorithm::AES_CCM_64_64_256
                | iana::Algorithm::AES_CCM_16_128_256
                | iana::Algorithm::AES_CCM_64_128_256 => {
                    // Check if this is a valid AES key, determine IV.
                    let (symm_key, iv) =
                        determine_and_check_aes_params(alg, parsed_key, protected, unprotected)?;

                    if ciphertext.len() < aes_ccm_algorithm_tag_len(alg)? {
                        return Err(CoseCipherError::VerificationFailure);
                    }

                    (*backend.borrow_mut()).decrypt_aes_ccm(
                        alg,
                        symm_key,
                        ciphertext,
                        enc_structure,
                        &iv,
                    )
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
