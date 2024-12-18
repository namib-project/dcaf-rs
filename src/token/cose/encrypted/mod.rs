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
use coset::{iana, Algorithm, Header, KeyOperation};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey, KeyProvider};
use crate::token::cose::CryptoBackend;

mod encrypt;
mod encrypt0;

use crate::token::cose::util::{
    determine_and_check_symmetric_params, symmetric_algorithm_tag_len, try_cose_crypto_operation,
};
pub use encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
pub use encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};

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

    /// Decrypts the given `ciphertext_with_tag` using AES-CCM with the parameters L (size of length field)
    /// and M (size of authentication tag) specified for the given `algorithm` in
    /// [RFC 9053, section 4.2](https://datatracker.ietf.org/doc/html/rfc9053#section-4.2), the
    /// given `key`, and the provided `iv`.
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
    /// * `aad` - Additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the decryption process.
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

    /// Encrypts the given `payload` using ChaCha20/Poly1305 using the parameters specified for it
    /// in [RFC 9053, section 4.3](https://datatracker.ietf.org/doc/html/rfc9053#section-4.3), the
    /// given `key`, and the provided `iv`.
    ///
    /// # Arguments
    ///
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for
    ///           ChaCha20/Poly1305 and panic if this is not the case.
    /// * `plaintext` - Data that should be encrypted.
    /// * `aad` - Additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the encryption process.
    ///           Implementations may assume that `iv` has the correct length for ChaCha20/Poly1305
    ///           and panic if this is not the case.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is the computed output of ChaCha20/Poly1305 as
    /// specified in [RFC 8439, Section 2.8](https://datatracker.ietf.org/doc/html/rfc8439#section-2.8).
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided key or IV are not of the right length for
    /// ChaCha20/Poly1305 or if an unrecoverable backend error occurs that necessitates a panic (at
    /// their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    #[allow(unused_variables)]
    fn encrypt_chacha20_poly1305(
        &mut self,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            iana::Algorithm::ChaCha20Poly1305,
        )))
    }

    /// Decrypts the given `ciphertext_with_tag` using ChaCha20/Poly1305 using the parameters specified for it
    /// in [RFC 9053, section 4.3](https://datatracker.ietf.org/doc/html/rfc9053#section-4.3), the
    /// given `key`, and the provided `iv`.
    ///
    /// # Arguments
    ///
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for
    ///           ChaCha20/Poly1305 and panic if this is not the case.
    /// * `ciphertext_with_tag` - The ciphertext that should be decrypted concatenated with the
    ///           authentication tag that should be verified (if valid, should be the output of a
    ///           previous encryption as specified in
    ///           [RFC 8439, Section 2.8](https://datatracker.ietf.org/doc/html/rfc8439#section-2.8)).
    ///           Is guaranteed to be at least as long as the authentication tag should be.
    /// * `aad` - Additional authenticated data that should be included in the calculation of the
    ///           authentication tag, but not encrypted.
    /// * `iv`  - Initialization vector that should be used for the decryption process.
    ///           Implementations may assume that `iv` has the correct length for ChaCha20/Poly1305
    ///           and panic if this is not the case.
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
    /// Implementations may panic if the provided key or IV are not of the right length for
    /// ChaCha20/Poly1305 or if an unrecoverable backend error occurs that necessitates a panic (at
    /// their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    #[allow(unused_variables)]
    fn decrypt_chacha20_poly1305(
        &mut self,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            iana::Algorithm::ChaCha20Poly1305,
        )))
    }
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
    try_cose_crypto_operation(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Encrypt)]),
        |key, alg, protected, unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;
            // Check if this is a valid symmetric key, determine IV.
            let (symm_key, iv) =
                determine_and_check_symmetric_params(alg, parsed_key, protected, unprotected)?;
            match alg {
                iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM => {
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
                    backend.encrypt_aes_ccm(alg, symm_key, plaintext, enc_structure, &iv)
                }
                iana::Algorithm::ChaCha20Poly1305 => {
                    backend.encrypt_chacha20_poly1305(symm_key, plaintext, enc_structure, &iv)
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
    try_cose_crypto_operation(
        key_provider,
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Decrypt)]),
        |key, alg, protected, unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;
            // Check if this is a valid symmetric key, determine IV.
            let (symm_key, iv) =
                determine_and_check_symmetric_params(alg, parsed_key, protected, unprotected)?;

            // Authentication tag is 16 bytes long and should be included in the ciphertext.
            // Empty payloads are allowed, therefore we check for ciphertext.len() < 16, not <= 16.
            if ciphertext.len() < symmetric_algorithm_tag_len(alg)? {
                return Err(CoseCipherError::VerificationFailure);
            }

            match alg {
                iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM => {
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
                | iana::Algorithm::AES_CCM_64_128_256 => (*backend.borrow_mut()).decrypt_aes_ccm(
                    alg,
                    symm_key,
                    ciphertext,
                    enc_structure,
                    &iv,
                ),
                iana::Algorithm::ChaCha20Poly1305 => (*backend.borrow_mut())
                    .decrypt_chacha20_poly1305(symm_key, ciphertext, enc_structure, &iv),
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
