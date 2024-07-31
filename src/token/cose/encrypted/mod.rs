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
use crate::token::cose::header_util::HeaderParam;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey, KeyProvider};
use crate::token::cose::{header_util, key, CryptoBackend};

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
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    /// Decrypts the given `payload` using the AES-GCM variant provided as `algorithm` and the given
    /// `key`.
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
    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
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
                    // Check if this is a valid AES key.
                    let symm_key = key::ensure_valid_aes_key::<B::Error>(alg, parsed_key)?;

                    let iv = protected
                        .into_iter()
                        .chain(unprotected.into_iter())
                        .filter(|x| !x.iv.is_empty())
                        .map(|x| x.iv.as_ref())
                        .next()
                        .ok_or(CoseCipherError::MissingHeaderParam(HeaderParam::Generic(
                            iana::HeaderParameter::Iv,
                        )))?;

                    backend.encrypt_aes_gcm(alg, symm_key, plaintext, enc_structure, iv)
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
                    // Check if this is a valid AES key.
                    let symm_key = key::ensure_valid_aes_key::<B::Error>(alg, parsed_key)?;

                    let iv = protected
                        .into_iter()
                        .chain(unprotected.into_iter())
                        .filter(|x| !x.iv.is_empty())
                        .map(|x| x.iv.as_ref())
                        .next()
                        .ok_or(CoseCipherError::MissingHeaderParam(HeaderParam::Generic(
                            iana::HeaderParameter::Iv,
                        )))?;

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
                        iv,
                    )
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
