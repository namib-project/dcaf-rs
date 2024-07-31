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
use alloc::collections::{BTreeSet, VecDeque};
use alloc::rc::Rc;
use alloc::vec::Vec;
use ciborium::Value;
use core::borrow::Borrow;
use core::cell::RefCell;
use core::fmt::Display;
use coset::{
    iana, Algorithm, CoseKey, CoseKeyBuilder, CoseRecipient, CoseRecipientBuilder,
    EncryptionContext, Header, KeyOperation,
};

use crate::error::CoseCipherError;
use crate::token::cose::aad::{AadProvider, InvertedAadProvider};
use crate::token::cose::header_util::{determine_algorithm, determine_key_candidates};
use crate::token::cose::key::ensure_valid_aes_key;
use crate::token::cose::key::{CoseParsedKey, KeyProvider};
use crate::token::cose::{
    determine_header_param, try_cose_crypto_operation, CoseSymmetricKey, CryptoBackend, HeaderParam,
};

/// Trait for cryptographic backends that can perform key distribution operations for algorithms
/// used in COSE structures.
pub trait KeyDistributionCryptoBackend: CryptoBackend {
    /// Encrypts the given `plaintext` using the AES key wrap (RFC 3394) variant provided as
    /// `algorithm` and the given `key`.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AES key wrap variant to use.
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of AES key wrap are ever added).
    ///           If the algorithm is not an AES key wrap algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `plaintext` - Data (key) that should be wrapped.
    ///           Implementations may assume that the provided plaintext's length is a multiple of
    ///           64 bits, and panic otherwise.
    /// * `iv`  - Initialization vector that should be used for the key wrap process.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is the computed ciphertext/wrapped key as a `Vec` of
    /// bytes.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an AES key wrap algorithm, the
    /// provided key, plaintext or IV are not of the right length for the provided algorithm or if
    /// an unrecoverable backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new AES-GCM variants are ever
    /// defined).
    fn aes_key_wrap(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    /// Decrypts the given `ciphertext` using the AES key unwrap (RFC 3394) variant provided as
    /// `algorithm` and the given `key`.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The AES key wrap variant to use.
    ///           If unsupported by the backend, a [`CoseCipherError::UnsupportedAlgorithm`] error
    ///           should be returned.
    ///           If the given algorithm is an IANA-assigned value that is unknown, the
    ///           implementation should return [`CoseCipherError::UnsupportedAlgorithm`] (in case
    ///           additional variants of AES key wrap are ever added).
    ///           If the algorithm is not an AES key wrap algorithm, the implementation may return
    ///           [`CoseCipherError::UnsupportedAlgorithm`] or panic.
    /// * `key` - Symmetric key that should be used.
    ///           Implementations may assume that the provided key has the right length for the
    ///           provided algorithm, and panic if this is not the case.
    /// * `ciphertext` - Data (key) that should be unwrapped.
    ///           Implementations may assume that the resulting plaintext's length is a multiple of
    ///           64 bits, and panic otherwise.
    /// * `iv`  - Initialization vector that should be used for the key wrap process.
    ///
    /// # Returns
    ///
    /// It is expected that the return value is the computed plaintext/unwrapped key as a `Vec` of
    /// bytes.
    ///
    /// # Errors
    ///
    /// In case of errors, the implementation may return any valid [`CoseCipherError`].
    /// For backend-specific errors, [`CoseCipherError::Other`] may be used to convey a
    /// backend-specific error.
    ///
    /// # Panics
    ///
    /// Implementations may panic if the provided algorithm is not an AES key wrap algorithm, the
    /// provided key, plaintext or IV are not of the right length for the provided algorithm or if
    /// an unrecoverable backend error occurs that necessitates a panic (at their own discretion).
    /// In the last of the above cases, additional panics should be documented on the backend level.
    ///
    /// For unknown algorithms or key curves, however, the implementation must not panic and return
    /// [`CoseCipherError::UnsupportedAlgorithm`] instead (in case new AES-GCM variants are ever
    /// defined).
    fn aes_key_unwrap(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

/// Internal structure that implements the key provider trait by creating depth-first search
/// iterators ([`CoseNestedRecipientIterator`]) through a nested recipient structure.
pub(crate) struct CoseNestedRecipientSearchContext<
    'a,
    B: KeyDistributionCryptoBackend,
    CKP: KeyProvider,
    AAD: AadProvider,
> {
    recipient_iter: &'a Vec<CoseRecipient>,
    backend: Rc<RefCell<&'a mut B>>,
    key_provider: &'a CKP,
    aad_provider: Rc<InvertedAadProvider<AAD>>,
    context: EncryptionContext,
    errors: Rc<RefCell<Vec<(&'a CoseRecipient, CoseCipherError<B::Error>)>>>,
}

impl<'a, B: KeyDistributionCryptoBackend, CKP: KeyProvider, AAD: AadProvider>
    CoseNestedRecipientSearchContext<'a, B, CKP, AAD>
{
    /// Constructs a new recipient search context using the given iterator of top-level recipients
    /// (which should all belong to a COSE structure matching the provided `context`), `backend` and
    /// `key_provider`.
    pub(crate) fn new(
        recipient_iter: &'a Vec<CoseRecipient>,
        backend: Rc<RefCell<&'a mut B>>,
        key_provider: &'a CKP,
        aad_provider: AAD,
        context: EncryptionContext,
    ) -> CoseNestedRecipientSearchContext<'a, B, CKP, AAD> {
        CoseNestedRecipientSearchContext {
            recipient_iter,
            backend,
            key_provider,
            aad_provider: Rc::new(InvertedAadProvider(aad_provider)),
            context,
            errors: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Consumes this recipient search context, returning the errors that occurred during its use.
    pub(crate) fn into_errors(self) -> Vec<(CoseRecipient, CoseCipherError<B::Error>)> {
        RefCell::take(&self.errors)
            .into_iter()
            .map(|(r, e)| (r.clone(), e))
            .collect()
    }
}

impl<'a, B: KeyDistributionCryptoBackend, CKP: KeyProvider, AAD: AadProvider> KeyProvider
    for CoseNestedRecipientSearchContext<'a, B, CKP, AAD>
{
    /// Constructs a [`CoseNestedRecipientIterator`] for key lookup.
    fn lookup_key(&self, _key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        CoseNestedRecipientIterator {
            iteration_state: vec![self.recipient_iter.iter()],
            recipient_stack: vec![],
            backend: Rc::clone(&self.backend),
            key_provider: self.key_provider,
            aad_provider: Rc::clone(&self.aad_provider),
            current_key_candidates: VecDeque::default(),
            current_candidates_position: 0,
            errors: Rc::clone(&self.errors),
            context: self.context,
        }
    }
}

/// An iterator that performs a depth-first search through a nested [`CoseRecipient`] structure,
/// attempts to decrypt those recipients and yields potential CEKs resulting from this search.
struct CoseNestedRecipientIterator<
    'a,
    B: KeyDistributionCryptoBackend,
    CKP: KeyProvider,
    AAD: AadProvider,
> {
    iteration_state: Vec<alloc::slice::Iter<'a, CoseRecipient>>,
    recipient_stack: Vec<&'a CoseRecipient>,
    backend: Rc<RefCell<&'a mut B>>,
    key_provider: &'a CKP,
    aad_provider: Rc<InvertedAadProvider<AAD>>,
    current_key_candidates: VecDeque<CoseKey>,
    current_candidates_position: usize,
    errors: Rc<RefCell<Vec<(&'a CoseRecipient, CoseCipherError<B::Error>)>>>,
    context: EncryptionContext,
}

impl<'a, B: KeyDistributionCryptoBackend, CKP: KeyProvider, AAD: AadProvider> Iterator
    for CoseNestedRecipientIterator<'a, B, CKP, AAD>
{
    type Item = CoseKey;

    fn next(&mut self) -> Option<Self::Item> {
        // This iterator yields the next possible CEK candidate from a nested CoseRecipient
        // structure.

        // The following algorithm is an iterative implementation of a depth-first search for a
        // decryptable CoseRecipient, i.e. a recipient for which our key provider has a possible key
        // candidate.

        if let Some(key) = self.current_key_candidates.pop_front() {
            return Some(key);
        }

        // Get current iterator (aka. the iterator on top of the stack).
        while let Some(current_iterator) = self.iteration_state.last_mut() {
            // Get next recipient candidate from iterator.
            let next_recipient = match current_iterator.next() {
                None => {
                    // current iterator has no more recipient candidates to offer, which means that
                    // we have no way of decrypting the recipient on top of the stack.
                    // Remove last iterator and current decryptable recipient candidate from their
                    // respective stacks and proceed with next iteration.
                    self.iteration_state
                        .truncate(self.iteration_state.len() - 1);
                    if self.recipient_stack.is_empty() {
                        // If the recipient stack was already empty, we should have now removed the
                        // last iterator from the stack (will cause loop exit on next iteration).
                        debug_assert!(self.iteration_state.is_empty());
                    } else {
                        self.recipient_stack
                            .truncate(self.recipient_stack.len() - 1);
                    }

                    continue;
                }
                Some(r) => r,
            };

            if next_recipient.recipients.is_empty() {
                // Recipient has itself no recipients, therefore it is a leaf node, and we should
                // attempt to decrypt it using keys provided by the application.
                match self.attempt_to_decrypt_nested(next_recipient) {
                    Ok(v) => {
                        // If the attempt resulted in a list of possible CEKs to consider, return
                        // the first element.
                        if !v.is_empty() {
                            self.current_key_candidates = v;
                            self.current_candidates_position = 1;
                            return self.current_key_candidates.pop_front();
                        };
                        // Otherwise, just attempt to continue with the next possible candidate.
                        continue;
                    }
                    Err(e) => {
                        // An error occurred.
                        // Some errors are recoverable by simply proceeding with the next recipient,
                        // others are not.
                        // For non-recoverable errors, the called function will clear the iteration
                        // state, therefore we just continue with the next iteration here.
                        self.errors.borrow_mut().push((next_recipient, e));
                        continue;
                    }
                }
            }
            // Recipient has itself recipients, which means that the key for this recipient is
            // itself encrypted in its own recipient structures.
            // Proceed search with nested recipients.
            self.iteration_state.push(next_recipient.recipients.iter());
            self.recipient_stack.push(next_recipient);
        }

        // We ran out of recipients to consider, i.e. we have completed the DFS and still haven't
        // found a candidate.
        None
    }
}

/// Returns the `EncryptionContext` of recipients that are nested in a COSE structure of a given
/// `ctx`,
///
/// If you provide [`EncryptionContext::CoseEncrypt`], this function will return
/// [`EncryptionContext::EncRecipient`], as recipients that are part of `CoseEncrypt` structures
/// should have the encryption context `EncRecipient`.
#[inline]
pub(crate) fn struct_to_recipient_context(ctx: EncryptionContext) -> EncryptionContext {
    match ctx {
        EncryptionContext::CoseEncrypt => EncryptionContext::EncRecipient,
        EncryptionContext::CoseEncrypt0 => panic!("attempted to obtain recipient context for a CoseEncrypt0 object (which can't contain CoseRecipients)"),
        EncryptionContext::EncRecipient | EncryptionContext::MacRecipient | EncryptionContext::RecRecipient => EncryptionContext::RecRecipient,
    }
}

impl<'a, B: KeyDistributionCryptoBackend, CKP: KeyProvider, AAD: AadProvider>
    CoseNestedRecipientIterator<'a, B, CKP, AAD>
{
    /// Attempt to determine the top level key candidates that result from decrypting the recipient
    /// tree upwards from the given `leaf_recipient` (the struct fields should represent a state
    /// in which the stacks are a path from the tree root to the leaf node).
    fn attempt_to_decrypt_nested(
        &mut self,
        leaf_recipient: &CoseRecipient,
    ) -> Result<VecDeque<CoseKey>, CoseCipherError<B::Error>> {
        let ctx = if self.recipient_stack.is_empty() {
            self.context
        } else {
            EncryptionContext::RecRecipient
        };
        // Attempt to decrypt leaf node, return (non-search-terminating) error if that doesn't work.
        let mut current_keys: Vec<CoseKey> = leaf_recipient
            .try_decrypt::<_, _, &InvertedAadProvider<AAD>>(
                *self.backend.borrow_mut(),
                self.key_provider,
                ctx,
                self.aad_provider.borrow(),
            )?;

        let iter = self.recipient_stack.iter().copied().rev();

        for (rpos, recipient) in iter.enumerate() {
            let ctx = if self.recipient_stack.len() - 1 > rpos {
                EncryptionContext::RecRecipient
            } else {
                struct_to_recipient_context(self.context)
            };

            match recipient.try_decrypt::<_, _, &InvertedAadProvider<AAD>>(
                *self.backend.borrow_mut(),
                &current_keys,
                ctx,
                self.aad_provider.borrow(),
            ) {
                Ok(v) => current_keys = v,
                Err(e @ CoseCipherError::UnsupportedAlgorithm(_)) => return Err(e),
                Err(e) => {
                    // An error while decrypting an intermediate recipient indicates a malformed
                    // COSE object, terminate recursive search.
                    self.iteration_state.clear();
                    self.recipient_stack.clear();
                    return Err(e);
                }
            }
        }

        Ok(VecDeque::from(current_keys))
    }
}

/// Determine the key operations that a key may have in order to be valid for an encryption
/// operation of the given `algorithm`.
fn determine_encrypt_key_ops_for_alg<CE: Display>(
    algorithm: iana::Algorithm,
) -> Result<BTreeSet<KeyOperation>, CoseCipherError<CE>> {
    Ok(BTreeSet::from_iter(match algorithm {
        iana::Algorithm::Direct => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::WrapKey),
                KeyOperation::Assigned(iana::KeyOperation::UnwrapKey),
                KeyOperation::Assigned(iana::KeyOperation::MacCreate),
                KeyOperation::Assigned(iana::KeyOperation::MacVerify),
                KeyOperation::Assigned(iana::KeyOperation::Encrypt),
                KeyOperation::Assigned(iana::KeyOperation::Decrypt),
                KeyOperation::Assigned(iana::KeyOperation::DeriveBits),
                KeyOperation::Assigned(iana::KeyOperation::DeriveKey),
                KeyOperation::Assigned(iana::KeyOperation::Sign),
                KeyOperation::Assigned(iana::KeyOperation::Verify),
            ]
        }

        iana::Algorithm::Direct_HKDF_AES_128
        | iana::Algorithm::Direct_HKDF_AES_256
        | iana::Algorithm::Direct_HKDF_SHA_256
        | iana::Algorithm::Direct_HKDF_SHA_512
        | iana::Algorithm::ECDH_ES_HKDF_256
        | iana::Algorithm::ECDH_ES_HKDF_512
        | iana::Algorithm::ECDH_SS_HKDF_256
        | iana::Algorithm::ECDH_SS_HKDF_512
        | iana::Algorithm::ECDH_ES_A128KW
        | iana::Algorithm::ECDH_ES_A192KW
        | iana::Algorithm::ECDH_ES_A256KW
        | iana::Algorithm::ECDH_SS_A128KW
        | iana::Algorithm::ECDH_SS_A192KW
        | iana::Algorithm::ECDH_SS_A256KW => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::DeriveKey),
                KeyOperation::Assigned(iana::KeyOperation::DeriveBits),
            ]
        }
        iana::Algorithm::A128KW | iana::Algorithm::A192KW | iana::Algorithm::A256KW => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::Encrypt),
                KeyOperation::Assigned(iana::KeyOperation::WrapKey),
            ]
        }
        alg => {
            // Unsupported algorithm - skip over this recipient.
            return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                alg,
            )));
        }
    }))
}

/// Determine the key operations that a key may have in order to be valid for a decryption
/// operation of the given `algorithm`.
fn determine_decrypt_key_ops_for_alg<CE: Display>(
    alg: iana::Algorithm,
) -> Result<BTreeSet<KeyOperation>, CoseCipherError<CE>> {
    Ok(BTreeSet::from_iter(match alg {
        iana::Algorithm::Direct => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::WrapKey),
                KeyOperation::Assigned(iana::KeyOperation::UnwrapKey),
                KeyOperation::Assigned(iana::KeyOperation::MacCreate),
                KeyOperation::Assigned(iana::KeyOperation::MacVerify),
                KeyOperation::Assigned(iana::KeyOperation::Encrypt),
                KeyOperation::Assigned(iana::KeyOperation::Decrypt),
                KeyOperation::Assigned(iana::KeyOperation::DeriveBits),
                KeyOperation::Assigned(iana::KeyOperation::DeriveKey),
                KeyOperation::Assigned(iana::KeyOperation::Sign),
                KeyOperation::Assigned(iana::KeyOperation::Verify),
            ]
        }
        iana::Algorithm::Direct_HKDF_AES_128
        | iana::Algorithm::Direct_HKDF_AES_256
        | iana::Algorithm::Direct_HKDF_SHA_256
        | iana::Algorithm::Direct_HKDF_SHA_512
        | iana::Algorithm::ECDH_ES_HKDF_256
        | iana::Algorithm::ECDH_ES_HKDF_512
        | iana::Algorithm::ECDH_SS_HKDF_256
        | iana::Algorithm::ECDH_SS_HKDF_512
        | iana::Algorithm::ECDH_ES_A128KW
        | iana::Algorithm::ECDH_ES_A192KW
        | iana::Algorithm::ECDH_ES_A256KW
        | iana::Algorithm::ECDH_SS_A128KW
        | iana::Algorithm::ECDH_SS_A192KW
        | iana::Algorithm::ECDH_SS_A256KW => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::DeriveKey),
                KeyOperation::Assigned(iana::KeyOperation::DeriveBits),
            ]
        }
        iana::Algorithm::A128KW | iana::Algorithm::A192KW | iana::Algorithm::A256KW => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::Decrypt),
                KeyOperation::Assigned(iana::KeyOperation::UnwrapKey),
            ]
        }
        alg => {
            // Unsupported algorithm - skip over this recipient.
            return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                alg,
            )));
        }
    }))
}

/// Extensions to the [`CoseRecipientBuilder`] type that enable usage of cryptographic backends.
pub trait CoseRecipientBuilderExt: Sized {
    /// Attempts to encrypt the provided payload/key using a cryptographic backend.
    ///
    /// Note that you still have to ensure that the key is available to the recipient somehow, i.e.
    /// by adding nested [`CoseRecipient`] structures where suitable.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `context`      - Context under which this recipient was encrypted.
    /// - `protected`    - protected headers for the resulting [`CoseRecipient`] instance. Will
    ///                    override headers previously set using
    ///                    [`CoseRecipientBuilder::protected`](CoseRecipientBuilder).
    /// - `unprotected`  - unprotected headers for the resulting [`CoseRecipient`] instance. Will
    ///                    override headers previously set using
    ///                    [`CoseRecipientBuilder::unprotected`](CoseRecipientBuilder).
    /// - `payload`      - payload which should be added to the resulting [`CoseRecipient`] instance
    ///                    and for which the MAC should be calculated. Will override a payload
    ///                    previously set using
    ///                    [`CoseRecipientBuilder::payload`](CoseRecipientBuilder).
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](CoseKey) or AAD (or any combination of those)
    /// are malformed or otherwise unsuitable for encryption, this function will return the
    /// most fitting [`CoseCipherError`] for the specific type of error.
    ///
    /// If additional authenticated data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [`CoseCipherError::AadUnsupported`] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but the key provider does not provide a key, a
    /// [`CoseCipherError::NoMatchingKeyFound`] error will be returned.
    ///
    /// # Examples
    ///
    /// Refer to [the documentation for the CoseRecipient extensions](CoseRecipientExt) for examples.
    // Integration into coset will allow reducing the number of algorithms, but for now this will
    // have to make do.
    #[allow(clippy::too_many_arguments)]
    fn try_encrypt<B: KeyDistributionCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        context: EncryptionContext,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseRecipientBuilderExt for CoseRecipientBuilder {
    fn try_encrypt<B: KeyDistributionCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,

        context: EncryptionContext,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;

        let alg =
            match determine_algorithm::<B::Error>(None, protected.as_ref(), unprotected.as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    // A CoseRecipient MUST always have an algorithm set (see RFC 9052,
                    // Section 8), which means that this COSE object is malformed.
                    return Err(e);
                }
            };

        // Direct => Key of will be used for lower layer directly, must not contain ciphertext.
        if iana::Algorithm::Direct == alg {
            return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                iana::Algorithm::Direct,
            )));
        }

        if let Some(iv) = determine_header_param(protected.as_ref(), unprotected.as_ref(), |h| {
            Some(&h.iv).filter(|v| !v.is_empty()).cloned()
        }) {
            return Err(CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.clone()),
            ));
        }

        // Determine key operations that fulfill the requirements of the algorithm.
        let operation = determine_encrypt_key_ops_for_alg(alg)?;

        builder = builder.try_create_ciphertext(
            context,
            payload,
            external_aad
                .lookup_aad(Some(context), protected.as_ref(), unprotected.as_ref())
                .unwrap_or(&[] as &[u8]),
            |plaintext, _aad| {
                try_cose_crypto_operation(
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    operation,
                    |key, alg, protected, _unprotected| {
                        let parsed_key = CoseParsedKey::try_from(key)?;
                        match alg {
                            iana::Algorithm::A128KW
                            | iana::Algorithm::A192KW
                            | iana::Algorithm::A256KW => {
                                let symm_key = ensure_valid_aes_key(alg, parsed_key)?;

                                if protected.is_some() && !protected.as_ref().unwrap().is_empty() {
                                    return Err(CoseCipherError::AadUnsupported);
                                }

                                if plaintext.len() % 8 != 0 {
                                    return Err(CoseCipherError::InvalidPayload(
                                        plaintext.to_vec(),
                                    ));
                                }

                                backend.aes_key_wrap(
                                    alg,
                                    symm_key,
                                    plaintext,
                                    // Fixed IV, see RFC 9053, Section 6.2.1
                                    &[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6],
                                )
                            }
                            alg => {
                                // Unsupported algorithm - skip over this recipient.
                                Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                                    alg,
                                )))
                            }
                        }
                    },
                )
            },
        )?;

        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }

        Ok(builder)
    }
}

/// Extensions to the [`CoseRecipient`] type that enable usage of cryptographic backends.
///
/// # Examples
///
/// Create a simple [`CoseRecipient`] instance that encrypts a content encryption key using AES key
/// wrap and then decrypts it again:
///
/// ```
///
/// use coset::{CoseEncrypt0Builder, CoseKeyBuilder, CoseRecipientBuilder, EncryptionContext, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseEncrypt0BuilderExt, CoseEncrypt0Ext, CoseRecipientBuilderExt, CoseRecipientExt, CoseSymmetricKey, HeaderBuilderExt};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
///
/// let mut backend = OpensslContext::new();
///
/// let mut kek_data = vec![0; 32];
/// backend.generate_rand(kek_data.as_mut_slice())?;
/// let kek = CoseKeyBuilder::new_symmetric_key(kek_data).build();
///
/// let mut cek_data = vec![0; 32];
/// backend.generate_rand(cek_data.as_mut_slice())?;
/// let cek = CoseKeyBuilder::new_symmetric_key(cek_data.clone()).build();
///
/// let unprotected = HeaderBuilder::new()
///                             .algorithm(iana::Algorithm::A256KW)
///                             .key_id("example_key".as_bytes().to_vec())
///                             .build();
/// let cose_object = CoseRecipientBuilder::new()
///                     .try_encrypt(
///                         &mut backend,
///                         &kek,
///                         EncryptionContext::EncRecipient,
///                         None,
///                         Some(unprotected),
///                         cek_data.as_slice(),
///                         &[] as &[u8]
///                     )?
///                     .build();
///
/// let decrypted_key = cose_object.try_decrypt(
///                         &mut backend,
///                         &kek,
///                         EncryptionContext::EncRecipient,
///                         &[] as &[u8]
///                     )?;
///
/// assert_eq!(decrypted_key.len(), 1);
/// let parsed_key = CoseSymmetricKey::try_from(decrypted_key.get(0).unwrap())?;
/// assert_eq!(parsed_key.k, cek_data.as_slice());
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
pub trait CoseRecipientExt {
    /// Attempts to decrypt the key contained in this object using a cryptographic backend.
    ///
    /// Returns a `Vec` of potential decryption results for this key.
    /// The reason why a `Vec` is returned here is that if the algorithm is
    /// [`iana::Algorithm::Direct`], the key provider's result will be returned directly, which might
    /// include multiple potential keys for the `key_id` provided in the recipient.
    ///
    /// Note that nested [`CoseRecipient`]s are not considered for key lookup here, the key provider
    /// must provide the key used directly for MAC calculation.
    ///
    /// Usually, you wouldn't decrypt a recipient directly, but instead use
    /// [`super::CoseEncryptExt::try_decrypt_with_recipients`] or
    /// [`super::CoseMacExt::try_verify_with_recipients`] instead, which automatically search through the
    /// respective COSE structures for recipient candidates.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `context`      - Context under which this recipient was encrypted.
    /// - `external_aad` - provider of additional authenticated data that should be authenticated
    ///                    while decrypting (only for AEAD algorithms).
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for decryption, this function will return the most fitting
    /// [`CoseCipherError`] for the specific type of error.
    ///
    /// If additional authenticated data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [`CoseCipherError::AadUnsupported`] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [`CoseCipherError::NoMatchingKeyFound`] will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Refer to the trait-level documentation for an example.
    fn try_decrypt<B: KeyDistributionCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        context: EncryptionContext,
        external_aad: CAP,
    ) -> Result<Vec<CoseKey>, CoseCipherError<B::Error>>;
}

impl CoseRecipientExt for CoseRecipient {
    fn try_decrypt<B: KeyDistributionCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        context: EncryptionContext,
        external_aad: CAP,
    ) -> Result<Vec<CoseKey>, CoseCipherError<B::Error>> {
        let alg = match determine_algorithm::<B::Error>(
            None,
            Some(&self.protected.header),
            Some(&self.unprotected),
        ) {
            Ok(v) => v,
            Err(e) => {
                // A CoseRecipient MUST always have an algorithm set (see RFC 9052,
                // Section 8), which means that this COSE object is malformed.
                return Err(e);
            }
        };

        // Determine key operations that fulfill the requirements of the algorithm.
        let operation = determine_decrypt_key_ops_for_alg(alg)?;

        // Direct => Key of key provider will be used for lower layer directly.
        // TODO ensure that Direct is the only method used on the message (RFC 9052, Section 8.5.1)
        if iana::Algorithm::Direct == alg {
            let mut successful_candidates = Vec::new();
            let mut multi_verification_errors = Vec::new();
            for kc in determine_key_candidates::<CKP, B::Error>(
                key_provider,
                Some(&self.protected.header),
                Some(&self.unprotected),
                operation,
            )
            .map(|kc| kc.map(|(key, _alg)| key))
            {
                match kc {
                    Ok(v) => successful_candidates.push(v),
                    Err(e) => multi_verification_errors.push(e),
                }
            }
            if successful_candidates.is_empty() {
                return Err(CoseCipherError::NoMatchingKeyFound(
                    multi_verification_errors,
                ));
            }
            return Ok(successful_candidates);
        }

        if external_aad
            .lookup_aad(
                Some(context),
                Some(&self.protected.header),
                Some(&self.unprotected),
            )
            .filter(|v| !v.is_empty())
            .is_some()
        {
            return Err(CoseCipherError::AadUnsupported);
        }

        match self.decrypt(context, &[] as &[u8], |ciphertext, _aad| {
            try_cose_crypto_operation(
                key_provider,
                Some(&self.protected.header),
                Some(&self.unprotected),
                operation,
                |key, alg, _protected, _unprotected| {
                    let parsed_key = CoseParsedKey::try_from(key)?;
                    match alg {
                        iana::Algorithm::A128KW
                        | iana::Algorithm::A192KW
                        | iana::Algorithm::A256KW => {
                            let symm_key = ensure_valid_aes_key(alg, parsed_key)?;
                            if !self.protected.is_empty() {
                                return Err(CoseCipherError::AadUnsupported);
                            }
                            // Ignore AAD as this is not an AEAD algorithm, just an AE algorithm.
                            backend.aes_key_unwrap(
                                alg,
                                symm_key,
                                ciphertext,
                                // Fixed IV, see RFC 9053, Section 6.2.1
                                &[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6],
                            )
                        }
                        alg => {
                            // Unsupported algorithm
                            Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                                alg,
                            )))
                        }
                    }
                },
            )
        }) {
            Ok(v) => Ok(vec![CoseKeyBuilder::new_symmetric_key(v).build()]),
            Err(e) => Err(e),
        }
    }
}
