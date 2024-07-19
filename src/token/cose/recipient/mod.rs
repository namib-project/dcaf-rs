use alloc::boxed::Box;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cell::RefCell;
use core::fmt::Display;
use coset::{
    iana, Algorithm, CoseKey, CoseKeyBuilder, CoseRecipient, CoseRecipientBuilder,
    EncryptionContext, Header, KeyOperation,
};

use crate::error::CoseCipherError;
use crate::token::cose::encrypted::CoseKeyDistributionCipher;
use crate::token::cose::header_util::{determine_algorithm, determine_key_candidates};
use crate::token::cose::key::ensure_valid_aes_key;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider, CoseParsedKey};
use crate::token::cose::{try_cose_crypto_operation, InvertedAadProvider};

pub(crate) struct CoseNestedRecipientSearchContext<
    'a,
    B: CoseKeyDistributionCipher,
    CKP: CoseKeyProvider,
    AAD: CoseAadProvider,
> {
    recipient_iter: &'a Vec<CoseRecipient>,
    backend: Rc<RefCell<&'a mut B>>,
    key_provider: &'a CKP,
    aad_provider: Rc<InvertedAadProvider<AAD>>,
    context: EncryptionContext,
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, AAD: CoseAadProvider>
    CoseNestedRecipientSearchContext<'a, B, CKP, AAD>
{
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
        }
    }
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, AAD: CoseAadProvider> CoseKeyProvider
    for CoseNestedRecipientSearchContext<'a, B, CKP, AAD>
{
    fn lookup_key(&self, key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        let mut iter: Box<dyn Iterator<Item = CoseKey>> = Box::new(CoseNestedRecipientIterator {
            iteration_state: vec![self.recipient_iter.iter()],
            recipient_stack: vec![],
            backend: Rc::clone(&self.backend),
            key_provider: self.key_provider,
            aad_provider: Rc::clone(&self.aad_provider),
            current_key_candidates: VecDeque::default(),
            current_candidates_position: 0,
            last_error: None,
            context: self.context,
        });
        if let Some(kid) = key_id {
            let kid = Vec::from(kid);
            iter = Box::new(iter.filter(move |k| k.key_id == kid));
        }
        iter
    }
}

struct CoseNestedRecipientIterator<
    'a,
    B: CoseKeyDistributionCipher,
    CKP: CoseKeyProvider,
    AAD: CoseAadProvider,
> {
    iteration_state: Vec<alloc::slice::Iter<'a, CoseRecipient>>,
    recipient_stack: Vec<&'a CoseRecipient>,
    backend: Rc<RefCell<&'a mut B>>,
    key_provider: &'a CKP,
    aad_provider: Rc<InvertedAadProvider<AAD>>,
    current_key_candidates: VecDeque<CoseKey>,
    current_candidates_position: usize,
    last_error: Option<CoseCipherError<B::Error>>,
    context: EncryptionContext,
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, AAD: CoseAadProvider> Iterator
    for CoseNestedRecipientIterator<'a, B, CKP, AAD>
{
    type Item = CoseKey;

    fn next(&mut self) -> Option<Self::Item> {
        // This iterator yields the next possible CEK candidate from a nested CoseRecipient
        // structure.

        // The following algorithm is an iterative implementation of a depth-first search for a
        // decryptable CoseRecipient, i.e. a recipient for which our key provider has a possible key
        // candidate.

        if !self.current_key_candidates.is_empty() {
            if let Some(key) = self.current_key_candidates.pop_front() {
                return Some(key);
            }
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
                        self.last_error = Some(e);
                        continue;
                    }
                }
            }
            // Recipients has itself recipients, which means that the key for this recipient is
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

pub(crate) fn struct_to_recipient_context(ctx: EncryptionContext) -> EncryptionContext {
    match ctx {
        EncryptionContext::CoseEncrypt => EncryptionContext::EncRecipient,
        EncryptionContext::CoseEncrypt0 => panic!("attempted to obtain recipient context for a CoseEncrypt0 object (which can't contain CoseRecipients)"),
        EncryptionContext::EncRecipient | EncryptionContext::MacRecipient | EncryptionContext::RecRecipient => EncryptionContext::RecRecipient,
    }
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, AAD: CoseAadProvider>
    CoseNestedRecipientIterator<'a, B, CKP, AAD>
{
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

fn determine_encrypt_key_ops_for_alg<CE: Display>(
    alg: iana::Algorithm,
) -> Result<BTreeSet<KeyOperation>, CoseCipherError<CE>> {
    Ok(BTreeSet::from_iter(match alg {
        iana::Algorithm::Direct => {
            // TODO maybe needs to be all operations instead
            vec![]
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

pub trait CoseRecipientBuilderExt: Sized {
    /// Attempts to encrypt the provided payload/key using a cryptographic backend.
    ///
    /// Note that you still have to ensure that the key is available to the recipient somehow, i.e.
    /// by adding nested [CoseRecipient] structures where suitable.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `context`      - Context under which this recipient was encrypted.
    /// - `protected`    - protected headers for the resulting [CoseEncrypt] instance. Will override
    ///                    headers previously set using [CoseEncryptBuilder::protected].
    /// - `unprotected`  - unprotected headers for the resulting [CoseEncrypt] instance. Will
    ///                    override headers previously set using [CoseEncryptBuilder::unprotected].
    /// - `payload`      - payload which should be added to the resulting [CoseMac0] instance and
    ///                    for which the MAC should be calculated. Will override a payload
    ///                    previously set using [CoseEncryptBuilder::payload].
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for MAC calculation, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
    ///
    /// If Additional Authenticated Data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [CoseCipherError::AadUnsupported] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but the key provider does not provide a key, a
    /// [CoseCipherError::NoMatchingKeyFound] error will be returned.
    ///
    /// # Examples
    ///
    /// TODO
    fn try_encrypt<
        B: CoseKeyDistributionCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
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
    fn try_encrypt<
        B: CoseKeyDistributionCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
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

        // TODO return an error if IV is set in headers?

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

pub trait CoseRecipientExt {
    /// Attempts to decrypt the key contained in this object using a cryptographic backend.
    ///
    /// Note that nested [CoseRecipient]s are not considered for key lookup here, the key provider
    /// must provide the key used directly for MAC calculation.
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
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for decryption, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
    ///
    /// If Additional Authenticated Data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [CoseCipherError::AadUnsupported] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [CoseCipherError::NoMatchingKeyFound] error will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// TODO
    fn try_decrypt<
        B: CoseKeyDistributionCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        context: EncryptionContext,
        external_aad: CAP,
    ) -> Result<Vec<CoseKey>, CoseCipherError<B::Error>>;
}

impl CoseRecipientExt for CoseRecipient {
    fn try_decrypt<
        B: CoseKeyDistributionCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
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
                // TODO in theory, we could proceed here by skipping over this recipient,
                //      but I'm not sure if we should continue parsing a
                //      non-standard-compliant object...
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

        match self.decrypt(
            context,
            external_aad
                .lookup_aad(
                    Some(context),
                    Some(&self.protected.header),
                    Some(&self.unprotected),
                )
                .unwrap_or(&[] as &[u8]),
            |ciphertext, _aad| {
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
            },
        ) {
            Ok(v) => Ok(vec![CoseKeyBuilder::new_symmetric_key(v).build()]),
            Err(e) => Err(e),
        }
    }
}
