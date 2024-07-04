use crate::error::CoseCipherError;
use crate::token::cose::encrypt::is_valid_aes_key;
use crate::token::cose::encrypt::CoseKeyDistributionCipher;
use crate::token::cose::header_util::{determine_algorithm, determine_key_candidates, HeaderParam};
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider, CoseParsedKey};
use alloc::rc::Rc;
use core::fmt::Display;
use coset::{
    iana, Algorithm, CoseKey, CoseKeyBuilder, CoseRecipient, CoseRecipientBuilder,
    EncryptionContext, Header, KeyOperation,
};
use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::marker::PhantomData;

pub(crate) struct CoseNestedRecipientSearchContext<
    'a,
    B: CoseKeyDistributionCipher,
    CKP: CoseKeyProvider,
> {
    recipient_iter: &'a Vec<CoseRecipient>,
    backend: Rc<RefCell<&'a mut B>>,
    key_provider: Rc<RefCell<&'a mut CKP>>,
    try_all_keys: bool,
    context: EncryptionContext,
    _key_lifetime_marker: PhantomData<&'a CKP>,
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider>
    CoseNestedRecipientSearchContext<'a, B, CKP>
{
    pub(crate) fn new(
        recipient_iter: &'a Vec<CoseRecipient>,
        backend: Rc<RefCell<&'a mut B>>,
        key_provider: Rc<RefCell<&'a mut CKP>>,
        try_all_keys: bool,
        context: EncryptionContext,
    ) -> CoseNestedRecipientSearchContext<'a, B, CKP> {
        CoseNestedRecipientSearchContext {
            recipient_iter,
            backend,
            key_provider,
            try_all_keys,
            context,
            _key_lifetime_marker: Default::default(),
        }
    }
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider> CoseKeyProvider
    for CoseNestedRecipientSearchContext<'a, B, CKP>
{
    fn lookup_key(&mut self, key_id: Option<&[u8]>) -> impl Iterator<Item = CoseKey> + 'a {
        let mut iter: Box<dyn Iterator<Item = CoseKey>> = Box::new(CoseNestedRecipientIterator {
            iteration_state: vec![self.recipient_iter.iter()],
            recipient_stack: vec![],
            backend: Rc::clone(&self.backend),
            key_provider: Rc::clone(&self.key_provider),
            try_all_keys: self.try_all_keys,
            current_key_candidates: Default::default(),
            current_candidates_position: 0,
            last_error: None,
            context: self.context,
        });
        if let Some(kid) = key_id {
            let kid = Vec::from(kid);
            iter = Box::new(iter.filter(move |k| k.key_id == kid))
        }
        iter
    }
}

struct CoseNestedRecipientIterator<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider> {
    iteration_state: Vec<alloc::slice::Iter<'a, CoseRecipient>>,
    recipient_stack: Vec<&'a CoseRecipient>,
    backend: Rc<RefCell<&'a mut B>>,
    key_provider: Rc<RefCell<&'a mut CKP>>,
    try_all_keys: bool,
    current_key_candidates: VecDeque<CoseKey>,
    current_candidates_position: usize,
    last_error: Option<CoseCipherError<B::Error>>,
    context: EncryptionContext,
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider> Iterator
    for CoseNestedRecipientIterator<'a, B, CKP>
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
                    self.recipient_stack
                        .truncate(self.recipient_stack.len() - 1);
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
                        if v.len() > 0 {
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
            } else {
                // Recipients has itself recipients, which means that the key for this recipient is
                // itself encrypted in its own recipient structures.
                // Proceed search with nested recipients.
                self.iteration_state.push(next_recipient.recipients.iter());
                self.recipient_stack.push(next_recipient);
            }
        }

        // We ran out of recipients to consider, i.e. we have completed the DFS and still haven't
        // found a candidate.
        None
    }
}

impl<'a, B: CoseKeyDistributionCipher, CKP: CoseKeyProvider>
    CoseNestedRecipientIterator<'a, B, CKP>
{
    fn attempt_to_decrypt_nested(
        &mut self,
        leaf_recipient: &CoseRecipient,
    ) -> Result<VecDeque<CoseKey>, CoseCipherError<B::Error>> {
        // Attempt to decrypt leaf node, return (non-search-terminating) error if that doesn't work.
        let mut current_keys: Vec<CoseKey> = leaf_recipient.try_decrypt(
            *self.backend.borrow_mut(),
            *self.key_provider.borrow_mut(),
            self.try_all_keys,
            self.context,
            &mut (&[] as &[u8]),
        )?;

        for recipient in self.recipient_stack.iter().map(|v| *v).rev() {
            match recipient.try_decrypt(
                *self.backend.borrow_mut(),
                *self.key_provider.borrow_mut(),
                // Use all keys in current_keys for intermediates.
                true,
                self.context,
                &mut (&[] as &[u8]),
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
    alg: &Algorithm,
) -> Result<BTreeSet<KeyOperation>, CoseCipherError<CE>> {
    Ok(BTreeSet::from_iter(match alg {
        Algorithm::Assigned(iana::Algorithm::Direct) => {
            // TODO maybe needs to be all operations instead
            vec![]
        }
        Algorithm::Assigned(
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
            | iana::Algorithm::ECDH_SS_A256KW,
        ) => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::DeriveKey),
                KeyOperation::Assigned(iana::KeyOperation::DeriveBits),
            ]
        }
        Algorithm::Assigned(
            iana::Algorithm::A128KW | iana::Algorithm::A192KW | iana::Algorithm::A256KW,
        ) => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::Encrypt),
                KeyOperation::Assigned(iana::KeyOperation::WrapKey),
            ]
        }
        v @ Algorithm::Assigned(_) => {
            // Unsupported algorithm - skip over this recipient.
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
        }
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            // Unsupported algorithm - skip over this recipient.
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
        }
    }))
}

fn determine_decrypt_key_ops_for_alg<CE: Display>(
    alg: &Algorithm,
) -> Result<BTreeSet<KeyOperation>, CoseCipherError<CE>> {
    Ok(BTreeSet::from_iter(match alg {
        Algorithm::Assigned(iana::Algorithm::Direct) => {
            // TODO maybe needs to be all operations instead
            vec![]
        }
        Algorithm::Assigned(
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
            | iana::Algorithm::ECDH_SS_A256KW,
        ) => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::DeriveKey),
                KeyOperation::Assigned(iana::KeyOperation::DeriveBits),
            ]
        }
        Algorithm::Assigned(
            iana::Algorithm::A128KW | iana::Algorithm::A192KW | iana::Algorithm::A256KW,
        ) => {
            vec![
                KeyOperation::Assigned(iana::KeyOperation::Decrypt),
                KeyOperation::Assigned(iana::KeyOperation::UnwrapKey),
            ]
        }
        v @ Algorithm::Assigned(_) => {
            // Unsupported algorithm - skip over this recipient.
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
        }
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            // Unsupported algorithm - skip over this recipient.
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
        }
    }))
}

pub trait CoseRecipientBuilderExt: Sized {
    fn try_encrypt<B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        context: EncryptionContext,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseRecipientBuilderExt for CoseRecipientBuilder {
    fn try_encrypt<B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        context: EncryptionContext,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let alg =
            match determine_algorithm::<B::Error>(None, unprotected.as_ref(), protected.as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    // A CoseRecipient MUST always have an algorithm set (see RFC 9052,
                    // Section 8), which means that this COSE object is malformed.
                    return Err(e);
                }
            };

        // Determine key operations that fulfill the requirements of the algorithm.
        let operation = determine_decrypt_key_ops_for_alg(&alg)?;

        let key = determine_key_candidates(
            key_provider,
            protected.as_ref(),
            unprotected.as_ref(),
            operation,
            try_all_keys,
        )?
        .into_iter()
        .next()
        .ok_or(CoseCipherError::NoKeyFound)?;
        let parsed_key = CoseParsedKey::try_from(&key)?;

        // Direct => Key of will be used for lower layer directly, must not contain ciphertext.
        if let Algorithm::Assigned(iana::Algorithm::Direct) = alg {
            return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                iana::Algorithm::Direct,
            )));
        }

        match alg {
            Algorithm::Assigned(
                iana::Algorithm::A128KW | iana::Algorithm::A192KW | iana::Algorithm::A256KW,
            ) => {
                let symm_key = is_valid_aes_key(&alg, parsed_key)?;

                self.try_create_ciphertext(
                    context,
                    plaintext,
                    external_aad.lookup_aad(protected.as_ref(), unprotected.as_ref()),
                    |plaintext, aad| {
                        if !aad.is_empty() {
                            return Err(CoseCipherError::AadUnsupported);
                        }

                        backend.encrypt_aes_single_block(
                            alg.clone(),
                            symm_key,
                            plaintext,
                            // Fixed IV, see RFC 9053, Section 6.2.1
                            &[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6],
                        )
                    },
                )
            }
            v @ Algorithm::Assigned(_) => {
                // Unsupported algorithm - skip over this recipient.
                return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
            }
            v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
                // Unsupported algorithm - skip over this recipient.
                return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
            }
        }
    }
}

pub trait CoseRecipientExt {
    fn try_decrypt<B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        context: EncryptionContext,
        external_aad: &mut CAP,
    ) -> Result<Vec<CoseKey>, CoseCipherError<B::Error>>;
}

impl CoseRecipientExt for CoseRecipient {
    fn try_decrypt<B: CoseKeyDistributionCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        context: EncryptionContext,
        external_aad: &mut CAP,
    ) -> Result<Vec<CoseKey>, CoseCipherError<B::Error>> {
        let alg = match determine_algorithm::<B::Error>(
            None,
            Some(&self.unprotected),
            Some(&self.protected.header),
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
        let operation = determine_decrypt_key_ops_for_alg(&alg)?;

        let key_candidates: Vec<CoseKey> = determine_key_candidates::<B::Error, CKP>(
            key_provider,
            Some(&self.protected.header),
            Some(&self.unprotected),
            operation,
            try_all_keys,
        )
        .map(|v| v.into_iter().map(|v| v).collect())?;

        // Direct => Key of key provider will be used for lower layer directly.
        if let Algorithm::Assigned(iana::Algorithm::Direct) = alg {
            return Ok(key_candidates);
        }

        for key in key_candidates {
            let parsed_key = CoseParsedKey::try_from(&key)?;
            match alg {
                Algorithm::Assigned(
                    iana::Algorithm::A128KW | iana::Algorithm::A192KW | iana::Algorithm::A256KW,
                ) => {
                    let symm_key = match is_valid_aes_key(&alg, parsed_key) {
                        Ok(v) => v,
                        Err(_e) => {
                            // Key is not an AES key, skip.
                            continue;
                        }
                    };
                    match self.decrypt(
                        context,
                        external_aad
                            .lookup_aad(Some(&self.protected.header), Some(&self.unprotected)),
                        |ciphertext, aad| {
                            if !aad.is_empty() {
                                return Err(CoseCipherError::AadUnsupported);
                            }
                            backend.decrypt_aes_single_block(
                                alg.clone(),
                                symm_key,
                                ciphertext,
                                // Fixed IV, see RFC 9053, Section 6.2.1
                                &[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6],
                            )
                        },
                    ) {
                        Ok(v) => return Ok(vec![CoseKeyBuilder::new_symmetric_key(v).build()]),
                        Err(_e) => {
                            // Decryption using key failed, skip.
                            continue;
                        }
                    };
                }
                v @ Algorithm::Assigned(_) => {
                    // Unsupported algorithm - skip over this recipient.
                    return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
                }
                v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
                    // Unsupported algorithm - skip over this recipient.
                    return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()));
                }
            }
        }

        Err(CoseCipherError::NoKeyFound)
    }
}
