use alloc::collections::BTreeSet;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use coset::{iana, Algorithm, Header, KeyOperation};

use crate::error::CoseCipherError;
use crate::token::cose::header_util::{
    check_for_duplicate_headers, determine_algorithm, determine_key_candidates, HeaderParam,
};
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, CoseSymmetricKey};
use crate::token::cose::{key, CoseCipher};

mod encrypt;
mod encrypt0;

pub use encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
pub use encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};

pub trait CoseEncryptCipher: CoseCipher {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

pub trait CoseKeyDistributionCipher: CoseCipher {
    fn aes_key_wrap(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn aes_key_unwrap(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

fn try_encrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    try_all_keys: bool,
    plaintext: &[u8],
    // NOTE: this should be treated as the AAD for the purposes of the cryptographic backend
    // (RFC 9052, Section 5.3).
    enc_structure: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    if let (Some(protected), Some(unprotected)) = (protected, unprotected) {
        check_for_duplicate_headers(protected, unprotected)?;
    }
    let key = determine_key_candidates::<CKP>(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Encrypt)]),
        try_all_keys,
    )
    .next()
    .ok_or(CoseCipherError::NoMatchingKeyFound(Vec::new()))?;
    let parsed_key = CoseParsedKey::try_from(&key)?;

    match determine_algorithm(Some(&parsed_key), protected, unprotected)? {
        alg @ (iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM) => {
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
}

fn try_decrypt_with_key<B: CoseEncryptCipher>(
    backend: &mut B,
    key: CoseParsedKey<B::Error>,
    protected: &Header,
    unprotected: &Header,
    ciphertext: &[u8],
    // NOTE: this should be treated as the AAD for the purposes of the cryptographic backend
    // (RFC 9052, Section 5.3).
    enc_structure: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    check_for_duplicate_headers(protected, unprotected)?;

    match determine_algorithm(Some(&key), Some(protected), Some(unprotected))? {
        alg @ (iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM) => {
            // Check if this is a valid AES key.
            let symm_key = key::ensure_valid_aes_key::<B::Error>(alg, key)?;

            let iv = core::iter::once(protected)
                .chain(core::iter::once(unprotected))
                .filter(|x| !x.iv.is_empty())
                .map(|x| x.iv.as_ref())
                .next()
                .ok_or(CoseCipherError::MissingHeaderParam(HeaderParam::Generic(
                    iana::HeaderParameter::Iv,
                )))?;

            // Authentication tag is 16 bytes long and should be included in the ciphertext.
            if ciphertext.len() < 16 {
                return Err(CoseCipherError::VerificationFailure);
            }

            backend.decrypt_aes_gcm(alg, symm_key, ciphertext, enc_structure, iv)
        }
        alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            alg,
        ))),
    }
}

pub(crate) fn try_decrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &Rc<RefCell<&mut CKP>>,
    protected: &Header,
    unprotected: &Header,
    try_all_keys: bool,
    ciphertext: &[u8],
    // NOTE: this should be treated as the AAD for the purposes of the cryptographic backend
    // (RFC 9052, Section 5.3).
    enc_structure: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    check_for_duplicate_headers(protected, unprotected)?;
    let mut multi_verification_errors = Vec::new();
    for key in determine_key_candidates::<CKP>(
        *key_provider.borrow_mut(),
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Decrypt)]),
        try_all_keys,
    ) {
        match try_decrypt_with_key(
            *backend.borrow_mut(),
            CoseParsedKey::try_from(&key)?,
            protected,
            unprotected,
            ciphertext,
            enc_structure,
        ) {
            Ok(v) => return Ok(v),
            Err(e) => {
                multi_verification_errors.push((key.clone(), e));
                continue;
            }
        }
    }

    Err(CoseCipherError::NoMatchingKeyFound(
        multi_verification_errors,
    ))
}
