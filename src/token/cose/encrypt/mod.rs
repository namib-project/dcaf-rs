use alloc::collections::BTreeSet;
use alloc::rc::Rc;
use core::cell::RefCell;
use core::fmt::Display;

use coset::{iana, Algorithm, Header, HeaderBuilder, KeyOperation};

use crate::error::CoseCipherError;
use crate::token::cose::header_util::{
    check_for_duplicate_headers, determine_algorithm, determine_key_candidates,
};
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, CoseSymmetricKey};
use crate::token::cose::{key, CoseCipher};

mod encrypt;
mod encrypt0;

pub use encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
pub use encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};

/// Provides basic operations for encrypting and decrypting COSE structures.
///
/// This will be used by [`encrypt_access_token`] and [`decrypt_access_token`] (as well as the
/// variants for multiple recipients: [`encrypt_access_token_multiple`]
/// and [`decrypt_access_token_multiple`]) to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// The [`set_headers` method](CoseCipher::set_headers) can be used to set parameters this
/// cipher requires to be set.
pub trait CoseEncryptCipher: CoseCipher {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

pub trait CoseKeyDistributionCipher: CoseCipher {
    fn aes_key_wrap(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn aes_key_unwrap(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

pub trait HeaderBuilderExt: Sized {
    fn gen_iv<B: CoseEncryptCipher>(
        self,
        backend: &mut B,
        alg: &Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl HeaderBuilderExt for HeaderBuilder {
    fn gen_iv<B: CoseCipher>(
        self,
        backend: &mut B,
        alg: &Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let iv_size = match alg {
            // AES-GCM: Nonce is fixed at 96 bits
            Algorithm::Assigned(
                iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
            ) => 12,
            v => return Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        };
        let mut iv = vec![0; iv_size];
        backend.generate_rand(&mut iv)?;
        Ok(self.iv(iv))
    }
}

fn try_encrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    try_all_keys: bool,
    plaintext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    if let (Some(protected), Some(unprotected)) = (protected, unprotected) {
        check_for_duplicate_headers(protected, unprotected)?;
    }
    let key = determine_key_candidates::<B::Error, CKP>(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Encrypt)]),
        try_all_keys,
    )
    .next()
    .ok_or(CoseCipherError::NoKeyFound)?;
    let parsed_key = CoseParsedKey::try_from(&key)?;
    let algorithm = determine_algorithm(Some(&parsed_key), protected, unprotected)?;

    match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
        ) => {
            // Check if this is a valid AES key.
            let symm_key = key::is_valid_aes_key::<B::Error>(&algorithm, parsed_key)?;

            let iv = if protected.is_some() && !protected.unwrap().iv.is_empty() {
                protected.unwrap().iv.as_ref()
            } else if unprotected.is_some() && !unprotected.unwrap().iv.is_empty() {
                unprotected.unwrap().iv.as_ref()
            } else {
                return Err(CoseCipherError::IvRequired);
            };

            backend.encrypt_aes_gcm(algorithm, symm_key, plaintext, aad, iv)
        }
        v @ Algorithm::Assigned(_) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    }
}

fn try_decrypt_with_key<B: CoseEncryptCipher>(
    backend: &mut B,
    key: CoseParsedKey<B::Error>,
    protected: &Header,
    unprotected: &Header,
    ciphertext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    check_for_duplicate_headers(protected, unprotected)?;
    let algorithm = determine_algorithm(Some(&key), Some(protected), Some(unprotected))?;

    match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
        ) => {
            // Check if this is a valid AES key.
            let symm_key = key::is_valid_aes_key::<B::Error>(&algorithm, key)?;

            let iv = if !protected.iv.is_empty() {
                protected.iv.as_ref()
            } else if !unprotected.iv.is_empty() {
                unprotected.iv.as_ref()
            } else {
                return Err(CoseCipherError::IvRequired);
            };

            // Authentication tag is 16 bytes long and should be included in the ciphertext.
            if ciphertext.len() < 16 {
                return Err(CoseCipherError::VerificationFailure);
            }

            backend.decrypt_aes_gcm(algorithm, symm_key, ciphertext, aad, iv)
        }
        v @ Algorithm::Assigned(_) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    }
}

pub(crate) fn try_decrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &Rc<RefCell<&mut CKP>>,
    protected: &Header,
    unprotected: &Header,
    try_all_keys: bool,
    ciphertext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    check_for_duplicate_headers(protected, unprotected)?;
    for key in determine_key_candidates::<B::Error, CKP>(
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
            aad,
        ) {
            Ok(v) => return Ok(v),
            Err(e) => {
                dbg!(e);
            }
        }
    }

    Err(CoseCipherError::NoKeyFound)
}
