use alloc::collections::BTreeSet;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use coset::{iana, Algorithm, Header, KeyOperation};

use crate::error::CoseCipherError;
use crate::token::cose::header_util::HeaderParam;
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, CoseSymmetricKey};
use crate::token::cose::{header_util, key, CoseCipher};

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

pub(crate) fn try_decrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider>(
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
                    if ciphertext.len() < 16 {
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
