mod encrypt;
mod encrypt0;

use crate::error::CoseCipherError;
use crate::token::cose::header_util::{determine_algorithm, determine_key_candidates};
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, CoseSymmetricKey, KeyParam};
use crate::token::cose::CoseCipher;
use crate::CoseSignCipher;
use alloc::rc::Rc;
use ciborium::Value;
use core::fmt::{Debug, Display};
use coset::{iana, Algorithm, Header, HeaderBuilder, KeyOperation};
use std::cell::RefCell;
use std::collections::BTreeSet;

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
/*
/// Intended for ciphers which can encrypt for multiple recipients.
/// For this purpose, a method must be provided which generates the Content Encryption Key.
///
/// If these recipients each use different key types, you can use an enum to represent them.
pub trait MultipleEncryptCipher: CoseEncryptCipher {
    /// Randomly generates a new Content Encryption Key (CEK) using the given `rng`.
    /// The content of the `CoseEncrypt` will then be encrypted with the key, while each recipient
    /// will be encrypted with a corresponding Key Encryption Key (KEK) provided by the caller
    /// of [`encrypt_access_token_multiple`].
    fn generate_cek<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> CoseKey;
}

pub trait CoseEncrypt0BuilderExt {}

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {}

pub trait CoseEncrypt0Ext {
    fn try_decrypt<B: CoseEncryptCipher>(
        &self,
        backend: &mut B,
        external_aad: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0Ext for CoseEncrypt0 {
    fn try_decrypt<B: CoseEncryptCipher>(
        &self,
        backend: &mut B,
        external_aad: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    }
}

pub trait CoseEncryptBuilderExt {}

impl CoseEncryptBuilderExt for CoseEncryptBuilder {}

pub trait CoseEncryptExt {}

impl CoseEncryptExt for CoseEncrypt {}
*/
pub(crate) fn is_valid_aes_key<'a, BE: Display>(
    algorithm: &Algorithm,
    parsed_key: CoseParsedKey<'a, BE>,
) -> Result<CoseSymmetricKey<'a, BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 4.1 and 4.2.

    // Key type must be symmetric.
    let symm_key = if let CoseParsedKey::Symmetric(symm_key) = parsed_key {
        symm_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            algorithm.clone(),
        ));
    };

    // Algorithm in key must match algorithm to use.
    if let Some(alg) = &symm_key.as_ref().alg {
        if alg != algorithm {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                alg.clone(),
                algorithm.clone(),
            ));
        }
    }

    // For algorithms that we know, check the key length (would lead to a cipher error later on).
    let key_len = match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::A128GCM
            | iana::Algorithm::AES_CCM_16_64_128
            | iana::Algorithm::AES_CCM_64_64_128
            | iana::Algorithm::AES_CCM_16_128_128
            | iana::Algorithm::AES_CCM_64_128_128
            | iana::Algorithm::A128KW,
        ) => Some(16),
        Algorithm::Assigned(iana::Algorithm::A192GCM | iana::Algorithm::A192KW) => Some(24),
        Algorithm::Assigned(
            iana::Algorithm::A256GCM
            | iana::Algorithm::AES_CCM_16_64_256
            | iana::Algorithm::AES_CCM_64_64_256
            | iana::Algorithm::AES_CCM_16_128_256
            | iana::Algorithm::AES_CCM_64_128_256
            | iana::Algorithm::A256KW,
        ) => Some(32),
        _ => None,
    };
    if let Some(key_len) = key_len {
        if symm_key.k.len() != key_len {
            return Err(CoseCipherError::InvalidKeyParam(
                KeyParam::Symmetric(iana::SymmetricKeyParameter::K),
                Value::Bytes(symm_key.k.to_vec()),
            ));
        }
    }

    Ok(symm_key)
}

fn try_encrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    try_all_keys: bool,
    plaintext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    let key = determine_key_candidates(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Encrypt)]),
        try_all_keys,
    )?
    .into_iter()
    .next()
    .ok_or(CoseCipherError::NoKeyFound)?;
    let parsed_key = CoseParsedKey::try_from(&key)?;
    let algorithm = determine_algorithm(Some(&parsed_key), protected, unprotected)?;

    match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
        ) => {
            // Check if this is a valid AES key.
            let symm_key = is_valid_aes_key::<B::Error>(&algorithm, parsed_key)?;

            let iv = if protected.is_some() && !protected.unwrap().iv.is_empty() {
                protected.unwrap().iv.as_ref()
            } else if unprotected.is_some() && !unprotected.unwrap().iv.is_empty() {
                unprotected.unwrap().iv.as_ref()
            } else {
                return Err(CoseCipherError::IvRequired);
            };

            backend.encrypt_aes_gcm(algorithm, symm_key, plaintext, aad, iv)
        }
        v @ (Algorithm::Assigned(_)) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
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
    let algorithm = determine_algorithm(Some(&key), Some(protected), Some(unprotected))?;

    match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
        ) => {
            // Check if this is a valid AES key.
            let symm_key = is_valid_aes_key::<B::Error>(&algorithm, key)?;

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
        v @ (Algorithm::Assigned(_)) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    }
}

pub(crate) fn try_decrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider>(
    backend: Rc<RefCell<&mut B>>,
    key_provider: Rc<RefCell<&mut CKP>>,
    protected: &Header,
    unprotected: &Header,
    try_all_keys: bool,
    ciphertext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    for key in determine_key_candidates(
        *key_provider.borrow_mut(),
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Decrypt)]),
        try_all_keys,
    )? {
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
