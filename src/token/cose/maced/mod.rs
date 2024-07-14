use alloc::collections::BTreeSet;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Display;

use ciborium::Value;
use coset::{iana, Algorithm, Header, KeyOperation};

pub use mac::{CoseMacBuilderExt, CoseMacExt};
pub use mac0::{CoseMac0BuilderExt, CoseMac0Ext};

use crate::error::CoseCipherError;
use crate::token::cose::header_util::{
    check_for_duplicate_headers, determine_algorithm, determine_key_candidates,
};
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, CoseSymmetricKey, KeyParam};
use crate::token::cose::CoseCipher;

/// Provides basic operations for generating and verifying MAC tags for COSE structures.
///
/// This trait is currently not used by any access token function.
pub trait CoseMacCipher: CoseCipher {
    fn compute_hmac(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        input: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn verify_hmac(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

mod mac;
mod mac0;

pub(crate) fn is_valid_hmac_key<'a, BE: Display>(
    algorithm: &Algorithm,
    parsed_key: CoseParsedKey<'a, BE>,
) -> Result<CoseSymmetricKey<'a, BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 3.1.

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
        Algorithm::Assigned(iana::Algorithm::HMAC_256_256 | iana::Algorithm::HMAC_256_64) => {
            Some(32)
        }
        Algorithm::Assigned(iana::Algorithm::HMAC_384_384) => Some(48),
        Algorithm::Assigned(iana::Algorithm::HMAC_512_512) => Some(64),
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

fn try_compute<B: CoseMacCipher, CKP: CoseKeyProvider>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    try_all_keys: bool,
    input: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    if let (Some(protected), Some(unprotected)) = (protected, unprotected) {
        check_for_duplicate_headers(protected, unprotected)?;
    }
    let key = determine_key_candidates::<CKP>(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacCreate)]),
        try_all_keys,
    )
    .next()
    .ok_or(CoseCipherError::NoKeyFound)?;
    let parsed_key = CoseParsedKey::try_from(&key)?;
    let algorithm = determine_algorithm(Some(&parsed_key), protected, unprotected)?;

    match algorithm {
        Algorithm::Assigned(iana::Algorithm::HMAC_256_256) => {
            let symm_key = is_valid_hmac_key(&algorithm, parsed_key)?;
            backend.compute_hmac(algorithm, symm_key, input)
        }
        v @ Algorithm::Assigned(_) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    }
}

fn try_verify_with_key<B: CoseMacCipher>(
    backend: &mut B,
    key: CoseParsedKey<B::Error>,
    protected: &Header,
    unprotected: &Header,
    tag: &[u8],
    data: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    check_for_duplicate_headers(protected, unprotected)?;
    let algorithm = determine_algorithm(Some(&key), Some(protected), Some(unprotected))?;

    match algorithm {
        Algorithm::Assigned(iana::Algorithm::HMAC_256_256) => {
            let symm_key = is_valid_hmac_key(&algorithm, key)?;
            backend.verify_hmac(algorithm, symm_key, tag, data)
        }
        v @ Algorithm::Assigned(_) => Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    }
}

pub(crate) fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &Rc<RefCell<&mut CKP>>,
    protected: &Header,
    unprotected: &Header,
    try_all_keys: bool,
    tag: &[u8],
    data: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    check_for_duplicate_headers(protected, unprotected)?;
    for key in determine_key_candidates::<CKP>(
        *key_provider.borrow_mut(),
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::Decrypt)]),
        try_all_keys,
    ) {
        match try_verify_with_key(
            *backend.borrow_mut(),
            CoseParsedKey::try_from(&key)?,
            protected,
            unprotected,
            tag,
            data,
        ) {
            Ok(v) => return Ok(v),
            Err(_e) => {
                // TODO better output here
                continue;
            }
        }
    }

    Err(CoseCipherError::NoKeyFound)
}
