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
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, CoseSymmetricKey, KeyParam};
use crate::token::cose::{header_util, CoseCipher};

pub trait CoseMacCipher: CoseCipher {
    fn compute_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        input: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn verify_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

mod mac;
mod mac0;

pub(crate) fn is_valid_hmac_key<BE: Display>(
    algorithm: iana::Algorithm,
    parsed_key: CoseParsedKey<BE>,
) -> Result<CoseSymmetricKey<BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 3.1.

    // Key type must be symmetric.
    let symm_key = if let CoseParsedKey::Symmetric(symm_key) = parsed_key {
        symm_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            Algorithm::Assigned(algorithm),
        ));
    };

    // Algorithm in key must match algorithm to use.
    if let Some(key_alg) = &symm_key.as_ref().alg {
        if key_alg != &Algorithm::Assigned(algorithm) {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                key_alg.clone(),
                Algorithm::Assigned(algorithm),
            ));
        }
    }

    // For algorithms that we know, check the key length (would lead to a cipher error later on).
    let key_len = match algorithm {
        iana::Algorithm::HMAC_256_256 | iana::Algorithm::HMAC_256_64 => Some(32),
        iana::Algorithm::HMAC_384_384 => Some(48),
        iana::Algorithm::HMAC_512_512 => Some(64),
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
    key_provider: &CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    input: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    header_util::try_cose_crypto_operation(
        key_provider,
        protected,
        unprotected,
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacCreate)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;

            match alg {
                iana::Algorithm::HMAC_256_256 => {
                    let symm_key = is_valid_hmac_key(alg, parsed_key)?;
                    backend.compute_hmac(alg, symm_key, input)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}

pub(crate) fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider>(
    backend: &Rc<RefCell<&mut B>>,
    key_provider: &CKP,
    protected: &Header,
    unprotected: &Header,
    tag: &[u8],
    data: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    header_util::try_cose_crypto_operation(
        key_provider,
        Some(protected),
        Some(unprotected),
        BTreeSet::from_iter(vec![KeyOperation::Assigned(iana::KeyOperation::MacVerify)]),
        |key, alg, _protected, _unprotected| {
            let parsed_key = CoseParsedKey::try_from(key)?;

            match alg {
                iana::Algorithm::HMAC_256_256 => {
                    let symm_key = is_valid_hmac_key(alg, parsed_key)?;
                    (*backend.borrow_mut()).verify_hmac(alg, symm_key, tag, data)
                }
                alg => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    alg,
                ))),
            }
        },
    )
}
