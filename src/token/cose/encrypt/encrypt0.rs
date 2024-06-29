use crate::error::CoseCipherError;
use crate::token::cose::encrypt::CoseEncryptCipher;
use crate::token::cose::header_util::{
    determine_algorithm, determine_key_candidates, find_param_by_label,
};
use crate::token::cose::key::{
    CoseAadProvider, CoseEc2Key, CoseKeyProvider, CoseParsedKey, CoseSymmetricKey, KeyParam,
};
use ciborium::Value;
use core::fmt::Display;
use coset::{iana, Algorithm, CoseEncrypt0, CoseEncrypt0Builder, Header, KeyOperation};

pub trait CoseEncrypt0BuilderExt {}

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {}

pub trait CoseEncrypt0Ext {
    fn try_decrypt<
        'a,
        'b,
        B: CoseEncryptCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

fn is_valid_aes_key<'a, BE: Display>(
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
            | iana::Algorithm::AES_CCM_64_128_128,
        ) => Some(16),
        Algorithm::Assigned(iana::Algorithm::A192GCM) => Some(24),
        Algorithm::Assigned(
            iana::Algorithm::A256GCM
            | iana::Algorithm::AES_CCM_16_64_256
            | iana::Algorithm::AES_CCM_64_64_256
            | iana::Algorithm::AES_CCM_16_128_256
            | iana::Algorithm::AES_CCM_64_128_256,
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

fn try_encrypt_single<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider<'a>>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: &Header,
    unprotected: &Header,
    try_all_keys: bool,
    plaintext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    let parsed_key = determine_key_candidates(
        key_provider,
        Some(protected),
        Some(unprotected),
        &KeyOperation::Assigned(iana::KeyOperation::Sign),
        false,
    )?
    .into_iter()
    .next()
    .ok_or(CoseCipherError::NoKeyFound)?;
    let algorithm = determine_algorithm(&parsed_key, Some(protected), Some(unprotected))?;

    match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
        ) => {
            // Check if this is a valid AES key.
            let symm_key = is_valid_aes_key::<B::Error>(&algorithm, parsed_key)?;

            let iv = if !protected.iv.is_empty() {
                protected.iv.as_ref()
            } else if !unprotected.iv.is_empty() {
                unprotected.iv.as_ref()
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
    let algorithm = determine_algorithm(&key, Some(protected), Some(unprotected))?;

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

fn try_decrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider<'a>>(
    backend: &mut B,
    key_provider: &mut CKP,
    protected: &Header,
    unprotected: &Header,
    try_all_keys: bool,
    ciphertext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    for key in determine_key_candidates(
        key_provider,
        Some(protected),
        Some(unprotected),
        &KeyOperation::Assigned(iana::KeyOperation::Decrypt),
        try_all_keys,
    )? {
        match try_decrypt_with_key(backend, key, protected, unprotected, ciphertext, aad) {
            Ok(v) => return Ok(v),
            Err(e) => {
                dbg!(e);
            }
        }
    }

    Err(CoseCipherError::NoKeyFound)
}

impl CoseEncrypt0Ext for CoseEncrypt0 {
    fn try_decrypt<
        'a,
        'b,
        B: CoseEncryptCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
        self.decrypt(
            external_aad.lookup_aad(Some(&self.protected.header), Some(&self.unprotected)),
            |ciphertext, aad| {
                try_decrypt(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}
