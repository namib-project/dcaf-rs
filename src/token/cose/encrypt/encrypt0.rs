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
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    try_all_keys: bool,
    plaintext: &[u8],
    // NOTE: aad ist not the external AAD provided by the user, but the Enc_structure as defined in RFC 9052, Section 5.3
    aad: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    let parsed_key = determine_key_candidates(
        key_provider,
        protected,
        unprotected,
        &KeyOperation::Assigned(iana::KeyOperation::Sign),
        false,
    )?
    .into_iter()
    .next()
    .ok_or(CoseCipherError::NoKeyFound)?;
    let algorithm = determine_algorithm(&parsed_key, protected, unprotected)?;

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

pub trait CoseEncrypt0BuilderExt: Sized {
    fn try_encrypt<
        'a,
        'b,
        B: CoseEncryptCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {
    fn try_encrypt<
        'a,
        'b,
        B: CoseEncryptCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_ciphertext(
            plaintext,
            external_aad.lookup_aad(protected.as_ref(), unprotected.as_ref()),
            |ciphertext, aad| {
                try_encrypt_single(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    try_all_keys,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::token::cose::crypto_impl::openssl::OpensslContext;
    use crate::token::cose::encrypt::encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};
    use crate::token::cose::encrypt::{CoseEncryptCipher, HeaderBuilderExt};
    use crate::token::cose::sign::CoseSign1BuilderExt;
    use crate::token::cose::sign::CoseSign1Ext;
    use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
    use crate::token::cose::test_helper::{
        apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
        TestCaseEncrypted, TestCaseFailures, TestCaseInput, TestCaseRecipient, TestCaseSign,
    };
    use crate::CoseSignCipher;
    use base64::Engine;
    use coset::iana::EnumI64;
    use coset::{
        AsCborValue, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseError, CoseKey,
        CoseSign, CoseSign1, CoseSign1Builder, CoseSignBuilder, CoseSignature,
        CoseSignatureBuilder, Header, HeaderBuilder, Label, TaggedCborSerializable,
    };
    use hex::FromHex;
    use rstest::rstest;
    use serde::de::{MapAccess, Visitor};
    use serde::{Deserialize, Deserializer};
    use serde_json::Value;
    use std::any::Any;
    use std::path::PathBuf;

    fn serialize_encrypt0_and_apply_failures(
        failures: &mut TestCaseFailures,
        key: &mut CoseKey,
        mut value: CoseEncrypt0,
    ) -> (Option<CoseError>, Vec<u8>) {
        if let Some(1) = &failures.change_tag {
            let byte = value.ciphertext.as_mut().unwrap().first_mut().unwrap();
            *byte = byte.wrapping_add(1);
        }

        apply_header_failures(&mut value.protected.header, &failures);

        let serialized_data = serialize_cose_with_failures(value, &failures);

        (apply_attribute_failures(key, &failures), serialized_data)
    }

    fn verify_encrypt0_test_case<T: CoseEncryptCipher>(
        backend: &mut T,
        encrypt0: &CoseEncrypt0,
        test_case: &mut TestCaseEncrypted,
        expected_plaintext: &[u8],
        should_fail: bool,
    ) {
        let keys: Vec<CoseKey> = test_case
            .recipients
            .iter()
            .map(|v| {
                let mut key_with_alg = v.key.clone();
                if key_with_alg.alg.is_none() {
                    key_with_alg.alg = v.alg.map(|a| coset::Algorithm::Assigned(a));
                }
                key_with_alg
            })
            .collect();
        let mut aad = test_case.external.as_slice();

        let verify_result = encrypt0.try_decrypt(backend, &mut &keys, false, &mut aad);

        if should_fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            let plaintext = verify_result.expect("unable to verify token");

            assert_eq!(expected_plaintext, plaintext.as_slice());
            let empty_hdr = Header::default();
            // TODO IV is apprarently taken from rng_stream field, not header field, but still implicitly added to header.
            //      ugh...
            let mut unprotected = test_case.unprotected.clone().unwrap_or_default();
            let mut protected = test_case.protected.clone().unwrap_or_default();
            unprotected.iv = encrypt0.unprotected.iv.clone();
            protected.iv = encrypt0.protected.header.iv.clone();
            assert_eq!(&unprotected, &encrypt0.unprotected);
            assert_eq!(&protected, &encrypt0.protected.header);
        }
    }

    fn perform_encrypt0_reference_output_test(
        test_path: PathBuf,
        mut backend: impl CoseEncryptCipher,
    ) {
        let test_case_description: TestCase = serde_json::from_reader(
            std::fs::File::open(test_path).expect("unable to open test case"),
        )
        .expect("invalid test case");

        let mut encrypt0_cfg = test_case_description
            .input
            .encrypted
            .expect("expected a CoseSign test case, but it was not found");

        let example_output =
            match CoseEncrypt0::from_tagged_slice(test_case_description.output.cbor.as_slice())
                .or_else(|e1| {
                    CoseEncrypt0::from_slice(test_case_description.output.cbor.as_slice())
                        .map_err(|e2| Result::<CoseSign1, (CoseError, CoseError)>::Err((e1, e2)))
                }) {
                Ok(v) => v,
                e => {
                    if test_case_description.fail {
                        println!("test case failed as expected. Error: {:?}", e);
                        return;
                    } else {
                        e.expect("unable to deserialize test case data");
                        unreachable!()
                    }
                }
            };

        verify_encrypt0_test_case(
            &mut backend,
            &example_output,
            &mut encrypt0_cfg,
            test_case_description.input.plaintext.as_bytes(),
            test_case_description.fail,
        )
    }

    fn perform_encrypt0_self_signed_test(test_path: PathBuf, mut backend: impl CoseEncryptCipher) {
        let mut test_case_description: TestCase = serde_json::from_reader(
            std::fs::File::open(test_path).expect("unable to open test case"),
        )
        .expect("invalid test case");

        let mut encrypt0_cfg = test_case_description
            .input
            .encrypted
            .as_mut()
            .expect("expected a CoseEncrypt0 test case, but it was not found");

        let mut encrypt0 = CoseEncrypt0Builder::new();

        let mut recipient = encrypt0_cfg
            .recipients
            .first_mut()
            .expect("test case has no recipient");

        // Need to generate an IV. Have to do this quite ugly, because we have implemented our IV
        // generation on the header builder only.
        let iv_generator = HeaderBuilder::new()
            .gen_iv(
                &mut backend,
                &encrypt0_cfg
                    .protected
                    .as_ref()
                    .or_else(|| encrypt0_cfg.unprotected.as_ref())
                    .unwrap()
                    .alg
                    .as_ref()
                    .unwrap()
                    .clone(),
            )
            .expect("unable to generate IV")
            .build();
        let mut unprotected = encrypt0_cfg.unprotected.clone().unwrap_or_default();
        unprotected.iv = iv_generator.iv;

        let mut encrypt0 = encrypt0
            .try_encrypt(
                &mut backend,
                &mut &recipient.key,
                false,
                encrypt0_cfg.protected.clone(),
                Some(unprotected),
                &test_case_description.input.plaintext.clone().into_bytes(),
                &mut encrypt0_cfg.external.as_slice(),
            )
            .expect("unable to encrypt Encrypt0 object");

        let (failure, sign_serialized) = serialize_encrypt0_and_apply_failures(
            &mut test_case_description.input.failures,
            &mut recipient.key,
            encrypt0.build(),
        );

        if failure.is_some() && test_case_description.fail {
            println!(
                "serialization failed as expected for test case: {:?}",
                failure.unwrap()
            );
            return;
        } else if failure.is_some() && !test_case_description.fail {
            panic!(
                "unexpected error occurred while serializing Sign1 object: {:?}",
                failure.unwrap()
            )
        }

        let encrypt0_redeserialized =
            match CoseEncrypt0::from_tagged_slice(sign_serialized.as_slice()).or_else(|e1| {
                CoseEncrypt0::from_slice(sign_serialized.as_slice())
                    .map_err(|e2| Result::<CoseEncrypt0, (CoseError, CoseError)>::Err((e1, e2)))
            }) {
                Ok(v) => v,
                e => {
                    if test_case_description.fail {
                        println!("test case failed as expected. Error: {:?}", e);
                        return;
                    } else {
                        e.expect("unable to deserialize test case data");
                        unreachable!()
                    }
                }
            };

        verify_encrypt0_test_case(
            &mut backend,
            &encrypt0_redeserialized,
            test_case_description
                .input
                .encrypted
                .as_mut()
                .expect("expected a CoseSign test case, but it was not found"),
            &test_case_description.input.plaintext.as_bytes(),
            test_case_description.fail,
        )
    }

    #[rstest]
    fn cose_examples_encrypted_encrypt0_reference_output(
        #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
        #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
    ) {
        perform_encrypt0_reference_output_test(test_path, backend)
    }

    #[rstest]
    fn cose_examples_encrypted_encrypt0_self_signed(
        #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
        #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
    ) {
        perform_encrypt0_self_signed_test(test_path, backend)
    }

    #[rstest]
    fn cose_examples_aes_gcm_encrypt0_reference_output(
        #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
        #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
    ) {
        perform_encrypt0_reference_output_test(test_path, backend)
    }

    #[rstest]
    fn cose_examples_aes_gcm_encrypt0_self_signed(
        #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
        #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
    ) {
        perform_encrypt0_self_signed_test(test_path, backend)
    }
}
