#![cfg(all(test, feature = "std"))]
use std::path::PathBuf;

use coset::{CoseEncrypt0, CoseEncrypt0Builder, CoseError, CoseKey, HeaderBuilder};
use rstest::rstest;

use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::encrypt::encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};
use crate::token::cose::encrypt::{CoseEncryptCipher, HeaderBuilderExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, perform_cose_reference_output_test,
    perform_cose_self_signed_test, serialize_cose_with_failures, CoseStructTestHelper, TestCase,
};
use crate::token::cose::CoseCipher;

impl<B: CoseCipher + CoseEncryptCipher> CoseStructTestHelper<B> for CoseEncrypt0 {
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let encrypt0_cfg = case
            .input
            .encrypted
            .as_ref()
            .expect("expected a CoseEncrypt0 test case, but it was not found");

        let encrypt0 = CoseEncrypt0Builder::new();

        let recipient = encrypt0_cfg
            .recipients
            .first()
            .expect("test case has no recipient");

        // Need to generate an IV. Have to do this quite ugly, because we have implemented our IV
        // generation on the header builder only.
        let iv_generator = HeaderBuilder::new()
            .gen_iv(
                backend,
                &encrypt0_cfg
                    .protected
                    .as_ref()
                    .or(encrypt0_cfg.unprotected.as_ref())
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

        encrypt0
            .try_encrypt(
                backend,
                &mut &recipient.key,
                false,
                encrypt0_cfg.protected.clone(),
                Some(unprotected),
                &case.input.plaintext.clone().into_bytes(),
                &mut encrypt0_cfg.external.as_slice(),
            )
            .expect("unable to encrypt Encrypt0 object")
            .build()
    }

    fn serialize_and_apply_failures(mut self, case: &TestCase) -> Result<Vec<u8>, CoseError> {
        let failures = &case.input.failures;
        if let Some(1) = &failures.change_tag {
            let byte = self.ciphertext.as_mut().unwrap().first_mut().unwrap();
            *byte = byte.wrapping_add(1);
        }

        apply_header_failures(&mut self.protected.header, failures);

        apply_attribute_failures(&mut self.unprotected, failures)?;
        Ok(serialize_cose_with_failures(self, failures))
    }

    fn check_against_test_case(&self, case: &TestCase, backend: &mut B) {
        let test_case = case
            .input
            .encrypted
            .as_ref()
            .expect("expected CoseEncrypt0 test case");
        let keys: Vec<CoseKey> = test_case
            .recipients
            .iter()
            .map(|v| {
                let mut key_with_alg = v.key.clone();
                if key_with_alg.alg.is_none() {
                    key_with_alg.alg = v.alg.map(coset::Algorithm::Assigned);
                }
                key_with_alg
            })
            .collect();
        let mut aad = test_case.external.as_slice();

        let verify_result = self.try_decrypt(backend, &mut &keys, false, &mut aad);

        if case.fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            let plaintext = verify_result.expect("unable to verify token");

            assert_eq!(case.input.plaintext.as_bytes(), plaintext.as_slice());
            // TODO IV is apprarently taken from rng_stream field, not header field, but still implicitly added to header.
            //      ugh...
            let mut unprotected = test_case.unprotected.clone().unwrap_or_default();
            let mut protected = test_case.protected.clone().unwrap_or_default();
            unprotected.iv.clone_from(&self.unprotected.iv);
            protected.iv.clone_from(&self.protected.header.iv);
            assert_eq!(&unprotected, &self.unprotected);
            assert_eq!(&protected, &self.protected.header);
        }
    }
}

#[rstest]
fn cose_examples_encrypted_encrypt0_reference_output<B: CoseEncryptCipher>(
    #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
fn cose_examples_encrypted_encrypt0_self_signed<B: CoseEncryptCipher>(
    #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
fn cose_examples_aes_gcm_encrypt0_reference_output<B: CoseEncryptCipher>(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
fn cose_examples_aes_gcm_encrypt0_self_signed<B: CoseEncryptCipher>(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt0, B>(test_path, backend);
}
