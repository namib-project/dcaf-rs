#![cfg(all(test, feature = "std"))]
use core::convert::Infallible;
use std::path::PathBuf;

use coset::iana::Algorithm;
use coset::{
    CoseEncrypt, CoseEncryptBuilder, CoseError, CoseKey, CoseKeyBuilder, CoseRecipientBuilder,
    EncryptionContext, HeaderBuilder,
};
use rstest::rstest;

use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::encrypt::encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher, HeaderBuilderExt};
use crate::token::cose::header_util::determine_algorithm;
use crate::token::cose::key::CoseSymmetricKey;
use crate::token::cose::recipient::CoseRecipientBuilderExt;
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, perform_cose_reference_output_test,
    perform_cose_self_signed_test, serialize_cose_with_failures, CoseStructTestHelper, TestCase,
};
use crate::token::cose::CoseCipher;

impl<B: CoseCipher + CoseEncryptCipher + CoseKeyDistributionCipher> CoseStructTestHelper<B>
    for CoseEncrypt
{
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let encrypt_cfg = case
            .input
            .enveloped
            .as_ref()
            .expect("expected a CoseEncrypt test case, but it was not found");

        let encrypt = CoseEncryptBuilder::new();

        let recipient = encrypt_cfg
            .recipients
            .first()
            .expect("test case has no recipient");

        // Need to generate an IV. Have to do this quite ugly, because we have implemented our IV
        // generation on the header builder only.
        let iv_generator = HeaderBuilder::new()
            .gen_iv(
                backend,
                &encrypt_cfg
                    .protected
                    .as_ref()
                    .or(encrypt_cfg.unprotected.as_ref())
                    .unwrap()
                    .alg
                    .as_ref()
                    .unwrap()
                    .clone(),
            )
            .expect("unable to generate IV")
            .build();
        let mut unprotected = encrypt_cfg.unprotected.clone().unwrap_or_default();
        unprotected.iv = iv_generator.iv;

        let mut recipient_struct_builder = CoseRecipientBuilder::from(recipient.clone());
        let enc_key: CoseKey;
        if recipient.alg == Some(Algorithm::Direct)
            || determine_algorithm::<Infallible>(
                None,
                recipient.unprotected.as_ref(),
                recipient.protected.as_ref(),
            ) == Ok(coset::Algorithm::Assigned(Algorithm::Direct))
        {
            enc_key = recipient.key.clone();
        } else {
            enc_key = CoseKeyBuilder::new_symmetric_key(
                case.intermediates
                    .as_ref()
                    .expect("CoseEncrypt test case should have intermediates")
                    .cek
                    .clone(),
            )
            .build();
            let parsed_key = CoseSymmetricKey::<Infallible>::try_from(&enc_key)
                .expect("unable to parse CEK input as symmetric key");
            recipient_struct_builder = recipient_struct_builder
                .try_encrypt(
                    backend,
                    &mut &recipient.key,
                    true,
                    EncryptionContext::EncRecipient,
                    recipient.protected.clone(),
                    recipient.unprotected.clone(),
                    parsed_key.k,
                    &mut (&[] as &[u8]),
                )
                .expect("unable to create CoseRecipient structure");
        }

        encrypt
            .add_recipient(recipient_struct_builder.build())
            .try_encrypt(
                backend,
                &mut &enc_key,
                false,
                encrypt_cfg.protected.clone(),
                Some(unprotected),
                &case.input.plaintext.clone().into_bytes(),
                &mut encrypt_cfg.external.as_slice(),
            )
            .expect("unable to encrypt Encrypt object")
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
            .enveloped
            .as_ref()
            .expect("expected CoseEncrypt test case");
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

        let verify_result = self.try_decrypt_with_recipients(backend, &mut &keys, false, &mut aad);

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
fn cose_examples_enveloped_reference_output<B: CoseEncryptCipher + CoseKeyDistributionCipher>(
    #[files("tests/cose_examples/enveloped-tests/env-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
fn cose_examples_enveloped_self_signed<B: CoseEncryptCipher + CoseKeyDistributionCipher>(
    #[files("tests/cose_examples/enveloped-tests/env-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
fn cose_examples_aes_wrap_reference_output<B: CoseEncryptCipher + CoseKeyDistributionCipher>(
    #[files("tests/cose_examples/aes-wrap-examples/aes-wrap-*-0[45].json")] test_path: PathBuf, // The other tests use (as of now) unsupported algorithms
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
fn cose_examples_aes_wrap_self_signed<B: CoseEncryptCipher + CoseKeyDistributionCipher>(
    #[files("tests/cose_examples/aes-wrap-examples/aes-wrap-*-0[45].json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}
