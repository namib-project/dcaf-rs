/*
 * Copyright (c) 2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::path::PathBuf;

use coset::{CoseEncrypt0, CoseEncrypt0Builder, CoseError, CoseKey, HeaderBuilder};
use rstest::rstest;

use crate::token::cose::encrypted::encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};
use crate::token::cose::encrypted::EncryptCryptoBackend;
use crate::token::cose::header::HeaderBuilderExt;
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, perform_cose_reference_output_test,
    perform_cose_self_signed_test, serialize_cose_with_failures, CoseStructTestHelper, TestCase,
};
use crate::token::cose::CryptoBackend;

#[cfg(feature = "openssl")]
use crate::token::cose::test_helper::openssl_ctx;
#[cfg(any(feature = "rustcrypto-aes-gcm", feature = "rustcrypto-aes-ccm"))]
use crate::token::cose::test_helper::rustcrypto_ctx;

impl<B: CryptoBackend + EncryptCryptoBackend> CoseStructTestHelper<B> for CoseEncrypt0 {
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

        // Need to generate an IV. Have to do this quite uglily, because we have implemented our IV
        // generation on the header builder only.
        let alg = if let coset::Algorithm::Assigned(alg) = encrypt0_cfg
            .protected
            .as_ref()
            .or(encrypt0_cfg.unprotected.as_ref())
            .unwrap()
            .alg
            .as_ref()
            .unwrap()
        {
            alg
        } else {
            panic!("unknown/invalid algorithm in test case")
        };
        let iv_generator = HeaderBuilder::new()
            .gen_iv(backend, *alg)
            .expect("unable to generate IV")
            .build();
        let mut unprotected = encrypt0_cfg.unprotected.clone().unwrap_or_default();
        unprotected.iv = iv_generator.iv;

        encrypt0
            .try_encrypt(
                backend,
                &recipient.key,
                encrypt0_cfg.protected.clone(),
                Some(unprotected),
                case.input.plaintext.clone().into_bytes().as_slice(),
                encrypt0_cfg.external.as_slice(),
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
                    key_with_alg.alg.clone_from(&v.alg);
                }
                key_with_alg
            })
            .collect();
        let aad = test_case.external.as_slice();

        let verify_result = self.try_decrypt(backend, &keys, aad);

        if case.fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            let plaintext = verify_result.expect("unable to verify token");

            assert_eq!(case.input.plaintext.as_bytes(), plaintext.as_slice());
            // IV is apparently taken from rng_stream field, not header field, but still implicitly added to header.
            // ugh...
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
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-aes-gcm", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_encrypted_encrypt0_reference_output<B: EncryptCryptoBackend>(
    #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-aes-gcm", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_encrypted_encrypt0_self_signed<B: EncryptCryptoBackend>(
    #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-aes-gcm", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_aes_gcm_encrypt0_reference_output<B: EncryptCryptoBackend>(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-aes-gcm", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_aes_gcm_encrypt0_self_signed<B: EncryptCryptoBackend>(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-aes-ccm", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_aes_ccm_encrypt0_reference_output<B: EncryptCryptoBackend>(
    #[files("tests/cose_examples/aes-ccm-examples/aes-ccm-enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-aes-ccm", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_aes_ccm_encrypt0_self_signed<B: EncryptCryptoBackend>(
    #[files("tests/cose_examples/aes-ccm-examples/aes-ccm-enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt0, B>(test_path, backend);
}
