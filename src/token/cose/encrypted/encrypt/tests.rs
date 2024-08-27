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
use core::convert::Infallible;
use std::path::PathBuf;

use coset::{
    iana, Algorithm, CoseEncrypt, CoseEncryptBuilder, CoseError, CoseKey, CoseKeyBuilder,
    CoseRecipientBuilder, EncryptionContext, HeaderBuilder,
};
use rstest::rstest;

use crate::token::cose::encrypted::encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
use crate::token::cose::encrypted::EncryptCryptoBackend;
use crate::token::cose::header::HeaderBuilderExt;
use crate::token::cose::key::CoseSymmetricKey;
use crate::token::cose::recipient::{CoseRecipientBuilderExt, KeyDistributionCryptoBackend};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, calculate_base_iv,
    perform_cose_reference_output_test, perform_cose_self_signed_test,
    serialize_cose_with_failures, CoseStructTestHelper, TestCase,
};
use crate::token::cose::{util::determine_header_param, CryptoBackend};

#[cfg(feature = "openssl")]
use crate::token::cose::test_helper::openssl_ctx;
#[cfg(all(
    any(feature = "rustcrypto-aes-gcm", feature = "rustcrypto-aes-ccm"),
    feature = "rustcrypto-aes-kw"
))]
use crate::token::cose::test_helper::rustcrypto_ctx;
use crate::token::cose::util::determine_algorithm;

impl<B: CryptoBackend + EncryptCryptoBackend + KeyDistributionCryptoBackend> CoseStructTestHelper<B>
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

        let mut recipient_struct_builder = CoseRecipientBuilder::from(recipient.clone());
        let mut enc_key: CoseKey;
        if recipient.alg == Some(Algorithm::Assigned(iana::Algorithm::Direct))
            || determine_algorithm::<Infallible>(
                None,
                recipient.protected.as_ref(),
                recipient.unprotected.as_ref(),
            ) == Ok(iana::Algorithm::Direct)
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
                    &recipient.key,
                    EncryptionContext::EncRecipient,
                    recipient.protected.clone(),
                    recipient.unprotected.clone(),
                    parsed_key.k,
                    &[] as &[u8],
                )
                .expect("unable to create CoseRecipient structure");
        }

        // Need to generate an IV. Have to do this quite uglily, because we have implemented our IV
        // generation on the header builder only.
        let alg = if let Algorithm::Assigned(alg) = encrypt_cfg
            .protected
            .as_ref()
            .or(encrypt_cfg.unprotected.as_ref())
            .unwrap()
            .alg
            .as_ref()
            .unwrap()
        {
            alg
        } else {
            panic!("unknown/invalid algorithm in test case")
        };

        let mut unprotected = encrypt_cfg.unprotected.clone().unwrap_or_default();
        if let Some(partial_iv) = determine_header_param(
            encrypt_cfg.protected.as_ref(),
            encrypt_cfg.unprotected.as_ref(),
            |v| (!v.partial_iv.is_empty()).then_some(&v.partial_iv),
        ) {
            enc_key.base_iv = calculate_base_iv(
                encrypt_cfg
                    .unsent
                    .as_ref()
                    .expect("test case has partial IV but no full IV defined"),
                partial_iv,
            );
        } else {
            let iv_generator = HeaderBuilder::new()
                .gen_iv(backend, *alg)
                .expect("unable to generate IV")
                .build();
            unprotected.iv = iv_generator.iv;
        }

        encrypt
            .add_recipient(recipient_struct_builder.build())
            .try_encrypt(
                backend,
                &enc_key,
                encrypt_cfg.protected.clone(),
                Some(unprotected),
                &case.input.plaintext.clone().into_bytes(),
                encrypt_cfg.external.as_slice(),
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
                    key_with_alg.alg.clone_from(&v.alg);
                }
                if let Some(partial_iv) = determine_header_param(
                    test_case.protected.as_ref(),
                    test_case.unprotected.as_ref(),
                    |v| (!v.partial_iv.is_empty()).then_some(&v.partial_iv),
                ) {
                    key_with_alg.base_iv = calculate_base_iv(
                        test_case
                            .unsent
                            .as_ref()
                            .expect("test case has partial IV but no full IV defined"),
                        partial_iv,
                    );
                }
                key_with_alg
            })
            .collect();
        let aad = test_case.external.as_slice();

        let verify_result = self.try_decrypt_with_recipients(backend, &keys, aad);

        if case.fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            let plaintext = verify_result.expect("unable to verify token");

            assert_eq!(case.input.plaintext.as_bytes(), plaintext.as_slice());
            // IV is apparently taken from rng_stream field, not header field, but still implicitly
            // added to header. ugh...
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
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_enveloped_reference_output<
    B: EncryptCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/enveloped-tests/env-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_enveloped_self_signed<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/enveloped-tests/env-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_aes_wrap_reference_output<
    B: EncryptCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/aes-wrap-examples/aes-wrap-*-0[45].json")] test_path: PathBuf, // The other tests use (as of now) unsupported algorithms
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_aes_wrap_self_signed<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/aes-wrap-examples/aes-wrap-*-0[45].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_aes_gcm_reference_output<
    B: EncryptCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-0[0-9].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_aes_gcm_self_signed<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-0[0-9].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-ccm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_aes_ccm_reference_output<
    B: EncryptCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/aes-ccm-examples/aes-ccm-0[0-9].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-ccm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_aes_ccm_self_signed<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/aes-ccm-examples/aes-ccm-0[0-9].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn aes_wrap_tests<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/dcaf_cose_examples/aes-kw/*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-gcm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn aes_gcm_tests<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/dcaf_cose_examples/aes-gcm/*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-aes-kw", feature = "rustcrypto-aes-ccm"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn aes_ccm_tests<B: EncryptCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/dcaf_cose_examples/aes-ccm/*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseEncrypt, B>(test_path, backend);
}
