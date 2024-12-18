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

use coset::{CoseError, CoseKey, CoseSign, CoseSignBuilder, CoseSignatureBuilder, Header};
use rstest::rstest;

use crate::token::cose::recipient::KeyDistributionCryptoBackend;
use crate::token::cose::signed::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, perform_cose_reference_output_test,
    perform_cose_self_signed_test, serialize_cose_with_failures, CoseStructTestHelper, TestCase,
};
use crate::token::cose::CryptoBackend;
use crate::token::cose::SignCryptoBackend;

#[cfg(feature = "openssl")]
use crate::token::cose::test_helper::openssl_ctx;
#[cfg(feature = "rustcrypto-ecdsa")]
use crate::token::cose::test_helper::rustcrypto_ctx;

impl<B: CryptoBackend + SignCryptoBackend + KeyDistributionCryptoBackend> CoseStructTestHelper<B>
    for CoseSign
{
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let sign_cfg = case
            .input
            .sign
            .as_ref()
            .expect("expected a CoseSign test case, but it was not found");

        let builder = CoseSignBuilder::new();

        let mut sign = builder.payload(case.input.plaintext.clone().into_bytes());

        if let Some(unprotected) = &sign_cfg.unprotected {
            sign = sign.unprotected(unprotected.clone());
        }
        if let Some(protected) = &sign_cfg.protected {
            sign = sign.protected(protected.clone());
        }
        for signer in &sign_cfg.signers {
            let mut signature = CoseSignatureBuilder::new();

            if let Some(unprotected) = &signer.unprotected {
                signature = signature.unprotected(unprotected.clone());
            }
            if let Some(protected) = &signer.protected {
                signature = signature.protected(protected.clone());
            }
            sign = sign
                .try_add_sign(
                    backend,
                    &signer.key,
                    signature.build(),
                    signer.external.as_slice(),
                )
                .expect("unable to sign Sign object");
        }

        sign.build()
    }

    fn serialize_and_apply_failures(mut self, case: &TestCase) -> Result<Vec<u8>, CoseError> {
        let failures = &case.input.failures;
        apply_header_failures(&mut self.protected.header, failures);

        for (signer, signature) in case
            .input
            .sign
            .as_ref()
            .expect("expected CoseSign test case")
            .signers
            .iter()
            .zip(self.signatures.iter_mut())
        {
            if let Some(1) = &signer.failures.change_tag {
                let byte = signature.signature.first_mut().unwrap();
                *byte = byte.wrapping_add(1);
            }

            apply_header_failures(&mut signature.protected.header, &signer.failures);

            apply_attribute_failures(&mut signature.unprotected, &signer.failures)?;
        }

        Ok(serialize_cose_with_failures(self, failures))
    }

    fn check_against_test_case(&self, case: &TestCase, backend: &mut B) {
        let test_case = case
            .input
            .sign
            .as_ref()
            .expect("expected CoseSign test case");
        let keys: Vec<CoseKey> = test_case
            .signers
            .iter()
            .map(|v| {
                let mut key_with_alg = v.key.clone();
                if key_with_alg.alg.is_none() {
                    key_with_alg.alg.clone_from(&v.alg);
                }
                key_with_alg
            })
            .collect();
        let aads: Vec<(Vec<u8>, &[u8])> = test_case
            .signers
            .iter()
            .map(|v| (v.key.key_id.clone(), v.external.as_slice()))
            .collect();

        let verify_result = self.try_verify(backend, &keys, &aads);

        if case.fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            verify_result.expect("unable to verify token");

            let empty_hdr = Header::default();
            assert_eq!(
                test_case.unprotected.as_ref().unwrap_or(&empty_hdr),
                &self.unprotected
            );
            assert_eq!(
                test_case.protected.as_ref().unwrap_or(&empty_hdr),
                &self.protected.header
            );
            for (signer, signature) in test_case.signers.iter().zip(self.signatures.iter()) {
                assert_eq!(
                    signer.unprotected.as_ref().unwrap_or(&empty_hdr),
                    &signature.unprotected
                );
                assert_eq!(
                    signer.protected.as_ref().unwrap_or(&empty_hdr),
                    &signature.protected.header
                );
            }
        }
    }
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p256_sign_reference_output<
    B: SignCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-0[14].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p256_sign_self_signed<
    B: SignCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-0[14].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p384_sign_reference_output<
    B: SignCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-02.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p384_sign_self_signed<
    B: SignCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-02.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign, B>(test_path, backend);
}

#[cfg(feature = "openssl")]
#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
fn cose_examples_ecdsa_p521_sign_reference_output<
    B: SignCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-03.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign, B>(test_path, backend);
}

#[cfg(feature = "openssl")]
#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
fn cose_examples_ecdsa_p521_sign_self_signed<
    B: SignCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-03.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_sign_reference_output<B: SignCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/sign-tests/sign-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_sign_self_signed<B: SignCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/sign-tests/sign-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn ecdsa_tests<B: SignCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/dcaf_cose_examples/ecdsa/*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign, B>(test_path, backend);
}
