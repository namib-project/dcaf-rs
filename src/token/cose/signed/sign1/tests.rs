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

use coset::{CoseError, CoseKey, CoseSign1, CoseSign1Builder, Header};
use rstest::rstest;

use crate::token::cose::signed::CoseSign1BuilderExt;
use crate::token::cose::signed::CoseSign1Ext;
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

impl<B: CryptoBackend + SignCryptoBackend> CoseStructTestHelper<B> for CoseSign1 {
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let sign1_cfg = case
            .input
            .clone()
            .sign0
            .expect("expected a CoseSign1 test case, but it was not found");

        let builder = CoseSign1Builder::new();

        builder
            .payload(case.input.plaintext.clone().into_bytes())
            .try_sign(
                backend,
                &sign1_cfg.key,
                sign1_cfg.protected.clone(),
                sign1_cfg.unprotected.clone(),
                sign1_cfg.external.as_slice(),
            )
            .expect("unable to sign Sign1 object")
            .build()
    }

    fn serialize_and_apply_failures(mut self, case: &TestCase) -> Result<Vec<u8>, CoseError> {
        let failures = &case.input.failures;
        if let Some(1) = &failures.change_tag {
            let byte = self.signature.first_mut().unwrap();
            *byte = byte.wrapping_add(1);
        }

        apply_header_failures(&mut self.protected.header, failures);
        apply_attribute_failures(&mut self.unprotected, failures)?;
        Ok(serialize_cose_with_failures(self, failures))
    }

    fn check_against_test_case(&self, case: &TestCase, backend: &mut B) {
        let sign1_case = case.input.sign0.as_ref().expect("expected Sign1 test case");
        let key: CoseKey = sign1_case.key.clone();

        let verify_result = self.try_verify(backend, &key, sign1_case.external.as_slice());

        if case.fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            verify_result.expect("unable to verify token");

            let empty_hdr = Header::default();
            assert_eq!(
                sign1_case.unprotected.as_ref().unwrap_or(&empty_hdr),
                &self.unprotected
            );
            assert_eq!(
                sign1_case.protected.as_ref().unwrap_or(&empty_hdr),
                &self.protected.header
            );
        }
    }
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p256_sign1_reference_output<B: SignCryptoBackend>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-0[14].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p256_sign1_self_signed<B: SignCryptoBackend>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-0[14].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p384_sign1_reference_output<B: SignCryptoBackend>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-02.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_ecdsa_p384_sign1_self_signed<B: SignCryptoBackend>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-02.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign1, B>(test_path, backend);
}

#[cfg(feature = "openssl")]
#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
fn cose_examples_ecdsa_p521_sign1_reference_output<B: SignCryptoBackend>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-03.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign1, B>(test_path, backend);
}

#[cfg(feature = "openssl")]
#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
fn cose_examples_ecdsa_p521_sign1_self_signed<B: SignCryptoBackend>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-03.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_sign1_reference_output<B: SignCryptoBackend>(
    #[files("tests/cose_examples/sign1-tests/sign-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-ecdsa", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_sign1_self_signed<B: SignCryptoBackend>(
    #[files("tests/cose_examples/sign1-tests/sign-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign1, B>(test_path, backend);
}
