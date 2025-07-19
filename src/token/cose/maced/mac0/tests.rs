/*
 * Copyright (c) 2024-2025 The NAMIB Project Developers.
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

use coset::iana::Algorithm;
use coset::{CoseError, CoseKey, CoseKeyBuilder, CoseMac0, CoseMac0Builder, Header};
use rstest::rstest;

use crate::token::cose::maced::mac0::{CoseMac0BuilderExt, CoseMac0Ext};
use crate::token::cose::maced::MacCryptoBackend;
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures,
    CoseStructTestHelper, TestCase,
};
use crate::token::cose::util::determine_algorithm;
use crate::token::cose::{test_helper, CryptoBackend};

#[cfg(feature = "openssl")]
use crate::token::cose::test_helper::openssl_ctx;
#[cfg(any(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-cbc-mac"))]
use crate::token::cose::test_helper::rustcrypto_ctx;

impl<B: CryptoBackend + MacCryptoBackend> CoseStructTestHelper<B> for CoseMac0 {
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let mac0_cfg = case
            .input
            .mac0
            .as_ref()
            .expect("expected a CoseMac0 test case, but it was not found");

        let mac0 = CoseMac0Builder::new();

        let recipient = mac0_cfg
            .recipients
            .first()
            .expect("test case has no recipient");

        let unprotected = mac0_cfg.unprotected.clone().unwrap_or_default();

        let enc_key = if recipient.alg == Some(coset::Algorithm::Assigned(Algorithm::Direct))
            || determine_algorithm::<Infallible>(
                None,
                recipient.protected.as_ref(),
                recipient.unprotected.as_ref(),
            ) == Ok(Algorithm::Direct)
        {
            recipient.key.clone()
        } else {
            CoseKeyBuilder::new_symmetric_key(
                case.intermediates
                    .as_ref()
                    .expect("CoseMac0 test case should have intermediates")
                    .cek
                    .clone(),
            )
            .build()
        };

        let mac0 = mac0
            .payload(case.input.plaintext.clone().into_bytes())
            .try_compute(
                backend,
                &enc_key,
                mac0_cfg.protected.clone(),
                Some(unprotected),
                mac0_cfg.external.as_slice(),
            )
            .expect("unable to encrypt Mac0 object");

        mac0.build()
    }

    fn serialize_and_apply_failures(mut self, case: &TestCase) -> Result<Vec<u8>, CoseError> {
        let failures = &case.input.failures;
        if let Some(1) = &failures.change_tag {
            let byte = self
                .payload
                .as_mut()
                .expect("Mac0 has no payload, can't apply failure")
                .first_mut()
                .unwrap();
            *byte = byte.wrapping_add(1);
        }

        apply_header_failures(&mut self.protected.header, failures);

        apply_attribute_failures(&mut self.unprotected, failures)?;
        Ok(serialize_cose_with_failures(self, failures))
    }

    fn check_against_test_case(&self, case: &TestCase, backend: &mut B) {
        let test_case = case
            .input
            .mac0
            .as_ref()
            .expect("CoseMac0 test case expected");
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

        let verify_result = self.try_verify(backend, &keys, aad);

        if case.fail {
            verify_result.expect_err("invalid token was successfully verified");
        } else {
            verify_result.expect("unable to verify token");

            assert_eq!(
                &case.input.plaintext.as_bytes(),
                &self.payload.as_deref().unwrap_or(&[] as &[u8])
            );
            let empty_hdr = Header::default();
            assert_eq!(
                test_case.unprotected.as_ref().unwrap_or(&empty_hdr),
                &self.unprotected
            );
            assert_eq!(
                test_case.protected.as_ref().unwrap_or(&empty_hdr),
                &self.protected.header
            );
        }
    }
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-hmac", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_mac0_reference_output<B: MacCryptoBackend>(
    #[files("tests/cose_examples/mac0-tests/mac-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-hmac", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_mac0_self_signed<B: MacCryptoBackend>(
    #[files("tests/cose_examples/mac0-tests/mac-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac0, B>(test_path, backend);
}

// As of now, we don't support CBC-MAC with the OpenSSL backend.
#[cfg(feature = "rustcrypto-aes-cbc-mac")]
#[rstest]
#[cfg_attr(
    all(feature = "rustcrypto-aes-cbc-mac"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_cbc_mac_mac0_reference_output<B: MacCryptoBackend>(
    #[files("tests/cose_examples/cbc-mac-examples/cbc-mac-enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac0, B>(test_path, backend);
}

// As of now, we don't support CBC-MAC with the OpenSSL backend.
#[cfg(feature = "rustcrypto-aes-cbc-mac")]
#[rstest]
#[cfg_attr(
    all(feature = "rustcrypto-aes-cbc-mac"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_cbc_mac_mac0_self_signed<B: MacCryptoBackend>(
    #[files("tests/cose_examples/cbc-mac-examples/cbc-mac-enc-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-hmac", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_hmac_mac0_reference_output<B: MacCryptoBackend>(
    #[files("tests/cose_examples/hmac-examples/HMac-enc-0[0-4].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac0, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(feature = "rustcrypto-hmac", case::rustcrypto(rustcrypto_ctx()))]
fn cose_examples_hmac_mac0_self_signed<B: MacCryptoBackend>(
    #[files("tests/cose_examples/hmac-examples/HMac-enc-0[0-4].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac0, B>(test_path, backend);
}
