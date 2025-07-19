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
use coset::{
    CoseError, CoseKey, CoseKeyBuilder, CoseMac, CoseMacBuilder, CoseRecipientBuilder,
    EncryptionContext, Header,
};
use rstest::rstest;

use crate::token::cose::key::CoseSymmetricKey;
use crate::token::cose::maced::mac::{CoseMacBuilderExt, CoseMacExt};
use crate::token::cose::maced::MacCryptoBackend;
use crate::token::cose::recipient::CoseRecipientBuilderExt;
use crate::token::cose::recipient::KeyDistributionCryptoBackend;
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures,
    CoseStructTestHelper, TestCase,
};
use crate::token::cose::util::determine_algorithm;
use crate::token::cose::{test_helper, CryptoBackend};

#[cfg(feature = "openssl")]
use crate::token::cose::test_helper::openssl_ctx;
#[cfg(all(
    any(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-cbc-mac"),
    feature = "rustcrypto-aes-kw"
))]
use crate::token::cose::test_helper::rustcrypto_ctx;

impl<B: CryptoBackend + MacCryptoBackend + KeyDistributionCryptoBackend> CoseStructTestHelper<B>
    for CoseMac
{
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let mac_cfg = case
            .input
            .mac
            .as_ref()
            .expect("expected a CoseMac test case, but it was not found");

        let mac = CoseMacBuilder::new();

        let recipient = mac_cfg
            .recipients
            .first()
            .expect("test case has no recipient");

        let unprotected = mac_cfg.unprotected.clone().unwrap_or_default();

        let mut recipient_struct_builder = CoseRecipientBuilder::from(recipient.clone());
        let enc_key: CoseKey;
        if recipient.alg == Some(coset::Algorithm::Assigned(Algorithm::Direct))
            || determine_algorithm::<Infallible>(
                None,
                recipient.protected.as_ref(),
                recipient.unprotected.as_ref(),
            ) == Ok(Algorithm::Direct)
        {
            enc_key = recipient.key.clone();
        } else {
            enc_key = CoseKeyBuilder::new_symmetric_key(
                case.intermediates
                    .as_ref()
                    .expect("CoseMac test case should have intermediates")
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

        mac.add_recipient(recipient_struct_builder.build())
            .payload(case.input.plaintext.clone().into_bytes())
            .try_compute(
                backend,
                &enc_key,
                mac_cfg.protected.clone(),
                Some(unprotected),
                mac_cfg.external.as_slice(),
            )
            .expect("unable to encrypt Mac object")
            .build()
    }

    fn serialize_and_apply_failures(mut self, case: &TestCase) -> Result<Vec<u8>, CoseError> {
        let failures = &case.input.failures;
        if let Some(1) = &failures.change_tag {
            let byte = self.tag.first_mut().unwrap();
            *byte = byte.wrapping_add(1);
        }

        apply_header_failures(&mut self.protected.header, failures);

        apply_attribute_failures(&mut self.unprotected, failures)?;
        Ok(serialize_cose_with_failures(self, failures))
    }

    fn check_against_test_case(&self, case: &TestCase, backend: &mut B) {
        let test_case = case.input.mac.as_ref().expect("CoseMac test case expected");
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

        let verify_result = self.try_verify_with_recipients(backend, &keys, aad);

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
#[cfg_attr(
    all(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_mac_reference_output<B: MacCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/mac-tests/mac-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_mac_self_signed<B: MacCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/mac-tests/mac-*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac, B>(test_path, backend);
}

// As of now, we don't support CBC-MAC with the OpenSSL backend.
#[cfg(all(feature = "rustcrypto-aes-cbc-mac", feature = "rustcrypto-aes-kw"))]
#[rstest]
#[cfg_attr(
    all(feature = "rustcrypto-aes-cbc-mac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_cbc_mac_mac_reference_output<
    B: MacCryptoBackend + KeyDistributionCryptoBackend,
>(
    #[files("tests/cose_examples/cbc-mac-examples/cbc-mac-0*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac, B>(test_path, backend);
}

// As of now, we don't support CBC-MAC with the OpenSSL backend.
#[cfg(all(feature = "rustcrypto-aes-cbc-mac", feature = "rustcrypto-aes-kw"))]
#[rstest]
#[cfg_attr(
    all(feature = "rustcrypto-aes-cbc-mac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_cbc_mac_mac_self_signed<B: MacCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/cbc-mac-examples/cbc-mac-0*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_hmac_mac_reference_output<B: MacCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/hmac-examples/HMac-0[0-4].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn cose_examples_hmac_mac_self_signed<B: MacCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/cose_examples/hmac-examples/HMac-0[0-4].json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac, B>(test_path, backend);
}

#[rstest]
#[cfg_attr(feature = "openssl", case::openssl(openssl_ctx()))]
#[cfg_attr(
    all(feature = "rustcrypto-hmac", feature = "rustcrypto-aes-kw"),
    case::rustcrypto(rustcrypto_ctx())
)]
fn hmac_tests<B: MacCryptoBackend + KeyDistributionCryptoBackend>(
    #[files("tests/dcaf_cose_examples/hmac/*.json")] test_path: PathBuf,
    #[case] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac, B>(test_path, backend);
}
