#![cfg(all(test, feature = "std"))]
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::encrypt::CoseKeyDistributionCipher;
use crate::token::cose::header_util::determine_algorithm;
use crate::token::cose::key::CoseSymmetricKey;
use crate::token::cose::mac::mac::{CoseMacBuilderExt, CoseMacExt};
use crate::token::cose::mac::CoseMacCipher;
use crate::token::cose::recipient::CoseRecipientBuilderExt;
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures,
    CoseStructTestHelper, TestCase, TestCaseFailures,
};
use crate::token::cose::{test_helper, CoseCipher};
use coset::iana::Algorithm;
use coset::{
    CborSerializable, CoseError, CoseKey, CoseKeyBuilder, CoseMac, CoseMacBuilder,
    CoseRecipientBuilder, EncryptionContext, Header, TaggedCborSerializable,
};
use rstest::rstest;
use std::convert::Infallible;
use std::path::PathBuf;

impl<B: CoseCipher + CoseMacCipher + CoseKeyDistributionCipher> CoseStructTestHelper<B>
    for CoseMac
{
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let mac_cfg = case
            .input
            .mac
            .as_ref()
            .expect("expected a CoseEncrypt test case, but it was not found");

        let mac = CoseMacBuilder::new();

        let recipient = mac_cfg
            .recipients
            .first()
            .expect("test case has no recipient");

        let unprotected = mac_cfg.unprotected.clone().unwrap_or_default();

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

        mac.add_recipient(recipient_struct_builder.build())
            .try_compute(
                backend,
                &mut &enc_key,
                false,
                mac_cfg.protected.clone(),
                Some(unprotected),
                case.input.plaintext.clone().into_bytes(),
                &mut mac_cfg.external.as_slice(),
            )
            .expect("unable to encrypt Encrypt object")
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
                    key_with_alg.alg = v.alg.map(coset::Algorithm::Assigned);
                }
                key_with_alg
            })
            .collect();
        let mut aad = test_case.external.as_slice();

        let verify_result = self.try_verify_with_recipients(backend, &mut &keys, false, &mut aad);

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
fn cose_examples_mac_reference_output<B: CoseMacCipher + CoseKeyDistributionCipher>(
    #[files("tests/cose_examples/mac-tests/mac-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    test_helper::perform_cose_reference_output_test::<CoseMac, B>(test_path, backend);
}

#[rstest]
fn cose_examples_mac_self_signed<B: CoseMacCipher + CoseKeyDistributionCipher>(
    #[files("tests/cose_examples/mac-tests/mac-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    test_helper::perform_cose_self_signed_test::<CoseMac, B>(test_path, backend);
}