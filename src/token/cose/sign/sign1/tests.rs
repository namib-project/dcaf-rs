#![cfg(all(test, feature = "std"))]
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::CoseSignExt;
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, perform_cose_reference_output_test,
    perform_cose_self_signed_test, serialize_cose_with_failures, CoseStructTestHelper, TestCase,
    TestCaseFailures,
};
use crate::token::cose::CoseCipher;
use crate::CoseSignCipher;
use coset::{
    CborSerializable, CoseError, CoseKey, CoseSign1, CoseSign1Builder, Header,
    TaggedCborSerializable,
};
use rstest::rstest;
use std::path::PathBuf;

impl<B: CoseCipher + CoseSignCipher> CoseStructTestHelper<B> for CoseSign1 {
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self {
        let mut sign1_cfg = case
            .input
            .clone()
            .sign0
            .expect("expected a CoseSign1 test case, but it was not found");

        let builder = CoseSign1Builder::new();

        builder
            .payload(case.input.plaintext.clone().into_bytes())
            .try_sign(
                backend,
                &mut &sign1_cfg.key,
                sign1_cfg.protected.clone(),
                sign1_cfg.unprotected.clone(),
                &mut sign1_cfg.external.as_slice(),
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

        apply_header_failures(&mut self.protected.header, &failures);
        apply_attribute_failures(&mut self.unprotected, failures)?;
        Ok(serialize_cose_with_failures(self, failures))
    }

    fn check_against_test_case(&self, case: &TestCase, backend: &mut B) {
        let sign1_case = case.input.sign0.as_ref().expect("expected Sign1 test case");
        let key: CoseKey = sign1_case.key.clone();

        let verify_result = self.try_verify(backend, &mut &key, false, &mut &*sign1_case.external);

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
fn cose_examples_ecdsa_sign1_reference_output<B: CoseSignCipher>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
fn cose_examples_ecdsa_sign1_self_signed<B: CoseSignCipher>(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
fn cose_examples_sign1_reference_output<B: CoseSignCipher>(
    #[files("tests/cose_examples/sign1-tests/sign-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_reference_output_test::<CoseSign1, B>(test_path, backend);
}

#[rstest]
fn cose_examples_sign1_self_signed<B: CoseSignCipher>(
    #[files("tests/cose_examples/sign1-tests/sign-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: B,
) {
    perform_cose_self_signed_test::<CoseSign1, B>(test_path, backend);
}
