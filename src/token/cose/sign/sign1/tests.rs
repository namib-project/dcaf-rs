#![cfg(all(test, feature = "std"))]
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
    TestCaseInput, TestCaseRecipient,
};
use crate::CoseSignCipher;
use base64::Engine;
use coset::iana::EnumI64;
use coset::{
    AsCborValue, CborSerializable, CoseError, CoseKey, CoseSign1, CoseSign1Builder, Header,
    TaggedCborSerializable,
};
use hex::FromHex;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::any::Any;
use std::path::PathBuf;

fn serialize_sign1_and_apply_failures(
    test_case_input: &TestCaseInput,
    key: &mut CoseKey,
    mut value: CoseSign1,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(1) = &test_case_input.failures.change_tag {
        let byte = value.signature.first_mut().unwrap();
        *byte = byte.wrapping_add(1);
    }

    apply_header_failures(&mut value.protected.header, &test_case_input.failures);
    let serialized_data = serialize_cose_with_failures(value, &test_case_input.failures);

    (
        apply_attribute_failures(key, &test_case_input.failures),
        serialized_data,
    )
}

fn verify_sign1_test_case<T: CoseSignCipher>(
    backend: &mut T,
    sign1: &CoseSign1,
    test_case: &TestCaseRecipient,
    should_fail: bool,
    aad: &[u8],
) {
    let key: CoseKey = test_case.key.clone();

    let verify_result = sign1.try_verify(backend, &mut &key, false, &mut &*aad);

    if should_fail {
        verify_result.expect_err("invalid token was successfully verified");
    } else {
        verify_result.expect("unable to verify token");

        let empty_hdr = Header::default();
        assert_eq!(
            test_case.unprotected.as_ref().unwrap_or(&empty_hdr),
            &sign1.unprotected
        );
        assert_eq!(
            test_case.protected.as_ref().unwrap_or(&empty_hdr),
            &sign1.protected.header
        );
    }
}

fn perform_sign1_reference_output_test(test_path: PathBuf, mut backend: impl CoseSignCipher) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let sign1_cfg = test_case_description
        .input
        .sign0
        .expect("expected a CoseSign1 test case, but it was not found");

    let example_output = match CoseSign1::from_tagged_slice(
        test_case_description.output.cbor.as_slice(),
    )
    .or_else(|e1| {
        CoseSign1::from_slice(test_case_description.output.cbor.as_slice())
            .map_err(|e2| Result::<CoseSign1, (CoseError, CoseError)>::Err((e1, e2)))
    }) {
        Ok(v) => v,
        e => {
            if test_case_description.fail {
                println!("test case failed as expected. Error: {:?}", e);
                return;
            } else {
                e.expect("unable to deserialize test case data");
                unreachable!()
            }
        }
    };

    verify_sign1_test_case(
        &mut backend,
        &example_output,
        &sign1_cfg,
        test_case_description.fail,
        sign1_cfg.external.as_slice(),
    )
}

fn perform_sign1_self_signed_test(test_path: PathBuf, mut backend: impl CoseSignCipher) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut sign1_cfg = test_case_description
        .input
        .clone()
        .sign0
        .expect("expected a CoseSign1 test case, but it was not found");

    let mut builder = CoseSign1Builder::new();

    let sign1 = builder
        .payload(test_case_description.input.plaintext.clone().into_bytes())
        .try_sign(
            &mut backend,
            &mut &sign1_cfg.key,
            sign1_cfg.protected.clone(),
            sign1_cfg.unprotected.clone(),
            &mut sign1_cfg.external.as_slice(),
        )
        .expect("unable to sign Sign1 object")
        .build();

    let (failure, sign1_serialized) = serialize_sign1_and_apply_failures(
        &test_case_description.input,
        &mut sign1_cfg.key,
        sign1.clone(),
    );

    if failure.is_some() && test_case_description.fail {
        println!(
            "serialization failed as expected for test case: {:?}",
            failure.unwrap()
        );
        return;
    } else if failure.is_some() && !test_case_description.fail {
        panic!(
            "unexpected error occurred while serializing Sign1 object: {:?}",
            failure.unwrap()
        )
    }

    let sign1_redeserialized = match CoseSign1::from_tagged_slice(sign1_serialized.as_slice())
        .or_else(|e1| {
            CoseSign1::from_slice(sign1_serialized.as_slice())
                .map_err(|e2| Result::<CoseSign1, (CoseError, CoseError)>::Err((e1, e2)))
        }) {
        Ok(v) => v,
        e => {
            if test_case_description.fail {
                println!("test case failed as expected. Error: {:?}", e);
                return;
            } else {
                e.expect("unable to deserialize test case data");
                unreachable!()
            }
        }
    };

    verify_sign1_test_case(
        &mut backend,
        &sign1_redeserialized,
        &sign1_cfg,
        test_case_description.fail,
        sign1_cfg.external.as_slice(),
    )
}

#[rstest]
fn cose_examples_ecdsa_sign1_reference_output(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] mut backend: impl CoseSignCipher,
) {
    perform_sign1_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_ecdsa_sign1_self_signed(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-sig-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign1_self_signed_test(test_path, backend)
}

#[rstest]
fn cose_examples_sign1_reference_output(
    #[files("tests/cose_examples/sign1-tests/sign-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign1_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_sign1_self_signed(
    #[files("tests/cose_examples/sign1-tests/sign-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign1_self_signed_test(test_path, backend)
}
