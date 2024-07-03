#![cfg(all(test, feature = "std"))]

use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
    TestCaseFailures, TestCaseInput, TestCaseSign,
};
use crate::CoseSignCipher;
use base64::Engine;
use coset::iana::EnumI64;
use coset::{
    AsCborValue, CborSerializable, CoseError, CoseKey, CoseSign, CoseSign1, CoseSignBuilder,
    CoseSignature, CoseSignatureBuilder, Header, TaggedCborSerializable,
};
use hex::FromHex;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::any::Any;
use std::path::PathBuf;

fn serialize_sign_and_apply_failures(
    test_case_input: &mut TestCaseInput,
    mut value: CoseSign,
) -> (Option<CoseError>, Vec<u8>) {
    apply_header_failures(&mut value.protected.header, &test_case_input.failures);

    let mut alg_change_error = None;
    let mut signers = test_case_input
        .sign
        .as_mut()
        .unwrap()
        .signers
        .iter_mut()
        .zip(&mut value.signatures);
    for (signer, signature) in signers {
        if let Some(err) = apply_failures_to_signer(&signer.failures, &mut signer.key, signature) {
            alg_change_error = Some(err);
        };
    }

    let serialized_data = serialize_cose_with_failures(value, &test_case_input.failures);

    (alg_change_error, serialized_data)
}

fn apply_failures_to_signer(
    failures: &TestCaseFailures,
    key: &mut CoseKey,
    value: &mut CoseSignature,
) -> Option<CoseError> {
    if let Some(1) = &failures.change_tag {
        let byte = value.signature.first_mut().unwrap();
        *byte = byte.wrapping_add(1);
    }

    apply_header_failures(&mut value.protected.header, &failures);

    apply_attribute_failures(key, &failures)
}

fn verify_sign_test_case<T: CoseSignCipher>(
    backend: &mut T,
    sign: &CoseSign,
    test_case: &TestCaseSign,
    should_fail: bool,
) {
    let keys: Vec<CoseKey> = test_case
        .signers
        .iter()
        .map(|v| {
            let mut key_with_alg = v.key.clone();
            if key_with_alg.alg.is_none() {
                key_with_alg.alg = v.alg.map(|a| coset::Algorithm::Assigned(a));
            }
            key_with_alg
        })
        .collect();
    let mut aads = test_case.signers.iter().map(|v| v.external.as_slice());

    let verify_result = sign.try_verify(backend, &mut &keys, false, &mut &mut aads);

    if should_fail {
        verify_result.expect_err("invalid token was successfully verified");
    } else {
        verify_result.expect("unable to verify token");

        let empty_hdr = Header::default();
        assert_eq!(
            test_case.unprotected.as_ref().unwrap_or(&empty_hdr),
            &sign.unprotected
        );
        assert_eq!(
            test_case.protected.as_ref().unwrap_or(&empty_hdr),
            &sign.protected.header
        );
        for (signer, signature) in test_case.signers.iter().zip(sign.signatures.iter()) {
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

fn perform_sign_reference_output_test(test_path: PathBuf, mut backend: impl CoseSignCipher) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let sign_cfg = test_case_description
        .input
        .sign
        .expect("expected a CoseSign test case, but it was not found");

    let example_output = match CoseSign::from_tagged_slice(
        test_case_description.output.cbor.as_slice(),
    )
    .or_else(|e1| {
        CoseSign::from_slice(test_case_description.output.cbor.as_slice())
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

    verify_sign_test_case(
        &mut backend,
        &example_output,
        &sign_cfg,
        test_case_description.fail,
    )
}

fn perform_sign_self_signed_test(test_path: PathBuf, mut backend: impl CoseSignCipher) {
    let mut test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut sign_cfg = test_case_description
        .input
        .sign
        .as_mut()
        .expect("expected a CoseSign test case, but it was not found");

    let mut builder = CoseSignBuilder::new();

    let mut sign = builder.payload(test_case_description.input.plaintext.clone().into_bytes());

    if let Some(unprotected) = &sign_cfg.unprotected {
        sign = sign.unprotected(unprotected.clone())
    }
    if let Some(protected) = &sign_cfg.protected {
        sign = sign.protected(protected.clone())
    }
    for signer in &mut sign_cfg.signers {
        let mut signature = CoseSignatureBuilder::new();

        if let Some(unprotected) = &signer.unprotected {
            signature = signature.unprotected(unprotected.clone())
        }
        if let Some(protected) = &signer.protected {
            signature = signature.protected(protected.clone())
        }
        sign = sign
            .try_add_sign::<_, &CoseKey, &[u8]>(
                &mut backend,
                &mut &signer.key,
                signature.build(),
                &mut signer.external.as_slice(),
            )
            .expect("unable to sign Sign object")
    }

    let (failure, sign_serialized) =
        serialize_sign_and_apply_failures(&mut test_case_description.input, sign.build());

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

    let sign_redeserialized =
        match CoseSign::from_tagged_slice(sign_serialized.as_slice()).or_else(|e1| {
            CoseSign::from_slice(sign_serialized.as_slice())
                .map_err(|e2| Result::<CoseSign, (CoseError, CoseError)>::Err((e1, e2)))
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

    verify_sign_test_case(
        &mut backend,
        &sign_redeserialized,
        &test_case_description
            .input
            .sign
            .as_ref()
            .expect("expected a CoseSign test case, but it was not found"),
        test_case_description.fail,
    )
}

#[rstest]
fn cose_examples_ecdsa_sign_reference_output(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-0*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_ecdsa_sign_self_signed(
    #[files("tests/cose_examples/ecdsa-examples/ecdsa-0*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign_self_signed_test(test_path, backend)
}

#[rstest]
fn cose_examples_sign_reference_output(
    #[files("tests/cose_examples/sign-tests/sign-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_sign_self_signed(
    #[files("tests/cose_examples/sign-tests/sign-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseSignCipher,
) {
    perform_sign_self_signed_test(test_path, backend)
}
