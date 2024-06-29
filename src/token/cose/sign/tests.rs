use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    TestCase, TestCaseFailures, TestCaseInput, TestCaseSign, TestCaseSigner,
};
use crate::CoseSignCipher;
use base64::Engine;
use coset::iana::EnumI64;
use coset::{
    AsCborValue, CborSerializable, CoseError, CoseKey, CoseSign, CoseSign1, CoseSign1Builder,
    CoseSignBuilder, CoseSignature, CoseSignatureBuilder, Header, Label, TaggedCborSerializable,
};
use hex::FromHex;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
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

    if let Some(headers_to_remove) = &test_case_input.failures.remove_protected_headers {
        if !headers_to_remove.key_id.is_empty() {
            value.protected.header.key_id = Vec::new();
        }
        if !headers_to_remove.counter_signatures.is_empty() {
            value.protected.header.counter_signatures = Vec::new();
        }
        if let Some(new_val) = &headers_to_remove.alg {
            value.protected.header.alg = None
        }
        if let Some(new_val) = &headers_to_remove.content_type {
            value.protected.header.content_type = None
        }
        if !headers_to_remove.crit.is_empty() {
            value.protected.header.crit = Vec::new();
        }
        if !headers_to_remove.iv.is_empty() {
            value.protected.header.iv = Vec::new();
        }
        if !headers_to_remove.partial_iv.is_empty() {
            value.protected.header.partial_iv = Vec::new()
        }
        let removed_fields = headers_to_remove
            .rest
            .iter()
            .map(|(label, _value)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let new_headers = value
            .protected
            .header
            .rest
            .iter()
            .filter(|(label, _value)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        value.protected.header.rest = new_headers
    }

    if let Some(headers_to_add) = &test_case_input.failures.add_protected_headers {
        if !headers_to_add.key_id.is_empty() {
            value.protected.header.key_id = headers_to_add.key_id.clone();
        }
        if !headers_to_add.counter_signatures.is_empty() {
            value.protected.header.counter_signatures = headers_to_add.counter_signatures.clone();
        }
        if let Some(new_val) = &headers_to_add.alg {
            value.protected.header.alg = Some(new_val.clone())
        }
        if let Some(new_val) = &headers_to_add.content_type {
            value.protected.header.content_type = Some(new_val.clone())
        }
        if !headers_to_add.crit.is_empty() {
            value.protected.header.crit = headers_to_add.crit.clone();
        }
        if !headers_to_add.iv.is_empty() {
            value.protected.header.iv = headers_to_add.iv.clone();
        }
        if !headers_to_add.partial_iv.is_empty() {
            value.protected.header.partial_iv = headers_to_add.partial_iv.clone();
        }

        let removed_fields = headers_to_add
            .rest
            .iter()
            .map(|(label, _value)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let mut new_headers = value
            .protected
            .header
            .rest
            .iter()
            .filter(|(label, _value)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        new_headers.append(&mut headers_to_add.rest.clone());
        value.protected.header.rest = new_headers
    }

    let serialized_data = if let Some(new_tag) = &test_case_input.failures.change_cbor_tag {
        let untagged_value = value
            .to_cbor_value()
            .expect("unable to generate CBOR value of CoseSign1");
        ciborium::Value::Tag(*new_tag, Box::new(untagged_value))
            .to_vec()
            .expect("unable to serialize CBOR value")
    } else {
        value
            .to_tagged_vec()
            .expect("unable to generate CBOR value of CoseSign1")
    };

    if let Some(attribute_changes) = &test_case_input.failures.change_attribute {
        match attribute_changes.get("alg") {
            None => (None, serialized_data),
            Some(Value::Number(v)) => {
                let cbor_value = ciborium::Value::Integer(ciborium::value::Integer::from(
                    v.as_i64().expect("unable to parse algorithm number"),
                ));
                match coset::Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        key.alg = Some(value);
                        (None, serialized_data)
                    }
                    Err(e) => (Some(e), serialized_data),
                }
            }
            Some(Value::String(v)) => {
                let cbor_value = ciborium::Value::Text(v.to_string());
                match coset::Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        key.alg = Some(value);
                        (None, serialized_data)
                    }
                    Err(e) => (Some(e), serialized_data),
                }
            }
            v => panic!("unable to set algorithm to {:?}", v),
        }
    } else {
        (None, serialized_data)
    }
}

fn verify_sign1_test_case<T: CoseSignCipher>(
    backend: &mut T,
    sign1: &CoseSign1,
    test_case: &TestCaseSigner,
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
            &sign1_cfg.key,
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

fn serialize_sign_and_apply_failures(
    test_case_input: &mut TestCaseInput,
    mut value: CoseSign,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(headers_to_remove) = &test_case_input.failures.remove_protected_headers {
        if !headers_to_remove.key_id.is_empty() {
            value.protected.header.key_id = Vec::new();
        }
        if !headers_to_remove.counter_signatures.is_empty() {
            value.protected.header.counter_signatures = Vec::new();
        }
        if let Some(new_val) = &headers_to_remove.alg {
            value.protected.header.alg = None
        }
        if let Some(new_val) = &headers_to_remove.content_type {
            value.protected.header.content_type = None
        }
        if !headers_to_remove.crit.is_empty() {
            value.protected.header.crit = Vec::new();
        }
        if !headers_to_remove.iv.is_empty() {
            value.protected.header.iv = Vec::new();
        }
        if !headers_to_remove.partial_iv.is_empty() {
            value.protected.header.partial_iv = Vec::new()
        }
        let removed_fields = headers_to_remove
            .rest
            .iter()
            .map(|(label, _value)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let new_headers = value
            .protected
            .header
            .rest
            .iter()
            .filter(|(label, _value)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        value.protected.header.rest = new_headers
    }

    if let Some(headers_to_add) = &test_case_input.failures.add_protected_headers {
        if !headers_to_add.key_id.is_empty() {
            value.protected.header.key_id = headers_to_add.key_id.clone();
        }
        if !headers_to_add.counter_signatures.is_empty() {
            value.protected.header.counter_signatures = headers_to_add.counter_signatures.clone();
        }
        if let Some(new_val) = &headers_to_add.alg {
            value.protected.header.alg = Some(new_val.clone())
        }
        if let Some(new_val) = &headers_to_add.content_type {
            value.protected.header.content_type = Some(new_val.clone())
        }
        if !headers_to_add.crit.is_empty() {
            value.protected.header.crit = headers_to_add.crit.clone();
        }
        if !headers_to_add.iv.is_empty() {
            value.protected.header.iv = headers_to_add.iv.clone();
        }
        if !headers_to_add.partial_iv.is_empty() {
            value.protected.header.partial_iv = headers_to_add.partial_iv.clone();
        }

        let removed_fields = headers_to_add
            .rest
            .iter()
            .map(|(label, _value)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let mut new_headers = value
            .protected
            .header
            .rest
            .iter()
            .filter(|(label, _value)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        new_headers.append(&mut headers_to_add.rest.clone());
        value.protected.header.rest = new_headers
    }

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

    let serialized_data = if let Some(new_tag) = &test_case_input.failures.change_cbor_tag {
        let untagged_value = value
            .to_cbor_value()
            .expect("unable to generate CBOR value of CoseSign1");
        ciborium::Value::Tag(*new_tag, Box::new(untagged_value))
            .to_vec()
            .expect("unable to serialize CBOR value")
    } else {
        value
            .to_tagged_vec()
            .expect("unable to generate CBOR value of CoseSign1")
    };

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

    if let Some(headers_to_remove) = &failures.remove_protected_headers {
        if !headers_to_remove.key_id.is_empty() {
            value.protected.header.key_id = Vec::new();
        }
        if !headers_to_remove.counter_signatures.is_empty() {
            value.protected.header.counter_signatures = Vec::new();
        }
        if let Some(new_val) = &headers_to_remove.alg {
            value.protected.header.alg = None
        }
        if let Some(new_val) = &headers_to_remove.content_type {
            value.protected.header.content_type = None
        }
        if !headers_to_remove.crit.is_empty() {
            value.protected.header.crit = Vec::new();
        }
        if !headers_to_remove.iv.is_empty() {
            value.protected.header.iv = Vec::new();
        }
        if !headers_to_remove.partial_iv.is_empty() {
            value.protected.header.partial_iv = Vec::new()
        }
        let removed_fields = headers_to_remove
            .rest
            .iter()
            .map(|(label, _value)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let new_headers = value
            .protected
            .header
            .rest
            .iter()
            .filter(|(label, _value)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        value.protected.header.rest = new_headers
    }

    if let Some(headers_to_add) = &failures.add_protected_headers {
        if !headers_to_add.key_id.is_empty() {
            value.protected.header.key_id = headers_to_add.key_id.clone();
        }
        if !headers_to_add.counter_signatures.is_empty() {
            value.protected.header.counter_signatures = headers_to_add.counter_signatures.clone();
        }
        if let Some(new_val) = &headers_to_add.alg {
            value.protected.header.alg = Some(new_val.clone())
        }
        if let Some(new_val) = &headers_to_add.content_type {
            value.protected.header.content_type = Some(new_val.clone())
        }
        if !headers_to_add.crit.is_empty() {
            value.protected.header.crit = headers_to_add.crit.clone();
        }
        if !headers_to_add.iv.is_empty() {
            value.protected.header.iv = headers_to_add.iv.clone();
        }
        if !headers_to_add.partial_iv.is_empty() {
            value.protected.header.partial_iv = headers_to_add.partial_iv.clone();
        }

        let removed_fields = headers_to_add
            .rest
            .iter()
            .map(|(label, _value)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let mut new_headers = value
            .protected
            .header
            .rest
            .iter()
            .filter(|(label, _value)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        new_headers.append(&mut headers_to_add.rest.clone());
        value.protected.header.rest = new_headers
    }

    if let Some(attribute_changes) = &failures.change_attribute {
        match attribute_changes.get("alg") {
            None => None,
            Some(Value::Number(v)) => {
                let cbor_value = ciborium::Value::Integer(ciborium::value::Integer::from(
                    v.as_i64().expect("unable to parse algorithm number"),
                ));
                match coset::Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        key.alg = Some(value);
                        None
                    }
                    Err(e) => Some(e),
                }
            }
            Some(Value::String(v)) => {
                let cbor_value = ciborium::Value::Text(v.to_string());
                match coset::Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        key.alg = Some(value);
                        None
                    }
                    Err(e) => Some(e),
                }
            }
            v => panic!("unable to set algorithm to {:?}", v),
        }
    } else {
        None
    }
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

    let verify_result = sign.try_verify(backend, &mut &keys, false, &mut aads);

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
