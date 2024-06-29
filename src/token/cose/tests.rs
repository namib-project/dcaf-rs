use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::sign::{CoseSign1Ext, CoseSignExt};
use crate::token::CoseSign1BuilderExt;
use crate::CoseSignCipher;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use core::fmt::Formatter;
use coset::iana::{Algorithm, EnumI64};
use coset::{
    iana, AsCborValue, CborSerializable, CoseError, CoseKey, CoseKeyBuilder, CoseSign, CoseSign1,
    CoseSign1Builder, CoseSignature, Header, HeaderBuilder, Label, TaggedCborSerializable,
};
use hex::FromHex;
use openssl::sign::Signer;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn deserialize_key<'de, D>(deserializer: D) -> Result<CoseKey, D::Error>
where
    D: Deserializer<'de>,
{
    let key_obj = serde_json::Map::deserialize(deserializer)?;
    match key_obj.get("kty").map(Value::as_str).flatten() {
        Some("EC") => {
            let curve = match key_obj.get("crv").map(Value::as_str).flatten() {
                Some("P-256") => iana::EllipticCurve::P_256,
                Some("P-384") => iana::EllipticCurve::P_384,
                Some("P-521") => iana::EllipticCurve::P_521,
                _ => return Err(de::Error::custom("COSE key does not have valid curve")),
            };

            let x = if let Some(v) = key_obj
                .get("x")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };

            let y = if let Some(v) = key_obj
                .get("y")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };
            let d = if let Some(v) = key_obj
                .get("d")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };

            let mut builder = CoseKeyBuilder::new_ec2_priv_key(curve, x, y, d);

            if let Some(v) = key_obj.get("kid").map(Value::as_str).flatten() {
                builder = builder.key_id(v.to_string().into_bytes())
            }

            Ok(builder.build())
        }
        _ => Err(de::Error::custom("COSE key does not have valid key type")),
    }
}

fn deserialize_header<'de, D>(deserializer: D) -> Result<Option<Header>, D::Error>
where
    D: Deserializer<'de>,
{
    let hdr_obj =
        if let Some(hdr) = Option::<serde_json::Map<String, Value>>::deserialize(deserializer)? {
            hdr
        } else {
            return Ok(None);
        };

    let mut builder = HeaderBuilder::new();

    if let Some(v) = hdr_obj.get("kid").map(Value::as_str).flatten() {
        builder = builder.key_id(v.to_string().into_bytes());
    }
    if let Some(v) = hdr_obj
        .get("kid_hex")
        .map(Value::as_str)
        .flatten()
        .map(hex::decode)
    {
        builder = builder
            .key_id(v.map_err(|e| de::Error::custom("could not parse test case key ID hex"))?);
    }

    builder = match hdr_obj.get("alg").map(Value::as_str).flatten() {
        Some("ES256") => builder.algorithm(Algorithm::ES256),
        Some("ES384") => builder.algorithm(Algorithm::ES384),
        Some("ES512") => builder.algorithm(Algorithm::ES512),
        Some(_) => return Err(de::Error::custom("could not parse test case algorithm")),
        None => builder,
    };

    builder = match hdr_obj.get("ctyp").map(Value::as_i64).flatten() {
        Some(v) => {
            let content_format = iana::CoapContentFormat::from_i64(v)
                .ok_or(de::Error::custom("could not parse test case algorithm"))?;
            builder.content_format(content_format)
        }
        None => builder,
    };

    Ok(Some(builder.build()))
}

fn deserialize_algorithm<'de, D>(deserializer: D) -> Result<Option<Algorithm>, D::Error>
where
    D: Deserializer<'de>,
{
    let alg = if let Some(alg) = Option::<Value>::deserialize(deserializer)? {
        alg
    } else {
        return Ok(None);
    };
    match alg.as_str() {
        Some("ES256") => Ok(Some(Algorithm::ES256)),
        Some("ES384") => Ok(Some(Algorithm::ES384)),
        Some("ES512") => Ok(Some(Algorithm::ES512)),
        _ => Err(de::Error::custom("could not parse test case algorithm")),
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCase {
    title: String,
    description: Option<String>,
    #[serde(default)]
    fail: bool,
    input: TestCaseInput,
    intermediates: Option<TestCaseIntermediates>,
    output: TestCaseOutput,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct TestCaseFailures {
    #[serde(rename = "ChangeTag")]
    change_payload: Option<u64>,
    #[serde(rename = "ChangeCBORTag")]
    change_cbor_tag: Option<u64>,
    #[serde(rename = "ChangeAttr")]
    change_attribute: Option<HashMap<String, Value>>,
    #[serde(
        rename = "AddProtected",
        deserialize_with = "deserialize_header",
        default
    )]
    add_protected_headers: Option<Header>,
    #[serde(
        rename = "RemoveProtected",
        deserialize_with = "deserialize_header",
        default
    )]
    remove_protected_headers: Option<Header>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseInput {
    plaintext: String,
    #[serde(default)]
    detached: bool,
    sign0: Option<TestCaseSigner>,
    sign: Option<TestCaseSign>,
    #[serde(default)]
    failures: TestCaseFailures,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseSign {
    #[serde(deserialize_with = "deserialize_header", default)]
    unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    protected: Option<Header>,
    signers: Vec<TestCaseSigner>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseSigner {
    #[serde(deserialize_with = "deserialize_key")]
    key: CoseKey,
    #[serde(deserialize_with = "deserialize_header", default)]
    unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    protected: Option<Header>,
    #[serde(deserialize_with = "deserialize_algorithm", default)]
    alg: Option<Algorithm>,
    #[serde(deserialize_with = "hex::deserialize", default)]
    external: Vec<u8>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseIntermediates {}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseOutput {
    #[serde(deserialize_with = "hex::deserialize")]
    cbor: Vec<u8>,
}

fn serialize_sign1_and_apply_failures(
    test_case_input: &TestCaseInput,
    key: &mut CoseKey,
    mut value: CoseSign1,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(1) = &test_case_input.failures.change_payload {
        value.payload = Some("hi".to_string().into_bytes());
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
    test_case_input: &TestCaseInput,
    key: &mut CoseKey,
    mut value: CoseSign,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(1) = &test_case_input.failures.change_payload {
        value.payload = Some("hi".to_string().into_bytes());
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

    let mut alg_change_error = None;
    for signature in &mut value.signatures {
        if let Some(err) = apply_failures_to_signer(&test_case_input, key, signature) {
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
    test_case_input: &TestCaseInput,
    key: &mut CoseKey,
    value: &mut CoseSignature,
) -> Option<CoseError> {
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

    if let Some(attribute_changes) = &test_case_input.failures.change_attribute {
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
    let keys: Vec<&CoseKey> = test_case.signers.iter().map(|v| &v.key).collect();
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
