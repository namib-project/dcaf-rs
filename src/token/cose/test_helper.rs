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

use core::fmt::Debug;
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "openssl")]
use crate::token::cose::crypto_impl::openssl::OpensslContext;
#[cfg(rustcrypto_base)]
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::CryptoBackend;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use coset::iana::EnumI64;
use coset::{
    iana, Algorithm, AsCborValue, CborSerializable, CoseError, CoseKey, CoseKeyBuilder,
    CoseRecipientBuilder, Header, HeaderBuilder, Label, TaggedCborSerializable,
};
#[cfg(rustcrypto_base)]
use rand::rngs::ThreadRng;
use rstest::fixture;
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;

/// Deserialize a key from a test case JSON file.
fn deserialize_key<'de, D>(deserializer: D) -> Result<CoseKey, D::Error>
where
    D: Deserializer<'de>,
{
    let key_obj = serde_json::Map::deserialize(deserializer)?;
    match key_obj.get("kty").and_then(Value::as_str) {
        Some("EC") => {
            let curve = match key_obj.get("crv").and_then(Value::as_str) {
                Some("P-256") => iana::EllipticCurve::P_256,
                Some("P-384") => iana::EllipticCurve::P_384,
                Some("P-521") => iana::EllipticCurve::P_521,
                _ => return Err(de::Error::custom("COSE key does not have valid curve")),
            };

            let x = if let Some(v) = key_obj
                .get("x")
                .and_then(Value::as_str)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };

            let y = if let Some(v) = key_obj
                .get("y")
                .and_then(Value::as_str)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid y"));
            };
            let d = if let Some(v) = key_obj
                .get("d")
                .and_then(Value::as_str)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid d"));
            };

            let mut builder = CoseKeyBuilder::new_ec2_priv_key(curve, x, y, d);

            if let Some(v) = key_obj.get("kid").and_then(Value::as_str) {
                builder = builder.key_id(v.to_string().into_bytes());
            }

            Ok(builder.build())
        }
        Some("oct") => {
            let k = if let Some(v) = key_obj
                .get("k")
                .and_then(Value::as_str)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid k"));
            };

            let mut builder = CoseKeyBuilder::new_symmetric_key(k);

            if let Some(v) = key_obj.get("kid").and_then(Value::as_str) {
                builder = builder.key_id(v.to_string().into_bytes());
            }

            Ok(builder.build())
        }
        _ => Err(de::Error::custom("COSE key does not have valid key type")),
    }
}

/// Parse a string to an [iana::Algorithm].
fn string_to_algorithm<'de, D: Deserializer<'de>>(
    alg: Option<&str>,
) -> Result<Option<iana::Algorithm>, D::Error> {
    match alg {
        Some("ES256") => Ok(Some(iana::Algorithm::ES256)),
        Some("ES384") => Ok(Some(iana::Algorithm::ES384)),
        Some("ES512") => Ok(Some(iana::Algorithm::ES512)),
        Some("A128GCM") => Ok(Some(iana::Algorithm::A128GCM)),
        Some("A192GCM") => Ok(Some(iana::Algorithm::A192GCM)),
        Some("A256GCM") => Ok(Some(iana::Algorithm::A256GCM)),
        Some("ChaCha-Poly1305") => Ok(Some(iana::Algorithm::ChaCha20Poly1305)),
        Some("AES-CCM-16-128/64") => Ok(Some(iana::Algorithm::AES_CCM_16_64_128)),
        Some("AES-CCM-16-256/64") => Ok(Some(iana::Algorithm::AES_CCM_16_64_256)),
        Some("AES-CCM-64-128/64") => Ok(Some(iana::Algorithm::AES_CCM_64_64_128)),
        Some("AES-CCM-64-256/64") => Ok(Some(iana::Algorithm::AES_CCM_64_64_256)),
        Some("AES-CCM-16-128/128") => Ok(Some(iana::Algorithm::AES_CCM_16_128_128)),
        Some("AES-CCM-16-256/128") => Ok(Some(iana::Algorithm::AES_CCM_16_128_256)),
        Some("AES-CCM-64-128/128") => Ok(Some(iana::Algorithm::AES_CCM_64_128_128)),
        Some("AES-CCM-64-256/128") => Ok(Some(iana::Algorithm::AES_CCM_64_128_256)),
        Some("A128KW") => Ok(Some(iana::Algorithm::A128KW)),
        Some("A192KW") => Ok(Some(iana::Algorithm::A192KW)),
        Some("A256KW") => Ok(Some(iana::Algorithm::A256KW)),
        Some("HS256") => Ok(Some(iana::Algorithm::HMAC_256_256)),
        Some("HS384") => Ok(Some(iana::Algorithm::HMAC_384_384)),
        Some("HS512") => Ok(Some(iana::Algorithm::HMAC_512_512)),
        Some("AES-MAC-128/64") => Ok(Some(iana::Algorithm::AES_MAC_128_64)),
        Some("AES-MAC-128/128") => Ok(Some(iana::Algorithm::AES_MAC_128_128)),
        Some("AES-MAC-256/64") => Ok(Some(iana::Algorithm::AES_MAC_256_64)),
        Some("AES-MAC-256/128") => Ok(Some(iana::Algorithm::AES_MAC_256_128)),
        Some("direct") => Ok(Some(iana::Algorithm::Direct)),
        None => Ok(None),
        _ => Err(de::Error::custom("could not parse test case algorithm")),
    }
}

/// Deserialize a header from a test case JSON file.
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

    if let Some(v) = hdr_obj.get("kid").and_then(Value::as_str) {
        builder = builder.key_id(v.to_string().into_bytes());
    }
    if let Some(v) = hdr_obj
        .get("kid_hex")
        .and_then(Value::as_str)
        .map(hex::decode)
    {
        builder = builder.key_id(v.map_err(|e| {
            de::Error::custom(format!("could not parse test case key ID hex: {e}"))
        })?);
    }

    if let Some(alg) = string_to_algorithm::<D>(hdr_obj.get("alg").and_then(Value::as_str))? {
        builder = builder.algorithm(alg);
    }

    builder = match hdr_obj.get("ctyp").and_then(Value::as_i64) {
        Some(v) => {
            let content_format = iana::CoapContentFormat::from_i64(v).ok_or(de::Error::custom(
                "could not parse test case content format",
            ))?;
            builder.content_format(content_format)
        }
        None => builder,
    };

    if let Some(partial_iv) = hdr_obj.get("partialIV_hex").and_then(Value::as_str) {
        let partial_iv = hex::decode(partial_iv).map_err(|e| {
            de::Error::custom(format!("could not parse test case partial IV hex: {e}"))
        })?;
        builder = builder.partial_iv(partial_iv);
    }

    Ok(Some(builder.build()))
}

/// Deserialize an algorithm from a test case JSON file.
fn deserialize_algorithm<'de, D>(deserializer: D) -> Result<Option<Algorithm>, D::Error>
where
    D: Deserializer<'de>,
{
    let alg = if let Some(alg) = Option::<Value>::deserialize(deserializer)? {
        alg
    } else {
        return Ok(None);
    };
    Ok(string_to_algorithm::<D>(alg.as_str())?.map(Algorithm::Assigned))
}

/// Test case parsed from a JSON file as it would be found in the cose-wg/Examples repository.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCase {
    pub title: String,
    pub description: Option<String>,
    #[serde(default)]
    pub fail: bool,
    pub input: TestCaseInput,
    pub intermediates: Option<TestCaseIntermediates>,
    #[serde(default)]
    pub output: TestCaseOutput,
}

/// Modifications that should be applied to a created COSE object to cause potential failures in a
/// JSON test case.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct TestCaseFailures {
    #[serde(rename = "ChangeTag")]
    pub change_tag: Option<u64>,
    #[serde(rename = "ChangeCBORTag")]
    pub change_cbor_tag: Option<u64>,
    #[serde(rename = "ChangeAttr")]
    pub change_attribute: Option<HashMap<String, Value>>,
    #[serde(
        rename = "AddProtected",
        deserialize_with = "deserialize_header",
        default
    )]
    pub add_protected_headers: Option<Header>,
    #[serde(
        rename = "RemoveProtected",
        deserialize_with = "deserialize_header",
        default
    )]
    pub remove_protected_headers: Option<Header>,
}

/// Inputs to a JSON-based test case.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseInput {
    pub plaintext: String,
    //#[serde(default)]
    //pub detached: bool,
    pub sign0: Option<TestCaseRecipient>,
    pub sign: Option<TestCaseSign>,
    pub encrypted: Option<TestCaseEncrypted>,
    pub enveloped: Option<TestCaseEncrypted>,
    pub mac0: Option<TestCaseMac>,
    pub mac: Option<TestCaseMac>,
    #[serde(default)]
    pub failures: TestCaseFailures,
}

/// Signature inputs to a JSON-based test case.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseSign {
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    pub signers: Vec<TestCaseRecipient>,
}

/// Data used for COSE object encryption that is not sent over the wire (e.g. the full IV if only a
/// partial IV is provided).
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseUnsent {
    #[serde(rename = "IV_hex", deserialize_with = "hex::deserialize", default)]
    pub iv: Vec<u8>,
}

/// Encryption inputs to a JSON-based test case.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseEncrypted {
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    pub unsent: Option<TestCaseUnsent>,
    #[serde(deserialize_with = "hex::deserialize", default)]
    pub external: Vec<u8>,
    pub recipients: Vec<TestCaseRecipient>,
}

/// MAC inputs to a JSON-based test case.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseMac {
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    #[serde(deserialize_with = "hex::deserialize", default)]
    pub external: Vec<u8>,
    pub recipients: Vec<TestCaseRecipient>,
}

/// Recipients for a JSON-based test case.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseRecipient {
    #[serde(deserialize_with = "deserialize_key")]
    pub key: CoseKey,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    #[serde(deserialize_with = "deserialize_algorithm", default)]
    pub alg: Option<Algorithm>,
    #[serde(deserialize_with = "hex::deserialize", default)]
    pub external: Vec<u8>,
    #[serde(default)]
    pub failures: TestCaseFailures,
}

impl From<TestCaseRecipient> for CoseRecipientBuilder {
    fn from(value: TestCaseRecipient) -> Self {
        let mut builder = CoseRecipientBuilder::new();
        if let Some(hdr) = value.unprotected {
            builder = builder.unprotected(hdr);
        }
        if let Some(hdr) = value.protected {
            builder = builder.protected(hdr);
        }
        builder
    }
}

/// Intermediates that should be used in a JSON-based test case.
#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseIntermediates {
    #[serde(rename = "CEK_hex", deserialize_with = "hex::deserialize", default)]
    pub cek: Vec<u8>,
}

/// Expected output of a JSON-based test case.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct TestCaseOutput {
    #[serde(deserialize_with = "hex::deserialize")]
    pub cbor: Vec<u8>,
}

/// Print some basic information about a JSON test case.
fn print_test_information(case: &TestCase) {
    println!("COSE Examples Test information:");
    println!("Name: {}", case.title);
    println!(
        "Description: {}",
        case.description.as_ref().map_or("None", String::as_str)
    );
    println!("Verification should fail: {}", case.fail);
}

/// Tests a JSON-based test case by attempting to deserialize and verify the expected output
/// provided in the JSON file.
///
/// Only tests the verification procedure, the creation procedure will not run here (as we use the
/// expected output from the JSON-file instead).
pub fn perform_cose_reference_output_test<T: CoseStructTestHelper<B>, B: CryptoBackend>(
    test_path: PathBuf,
    mut backend: B,
) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");
    print_test_information(&test_case_description);
    println!("Performing reference output test (deserializing and verifying the already serialized CBOR output provided by the test case description)...");

    let example_output = match <T as CoseStructTestHelper<B>>::from_test_case_output(
        test_case_description.output.cbor.as_slice(),
    ) {
        Ok(v) => v,
        Err(e) => {
            if test_case_description.fail {
                println!("test case failed as expected. Error: {e:?}");
                return;
            }
            panic!("unable to deserialize test case data");
        }
    };

    example_output.check_against_test_case(&test_case_description, &mut backend);
}

/// Tests a JSON-based test case by attempting to construct the COSE structure described in it,
/// applying the appropriate encryption/signing/authentication operation, and then attempting to
/// deserialize and verify the resulting structure.
///
/// Unlike [perform_cose_reference_output_test], this tests both creation and verification
/// procedures.
pub fn perform_cose_self_signed_test<T: CoseStructTestHelper<B>, B: CryptoBackend>(
    test_path: PathBuf,
    mut backend: B,
) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");
    print_test_information(&test_case_description);
    println!("Performing self-signed test (creating and signing the object ourselves, then verifying both the signature and equality to test case description)...");

    let structure = T::from_test_case(&test_case_description, &mut backend);

    let v = match <T as CoseStructTestHelper<B>>::serialize_and_apply_failures(
        structure,
        &test_case_description,
    ) {
        Ok(v) => v,
        Err(e) => {
            if test_case_description.fail {
                println!("serialization failed as expected for test case: {e}");
                return;
            }
            panic!("unexpected error occurred while serializing COSE object: {e}")
        }
    };

    let redeserialized = match <T as CoseStructTestHelper<B>>::from_test_case_output(v.as_slice()) {
        Ok(v) => v,
        Err(e) => {
            if test_case_description.fail {
                println!("deserialization failed as expected for test case: {e}");
                return;
            }
            panic!("unexpected error occurred while deserializing COSE structure: {e}")
        }
    };
    redeserialized.check_against_test_case(&test_case_description, &mut backend);
}

/// Helper methods to perform operations on COSE structures based on a parsed test case.
pub trait CoseStructTestHelper<B: CryptoBackend>:
    Sized + CborSerializable + TaggedCborSerializable
{
    /// Deserialize an expected test case output into a COSE structure of this type.
    fn from_test_case_output(output: &[u8]) -> Result<Self, CoseError> {
        Self::from_tagged_slice(output).or_else(|_e1| Self::from_slice(output))
    }

    /// Attempts to create and encrypt/sign/calculate a MAC for this COSE structure based on its
    /// description in a test case.
    fn from_test_case(case: &TestCase, backend: &mut B) -> Self;

    /// Serialize this COSE structure, applying possible modifications as described in the test
    /// case's [TestCaseFailures] instance.
    fn serialize_and_apply_failures(self, case: &TestCase) -> Result<Vec<u8>, CoseError>;

    /// Checks whether this COSE structure's fields match those provided in a test case.
    fn check_against_test_case(&self, case: &TestCase, backend: &mut B);
}

/// Apply failures to `hdr` based on a description given in `failures`.
pub(crate) fn apply_header_failures(hdr: &mut Header, failures: &TestCaseFailures) {
    if let Some(headers_to_remove) = &failures.remove_protected_headers {
        if !headers_to_remove.key_id.is_empty() {
            hdr.key_id = Vec::new();
        }
        if !headers_to_remove.counter_signatures.is_empty() {
            hdr.counter_signatures = Vec::new();
        }
        if headers_to_remove.alg.is_some() {
            hdr.alg = None;
        }
        if headers_to_remove.content_type.is_some() {
            hdr.content_type = None;
        }
        if !headers_to_remove.crit.is_empty() {
            hdr.crit = Vec::new();
        }
        if !headers_to_remove.iv.is_empty() {
            hdr.iv = Vec::new();
        }
        if !headers_to_remove.partial_iv.is_empty() {
            hdr.partial_iv = Vec::new();
        }
        let removed_fields = headers_to_remove
            .rest
            .iter()
            .map(|(label, _hdr)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let new_headers = hdr
            .rest
            .iter()
            .filter(|(label, _hdr)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        hdr.rest = new_headers;
    }

    if let Some(headers_to_add) = &failures.add_protected_headers {
        if !headers_to_add.key_id.is_empty() {
            hdr.key_id.clone_from(&headers_to_add.key_id);
        }
        if !headers_to_add.counter_signatures.is_empty() {
            hdr.counter_signatures
                .clone_from(&headers_to_add.counter_signatures);
        }
        if let Some(new_val) = &headers_to_add.alg {
            hdr.alg = Some(new_val.clone());
        }
        if let Some(new_val) = &headers_to_add.content_type {
            hdr.content_type = Some(new_val.clone());
        }
        if !headers_to_add.crit.is_empty() {
            hdr.crit.clone_from(&headers_to_add.crit);
        }
        if !headers_to_add.iv.is_empty() {
            hdr.iv.clone_from(&headers_to_add.iv);
        }
        if !headers_to_add.partial_iv.is_empty() {
            hdr.partial_iv.clone_from(&headers_to_add.partial_iv);
        }

        let removed_fields = headers_to_add
            .rest
            .iter()
            .map(|(label, _hdr)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let mut new_headers = hdr
            .rest
            .iter()
            .filter(|(label, _hdr)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        new_headers.append(&mut headers_to_add.rest.clone());
        hdr.rest = new_headers;
    }
}

/// Serialize the given COSE structure, applying possible failures that concern the entire
/// serialized structure (such as modifying the CBOR tag).
pub(crate) fn serialize_cose_with_failures<T: AsCborValue + TaggedCborSerializable>(
    value: T,
    failures: &TestCaseFailures,
) -> Vec<u8> {
    if let Some(new_tag) = &failures.change_cbor_tag {
        let untagged_value = value
            .to_cbor_value()
            .expect("unable to generate CBOR value of COSE structure");
        ciborium::Value::Tag(*new_tag, Box::new(untagged_value))
            .to_vec()
            .expect("unable to serialize CBOR value")
    } else {
        value
            .to_tagged_vec()
            .expect("unable to generate CBOR value of CoseSign1")
    }
}

/// Apply attribute modifications causing failures to `header` based on a description given in
/// `failures`.
///
/// Unlike [apply_header_failures], these changes might be applied in other places instead of the
/// `header`, this was just the most convenient way of implementing them.
// CLion does not understand that `v` is actually used in the format string.
// Clippy should still detect any such issues, though.
//noinspection RsLiveness
pub(crate) fn apply_attribute_failures(
    header: &mut Header,
    failures: &TestCaseFailures,
) -> Result<(), CoseError> {
    if let Some(attribute_changes) = &failures.change_attribute {
        match attribute_changes.get("alg") {
            None => Ok(()),
            Some(Value::Number(v)) => {
                let cbor_value = ciborium::Value::Integer(ciborium::value::Integer::from(
                    v.as_i64().expect("unable to parse algorithm number"),
                ));
                match Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        header.alg = Some(value);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            Some(Value::String(v)) => {
                let cbor_value = ciborium::Value::Text(v.to_string());
                match Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        header.alg = Some(value);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            v => panic!("unable to set algorithm to {v:?}"),
        }
    } else {
        Ok(())
    }
}

/// Determines the Base IV field for a test case based on the full IV provided as an unsent test
/// input and the partial IV provided in the key itself.
// Nobody knows why the people who wrote the test cases in the cose-wg/Examples thought that this
// would be better than just providing partial IV and base IV directly.
pub(crate) fn calculate_base_iv(unsent: &TestCaseUnsent, partial_iv: &Vec<u8>) -> Vec<u8> {
    let full_iv = &unsent.iv;
    let mut base_iv = vec![0u8; full_iv.len()];
    base_iv[full_iv.len() - partial_iv.len()..].clone_from_slice(partial_iv.as_slice());
    base_iv
        .iter_mut()
        .zip(full_iv)
        .for_each(|(b1, b2)| *b1 ^= b2);
    base_iv
}

/*pub struct RngMockCipher<T: CoseEncryptCipher> {
    rng_outputs: Vec<Vec<u8>>,
    cipher: T,
}

impl<T: CoseEncryptCipher> CoseCipher for RngMockCipher<T> {
    type Error = <T as CoseCipher>::Error;
    // TODO reproducible outputs by mocking the RNG
    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>> {
        todo!()
    }
}*/

#[cfg(feature = "openssl")]
#[fixture]
pub(crate) fn openssl_ctx() -> OpensslContext {
    OpensslContext::new()
}

#[cfg(rustcrypto_base)]
#[fixture]
pub(crate) fn rustcrypto_ctx() -> RustCryptoContext<ThreadRng> {
    RustCryptoContext::new(rand::thread_rng())
}
