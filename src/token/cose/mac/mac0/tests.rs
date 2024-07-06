#![cfg(all(test, feature = "std"))]
use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher, HeaderBuilderExt};
use crate::token::cose::header_util::determine_algorithm;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey};
use crate::token::cose::mac::mac::CoseMacExt;
use crate::token::cose::mac::mac0::{CoseMac0BuilderExt, CoseMac0Ext};
use crate::token::cose::mac::CoseMacCipher;
use crate::token::cose::recipient::CoseRecipientBuilderExt;
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
    TestCaseEncrypted, TestCaseFailures, TestCaseMac,
};
use crate::CoseSignCipher;
use base64::Engine;
use coset::iana::{Algorithm, EnumI64};
use coset::{
    AsCborValue, CborSerializable, CoseError, CoseKey, CoseKeyBuilder, CoseMac, CoseMac0,
    CoseMac0Builder, CoseMacBuilder, CoseRecipientBuilder, CoseSign1, EncryptionContext, Header,
    HeaderBuilder, TaggedCborSerializable,
};
use hex::FromHex;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::any::Any;
use std::convert::Infallible;
use std::path::PathBuf;

fn serialize_mac0_and_apply_failures(
    failures: &mut TestCaseFailures,
    key: &mut CoseKey,
    mut value: CoseMac0,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(1) = &failures.change_tag {
        let byte = value
            .payload
            .as_mut()
            .expect("Mac0 has no payload, can't apply failure")
            .first_mut()
            .unwrap();
        *byte = byte.wrapping_add(1);
    }

    apply_header_failures(&mut value.protected.header, &failures);

    let serialized_data = serialize_cose_with_failures(value, &failures);

    (apply_attribute_failures(key, &failures), serialized_data)
}

fn verify_mac0_test_case<T: CoseMacCipher + CoseKeyDistributionCipher>(
    backend: &mut T,
    mac: &CoseMac0,
    test_case: &mut TestCaseMac,
    expected_plaintext: &[u8],
    should_fail: bool,
) {
    let keys: Vec<CoseKey> = test_case
        .recipients
        .iter()
        .map(|v| {
            let mut key_with_alg = v.key.clone();
            if key_with_alg.alg.is_none() {
                key_with_alg.alg = v.alg.map(|a| coset::Algorithm::Assigned(a));
            }
            key_with_alg
        })
        .collect();
    let mut aad = test_case.external.as_slice();

    let verify_result = mac.try_verify(backend, &mut &keys, false, &mut aad);

    if should_fail {
        verify_result.expect_err("invalid token was successfully verified");
    } else {
        let plaintext = verify_result.expect("unable to verify token");

        assert_eq!(
            &expected_plaintext,
            &mac.payload
                .as_ref()
                .map(Vec::as_slice)
                .unwrap_or(&[] as &[u8])
        );
        let empty_hdr = Header::default();
        assert_eq!(
            test_case.unprotected.as_ref().unwrap_or(&empty_hdr),
            &mac.unprotected
        );
        assert_eq!(
            test_case.protected.as_ref().unwrap_or(&empty_hdr),
            &mac.protected.header
        );
    }
}

fn perform_mac0_reference_output_test(
    test_path: PathBuf,
    mut backend: impl CoseMacCipher + CoseKeyDistributionCipher,
) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut mac0_cfg = test_case_description
        .input
        .mac0
        .expect("expected a CoseMac0 test case, but it was not found");

    let example_output = match CoseMac0::from_tagged_slice(
        test_case_description.output.cbor.as_slice(),
    )
    .or_else(|e1| {
        CoseMac0::from_slice(test_case_description.output.cbor.as_slice())
            .map_err(|e2| Result::<CoseMac0, (CoseError, CoseError)>::Err((e1, e2)))
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

    verify_mac0_test_case(
        &mut backend,
        &example_output,
        &mut mac0_cfg,
        test_case_description.input.plaintext.as_bytes(),
        test_case_description.fail,
    )
}

fn perform_mac0_self_signed_test(
    test_path: PathBuf,
    mut backend: impl CoseMacCipher + CoseKeyDistributionCipher,
) {
    let mut test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut mac0_cfg = test_case_description
        .input
        .mac0
        .as_mut()
        .expect("expected a CoseMac0 test case, but it was not found");

    let mut mac0 = CoseMac0Builder::new();

    let mut recipient = mac0_cfg
        .recipients
        .first_mut()
        .expect("test case has no recipient");

    let unprotected = mac0_cfg.unprotected.clone().unwrap_or_default();

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
            test_case_description
                .intermediates
                .expect("CoseMac0 test case should have intermediates")
                .cek
                .clone(),
        )
        .build();
    }

    let mut mac0 = mac0
        .try_compute(
            &mut backend,
            &mut &enc_key,
            false,
            mac0_cfg.protected.clone(),
            Some(unprotected),
            test_case_description.input.plaintext.clone().into_bytes(),
            &mut mac0_cfg.external.as_slice(),
        )
        .expect("unable to encrypt Mac0 object");

    let (failure, sign_serialized) = serialize_mac0_and_apply_failures(
        &mut test_case_description.input.failures,
        &mut recipient.key,
        mac0.build(),
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

    let mac_redeserialized =
        match CoseMac0::from_tagged_slice(sign_serialized.as_slice()).or_else(|e1| {
            coset::CoseMac0::from_slice(sign_serialized.as_slice())
                .map_err(|e2| Result::<CoseMac0, (CoseError, CoseError)>::Err((e1, e2)))
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

    verify_mac0_test_case(
        &mut backend,
        &mac_redeserialized,
        test_case_description
            .input
            .mac0
            .as_mut()
            .expect("expected a CoseMac0 test case, but it was not found"),
        &test_case_description.input.plaintext.as_bytes(),
        test_case_description.fail,
    )
}

#[rstest]
fn cose_examples_mac0_reference_output(
    #[files("tests/cose_examples/mac0-tests/mac-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseMacCipher + CoseKeyDistributionCipher,
) {
    perform_mac0_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_mac_self_signed(
    #[files("tests/cose_examples/mac0-tests/mac-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseMacCipher + CoseKeyDistributionCipher,
) {
    perform_mac0_self_signed_test(test_path, backend)
}
