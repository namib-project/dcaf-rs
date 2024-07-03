#![cfg(all(test, feature = "std"))]
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::encrypt::encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};
use crate::token::cose::encrypt::{CoseEncryptCipher, HeaderBuilderExt};
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
    TestCaseEncrypted, TestCaseFailures,
};
use crate::CoseSignCipher;
use base64::Engine;
use coset::iana::EnumI64;
use coset::{
    AsCborValue, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseError, CoseKey,
    CoseSign1, Header, HeaderBuilder, TaggedCborSerializable,
};
use hex::FromHex;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::any::Any;
use std::path::PathBuf;

fn serialize_encrypt0_and_apply_failures(
    failures: &mut TestCaseFailures,
    key: &mut CoseKey,
    mut value: CoseEncrypt0,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(1) = &failures.change_tag {
        let byte = value.ciphertext.as_mut().unwrap().first_mut().unwrap();
        *byte = byte.wrapping_add(1);
    }

    apply_header_failures(&mut value.protected.header, &failures);

    let serialized_data = serialize_cose_with_failures(value, &failures);

    (apply_attribute_failures(key, &failures), serialized_data)
}

fn verify_encrypt0_test_case<T: CoseEncryptCipher>(
    backend: &mut T,
    encrypt0: &CoseEncrypt0,
    test_case: &mut TestCaseEncrypted,
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

    let verify_result = encrypt0.try_decrypt(backend, &mut &keys, false, &mut aad);

    if should_fail {
        verify_result.expect_err("invalid token was successfully verified");
    } else {
        let plaintext = verify_result.expect("unable to verify token");

        assert_eq!(expected_plaintext, plaintext.as_slice());
        let empty_hdr = Header::default();
        // TODO IV is apprarently taken from rng_stream field, not header field, but still implicitly added to header.
        //      ugh...
        let mut unprotected = test_case.unprotected.clone().unwrap_or_default();
        let mut protected = test_case.protected.clone().unwrap_or_default();
        unprotected.iv = encrypt0.unprotected.iv.clone();
        protected.iv = encrypt0.protected.header.iv.clone();
        assert_eq!(&unprotected, &encrypt0.unprotected);
        assert_eq!(&protected, &encrypt0.protected.header);
    }
}

fn perform_encrypt0_reference_output_test(test_path: PathBuf, mut backend: impl CoseEncryptCipher) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut encrypt0_cfg = test_case_description
        .input
        .encrypted
        .expect("expected a CoseSign test case, but it was not found");

    let example_output = match CoseEncrypt0::from_tagged_slice(
        test_case_description.output.cbor.as_slice(),
    )
    .or_else(|e1| {
        CoseEncrypt0::from_slice(test_case_description.output.cbor.as_slice())
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

    verify_encrypt0_test_case(
        &mut backend,
        &example_output,
        &mut encrypt0_cfg,
        test_case_description.input.plaintext.as_bytes(),
        test_case_description.fail,
    )
}

fn perform_encrypt0_self_signed_test(test_path: PathBuf, mut backend: impl CoseEncryptCipher) {
    let mut test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut encrypt0_cfg = test_case_description
        .input
        .encrypted
        .as_mut()
        .expect("expected a CoseEncrypt0 test case, but it was not found");

    let mut encrypt0 = CoseEncrypt0Builder::new();

    let mut recipient = encrypt0_cfg
        .recipients
        .first_mut()
        .expect("test case has no recipient");

    // Need to generate an IV. Have to do this quite ugly, because we have implemented our IV
    // generation on the header builder only.
    let iv_generator = HeaderBuilder::new()
        .gen_iv(
            &mut backend,
            &encrypt0_cfg
                .protected
                .as_ref()
                .or_else(|| encrypt0_cfg.unprotected.as_ref())
                .unwrap()
                .alg
                .as_ref()
                .unwrap()
                .clone(),
        )
        .expect("unable to generate IV")
        .build();
    let mut unprotected = encrypt0_cfg.unprotected.clone().unwrap_or_default();
    unprotected.iv = iv_generator.iv;

    let mut encrypt0 = encrypt0
        .try_encrypt(
            &mut backend,
            &mut &recipient.key,
            false,
            encrypt0_cfg.protected.clone(),
            Some(unprotected),
            &test_case_description.input.plaintext.clone().into_bytes(),
            &mut encrypt0_cfg.external.as_slice(),
        )
        .expect("unable to encrypt Encrypt0 object");

    let (failure, sign_serialized) = serialize_encrypt0_and_apply_failures(
        &mut test_case_description.input.failures,
        &mut recipient.key,
        encrypt0.build(),
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

    let encrypt0_redeserialized = match CoseEncrypt0::from_tagged_slice(sign_serialized.as_slice())
        .or_else(|e1| {
            CoseEncrypt0::from_slice(sign_serialized.as_slice())
                .map_err(|e2| Result::<CoseEncrypt0, (CoseError, CoseError)>::Err((e1, e2)))
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

    verify_encrypt0_test_case(
        &mut backend,
        &encrypt0_redeserialized,
        test_case_description
            .input
            .encrypted
            .as_mut()
            .expect("expected a CoseSign test case, but it was not found"),
        &test_case_description.input.plaintext.as_bytes(),
        test_case_description.fail,
    )
}

#[rstest]
fn cose_examples_encrypted_encrypt0_reference_output(
    #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
) {
    perform_encrypt0_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_encrypted_encrypt0_self_signed(
    #[files("tests/cose_examples/encrypted-tests/enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
) {
    perform_encrypt0_self_signed_test(test_path, backend)
}

#[rstest]
fn cose_examples_aes_gcm_encrypt0_reference_output(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
) {
    perform_encrypt0_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_aes_gcm_encrypt0_self_signed(
    #[files("tests/cose_examples/aes-gcm-examples/aes-gcm-enc-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher,
) {
    perform_encrypt0_self_signed_test(test_path, backend)
}
