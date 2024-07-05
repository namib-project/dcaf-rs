#![cfg(all(test, feature = "std"))]
use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::openssl::OpensslContext;
use crate::token::cose::encrypt::encrypt::{CoseEncryptBuilderExt, CoseEncryptExt};
use crate::token::cose::encrypt::encrypt0::{CoseEncrypt0BuilderExt, CoseEncrypt0Ext};
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher, HeaderBuilderExt};
use crate::token::cose::header_util::determine_algorithm;
use crate::token::cose::key::{CoseParsedKey, CoseSymmetricKey};
use crate::token::cose::recipient::CoseRecipientBuilderExt;
use crate::token::cose::sign::CoseSign1BuilderExt;
use crate::token::cose::sign::CoseSign1Ext;
use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
use crate::token::cose::test_helper::{
    apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
    TestCaseEncrypted, TestCaseFailures,
};
use crate::CoseSignCipher;
use base64::Engine;
use coset::iana::{Algorithm, EnumI64};
use coset::{
    AsCborValue, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder,
    CoseEncryptBuilder, CoseError, CoseKey, CoseKeyBuilder, CoseRecipientBuilder, CoseSign1,
    EncryptionContext, Header, HeaderBuilder, TaggedCborSerializable,
};
use hex::FromHex;
use rstest::rstest;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::any::Any;
use std::convert::Infallible;
use std::path::PathBuf;

fn serialize_encrypt_and_apply_failures(
    failures: &mut TestCaseFailures,
    key: &mut CoseKey,
    mut value: CoseEncrypt,
) -> (Option<CoseError>, Vec<u8>) {
    if let Some(1) = &failures.change_tag {
        let byte = value.ciphertext.as_mut().unwrap().first_mut().unwrap();
        *byte = byte.wrapping_add(1);
    }

    apply_header_failures(&mut value.protected.header, &failures);

    let serialized_data = serialize_cose_with_failures(value, &failures);

    (apply_attribute_failures(key, &failures), serialized_data)
}

fn verify_encrypt_test_case<T: CoseEncryptCipher + CoseKeyDistributionCipher>(
    backend: &mut T,
    encrypt: &CoseEncrypt,
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

    let verify_result = encrypt.try_decrypt_with_recipients(backend, &mut &keys, false, &mut aad);

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
        unprotected.iv = encrypt.unprotected.iv.clone();
        protected.iv = encrypt.protected.header.iv.clone();
        assert_eq!(&unprotected, &encrypt.unprotected);
        assert_eq!(&protected, &encrypt.protected.header);
    }
}

fn perform_encrypt_reference_output_test(
    test_path: PathBuf,
    mut backend: impl CoseEncryptCipher + CoseKeyDistributionCipher,
) {
    let test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut encrypt_cfg = test_case_description
        .input
        .enveloped
        .expect("expected a CoseSign test case, but it was not found");

    let example_output = match CoseEncrypt::from_tagged_slice(
        test_case_description.output.cbor.as_slice(),
    )
    .or_else(|e1| {
        CoseEncrypt::from_slice(test_case_description.output.cbor.as_slice())
            .map_err(|e2| Result::<CoseEncrypt, (CoseError, CoseError)>::Err((e1, e2)))
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

    verify_encrypt_test_case(
        &mut backend,
        &example_output,
        &mut encrypt_cfg,
        test_case_description.input.plaintext.as_bytes(),
        test_case_description.fail,
    )
}

fn perform_encrypt_self_signed_test(
    test_path: PathBuf,
    mut backend: impl CoseEncryptCipher + CoseKeyDistributionCipher,
) {
    let mut test_case_description: TestCase =
        serde_json::from_reader(std::fs::File::open(test_path).expect("unable to open test case"))
            .expect("invalid test case");

    let mut encrypt_cfg = test_case_description
        .input
        .enveloped
        .as_mut()
        .expect("expected a CoseEncrypt test case, but it was not found");

    let mut encrypt = CoseEncryptBuilder::new();

    let mut recipient = encrypt_cfg
        .recipients
        .first_mut()
        .expect("test case has no recipient");

    // Need to generate an IV. Have to do this quite ugly, because we have implemented our IV
    // generation on the header builder only.
    let iv_generator = HeaderBuilder::new()
        .gen_iv(
            &mut backend,
            &encrypt_cfg
                .protected
                .as_ref()
                .or_else(|| encrypt_cfg.unprotected.as_ref())
                .unwrap()
                .alg
                .as_ref()
                .unwrap()
                .clone(),
        )
        .expect("unable to generate IV")
        .build();
    let mut unprotected = encrypt_cfg.unprotected.clone().unwrap_or_default();
    unprotected.iv = iv_generator.iv;

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
            test_case_description
                .intermediates
                .expect("CoseEncrypt test case should have intermediates")
                .cek
                .clone(),
        )
        .build();
        let parsed_key = CoseSymmetricKey::<Infallible>::try_from(&enc_key)
            .expect("unable to parse CEK input as symmetric key");
        recipient_struct_builder = recipient_struct_builder
            .try_encrypt(
                &mut backend,
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

    let mut encrypt = encrypt
        .add_recipient(recipient_struct_builder.build())
        .try_encrypt(
            &mut backend,
            &mut &enc_key,
            false,
            encrypt_cfg.protected.clone(),
            Some(unprotected),
            &test_case_description.input.plaintext.clone().into_bytes(),
            &mut encrypt_cfg.external.as_slice(),
        )
        .expect("unable to encrypt Encrypt object");

    let (failure, sign_serialized) = serialize_encrypt_and_apply_failures(
        &mut test_case_description.input.failures,
        &mut recipient.key,
        encrypt.build(),
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

    let encrypt_redeserialized = match CoseEncrypt::from_tagged_slice(sign_serialized.as_slice())
        .or_else(|e1| {
            CoseEncrypt::from_slice(sign_serialized.as_slice())
                .map_err(|e2| Result::<CoseEncrypt, (CoseError, CoseError)>::Err((e1, e2)))
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

    verify_encrypt_test_case(
        &mut backend,
        &encrypt_redeserialized,
        test_case_description
            .input
            .enveloped
            .as_mut()
            .expect("expected a CoseEncrypt test case, but it was not found"),
        &test_case_description.input.plaintext.as_bytes(),
        test_case_description.fail,
    )
}

#[rstest]
fn cose_examples_enveloped_reference_output(
    #[files("tests/cose_examples/enveloped-tests/env-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher + CoseKeyDistributionCipher,
) {
    perform_encrypt_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_enveloped_self_signed(
    #[files("tests/cose_examples/enveloped-tests/env-*.json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher + CoseKeyDistributionCipher,
) {
    perform_encrypt_self_signed_test(test_path, backend)
}

#[rstest]
fn cose_examples_aes_wrap_reference_output(
    #[files("tests/cose_examples/aes-wrap-examples/aes-wrap-*-0[45].json")] test_path: PathBuf, // The other tests use (as of now) unsupported algorithms
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher + CoseKeyDistributionCipher,
) {
    perform_encrypt_reference_output_test(test_path, backend)
}

#[rstest]
fn cose_examples_aes_wrap_self_signed(
    #[files("tests/cose_examples/aes-wrap-examples/aes-wrap-*-0[45].json")] test_path: PathBuf,
    #[values(OpensslContext {})] backend: impl CoseEncryptCipher + CoseKeyDistributionCipher,
) {
    perform_encrypt_self_signed_test(test_path, backend)
}
