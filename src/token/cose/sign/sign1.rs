use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::sign;
use crate::CoseSignCipher;
use core::borrow::BorrowMut;
use coset::{CoseKey, CoseSign1, CoseSign1Builder, CoseSignatureBuilder, Header};

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSign1BuilderExt: Sized {
    /// Creates the signature for the CoseSign1 object using the given backend.
    ///
    /// Will also set potentially required headers and check whether the given key is appropriate
    /// for signing and matches the header information.
    ///
    /// Parameters:
    /// - `backend`: cryptographic backend to use
    /// - `key`: Key to use for signing.
    /// - `protected`: protected headers, will override the previously set ones.
    /// - `unprotected`: unprotected headers, will override the previously set ones.
    ///
    /// TODO: Setting all of these options at once kind of defeats the purpose of
    ///       the builder pattern, but it is necessary here, as we lack access to the `protected`
    ///       and `unprotected` headers that were previously set (the field is private).
    ///       This should be fixed when porting all of this to coset.
    fn try_sign<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider<'a>, CAP: CoseAadProvider<'b>>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;

    /// Builds the CoseSign1 object with a detached payload using the given backend.
    ///
    /// Will also set potentially required headers and check whether the given key is appropriate
    /// for signing and matches the header information.
    ///
    /// Parameters:
    /// - `backend`: cryptographic backend to use
    /// - `key`: Key to use for signing.
    /// - `protected`: protected headers, will override the previously set ones.
    /// - `unprotected`: unprotected headers, will override the previously set ones.
    ///
    /// TODO: Setting all of these options at once kind of defeats the purpose of
    ///       the builder pattern, but it is necessary here, as we lack access to the `protected`
    ///       and `unprotected` headers that were previously set (the field is private).
    ///       This should be fixed when porting all of this to coset.
    fn try_sign_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSign1BuilderExt for CoseSign1Builder {
    fn try_sign<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider<'a>, CAP: CoseAadProvider<'b>>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        mut aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_signature(
            aad.lookup_aad(protected.as_ref(), unprotected.as_ref()),
            |tosign| {
                sign::try_sign(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    tosign,
                )
            },
        )
    }
    fn try_sign_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        mut aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_detached_signature(
            payload,
            aad.lookup_aad(protected.as_ref(), unprotected.as_ref()),
            |tosign| {
                sign::try_sign(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    tosign,
                )
            },
        )
    }
}

pub trait CoseSign1Ext {
    fn try_verify<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider<'a>, CAP: CoseAadProvider<'b>>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    fn try_verify_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSign1Ext for CoseSign1 {
    fn try_verify<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider<'a>, CAP: CoseAadProvider<'b>>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_signature(
            aad.lookup_aad(Some(&self.protected.header), Some(&self.unprotected)),
            |signature, toverify| {
                sign::try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    signature,
                    toverify,
                )
            },
        )?;

        Ok(())
    }

    fn try_verify_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider<'a>,
        CAP: CoseAadProvider<'b>,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        payload: &[u8],
        mut aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_detached_signature(
            payload,
            aad.lookup_aad(Some(&self.protected.header), Some(&self.unprotected)),
            |signature, toverify| {
                sign::try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    signature,
                    toverify,
                )
            },
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::token::cose::crypto_impl::openssl::OpensslContext;
    use crate::token::cose::sign::CoseSign1BuilderExt;
    use crate::token::cose::sign::CoseSign1Ext;
    use crate::token::cose::sign::{CoseSignBuilderExt, CoseSignExt};
    use crate::token::cose::test_helper::{
        apply_attribute_failures, apply_header_failures, serialize_cose_with_failures, TestCase,
        TestCaseFailures, TestCaseInput, TestCaseRecipient, TestCaseSign,
    };
    use crate::CoseSignCipher;
    use base64::Engine;
    use coset::iana::EnumI64;
    use coset::{
        AsCborValue, CborSerializable, CoseError, CoseKey, CoseSign, CoseSign1, CoseSign1Builder,
        CoseSignBuilder, CoseSignature, CoseSignatureBuilder, Header, Label,
        TaggedCborSerializable,
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
        let test_case_description: TestCase = serde_json::from_reader(
            std::fs::File::open(test_path).expect("unable to open test case"),
        )
        .expect("invalid test case");

        let sign1_cfg = test_case_description
            .input
            .sign0
            .expect("expected a CoseSign1 test case, but it was not found");

        let example_output =
            match CoseSign1::from_tagged_slice(test_case_description.output.cbor.as_slice())
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
        let test_case_description: TestCase = serde_json::from_reader(
            std::fs::File::open(test_path).expect("unable to open test case"),
        )
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
}
