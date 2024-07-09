use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use coset::iana::{Algorithm, KeyOperation};
use coset::{
    iana, AsCborValue, CborSerializable, CoseKey, CoseKeyBuilder, CoseSign1, CoseSign1Builder,
    Header, HeaderBuilder, TaggedCborSerializable,
};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::sign::{Signer, Verifier};
use serde::Serialize;

use parameterized::parameterized;

use crate::common::test_helper::FakeRng;
use crate::token::CoseCipher;
use crate::CoseSignCipher;

fn p256_testkey() -> CoseKey {
    CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        URL_SAFE_NO_PAD
            .decode("-ZC6FAgf1yptcLLiu-6VRb7a7n3_l2AGoNg29TR03Mw")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("DD-Gx3txJu0VInf1p4tHgDTWOWgGdl2JumUnUZsgJDI")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("6iSKFEJCauf1K5QzyZjJM4iBEAOQqZkwVUeeTUcElRQ")
            .unwrap(),
    )
    .add_key_op(KeyOperation::Sign)
    .add_key_op(KeyOperation::Verify)
    .add_key_op(KeyOperation::Encrypt)
    .add_key_op(KeyOperation::Decrypt)
    .build()
}

fn p384_testkey() -> CoseKey {
    CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_384,
        URL_SAFE_NO_PAD
            .decode("95pFzElUJ9UZGA-aumXFzu4gR_2d2elGjE83WPht68An6TEzfiWcbVmuA-_fyVVy")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("2htQSt2Nac-rNDKLswdzC4DcNOJjbfPgHYETK9iE8dwfDSNxfPr3Xz4EeuCuM8Uc")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("9mclx3tODsIseWFdCR5weP-oOqA6NUsTjOmdIkqqCMNBONCCCM_8WcLOId4a3QwI")
            .unwrap(),
    )
    .add_key_op(KeyOperation::Sign)
    .add_key_op(KeyOperation::Verify)
    .add_key_op(KeyOperation::Encrypt)
    .add_key_op(KeyOperation::Decrypt)
    .build()
}

fn p521_testkey() -> CoseKey {
    CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_521,
        URL_SAFE_NO_PAD
            .decode("wA6_xLH2RPqAxf7fp1C2kYt9inWujnhVMZieDY9Ikv-jKBQ0EUaqAFIaVHeX9qh_iZ-lz2jM-JHmlVQsK6TpUGk")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("AWXuSZZKUCbLWIQB4xnmjlR-KWRwUgcc2hn2FlHchOKuNWrOiIVQHXYo5R4dLq4iji9MNrnibFh_2MCuch0LuYbR")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("AT8UDI_AkaK1Ra9mSDJ8lCFy2erCOzGeiZtcx1_ZFiIm42nZ-zvKqWzq3p6H1kgMdo5761p-6XDhZU5JD4rhYfiX")
            .unwrap(),
    )
        .add_key_op(KeyOperation::Sign)
        .add_key_op(KeyOperation::Verify)
        .add_key_op(KeyOperation::Encrypt)
        .add_key_op(KeyOperation::Decrypt)
        .build()
}

// Code to generate new keys for testing purposes.
fn gen_key() {
    let group: EcGroup = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let d = URL_SAFE_NO_PAD.encode(key.private_key().to_vec());
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    key.public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut BigNumContext::new().unwrap())
        .unwrap();
    let x = URL_SAFE_NO_PAD.encode(x.to_vec());
    let y = URL_SAFE_NO_PAD.encode(y.to_vec());
    println!("X: {}", x);
    println!("Y: {}", y);
    println!("D: {}", d);
}

fn run_sign_verify(key: &CoseKey, payload: &str, unprotected: &mut Header, protected: &mut Header) {
    <Signer as CoseCipher>::set_headers(&key, unprotected, protected, FakeRng).unwrap();
    let sign_struct = CoseSign1Builder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .payload(Vec::from(payload));

    let sign_cbor = sign_struct
        .try_create_signature(&[], |tosign| {
            <Signer as CoseSignCipher>::sign(&key, tosign, &unprotected, &protected)
        })
        .unwrap()
        .build();

    let output_cbor = sign_cbor.clone().to_tagged_vec().unwrap();
    println!("Output CBOR of CoseSign1: {}", hex::encode(&output_cbor));

    let reimported_sign = CoseSign1::from_tagged_slice(output_cbor.as_slice()).unwrap();
    assert_eq!(
        sign_cbor.to_cbor_value().unwrap(),
        reimported_sign.clone().to_cbor_value().unwrap()
    );

    reimported_sign
        .verify_signature(&[], |signature, toverify| {
            <Signer as CoseSignCipher>::verify(
                &key,
                signature,
                toverify,
                &reimported_sign.unprotected,
                &reimported_sign.protected,
                None,
                None,
            )
        })
        .unwrap();
}

#[parameterized(keygen = {
p256_testkey, p384_testkey, p521_testkey
})]
fn test_sign_verify(keygen: fn() -> CoseKey) {
    //let keygen = p521_testkey;
    run_sign_verify(
        &keygen(),
        "This is the content.",
        &mut Header::default(),
        &mut Header::default(),
    );
}

/// Test case from the cose-wg/Examples repository - sign1-tests/sign-pass-01.json
/// Sign and Verify using OpenSSL backend.
/// https://github.com/cose-wg/Examples/blob/master/sign1-tests/sign-pass-01.json
#[test]
fn example_test_sign_verify_pass_01() {
    let key = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        URL_SAFE_NO_PAD
            .decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
            .unwrap(),
    )
    .key_id("11".as_bytes().to_vec())
    .add_key_op(KeyOperation::Sign)
    .add_key_op(KeyOperation::Verify)
    .add_key_op(KeyOperation::Encrypt)
    .add_key_op(KeyOperation::Decrypt)
    .build();
    let mut unprotected = HeaderBuilder::new()
        .key_id("11".as_bytes().to_vec())
        .algorithm(Algorithm::ES256)
        .build();
    run_sign_verify(
        &key,
        "This is the content.",
        &mut unprotected,
        &mut HeaderBuilder::new().build(),
    )
}

/// Test case from the cose-wg/Examples repository - sign1-tests/sign-pass-01.json
/// Verify signature from given example using OpenSSL.
/// https://github.com/cose-wg/Examples/blob/master/sign1-tests/sign-pass-01.json
#[test]
fn example_test_verify_pass_01() {
    let key = CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        URL_SAFE_NO_PAD
            .decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
            .unwrap(),
    )
    .build();
    let plaintext = "This is the content.";

    let unprotected = HeaderBuilder::new()
        .key_id("11".as_bytes().to_vec())
        .algorithm(Algorithm::ES256)
        .build();

    let sign_struct = CoseSign1Builder::new()
        .unprotected(unprotected.clone())
        .protected(HeaderBuilder::new().build())
        .payload(Vec::from(plaintext));

    let sign_cbor = sign_struct
        .try_create_signature(&[], |tosign| {
            let intermediate_tobesigned = hex::decode(
                "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E",
            )
            .unwrap();
            assert_eq!(tosign, intermediate_tobesigned.as_slice());
            <Signer as CoseSignCipher>::sign(
                &key,
                tosign,
                &unprotected,
                &HeaderBuilder::new().build(),
            )
        })
        .unwrap()
        .build();

    let example_cbor_raw = hex::decode("D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F").unwrap();
    let example_cbor: ciborium::Value = ciborium::from_reader(example_cbor_raw.as_slice()).unwrap();
    let example_sign = CoseSign1::from_tagged_slice(example_cbor_raw.as_slice()).unwrap();

    println!("{:?}", &example_sign);
    example_sign
        .verify_signature(&[], |signature, toverify| {
            let intermediate_tobeverified = hex::decode(
                "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E",
            )
            .unwrap();
            println!("{}", hex::encode(&toverify));
            // TODO Value for which to verify signature for seems to be mismatched - presumably because the example token has this zero length string encoding with the A0 byte for the protected header.
            assert_eq!(toverify, intermediate_tobeverified.as_slice());
            <Signer as CoseSignCipher>::verify(
                &key,
                signature,
                toverify,
                &example_sign.unprotected,
                &example_sign.protected,
                None,
                None,
            )
        })
        .unwrap();
}
