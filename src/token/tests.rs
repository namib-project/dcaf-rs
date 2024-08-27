/*
 * Copyright (c) 2022, 2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::*;
use crate::common::test_helper::MockCipher;
use crate::error::CoseCipherError;
use crate::token::cose::util::symmetric_algorithm_iv_len;
use alloc::vec::Vec;
use alloc::{string::ToString, vec};
use base64::Engine;
use ciborium::value::Value;
use core::convert::Infallible;
use coset::cwt::ClaimsSetBuilder;
use coset::iana::Algorithm::{A128GCM, A128KW, ES256, ES384, HMAC_256_256};
use coset::iana::{Algorithm, CoapContentFormat, CwtClaimName, EllipticCurve};
use coset::{AsCborValue, CoseKey, CoseKeyBuilder, CoseMac0Builder, HeaderBuilder, Label};
use rand::rngs::ThreadRng;

/// Generates a test key with content `[0, 1, 2, 3, 4, 5, ...]` and key id `[0xDC, 0xAF]`.
fn example_key_one(alg: Algorithm) -> CoseKey {
    CoseKeyBuilder::new_symmetric_key(vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    ])
    .key_id(vec![0xDC, 0xAF])
    .algorithm(alg)
    .build()
}

/// Generates a test key with content `[0xF, 0xE, 0xD, 0xC, 0xB, ...]` and key id `[0xCA, 0xFE]`.
fn example_key_two(alg: Algorithm) -> CoseKey {
    CoseKeyBuilder::new_symmetric_key(vec![
        0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ])
    .key_id(vec![0xCA, 0xFE])
    .algorithm(alg)
    .build()
}

/// Generates an ECDSA test key.
fn example_ec_key_one(alg: Algorithm) -> CoseKey {
    CoseKeyBuilder::new_ec2_priv_key(
        EllipticCurve::P_256,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
            .unwrap(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
            .unwrap(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
            .unwrap(),
    )
    .key_id("P256".as_bytes().to_vec())
    .algorithm(alg)
    .build()
}

/// Generates an ECDSA test key.
fn example_ec_key_two(alg: Algorithm) -> CoseKey {
    CoseKeyBuilder::new_ec2_priv_key(
        EllipticCurve::P_384,
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc")
            .unwrap(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s")
            .unwrap(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo")
            .unwrap(),
    )
    .key_id("P384".as_bytes().to_vec())
    .algorithm(alg)
    .build()
}

fn example_headers(alg: Algorithm, generate_iv: bool) -> (Header, Header) {
    let mut unprotected_header_builder = HeaderBuilder::new().algorithm(alg).value(47, Value::Null);
    if generate_iv {
        let mut iv = vec![
            0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC, 0x7B, 0xFC, 0xF6, 0xD3, 0xF9, 0x5B,
        ];
        iv.truncate(symmetric_algorithm_iv_len::<Infallible>(alg).expect("invalid algorithm"));
        unprotected_header_builder = unprotected_header_builder.iv(iv);
    }
    let unprotected_header = unprotected_header_builder.build();
    let protected_header = HeaderBuilder::new()
        .content_format(CoapContentFormat::Cbor)
        .build();
    (unprotected_header, protected_header)
}

fn example_invalid_headers() -> (Header, Header) {
    let unprotected_header = HeaderBuilder::new()
        .content_format(CoapContentFormat::Cbor)
        .iv(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        ])
        .build();
    let protected_header = HeaderBuilder::new().value(47, Value::Null).build();
    (unprotected_header, protected_header)
}

fn example_aad() -> Vec<u8> {
    vec![0x10, 0x12, 0x13, 0x14, 0x15]
}

fn example_claims(
    key: &CoseKey,
) -> Result<ClaimsSet, AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    Ok(ClaimsSetBuilder::new()
        .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
        .build())
}

fn assert_header_is_part_of(subset: &Header, superset: &Header) {
    // If the subset contains a field, the superset must have it set to that as well.
    // All other fields will be ignored.
    if subset.alg.is_some() {
        assert_eq!(subset.alg, superset.alg, "'alg' has been changed");
    }
    if !subset.crit.is_empty() {
        assert_eq!(subset.crit, superset.crit, "'crit' has been changed");
    }
    if subset.content_type.is_some() {
        assert_eq!(
            subset.content_type, superset.content_type,
            "'content_type' has been changed"
        );
    }
    if !subset.key_id.is_empty() {
        assert_eq!(subset.key_id, superset.key_id, "'key_id' has been changed");
    }
    if !subset.iv.is_empty() {
        assert_eq!(subset.iv, superset.iv, "'iv' has been changed");
    }
    if !subset.partial_iv.is_empty() {
        assert_eq!(
            subset.partial_iv, superset.partial_iv,
            "'partial_iv' has been changed"
        );
    }
    if !subset.counter_signatures.is_empty() {
        assert_eq!(
            subset.counter_signatures, superset.counter_signatures,
            "'counter_signatures' has been changed"
        );
    }
    assert!(subset.rest.iter().all(|x| superset.rest.contains(x)));
}

#[test]
fn test_get_headers_enc(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let (unprotected_header, protected_header) = example_headers(A128GCM, true);
    let enc_test = CoseEncrypt0Builder::new()
        .unprotected(unprotected_header.clone())
        .protected(protected_header.clone())
        .build()
        .to_vec()?;
    assert_eq!(
        (unprotected_header, protected_header),
        get_token_headers(&enc_test)
            .map(|(u, p)| (u, p.header))
            .unwrap()
    );
    Ok(())
}

#[test]
fn test_get_headers_sign(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let (unprotected_header, protected_header) = example_headers(ES256, false);
    let sign_test = CoseSign1Builder::new()
        .unprotected(unprotected_header.clone())
        .protected(protected_header.clone())
        .build()
        .to_vec()?;
    assert_eq!(
        (unprotected_header, protected_header),
        get_token_headers(&sign_test)
            .map(|(u, p)| (u, p.header))
            .unwrap()
    );
    Ok(())
}

#[test]
fn test_get_headers_mac(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let (unprotected_header, protected_header) = example_headers(HMAC_256_256, false);
    let mac_test = CoseMac0Builder::new()
        .unprotected(unprotected_header.clone())
        .protected(protected_header.clone())
        .build()
        .to_vec()?;
    assert_eq!(
        (unprotected_header, protected_header),
        get_token_headers(&mac_test)
            .map(|(u, p)| (u, p.header))
            .unwrap()
    );
    Ok(())
}

#[test]
fn test_get_headers_invalid() {
    let inputs = vec![
        vec![0],
        vec![1, 2, 3, 4],
        vec![],
        hex::decode("A401474A5015DF68642802190E1008A101A301040246849B5786457C2051849B5786457C1491BE3A76DCEA6C427108182601").unwrap(),
        CoseKeyBuilder::new_symmetric_key(vec![0xDC, 0xAF]).build().to_vec().unwrap(),
    ];
    for input in inputs {
        assert!(get_token_headers(&input).is_none());
    }
}

#[test]
fn test_encrypt_decrypt(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let mut backend = MockCipher::<ThreadRng>::new(rand::thread_rng());
    let key = example_key_one(A128GCM);
    let (unprotected_header, protected_header) = example_headers(A128GCM, true);
    let claims = example_claims(&key)?;
    let aad = example_aad();
    let encrypted = encrypt_access_token(
        &mut backend,
        &key,
        claims.clone(),
        &aad.as_slice(),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).expect("invalid headers");
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    assert_eq!(
        decrypt_access_token(&mut backend, &key, &encrypted, &aad.as_slice())?,
        claims
    );
    Ok(())
}

#[test]
fn test_encrypt_decrypt_multiple(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    const AUDIENCE: &str = "example_aud";
    let mut backend = MockCipher::<ThreadRng>::new(rand::thread_rng());
    let (unprotected_header, protected_header) = example_headers(A128GCM, true);
    let key1 = example_key_one(A128KW);
    let key2 = example_key_two(A128KW);
    let invalid_key1 = CoseKeyBuilder::new_symmetric_key(vec![0; 5])
        .key_id(vec![0, 0])
        .build();
    let invalid_key2 = CoseKeyBuilder::new_symmetric_key(vec![0; 5])
        .key_id(vec![0xDC, 0xAF])
        .build();
    let aad = example_aad();
    // Using example_claims doesn't make sense, since they contain a cnf for the key,
    // but we don't know the CEK at this point.
    let claims = ClaimsSetBuilder::new()
        .audience(AUDIENCE.to_string())
        .build();
    let encrypted = encrypt_access_token_multiple(
        &mut backend,
        vec![&key1, &key2],
        claims.clone(),
        &aad,
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).expect("invalid headers");
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    for key in vec![key1, key2] {
        assert_eq!(
            &decrypt_access_token_multiple(&mut backend, &key, &encrypted, &aad)?,
            &claims
        );
    }
    let failed = decrypt_access_token_multiple(&mut backend, &invalid_key1, &encrypted, &aad);
    assert!(failed
        .err()
        .filter(|x| matches!(
            x,
            AccessTokenError::CoseCipherError(CoseCipherError::NoDecryptableRecipientFound(_, _))
        ))
        .is_some());
    let failed = decrypt_access_token_multiple(&mut backend, &invalid_key2, &encrypted, &aad);
    assert!(failed
        .err()
        .filter(|x| matches!(
            x,
            AccessTokenError::CoseCipherError(CoseCipherError::NoDecryptableRecipientFound(_, _))
        ))
        .is_some());
    Ok(())
}

#[test]
fn test_encrypt_decrypt_match_multiple(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let mut backend = MockCipher::<ThreadRng>::new(rand::thread_rng());
    let (unprotected_header, protected_header) = example_headers(A128GCM, true);
    let key1 = example_key_one(A128KW);
    let aad = example_aad();
    let claims = ClaimsSetBuilder::new().build();
    let encrypted = encrypt_access_token_multiple(
        &mut backend,
        vec![&key1, &key1],
        claims,
        &aad,
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).expect("invalid headers");
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    // In the future, this should only be an error in "strict mode".
    decrypt_access_token_multiple(&mut backend, &key1, &encrypted, &aad)
        .expect("error while decrypting");
    Ok(())
}

#[test]
fn test_encrypt_decrypt_invalid_header(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let mut backend = MockCipher::<ThreadRng>::new(rand::thread_rng());
    let key = example_key_one(A128GCM);
    let (unprotected_header, protected_header) = example_headers(A128GCM, true);
    let (unprotected_invalid, protected_invalid) = example_invalid_headers();
    let claims = example_claims(&key)?;
    let aad = example_aad();
    let encrypted = encrypt_access_token(
        &mut backend,
        &key,
        claims.clone(),
        &aad,
        Some(unprotected_invalid),
        Some(protected_header),
    );
    assert!(
        encrypted.as_ref().err().map_or(false, |x| {
            if let AccessTokenError::CoseCipherError(CoseCipherError::DuplicateHeaders(l)) = x {
                vec![Label::Int(3)].eq(l)
            } else {
                false
            }
        }),
        "unexpected error: {:?}",
        encrypted.err()
    );

    let encrypted = encrypt_access_token(
        &mut backend,
        &key,
        claims,
        &aad,
        Some(unprotected_header),
        Some(protected_invalid),
    );
    assert!(encrypted.is_err());
    assert!(
        encrypted.as_ref().err().map_or(false, |x| {
            if let AccessTokenError::CoseCipherError(CoseCipherError::DuplicateHeaders(l)) = x {
                vec![Label::Int(47)].eq(l)
            } else {
                false
            }
        }),
        "unexpected error: {:?}",
        encrypted.err()
    );

    Ok(())
}

#[test]
fn test_sign_verify(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    let mut backend = MockCipher::<ThreadRng>::new(rand::thread_rng());
    let key = example_ec_key_one(ES256);
    let (unprotected_header, protected_header) = example_headers(ES256, false);
    let claims = example_claims(&key)?;
    let aad = example_aad();
    let signed = sign_access_token(
        &mut backend,
        &key,
        claims,
        &aad,
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;

    #[cfg(feature = "std")]
    println!("{:x?}", &signed);
    let (unprotected, protected) =
        get_token_headers(&signed).ok_or(AccessTokenError::<Infallible>::UnknownCoseStructure)?;
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    verify_access_token(&mut backend, &key, &signed, &aad)?;
    Ok(())
}

#[test]
fn test_sign_verify_multiple(
) -> Result<(), AccessTokenError<<MockCipher<ThreadRng> as CryptoBackend>::Error>> {
    const AUDIENCE: &str = "example_aud";
    let mut backend = MockCipher::<ThreadRng>::new(rand::thread_rng());
    let key1 = example_ec_key_one(ES256);
    let key2 = example_ec_key_two(ES384);
    let invalid_key1 = CoseKeyBuilder::new_symmetric_key(vec![0; 5])
        .key_id(vec![0, 0])
        .build();
    let invalid_key2 = CoseKeyBuilder::new_symmetric_key(vec![0; 5])
        .key_id(vec![0xDC, 0xAF])
        .build();
    let (unprotected_header, protected_header) = example_headers(A128GCM, true);
    let claims = ClaimsSetBuilder::new()
        .audience(AUDIENCE.to_string())
        .build();
    let aad = example_aad();
    let signed = sign_access_token_multiple(
        &mut backend,
        vec![
            (&key1, CoseSignature::default()),
            (&key2, CoseSignature::default()),
        ],
        claims,
        &aad,
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;
    let (unprotected, protected) =
        get_token_headers(&signed).ok_or(AccessTokenError::<Infallible>::UnknownCoseStructure)?;
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    for key in vec![key1, key2] {
        verify_access_token_multiple(&mut backend, &key, &signed, &aad)?;
    }
    assert!(
        verify_access_token_multiple(&mut backend, &invalid_key1, &signed, &aad)
            .err()
            .filter(|x| matches!(
                x,
                AccessTokenError::CoseCipherError(CoseCipherError::NoValidSignatureFound(_))
            ))
            .is_some()
    );
    assert!(
        verify_access_token_multiple(&mut backend, &invalid_key2, &signed, &aad)
            .err()
            .filter(|x| matches!(
                x,
                AccessTokenError::CoseCipherError(CoseCipherError::NoValidSignatureFound(_))
            ))
            .is_some()
    );
    Ok(())
}
