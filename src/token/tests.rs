/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#[cfg(not(feature = "std"))]
use alloc::vec;

use ciborium::value::Value;
use coset::{AsCborValue, CoseKey, CoseKeyBuilder, CoseMac0Builder, HeaderBuilder};
use coset::cwt::ClaimsSetBuilder;
use coset::iana::{Algorithm, CoapContentFormat, CwtClaimName};

use crate::common::test_helper::{FakeCrypto, FakeKey, FakeRng};
use crate::error::CoseCipherError;

use super::*;

/// Generates a test key with content `[1,2,3,4,5]` and key id `[0xDC, 0xAF]`.
fn example_key_one() -> FakeKey {
    FakeKey::try_from(vec![1, 2, 3, 4, 5, 0xDC, 0xAF]).expect("invalid test key")
}

/// Generates a test key with content `[10, 9, 8, 7, 6]` and key id `[0xCA, 0xFE]`.
fn example_key_two() -> FakeKey {
    FakeKey::try_from(vec![10, 9, 8, 7, 6, 0xCA, 0xFE]).expect("invalid test key")
}

fn example_headers() -> (Header, Header) {
    let unprotected_header = HeaderBuilder::new()
        .iv(vec![
            0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC, 0x7B, 0xFC, 0xF6, 0xD3, 0xF9, 0x5B,
        ])
        .build();
    let protected_header = HeaderBuilder::new().content_format(CoapContentFormat::Cbor).build();
    (unprotected_header, protected_header)
}

fn example_invalid_headers() -> (Header, Header) {
    let unprotected_header = HeaderBuilder::new().value(47, Value::Null).build();
    let protected_header = HeaderBuilder::new()
        .algorithm(Algorithm::AES_CCM_16_64_128)
        .build();
    (unprotected_header, protected_header)
}

fn example_aad() -> Vec<u8> {
    vec![0x10, 0x12, 0x13, 0x14, 0x15]
}

fn example_claims(
    key: CoseKey,
) -> Result<ClaimsSet, AccessTokenError<<FakeCrypto as CoseEncryptCipher>::Error>> {
    Ok(ClaimsSetBuilder::new()
        .claim(
            CwtClaimName::Cnf,
            key.to_cbor_value()?,
        )
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
fn test_get_headers_enc() -> Result<(), AccessTokenError<<FakeCrypto as CoseEncryptCipher>::Error>>
{
    let (unprotected_header, protected_header) = example_headers();
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
fn test_get_headers_sign() -> Result<(), AccessTokenError<<FakeCrypto as CoseSignCipher>::Error>> {
    let (unprotected_header, protected_header) = example_headers();
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
fn test_get_headers_mac() -> Result<(), AccessTokenError<<FakeCrypto as CoseMacCipher>::Error>> {
    let (unprotected_header, protected_header) = example_headers();
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
fn test_encrypt_decrypt() -> Result<(), AccessTokenError<<FakeCrypto as CoseEncryptCipher>::Error>> {
    let key = example_key_one();
    let (unprotected_header, protected_header) = example_headers();
    let claims = example_claims(key.to_cose_key())?;
    let aad = example_aad();
    let rng = FakeRng;
    let encrypted = encrypt_access_token::<FakeCrypto, FakeRng>(
        key.clone(),
        claims.clone(),
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
        rng,
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).expect("invalid headers");
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    assert_eq!(
        decrypt_access_token::<FakeCrypto>(&key, &encrypted, Some(&aad))?,
        claims
    );
    Ok(())
}

#[test]
fn test_encrypt_decrypt_multiple() -> Result<(), AccessTokenError<<FakeCrypto as CoseEncryptCipher>::Error>> {
    const AUDIENCE: &str = "example_aud";
    let (unprotected_header, protected_header) = example_headers();
    let key1 = example_key_one();
    let key2 = example_key_two();
    let invalid_key1 = FakeKey::try_from(vec![0, 0, 0, 0, 0, 0, 0]).expect("invalid test key");
    let invalid_key2 = FakeKey::try_from(vec![0, 0, 0, 0, 0, 0xDC, 0xAF]).expect("invalid test key");
    let rng = FakeRng;
    let aad = example_aad();
    // Using example_claims doesn't make sense, since they contain a cnf for the key,
    // but we don't know the CEK at this point.
    let claims = ClaimsSetBuilder::new().audience(AUDIENCE.to_string()).build();
    let encrypted = encrypt_access_token_multiple::<FakeCrypto, FakeRng>(
        vec![&key1, &key2],
        claims.clone(),
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
        rng
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).expect("invalid headers");
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    for key in vec![key1, key2] {
        assert_eq!(
            &decrypt_access_token_multiple::<FakeCrypto, FakeCrypto>(&key, &encrypted, Some(&aad))?,
            &claims
        );
    }
    let failed = decrypt_access_token_multiple::<FakeCrypto, FakeCrypto>(&invalid_key1, &encrypted, Some(&aad));
    assert!(failed.err().filter(|x| matches!(x, AccessTokenError::NoMatchingRecipient)).is_some());
    let failed = decrypt_access_token_multiple::<FakeCrypto, FakeCrypto>(&invalid_key2, &encrypted, Some(&aad));
    dbg!(&failed);
    assert!(failed.err().filter(|x| matches!(x, AccessTokenError::CoseCipherError(CoseCipherError::DecryptionFailure))).is_some());
    Ok(())
}

#[test]
fn test_encrypt_decrypt_match_multiple() -> Result<(), AccessTokenError<<FakeCrypto as CoseEncryptCipher>::Error>> {
    let (unprotected_header, protected_header) = example_headers();
    let key1 = example_key_one();
    let rng = FakeRng;
    let aad = example_aad();
    let claims = ClaimsSetBuilder::new().build();
    let encrypted = encrypt_access_token_multiple::<FakeCrypto, FakeRng>(
        vec![&key1, &key1],
        claims,
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
        rng
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).expect("invalid headers");
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    // In the future, this should only be an error in "strict mode".
    assert!(decrypt_access_token_multiple::<FakeCrypto, FakeCrypto>(&key1, &encrypted, Some(&aad)).err().filter(|x| matches!(x, AccessTokenError::MultipleMatchingRecipients)).is_some());
    Ok(())
}

#[test]
fn test_encrypt_decrypt_invalid_header() -> Result<(), AccessTokenError<<FakeCrypto as CoseEncryptCipher>::Error>> {
    let key = example_key_one();
    let (unprotected_header, protected_header) = example_headers();
    let (unprotected_invalid, protected_invalid) = example_invalid_headers();
    let claims = example_claims(key.to_cose_key())?;
    let aad = example_aad();
    let rng = FakeRng;
    let encrypted = encrypt_access_token::<FakeCrypto, FakeRng>(
        key.clone(),
        claims.clone(),
        Some(&aad),
        Some(unprotected_invalid),
        Some(protected_header),
        rng,
    );
    assert!(encrypted.err().map_or(false, |x| {
        if let AccessTokenError::CoseCipherError(CoseCipherError::HeaderAlreadySet {
                                                     existing_header_name,
                                                 }) = x
        {
            existing_header_name == "47"
        } else {
            false
        }
    }));

    let encrypted = encrypt_access_token::<FakeCrypto, FakeRng>(
        key,
        claims,
        Some(&aad),
        Some(unprotected_header),
        Some(protected_invalid),
        rng,
    );
    assert!(encrypted.is_err());
    assert!(encrypted.err().map_or(false, |x| {
        if let AccessTokenError::CoseCipherError(CoseCipherError::HeaderAlreadySet {
                                                     existing_header_name,
                                                 }) = x
        {
            existing_header_name == "alg"
        } else {
            false
        }
    }));

    Ok(())
}

#[test]
fn test_sign_verify() -> Result<(), AccessTokenError<<FakeCrypto as CoseSignCipher>::Error>> {
    let key = example_key_one();
    let (unprotected_header, protected_header) = example_headers();
    let claims = example_claims(key.to_cose_key())?;
    let aad = example_aad();
    let rng = FakeRng;
    let signed = sign_access_token::<FakeCrypto, FakeRng>(
        &key,
        claims,
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
        rng,
    )?;

    #[cfg(feature = "std")]
    println!("{:x?}", &signed);
    let (unprotected, protected) =
        get_token_headers(&signed).ok_or(AccessTokenError::<String>::UnknownCoseStructure)?;
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    verify_access_token::<FakeCrypto>(&key, &signed, Some(&aad))?;
    Ok(())
}

#[test]
fn test_sign_verify_multiple() -> Result<(), AccessTokenError<<FakeCrypto as CoseSignCipher>::Error>> {
    const AUDIENCE: &str = "example_aud";
    let key1 = example_key_one();
    let key2 = example_key_two();
    let invalid_key1 = FakeKey::try_from(vec![0, 0, 0, 0, 0, 0, 0]).expect("invalid test key");
    let invalid_key2 = FakeKey::try_from(vec![0, 0, 0, 0, 0, 0xDC, 0xAF]).expect("invalid test key");
    let (unprotected_header, protected_header) = example_headers();
    let claims = ClaimsSetBuilder::new().audience(AUDIENCE.to_string()).build();
    let aad = example_aad();
    let rng = FakeRng;
    let signed = sign_access_token_multiple::<FakeCrypto, FakeRng>(
        vec![&key1, &key2],
        claims,
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
        rng
    )?;
    let (unprotected, protected) =
        get_token_headers(&signed).ok_or(AccessTokenError::<String>::UnknownCoseStructure)?;
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    for key in vec![key1, key2] {
        verify_access_token_multiple::<FakeCrypto>(&key, &signed, Some(&aad))?;
    }
    assert!(verify_access_token_multiple::<FakeCrypto>(&invalid_key1, &signed, Some(&aad)).err().filter(|x| matches!(x, AccessTokenError::NoMatchingRecipient)).is_some());
    assert!(verify_access_token_multiple::<FakeCrypto>(&invalid_key2, &signed, Some(&aad)).err().filter(|x| matches!(x, AccessTokenError::CoseCipherError(CoseCipherError::VerificationFailure))).is_some());
    Ok(())
}