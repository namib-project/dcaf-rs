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

use crate::common::test_helper::FakeCrypto;
use crate::error::CoseCipherError;
use ciborium::value::Value;
use coset::cwt::ClaimsSetBuilder;
use coset::iana::{Algorithm, CwtClaimName};
use coset::{AsCborValue, CoseKey, CoseKeyBuilder, CoseMac0Builder, HeaderBuilder};

#[cfg(not(feature = "std"))]
use alloc::vec;

use super::*;

fn example_key() -> CoseKey {
    CoseKeyBuilder::new_symmetric_key(vec![
        0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
        0x71, 0x08,
    ])
    .key_id(vec![0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c])
    .build()
}

fn example_headers() -> (Header, Header) {
    let unprotected_header = HeaderBuilder::new()
        .iv(vec![
            0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC, 0x7B, 0xFC, 0xF6, 0xD3, 0xF9, 0x5B,
        ])
        .build();
    let protected_header = HeaderBuilder::new().key_id(example_key().key_id).build();
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
    vec![0x01, 0x02, 0x03, 0x04, 0x05]
}

fn example_claims(
    key: CoseKey,
) -> Result<ClaimsSet, AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>> {
    Ok(ClaimsSetBuilder::new()
        .claim(
            CwtClaimName::Cnf,
            key.to_cbor_value()
                .map_err(AccessTokenError::from_cose_error)?,
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
fn test_get_headers_enc() -> Result<(), AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>> {
    let (unprotected_header, protected_header) = example_headers();
    let enc_test = CoseEncrypt0Builder::new()
        .unprotected(unprotected_header.clone())
        .protected(protected_header.clone())
        .build()
        .to_vec()
        .map_err(AccessTokenError::CoseError)?;
    assert_eq!(
        (unprotected_header, protected_header),
        get_token_headers(&enc_test)
            .map(|(u, p)| (u, p.header))
            .unwrap()
    );
    Ok(())
}

#[test]
fn test_get_headers_sign() -> Result<(), AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>>
{
    let (unprotected_header, protected_header) = example_headers();
    let sign_test = CoseSign1Builder::new()
        .unprotected(unprotected_header.clone())
        .protected(protected_header.clone())
        .build()
        .to_vec()
        .map_err(AccessTokenError::CoseError)?;
    assert_eq!(
        (unprotected_header, protected_header),
        get_token_headers(&sign_test)
            .map(|(u, p)| (u, p.header))
            .unwrap()
    );
    Ok(())
}

#[test]
fn test_get_headers_mac() -> Result<(), AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>> {
    let (unprotected_header, protected_header) = example_headers();
    let mac_test = CoseMac0Builder::new()
        .unprotected(unprotected_header.clone())
        .protected(protected_header.clone())
        .build()
        .to_vec()
        .map_err(AccessTokenError::CoseError)?;
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
fn test_encrypt_decrypt() -> Result<(), AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>> {
    let mut crypto = FakeCrypto {};
    let key = example_key();
    let (unprotected_header, protected_header) = example_headers();
    let claims = example_claims(key)?;
    let aad = example_aad();
    let encrypted = encrypt_access_token(
        claims.clone(),
        &mut crypto,
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;
    let (unprotected, protected) = get_token_headers(&encrypted).unwrap();
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    assert_eq!(
        decrypt_access_token(&encrypted, &mut crypto, Some(&aad))?,
        claims
    );
    Ok(())
}

#[test]
fn test_encrypt_decrypt_invalid_header(
) -> Result<(), AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>> {
    let mut crypto = FakeCrypto {};
    let key = example_key();
    let (unprotected_header, protected_header) = example_headers();
    let (unprotected_invalid, protected_invalid) = example_invalid_headers();
    let claims = example_claims(key)?;
    let aad = example_aad();
    let encrypted = encrypt_access_token(
        claims.clone(),
        &mut crypto,
        Some(&aad),
        Some(unprotected_invalid),
        Some(protected_header),
    );
    assert!(encrypted.is_err());
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

    let encrypted = encrypt_access_token(
        claims,
        &mut crypto,
        Some(&aad),
        Some(unprotected_header),
        Some(protected_invalid),
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
fn test_sign_verify() -> Result<(), AccessTokenError<<FakeCrypto as CoseCipherCommon>::Error>> {
    let mut crypto = FakeCrypto {};
    let key = example_key();
    let (unprotected_header, protected_header) = example_headers();
    let claims = example_claims(key)?;
    let aad = example_aad();
    let signed = sign_access_token(
        claims,
        &mut crypto,
        Some(&aad),
        Some(unprotected_header.clone()),
        Some(protected_header.clone()),
    )?;

    #[cfg(feature = "std")]
    println!("{:x?}", &signed);
    let (unprotected, protected) =
        get_token_headers(&signed).ok_or(AccessTokenError::UnknownCoseStructure)?;
    assert_header_is_part_of(&unprotected_header, &unprotected);
    assert_header_is_part_of(&protected_header, &protected.header);
    verify_access_token(&signed, &mut crypto, Some(&aad))?;
    Ok(())
}
