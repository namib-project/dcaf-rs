use coset::{AsCborValue, CoseKey, CoseKeyBuilder, HeaderBuilder};
use coset::cwt::ClaimsSetBuilder;
use coset::iana::{Algorithm, CwtClaimName};

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
    let protected_header = HeaderBuilder::new()
        .algorithm(Algorithm::AES_CCM_16_64_128)
        .build();
    (unprotected_header, protected_header)
}

fn example_aad() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05]
}

fn example_claims(key: CoseKey) -> Result<ClaimsSet, AccessTokenError> {
    Ok(ClaimsSetBuilder::new()
        .claim(
            CwtClaimName::Cnf,
            key.to_cbor_value()
                .map_err(AccessTokenError::from_cose_error)?,
        )
        .build())
}

#[derive(Copy, Clone)]
struct FakeCrypto {}

impl CipherProvider for FakeCrypto {
    fn encrypt(&mut self, data: &[u8], aad: &[u8]) -> Vec<u8> {
        // We simply put AAD behind the data and call it a day.
        let mut result: Vec<u8> = vec![];
        result.append(&mut data.to_vec());
        result.append(&mut aad.to_vec());
        result
    }

    fn decrypt(&mut self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        // Now we just split off the AAD we previously put at the end of the data.
        // We return an error if it does not match.
        if data.len() < aad.len() {
            return Err("Encrypted data must be at least as long as AAD!".to_string());
        }
        let mut result: Vec<u8> = data.to_vec();
        let aad_result = result.split_off(data.len() - aad.len());
        if aad != aad_result {
            Err("AADs don't match!".to_string())
        } else {
            Ok(result)
        }
    }

    fn sign(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn verify(&mut self, sig: &[u8], data: &[u8]) -> Result<(), String> {
        if sig != self.sign(data) {
            Err("failed to verify".to_string())
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_encrypt_decrypt() -> Result<(), AccessTokenError> {
    let mut crypto = FakeCrypto {};
    let key = example_key();
    let (unprotected_header, protected_header) = example_headers();
    let claims = example_claims(key)?;
    let aad = example_aad();
    let encrypted = encrypt_access_token(
        claims.clone(),
        unprotected_header,
        protected_header,
        &mut crypto,
        &aad,
    )?;
    assert_eq!(
        decrypt_access_token(encrypted, &aad, &mut crypto)?,
        claims
    );
    Ok(())
}

#[test]
fn test_sign_validate() -> Result<(), AccessTokenError> {
    let mut signer = FakeCrypto {};
    let key = example_key();
    let (unprotected_header, protected_header) = example_headers();
    let claims = example_claims(key)?;
    let aad = example_aad();
    let signed = sign_access_token(
        claims,
        unprotected_header,
        protected_header,
        &mut signer,
        &aad,
    )?;
    validate_access_token(signed, &aad, &mut signer)?;
    Ok(())
}
