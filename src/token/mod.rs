use coset::cwt::ClaimsSet;
use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseSign1, CoseSign1Builder, Header,
};

use crate::cbor_values::ByteString;
use crate::AccessTokenError;

// TODO: Better error handling — don't just use Strings

#[cfg(test)]
mod tests;

pub fn encrypt_access_token<F>(
    claims: ClaimsSet,
    unprotected_header: Header,
    protected_header: Header,
    cipher: F,
    aad: &[u8],
) -> Result<ByteString, AccessTokenError>
where
    F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
{
    Ok(ByteString::from(
        CoseEncrypt0Builder::new()
            .unprotected(unprotected_header)
            .protected(protected_header)
            .create_ciphertext(
                &claims.to_vec().map_err(AccessTokenError::from_cose_error)?[..],
                aad,
                cipher,
            )
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
}

pub fn sign_access_token<F>(
    claims: ClaimsSet,
    unprotected_header: Header,
    protected_header: Header,
    cipher: F,
    aad: &[u8],
) -> Result<ByteString, AccessTokenError>
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    Ok(ByteString::from(
        CoseSign1Builder::new()
            .unprotected(unprotected_header)
            .protected(protected_header)
            .payload(claims.to_vec().map_err(AccessTokenError::from_cose_error)?)
            .create_signature(aad, cipher)
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
}

pub fn validate_access_token<F>(
    token: ByteString,
    aad: &[u8],
    verifier: F,
) -> Result<(), AccessTokenError>
where
    F: FnOnce(&[u8], &[u8]) -> Result<(), String>,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    // TODO: Validate protected headers
    sign.verify_signature(aad, verifier)
        .map_err(AccessTokenError::with_validation_error_details)
}

pub fn decrypt_access_token<F>(
    token: ByteString,
    aad: &[u8],
    cipher: F,
) -> Result<ClaimsSet, AccessTokenError>
where
    F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, String>,
{
    let encrypt =
        CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from_cose_error)?;
    let result = encrypt
        .decrypt(aad, cipher)
        .map_err(AccessTokenError::with_validation_error_details)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from_cose_error)
}
