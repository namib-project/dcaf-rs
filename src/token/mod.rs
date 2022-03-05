use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseSign1, CoseSign1Builder, Header,
};
use coset::cwt::ClaimsSet;

use crate::common::ByteString;
use crate::error::AccessTokenError;

#[cfg(test)]
mod tests;

pub trait CipherProvider {
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
    fn sign(&mut self, target: &[u8]) -> Vec<u8>;
    fn verify(&mut self, signature: &[u8], signed_data: &[u8]) -> Result<(), String>;
}

pub fn encrypt_access_token<T>(claims: ClaimsSet, unprotected_header: Header,
                               protected_header: Header, cipher: &mut T, aad: &[u8],
) -> Result<ByteString, AccessTokenError> where T: CipherProvider
{
    Ok(ByteString::from(
        CoseEncrypt0Builder::new()
            .unprotected(unprotected_header)
            .protected(protected_header)
            .create_ciphertext(
                &claims.to_vec().map_err(AccessTokenError::from_cose_error)?[..],
                aad,
                |payload, aad| cipher.encrypt(payload, aad),
            )
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
}

pub fn sign_access_token<T>(
    claims: ClaimsSet,
    unprotected_header: Header,
    protected_header: Header,
    cipher: &mut T,
    aad: &[u8],
) -> Result<ByteString, AccessTokenError>
    where
        T: CipherProvider
{
    Ok(ByteString::from(
        CoseSign1Builder::new()
            .unprotected(unprotected_header)
            .protected(protected_header)
            .payload(claims.to_vec().map_err(AccessTokenError::from_cose_error)?)
            .create_signature(aad, |x| cipher.sign(x))
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
}

pub fn validate_access_token<T>(
    token: ByteString,
    aad: &[u8],
    verifier: &mut T,
) -> Result<(), AccessTokenError>
    where
        T: CipherProvider
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    // TODO: Validate protected headers
    sign.verify_signature(aad, |signature, signed_data| verifier.verify(signature, signed_data))
        .map_err(AccessTokenError::with_validation_error_details)
}

pub fn decrypt_access_token<T>(
    token: ByteString,
    aad: &[u8],
    cipher: &mut T,
) -> Result<ClaimsSet, AccessTokenError>
    where
        T: CipherProvider
{
    let encrypt =
        CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from_cose_error)?;
    let result = encrypt
        .decrypt(aad, |ciphertext, aad| cipher.decrypt(ciphertext, aad))
        .map_err(AccessTokenError::with_validation_error_details)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from_cose_error)
}
