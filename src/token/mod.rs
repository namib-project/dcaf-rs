//! **NOTE: The APIs in this module are experimental and likely to change in the future!**
//! This is due to the COSE support being very basic right now (e.g. only `CoseEncrypt0` instead of
//! `CoseEncrypt`) and due to the `CipherProvider` carrying more data which is present in the
//! parameters of the respective token functions right now, such as (part of) the headers.

use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseSign1, CoseSign1Builder, Header,
};
use coset::cwt::ClaimsSet;

use crate::common::ByteString;
use crate::error::AccessTokenError;

#[cfg(test)]
mod tests;

// TODO: Use actual error types for CipherProvider Results.

/// Provides basic operations for encrypting, decrypting, signing and verifying COSE structures.
///
/// This will be used by the corresponding token methods in this module to apply the cryptographic
/// operations to the constructed token bytestring.
/// If you need to operate on other fields in the token than just the claims, you can use the
/// struct behind this strait for that.
/// The methods provided in this trait accept `&mut self` in case the structure behind it needs to
/// modify internal fields during any cryptographic operation.
pub trait CipherProvider {

    /// Encrypts the given `plaintext` and `aad`, returning the result.
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;

    /// Decrypts the given `ciphertext` and `aad`, returning the result.
    ///
    /// # Errors
    /// If the `ciphertext` and `aad` are invalid, i.e., can't be decrypted.
    fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;

    /// Cryptographically signs the given `target` value and returns the signature.
    fn sign(&mut self, target: &[u8]) -> Vec<u8>;

    /// Verifies the `signature` of the `signed_data`.
    ///
    /// # Errors
    /// If the `signature` is invalid or does not belong to the `signed_data`.
    fn verify(&mut self, signature: &[u8], signed_data: &[u8]) -> Result<(), String>;
}

/// Encrypts the given `claims` with the given headers and `aad` using `cipher` for cryptography, 
/// returning the token as a serialized bytestring of the [`CoseEncrypt0`] structure.
///
/// If you need to encode additional fields other than `claims`, use the [`CipherProvider`] given in
/// `cipher` to store and encrypt them.
///
/// # Errors
/// - When there's a [`CoseError`] while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`] while serializing the [`CoseEncrypt0`] structure.
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

/// Signs the given `claims` with the given headers and `aad` using `cipher` for cryptography, 
/// returning the token as a serialized bytestring of the [`CoseSign1`] structure.
///
/// If you need to encode additional fields other than `claims`, use the [`CipherProvider`] given in
/// `cipher` to store and sign them.
///
/// # Errors
/// - When there's a [`CoseError`] while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`] while serializing the [`CoseSign1`] structure.
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

// TODO: Rename to `verify`, including validation error

/// Verifies the given `token` and `aad` using `verifier` for cryptography, 
/// returning an error in case it could not be verified.
///
/// NOTE: Protected headers are not verified as of now.
///
/// # Errors
/// - When there's a [`CoseError`] while deserializing the given `token` to a [`CoseSign1`] structure
///   (e.g., if it's not in fact a [`CoseSign1`] structure but rather something else).
/// - When there's a verification error coming from the `verifier` 
///   (e.g., if the `token`'s data does not match its signature).
pub fn validate_access_token<T>(
    token: ByteString,
    aad: &[u8],
    verifier: &mut T,
) -> Result<(), AccessTokenError>
    where
        T: CipherProvider
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    // TODO: Verify protected headers
    sign.verify_signature(aad, |signature, signed_data| verifier.verify(signature, signed_data))
        .map_err(AccessTokenError::with_validation_error_details)
}

/// Decrypts the given `token` and `aad` using `cipher` for cryptography, 
/// returning the decrypted `ClaimsSet`.
///
/// # Errors
/// - When there's a [`CoseError`] while deserializing the given `token` to a [`CoseEncrypt0`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt0`] structure but rather something else).
/// - When there's a decryption error coming from the `cipher`.
/// - When the deserialized and decrypted [`CoseEncrypt0`] structure does not contain a valid
///   [`ClaimsSet`].
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
