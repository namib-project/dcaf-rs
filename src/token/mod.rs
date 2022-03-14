//! Contains methods for encrypting, decrypting, signing and verifying access tokens.
//!
//! **NOTE: The APIs in this module are experimental and likely to change in the future!**
//! This is due to the COSE support being very basic right now (e.g. only `CoseEncrypt0` instead of
//! `CoseEncrypt`) and due to the `CipherProvider` carrying more data which is present in the
//! parameters of the respective token functions right now, such as (part of) the headers.

use core::fmt::{Debug, Display};
use crate::common::cbor_values::ByteString;
use coset::cwt::ClaimsSet;
use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseMac0, CoseSign1, CoseSign1Builder,
    Header, ProtectedHeader,
};

use crate::error::{AccessTokenError, CoseCipherError};

#[cfg(test)]
mod tests;

pub trait CoseCipherCommon {
    type Error: Display + Debug;

    fn header(
        &self,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Provides basic operations for encrypting, decrypting, signing and verifying COSE structures.
///
/// This will be used by the corresponding token methods in this module to apply the cryptographic
/// operations to the constructed token bytestring.
/// If you need to operate on other fields in the token than just the claims, you can use the
/// struct behind this strait for that.
/// The methods provided in this trait accept `&mut self` in case the structure behind it needs to
/// modify internal fields during any cryptographic operation.
pub trait CoseEncrypt0Cipher: CoseCipherCommon {
    /// Encrypts the given `plaintext` and `aad`, returning the result.
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;

    /// Decrypts the given `ciphertext` and `aad`, returning the result.
    ///
    /// # Errors
    /// If the `ciphertext` and `aad` are invalid, i.e., can't be decrypted.
    fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

pub trait CoseSign1Cipher: CoseCipherCommon {
    /// Cryptographically signs the given `target` value and returns the signature.
    fn generate_signature(&mut self, target: &[u8]) -> Vec<u8>;

    /// Verifies the `signature` of the `signed_data`.
    ///
    /// # Errors
    /// If the `signature` is invalid or does not belong to the `signed_data`.
    fn verify_signature(
        &mut self,
        signature: &[u8],
        signed_data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

pub trait CoseMac0Cipher: CoseCipherCommon {
    fn generate_tag(&mut self, target: &[u8]) -> Vec<u8>;

    fn verify_tag(&mut self, tag: &[u8], maced_data: &[u8]) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Encrypts the given `claims` with the given headers and `aad` using `cipher` for cryptography,
/// returning the token as a serialized bytestring of the [`CoseEncrypt0`] structure.
///
/// If you need to encode additional fields other than `claims`, use the [`CoseEncrypt0Cipher`] given in
/// `cipher` to store and encrypt them.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt0`] structure.
pub fn encrypt_access_token<T>(
    claims: ClaimsSet,
    mut unprotected_header: Header,
    mut protected_header: Header,
    cipher: &mut T,
    aad: &[u8],
) -> Result<ByteString, AccessTokenError<T::Error>>
    where
        T: CoseEncrypt0Cipher,
{
    cipher
        .header(&mut unprotected_header, &mut protected_header)
        .map_err(AccessTokenError::from_cose_cipher_error)?;
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
/// If you need to encode additional fields other than `claims`, use the [`CoseSign1Cipher`] given
/// in `cipher` to store and sign them.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign1`] structure.
pub fn sign_access_token<T>(
    claims: ClaimsSet,
    mut unprotected_header: Header,
    mut protected_header: Header,
    cipher: &mut T,
    aad: &[u8],
) -> Result<ByteString, AccessTokenError<T::Error>>
    where
        T: CoseSign1Cipher,
{
    cipher
        .header(&mut unprotected_header, &mut protected_header)
        .map_err(AccessTokenError::from_cose_cipher_error)?;
    Ok(ByteString::from(
        CoseSign1Builder::new()
            .unprotected(unprotected_header)
            .protected(protected_header)
            .payload(claims.to_vec().map_err(AccessTokenError::from_cose_error)?)
            .create_signature(aad, |x| cipher.generate_signature(x))
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
}

/// Returns the headers of the given signed ([`CoseSign1`]), MAC tagged ([`CoseMac0`]),
/// or encrypted ([`CoseEncrypt0`]) access token.
///
/// When the given `token` is neither a [`CoseEncrypt0`], [`CoseSign1`], nor a [`CoseMac0`]
/// structure, `None` is returned.
pub fn get_token_headers(
    token: &ByteString,
) -> Option<(Header, ProtectedHeader)> {
    CoseSign1::from_slice(token.as_slice())
        .map(|x| (x.unprotected, x.protected))
        .or_else(|_| {
            CoseEncrypt0::from_slice(token.as_slice()).map(|x| (x.unprotected, x.protected))
        })
        .or_else(|_| CoseMac0::from_slice(token.as_slice()).map(|x| (x.unprotected, x.protected)))
        .ok()
}

/// Verifies the given `token` and `aad` using `verifier` for cryptography,
/// returning an error in case it could not be verified.
///
/// NOTE: Protected headers are not verified as of now.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing the given `token`
///   to a [`CoseSign1`] structure
///   (e.g., if it's not in fact a [`CoseSign1`] structure but rather something else).
/// - When there's a verification error coming from the `verifier`
///   (e.g., if the `token`'s data does not match its signature).
pub fn verify_access_token<T>(
    token: &ByteString,
    aad: &[u8],
    verifier: &mut T,
) -> Result<(), AccessTokenError<T::Error>>
    where
        T: CoseSign1Cipher,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    // TODO: Verify protected headers
    sign.verify_signature(aad, |signature, signed_data| {
        verifier.verify_signature(signature, signed_data)
    })
        .map_err(AccessTokenError::from_cose_cipher_error)
}

/// Decrypts the given `token` and `aad` using `cipher` for cryptography,
/// returning the decrypted `ClaimsSet`.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing
///   the given `token` to a [`CoseEncrypt0`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt0`] structure but rather something else).
/// - When there's a decryption error coming from the `cipher`.
/// - When the deserialized and decrypted [`CoseEncrypt0`] structure does not contain a valid
///   [`ClaimsSet`].
pub fn decrypt_access_token<T>(
    token: &ByteString,
    aad: &[u8],
    cipher: &mut T,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
    where
        T: CoseEncrypt0Cipher,
{
    let encrypt =
        CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from_cose_error)?;
    let result = encrypt
        .decrypt(aad, |ciphertext, aad| cipher.decrypt(ciphertext, aad))
        .map_err(AccessTokenError::from_cose_cipher_error)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from_cose_error)
}
