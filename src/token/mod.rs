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

//! Contains methods for [encrypting](encrypt_access_token), [decrypting](decrypt_access_token),
//! [signing](sign_access_token) and [verifying](verify_access_token) access tokens.
//!
//! **NOTE: The APIs in this module are experimental and likely to change in the future!**
//! This is because we plan to move much of the code here to the [coset](https://docs.rs/coset/)
//! library, since much of this just builds on COSE functionality and isn't ACE-OAuth specific.
//!
//! In order to use any of these methods, you will need to provide a cipher which handles
//! the cryptographic operations by implementing either [`CoseEncryptCipher`],
//! [`CoseMacCipher`] or [`CoseSignCipher`], depending on the intended operation.
//! If you plan to support `CoseEncrypt` or `CoseSign` rather than just `CoseEncrypt0` or
//! `CoseSign1` (i.e., if you have multiple recipients with separate keys), you will also need to
//! implement [`MultipleEncryptCipher`] or [`MultipleSignCipher`].
//! See the respective traits for details.
//!
//! # Example
//! The following shows how to create and sign an access token (assuming a cipher named
//! `FakeCrypto` which implements [`CoseSignCipher`] exists.):
//! ```ignore
//! # // TODO: There's really too much hidden code here. Should be heavily refactored once we have
//! # //       crypto implementations available. Same goes for crate-level docs.
//! # use ciborium::value::Value;
//! # use coset::{AsCborValue, CoseKey, CoseKeyBuilder, Header, iana, Label, ProtectedHeader};
//! # use coset::cwt::{ClaimsSetBuilder, Timestamp};
//! # use coset::iana::{Algorithm, CwtClaimName};
//! # use rand::{CryptoRng, RngCore};
//! # use dcaf::{ToCborMap, sign_access_token, verify_access_token, CoseSignCipher};
//! # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! # use dcaf::common::cbor_values::ProofOfPossessionKey::PlainCoseKey;
//! # use dcaf::error::{AccessTokenError, CoseCipherError};
//! use dcaf::token::CoseCipher;
//!
//! # struct FakeCrypto {}
//! #
//! # fn get_k_from_key(key: &CoseKey) -> Option<Vec<u8>> {
//! #     const K_PARAM: i64 = iana::SymmetricKeyParameter::K as i64;
//! #     for (label, value) in key.params.iter() {
//! #         if let Label::Int(K_PARAM) = label {
//! #             if let Value::Bytes(k_val) = value {
//! #                 return Some(k_val.clone());
//! #             }
//! #         }
//! #     }
//! #     None
//! # }
//! #
//! # #[derive(Clone, Copy)]
//! # pub(crate) struct FakeRng;
//! #
//! # impl RngCore for FakeRng {
//! #     fn next_u32(&mut self) -> u32 {
//! #         0
//! #     }
//! #
//! #     fn next_u64(&mut self) -> u64 {
//! #         0
//! #     }
//! #
//! #     fn fill_bytes(&mut self, dest: &mut [u8]) {
//! #         dest.fill(0);
//! #     }
//! #
//! #     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
//! #         dest.fill(0);
//! #         Ok(())
//! #     }
//! # }
//! #
//! # impl CryptoRng for FakeRng {}
//! #
//! # impl CoseCipher for FakeCrypto {
//! #     type Error = String;
//! #
//! #     fn set_headers<RNG: RngCore + CryptoRng>(key: &CoseKey, unprotected_header: &mut Header, protected_header: &mut Header, rng: RNG) -> Result<(), CoseCipherError<Self::Error>> {
//! #         // We have to later verify these headers really are used.
//! #         if let Some(label) = unprotected_header
//! #             .rest
//! #             .iter()
//! #             .find(|x| x.0 == Label::Int(47))
//! #         {
//! #             return Err(CoseCipherError::existing_header_label(&label.0));
//! #         }
//! #         if protected_header.alg != None {
//! #             return Err(CoseCipherError::existing_header("alg"));
//! #         }
//! #         unprotected_header.rest.push((Label::Int(47), Value::Null));
//! #         protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::Direct));
//! #         Ok(())
//! #     }
//! # }
//! #
//! # /// Implements basic operations from the [`CoseSignCipher`](crate::token::CoseSignCipher) trait
//! # /// without actually using any "real" cryptography.
//! # /// This is purely to be used for testing and obviously offers no security at all.
//! # impl CoseSignCipher for FakeCrypto {
//! #     fn sign(
//! #         key: &CoseKey,
//! #         target: &[u8],
//! #         unprotected_header: &Header,
//! #         protected_header: &Header,
//! #     ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
//! #         // We simply append the key behind the data.
//! #         let mut signature = target.to_vec();
//! #         let k = get_k_from_key(key);
//! #         signature.append(&mut k.expect("k must be present in key!"));
//! #         Ok(signature)
//! #     }
//! #
//! #     fn verify(
//! #         key: &CoseKey,
//! #         signature: &[u8],
//! #         signed_data: &[u8],
//! #         unprotected_header: &Header,
//! #         protected_header: &ProtectedHeader,
//! #         unprotected_signature_header: Option<&Header>,
//! #         protected_signature_header: Option<&ProtectedHeader>,
//! #     ) -> Result<(), CoseCipherError<Self::Error>> {
//! #         if signature
//! #             == Self::sign(
//! #             key,
//! #             signed_data,
//! #             unprotected_header,
//! #             &protected_header.header,
//! #         )?
//! #         {
//! #             Ok(())
//! #         } else {
//! #             Err(CoseCipherError::VerificationFailure)
//! #         }
//! #     }
//! # }
//!
//! let rng = FakeRng;
//! let key = CoseKeyBuilder::new_symmetric_key(vec![1,2,3,4,5]).key_id(vec![0xDC, 0xAF]).build();
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
//!      .build();
//! let token = sign_access_token::<FakeCrypto, FakeRng>(&key, claims, None, None, None, rng)?;
//! assert!(verify_access_token::<FakeCrypto>(&key, &token, None).is_ok());
//! # Ok::<(), AccessTokenError<String>>(())
//! ```

use core::fmt::{Debug, Display};

use crate::common::cbor_values::ByteString;
use crate::error::AccessTokenError;
use crate::token::cose::key::CoseKeyProvider;
pub use crate::token::cose::sign::CoseSignCipher;
use ciborium::value::Value;
use cose::sign::{CoseSign1BuilderExt, CoseSign1Ext};
use cose::sign::{CoseSignBuilderExt, CoseSignExt};
use coset::cwt::ClaimsSet;
use coset::{
    AsCborValue, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseKey, CoseSign, CoseSign1,
    CoseSign1Builder, CoseSignBuilder, CoseSignature, Header, ProtectedHeader,
};
use rand::{CryptoRng, RngCore};

pub mod cose;
#[cfg(test)]
#[cfg(disabled)]
mod tests;

/// Creates new headers if `unprotected_header` or `protected_header` is `None`, respectively,
/// and passes them to the `cipher`'s `header` function, returning the mutated result.
/// Arguments: key (expr), unprotected (ident), protected (ident), rng (expr), cipher (type)
macro_rules! prepare_headers {
    ($key:expr, $unprotected:ident, $protected:ident, $rng:expr, $t:ty) => {{
        let mut unprotected = $unprotected.unwrap_or_else(|| HeaderBuilder::new().build());
        let mut protected = $protected.unwrap_or_else(|| HeaderBuilder::new().build());
        <$t>::set_headers($key, &mut unprotected, &mut protected, $rng)?;
        Ok::<(Header, Header), CoseCipherError<<$t>::Error>>((unprotected, protected))
    }};
}

/*/// Encrypts the given `claims` with the given headers and `external_aad` using the
/// `key` and the cipher given by type parameter `T`, returning the token as a serialized
/// bytestring of the [`CoseEncrypt0`] structure.
///
/// Note that this method will create a token intended for a single recipient.
/// If you wish to create a token for more than one recipient, use
/// [`encrypt_access_token_multiple`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt0`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`CoseEncryptCipher`] in `FakeCrypto`, a random number generator
/// in `rng`, a [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey)
/// in `key` and want to associate this key with the access token we are about to create and encrypt:
/// ```ignore
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.to_cose_key().to_cbor_value()?)
///    .build();
/// let token: ByteString = encrypt_access_token::<FakeCrypto, FakeRng>(&key, claims.clone(), None, None, None, rng)?;
/// assert_eq!(decrypt_access_token::<FakeCrypto>(&key, &token, None)?, claims);
/// ```
pub fn encrypt_access_token<T, RNG>(
    key: &CoseKey,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    mut rng: RNG,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher,
    RNG: RngCore + CryptoRng,
{
    let (unprotected, protected) =
        prepare_headers!(key, unprotected_header, protected_header, &mut rng, T)?;
    CoseEncrypt0Builder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .create_ciphertext(
            &claims.to_vec()?[..],
            external_aad.unwrap_or(&[0; 0]),
            |payload, aad| T::encrypt(key, payload, aad, &unprotected, &protected),
        )
        .build()
        .to_vec()
        .map_err(AccessTokenError::from)
}

/// Encrypts the given `claims` with the given headers and `external_aad` for each recipient
/// by using the `keys` with the cipher given by type parameter `T`,
/// returning the token as a serialized bytestring of the [`CoseEncrypt`] structure.
///
/// Note that the given `keys` must each have an associated `kid` (key ID) field when converted
/// to COSE keys, as the recipients inside the [`CoseEncrypt`] are identified in this way.
///
/// The Content Encryption Key (used to encrypt the actual claims) is randomly generated by the
/// given cipher in `T`, whereas the given `keys` are used as Key Encryption Keys, that is,
/// they encrypt the Content Encryption Key for each recipient.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`MultipleEncryptCipher`] in `FakeCrypto`, a random number
/// generator in `rng`, and some `claims`, we can then create a token encrypted for two recipients
/// (with keys `key1` and `key2`, respectively) as follows:
/// ```ignore
/// let encrypted = encrypt_access_token_multiple::<FakeCrypto, FakeRng>(
///    vec![&key1, &key2], claims.clone(), None, None, None rng
/// )?;
/// ```
pub fn encrypt_access_token_multiple<T, RNG>(
    keys: Vec<&CoseKey>,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    mut rng: RNG,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: MultipleEncryptCipher,
    RNG: CryptoRng + RngCore,
{
    let key = T::generate_cek(&mut rng);
    let (unprotected, protected) =
        prepare_headers!(&key, unprotected_header, protected_header, &mut rng, T)?;
    let mut builder = CoseEncryptBuilder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .create_ciphertext(
            &claims.to_vec()?[..],
            external_aad.unwrap_or(&[0; 0]),
            |payload, aad| T::encrypt(&key, payload, aad, &protected, &unprotected),
        );
    let serialized_key: Vec<u8> = key.to_vec().map_err(AccessTokenError::CoseError)?;
    for rec_key in keys {
        let (rec_unprotected, rec_protected) = prepare_headers!(rec_key, None, None, &mut rng, T)?;
        builder = builder.add_recipient(
            CoseRecipientBuilder::new()
                .protected(rec_protected.clone())
                .unprotected(rec_unprotected.clone())
                .create_ciphertext(
                    // TODO: What should AAD be here?
                    EncryptionContext::EncRecipient,
                    &serialized_key,
                    &[0; 0],
                    |payload, aad| {
                        T::encrypt(rec_key, payload, aad, &rec_protected, &rec_unprotected)
                    },
                )
                .build(),
        );
    }
    builder.build().to_vec().map_err(AccessTokenError::from)
}*/

/// Signs the given `claims` with the given headers and `external_aad` using the `key` and the
/// cipher given by type parameter `T`, returning the token as a serialized bytestring of
/// the [`CoseSign1`] structure.
///
/// Note that this method will create a token intended for a single recipient.
/// If you wish to create a token for more than one recipient, use
/// [`sign_access_token_multiple`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign1`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`CoseSignCipher`] in `FakeCrypto`, a random number generator
/// in `rng`, a [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey)
/// in `key` and want to associate this key with the access token we are about to create and sign:
/// ```ignore
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.to_cose_key().to_cbor_value()?)
///    .build();
/// let token: ByteString = sign_access_token::<FakeCrypto, FakeRng>(&key, claims, None, None, None, rng)?;
/// assert!(verify_access_token::<FakeCrypto>(&key, &token, None).is_ok());
/// ```
pub fn sign_access_token<T>(
    backend: &mut T,
    key: &CoseKey,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
{
    CoseSign1Builder::new()
        .payload(claims.to_vec()?)
        .try_sign(
            backend,
            key,
            protected_header,
            unprotected_header,
            &mut external_aad.unwrap_or(&[]),
        )?
        .build()
        .to_vec()
        .map_err(AccessTokenError::from)
}

/// Signs the given `claims` with the given headers and `external_aad` for each recipient
/// by using the `keys` with the cipher given by type parameter `T`,
/// returning the token as a serialized bytestring of the [`CoseSign`] structure.
///
/// For each key in `keys`, another signature will be added, created with that respective key.
/// The given headers will be used for the [`CoseSign`] structure as a whole, not for each
/// individual signature.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`MultipleSignCipher`] in `FakeCrypto`,
/// a random number generator in `rng`, and some `claims`, we can then create a token
/// with signatures for two recipients (with keys `key1` and `key2`, respectively) as follows:
/// ```ignore
/// let signed = sign_access_token_multiple::<FakeCrypto, FakeRng>(
///     vec![&key1, &key2],
///     claims,
///     None, None, None,
///     rng
/// )?;
/// ```
pub fn sign_access_token_multiple<'a, T, I>(
    backend: &mut T,
    keys: I,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
    I: IntoIterator<Item = (&'a CoseKey, CoseSignature)>,
{
    let mut builder = CoseSignBuilder::new().payload(claims.to_vec()?);
    if let Some(unprotected) = unprotected_header {
        builder = builder.unprotected(unprotected);
    }
    if let Some(protected) = protected_header {
        builder = builder.protected(protected);
    }
    for (key, signature) in keys.into_iter() {
        builder = builder.try_add_sign::<T, &CoseKey, &[u8]>(
            backend,
            &mut &*key,
            signature,
            &mut external_aad.unwrap_or(&[]),
        )?;
    }

    builder.build().to_vec().map_err(AccessTokenError::from)
}

/// Returns the headers of the given signed ([`CoseSign1`] / [`CoseSign`]),
/// MAC tagged (`CoseMac0` / `CoseMac`), or encrypted ([`CoseEncrypt0`] / [`CoseEncrypt`])
/// access token.
///
/// When the given `token` is none of those structures mentioned above, `None` is returned.
///
/// # Example
/// For example, say you have an access token saved in `token` and want to look at its headers:
/// ```
/// # use dcaf::common::cbor_values::ByteString;
/// # use dcaf::token::get_token_headers;
/// # let token = vec![
/// # 0x84, 0x4b, 0xa2, 0x1, 0x25, 0x4, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0xa2, 0x5, 0x4d,
/// # 0x63, 0x68, 0x98, 0x99, 0x4f, 0xf0, 0xec, 0x7b, 0xfc, 0xf6, 0xd3, 0xf9, 0x5b, 0x18, 0x2f, 0xf6,
/// # 0x58, 0x20, 0xa1, 0x8, 0xa3, 0x1, 0x4, 0x2, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x20,
/// # 0x51, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
/// # 0x71, 0x8, 0x58, 0x40, 0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
/// # 0x4b, 0xa2, 0x1, 0x25, 0x4, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x45, 0x1, 0x2, 0x3, 0x4,
/// # 0x5, 0x58, 0x20, 0xa1, 0x8, 0xa3, 0x1, 0x4, 0x2, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x20,
/// # 0x51, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
/// # 0x71, 0x8];
/// if let Some((unprotected_header, protected_header)) = get_token_headers(&token) {
///   assert_eq!(protected_header.header.key_id, vec![0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c])
/// } else {
///   unreachable!("Example token should be valid.")
/// }
/// ```
#[must_use]
pub fn get_token_headers(token: &ByteString) -> Option<(Header, ProtectedHeader)> {
    let value: Option<Value> = ciborium::de::from_reader(token.as_slice()).ok();
    // All of COSE_Encrypt(0), COSE_Sign(1), COSE_Mac(0) are an array with headers first
    match value {
        Some(Value::Array(x)) => {
            let mut iter = x.into_iter();
            let protected = iter
                .next()
                .map(ProtectedHeader::from_cbor_bstr)
                .and_then(Result::ok);
            let unprotected = iter
                .next()
                .map(Header::from_cbor_value)
                .and_then(Result::ok);
            if let (Some(u), Some(p)) = (unprotected, protected) {
                Some((u, p))
            } else {
                None
            }
        }
        Some(_) | None => None,
    }
}

/// Verifies the given `token` and `external_aad` with the `key` using the cipher
/// given by type parameter `T`, returning an error in case it could not be verified.
///
/// This method should be used when the given `token` is a [`CoseSign1`] rather than
/// [`CoseSign`] (i.e., if it is intended for a single recipient). In case the token is an
/// instance of the latter, use [`verify_access_token_multiple`] instead.
///
/// NOTE: Protected headers are not verified as of now.
///
/// For an example, see the documentation of [`sign_access_token`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing the given `token`
///   to a [`CoseSign1`] structure
///   (e.g., if it's not in fact a [`CoseSign1`] structure but rather something else).
/// - When there's a verification error coming from the cipher `T`
///   (e.g., if the `token`'s data does not match its signature).
pub fn verify_access_token<'a, T, CKP>(
    backend: &mut T,
    key_provider: &mut CKP,
    try_all_keys: bool,
    token: &ByteString,
    mut external_aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
    CKP: CoseKeyProvider<'a>,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    let result = sign.try_verify(backend, key_provider, try_all_keys, &mut external_aad);
    result?;

    Ok(())
}

/// Verifies the given `token` and `external_aad` with the `key` using the cipher
/// given by type parameter `T`, returning an error in case it could not be verified.
///
/// This method should be used when the given `token` is a [`CoseSign`] rather than
/// [`CoseSign1`] (i.e., if it is intended for a multiple recipients). In case the token is an
/// instance of the latter, use [`verify_access_token`] instead.
///
/// NOTE: Protected headers are not verified as of now.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing the given `token`
///   to a [`CoseSign`] structure
///   (e.g., if it's not in fact a [`CoseSign`] structure but rather something else).
/// - When there's a verification error coming from the cipher `T`
///   (e.g., if the `token`'s data does not match its signature).
pub fn verify_access_token_multiple<'a, T, CKP>(
    backend: &mut T,
    key_provider: &mut CKP,
    try_all_keys: bool,
    token: &ByteString,
    mut external_aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
    CKP: CoseKeyProvider<'a>,
{
    let sign = CoseSign::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    sign.try_verify(backend, key_provider, try_all_keys, &mut &external_aad)?;

    // TODO NoMatchingRecipient error (probably requires CoseCipherError to have a variant for this
    //      as well)
    Ok(())
}

/*/// Decrypts the given `token` and `external_aad` using the `key` and the cipher
/// given by type parameter `T`, returning the decrypted [`ClaimsSet`].
///
/// This method should be used when the given `token` is a [`CoseEncrypt0`] rather than
/// [`CoseEncrypt`] (i.e., if it is intended for a single recipient). In case the token is an
/// instance of the latter, use [`decrypt_access_token_multiple`] instead.
///
/// For an example, see the documentation of [`encrypt_access_token`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing
///   the given `token` to a [`CoseEncrypt0`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt0`] structure but rather something else).
/// - When there's a decryption error coming from the cipher given by `T`.
/// - When the deserialized and decrypted [`CoseEncrypt0`] structure does not contain a valid
///   [`ClaimsSet`].
pub fn decrypt_access_token<T>(
    key: &CoseKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher,
{
    let encrypt = CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    // TODO: Verify protected header
    let result = encrypt.decrypt(external_aad.unwrap_or(&[0; 0]), |ciphertext, aad| {
        T::decrypt(key, ciphertext, aad, &unprotected, &protected)
    })?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
}

/// Decrypts the given `token` and `external_aad` using the Key Encryption Key `kek` and the cipher given
/// by type parameter `T`, returning the decrypted [`ClaimsSet`].
///
/// Note that the given `kek` must have an associated `kid` (key ID) field when converted
/// to a COSE key, as the recipient inside the [`CoseEncrypt`] is identified in this way.
///
/// This method should be used when the given `token` is a [`CoseEncrypt`] rather than
/// [`CoseEncrypt0`] (i.e., if it is intended for multiple recipients). In case the token is an
/// instance of the latter, use [`decrypt_access_token`] instead.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing
///   the given `token` to a [`CoseEncrypt`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt`] structure but rather something else).
/// - When there's a decryption error coming from the cipher given by `T`.
/// - When the deserialized and decrypted [`CoseEncrypt`] structure does not contain a valid
///   [`ClaimsSet`].
/// - When the [`CoseEncrypt`] contains either multiple matching recipients or none at all for
///   the given `kek`.
pub fn decrypt_access_token_multiple<K, C>(
    kek: &CoseKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<ClaimsSet, AccessTokenError<MultipleCoseError<K::Error, C::Error>>>
where
    K: CoseEncryptCipher,
    C: CoseEncryptCipher,
{
    let encrypt = CoseEncrypt::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    let aad = external_aad.unwrap_or(&[0; 0]);
    let kek_id = kek.key_id.as_slice();
    // One of the recipient structures should contain the CEK encrypted with our KEK.
    // TODO: Recipient structures can be encrypted themselves, and have nested recipient structures
    //       inside of them. We should probably search those as well (while still ensuring that
    //       there is a maximum recursion depth to avoid DoS or stack overflow.
    let recipients = encrypt
        .recipients
        .iter()
        .filter(|x| x.unprotected.key_id == kek_id || x.protected.header.key_id == kek_id);
    let mut content_keys = recipients.map(|r| {
        r.decrypt(
            EncryptionContext::EncRecipient,
            &[0; 0],
            |ciphertext, aad| K::decrypt(kek, ciphertext, aad, &r.unprotected, &r.protected),
        )
    });
    // Our CEK must be contained exactly once.
    if let Some(content_key_result) = content_keys.next() {
        if content_keys.next().is_none() {
            let content_key = content_key_result.map_err(CoseCipherError::from_kek_error)?;
            let target_key = CoseKey::from_slice(&content_key)
                .map_err(|_| CoseCipherError::DecryptionFailure)?;
            // TODO: Verify protected header
            let result = encrypt
                .decrypt(aad, |ciphertext, aad| {
                    C::decrypt(&target_key, ciphertext, aad, &unprotected, &protected)
                })
                .map_err(CoseCipherError::from_cek_error)?;
            ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
        } else {
            // TODO: Implement strict mode, where this is prohibited, otherwise allow it
            Err(AccessTokenError::MultipleMatchingRecipients)
        }
    } else {
        Err(AccessTokenError::NoMatchingRecipient)
    }
}
*/
