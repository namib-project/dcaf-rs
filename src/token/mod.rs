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

use crate::common::cbor_values::ByteString;
use crate::error::AccessTokenError;
pub use crate::token::cose::CoseSignCipher;
use crate::token::cose::{CoseAadProvider, CoseCipher};
use ciborium::value::Value;
use cose::determine_algorithm;
use cose::CoseRecipientBuilderExt;
use cose::{generate_cek_for_alg, CoseKeyProvider};
use cose::{
    CoseEncrypt0BuilderExt, CoseEncrypt0Ext, CoseEncryptBuilderExt, CoseEncryptCipher,
    CoseEncryptExt, CoseKeyDistributionCipher,
};
use cose::{CoseSign1BuilderExt, CoseSign1Ext};
use cose::{CoseSignBuilderExt, CoseSignExt};
use coset::cwt::ClaimsSet;
use coset::{
    iana, Algorithm, AsCborValue, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder,
    CoseEncryptBuilder, CoseKey, CoseKeyBuilder, CoseRecipientBuilder, CoseSign, CoseSign1,
    CoseSign1Builder, CoseSignBuilder, CoseSignature, EncryptionContext, Header, HeaderBuilder,
    ProtectedHeader,
};

/// `coset` extensions that enable COSE operations using predefined cryptographic backends.
pub mod cose;
#[cfg(test)]
mod tests;

/// Encrypts the given `claims` with the given headers and `external_aad` using the
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
pub fn encrypt_access_token<T, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    key: &CoseKey,
    claims: ClaimsSet,
    external_aad: &AAD,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher + CoseCipher,
{
    CoseEncrypt0Builder::new()
        .try_encrypt(
            backend,
            key,
            protected_header,
            unprotected_header,
            claims.to_vec()?.as_slice(),
            external_aad,
        )?
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
pub fn encrypt_access_token_multiple<'a, T, I, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    keys: I,
    claims: ClaimsSet,
    external_aad: &AAD,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher + CoseKeyDistributionCipher,
    I: IntoIterator<Item = &'a CoseKey>,
    I::IntoIter: ExactSizeIterator,
{
    let mut result = CoseEncryptBuilder::new();
    let mut key_iter = keys.into_iter();
    let preset_algorithm =
        determine_algorithm(None, protected_header.as_ref(), unprotected_header.as_ref());

    let cek = if key_iter.len() == 1 && preset_algorithm.is_err() {
        let key = key_iter.next().unwrap();
        let ce_alg = determine_algorithm(
            Some(key),
            protected_header.as_ref(),
            unprotected_header.as_ref(),
        )?;
        let recipient_header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::Direct)
            .key_id(key.key_id.clone())
            .build();
        result = result.add_recipient(
            CoseRecipientBuilder::new()
                .unprotected(recipient_header)
                .build(),
        );
        let mut cek_key = key.clone();
        cek_key.alg = Some(Algorithm::Assigned(ce_alg));
        cek_key
    } else {
        let ce_alg = preset_algorithm?;
        let cek_v = generate_cek_for_alg(backend, ce_alg)?;
        let cek = CoseKeyBuilder::new_symmetric_key(cek_v.clone()).build();

        for key in key_iter {
            // TODO allow manually setting headers for each recipient.
            let kek_alg = determine_algorithm(Some(key), None, None)?;
            let recipient_header = HeaderBuilder::new().algorithm(kek_alg).build();
            let recipient = CoseRecipientBuilder::new().try_encrypt(
                backend,
                key,
                EncryptionContext::EncRecipient,
                None,
                Some(recipient_header),
                cek_v.as_slice(),
                None,
            )?;

            result = result.add_recipient(recipient.build());
        }
        cek
    };

    result = result.try_encrypt(
        backend,
        &cek,
        protected_header,
        unprotected_header,
        claims.to_vec()?.as_slice(),
        external_aad,
    )?;
    result.build().to_vec().map_err(AccessTokenError::from)
}

/// Signs the given `claims` with the given headers and `external_aad` using the `key` and the
/// cryptographic backend given by type parameter `T`, returning the token as a serialized
/// byte string of the resulting [`CoseSign1`] structure.
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
pub fn sign_access_token<T, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    key: &CoseKey,
    claims: ClaimsSet,
    external_aad: &AAD,
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
            external_aad,
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
pub fn sign_access_token_multiple<'a, T, I, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    keys: I,
    claims: ClaimsSet,
    external_aad: &AAD,
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
    for (key, signature) in keys {
        builder = builder.try_add_sign::<T, &CoseKey, _>(backend, &key, signature, external_aad)?;
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
pub fn verify_access_token<T, CKP, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,

    token: &ByteString,
    external_aad: &AAD,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
    CKP: CoseKeyProvider,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    sign.try_verify(backend, key_provider, external_aad)
        .map_err(AccessTokenError::from)
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
pub fn verify_access_token_multiple<T, CKP, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,

    token: &ByteString,
    external_aad: &AAD,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
    CKP: CoseKeyProvider,
{
    let sign = CoseSign::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    sign.try_verify(backend, key_provider, external_aad)?;
    Ok(())
}

/// Decrypts the given `token` and `external_aad` using the `key` and the cipher
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
pub fn decrypt_access_token<T, CKP, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,

    token: &ByteString,
    external_aad: &AAD,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher,
    CKP: CoseKeyProvider,
{
    let encrypt = CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let result = encrypt.try_decrypt(backend, key_provider, external_aad)?;
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
pub fn decrypt_access_token_multiple<T, CKP, AAD: CoseAadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,

    token: &ByteString,
    external_aad: &AAD,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher + CoseKeyDistributionCipher,
    CKP: CoseKeyProvider,
{
    let encrypt = CoseEncrypt::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let result = encrypt.try_decrypt_with_recipients(backend, key_provider, external_aad)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
}
