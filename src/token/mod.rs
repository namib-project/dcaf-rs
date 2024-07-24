/*
 * Copyright (c) 2022-2024 The NAMIB Project Developers.
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
//! This is because we plan to move much of the code here to the [`coset`]
//! library, since much of this just builds on COSE functionality and isn't ACE-OAuth specific.
//!
//! In order to use any of these methods, you will need to provide a cryptographic backend which
//! handles the cryptographic operations by implementing either [`EncryptCryptoBackend`],
//! [`MacCryptoBackend`](cose::MacCryptoBackend) or [`SignCryptoBackend`], depending on the intended
//! operation.
//!
//! Implementations for these traits may be found in the [`cose::crypto_impl`]  module.
//!
//! If you plan to support `CoseEncrypt` or `CoseSign` rather than just `CoseEncrypt0` or
//! `CoseSign1` (i.e., if you have multiple recipients with separate keys), your backend might also
//! need to implement [`KeyDistributionCryptoBackend`].
//!
//! See the respective traits for details.
//!
//! # Creating Access Tokens
//! In order to create access tokens, you can use either [`encrypt_access_token`] or
//! [`sign_access_token`],
//! depending on whether you want the access token to be wrapped in a
//! `COSE_Encrypt0` or `COSE_Sign1` structure. In case you want to create a token intended for
//! multiple recipients (each with their own key), you can use
//! [`encrypt_access_token_multiple`] or [`sign_access_token_multiple`].
//!
//! Both functions take a [`ClaimsSet`] containing the claims that shall be part of the access
//! token, a key used to encrypt or sign the token, optional `aad` (additional authenticated data),
//! un-/protected headers and a cryptographic `backend` (as described in the [`cose`]  module).
//!
//! Note that if the headers you pass in set fields to invalid values, an error will be returned.
//! For more information on how to set headers, see the [`cose`]  module.
//!
//! The function will return a [`Result`] of the opaque [`ByteString`] containing the access token.
//!
//! # Verifying and Decrypting Access Tokens
//! In order to verify or decrypt existing access tokens represented as [`ByteString`]s, use
//! [`verify_access_token`] or [`decrypt_access_token`] respectively.
//! In case the token was created for multiple recipients (each with their own key),
//! use [`verify_access_token_multiple`] or [`decrypt_access_token_multiple`].
//!
//! Both functions take the access token, a `key_provider` that allows looking up keys that might be
//! used to decrypt or verify, optional `aad` (additional authenticated data) and a cryptographic
//! `backend` (as described in the [`cose`]  module).
//!
//! [`decrypt_access_token`] will return a result containing the decrypted [`ClaimsSet`].
//! [`verify_access_token`] will return an empty result which indicates that the token was
//! successfully verified---an [`Err`](Result)
//! would indicate failure.
//!
//! # Extracting Headers from an Access Token
//! Regardless of whether a token was signed, encrypted, or MAC-tagged, you can extract its
//! headers using [`get_token_headers`], which will return an option containing both unprotected and
//! protected headers (or which will be [`None`] in case he token is invalid).
//!
//! # Example
//! The following shows how to create and encrypt an access token:
//! ```
//! use coset::{AsCborValue, CoseKeyBuilder, HeaderBuilder, iana};
//! use coset::cwt::ClaimsSetBuilder;
//! use coset::iana::CwtClaimName;
//! use dcaf::{decrypt_access_token, encrypt_access_token};
//! use dcaf::error::{AccessTokenError, CoseCipherError};
//! use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
//! use dcaf::token::cose::{CryptoBackend, HeaderBuilderExt};
//!
//! let mut backend = OpensslContext::new();
//!
//! let mut key_data = vec![0; 32];
//! backend.generate_rand(key_data.as_mut_slice()).map_err(CoseCipherError::from)?;
//! let key = CoseKeyBuilder::new_symmetric_key(key_data).algorithm(iana::Algorithm::A256GCM).build();
//!
//! let unprotected_header = HeaderBuilder::new().gen_iv(&mut backend, iana::Algorithm::A256GCM)?.build();
//!
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
//!      .build();
//!
//! let token = encrypt_access_token(&mut backend, &key, claims, &None, Some(unprotected_header), None)?;
//! assert!(decrypt_access_token(&mut backend, &key, &token, &None).is_ok());
//! # Ok::<(), AccessTokenError<<OpensslContext as CryptoBackend>::Error>>(())
//! ```

use crate::common::cbor_values::ByteString;
use crate::error::AccessTokenError;
use crate::token::cose::CryptoBackend;
pub use crate::token::cose::SignCryptoBackend;
use ciborium::value::Value;
use cose::AadProvider;
use cose::CoseRecipientBuilderExt;
use cose::{determine_algorithm, KeyDistributionCryptoBackend};
use cose::{generate_cek_for_alg, KeyProvider};
use cose::{
    CoseEncrypt0BuilderExt, CoseEncrypt0Ext, CoseEncryptBuilderExt, CoseEncryptExt,
    EncryptCryptoBackend,
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

pub mod cose;
#[cfg(test)]
mod tests;

/// Encrypts the given `claims` with the given headers and `external_aad` using the
/// `key` and the cryptographic `backend`, returning the token as a serialized bytestring of the
/// [`CoseEncrypt0`] structure.
///
/// Note that this method will create a token intended for a single recipient.
/// If you wish to create a token for more than one recipient, use
/// [`encrypt_access_token_multiple`].
///
/// # Errors
/// Returns an error if the [`ClaimsSet`]  could not be encoded or an error during signing
/// occurs (see [`CoseEncryptBuilderExt::try_encrypt`]   for possible errors).
///
/// # Example
///
/// see the [module-level documentation](self) for an example
pub fn encrypt_access_token<T, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    key: &CoseKey,
    claims: ClaimsSet,
    external_aad: &AAD,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: EncryptCryptoBackend + CryptoBackend,
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
/// by using the `keys` with the cryptographic `backend`, returning the token as a serialized
/// bytestring of the [`CoseEncrypt`] structure.
///
/// The Content Encryption Key (used to encrypt the actual claims) is randomly generated by the
/// given `backend`, whereas the given `keys` are used as Key Encryption Keys, that is,
/// they encrypt the Content Encryption Key for each recipient.
///
/// # Errors
/// Returns an error if the [`ClaimsSet`]  could not be encoded or an error during signing
/// occurs (see [`CoseEncryptBuilderExt::try_encrypt] and [`CoseRecipientBuilderExt::try_encrypt``]  for
/// possible errors).
///
/// # Example
///
/// ```
/// use coset::{AsCborValue, CoseKeyBuilder, HeaderBuilder, iana};
/// use coset::cwt::ClaimsSetBuilder;
/// use coset::iana::CwtClaimName;
/// use dcaf::{decrypt_access_token, decrypt_access_token_multiple, encrypt_access_token, encrypt_access_token_multiple};
/// use dcaf::error::{AccessTokenError, CoseCipherError};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
/// use dcaf::token::cose::{CryptoBackend, HeaderBuilderExt};
///
/// let mut backend = OpensslContext::new();
///
/// let mut key1_data = vec![0; 32];
/// backend.generate_rand(key1_data.as_mut_slice()).map_err(CoseCipherError::from)?;
/// let key1 = CoseKeyBuilder::new_symmetric_key(key1_data).algorithm(iana::Algorithm::A256KW).build();
///
/// let mut key2_data = vec![0; 32];
/// backend.generate_rand(key2_data.as_mut_slice()).map_err(CoseCipherError::from)?;
/// let key2 = CoseKeyBuilder::new_symmetric_key(key2_data).algorithm(iana::Algorithm::A256KW).build();
///
/// let unprotected_header = HeaderBuilder::new().gen_iv(&mut backend, iana::Algorithm::A256GCM)?.algorithm(iana::Algorithm::A256GCM).build();
///
/// let claims = ClaimsSetBuilder::new()
///      .audience(String::from("coaps://rs.example.com"))
///      .issuer(String::from("coaps://as.example.com"))
///      .claim(CwtClaimName::Cnf, key1.clone().to_cbor_value()?)
///      .build();
///
/// let keys = vec![key1.clone(), key2.clone()];
///
/// let token = encrypt_access_token_multiple(&mut backend, &keys, claims, &None, Some(unprotected_header), None)?;
/// assert!(decrypt_access_token_multiple(&mut backend, &key1, &token, &None).is_ok());
/// assert!(decrypt_access_token_multiple(&mut backend, &key2, &token, &None).is_ok());
/// # Ok::<(), AccessTokenError<<OpensslContext as CryptoBackend>::Error>>(())
/// ```
// TODO I'm pretty sure this can't panic
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_access_token_multiple<'a, T, I, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    keys: I,
    claims: ClaimsSet,
    external_aad: &AAD,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: EncryptCryptoBackend + KeyDistributionCryptoBackend,
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
/// cryptographic `backend`, returning the token as a serialized byte string of the resulting
/// [`CoseSign1`] structure.
///
/// Note that this method will create a token with a single signature.
/// If you wish to create a token with multiple signatures, use [`sign_access_token_multiple`].
///
/// # Errors
/// Returns an error if the [`ClaimsSet`] could not be encoded or an error during signing
/// occurs (see [`CoseSign1BuilderExt::try_add_sign`](CoseSign1BuilderExt) for possible errors).
///
/// # Example
/// ```
/// use base64::Engine;
/// use coset::{AsCborValue, CoseKeyBuilder, HeaderBuilder, iana};
/// use coset::cwt::ClaimsSetBuilder;
/// use coset::iana::CwtClaimName;
/// use dcaf::{sign_access_token, verify_access_token};
/// use dcaf::error::{AccessTokenError, CoseCipherError};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
/// use dcaf::token::cose::{CryptoBackend, HeaderBuilderExt};
///
/// let mut backend = OpensslContext::new();
///
/// let cose_ec2_key_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
/// let cose_ec2_key_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
/// let cose_ec2_key_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
/// let key = CoseKeyBuilder::new_ec2_priv_key(
///                             iana::EllipticCurve::P_256,
///                             cose_ec2_key_x,
///                             cose_ec2_key_y,
///                             cose_ec2_key_d
///                 )
///                 .key_id("example_key".as_bytes().to_vec())
///                 .build();
///
/// let unprotected_header = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();
///
/// let claims = ClaimsSetBuilder::new()
///      .audience(String::from("coaps://rs.example.com"))
///      .issuer(String::from("coaps://as.example.com"))
///      .claim(CwtClaimName::Cnf, key.clone().to_cbor_value()?)
///      .build();
///
/// let token = sign_access_token(&mut backend, &key, claims, &None, Some(unprotected_header), None)?;
/// assert!(verify_access_token(&mut backend, &key, &token, &None).is_ok());
/// # Ok::<(), AccessTokenError<<OpensslContext as CryptoBackend>::Error>>(())
/// ```
pub fn sign_access_token<T, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    key: &CoseKey,
    claims: ClaimsSet,
    external_aad: &AAD,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: SignCryptoBackend,
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
/// by using the `keys` with the cryptographic `backend`, returning the token as a serialized
/// bytestring of the [`CoseSign`] structure.
///
/// For each key in `keys`, another signature will be added, created with that respective key.
/// The given headers will be used for the [`CoseSign`] structure as a whole, not for each
/// individual signature.
///
/// # Errors
/// Returns an error if the [`ClaimsSet`]  could not be encoded or an error during signing
/// occurs (see [`CoseSignBuilderExt::try_add_sign`]  for possible errors).
///
/// # Example
/// ```
/// use base64::Engine;
/// use coset::{AsCborValue, CoseKeyBuilder, CoseSignatureBuilder, HeaderBuilder, iana};
/// use coset::cwt::ClaimsSetBuilder;
/// use coset::iana::CwtClaimName;
/// use dcaf::{sign_access_token, sign_access_token_multiple, verify_access_token, verify_access_token_multiple};
/// use dcaf::error::{AccessTokenError, CoseCipherError};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
/// use dcaf::token::cose::{CryptoBackend, HeaderBuilderExt};
///
/// let mut backend = OpensslContext::new();
///
/// let cose_ec2_key1_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
/// let cose_ec2_key1_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
/// let cose_ec2_key1_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
/// let key1 = CoseKeyBuilder::new_ec2_priv_key(
///                             iana::EllipticCurve::P_256,
///                             cose_ec2_key1_x,
///                             cose_ec2_key1_y,
///                             cose_ec2_key1_d
///                 )
///                 .key_id("example_key".as_bytes().to_vec())
///                 .build();
/// let cose_ec2_key2_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc").unwrap();
/// let cose_ec2_key2_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s").unwrap();
/// let cose_ec2_key2_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo").unwrap();
/// let key2 = CoseKeyBuilder::new_ec2_priv_key(
///                             iana::EllipticCurve::P_384,
///                             cose_ec2_key2_x,
///                             cose_ec2_key2_y,
///                             cose_ec2_key2_d
///                 )
///                 .key_id("example_key2".as_bytes().to_vec())
///                 .build();
///
/// let unprotected_sig1_header = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();
/// let unprotected_sig2_header = HeaderBuilder::new().algorithm(iana::Algorithm::ES384).build();
///
/// let sig1 = CoseSignatureBuilder::new().unprotected(unprotected_sig1_header).build();
/// let sig2 = CoseSignatureBuilder::new().unprotected(unprotected_sig2_header).build();
///
/// let claims = ClaimsSetBuilder::new()
///      .audience(String::from("coaps://rs.example.com"))
///      .issuer(String::from("coaps://as.example.com"))
///      .claim(CwtClaimName::Cnf, key1.clone().to_cbor_value()?)
///      .build();
///
/// let keys = vec![(&key1, sig1), (&key2, sig2)];
///
/// let token = sign_access_token_multiple(&mut backend, keys, claims, &None, None, None)?;
/// assert!(verify_access_token_multiple(&mut backend, &key1, &token, &None).is_ok());
/// assert!(verify_access_token_multiple(&mut backend, &key2, &token, &None).is_ok());
/// # Ok::<(), AccessTokenError<<OpensslContext as CryptoBackend>::Error>>(())
/// ```
pub fn sign_access_token_multiple<'a, T, I, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    keys: I,
    claims: ClaimsSet,
    external_aad: &AAD,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: SignCryptoBackend,
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

/// Verifies the given `token` and `external_aad` using keys from the given `key_provider` and the
/// cryptographic `backend`, returning an error in case it could not be verified.
///
/// This method should be used when the given `token` is a [`CoseSign1`] rather than
/// [`CoseSign`] (i.e., if it is intended for a single recipient). In case the token is an
/// instance of the latter, use [`verify_access_token_multiple`] instead.
///
/// # Errors
/// Returns an error if the [`CoseSign1`]  structure could not be parsed, an error during decryption
/// occurs (see [`CoseSign1Ext::try_verify`]  for possible errors) or the contained payload is not a
/// valid [`ClaimsSet`] .
///
/// # Example
///
/// For an example, see the documentation of [`sign_access_token`].
pub fn verify_access_token<T, CKP, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,
    token: &ByteString,
    external_aad: &AAD,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: SignCryptoBackend,
    CKP: KeyProvider,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    sign.try_verify(backend, key_provider, external_aad)
        .map_err(AccessTokenError::from)
}

/// Verifies the given `token` and `external_aad` using keys from the given `key_provider` and the
/// cryptographic `backend`, returning an error in case it could not be verified.
///
/// This method should be used when the given `token` is a [`CoseSign`] rather than
/// [`CoseSign1`] (i.e., if it is intended for a multiple recipients). In case the token is an
/// instance of the latter, use [`verify_access_token`] instead.
///
/// # Errors
/// Returns an error if the [`CoseSign`]  structure could not be parsed, an error during decryption
/// occurs (see [`CoseSignExt::try_verify`]  for possible errors) or the contained payload is not a
/// valid [`ClaimsSet`] .
pub fn verify_access_token_multiple<T, CKP, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,
    token: &ByteString,
    external_aad: &AAD,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: SignCryptoBackend,
    CKP: KeyProvider,
{
    let sign = CoseSign::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    sign.try_verify(backend, key_provider, external_aad)?;
    Ok(())
}

/// Decrypts the given `token` and `external_aad` using keys from the given `key_provider` and the
/// cryptographic `backend`, returning the decrypted [`ClaimsSet`].
///
/// This method should be used when the given `token` is a [`CoseEncrypt0`] rather than
/// [`CoseEncrypt`] (i.e., if it is intended for a single recipient). In case the token is an
/// instance of the latter, use [`decrypt_access_token_multiple`] instead.
///
/// # Errors
/// Returns an error if the [`CoseEncrypt0`] structure could not be parsed, an error during
/// decryption occurs (see [`CoseEncrypt0Ext::try_decrypt_with_recipients`](CoseEncrypt0Ext) for
/// possible errors) or the decrypted payload is not a valid [`ClaimsSet`].
///
/// # Example
///
/// For an example, see the documentation of [`encrypt_access_token`].
pub fn decrypt_access_token<T, CKP, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,
    token: &ByteString,
    external_aad: &AAD,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: EncryptCryptoBackend,
    CKP: KeyProvider,
{
    let encrypt = CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let result = encrypt.try_decrypt(backend, key_provider, external_aad)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
}

/// Decrypts the given `token` and `external_aad` using keys from the given `key_provider` and the
/// cryptographic `backend`, returning the decrypted [`ClaimsSet`].
///
/// Note that the given `kek` must have an associated `kid` (key ID) field when converted
/// to a COSE key, as the recipient inside the [`CoseEncrypt`] is identified in this way.
///
/// This method should be used when the given `token` is a [`CoseEncrypt`] rather than
/// [`CoseEncrypt0`] (i.e., if it is intended for multiple recipients). In case the token is an
/// instance of the latter, use [`decrypt_access_token`] instead.
///
/// # Errors
/// Returns an error if the [`CoseEncrypt`]  structure could not be parsed, an error during decryption
/// occurs (see [`CoseEncryptExt::try_decrypt_with_recipients`]  for possible errors) or the decrypted
/// payload is not a valid [`ClaimsSet`] .
pub fn decrypt_access_token_multiple<T, CKP, AAD: AadProvider + ?Sized>(
    backend: &mut T,
    key_provider: &CKP,
    token: &ByteString,
    external_aad: &AAD,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: EncryptCryptoBackend + KeyDistributionCryptoBackend,
    CKP: KeyProvider,
{
    let encrypt = CoseEncrypt::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let result = encrypt.try_decrypt_with_recipients(backend, key_provider, external_aad)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
}
