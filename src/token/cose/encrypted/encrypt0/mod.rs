/*
 * Copyright (c) 2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use coset::{CoseEncrypt0, CoseEncrypt0Builder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::aad::AadProvider;
use crate::token::cose::encrypted;
use crate::token::cose::encrypted::EncryptCryptoBackend;
use crate::token::cose::key::KeyProvider;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extensions to the [`CoseEncrypt0Builder`] type that enable usage of cryptographic backends.
pub trait CoseEncrypt0BuilderExt: Sized {
    /// Attempts to encrypt the given `payload` using a cryptographic backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [`CoseEncrypt0`] instance. Will override
    ///                    headers previously set using [`CoseEncrypt0Builder::protected`].
    /// - `unprotected`  - unprotected headers for the resulting [`CoseEncrypt0`] instance. Will override
    ///                    headers previously set using [`CoseEncrypt0Builder::unprotected`].
    /// - `payload`      - Data that should be encrypted and included in the [`CoseEncrypt0`]
    ///                    instance.
    /// - `external_aad` - provider of additional authenticated data that should be provided to the
    ///                    encryption algorithm (only suitable for AEAD algorithms).
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for encryption, this function will return the most fitting
    /// [`CoseCipherError`] for the specific type of error.
    ///
    /// If additional authenticated data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [`CoseCipherError::AadUnsupported`] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but the key provider does not provide a key, a
    /// [`CoseCipherError::NoMatchingKeyFound`] will be returned.
    ///
    /// # Examples
    ///
    /// Refer to [the documentation for the CoseEncrypt0 extensions](CoseEncrypt0Ext) for examples.
    fn try_encrypt<B: EncryptCryptoBackend, CKP: KeyProvider, CAP: AadProvider>(
        self,
        backend: &mut B,
        key_provider: &CKP,

        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {
    fn try_encrypt<B: EncryptCryptoBackend, CKP: KeyProvider, CAP: AadProvider>(
        self,
        backend: &mut B,
        key_provider: &CKP,

        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_ciphertext(
            payload,
            external_aad
                .lookup_aad(
                    Some(EncryptionContext::CoseEncrypt0),
                    protected.as_ref(),
                    unprotected.as_ref(),
                )
                .unwrap_or(&[] as &[u8]),
            |plaintext, aad| {
                encrypted::try_encrypt(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    plaintext,
                    aad,
                )
            },
        )
    }
}

/// Extensions to the [`CoseEncrypt0`] type that enable usage of cryptographic backends.
///
/// # Examples
///
/// Create a simple [`CoseEncrypt0`] instance that uses the provided key directly and encrypts a
/// payload, then decrypt it:
///
/// ```
///
/// use coset::{CoseEncrypt0Builder,CoseKeyBuilder, CoseRecipientBuilder, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseEncrypt0BuilderExt, CoseEncrypt0Ext, HeaderBuilderExt};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
///
/// let mut backend = OpensslContext::new();
///
/// let mut key_data = vec![0; 32];
/// backend.generate_rand(key_data.as_mut_slice())?;
/// let key = CoseKeyBuilder::new_symmetric_key(key_data).build();
///
/// let unprotected = HeaderBuilder::new()
///                     .algorithm(iana::Algorithm::A256GCM)
///                     .gen_iv(&mut backend, iana::Algorithm::A256GCM)?
///                     .key_id("example_key".as_bytes().to_vec())
///                     .build();
///
/// let cose_object = CoseEncrypt0Builder::new()
///                     .try_encrypt(
///                         &mut backend,
///                         &key,
///                         None,
///                         Some(unprotected),
///                         "This is the payload!".as_bytes(),
///                         &[] as &[u8]
///                     )?
///                     .build();
///
/// let plaintext = cose_object.try_decrypt(&mut backend, &key, &[] as &[u8])?;
/// assert_eq!(plaintext.as_slice(), "This is the payload!".as_bytes());
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
pub trait CoseEncrypt0Ext {
    /// Attempts to decrypt the payload contained in this object using a cryptographic backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `external_aad` - provider of additional authenticated data that should be authenticated
    ///                    while decrypting (only for AEAD algorithms).
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for decryption, this function will return the most fitting
    /// [`CoseCipherError`] for the specific type of error.
    ///
    /// If additional authenticated data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [`CoseCipherError::AadUnsupported`] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but decryption fails for all key candidates provided
    /// by the key provider a [`CoseCipherError::NoMatchingKeyFound`] will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid ciphertext for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Verify the example `encrypted-tests/enc-pass-01.json` from the `cose-wg/Examples` repository
    /// referenced in RFC 9052 using the [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext)
    /// backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseEncrypt, CoseEncrypt0, CoseKeyBuilder, CoseMac, TaggedCborSerializable};
    /// use dcaf::token::cose::{CoseEncrypt0Ext, CoseEncryptExt, CoseMacExt};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D08341A0A20101054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B24BEE54AA5D797C8DC845929ACAA47EF").unwrap();
    /// let cose_symmetric_key_k = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("hJtXIZ2uSN5kbQfbtTNWbg").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseEncrypt0::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_symmetric_key(cose_symmetric_key_k).build();
    /// let aad: Vec<u8> = Vec::new();
    ///
    /// assert!(
    ///     cose_object.try_decrypt(
    ///         &mut OpensslContext::new(),
    ///         &mut &key,
    ///         &aad
    ///     ).is_ok()
    /// );
    /// ```
    ///
    /// Attempt to verify the example `encrypted-tests/enc-fail-02` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend (should fail, as the
    /// ciphertext is invalid):
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseEncrypt, CoseEncrypt0, CoseKeyBuilder, CoseMac, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseEncrypt0Ext;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    /// use dcaf::error::CoseCipherError;
    ///
    /// let cose_object_cbor_data =
    ///     hex::decode("D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250B")
    ///         .unwrap();
    /// let cose_symmetric_key_k =
    ///     base64::engine::general_purpose::URL_SAFE_NO_PAD
    ///         .decode("hJtXIZ2uSN5kbQfbtTNWbg")
    ///         .unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseEncrypt0::from_tagged_slice(
    ///                     cose_object_cbor_data.as_slice()
    ///                   ).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_symmetric_key(cose_symmetric_key_k).build();
    /// let aad: Vec<u8> = Vec::new();
    ///
    /// assert!(
    ///     matches!(
    ///         cose_object.try_decrypt(
    ///             &mut OpensslContext::new(),
    ///             &mut &key,
    ///             &aad
    ///         ),
    ///         Err(CoseCipherError::NoMatchingKeyFound(_))
    ///     )
    /// );
    /// ```
    fn try_decrypt<B: EncryptCryptoBackend, CKP: KeyProvider, CAP: AadProvider>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0Ext for CoseEncrypt0 {
    fn try_decrypt<B: EncryptCryptoBackend, CKP: KeyProvider, CAP: AadProvider>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        self.decrypt(
            external_aad
                .lookup_aad(
                    Some(EncryptionContext::CoseEncrypt0),
                    Some(&self.protected.header),
                    Some(&self.unprotected),
                )
                .unwrap_or(&[] as &[u8]),
            |ciphertext, aad| {
                encrypted::try_decrypt(
                    &backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}
