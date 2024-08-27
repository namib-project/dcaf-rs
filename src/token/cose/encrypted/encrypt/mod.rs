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

use coset::{CoseEncrypt, CoseEncryptBuilder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::aad::AadProvider;
use crate::token::cose::encrypted;
use crate::token::cose::encrypted::try_decrypt;
use crate::token::cose::encrypted::EncryptCryptoBackend;
use crate::token::cose::key::KeyProvider;
use crate::token::cose::recipient::{
    struct_to_recipient_context, CoseNestedRecipientSearchContext, KeyDistributionCryptoBackend,
};

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extensions to the [`CoseEncryptBuilder`] type that enable usage of cryptographic backends.
pub trait CoseEncryptBuilderExt: Sized {
    /// Attempts to encrypt the provided payload using a cryptographic backend.
    ///
    /// Note that you still have to ensure that the key is available to the recipient somehow, i.e.
    /// by adding [`CoseRecipient`](coset::CoseRecipient) structures where suitable.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [`CoseEncrypt`] instance.
    ///                    Will override headers previously set using
    ///                    [`CoseEncryptBuilder::protected`](CoseEncryptBuilder).
    /// - `unprotected`  - unprotected headers for the resulting [`CoseEncrypt`] instance. Will
    ///                    override headers previously set using
    ///                    [`CoseEncryptBuilder::unprotected`](CoseEncryptBuilder).
    /// - `payload`      - payload which should be added to the resulting
    ///                    [`CoseEncrypt`](CoseEncrypt) instance in encrypted form.
    ///                    Will override a payload previously set using
    ///                    [`CoseEncryptBuilder::payload`](CoseEncryptBuilder).
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of
    /// those) are malformed or otherwise unsuitable for encryption, this function will return
    /// the most fitting [`CoseCipherError`] for the specific type of error.
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
    /// Refer to [the documentation for the CoseEncrypt extensions](CoseEncryptExt) for examples.
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

impl CoseEncryptBuilderExt for CoseEncryptBuilder {
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
                    Some(EncryptionContext::CoseEncrypt),
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

/// Extensions to the [`CoseEncrypt`] type that enable usage of cryptographic backends.
///
/// # Examples
///
/// Create a simple [`CoseEncrypt`] instance that uses the provided key directly and encrypts a
/// payload, then decrypt it:
///
/// ```
///
/// use coset::{CoseEncryptBuilder, CoseKeyBuilder, CoseRecipientBuilder, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseEncryptBuilderExt, CoseEncryptExt, HeaderBuilderExt};
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
/// let recipient = CoseRecipientBuilder::new()
///                     .unprotected(
///                         HeaderBuilder::new()
///                             .algorithm(iana::Algorithm::Direct)
///                             .key_id("example_key".as_bytes().to_vec())
///                             .build()
///                     )
///                     .build();
///
/// let cose_object = CoseEncryptBuilder::new()
///                     .add_recipient(recipient)
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
///
/// Create a simple [`CoseEncrypt`] instance with recipients that protect a content encryption key
/// using AES key wrap. Encrypt a plaintext for it, then verify it:
/// ```
///
/// use coset::{CoseEncryptBuilder, CoseKeyBuilder, CoseRecipientBuilder, EncryptionContext, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseRecipientBuilderExt, CoseEncryptBuilderExt, CoseEncryptExt, HeaderBuilderExt};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
///
/// let mut backend = OpensslContext::new();
///
/// let mut kek_data = vec![0; 32];
/// backend.generate_rand(kek_data.as_mut_slice())?;
/// let kek = CoseKeyBuilder::new_symmetric_key(kek_data).build();
///
/// let mut cek_data = vec![0; 32];
/// backend.generate_rand(cek_data.as_mut_slice())?;
/// let cek = CoseKeyBuilder::new_symmetric_key(cek_data.clone()).build();
///
/// let unprotected = HeaderBuilder::new()
///                     .algorithm(iana::Algorithm::A256GCM)
///                     .gen_iv(&mut backend, iana::Algorithm::A256GCM)?
///                     .build();
///
/// let recipient_unprotected = HeaderBuilder::new()
///                             .algorithm(iana::Algorithm::A256KW)
///                             .key_id("example_key".as_bytes().to_vec())
///                             .build();
/// let recipient = CoseRecipientBuilder::new()
///                     .try_encrypt(
///                         &mut backend,
///                         &kek,
///                         EncryptionContext::MacRecipient,
///                         None,
///                         Some(recipient_unprotected),
///                         cek_data.as_slice(),
///                         &[] as &[u8]
///                     )?
///                     .build();
///
/// let cose_object = CoseEncryptBuilder::new()
///                     .try_encrypt(
///                         &mut backend,
///                         &cek,
///                         None,
///                         Some(unprotected),
///                         "This is the payload!".as_bytes(),
///                         &[] as &[u8]
///                     )?
///                     .add_recipient(recipient)
///                     .build();
///
/// let plaintext = cose_object.try_decrypt_with_recipients(&mut backend, &kek, &[] as &[u8])?;
///
/// assert_eq!(plaintext.as_slice(), "This is the payload!".as_bytes());
///
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
pub trait CoseEncryptExt {
    /// Attempts to decrypt the payload contained in this object using a cryptographic backend.
    ///
    /// Note that [`CoseRecipient`](coset::CoseRecipient)s are not considered for key lookup here,
    /// the key provider must provide the key used directly for MAC calculation.
    /// If your key provider can/should be able to provide the key for a contained
    /// [`CoseRecipient`](coset::CoseRecipient), not for the [`CoseEncrypt`] instance itself, use
    /// [`CoseEncrypt::try_decrypt_with_recipients`] instead.
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
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of
    /// those) are malformed or otherwise unsuitable for encryption, this function will return
    /// the most fitting [`CoseCipherError`] for the specific type of error.
    ///
    /// If additional authenticated data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [`CoseCipherError::AadUnsupported`] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but decryption fails for all key candidates provided by
    /// the key provider a [`CoseCipherError::NoMatchingKeyFound`] error will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid encrypted payload or AAD for an otherwise valid and suitable object+key
    ///  pairing, this would usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Verify the example `enveloped-tests/env-pass-01.json` from the `cose-wg/Examples` repository
    /// referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseEncrypt, CoseKeyBuilder, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseEncryptExt;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D8608441A0A20101054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B9874993C63B0382A855573F0990CD18E818340A20125044A6F75722D73656372657440").unwrap();
    /// let cose_symmetric_key_k = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("hJtXIZ2uSN5kbQfbtTNWbg").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseEncrypt::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
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
    /// Attempt to verify the example `enveloped-tests/env-fail-02` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend (should fail,
    /// as the ciphertext is invalid):
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseEncrypt, CoseKeyBuilder, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseEncryptExt;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    /// use dcaf::error::CoseCipherError;
    ///
    /// let cose_object_cbor_data =
    ///     hex::decode("D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FD818340A20125044A6F75722D73656372657440")
    ///         .unwrap();
    /// let cose_symmetric_key_k =
    ///     base64::engine::general_purpose::URL_SAFE_NO_PAD
    ///         .decode("hJtXIZ2uSN5kbQfbtTNWbg")
    ///         .unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseEncrypt::from_tagged_slice(
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

    /// Attempts to decrypt the payload contained in this object using a cryptographic backend,
    /// performing a search through the contained [`CoseRecipient`](coset::CoseRecipient)s in order
    /// to decrypt the content encryption key (CEK).
    ///
    /// Note: As of now, if a recipient of type [`iana::Algorithm::Direct`](coset::iana::Algorithm::Direct)
    /// is present, there is no check to ensure that `Direct` is the only method used on the message
    /// (RFC 9052, Section 8.5.1).
    /// If you _need_ to ensure this, you must implement this check on your own.
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
    /// If the COSE object itself is not malformed, but decryption of all [`CoseRecipient`](coset::CoseRecipient)s fails
    /// (due to non-available keys or malformation), [`CoseCipherError::NoDecryptableRecipientFound`]
    /// is returned with a list of the attempted recipients and resulting errors.
    ///
    /// Note that not all recipients will necessarily be tried, as a malformed [`CoseRecipient`](coset::CoseRecipient) will
    /// terminate the recipient search early.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid encrypted payload or AAD for an otherwise valid and suitable object+key
    /// pairing, this would usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Verify the example `aes-wrap-examples/aes-wrap-128-04.json` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseEncrypt, CoseKeyBuilder, CoseMac, TaggedCborSerializable};
    /// use dcaf::error::CoseCipherError;
    /// use dcaf::token::cose::{CryptoBackend, CoseEncryptExt, CoseMacExt};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D8608443A10101A1054CDDDC08972DF9BE62855291A158246F5556D71834CD1BD3FDCBFFF28CFA0F7D598C138D23B40C225AF5E3F2096A46C766813D818340A20122044A6F75722D7365637265745818112872F405A5AC48A2EDE46AC20E93E3D3A38B9762D0A3E8").unwrap();
    /// let cose_symmetric_key_k = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("hJtXIZ2uSN5kbQfbtTNWbg").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseEncrypt::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_symmetric_key(cose_symmetric_key_k).build();
    /// let aad: Vec<u8> = Vec::new();
    ///
    /// let plaintext = cose_object.try_decrypt_with_recipients(
    ///                     &mut OpensslContext::new(),
    ///                     &mut &key,
    ///                     &aad
    ///                 )?;
    ///
    /// assert_eq!(plaintext.as_slice(), "This is the content.".as_bytes());
    ///
    /// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
    /// ```
    fn try_decrypt_with_recipients<
        B: KeyDistributionCryptoBackend + EncryptCryptoBackend,
        CKP: KeyProvider,
        CAP: AadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        external_aad: CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncryptExt for CoseEncrypt {
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
                    Some(EncryptionContext::CoseEncrypt),
                    Some(&self.protected.header),
                    Some(&self.unprotected),
                )
                .unwrap_or(&[] as &[u8]),
            |ciphertext, aad| {
                try_decrypt(
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

    fn try_decrypt_with_recipients<
        B: KeyDistributionCryptoBackend + EncryptCryptoBackend,
        CKP: KeyProvider,
        CAP: AadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        external_aad: CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        let nested_recipient_key_provider = CoseNestedRecipientSearchContext::new(
            &self.recipients,
            Rc::clone(&backend),
            key_provider,
            &external_aad,
            struct_to_recipient_context(EncryptionContext::CoseEncrypt),
        );
        match self.decrypt(
            external_aad
                .lookup_aad(
                    Some(EncryptionContext::CoseEncrypt),
                    Some(&self.protected.header),
                    Some(&self.unprotected),
                )
                .unwrap_or(&[] as &[u8]),
            |ciphertext, aad| {
                try_decrypt(
                    &backend,
                    &nested_recipient_key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    ciphertext,
                    aad,
                )
            },
        ) {
            Err(CoseCipherError::NoMatchingKeyFound(cek_errors)) => {
                Err(CoseCipherError::NoDecryptableRecipientFound(
                    nested_recipient_key_provider.into_errors(),
                    cek_errors,
                ))
            }
            v => v,
        }
    }
}
