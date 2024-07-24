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
use core::cell::RefCell;

use coset::{CoseMac, CoseMacBuilder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::aad::AadProvider;
use crate::token::cose::key::KeyProvider;
use crate::token::cose::maced::{try_compute, try_verify, MacCryptoBackend};
use crate::token::cose::recipient::CoseNestedRecipientSearchContext;
use crate::token::cose::recipient::KeyDistributionCryptoBackend;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extensions to the [`CoseMacBuilder`]  type that enable usage of cryptographic backends.
pub trait CoseMacBuilderExt: Sized {
    /// Attempts to compute the MAC using a cryptographic backend.
    ///
    /// Note that you still have to ensure that the key is available to the recipient somehow, i.e.
    /// by adding [`CoseRecipient`](coset::CoseRecipient) structures where suitable.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [`CoseMac`] instance. Will override
    ///                    headers previously set using [`CoseMacBuilder::protected`].
    /// - `unprotected`  - unprotected headers for the resulting [`CoseMac`] instance. Will override
    ///                    headers previously set using [`CoseMacBuilder::unprotected`].
    /// - `payload`      - payload which should be added to the resulting [`CoseMac`] instance and
    ///                    for which the MAC should be calculated. Will override a payload
    ///                    previously set using [`CoseMacBuilder::payload`].
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for MAC calculation, this function will return the most fitting
    /// [`CoseCipherError`] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but the key provider does not provide a key, a
    /// [`CoseCipherError::NoMatchingKeyFound`] error will be returned.
    ///
    /// # Examples
    ///
    /// Refer to [the documentation for the CoseMac extensions](CoseMacExt) for examples.
    fn try_compute<B: MacCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseMacBuilderExt for CoseMacBuilder {
    fn try_compute<B: MacCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_tag(
            external_aad
                .lookup_aad(None, protected.as_ref(), unprotected.as_ref())
                .unwrap_or(&[] as &[u8]),
            |input| {
                try_compute(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    input,
                )
            },
        )
    }
}

/// Extensions to the [`CoseMac`]  type that enable usage of cryptographic backends.
///
/// # Examples
///
/// Create a simple [`CoseMac`]  instance that uses the provided key directly and compute a MAC for it,
/// then verify it:
///
/// ```
///
/// use coset::{CoseKeyBuilder, CoseMac0Builder, CoseMacBuilder, CoseRecipientBuilder, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseMac0BuilderExt, CoseMac0Ext, CoseMacBuilderExt, CoseMacExt};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
///
/// let mut backend = OpensslContext::new();
///
/// let mut key_data = vec![0; 32];
/// backend.generate_rand(key_data.as_mut_slice())?;
/// let key = CoseKeyBuilder::new_symmetric_key(key_data).build();
///
/// let unprotected = HeaderBuilder::new()
///                     .algorithm(iana::Algorithm::HMAC_256_256)
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
/// let cose_object = CoseMacBuilder::new()
///                     .payload("This is the payload!".as_bytes().to_vec())
///                     .add_recipient(recipient)
///                     .try_compute(&mut backend, &key, None, Some(unprotected), &[] as &[u8])?
///                     .build();
///
/// assert!(cose_object.try_verify(&mut backend, &key, &[] as &[u8]).is_ok());
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
///
/// Create a simple [`CoseMac`]  instance with recipients that protect a content encryption key using
/// AES key wrap. Compute a MAC for it, then verify it:
/// ```
///
/// use coset::{CoseKeyBuilder, CoseMac0Builder, CoseMacBuilder, CoseRecipientBuilder, EncryptionContext, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseMac0BuilderExt, CoseMac0Ext, CoseMacBuilderExt, CoseMacExt, CoseRecipientBuilderExt};
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
///                     .algorithm(iana::Algorithm::HMAC_256_256)
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
/// let cose_object = CoseMacBuilder::new()
///                     .payload("This is the payload!".as_bytes().to_vec())
///                     .try_compute(&mut backend, &cek, None, Some(unprotected), &[] as &[u8])?
///                     .add_recipient(recipient)
///                     .build();
///
/// cose_object.try_verify_with_recipients(&mut backend, &kek, &[] as &[u8])?;
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
pub trait CoseMacExt {
    /// Attempts to verify the MAC using a cryptographic backend.
    ///
    /// Note that [`CoseRecipient`](coset::CoseRecipient)s are not considered for key lookup here, the key provider must
    /// provide the key used directly for MAC calculation.
    /// If your key provider can/should be able to provide the key for a contained
    /// [`CoseRecipient](coset::CoseRecipient), not for the [CoseMac`] instance itself, use
    /// [`CoseMac::try_verify_with_recipients`] instead.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for MAC calculation, this function will return the most fitting
    /// [`CoseCipherError`] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but MAC verification fails for all key candidates
    /// provided by the key provider a [`CoseCipherError::NoMatchingKeyFound`] error will be
    /// returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Verify the example `mac-tests/mac-pass-01.json` from the `cose-wg/Examples` repository
    /// referenced in RFC 9052 using the [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext)
    /// backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseMac, TaggedCborSerializable};
    /// use dcaf::token::cose::{CoseMacExt};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D8618541A0A1010554546869732069732074686520636F6E74656E742E5820C2EBE664C1D996AA3026824BBBB7CAA454E2CC4212181AD9F34C7879CBA1972E818340A20125044A6F75722D73656372657440").unwrap();
    /// let cose_symmetric_key_k = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseMac::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_symmetric_key(cose_symmetric_key_k).build();
    /// let aad: Vec<u8> = Vec::new();
    ///
    /// assert!(
    ///     cose_object.try_verify(
    ///         &mut OpensslContext::new(),
    ///         &mut &key,
    ///         &aad
    ///     ).is_ok()
    /// );
    /// ```
    ///
    /// Attempt to verify the example `mac-tests/mac-fail-02` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend (should fail, as the MAC
    /// is invalid):
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseMac, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseMacExt;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    /// use dcaf::error::CoseCipherError;
    ///
    /// let cose_object_cbor_data =
    ///     hex::decode("D8618543A10105A054546869732069732074686520636F6E74656E742E58202BDCC89F058216B8A208DDC6D8B54AA91F48BD63484986565105C9AD5A6682F7818340A20125044A6F75722D73656372657440")
    ///         .unwrap();
    /// let cose_symmetric_key_k =
    ///     base64::engine::general_purpose::URL_SAFE_NO_PAD
    ///         .decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg")
    ///         .unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseMac::from_tagged_slice(
    ///                     cose_object_cbor_data.as_slice()
    ///                   ).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_symmetric_key(cose_symmetric_key_k).build();
    /// let aad: Vec<u8> = Vec::new();
    ///
    /// assert!(
    ///     matches!(
    ///         cose_object.try_verify(
    ///             &mut OpensslContext::new(),
    ///             &mut &key,
    ///             &aad
    ///         ),
    ///         Err(CoseCipherError::NoMatchingKeyFound(_))
    ///     )
    /// );
    /// ```
    fn try_verify<B: MacCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    /// Attempts to verify the MAC using a cryptographic backend, performing a search through the
    /// contained [`CoseRecipient`](coset::CoseRecipient)s in order to decrypt the content encryption key (CEK).
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of
    /// those) are malformed or otherwise unsuitable for MAC calculation, this function will return
    /// the most fitting [`CoseCipherError`] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object itself is not malformed, but decryption of all
    /// [`CoseRecipient`](coset::CoseRecipient)s fails (due to non-available keys or malformation),
    /// [`CoseCipherError::NoDecryptableRecipientFound`] is returned with a list of the attempted
    /// recipients and resulting errors.
    ///
    /// Note that not all recipients will necessarily be tried, as a malformed
    /// [`CoseRecipient`](coset::CoseRecipient) will terminate the recipient search early.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Verify the example `aes-wrap-examples/aes-wrap-128-01.json` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend:
    /// TODO this example is currently ignored, as the required algorithm is not implemented yet
    ///      (AES-MAC-128/64)
    /// ```ignore
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseMac, TaggedCborSerializable};
    /// use dcaf::token::cose::{CoseMacExt};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D8618543A1010EA054546869732069732074686520636F6E74656E742E4836F5AFAF0BAB5D43818340A20122044A6F75722D73656372657458182F8A3D2AA397D3D5C40AAF9F6656BAFA5DB714EF925B72BC").unwrap();
    /// let cose_symmetric_key_k = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("hJtXIZ2uSN5kbQfbtTNWbg").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseMac::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_symmetric_key(cose_symmetric_key_k).build();
    /// let aad: Vec<u8> = Vec::new();
    ///
    /// assert!(
    ///     cose_object.try_verify_with_recipients(
    ///             &mut OpensslContext::new(),
    ///             &mut &key,
    ///             &aad
    ///         ).is_ok()
    /// );
    /// ```
    fn try_verify_with_recipients<
        B: KeyDistributionCryptoBackend + MacCryptoBackend,
        CKP: KeyProvider,
        CAP: AadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseMacExt for CoseMac {
    fn try_verify<B: MacCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        self.verify_tag(
            external_aad
                .lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected))
                .unwrap_or(&[] as &[u8]),
            |tag, input| {
                try_verify(
                    &backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    tag,
                    input,
                )
            },
        )
    }

    fn try_verify_with_recipients<
        B: KeyDistributionCryptoBackend + MacCryptoBackend,
        CKP: KeyProvider,
        CAP: AadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        let nested_recipient_key_provider = CoseNestedRecipientSearchContext::new(
            &self.recipients,
            Rc::clone(&backend),
            key_provider,
            &external_aad,
            EncryptionContext::MacRecipient,
        );
        match self.verify_tag(
            external_aad
                .lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected))
                .unwrap_or(&[] as &[u8]),
            |tag, input| {
                try_verify(
                    &backend,
                    &nested_recipient_key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    tag,
                    input,
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
