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
use coset::{CoseSign1, CoseSign1Builder, Header};

use crate::error::CoseCipherError;
use crate::token::cose::aad::AadProvider;
use crate::token::cose::key::KeyProvider;
use crate::token::cose::signed;
use crate::token::cose::SignCryptoBackend;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSign1BuilderExt: Sized {
    /// Creates the signature for the CoseSign1 object using the given backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [`CoseSign1`] instance. Will override
    ///                    headers previously set using [`CoseSign1Builder::protected`].
    /// - `unprotected`  - unprotected headers for the resulting [`CoseSign1`] instance. Will override
    ///                    headers previously set using [`CoseSign1Builder::unprotected`].
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature calculation, this function will return the most
    /// fitting [`CoseCipherError`] for the specific type of error.
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
    /// Refer to [the documentation for the CoseSign1 extensions](CoseSign1Ext) for examples.
    ///
    /// TODO: Setting all of these options at once kind of defeats the purpose of
    ///       the builder pattern, but it is necessary here, as we lack access to the `protected`
    ///       and `unprotected` headers that were previously set (the field is private).
    ///       This should be fixed when porting all of this to coset.
    fn try_sign<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;

    /// Creates the signature for the CoseSign1 object using the given backend and detached payload.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [`CoseSign1`] instance. Will override
    ///                    headers previously set using [`CoseSign1Builder::protected`].
    /// - `unprotected`  - unprotected headers for the resulting [`CoseSign1`] instance. Will override
    ///                    headers previously set using [`CoseSign1Builder::unprotected`].
    /// - `payload`      - detached payload that should be signed.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature calculation, this function will return the most
    /// fitting [`CoseCipherError`] for the specific type of error.
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
    /// Refer to [the documentation for the CoseSign1 extensions](CoseSign1Ext) for examples.
    // TODO: Setting all of these options at once kind of defeats the purpose of
    //       the builder pattern, but it is necessary here, as we lack access to the `protected`
    //       and `unprotected` headers that were previously set (the field is private).
    //       This should be fixed when porting all of this to coset.
    //       This applies to all COSE structures.
    fn try_sign_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSign1BuilderExt for CoseSign1Builder {
    fn try_sign<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_signature(
            aad.lookup_aad(None, protected.as_ref(), unprotected.as_ref())
                .unwrap_or(&[] as &[u8]),
            |tosign| {
                signed::try_sign(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    tosign,
                )
            },
        )
    }
    fn try_sign_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_detached_signature(
            payload,
            aad.lookup_aad(None, protected.as_ref(), unprotected.as_ref())
                .unwrap_or(&[] as &[u8]),
            |tosign| {
                signed::try_sign(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    tosign,
                )
            },
        )
    }
}

/// Extensions to the [`CoseSign1`]  type that enable usage of cryptographic backends.
///
/// # Examples
///
/// Create a simple [`CoseSign1`] instance that uses the provided key directly and compute a signature
/// for it, then verify it:
///
/// ```
///
/// use base64::Engine;
/// use coset::{CoseKeyBuilder, CoseRecipientBuilder, CoseSign1Builder, CoseSignatureBuilder, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseSign1BuilderExt, CoseSign1Ext};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
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
/// let unprotected = HeaderBuilder::new()
///                     .algorithm(iana::Algorithm::ES256)
///                     .key_id("example_key".as_bytes().to_vec())
///                     .build();
///
/// let cose_object = CoseSign1Builder::new()
///                     .payload("This is the payload!".as_bytes().to_vec())
///                     .try_sign(&mut backend, &key, None, Some(unprotected), &[] as &[u8])?
///                     .build();
///
/// assert!(cose_object.try_verify(&mut backend, &key, &[] as &[u8]).is_ok());
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
///
/// Create a simple [`CoseSign1`]  instance with a detached payload that uses the provided key directly
/// and compute a signature for it, then verify it:
///
/// ```
///
/// use base64::Engine;
/// use coset::{CoseKeyBuilder, CoseRecipientBuilder, CoseSign1Builder, CoseSignatureBuilder, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseSign1BuilderExt, CoseSign1Ext};
/// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
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
/// let unprotected = HeaderBuilder::new()
///                     .algorithm(iana::Algorithm::ES256)
///                     .key_id("example_key".as_bytes().to_vec())
///                     .build();
///
/// let cose_object = CoseSign1Builder::new()
///                     .try_sign_detached(&mut backend, &key, None, Some(unprotected), "This is the payload!".as_bytes(), &[] as &[u8])?
///                     .build();
///
/// assert!(cose_object.try_verify_detached(&mut backend, &key, "This is the payload!".as_bytes(), &[] as &[u8]).is_ok());
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
pub trait CoseSign1Ext {
    /// Attempts to verify the signature using a cryptographic backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature verification, this function will return the most
    /// fitting [`CoseCipherError`] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [`CoseCipherError::NoMatchingKeyFound`] error will be
    /// returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid signature for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Verify the example `sign1-tests/sign-pass-01.json` from the `cose-wg/Examples` repository
    /// referenced in RFC 9052 using the [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext)
    /// backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseSign1, iana, TaggedCborSerializable};
    /// use dcaf::token::cose::{CoseSign1Ext};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F").unwrap();
    /// let cose_ec2_key_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
    /// let cose_ec2_key_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
    /// let cose_ec2_key_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseSign1::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_ec2_priv_key(iana::EllipticCurve::P_256, cose_ec2_key_x, cose_ec2_key_y, cose_ec2_key_d).build();
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
    /// Attempt to verify the example `sign1-tests/sign-fail-02` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [`OpensslContext`](super::super::crypto_impl::openssl::OpensslContext) backend (should fail, as the
    /// signature is invalid):
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseSign, CoseSign1, iana, TaggedCborSerializable};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    /// use dcaf::error::CoseCipherError;
    /// use dcaf::token::cose::CoseSign1Ext;
    ///
    /// let cose_object_cbor_data =
    ///     hex::decode("D28443A10126A10442313154546869732069732074686520636F6E74656E742F58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36")
    ///         .unwrap();
    /// let cose_ec2_key_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
    /// let cose_ec2_key_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
    /// let cose_ec2_key_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseSign1::from_tagged_slice(
    ///                     cose_object_cbor_data.as_slice()
    ///                   ).expect("unable to parse COSE object");
    /// // Create key and AAD as specified in the example.
    /// let key = CoseKeyBuilder::new_ec2_priv_key(iana::EllipticCurve::P_256, cose_ec2_key_x, cose_ec2_key_y, cose_ec2_key_d).build();
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
    fn try_verify<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    /// Attempts to verify the signature of this object and its detached payload using a
    /// cryptographic backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `payload`      - detached payload that should be included in signature calculation.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [`CoseKey`](coset::CoseKey) or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature verification, this function will return the most
    /// fitting [`CoseCipherError`] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [`CoseCipherError::Other`] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [`CoseCipherError::NoMatchingKeyFound`] error will be
    /// returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid signature for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [`CoseCipherError::VerificationFailure`].
    ///
    /// # Examples
    ///
    /// Refer to the trait-level documentation for examples.
    fn try_verify_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        payload: &[u8],
        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSign1Ext for CoseSign1 {
    fn try_verify<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_signature(
            external_aad
                .lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected))
                .unwrap_or(&[] as &[u8]),
            |signature, toverify| {
                signed::try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    signature,
                    toverify,
                )
            },
        )
    }

    fn try_verify_detached<
        'a,
        'b,
        B: SignCryptoBackend,
        CKP: KeyProvider,
        CAP: AadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        payload: &[u8],
        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_detached_signature(
            payload,
            external_aad
                .lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected))
                .unwrap_or(&[] as &[u8]),
            |signature, toverify| {
                signed::try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    signature,
                    toverify,
                )
            },
        )
    }
}
