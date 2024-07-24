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
use coset::{CoseSign, CoseSignBuilder, CoseSignature};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::CoseCipherError;
use crate::token::cose::aad::AadProvider;
use crate::token::cose::key::KeyProvider;
use crate::token::cose::signed;
use crate::token::cose::SignCryptoBackend;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSignBuilderExt: Sized {
    /// Calculates and adds a signature for the CoseSign object using the given backend..
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `sig`          - [CoseSignature] object to which the signature will be added. The headers
    ///                    should be set appropriately for the key and desired algorithm.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature calculation, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but the key provider does not provide a key, a
    /// [CoseCipherError::NoMatchingKeyFound] error will be returned.
    ///
    /// # Examples
    ///
    /// Refer to [the documentation for the CoseSign extensions](CoseSignExt) for examples.
    fn try_add_sign<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;

    /// Calculates and adds a signature for the CoseSign object using the given backend and
    /// detached payload.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `sig`          - [CoseSignature] object to which the signature will be added. The headers
    ///                    should be set appropriately for the key and desired algorithm.
    /// - `payload`      - detached payload that should be signed.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature calculation, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but the key provider does not provide a key, a
    /// [CoseCipherError::NoMatchingKeyFound] error will be returned.
    ///
    /// # Examples
    ///
    /// Refer to [the documentation for the CoseSign extensions](CoseSignExt) for examples.
    fn try_add_sign_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSignBuilderExt for CoseSignBuilder {
    fn try_add_sign<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_created_signature(
            sig.clone(),
            external_aad
                .lookup_aad(None, Some(&sig.protected.header), Some(&sig.unprotected))
                .unwrap_or(&[] as &[u8]),
            |tosign| {
                signed::try_sign(
                    backend,
                    key_provider,
                    Some(&sig.protected.header),
                    Some(&sig.unprotected),
                    tosign,
                )
            },
        )
    }
    fn try_add_sign_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_detached_signature(
            sig.clone(),
            payload,
            external_aad
                .lookup_aad(None, Some(&sig.protected.header), Some(&sig.unprotected))
                .unwrap_or(&[] as &[u8]),
            |tosign| {
                signed::try_sign(
                    backend,
                    key_provider,
                    Some(&sig.protected.header),
                    Some(&sig.unprotected),
                    tosign,
                )
            },
        )
    }
}

/// Extensions to the [CoseSign] type that enable usage of cryptographic backends.
///
/// # Examples
///
/// Create a simple [CoseSign] instance that uses the provided key directly and compute a signature
/// for it, then verify it:
///
/// ```
///
/// use base64::Engine;
/// use coset::{CoseKeyBuilder, CoseMac0Builder, CoseMacBuilder, CoseRecipientBuilder, CoseSignatureBuilder, CoseSignBuilder, HeaderBuilder, iana};
/// use dcaf::error::CoseCipherError;
/// use dcaf::token::cose::{CryptoBackend, CoseSignBuilderExt, CoseSignExt};
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
/// let sign_unprotected = HeaderBuilder::new()
///                     .algorithm(iana::Algorithm::ES256)
///                     .key_id("example_key".as_bytes().to_vec())
///                     .build();
///
/// let signature = CoseSignatureBuilder::new().unprotected(sign_unprotected).build();
///
/// let cose_object = CoseSignBuilder::new()
///                     .payload("This is the payload!".as_bytes().to_vec())
///                     .try_add_sign(&mut backend, &key, signature, &[] as &[u8])?
///                     .build();
///
/// assert!(cose_object.try_verify(&mut backend, &key, &[] as &[u8]).is_ok());
///
/// # Result::<(), CoseCipherError<<OpensslContext as CryptoBackend>::Error>>::Ok(())
/// ```
// TODO for now, we assume a single successful validation implies that the validation in general is
//      successful. However, some environments may have other policies, see
//      https://datatracker.ietf.org/doc/html/rfc9052#section-4.1.
pub trait CoseSignExt {
    /// Attempts to verify the signature using a cryptographic backend.
    ///
    /// Signature verification will succeed if at least one attached signature can be successfully
    /// verified.
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
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature verification, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [CoseCipherError::NoValidSignatureFound] will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid signature for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// Verify the example `sign-tests/sign-pass-01.json` from the `cose-wg/Examples` repository
    /// referenced in RFC 9052 using the [crate::token::cose::crypto_impl::openssl::OpensslContext]
    /// backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseSign, iana, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseSignExt;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D8628441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A").unwrap();
    /// let cose_ec2_key_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
    /// let cose_ec2_key_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
    /// let cose_ec2_key_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseSign::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
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
    /// Attempt to verify the example `sign-tests/sign-fail-02` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [crate::token::cose::crypto_impl::openssl::OpensslContext] backend (should fail, as the
    /// signature is invalid):
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseSign, iana, TaggedCborSerializable};
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    /// use dcaf::error::CoseCipherError;
    /// use dcaf::token::cose::CoseSignExt;
    ///
    /// let cose_object_cbor_data =
    ///     hex::decode("D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30B")
    ///         .unwrap();
    /// let cose_ec2_key_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8").unwrap();
    /// let cose_ec2_key_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4").unwrap();
    /// let cose_ec2_key_d = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseSign::from_tagged_slice(
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
    ///         Err(CoseCipherError::NoValidSignatureFound(_))
    ///     )
    /// );
    /// ```
    fn try_verify<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    /// Attempts to verify the signature of this object and its detached payload using a
    /// cryptographic backend.
    ///
    /// Signature verification will succeed if at least one attached signature can be successfully
    /// verified.
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
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature verification, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [CoseCipherError::NoValidSignatureFound] will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid signature for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// Refer to the trait-level documentation for examples.
    fn try_verify_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        payload: &[u8],
        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSignExt for CoseSign {
    fn try_verify<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let mut multi_verification_errors = Vec::new();
        for sigindex in 0..self.signatures.len() {
            match self.verify_signature(
                sigindex,
                aad.lookup_aad(
                    None,
                    Some(&self.signatures[sigindex].protected.header),
                    Some(&self.signatures[sigindex].unprotected),
                )
                .unwrap_or(&[] as &[u8]),
                |signature, toverify| {
                    signed::try_verify(
                        backend,
                        key_provider,
                        &self.signatures[sigindex].protected.header,
                        &self.signatures[sigindex].unprotected,
                        signature,
                        toverify,
                    )
                },
            ) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    multi_verification_errors.push((self.signatures.get(sigindex).unwrap(), e));
                }
            }
        }

        Err(CoseCipherError::NoValidSignatureFound(
            multi_verification_errors
                .into_iter()
                .map(|(s, e)| (s.clone(), e))
                .collect(),
        ))
    }
    fn try_verify_detached<B: SignCryptoBackend, CKP: KeyProvider, CAP: AadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        payload: &[u8],
        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let mut multi_verification_errors = Vec::new();
        for sigindex in 0..self.signatures.len() {
            match self.verify_detached_signature(
                sigindex,
                payload,
                aad.lookup_aad(
                    None,
                    Some(&self.signatures[sigindex].protected.header),
                    Some(&self.signatures[sigindex].unprotected),
                )
                .unwrap_or(&[] as &[u8]),
                |signature, toverify| {
                    signed::try_verify(
                        backend,
                        key_provider,
                        &self.signatures[sigindex].protected.header,
                        &self.signatures[sigindex].unprotected,
                        signature,
                        toverify,
                    )
                },
            ) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    multi_verification_errors.push((self.signatures.get(sigindex).unwrap(), e));
                }
            }
        }

        Err(CoseCipherError::NoValidSignatureFound(
            multi_verification_errors
                .into_iter()
                .map(|(s, e)| (s.clone(), e))
                .collect(),
        ))
    }
}
