use alloc::rc::Rc;
use core::cell::RefCell;

use coset::{CoseMac0, CoseMac0Builder, Header};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::maced::{try_compute, try_verify, CoseMacCipher};

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extensions to the [CoseMac0Builder] type that enable usage of cryptographic backends.
pub trait CoseMac0BuilderExt: Sized {
    /// Attempts to compute the MAC using a cryptographic backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [CoseMac0] instance. Will override
    ///                    headers previously set using [CoseMac0Builder::protected].
    /// - `unprotected`  - unprotected headers for the resulting [CoseMac0] instance. Will override
    ///                    headers previously set using [CoseMac0Builder::unprotected].
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for MAC calculation, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
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
    /// TODO
    fn try_compute<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseMac0BuilderExt for CoseMac0Builder {
    fn try_compute<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
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

/// Extensions to the [CoseMac0] type that enable usage of cryptographic backends.
pub trait CoseMac0Ext {
    /// Attempts to verify the MAC using a cryptographic backend.
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
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for MAC calculation, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but MAC verification fails for all key candidates
    /// provided by the key provider a [CoseCipherError::NoMatchingKeyFound] error will be
    /// returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// Verify the example `mac0-tests/mac-pass-01.json` from the `cose-wg/Examples` repository
    /// referenced in RFC 9052 using the [crate::token::cose::crypto_impl::openssl::OpensslContext]
    /// backend:
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseMac0, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseMac0Ext;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    ///
    /// let cose_object_cbor_data = hex::decode("D18441A0A1010554546869732069732074686520636F6E74656E742E5820176DCE14C1E57430C13658233F41DC89AA4FA0FF9B8783F23B0EF51CA6B026BC").unwrap();
    /// let cose_symmetric_key_k = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg").unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseMac0::from_tagged_slice(cose_object_cbor_data.as_slice()).expect("unable to parse COSE object");
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
    /// Attempt to verify the example `mac0-tests/mac-fail-02` from the `cose-wg/Examples`
    /// repository referenced in RFC 9052 using the
    /// [crate::token::cose::crypto_impl::openssl::OpensslContext] backend (should fail, as the MAC
    /// is invalid):
    /// ```
    /// use base64::Engine;
    /// use coset::{CoseKeyBuilder, CoseMac0, TaggedCborSerializable};
    /// use dcaf::token::cose::CoseMac0Ext;
    /// use dcaf::token::cose::crypto_impl::openssl::OpensslContext;
    /// use dcaf::error::CoseCipherError;
    ///
    /// let cose_object_cbor_data =
    ///     hex::decode("D18443A10105A054546869732069732074686520636F6E74656E742E5820A1A848D3471F9D61EE49018D244C824772F223AD4F935293F1789FC3A08D8C59")
    ///         .unwrap();
    /// let cose_symmetric_key_k =
    ///     base64::engine::general_purpose::URL_SAFE_NO_PAD
    ///         .decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg")
    ///         .unwrap();
    ///
    /// // Parse the object using `coset`.
    /// let cose_object = CoseMac0::from_tagged_slice(
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
    fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseMac0Ext for CoseMac0 {
    fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
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
}
