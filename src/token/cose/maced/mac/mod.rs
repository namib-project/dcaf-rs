use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use coset::{CoseMac, CoseMacBuilder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::encrypted::CoseKeyDistributionCipher;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::maced::{try_compute, try_verify, CoseMacCipher};
use crate::token::cose::recipient::CoseNestedRecipientSearchContext;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extensions to the [CoseMacBuilder] type that enable usage of cryptographic backends.
pub trait CoseMacBuilderExt: Sized {
    /// Attempts to compute the MAC using a cryptographic backend.
    ///
    /// Note that you still have to ensure that the key is available to the recipient somehow, i.e.
    /// by adding [CoseRecipient] structures where suitable.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [CoseMac] instance. Will override
    ///                    headers previously set using [CoseMacBuilder::protected].
    /// - `unprotected`  - unprotected headers for the resulting [CoseMac] instance. Will override
    ///                    headers previously set using [CoseMacBuilder::unprotected].
    /// - `payload`      - payload which should be added to the resulting [CoseMac] instance and
    ///                    for which the MAC should be calculated. Will override a payload
    ///                    previously set using [CoseMacBuilder::payload].
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
        payload: Vec<u8>,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseMacBuilderExt for CoseMacBuilder {
    fn try_compute<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,

        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: Vec<u8>,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder = builder.payload(payload);
        Ok(builder.create_tag(
            external_aad
                .lookup_aad(None, protected.as_ref(), unprotected.as_ref())
                .unwrap_or(&[] as &[u8]),
            |input| {
                // TODO proper error handling here
                try_compute(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    input,
                )
                .expect("computing MAC failed")
            },
        ))
    }
}

/// Extensions to the [CoseMac] type that enable usage of cryptographic backends.
pub trait CoseMacExt {
    /// Attempts to verify the MAC using a cryptographic backend.
    ///
    /// Note that [CoseRecipient]s are not considered for key lookup here, the key provider must
    /// provide the key used directly for MAC calculation.
    /// If your key provider can/should be able to provide the key for a contained [CoseRecipient],
    /// not for the [CoseMac] instance itself, use [CoseMac::try_verify_with_recipients] instead.
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
    /// TODO
    fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    /// Attempts to verify the MAC using a cryptographic backend, performing a search through the
    /// contained [CoseRecipient]s in order to decrypt the content encryption key (CEK).
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
    /// provided by the key provider a *TODO* error will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// TODO
    fn try_verify_with_recipients<
        B: CoseKeyDistributionCipher + CoseMacCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseMacExt for CoseMac {
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

    fn try_verify_with_recipients<
        B: CoseKeyDistributionCipher + CoseMacCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        // TODO handle iterator errors.
        let nested_recipient_key_provider = CoseNestedRecipientSearchContext::new(
            &self.recipients,
            Rc::clone(&backend),
            key_provider,
            &external_aad,
            EncryptionContext::MacRecipient,
        );
        self.verify_tag(
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
        )
    }
}
