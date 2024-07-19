use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use coset::{CoseEncrypt, CoseEncryptBuilder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::encrypted;
use crate::token::cose::encrypted::try_decrypt;
use crate::token::cose::encrypted::{CoseEncryptCipher, CoseKeyDistributionCipher};
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::recipient::{
    struct_to_recipient_context, CoseNestedRecipientSearchContext,
};

#[cfg(all(test, feature = "std"))]
mod tests;

pub trait CoseEncryptBuilderExt: Sized {
    /// Attempts to encrypt the provided payload using a cryptographic backend.
    ///
    /// Note that you still have to ensure that the key is available to the recipient somehow, i.e.
    /// by adding [CoseRecipient] structures where suitable.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [CoseEncrypt] instance. Will override
    ///                    headers previously set using [CoseEncryptBuilder::protected].
    /// - `unprotected`  - unprotected headers for the resulting [CoseEncrypt] instance. Will
    ///                    override headers previously set using [CoseEncryptBuilder::unprotected].
    /// - `payload`      - payload which should be added to the resulting [CoseMac0] instance and
    ///                    for which the MAC should be calculated. Will override a payload
    ///                    previously set using [CoseEncryptBuilder::payload].
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    MAC calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for MAC calculation, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
    ///
    /// If Additional Authenticated Data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [CoseCipherError::AadUnsupported] will be returned.
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
    fn try_encrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
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
    fn try_encrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
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

pub trait CoseEncryptExt {
    /// Attempts to decrypt the payload contained in this object using a cryptographic backend.
    ///
    /// Note that [CoseRecipient]s are not considered for key lookup here, the key provider must
    /// provide the key used directly for MAC calculation.
    /// If your key provider can/should be able to provide the key for a contained [CoseRecipient],
    /// not for the [CoseEncrypt] instance itself, use [CoseEncrypt::try_verify_with_recipients]
    /// instead.
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
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for decryption, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
    ///
    /// If Additional Authenticated Data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [CoseCipherError::AadUnsupported] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a [CoseCipherError::NoMatchingKeyFound] error will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid MAC for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// TODO
    fn try_decrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;

    /// Attempts to decrypt the payload contained in this object using a cryptographic backend,
    /// performing a search through the contained [CoseRecipient]s in order to decrypt the content
    /// encryption key (CEK).
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
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for decryption, this function will return the most fitting
    /// [CoseCipherError] for the specific type of error.
    ///
    /// If Additional Authenticated Data is provided even though the chosen algorithm is not an AEAD
    /// algorithm, a [CoseCipherError::AadUnsupported] will be returned.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
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
    fn try_decrypt_with_recipients<
        B: CoseKeyDistributionCipher + CoseEncryptCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        external_aad: CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncryptExt for CoseEncrypt {
    fn try_decrypt<B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
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
                    backend,
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
        B: CoseKeyDistributionCipher + CoseEncryptCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
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
                    backend,
                    &nested_recipient_key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}
