use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use coset::{CoseEncrypt0, CoseEncrypt0Builder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::encrypted;
use crate::token::cose::encrypted::CoseEncryptCipher;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};

#[cfg(all(test, feature = "std"))]
mod tests;

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
    /// If the COSE object is not malformed, but decryption fails for all key candidates provided
    /// by the key provider a [CoseCipherError::NoMatchingKeyFound] error will be returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid ciphertext for an otherwise valid and suitable object+key pairing, this would
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
}

impl CoseEncrypt0Ext for CoseEncrypt0 {
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
                    Some(EncryptionContext::CoseEncrypt0),
                    Some(&self.protected.header),
                    Some(&self.unprotected),
                )
                .unwrap_or(&[] as &[u8]),
            |ciphertext, aad| {
                encrypted::try_decrypt(
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
}

pub trait CoseEncrypt0BuilderExt: Sized {
    /// Attempts to encrypt the given `payload` using a cryptographic backend.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `protected`    - protected headers for the resulting [CoseEncrypt0] instance. Will override
    ///                    headers previously set using [CoseEncrypt0Builder::protected].
    /// - `unprotected`  - unprotected headers for the resulting [CoseEncrypt0] instance. Will override
    ///                    headers previously set using [CoseEncrypt0Builder::unprotected].
    /// - `payload`      - Data that should be encrypted and included in the [CoseEncrypt0]
    ///                    instance.
    /// - `external_aad` - provider of additional authenticated data that should be provided to the
    ///                    encryption algorithm (only suitable for AEAD algorithms).
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for encryption, this function will return the most fitting
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

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {
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
