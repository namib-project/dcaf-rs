use coset::{CoseSign1, CoseSign1Builder, Header};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::sign;
use crate::CoseSignCipher;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSign1BuilderExt: Sized {
    /// Creates the signature for the CoseSign1 object using the given backend.
    ///
    /// Will also set potentially required headers and check whether the given key is appropriate
    /// for signing and matches the header information.
    ///
    /// Parameters:
    /// - `backend`: cryptographic backend to use
    /// - `key`: Key to use for signing.
    /// - `protected`: protected headers, will override the previously set ones.
    /// - `unprotected`: unprotected headers, will override the previously set ones.
    ///
    /// TODO: Setting all of these options at once kind of defeats the purpose of
    ///       the builder pattern, but it is necessary here, as we lack access to the `protected`
    ///       and `unprotected` headers that were previously set (the field is private).
    ///       This should be fixed when porting all of this to coset.
    fn try_sign<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;

    /// Builds the CoseSign1 object with a detached payload using the given backend.
    ///
    /// Will also set potentially required headers and check whether the given key is appropriate
    /// for signing and matches the header information.
    ///
    /// Parameters:
    /// - `backend`: cryptographic backend to use
    /// - `key`: Key to use for signing.
    /// - `protected`: protected headers, will override the previously set ones.
    /// - `unprotected`: unprotected headers, will override the previously set ones.
    ///
    /// TODO: Setting all of these options at once kind of defeats the purpose of
    ///       the builder pattern, but it is necessary here, as we lack access to the `protected`
    ///       and `unprotected` headers that were previously set (the field is private).
    ///       This should be fixed when porting all of this to coset.
    fn try_sign_detached<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSign1BuilderExt for CoseSign1Builder {
    fn try_sign<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_signature(
            aad.lookup_aad(None, protected.as_ref(), unprotected.as_ref()),
            |tosign| {
                sign::try_sign(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    tosign,
                )
            },
        )
    }
    fn try_sign_detached<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: &mut CAP,
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
            aad.lookup_aad(None, protected.as_ref(), unprotected.as_ref()),
            |tosign| {
                sign::try_sign(
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

pub trait CoseSign1Ext {
    fn try_verify<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    fn try_verify_detached<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSign1Ext for CoseSign1 {
    fn try_verify<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_signature(
            aad.lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected)),
            |signature, toverify| {
                sign::try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    signature,
                    toverify,
                )
            },
        )?;

        Ok(())
    }

    fn try_verify_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_detached_signature(
            payload,
            aad.lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected)),
            |signature, toverify| {
                sign::try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    signature,
                    toverify,
                )
            },
        )
    }
}
