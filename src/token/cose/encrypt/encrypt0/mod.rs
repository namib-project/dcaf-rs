use crate::error::CoseCipherError;
use crate::token::cose::encrypt;
use crate::token::cose::encrypt::CoseEncryptCipher;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use alloc::rc::Rc;
use core::fmt::Display;
use coset::{CoseEncrypt0, CoseEncrypt0Builder, Header};
use std::cell::RefCell;

mod tests;

pub trait CoseEncrypt0Ext {
    fn try_decrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0Ext for CoseEncrypt0 {
    fn try_decrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        let key_provider = Rc::new(RefCell::new(key_provider));
        self.decrypt(
            external_aad.lookup_aad(Some(&self.protected.header), Some(&self.unprotected)),
            |ciphertext, aad| {
                encrypt::try_decrypt(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}

pub trait CoseEncrypt0BuilderExt: Sized {
    fn try_encrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {
    fn try_encrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        protected: Option<Header>,
        unprotected: Option<Header>,
        plaintext: &[u8],
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone());
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone());
        }
        builder.try_create_ciphertext(
            plaintext,
            external_aad.lookup_aad(protected.as_ref(), unprotected.as_ref()),
            |ciphertext, aad| {
                encrypt::try_encrypt_single(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    try_all_keys,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}
