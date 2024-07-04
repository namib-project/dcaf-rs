use crate::error::CoseCipherError;
use crate::token::cose::encrypt;
use crate::token::cose::encrypt::try_decrypt;
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher};
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::recipient::CoseNestedRecipientSearchContext;
use alloc::rc::Rc;
use core::cell::RefCell;
use core::fmt::Display;
use coset::{CoseEncrypt, CoseEncryptBuilder, EncryptionContext, Header};

pub trait CoseEncryptBuilderExt: Sized {
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

impl CoseEncryptBuilderExt for CoseEncryptBuilder {
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
            |plaintext, aad| {
                encrypt::try_encrypt(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    try_all_keys,
                    plaintext,
                    aad,
                )
            },
        )
    }
}

pub trait CoseEncryptExt {
    fn try_decrypt<'a, 'b, B: CoseEncryptCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;

    fn try_decrypt_with_recipients<
        'a,
        'b,
        B: CoseKeyDistributionCipher + CoseEncryptCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncryptExt for CoseEncrypt {
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

    fn try_decrypt_with_recipients<
        'a,
        'b,
        B: CoseKeyDistributionCipher + CoseEncryptCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        let key_provider = Rc::new(RefCell::new(key_provider));
        let mut nested_recipient_key_provider = CoseNestedRecipientSearchContext::new(
            &self.recipients,
            Rc::clone(&backend),
            Rc::clone(&key_provider),
            try_all_keys,
            EncryptionContext::CoseEncrypt,
        );
        self.decrypt(
            external_aad.lookup_aad(Some(&self.protected.header), Some(&self.unprotected)),
            |ciphertext, aad| {
                try_decrypt(
                    backend,
                    Rc::new(RefCell::new(&mut nested_recipient_key_provider)),
                    &self.protected.header,
                    &self.unprotected,
                    true,
                    ciphertext,
                    aad,
                )
            },
        )
    }
}
