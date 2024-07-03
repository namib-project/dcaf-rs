use crate::error::CoseCipherError;
use crate::token::cose::encrypt::try_decrypt;
use crate::token::cose::encrypt::{CoseEncryptCipher, CoseKeyDistributionCipher};
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::recipient::CoseNestedRecipientSearchContext;
use alloc::rc::Rc;
use core::cell::RefCell;
use core::fmt::Display;
use coset::{CoseEncrypt, EncryptionContext};

pub trait CoseEncryptExt {
    fn try_decrypt<
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
    fn try_decrypt<
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
        let mut nested_recipient_key_provider = CoseNestedRecipientSearchContext {
            recipient_iter: &self.recipients,
            backend: Rc::clone(&backend),
            key_provider: Rc::clone(&key_provider),
            try_all_keys,
            context: EncryptionContext::CoseEncrypt,
            iterator_store: vec![],
            _key_lifetime_marker: Default::default(),
        };
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
