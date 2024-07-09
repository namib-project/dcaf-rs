use alloc::rc::Rc;
use core::cell::RefCell;

use coset::{CoseMac, CoseMacBuilder, EncryptionContext, Header};

use crate::error::CoseCipherError;
use crate::token::cose::encrypt::CoseKeyDistributionCipher;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::mac::{try_compute, try_verify, CoseMacCipher};
use crate::token::cose::recipient::CoseNestedRecipientSearchContext;

#[cfg(all(test, feature = "std"))]
mod tests;

pub trait CoseMacBuilderExt: Sized {
    fn try_compute<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: Vec<u8>,
        external_aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseMacBuilderExt for CoseMacBuilder {
    fn try_compute<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: Vec<u8>,
        external_aad: &mut CAP,
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
            external_aad.lookup_aad(None, protected.as_ref(), unprotected.as_ref()),
            |input| {
                // TODO proper error handling here
                try_compute(
                    backend,
                    key_provider,
                    protected.as_ref(),
                    unprotected.as_ref(),
                    try_all_keys,
                    input,
                )
                .expect("computing MAC failed")
            },
        ))
    }
}

pub trait CoseMacExt {
    fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    fn try_verify_with_recipients<
        B: CoseKeyDistributionCipher + CoseMacCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseMacExt for CoseMac {
    fn try_verify<B: CoseMacCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        let key_provider = Rc::new(RefCell::new(key_provider));
        self.verify_tag(
            external_aad.lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected)),
            |tag, input| {
                try_verify(
                    &backend,
                    &key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    tag,
                    input,
                )
            },
        )
    }

    fn try_verify_with_recipients<
        B: CoseKeyDistributionCipher + CoseMacCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        external_aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let backend = Rc::new(RefCell::new(backend));
        let key_provider = Rc::new(RefCell::new(key_provider));
        let mut nested_recipient_key_provider = CoseNestedRecipientSearchContext::new(
            &self.recipients,
            Rc::clone(&backend),
            Rc::clone(&key_provider),
            try_all_keys,
            EncryptionContext::MacRecipient,
        );
        self.verify_tag(
            external_aad.lookup_aad(None, Some(&self.protected.header), Some(&self.unprotected)),
            |tag, input| {
                try_verify(
                    &backend,
                    &Rc::new(RefCell::new(&mut nested_recipient_key_provider)),
                    &self.protected.header,
                    &self.unprotected,
                    true,
                    tag,
                    input,
                )
            },
        )
    }
}
