use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::sign;
use crate::CoseSignCipher;
use core::borrow::BorrowMut;
use coset::{CoseSign, CoseSignBuilder, CoseSignature};

mod tests;

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSignBuilderExt: Sized {
    fn try_add_sign<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        sig: CoseSignature,
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;

    fn try_add_sign_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        sig: CoseSignature,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSignBuilderExt for CoseSignBuilder {
    fn try_add_sign<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        sig: CoseSignature,
        mut aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_created_signature(
            sig.clone(),
            aad.lookup_aad(Some(&sig.protected.header), Some(&sig.unprotected)),
            |tosign| {
                sign::try_sign(
                    backend,
                    key_provider,
                    Some(&sig.protected.header),
                    Some(&sig.unprotected),
                    tosign,
                )
            },
        )
    }

    fn try_add_sign_detached<
        'a,
        'b,
        B: CoseSignCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider,
    >(
        self,
        backend: &mut B,
        key_provider: &mut CKP,
        sig: CoseSignature,
        payload: &[u8],
        mut aad: &mut CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_detached_signature(
            sig.clone(),
            payload,
            aad.lookup_aad(Some(&sig.protected.header), Some(&sig.unprotected)),
            |tosign| {
                sign::try_sign(
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

/// TODO for now, we assume a single successful validation implies that the validation in general is
///      successful. However, some environments may have other policies, see
///      https://datatracker.ietf.org/doc/html/rfc9052#section-4.1.
pub trait CoseSignExt {
    fn try_verify<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    fn try_verify_detached<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSignExt for CoseSign {
    fn try_verify<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider>(
        &self,
        backend: &mut B,
        key_provider: &mut CKP,
        try_all_keys: bool,
        mut aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        for sigindex in 0..self.signatures.len() {
            match self.verify_signature(
                sigindex,
                aad.borrow_mut().lookup_aad(
                    Some(&self.signatures[sigindex].protected.header),
                    Some(&self.signatures[sigindex].unprotected),
                ),
                |signature, toverify| {
                    sign::try_verify(
                        backend,
                        key_provider,
                        &self.signatures[sigindex].protected.header,
                        &self.signatures[sigindex].unprotected,
                        try_all_keys,
                        signature,
                        toverify,
                    )
                },
            ) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // TODO debug logging? Allow debugging why each verification failed?
                }
            }
        }

        Err(CoseCipherError::VerificationFailure)
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
        mut aad: &mut CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        let aad = aad.borrow_mut();
        for sigindex in 0..self.signatures.len() {
            match self.verify_detached_signature(
                sigindex,
                payload,
                aad.lookup_aad(
                    Some(&self.signatures[sigindex].protected.header),
                    Some(&self.signatures[sigindex].unprotected),
                ),
                |signature, toverify| {
                    sign::try_verify(
                        backend,
                        key_provider,
                        &self.signatures[sigindex].protected.header,
                        &self.signatures[sigindex].unprotected,
                        try_all_keys,
                        signature,
                        toverify,
                    )
                },
            ) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // TODO debug logging? Allow debugging why each verification failed?
                }
            }
        }

        Err(CoseCipherError::VerificationFailure)
    }
}
