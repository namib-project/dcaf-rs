use coset::{CoseSign, CoseSignBuilder, CoseSignature};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseAadProvider, CoseKeyProvider};
use crate::token::cose::signed;
use crate::token::cose::CoseSignCipher;

#[cfg(all(test, feature = "std"))]
mod tests;

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSignBuilderExt: Sized {
    /// Calculates and adds a signature for the CoseSign object using the given backend..
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `sig`          - [CoseSignature] object to which the signature will be added. The headers
    ///                    should be set appropriately for the key and desired algorithm.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature calculation, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
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
    fn try_add_sign<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;

    /// Calculates and adds a signature for the CoseSign object using the given backend and
    /// detached payload.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `sig`          - [CoseSignature] object to which the signature will be added. The headers
    ///                    should be set appropriately for the key and desired algorithm.
    /// - `payload`      - detached payload that should be signed.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature calculation, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
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
    fn try_add_sign_detached<
        B: CoseSignCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSignBuilderExt for CoseSignBuilder {
    fn try_add_sign<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_created_signature(
            sig.clone(),
            external_aad
                .lookup_aad(None, Some(&sig.protected.header), Some(&sig.unprotected))
                .unwrap_or(&[] as &[u8]),
            |tosign| {
                signed::try_sign(
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
        B: CoseSignCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        self,
        backend: &mut B,
        key_provider: &CKP,
        sig: CoseSignature,
        payload: &[u8],
        external_aad: CAP,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_detached_signature(
            sig.clone(),
            payload,
            external_aad
                .lookup_aad(None, Some(&sig.protected.header), Some(&sig.unprotected))
                .unwrap_or(&[] as &[u8]),
            |tosign| {
                signed::try_sign(
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
    /// Attempts to verify the signature using a cryptographic backend.
    ///
    /// Signature verification will succeed if at least one attached signature can be successfully
    /// verified.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature verification, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a *TODO* error will be
    /// returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid signature for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// TODO
    fn try_verify<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;

    /// Attempts to verify the signature of this object and its detached payload using a
    /// cryptographic backend.
    ///
    /// Signature verification will succeed if at least one attached signature can be successfully
    /// verified.
    ///
    /// # Parameters
    ///
    /// - `backend`      - cryptographic backend to use.
    /// - `key_provider` - provider for cryptographic keys to use (if you already know the
    ///                    corresponding key, simply provide an immutable borrow of it).
    /// - `payload`      - detached payload that should be included in signature calculation.
    /// - `external_aad` - provider of additional authenticated data that should be included in the
    ///                    signature calculation.
    ///
    /// # Errors
    ///
    /// If the COSE structure, selected [CoseKey] or AAD (or any combination of those) are malformed
    /// or otherwise unsuitable for signature verification, this function will return the most
    /// fitting [CoseCipherError] for the specific type of error.
    ///
    /// If the COSE object is not malformed, but an error in the cryptographic backend occurs, a
    /// [CoseCipherError::Other] containing the backend error will be returned.
    /// Refer to the backend module's documentation for information on the possible errors that may
    /// occur.
    ///
    /// If the COSE object is not malformed, but signature verification fails for all key candidates
    /// provided by the key provider a *TODO* error will be
    /// returned.
    ///
    /// The error will then contain a list of attempted keys and the corresponding error that led to
    /// the verification error for that key.
    /// For an invalid signature for an otherwise valid and suitable object+key pairing, this would
    /// usually be a [CoseCipherError::VerificationFailure].
    ///
    /// # Examples
    ///
    /// TODO
    fn try_verify_detached<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        payload: &[u8],
        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSignExt for CoseSign {
    fn try_verify<B: CoseSignCipher, CKP: CoseKeyProvider, CAP: CoseAadProvider + ?Sized>(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        for sigindex in 0..self.signatures.len() {
            match self.verify_signature(
                sigindex,
                aad.lookup_aad(
                    None,
                    Some(&self.signatures[sigindex].protected.header),
                    Some(&self.signatures[sigindex].unprotected),
                )
                .unwrap_or(&[] as &[u8]),
                |signature, toverify| {
                    signed::try_verify(
                        backend,
                        key_provider,
                        &self.signatures[sigindex].protected.header,
                        &self.signatures[sigindex].unprotected,
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
        B: CoseSignCipher,
        CKP: CoseKeyProvider,
        CAP: CoseAadProvider + ?Sized,
    >(
        &self,
        backend: &mut B,
        key_provider: &CKP,

        payload: &[u8],
        aad: CAP,
    ) -> Result<(), CoseCipherError<B::Error>> {
        for sigindex in 0..self.signatures.len() {
            match self.verify_detached_signature(
                sigindex,
                payload,
                aad.lookup_aad(
                    None,
                    Some(&self.signatures[sigindex].protected.header),
                    Some(&self.signatures[sigindex].unprotected),
                )
                .unwrap_or(&[] as &[u8]),
                |signature, toverify| {
                    signed::try_verify(
                        backend,
                        key_provider,
                        &self.signatures[sigindex].protected.header,
                        &self.signatures[sigindex].unprotected,
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
