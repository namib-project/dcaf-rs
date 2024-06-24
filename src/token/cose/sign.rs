/*
 * Copyright (c) 2022-2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::error::CoseCipherError;
use crate::token::cose::header_util;
use crate::token::cose::header_util::check_for_duplicate_headers;
use crate::token::cose::key::{
    CoseEc2Key, CoseKeyProvider, CoseParsedKey, EllipticCurve, KeyParam,
};
use core::fmt::{Debug, Display};
use coset::iana::{Ec2KeyParameter, EnumI64};
use coset::{
    iana, Algorithm, CoseKey, CoseSign, CoseSign1, CoseSign1Builder, CoseSignBuilder,
    CoseSignature, Header, KeyOperation, KeyType, Label, ProtectedHeader, RegisteredLabel,
};

/// Provides basic operations for signing and verifying COSE structures.
///
/// This will be used by [`sign_access_token`] and [`verify_access_token`] (as well as the
/// equivalents for multiple recipients: [`sign_access_token_multiple`] and
/// [`verify_access_token_multiple`]) to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// The [`set_headers` method](CoseCipher::set_headers) can be used to set parameters
/// this cipher requires to be set.
pub trait CoseSignCipher {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;

    /// Cryptographically signs the `target` value with the `key` using ECDSA and returns the
    /// signature.
    ///
    /// # Arguments
    ///
    /// * `alg` - The variant of ECDSA to use (determines the hash function).
    ///           If unsupported by the backend, a [CoseCipherError::UnsupportedAlgorithm] error
    ///           should be returned. If the given algorithm is an IANA-assigned value that is not
    ///           an ECDSA algorithm, the implementation may panic or return
    ///           [CoseCipherError::UnsupportedAlgorithm].
    /// * `key` - Elliptic curve key that should be used. <br />
    ///           Implementations may assume that if the [CoseEc2Key::crv] field is an IANA-assigned
    ///           value, it will always be a curve feasible for ECDSA (currently P-256, P-384 or
    ///           P-521), and panic otherwise.
    ///           However, note that curve and hash bit sizes do not necessarily match.<br />
    ///           Additionally, implementations may assume the struct field `d` (the private key) to
    ///           always be set (and panic if this is not the case).
    ///           The fields x and y (the public key) may be used by implementations if they are
    ///           set. If they are not, implementations may either derive the public key from `d` or
    ///           return a [CoseCipherError::UnsupportedKeyDerivation] if this derivation is
    ///           unsupported.
    /// * `target` - Data to be signed.
    ///
    /// # Return Value
    ///
    /// It is expected that the return value is a signature conforming to RFC 9053, Section 2.1,
    /// i.e. the return value should consist of the `r` and `s` values of the signature, which are
    /// each padded (at the beginning) with zeros to the key size (rounded up to the next full
    /// byte).
    ///
    /// In case of errors, the implementation may return any valid [CoseCipherError].
    /// For backend-specific errors, [CoseCipherError::Other] may be used to convey a
    /// backend-specific error.
    fn sign_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn verify_ecdsa(
        &mut self,
        alg: Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        signature: &[u8],
        target: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Determines the algorithm to use for the signing operation based on the supplied key and headers.
fn determine_algorithm<CE: Display>(
    parsed_key: &CoseParsedKey<'_, CE>,
    unprotected_header: Option<&Header>,
    protected_header: Option<&Header>,
) -> Result<Algorithm, CoseCipherError<CE>> {
    // Check whether the algorithm has been explicitly set...
    if let Some(Some(alg)) = protected_header.map(|v| &v.alg) {
        // ...in the protected header...
        Ok(alg.clone())
    } else if let Some(Some(alg)) = unprotected_header.map(|v| &v.alg) {
        // ...in the unprotected header...
        Ok(alg.clone())
    } else if let Some(alg) = &parsed_key.as_ref().alg {
        // ...or the key itself.
        Ok(alg.clone())
    } else {
        // Otherwise, determine a reasonable default from the key type.
        match parsed_key {
            CoseParsedKey::Ec2(ec2_key) => {
                match &ec2_key.crv {
                    // RFC 9053
                    EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES256))
                    }
                    EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES384))
                    }
                    EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES512))
                    }
                    // RFC 8812
                    EllipticCurve::Assigned(iana::EllipticCurve::Secp256k1) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES256K))
                    }
                    // TODO brainpool curves (see IANA registry)
                    // For all others, we don't know which algorithm to use.
                    v => Err(CoseCipherError::NoDefaultAlgorithmForKey(
                        ec2_key.as_ref().kty.clone(),
                        Some(v.clone()),
                    )),
                }
            }
            CoseParsedKey::Okp(okp_key) => match &okp_key.crv {
                EllipticCurve::Assigned(
                    iana::EllipticCurve::Ed448 | iana::EllipticCurve::Ed25519,
                ) => Ok(Algorithm::Assigned(iana::Algorithm::EdDSA)),
                v => Err(CoseCipherError::NoDefaultAlgorithmForKey(
                    okp_key.as_ref().kty.clone(),
                    Some(v.clone()),
                )),
            },
            CoseParsedKey::Symmetric(symm_key) => Err(CoseCipherError::NoDefaultAlgorithmForKey(
                symm_key.as_ref().kty.clone(),
                None,
            )),
        }
    }
}

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
    fn try_sign<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: &[u8],
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
    fn try_sign_detached<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

fn is_valid_ecdsa_key<'a, B: CoseSignCipher>(
    algorithm: &Algorithm,
    parsed_key: CoseParsedKey<'a, B::Error>,
    key_should_be_private: bool,
) -> Result<CoseEc2Key<'a, B::Error>, CoseCipherError<B::Error>> {
    // Checks according to RFC 9053, Section 2.1 or RFC 8812, Section 3.2

    // Key type must be EC2 (both)
    let ec2_key = if let CoseParsedKey::Ec2(ec2_key) = parsed_key {
        ec2_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            algorithm.clone(),
        ));
    };

    // If algorithm in key is set, it must match our algorithm
    if ec2_key.as_ref().alg.is_some() && ec2_key.as_ref().alg.as_ref().unwrap() != algorithm {
        return Err(CoseCipherError::KeyAlgorithmMismatch(
            ec2_key.as_ref().alg.clone().unwrap(),
            algorithm.clone(),
        ));
    }

    // Key must contain private key information to perform signature.
    if key_should_be_private && ec2_key.d.is_none() {
        return Err(CoseCipherError::MissingKeyParam(KeyParam::Ec2(
            Ec2KeyParameter::D,
        )));
    } else if ec2_key.x.is_none() || ec2_key.y.is_none() {
        return Err(CoseCipherError::MissingKeyParam(KeyParam::Ec2(
            Ec2KeyParameter::X,
        )));
    }

    Ok(ec2_key)
}

fn try_sign<B: CoseSignCipher>(
    backend: &mut B,
    key: &CoseKey,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    tosign: &[u8],
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    let parsed_key: CoseParsedKey<B::Error> = CoseParsedKey::try_from(key)?;

    // Key must support the signing operation if key_ops field is present.
    if (!parsed_key.as_ref().key_ops.is_empty())
        && !parsed_key
            .as_ref()
            .key_ops
            .contains(&RegisteredLabel::Assigned(iana::KeyOperation::Sign))
    {
        return Err(CoseCipherError::KeyOperationNotPermitted(
            parsed_key.as_ref().key_ops.clone(),
            KeyOperation::Assigned(iana::KeyOperation::Sign),
        ));
    }

    let algorithm = determine_algorithm(&parsed_key, protected, unprotected)?;

    let sign_fn = match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::ES256
            | iana::Algorithm::ES384
            | iana::Algorithm::ES512
            | iana::Algorithm::ES256K,
        ) => {
            // Check if this is a valid ECDSA key.
            let ec2_key = is_valid_ecdsa_key::<B>(&algorithm, parsed_key, true)?;

            // Perform signing operation using backend.
            move |tosign| return backend.sign_ecdsa(algorithm, &ec2_key, tosign)
        }
        v @ (Algorithm::Assigned(_)) => {
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    };

    //check_signature_prerequisites(&algorithm, &parsed_key, &mut protected, &mut unprotected)?;
    sign_fn(tosign)
}

fn try_verify_with_key<B: CoseSignCipher>(
    backend: &mut B,
    key: &CoseKey,
    protected: &Header,
    unprotected: &Header,
    signature: &[u8],
    toverify: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    let parsed_key: CoseParsedKey<B::Error> = CoseParsedKey::try_from(key)?;

    // Key must support the signing operation if key_ops field is present.
    if (!parsed_key.as_ref().key_ops.is_empty())
        && !parsed_key
            .as_ref()
            .key_ops
            .contains(&RegisteredLabel::Assigned(iana::KeyOperation::Verify))
    {
        return Err(CoseCipherError::KeyOperationNotPermitted(
            parsed_key.as_ref().key_ops.clone(),
            KeyOperation::Assigned(iana::KeyOperation::Verify),
        ));
    }

    let algorithm = determine_algorithm(&parsed_key, Some(protected), Some(unprotected))?;

    let verify_fn = match algorithm {
        Algorithm::Assigned(
            iana::Algorithm::ES256
            | iana::Algorithm::ES384
            | iana::Algorithm::ES512
            | iana::Algorithm::ES256K,
        ) => {
            // Check if this is a valid ECDSA key.
            let ec2_key = is_valid_ecdsa_key::<B>(&algorithm, parsed_key, false)?;

            move |tosign| return backend.verify_ecdsa(algorithm, &ec2_key, signature, tosign)
        }
        v @ (Algorithm::Assigned(_)) => {
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
        // TODO make this extensible? I'm unsure whether it would be worth the effort, considering
        //      that using your own (or another non-recommended) algorithm is not a good idea anyways.
        v @ (Algorithm::PrivateUse(_) | Algorithm::Text(_)) => {
            return Err(CoseCipherError::UnsupportedAlgorithm(v.clone()))
        }
    };

    //check_signature_prerequisites(&algorithm, &parsed_key, &mut protected, &mut unprotected)?;
    verify_fn(toverify)
}

fn try_verify<'a, 'b, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
    backend: &mut B,
    key_provider: &CKP,
    protected: &'b Header,
    unprotected: &'b Header,
    try_all_keys: bool,
    signature: &[u8],
    toverify: &[u8],
) -> Result<(), CoseCipherError<B::Error>> {
    let key_id = if try_all_keys {
        None
    } else if !protected.key_id.is_empty() {
        Some(protected.key_id.clone())
    } else if !unprotected.key_id.is_empty() {
        Some(unprotected.key_id.clone())
    } else {
        None
    };

    let key_candidates = key_provider.lookup_key(key_id);

    for key in key_candidates {
        match try_verify_with_key(backend, key, protected, unprotected, signature, toverify) {
            Ok(()) => return Ok(()),
            Err(_) => {
                // TODO debug logging? Allow debugging why each verification failed?
            }
        }
    }

    // TODO maybe a more fitting error code here (NoKeyFound)?
    Err(CoseCipherError::VerificationFailure)
}

impl CoseSign1BuilderExt for CoseSign1Builder {
    fn try_sign<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        protected: Option<Header>,
        unprotected: Option<Header>,
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone())
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone())
        }
        builder.try_create_signature(aad, |tosign| {
            try_sign(
                backend,
                key,
                protected.as_ref(),
                unprotected.as_ref(),
                tosign,
            )
        })
    }
    fn try_sign_detached<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        protected: Option<Header>,
        unprotected: Option<Header>,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let mut builder = self;
        if let Some(protected) = &protected {
            builder = builder.protected(protected.clone())
        }
        if let Some(unprotected) = &unprotected {
            builder = builder.unprotected(unprotected.clone())
        }
        builder.try_create_detached_signature(payload, aad, |tosign| {
            try_sign(
                backend,
                key,
                protected.as_ref(),
                unprotected.as_ref(),
                tosign,
            )
        })
    }
}

pub trait CoseSign1Ext {
    fn try_verify<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>>;

    fn try_verify_detached<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSign1Ext for CoseSign1 {
    fn try_verify<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>> {
        let prot = self.protected.header.clone();
        let unprot = self.unprotected.clone();
        let verify = self.verify_signature(aad, |signature, toverify| {
            try_verify(
                backend,
                key_provider,
                &prot,
                &unprot,
                try_all_keys,
                signature,
                toverify,
            )
        })?;

        Ok(())
    }

    fn try_verify_detached<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>> {
        self.verify_detached_signature(payload, aad, |signature, toverify| {
            try_verify(
                backend,
                key_provider,
                &self.protected.header,
                &self.unprotected,
                try_all_keys,
                signature,
                toverify,
            )
        })
    }
}

/// Extension trait that enables signing using predefined backends instead of by providing signature
/// functions.
pub trait CoseSignBuilderExt: Sized {
    fn try_add_sign<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        sig: CoseSignature,
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>>;

    fn try_add_sign_detached<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        sig: CoseSignature,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl CoseSignBuilderExt for CoseSignBuilder {
    fn try_add_sign<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        sig: CoseSignature,
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_created_signature(sig.clone(), aad, |tosign| {
            try_sign(
                backend,
                key,
                Some(&sig.protected.header),
                Some(&sig.unprotected),
                tosign,
            )
        })
    }

    fn try_add_sign_detached<B: CoseSignCipher>(
        self,
        backend: &mut B,
        key: &CoseKey,
        sig: CoseSignature,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<Self, CoseCipherError<B::Error>> {
        self.try_add_detached_signature(sig.clone(), payload, aad, |tosign| {
            try_sign(
                backend,
                key,
                Some(&sig.protected.header),
                Some(&sig.unprotected),
                tosign,
            )
        })
    }
}

/// TODO for now, we assume a single successful validation implies that the validation in general is
///      successful. However, some environments may have other policies, see
///      https://datatracker.ietf.org/doc/html/rfc9052#section-4.1.
pub trait CoseSignExt {
    fn try_verify<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>>;

    fn try_verify_detached<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>>;
}

impl CoseSignExt for CoseSign {
    fn try_verify<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>> {
        for sigindex in 0..self.signatures.len() {
            match self.verify_signature(sigindex, aad, |signature, toverify| {
                try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    signature,
                    toverify,
                )
            }) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // TODO debug logging? Allow debugging why each verification failed?
                }
            }
        }

        Err(CoseCipherError::VerificationFailure)
    }

    fn try_verify_detached<'a, B: CoseSignCipher, CKP: CoseKeyProvider<'a>>(
        &self,
        backend: &mut B,
        key_provider: &CKP,
        try_all_keys: bool,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<(), CoseCipherError<B::Error>> {
        for sigindex in 0..self.signatures.len() {
            match self.verify_detached_signature(sigindex, payload, aad, |signature, toverify| {
                try_verify(
                    backend,
                    key_provider,
                    &self.protected.header,
                    &self.unprotected,
                    try_all_keys,
                    signature,
                    toverify,
                )
            }) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // TODO debug logging? Allow debugging why each verification failed?
                }
            }
        }

        Err(CoseCipherError::VerificationFailure)
    }
}
