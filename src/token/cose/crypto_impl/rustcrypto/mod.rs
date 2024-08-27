/*
 * Copyright (c) 2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use rand::{CryptoRng, RngCore};
use strum_macros::Display;

use crate::error::CoseCipherError;
use crate::token::cose::CryptoBackend;

#[cfg(rustcrypto_encrypt_base)]
mod encrypt;
#[cfg(rustcrypto_key_distribution_base)]
mod key_distribution;
#[cfg(rustcrypto_mac_base)]
mod mac;
#[cfg(rustcrypto_sign_base)]
mod sign;

#[derive(Debug, Display)]
/// Errors that might be returned from the `RustCrypto` cryptographic backend.
pub enum CoseRustCryptoCipherError {
    /// Error in AES key wrap.
    #[cfg(feature = "rustcrypto-aes-kw")]
    AesKwError(aes_kw::Error),
    /// Provided parameter has invalid length.
    #[cfg(any(feature = "rustcrypto-hmac", feature = "rustcrypto-sign"))]
    InvalidLength(digest::InvalidLength),
    /// Error regarding elliptic curve operations.
    #[cfg(feature = "rustcrypto-ecdsa")]
    EcError(elliptic_curve::Error),
    /// Error in ECDSA operation.
    #[cfg(feature = "rustcrypto-ecdsa")]
    EcdsaError(ecdsa::Error),
    /// Invalid elliptic curve point.
    #[cfg(feature = "rustcrypto-ecdsa")]
    InvalidPoint,
}

#[cfg(feature = "rustcrypto-aes-kw")]
impl From<aes_kw::Error> for CoseRustCryptoCipherError {
    fn from(value: aes_kw::Error) -> Self {
        CoseRustCryptoCipherError::AesKwError(value)
    }
}

#[cfg(any(feature = "rustcrypto-hmac", feature = "rustcrypto-sign"))]
impl From<digest::InvalidLength> for CoseRustCryptoCipherError {
    fn from(value: digest::InvalidLength) -> Self {
        CoseRustCryptoCipherError::InvalidLength(value)
    }
}

#[cfg(feature = "rustcrypto-ecdsa")]
impl From<ecdsa::elliptic_curve::Error> for CoseRustCryptoCipherError {
    fn from(value: ecdsa::elliptic_curve::Error) -> Self {
        CoseRustCryptoCipherError::EcError(value)
    }
}

#[cfg(feature = "rustcrypto-aes-kw")]
impl From<aes_kw::Error> for CoseCipherError<CoseRustCryptoCipherError> {
    fn from(value: aes_kw::Error) -> Self {
        CoseCipherError::Other(CoseRustCryptoCipherError::from(value))
    }
}

#[cfg(any(feature = "rustcrypto-hmac", feature = "rustcrypto-sign"))]
impl From<digest::InvalidLength> for CoseCipherError<CoseRustCryptoCipherError> {
    fn from(value: digest::InvalidLength) -> Self {
        CoseCipherError::Other(CoseRustCryptoCipherError::from(value))
    }
}

#[cfg(feature = "rustcrypto-ecdsa")]
impl From<ecdsa::elliptic_curve::Error> for CoseCipherError<CoseRustCryptoCipherError> {
    fn from(value: ecdsa::elliptic_curve::Error) -> Self {
        CoseCipherError::Other(CoseRustCryptoCipherError::EcError(value))
    }
}

#[cfg(feature = "rustcrypto-hmac")]
impl From<digest::MacError> for CoseCipherError<CoseRustCryptoCipherError> {
    fn from(_value: digest::MacError) -> Self {
        CoseCipherError::VerificationFailure
    }
}

#[cfg(feature = "rustcrypto-aes-gcm")]
impl From<aead::Error> for CoseCipherError<CoseRustCryptoCipherError> {
    fn from(_value: aead::Error) -> Self {
        CoseCipherError::VerificationFailure
    }
}

#[cfg(feature = "rustcrypto-ecdsa")]
impl From<ecdsa::Error> for CoseCipherError<CoseRustCryptoCipherError> {
    fn from(value: ecdsa::Error) -> Self {
        CoseCipherError::Other(CoseRustCryptoCipherError::EcdsaError(value))
    }
}

/// Context for the RustCrypto cryptographic backend
///
/// Can be used as a [`CryptoBackend`] for COSE operations.
///
/// Generic properties of this backend:
/// - [x] Can derive EC public key components if only the private component (d) is present.
/// - [x] Can work with compressed EC public keys (EC keys using point compression)
///
/// Algorithm support:
/// - Signature Algorithms (for COSE_Sign and COSE_Sign1)
///     - [x] ECDSA
///         - [x] ES256
///         - [x] ES384
///         - [x] ES512
///         - [ ] ES256K
///     - [ ] EdDSA
/// - Message Authentication Code Algorithms (for COSE_Mac and COSE_Mac0)
///     - [x] HMAC
///         - [ ] HMAC 256/64
///         - [x] HMAC 256/256
///         - [x] HMAC 384/384
///         - [x] HMAC 512/512
///     - [ ] AES-CBC-MAC
///         - [ ] AES-MAC 128/64
///         - [ ] AES-MAC 256/64
///         - [ ] AES-MAC 128/128
///         - [ ] AES-MAC 256/128
/// - Content Encryption Algorithms (for COSE_Encrypt and COSE_Encrypt0)
///     - [x] AES-GCM
///         - [x] A128GCM
///         - [x] A192GCM
///         - [x] A256GCM
///     - [x] AES-CCM
///         - [x] AES-CCM-16-64-128
///         - [x] AES-CCM-16-64-256
///         - [x] AES-CCM-64-64-128
///         - [x] AES-CCM-64-64-256
///         - [x] AES-CCM-16-128-128
///         - [x] AES-CCM-16-128-256
///         - [x] AES-CCM-64-128-128
///         - [x] AES-CCM-64-128-256
///     - [ ] ChaCha20/Poly1305
/// - Content Key Distribution Methods (for COSE_Recipients)
///     - Direct Encryption
///         - [ ] Direct Key with KDF
///             - [ ] direct+HKDF-SHA-256
///             - [ ] direct+HKDF-SHA-512
///             - [ ] direct+HKDF-AES-128
///             - [ ] direct+HKDF-AES-256
///     - Key Wrap
///         - [x] AES Key Wrap
///             - [x] A128KW
///             - [x] A192KW
///             - [x] A256KW
///     - Direct Key Agreement
///         - [ ] Direct ECDH
///             - [ ] ECDH-ES + HKDF-256
///             - [ ] ECDH-ES + HKDF-512
///             - [ ] ECDH-SS + HKDF-256
///             - [ ] ECDH-SS + HKDF-512
///     - Key Agreement with Key Wrap
///         - [ ] ECDH with Key Wrap
///             - [ ] ECDH-ES + A128KW
///             - [ ] ECDH-ES + A192KW
///             - [ ] ECDH-ES + A256KW
///             - [ ] ECDH-SS + A128KW
///             - [ ] ECDH-SS + A192KW
///             - [ ] ECDH-SS + A256KW
///
/// Elliptic Curve support (for EC algorithms):
/// - ES256/ES384/ES512 [^1]
///     - [x] P-256
///     - [x] P-384
///     - [ ] P-521 [^2]
/// - ES256K
///     - [ ] secp256k1
/// - EdDSA
///     - [ ] Ed448
///     - [ ] Ed25519
/// - ECDH
///     - [ ] X448
///     - [ ] X25519
///
/// [^1]: RFC 9053, Section 2.1 suggests using ES256 only with curve P-256, ES384 with curve P-384
///       and ES512 only with curve P-521.
/// [^2]: P-521 must implement DigestPrimitive in order to be usable in ECDSA.
///       This implementation was only recently added and is not released yet (p521 version 0.14.0
///       is only a pre-release right now).
pub struct RustCryptoContext<RNG: RngCore + CryptoRng> {
    rng: RNG,
}

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Creates a new RustCrypto context for cryptographic COSE operations using the given random
    /// number generator `rng`.
    pub fn new(rng: RNG) -> RustCryptoContext<RNG> {
        RustCryptoContext { rng }
    }
}

impl<RNG: RngCore + CryptoRng> CryptoBackend for RustCryptoContext<RNG> {
    type Error = CoseRustCryptoCipherError;

    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill_bytes(buf);
        Ok(())
    }
}
