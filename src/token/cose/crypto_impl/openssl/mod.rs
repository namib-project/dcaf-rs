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
mod encrypt;
mod key_distribution;
mod mac;
mod sign;

use crate::error::CoseCipherError;
use crate::token::cose::CryptoBackend;
use coset::{iana, Algorithm};
use openssl::cipher::CipherRef;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use strum_macros::Display;
/// Represents an error caused by the OpenSSL cryptographic backend.
#[derive(Debug, Display)]
#[non_exhaustive]
pub enum CoseOpensslCipherError {
    /// Standard OpenSSL error (represented as an [`ErrorStack`] in the openssl library crate).
    OpensslError(ErrorStack),
    /// AES key error.
    AesKeyError(openssl::aes::KeyError),
    /// Other error (error message is provided as a string).
    Other(&'static str),
}

impl From<ErrorStack> for CoseOpensslCipherError {
    fn from(value: ErrorStack) -> Self {
        CoseOpensslCipherError::OpensslError(value)
    }
}

impl From<openssl::aes::KeyError> for CoseOpensslCipherError {
    fn from(value: openssl::aes::KeyError) -> Self {
        CoseOpensslCipherError::AesKeyError(value)
    }
}

impl From<ErrorStack> for CoseCipherError<CoseOpensslCipherError> {
    fn from(value: ErrorStack) -> Self {
        CoseCipherError::Other(value.into())
    }
}

impl From<openssl::aes::KeyError> for CoseCipherError<CoseOpensslCipherError> {
    fn from(value: openssl::aes::KeyError) -> Self {
        CoseCipherError::Other(value.into())
    }
}

/// Context for the OpenSSL cryptographic backend.
///
/// Can be used as a [`CryptoBackend`] for COSE operations.
///
/// Generic properties of this backend:
/// - [ ] Can derive EC public key components if only the private component (d) is present.
/// - [ ] Can work with compressed EC public keys (EC keys using point compression)
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
///     - [x] P-521
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
#[derive(Default)]
pub struct OpensslContext {}

impl OpensslContext {
    /// Creates a new OpenSSL context for use with COSE algorithms.
    #[must_use]
    pub fn new() -> OpensslContext {
        OpensslContext {}
    }
}

impl CryptoBackend for OpensslContext {
    type Error = CoseOpensslCipherError;

    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        openssl::rand::rand_bytes(buf).map_err(CoseOpensslCipherError::from)
    }
}

/// Converts the provided [`iana::Algorithm`] to an OpenSSL [`CipherRef`] that can be used for a
/// symmetric [`CipherCtx`](openssl::cipher_ctx::CipherCtx).
fn algorithm_to_cipher(
    algorithm: iana::Algorithm,
) -> Result<&'static CipherRef, CoseCipherError<CoseOpensslCipherError>> {
    match algorithm {
        iana::Algorithm::A128GCM => Ok(openssl::cipher::Cipher::aes_128_gcm()),
        iana::Algorithm::A192GCM => Ok(openssl::cipher::Cipher::aes_192_gcm()),
        iana::Algorithm::A256GCM => Ok(openssl::cipher::Cipher::aes_256_gcm()),
        iana::Algorithm::A128KW => Ok(openssl::cipher::Cipher::aes_128_ecb()),
        iana::Algorithm::A192KW => Ok(openssl::cipher::Cipher::aes_192_ecb()),
        iana::Algorithm::A256KW => Ok(openssl::cipher::Cipher::aes_256_ecb()),
        iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_64_128_128 => Ok(openssl::cipher::Cipher::aes_128_ccm()),
        iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_64_64_256
        | iana::Algorithm::AES_CCM_16_128_256
        | iana::Algorithm::AES_CCM_64_128_256 => Ok(openssl::cipher::Cipher::aes_256_ccm()),
        v => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            v,
        ))),
    }
}

/// Determine the hash function (represented in OpenSSL as a [`MessageDigest`]) that should be used
/// for a given [`iana::Algorithm`].
fn get_algorithm_hash_function(
    alg: iana::Algorithm,
) -> Result<MessageDigest, CoseCipherError<CoseOpensslCipherError>> {
    match alg {
        iana::Algorithm::ES256 | iana::Algorithm::HMAC_256_256 => Ok(MessageDigest::sha256()),
        iana::Algorithm::ES384 | iana::Algorithm::HMAC_384_384 => Ok(MessageDigest::sha384()),
        iana::Algorithm::ES512 | iana::Algorithm::HMAC_512_512 => Ok(MessageDigest::sha512()),
        v => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            v,
        ))),
    }
}
