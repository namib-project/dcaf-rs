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

use alloc::vec::Vec;
use ciborium::value::Value;
use coset::{iana, Algorithm};
use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::bn::BigNum;
use openssl::cipher::CipherRef;
use openssl::cipher_ctx::CipherCtx;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use strum_macros::Display;

use crate::error::CoseCipherError;
use crate::token::cose::encrypted::{EncryptCryptoBackend, AES_GCM_TAG_LEN};
use crate::token::cose::header_util::HeaderParam;
use crate::token::cose::key::{CoseEc2Key, CoseSymmetricKey, EllipticCurve};
use crate::token::cose::maced::MacCryptoBackend;
use crate::token::cose::recipient::KeyDistributionCryptoBackend;
use crate::token::cose::signed::SignCryptoBackend;
use crate::token::cose::{aes_ccm_algorithm_tag_len, CryptoBackend};

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

impl SignCryptoBackend for OpensslContext {
    fn sign_ecdsa(
        &mut self,
        alg: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = get_algorithm_hash_function(alg)?;

        // Possible truncation is fine, the key size will never exceed the size of an i32.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        sign_ecdsa(&group, pad_size as i32, hash, key, target)
    }

    fn verify_ecdsa(
        &mut self,
        alg: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        signature: &[u8],
        target: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = get_algorithm_hash_function(alg)?;

        verify_ecdsa(&group, pad_size, hash, key, signature, target)
    }
}

/// Determine the openssl [`EcGroup`] instance and coordinate size that should be used for the given
/// ECDSA key (based on its curve).
fn get_ecdsa_group_params(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
) -> Result<(usize, EcGroup), CoseCipherError<CoseOpensslCipherError>> {
    match &key.crv {
        EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
            // ECDSA using P-256 curve, coordinates are padded to 256 bits
            Ok((32, EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()))
        }
        EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
            // ECDSA using P-384 curve, coordinates are padded to 384 bits
            Ok((48, EcGroup::from_curve_name(Nid::SECP384R1).unwrap()))
        }
        EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
            // ECDSA using P-521 curve, coordinates are padded to 528 bits (521 bits rounded up
            // to the nearest full bytes).
            Ok((66, EcGroup::from_curve_name(Nid::SECP521R1).unwrap()))
        }
        v => Err(CoseCipherError::UnsupportedCurve(v.clone())),
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

/// Perform an ECDSA signature operation with the given parameters.
fn sign_ecdsa(
    group: &EcGroup,
    pad_size: i32,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    target: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let private_key = cose_ec2_to_ec_private_key(key, group).map_err(CoseCipherError::from)?;

    let mut signer = Signer::new(
        hash,
        &*PKey::from_ec_key(private_key).map_err(CoseOpensslCipherError::from)?,
    )
    .map_err(CoseOpensslCipherError::from)?;

    // generated signature is of DER format, need to convert it to COSE key format
    let der_signature = signer
        .sign_oneshot_to_vec(target)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;

    let ecdsa_sig = EcdsaSig::from_der(der_signature.as_slice())
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;

    // See RFC 8152, section 8.1
    let mut sig = ecdsa_sig
        .r()
        .to_vec_padded(pad_size)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    let mut s_vec = ecdsa_sig
        .s()
        .to_vec_padded(pad_size)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    sig.append(&mut s_vec);

    Ok(sig)
}

/// Perform an ECDSA verification operation with the given parameters.
fn verify_ecdsa(
    group: &EcGroup,
    pad_size: usize,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    signature: &[u8],
    signed_data: &[u8],
) -> Result<(), CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, group).map_err(CoseCipherError::from)?;
    let pkey = PKey::from_ec_key(public_key).map_err(CoseOpensslCipherError::from)?;

    let mut verifier = Verifier::new(hash, &pkey).map_err(CoseOpensslCipherError::from)?;

    // signature is in COSE format, need to convert to DER format.
    let r = BigNum::from_slice(&signature[..pad_size]).map_err(CoseOpensslCipherError::from)?;
    let s = BigNum::from_slice(&signature[pad_size..]).map_err(CoseOpensslCipherError::from)?;
    let signature =
        EcdsaSig::from_private_components(r, s).map_err(CoseOpensslCipherError::from)?;
    // Note: EcdsaSig has its own "verify" method, but it is deprecated since OpenSSL
    // 3.0, which is why it's not used here.
    let der_signature = signature.to_der().map_err(CoseOpensslCipherError::from)?;

    verifier
        .verify_oneshot(der_signature.as_slice(), signed_data)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)
        .and_then(|verification_successful| {
            verification_successful
                .then_some(())
                .ok_or(CoseCipherError::VerificationFailure)
        })
}

/// Converts a private [`CoseEc2Key`] instance to its corresponding representation as an [`EcKey`]
/// in `openssl`.
fn cose_ec2_to_ec_private_key(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    group: &EcGroup,
) -> Result<EcKey<Private>, CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, group)?;

    EcKey::<Private>::from_private_components(
        group,
        &*BigNum::from_slice(
            // According to the contract of the trait, this should be ensured by the caller, so it's
            // fine to panic here.
            key.d
                .expect("key provided to backend has no private component"),
        )
        .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
        public_key.public_key(),
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}

/// Converts a public [`CoseEc2Key`] instance to its corresponding representation as an [`EcKey`]
/// in `openssl`.
fn cose_ec2_to_ec_public_key(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    group: &EcGroup,
) -> Result<EcKey<Public>, CoseCipherError<CoseOpensslCipherError>> {
    // TODO X and Y can be recomputed and are not strictly required if D is known
    //      (RFC 8152, Section 13.1.1)
    if key.x.is_none() || key.y.is_none() {
        return Err(CoseCipherError::UnsupportedKeyDerivation);
    }

    EcKey::<Public>::from_public_key_affine_coordinates(
        group,
        &*BigNum::from_slice(key.x.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
        &*BigNum::from_slice(key.y.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}

impl EncryptCryptoBackend for OpensslContext {
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = algorithm_to_cipher(algorithm)?;
        let mut ctx = CipherCtx::new()?;
        // So, apparently OpenSSL requires a very specific order of operations which differs
        // slightly for AES-GCM and AES-CCM in order to work.
        // It would have just been too easy if you could just generalize and reuse the code for
        // AES-CCM and AES-GCM, right?

        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.encrypt_init(Some(cipher), None, None)?;
        // 2. For GCM, we set the IV length _before_ setting key and IV.
        //    We do not set the tag length, as it is fixed for AES-GCM.
        ctx.set_iv_length(iv.len())?;
        // 3. Now we can set key and IV.
        ctx.encrypt_init(None, Some(key.k), Some(iv))?;
        let mut ciphertext = vec![];
        // Unlike for CCM, we *must not* set the data length here, otherwise encryption *will fail*.
        // 4. Then, we *must* set the AAD _before_ setting the plaintext.
        ctx.cipher_update(aad, None)?;
        // 5. Finally, we must provide all plaintext in a single call.
        ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
        // 6. Then, we can finish the operation.
        ctx.cipher_final_vec(&mut ciphertext)?;
        let ciphertext_len = ciphertext.len();
        ciphertext.resize(ciphertext_len + AES_GCM_TAG_LEN, 0u8);
        ctx.tag(&mut ciphertext[ciphertext_len..])?;
        Ok(ciphertext)
    }

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = algorithm_to_cipher(algorithm)?;
        let auth_tag = &ciphertext_with_tag[(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)..];
        let ciphertext = &ciphertext_with_tag[..(ciphertext_with_tag.len() - AES_GCM_TAG_LEN)];

        let mut ctx = CipherCtx::new()?;
        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_GCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.decrypt_init(Some(cipher), None, None)?;
        // 2. For GCM, we set the IV length _before_ setting key and IV.
        //    We do not set the tag length, as it is fixed for AES-GCM.
        ctx.set_iv_length(iv.len())?;
        // 3. Now we can set key and IV.
        ctx.decrypt_init(None, Some(key.k), Some(iv))?;
        // Unlike for CCM, we *must not* set the data length here, otherwise decryption *will fail*.
        // 4. Then, we *must* set the AAD _before_ setting the ciphertext.
        ctx.cipher_update(aad, None)?;
        // 5. After that, we provide the ciphertext in a single call for decryption.
        let mut plaintext = vec![0; ciphertext.len()];
        let mut plaintext_size = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
        // 6. For GCM, we must set the tag value right before the finalization call.
        ctx.set_tag(auth_tag)?;
        // 7. Now we can finalize decryption.
        plaintext_size += ctx.cipher_final_vec(&mut plaintext)?;

        plaintext.truncate(plaintext_size);

        Ok(plaintext)
    }

    fn encrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = algorithm_to_cipher(algorithm)?;
        let tag_len = aes_ccm_algorithm_tag_len(algorithm)?;
        let mut ctx = CipherCtx::new()?;
        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_CCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.encrypt_init(Some(cipher), None, None)?;
        // 2. At least for CCM, we *must* set the tag and IV length _before_ setting key and IV.
        //    (https://github.com/sfackler/rust-openssl/pull/1594#issue-1105067105)
        ctx.set_iv_length(iv.len())?;
        ctx.set_tag_length(tag_len)?;
        // 3. Now we can set key and IV.
        ctx.encrypt_init(None, Some(key.k), Some(iv))?;
        let mut ciphertext = vec![];
        // 4. For CCM, we *must* then inform OpenSSL about the size of the plaintext data _before_
        //    setting the AAD.
        ctx.set_data_len(plaintext.len())?;
        // 5. Then, we *must* set the AAD _before_ setting the plaintext.
        ctx.cipher_update(aad, None)?;
        // 6. Finally, we must provide all plaintext in a single call.
        ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
        // 7. Then, we can finish the operation.
        ctx.cipher_final_vec(&mut ciphertext)?;
        let ciphertext_len = ciphertext.len();
        ciphertext.resize(ciphertext_len + tag_len, 0u8);
        ctx.tag(&mut ciphertext[ciphertext_len..])?;
        Ok(ciphertext)
    }

    fn decrypt_aes_ccm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let cipher = algorithm_to_cipher(algorithm)?;
        let tag_len = aes_ccm_algorithm_tag_len(algorithm)?;
        let auth_tag = &ciphertext_with_tag[(ciphertext_with_tag.len() - tag_len)..];
        let ciphertext = &ciphertext_with_tag[..(ciphertext_with_tag.len() - tag_len)];

        let mut ctx = CipherCtx::new()?;
        // Refer to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_CCM_mode
        // for reference.
        // 1. First, we set the cipher.
        ctx.decrypt_init(Some(cipher), None, None)?;
        // 2. At least for CCM, we *must* set the tag and IV length _before_ setting key and IV.
        //    (https://github.com/sfackler/rust-openssl/pull/1594#issue-1105067105)
        ctx.set_iv_length(iv.len())?;
        ctx.set_tag(auth_tag)?;
        // 3. Now we can set key and IV.
        ctx.decrypt_init(None, Some(key.k), Some(iv))?;
        // 4. For CCM, we *must* then inform OpenSSL about the size of the ciphertext data _before_
        //    setting the AAD.
        ctx.set_data_len(ciphertext.len())?;
        // 5. Then, we *must* set the AAD _before_ setting the ciphertext.
        ctx.cipher_update(aad, None)?;
        // 6. Finally, we must provide all ciphertext in a single call for decryption.
        let mut plaintext = vec![0; ciphertext.len()];
        let plaintext_len = ctx.cipher_update(ciphertext, Some(&mut plaintext))?;
        plaintext.truncate(plaintext_len);
        // No call to cipher_final() here, I guess?
        // The official examples in the OpenSSL wiki don't finalize, so we won't either.

        Ok(plaintext)
    }
}

/// Converts the provided [`iana::Algorithm`] to an OpenSSL [`CipherRef`] that can be used for a
/// symmetric [`CipherCtx`].
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

impl KeyDistributionCryptoBackend for OpensslContext {
    fn aes_key_wrap(
        &mut self,
        _algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let key = AesKey::new_encrypt(key.k)?;
        let iv: [u8; 8] = iv.try_into().map_err(|_e| {
            CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.to_vec()),
            )
        })?;
        let mut output = vec![0u8; plaintext.len() + 8];
        let output_len = wrap_key(&key, Some(iv), output.as_mut_slice(), plaintext)?;
        output.truncate(output_len);
        Ok(output)
    }

    fn aes_key_unwrap(
        &mut self,
        _algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let key = AesKey::new_decrypt(key.k)?;
        let iv: [u8; 8] = iv.try_into().map_err(|_e| {
            CoseCipherError::InvalidHeaderParam(
                HeaderParam::Generic(iana::HeaderParameter::Iv),
                Value::Bytes(iv.to_vec()),
            )
        })?;
        let mut output = vec![0u8; ciphertext.len() - 8];
        let output_len = unwrap_key(&key, Some(iv), output.as_mut_slice(), ciphertext)?;
        output.truncate(output_len);
        Ok(output)
    }
}

/// Computes an HMAC for `input` using the given `algorithm` and `key`.
fn compute_hmac(
    algorithm: iana::Algorithm,
    key: &CoseSymmetricKey<'_, CoseOpensslCipherError>,
    input: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let hash = get_algorithm_hash_function(algorithm)?;
    let hmac_key = PKey::hmac(key.k)?;
    let mut signer = Signer::new(hash, &hmac_key)?;
    signer
        .sign_oneshot_to_vec(input)
        .map_err(CoseCipherError::from)
}

impl MacCryptoBackend for OpensslContext {
    fn compute_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        data: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        compute_hmac(algorithm, &key, data)
    }

    fn verify_hmac(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let hmac = compute_hmac(algorithm, &key, data)?;
        // Use openssl::memcmp::eq to prevent timing attacks.
        if openssl::memcmp::eq(hmac.as_slice(), tag) {
            Ok(())
        } else {
            Err(CoseCipherError::VerificationFailure)
        }
    }
}
