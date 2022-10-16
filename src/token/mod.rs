/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Contains methods for [encrypting](encrypt_access_token), [decrypting](decrypt_access_token),
//! [signing](sign_access_token) and [verifying](verify_access_token) access tokens.
//!
//! **NOTE: The APIs in this module are experimental and likely to change in the future!**
//! This is due to the COSE support being very basic right now (e.g. only `CoseEncrypt0` instead of
//! `CoseEncrypt`) and due to the APIs needing to be "battle-tested" in active use.
//! Builders will also most likely be added as well due to a lot of optional arguments present
//! in the functions at the moment.
//!
//! In order to use any of these methods, you will need to provide a cipher which handles
//! the cryptographic operations by implementing both [`CoseCipherCommon`] (which sets
//! necessary headers) and either [`CoseEncrypt0Cipher`], [`CoseMac0Cipher`] or [`CoseSign1Cipher`],
//! depending on the intended operation. See the respective traits for details.
//!
//! # Example
//! The following shows how to create and sign an access token (assuming a cipher implementing
//! both [`CoseSign1Cipher`] and [`CoseCipherCommon`] exists in variable `cipher`):
//! ```
//! # use ciborium::value::Value;
//! # use coset::{Header, Label};
//! # use coset::cwt::{ClaimsSetBuilder, Timestamp};
//! # use coset::iana::{Algorithm, CwtClaimName};
//! # use dcaf::{ToCborMap, CoseCipherCommon, CoseSign1Cipher, sign_access_token, verify_access_token};
//! # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! # use dcaf::common::cbor_values::ProofOfPossessionKey::PlainCoseKey;
//! # use dcaf::error::{AccessTokenError, CoseCipherError};
//! # struct FakeCrypto {}
//! #
//! # impl CoseCipherCommon for FakeCrypto {
//! #     type Error = String;
//! #
//! #     fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
//! #         // We have to later verify these headers really are used.
//! #         if let Some(label) = unprotected_header.rest.iter().find(|x| x.0 == Label::Int(47)) {
//! #             return Err(CoseCipherError::existing_header_label(&label.0));
//! #         }
//! #         if protected_header.alg != None {
//! #             return Err(CoseCipherError::existing_header("alg"));
//! #         }
//! #         unprotected_header.rest.push((Label::Int(47), Value::Null));
//! #         protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::Direct));
//! #         Ok(())
//! #     }
//! # }
//! #
//! # /// Implements basic operations from the [`CoseSign1Cipher`] trait without actually using any
//! # /// "real" cryptography.
//! # /// This is purely to be used for testing and obviously offers no security at all.
//! # impl CoseSign1Cipher for FakeCrypto {
//! #     fn generate_signature(&mut self, data: &[u8]) -> Vec<u8> {
//! #         data.to_vec()
//! #     }
//! #
//! #     fn verify_signature(&mut self, sig: &[u8], data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
//! #         if sig != self.generate_signature(data) {
//! #             Err(CoseCipherError::VerificationFailure)
//! #         } else {
//! #             Ok(())
//! #         }
//! #     }
//! # }
//!
//! # let mut cipher = FakeCrypto {};
//! let key = ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]);
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, key.to_ciborium_value())
//!      .build();
//! let token = sign_access_token(claims, &mut cipher, None, None, None)?;
//! assert!(verify_access_token(&token, &mut cipher, None).is_ok());
//! # Ok::<(), AccessTokenError<String>>(())
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use ciborium::value::Value;
use coset::{AsCborValue, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder, CoseEncryptBuilder, CoseKey, CoseMac0, CoseRecipient, CoseRecipientBuilder, CoseSign, CoseSign1, CoseSign1Builder, CoseSignatureBuilder, CoseSignBuilder, EncryptionContext, Header, HeaderBuilder, ProtectedHeader};
use coset::cwt::ClaimsSet;
use rand::{CryptoRng, RngCore};

use crate::common::cbor_values::ByteString;
use crate::error::{AccessTokenError, CoseCipherError};

#[cfg(test)]
mod tests;

pub trait ToCoseKey {
    fn to_cose_key(&self) -> CoseKey;
}

macro_rules! add_common_cipher_functionality {
    [$a:ty] => {
        /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
        type Error: Display + Debug;

        /// Sets headers specific to this cipher by adding new header fields to the given
        /// `unprotected_header` and `protected_header`.
        ///
        /// Before actually changing the headers, it will be verified that none of the header fields
        /// that are about to be set are already set, so as not to overwrite them. In such a
        /// case, an error is returned.
        ///
        /// This will usually not be called by users of `dcaf-rs`, but instead by access methods
        /// such as [`encrypt_access_token`], which will later pass it to [`coset`]'s methods.
        ///
        /// # Errors
        /// - When the fields that this method would set on the given headers are already set.
        ///
        /// # Example
        /// Let's say our cipher needs to set the content type to
        /// [`Cbor`](coset::iana::CoapContentFormat::Cbor) (in the unprotected header)
        /// and the algorithm to [`HMAC_256_256`](coset::iana::Algorithm::HMAC_256_256)
        /// (in the protected header). Our implementation would first need to verify that these
        /// header fields haven't already been set, then actually set them, so an implementation
        /// of this function might look like the following:
        /// ```
        /// # use ciborium::value::Value;
        /// # use coset::{ContentType, Header, Label, RegisteredLabel};
        /// # use coset::iana::Algorithm;
        /// # use dcaf::CoseCipherCommon;
        /// # use dcaf::error::CoseCipherError;
        /// # struct FakeCipher {}
        /// # impl CoseCipherCommon for FakeCipher {
        /// #    // This should of course be an actual error type, not just a String.
        /// #    type Error = String;
        ///
        /// fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
        ///    if unprotected_header.content_type.is_some() {
        ///        return Err(CoseCipherError::existing_header("content_type"));
        ///    }
        ///    if protected_header.alg.is_some() {
        ///        return Err(CoseCipherError::existing_header("alg"));
        ///    }
        ///    unprotected_header.content_type = Some(ContentType::Assigned(coset::iana::CoapContentFormat::Cbor));
        ///    protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::HMAC_256_256));
        ///    Ok(())
        /// }
        /// # }
        /// ```
        fn set_headers<RNG: RngCore + CryptoRng>(
            key: &$a,
            unprotected_header: &mut Header,
            protected_header: &mut Header,
            rng: RNG
        ) -> Result<(), CoseCipherError<Self::Error>>;
    }
}

/// Provides basic operations for encrypting and decrypting COSE structures.
///
/// This will be used by [`encrypt_access_token`] and [`decrypt_access_token`] to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// Since [`CoseCipherCommon`] also needs to be implemented, the
/// [`headers` method](CoseCipherCommon::header) can be used to set parameters this cipher requires
/// to be set. If you need to operate on other fields in the token than just the claims,
/// you can use the data type behind this trait for that.
/// The methods provided in this trait accept `&mut self` in case the structure behind it needs to
/// modify internal fields during any cryptographic operation.
///
/// # Example
/// For example, to simply implement the encryption operation as appending the `aad` to the
/// `plaintext` (which you **clearly should not do**, this is just for illustrative purposes),
/// and implementing `decrypt` by verifying that the AAD matches (same warning applies):
/// ```
/// # use coset::Header;
/// # use dcaf::{CoseCipherCommon, CoseEncryptCipher};
/// # use dcaf::error::CoseCipherError;
/// # struct FakeCrypto {};
/// # impl CoseCipherCommon for FakeCrypto {
/// #     type Error = String;
/// #     fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        unimplemented!()
/// #     }
/// # }
/// impl CoseEncryptCipher for FakeCrypto {
///     fn encrypt(&mut self, data: &[u8], aad: &[u8]) -> Vec<u8> {
///         // We simply put AAD behind the data and call it a day.
///         let mut result: Vec<u8> = Vec::new();
///         result.append(&mut data.to_vec());
///         result.append(&mut aad.to_vec());
///         result
///     }
///
///     fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
///         // Now we just split off the AAD we previously put at the end of the data.
///         // We return an error if it does not match.
///         if ciphertext.len() < aad.len() {
///             return Err(CoseCipherError::Other("Encrypted data must be at least as long as AAD!".to_string()));
///         }
///         let mut result: Vec<u8> = ciphertext.to_vec();
///         let aad_result = result.split_off(ciphertext.len() - aad.len());
///         if aad != aad_result {
///             Err(CoseCipherError::DecryptionFailure)
///         } else {
///             Ok(result)
///         }
///     }
/// }
///
/// let mut cipher = FakeCrypto{};
/// let data = vec![0xDC, 0xAF];
/// let aad = vec![42];
/// let encrypted = cipher.encrypt(&data, &aad);
/// assert_eq!(cipher.decrypt(&encrypted, &aad)?, data);
/// # Ok::<(), CoseCipherError<String>>(())
/// ```
pub trait CoseEncryptCipher {
    type EncryptKey: ToCoseKey + Into<Vec<u8>>;
    type DecryptKey: ToCoseKey + TryFrom<Vec<u8>>;
    /// Encrypts the given `plaintext` and `aad`, returning the result.
    ///
    /// For an example, view the documentation of [`CoseEncrypt0Cipher`].
    fn encrypt(
        key: &Self::EncryptKey,
        plaintext: &[u8],
        aad: &[u8],
        protected_header: &Header,
        unprotected_header: &Header,
    ) -> Vec<u8>;

    /// Decrypts the given `ciphertext` and `aad`, returning the result.
    ///
    /// For an example, view the documentation of [`CoseEncrypt0Cipher`].
    ///
    /// # Errors
    /// If the `ciphertext` and `aad` are invalid, i.e., can't be decrypted.
    fn decrypt(
        key: &Self::DecryptKey,
        ciphertext: &[u8],
        aad: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    add_common_cipher_functionality![Self::EncryptKey];
}

pub trait MultipleEncryptCipher: CoseEncryptCipher {
    fn generate_cek<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self::EncryptKey;
}

/// Provides basic operations for signing and verifying COSE structures.
///
/// This will be used by [`sign_access_token`] and [`verify_access_token`] to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// Since [`CoseCipherCommon`] also needs to be implemented, the
/// [`headers` method](CoseCipherCommon::header) can be used to set parameters this cipher requires
/// to be set. If you need to operate on other fields in the token than just the claims,
/// you can use the data type behind this trait for that.
/// The methods provided in this trait accept `&mut self` in case the structure behind it needs to
/// modify internal fields during any cryptographic operation.
///
/// # Example
/// For example, to simply implement the signing operation as the identity function
/// (which you **clearly should not do**, this is just for illustrative purposes):
/// ```
/// # use coset::Header;
/// # use dcaf::{CoseCipherCommon, CoseSign1Cipher};
/// # use dcaf::error::CoseCipherError;
/// # struct FakeSigner {};
/// # impl CoseCipherCommon for FakeSigner {
/// #     type Error = String;
/// #     fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        unimplemented!()
/// #     }
/// # }
/// impl CoseSign1Cipher for FakeSigner {
///    fn generate_signature(&mut self, target: &[u8]) -> Vec<u8> {
///        target.to_vec()
///    }
///
///    fn verify_signature(&mut self, signature: &[u8], signed_data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
///         if signature != self.generate_signature(signed_data) {
///              Err(CoseCipherError::VerificationFailure)
///         } else {
///              Ok(())
///         }
///    }
/// }
///
/// let mut signer = FakeSigner {};
/// let signature = signer.generate_signature(&vec![0xDC, 0xAF]);
/// assert!(signer.verify_signature(&signature, &vec![0xDC, 0xAF]).is_ok());
/// assert!(signer.verify_signature(&signature, &vec![0xDE, 0xAD]).is_err());
/// ```
pub trait CoseSignCipher {
    type SignKey: ToCoseKey;
    type VerifyKey: ToCoseKey;

    /// Cryptographically signs the given `target` value and returns the signature.
    ///
    /// For an example, see the documentation of [`CoseSign1Cipher`].
    fn sign(
        key: &Self::SignKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8>;

    /// Verifies the `signature` of the `signed_data`.
    ///
    /// For an example, see the documentation of [`CoseSign1Cipher`].
    ///
    /// # Errors
    /// If the `signature` is invalid or does not belong to the `signed_data`.
    fn verify(
        key: &Self::VerifyKey,
        signature: &[u8],
        signed_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
        unprotected_signature_header: Option<&Header>,
        protected_signature_header: Option<&ProtectedHeader>,
    ) -> Result<(), CoseCipherError<Self::Error>>;

    add_common_cipher_functionality![Self::SignKey];
}

pub trait MultipleSignCipher: CoseSignCipher {}

/// Provides basic operations for generating and verifying MAC tags for COSE structures.
///
/// This trait is currently not used by any access token function.
///
/// # Example
/// For example, to simply implement the signing operation as the identity function
/// (which you **clearly should not do**, this is just for illustrative purposes):
/// ```
/// # use coset::Header;
/// # use dcaf::{CoseCipherCommon, CoseMacCipher, CoseSign1Cipher};
/// # use dcaf::error::CoseCipherError;
/// # struct FakeTagger {};
/// # impl CoseCipherCommon for FakeTagger {
/// #     type Error = String;
/// #     fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        unimplemented!()
/// #     }
/// # }
/// impl CoseMacCipher for FakeTagger {
///    fn compute(&mut self, target: &[u8]) -> Vec<u8> {
///        target.to_vec()
///    }
///
///    fn verify(&mut self, tag: &[u8], signed_data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
///         if tag != self.generate_tag(signed_data) {
///              Err(CoseCipherError::VerificationFailure)
///         } else {
///              Ok(())
///         }
///    }
/// }
///
/// let mut tagger = FakeTagger {};
/// let tag = tagger.generate_tag(&vec![0xDC, 0xAF]);
/// assert!(tagger.verify_tag(&tag, &vec![0xDC, 0xAF]).is_ok());
/// assert!(tagger.verify_tag(&tag, &vec![0xDE, 0xAD]).is_err());
/// ```
pub trait CoseMacCipher {
    type ComputeKey: ToCoseKey;
    type VerifyKey: ToCoseKey;

    /// Generates a MAC tag for the given `target` and returns it.
    ///
    /// For an example, see the documentation of [`CoseMac0Cipher`].
    fn compute(
        key: &Self::ComputeKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8>;

    /// Verifies the `tag` of the `maced_data`.
    ///
    /// For an example, see the documentation of [`CoseMac0Cipher`].
    ///
    /// # Errors
    /// If the `tag` is invalid or does not belong to the `maced_data`.
    fn verify(
        key: &Self::VerifyKey,
        tag: &[u8],
        maced_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
    ) -> Result<(), CoseCipherError<Self::Error>>;

    add_common_cipher_functionality![Self::ComputeKey];
}

pub trait MultipleMacCipher: CoseMacCipher {}

/// Creates new headers if `unprotected_header` or `protected_header` is `None`, respectively,
/// and passes them to the `cipher`'s `header` function, returning the mutated result.
/// Arguments: key (expr), unprotected (ident), protected (ident), rng (expr) cipher (type)
macro_rules! prepare_headers {
    ($key:expr, $unprotected:ident, $protected:ident, $rng:expr, $t:ty) => {{
        let mut unprotected = $unprotected.unwrap_or_else(|| HeaderBuilder::new().build());
        let mut protected = $protected.unwrap_or_else(|| HeaderBuilder::new().build());
        if let Err(e) = <$t>::set_headers($key, &mut unprotected, &mut protected, $rng)
            .map_err(AccessTokenError::from_cose_cipher_error)
        {
            Err(e)
        } else {
            Ok((unprotected, protected))
        }
    }};
}

/// Encrypts the given `claims` with the given headers and `aad` using `cipher` for cryptography,
/// returning the token as a serialized bytestring of the [`CoseEncrypt0`] structure.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt0`] structure.
///
/// # Example
/// For example, assuming we have a [`CoseEncrypt0Cipher`] in `cipher`,
/// have a [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey)
/// in `key` and want to associate this key with the access token we are about to create and encrypt:
/// ```
/// # use coset::cwt::ClaimsSetBuilder;
/// # use coset::Header;
/// # use coset::iana::CwtClaimName;
/// # use dcaf::{ToCborMap, CoseCipherCommon, CoseEncryptCipher, decrypt_access_token, encrypt_access_token, sign_access_token, verify_access_token};
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::error::{AccessTokenError, CoseCipherError};
/// # struct FakeCrypto {};
/// # impl CoseCipherCommon for FakeCrypto {
/// #     type Error = String;
/// #     fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        Ok(())
/// #     }
/// # }
/// # impl CoseEncryptCipher for FakeCrypto {
/// #     fn encrypt(&mut self, data: &[u8], aad: &[u8]) -> Vec<u8> {
/// #         let mut result: Vec<u8> = Vec::new();
/// #         result.append(&mut data.to_vec());
/// #         result.append(&mut aad.to_vec());
/// #         result
/// #     }
/// #
/// #     fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
/// #         if ciphertext.len() < aad.len() {
/// #             return Err(CoseCipherError::Other("Encrypted data must be at least as long as AAD!".to_string()));
/// #         }
/// #         let mut result: Vec<u8> = ciphertext.to_vec();
/// #         let aad_result = result.split_off(ciphertext.len() - aad.len());
/// #         if aad != aad_result {
/// #             Err(CoseCipherError::DecryptionFailure)
/// #         } else {
/// #             Ok(result)
/// #         }
/// #     }
/// # }
/// # let mut cipher = FakeCrypto{};
/// # let key = ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]);
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.to_ciborium_value())
///    .build();
/// let token: ByteString = encrypt_access_token(claims.clone(), &mut cipher, None, None, None)?;
/// assert_eq!(decrypt_access_token(&token, &mut cipher, None)?, claims);
/// # Ok::<(), AccessTokenError<String>>(())
/// ```
pub fn encrypt_access_token<T, RNG>(
    key: T::EncryptKey,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    mut rng: RNG,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher,
    RNG: RngCore + CryptoRng,
{
    let (unprotected, protected) =
        prepare_headers!(&key, unprotected_header, protected_header, &mut rng, T)?;
    CoseEncrypt0Builder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .create_ciphertext(
            &claims.to_vec().map_err(AccessTokenError::from_cose_error)?[..],
            external_aad.unwrap_or(&[0; 0]),
            |payload, aad| T::encrypt(&key, payload, aad, &unprotected, &protected),
        )
        .build()
        .to_vec()
        .map_err(AccessTokenError::from_cose_error)
}

/// Encrypts the given `claims` with the given headers and `aad` using `cipher` for cryptography,
/// returning the token as a serialized bytestring of the [`CoseEncrypt0`] structure.
///
/// # Errors
/// TODO
///
/// # Panics
/// TODO
pub fn encrypt_access_token_multiple<T, RNG>(
    keys: Vec<&T::EncryptKey>,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    mut rng: RNG,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: MultipleEncryptCipher,
    RNG: CryptoRng + RngCore,
{
    let key = T::generate_cek(&mut rng);
    let (unprotected, protected) = prepare_headers!(&key, unprotected_header, protected_header, &mut rng, T)?;
    let mut builder = CoseEncryptBuilder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .create_ciphertext(
            &claims.to_vec().map_err(AccessTokenError::from_cose_error)?[..],
            external_aad.unwrap_or(&[0; 0]),
            |payload, aad| T::encrypt(&key, payload, aad, &protected, &unprotected),
        );
    let serialized_key: Vec<u8> = key.into();
    for rec_key in keys {
        let (rec_unprotected, rec_protected) = prepare_headers!(rec_key, None, None, &mut rng, T)?;
        builder = builder.add_recipient(CoseRecipientBuilder::new().protected(rec_protected.clone()).unprotected(rec_unprotected.clone()).create_ciphertext(
            // TODO: What should AAD be here?
            EncryptionContext::EncRecipient, &serialized_key, &[0; 0], |payload, aad| T::encrypt(rec_key, payload, aad, &rec_protected, &rec_unprotected)
        ).build());
    }
    builder.build()
        .to_vec()
        .map_err(AccessTokenError::from_cose_error)
}

/// Signs the given `claims` with the given headers and `aad` using `cipher` for cryptography,
/// returning the token as a serialized bytestring of the [`CoseSign1`] structure.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign1`] structure.
///
/// # Example
/// For example, assuming we have a [`CoseSign1Cipher`] in `cipher`,
/// have a [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey)
/// in `key` and want to associate this key with the access token we are about to create and sign:
/// ```
/// # use coset::cwt::ClaimsSetBuilder;
/// # use coset::Header;
/// # use coset::iana::CwtClaimName;
/// # use dcaf::{ToCborMap, CoseCipherCommon, CoseSign1Cipher, encrypt_access_token, sign_access_token, verify_access_token};
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::error::{AccessTokenError, CoseCipherError};
/// # struct FakeSigner {};
/// # impl CoseCipherCommon for FakeSigner {
/// #     type Error = String;
/// #     fn set_headers(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #         Ok(())
/// #     }
/// # }
/// # impl CoseSign1Cipher for FakeSigner {
/// #    fn generate_signature(&mut self, target: &[u8]) -> Vec<u8> {
/// #        target.to_vec()
/// #    }
/// #    fn verify_signature(&mut self, signature: &[u8], signed_data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
/// #         if signature != self.generate_signature(signed_data) {
/// #              Err(CoseCipherError::VerificationFailure)
/// #         } else {
/// #              Ok(())
/// #         }
/// #    }
/// # }
/// # let mut cipher = FakeSigner {};
/// # let key = ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]);
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.to_ciborium_value())
///    .build();
/// let token: ByteString = sign_access_token(claims, &mut cipher, None, None, None)?;
/// assert!(verify_access_token(&token, &mut cipher, None).is_ok());
/// # Ok::<(), AccessTokenError<String>>(())
/// ```
pub fn sign_access_token<T, RNG>(
    key: &T::SignKey,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    mut rng: RNG,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
    RNG: RngCore + CryptoRng,
{
    let (unprotected, protected) =
        prepare_headers!(key, unprotected_header, protected_header, &mut rng, T)?;
    CoseSign1Builder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .payload(claims.to_vec().map_err(AccessTokenError::from_cose_error)?)
        .create_signature(external_aad.unwrap_or(&[0; 0]), |x| {
            T::sign(key, x, &unprotected, &protected)
        })
        .build()
        .to_vec()
        .map_err(AccessTokenError::from_cose_error)
}

/// TODO.
/// # Errors
/// TODO.
pub fn sign_access_token_multiple<T, RNG>(
    keys: Vec<&T::SignKey>,
    claims: ClaimsSet,
    external_aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    mut rng: RNG,
) -> Result<ByteString, AccessTokenError<T::Error>>
    where
        T: MultipleSignCipher,
        RNG: RngCore + CryptoRng,
{
    let (unprotected, protected) = (unprotected_header.unwrap_or_else(|| HeaderBuilder::default().build()), protected_header.unwrap_or_else(|| HeaderBuilder::default().build()));
    let mut builder = CoseSignBuilder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .payload(claims.to_vec().map_err(AccessTokenError::from_cose_error)?);

    for key in keys {
        let (rec_unprotected, rec_protected) = prepare_headers!(key, None, None, &mut rng, T)?;
        let signature = CoseSignatureBuilder::new().unprotected(rec_unprotected.clone()).protected(rec_protected.clone()).build();
        builder = builder.add_created_signature(signature, external_aad.unwrap_or(&[0; 0]), |x| {
            T::sign(key, x, &unprotected, &protected)
        });
    }

    builder.build()
        .to_vec()
        .map_err(AccessTokenError::from_cose_error)
}

/// Returns the headers of the given signed ([`CoseSign1`]), MAC tagged ([`CoseMac0`]),
/// or encrypted ([`CoseEncrypt0`]) access token.
///
/// When the given `token` is neither a [`CoseEncrypt0`], [`CoseSign1`], nor a [`CoseMac0`]
/// structure, `None` is returned.
///
/// # Example
/// For example, say you have an access token saved in `token` and want to look at its headers:
/// ```
/// # use dcaf::common::cbor_values::ByteString;
/// # use dcaf::token::get_token_headers;
/// # let token = vec![
/// # 0x84, 0x4b, 0xa2, 0x1, 0x25, 0x4, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0xa2, 0x5, 0x4d,
/// # 0x63, 0x68, 0x98, 0x99, 0x4f, 0xf0, 0xec, 0x7b, 0xfc, 0xf6, 0xd3, 0xf9, 0x5b, 0x18, 0x2f, 0xf6,
/// # 0x58, 0x20, 0xa1, 0x8, 0xa3, 0x1, 0x4, 0x2, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x20,
/// # 0x51, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
/// # 0x71, 0x8, 0x58, 0x40, 0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
/// # 0x4b, 0xa2, 0x1, 0x25, 0x4, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x45, 0x1, 0x2, 0x3, 0x4,
/// # 0x5, 0x58, 0x20, 0xa1, 0x8, 0xa3, 0x1, 0x4, 0x2, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x20,
/// # 0x51, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
/// # 0x71, 0x8];
/// if let Some((unprotected_header, protected_header)) = get_token_headers(&token) {
///   assert_eq!(protected_header.header.key_id, vec![0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c])
/// } else {
///   unreachable!("Example token should be valid.")
/// }
/// ```
#[must_use]
pub fn get_token_headers(token: &ByteString) -> Option<(Header, ProtectedHeader)> {
    let value: Option<Value> = ciborium::de::from_reader(token.as_slice()).ok();
    // All of COSE_Encrypt(0), COSE_Sign(1), COSE_Mac(0) are an array with headers first
    match value {
        Some(Value::Array(x)) => {
            let mut iter = x.into_iter();
            let protected = iter
                .next()
                .map(ProtectedHeader::from_cbor_bstr)
                .and_then(Result::ok);
            let unprotected = iter
                .next()
                .map(Header::from_cbor_value)
                .and_then(Result::ok);
            if let (Some(u), Some(p)) = (unprotected, protected) {
                Some((u, p))
            } else {
                None
            }
        }
        Some(_) | None => None,
    }
}

/// Verifies the given `token` and `aad` using `verifier` for cryptography,
/// returning an error in case it could not be verified.
///
/// NOTE: Protected headers are not verified as of now.
///
/// For an example, see the documentation of [`sign_access_token`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing the given `token`
///   to a [`CoseSign1`] structure
///   (e.g., if it's not in fact a [`CoseSign1`] structure but rather something else).
/// - When there's a verification error coming from the `verifier`
///   (e.g., if the `token`'s data does not match its signature).
pub fn verify_access_token<T>(
    key: &T::VerifyKey,
    token: &ByteString,
    aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    // TODO: Verify protected headers
    sign.verify_signature(aad.unwrap_or(&[0; 0]), |signature, signed_data| {
        T::verify(
            key,
            signature,
            signed_data,
            &unprotected,
            &protected,
            None,
            None,
        )
    })
    .map_err(AccessTokenError::from_cose_cipher_error)
}

/// TODO.
/// # Errors
/// TODO.
/// # Panics
/// TODO.
pub fn verify_access_token_multiple<T>(
    key: &T::VerifyKey,
    kid: &[u8],
    token: &ByteString,
    aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
{
    let sign = CoseSign::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    let matching = sign
        .signatures
        .iter()
        .enumerate()
        .filter(|(_, s)| s.unprotected.key_id == kid || s.protected.header.key_id == kid)
        .map(|(i, _)| i);
    // We iterate over each signature whose kid matches until it completes successfully.
    // TODO: However: https://www.rfc-editor.org/rfc/rfc9052.html#section-4.1-3
    for index in matching {
        // TODO: Verify protected headers
        if let Ok(()) =
            sign.verify_signature(index, aad.unwrap_or(&[0; 0]), |signature, signed_data| {
                T::verify(
                    key,
                    signature,
                    signed_data,
                    &unprotected,
                    &protected,
                    Some(&sign.signatures[index].unprotected),
                    Some(&sign.signatures[index].protected),
                )
            })
        {
            return Ok(());
        }
    }
    Err(AccessTokenError::from_cose_cipher_error(
        CoseCipherError::VerificationFailure,
    ))
}

/// Decrypts the given `token` and `aad` using `cipher` for cryptography,
/// returning the decrypted `ClaimsSet`.
///
/// For an example, see the documentation of [`encrypt_access_token`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing
///   the given `token` to a [`CoseEncrypt0`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt0`] structure but rather something else).
/// - When there's a decryption error coming from the `cipher`.
/// - When the deserialized and decrypted [`CoseEncrypt0`] structure does not contain a valid
///   [`ClaimsSet`].
pub fn decrypt_access_token<T>(
    key: &T::DecryptKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: CoseEncryptCipher,
{
    let encrypt =
        CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from_cose_error)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    // TODO: Verify protected header
    let result = encrypt
        .decrypt(external_aad.unwrap_or(&[0; 0]), |ciphertext, aad| {
            T::decrypt(key, ciphertext, aad, &unprotected, &protected)
        })
        .map_err(AccessTokenError::from_cose_cipher_error)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from_cose_error)
}

/// TODO.
/// # Errors
/// TODO.
pub fn decrypt_access_token_multiple<K, C>(
    kek: &K::DecryptKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<ClaimsSet, AccessTokenError<C::Error>>
where
    K: CoseEncryptCipher,
    C: CoseEncryptCipher,
{
    let encrypt =
        CoseEncrypt::from_slice(token.as_slice()).map_err(AccessTokenError::from_cose_error)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    let aad = external_aad.unwrap_or(&[0; 0]);
    // FIXME: below line does not compile
    let cose_kek: CoseKey = kek.to_cose_key();
    let kek_id = cose_kek.key_id.as_slice();
    // One of the recipient structures should contain CEK encrypted with our KEK.
    let recipients = encrypt
        .recipients
        .iter()
        .filter(|x| x.unprotected.key_id == kek_id || x.protected.header.key_id == kek_id);
    let mut content_keys = recipients.filter_map(|r| {
        r.decrypt(EncryptionContext::EncRecipient, aad, |ciphertext, aad| {
            K::decrypt(kek, ciphertext, aad, &r.unprotected, &r.protected)
        })
            .ok()
    });
    // Our CEK must be contained exactly once.
    if let Some(content_key) = content_keys.next() {
        if content_keys.next().is_none() {
            let target_key = C::DecryptKey::try_from(content_key).map_err(|_| {
                AccessTokenError::from_cose_cipher_error(CoseCipherError::DecryptionFailure)
            })?;
            // TODO: Verify protected header
            let result = encrypt
                .decrypt(aad, |ciphertext, aad| {
                    C::decrypt(&target_key, ciphertext, aad, &unprotected, &protected)
                })
                .map_err(AccessTokenError::from_cose_cipher_error)?;
            ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from_cose_error)
        } else {
            // TODO: Implement strict mode, where this is prohibited, otherwise allow it
            Err(AccessTokenError::MultipleMatchingKeys)
        }
    } else {
        Err(AccessTokenError::NoMatchingKey)
    }
}
