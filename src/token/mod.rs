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
//! This is because we plan to move much of the code here to the [coset](https://docs.rs/coset/)
//! library, since much of this just builds on COSE functionality and isn't ACE-OAuth specific.
//!
//! In order to use any of these methods, you will need to provide a cipher which handles
//! the cryptographic operations by implementingeither [`CoseEncryptCipher`],
//! [`CoseMacCipher`] or [`CoseSignCipher`], depending on the intended operation.
//! If you plan to support `CoseEncrypt` or `CoseSign` rather than just `CoseEncrypt0` or
//! `CoseSign1` (i.e., if you have multiple recipients with separate keys), you will also need to
//! implement [`MultipleEncryptCipher`] or [`MultipleSignCipher`].
//! See the respective traits for details.
//!
//! # Example
//! The following shows how to create and sign an access token (assuming a cipher named
//! `FakeCrypto` which implements [`CoseSignCipher`] exists.):
//! ```
//! # // TODO: There's really too much hidden code here. Should be heavily refactored once we have
//! # //       crypto implementations available. Same goes for crate-level docs.
//! # use ciborium::value::Value;
//! # use coset::{AsCborValue, CoseKey, CoseKeyBuilder, Header, Label, ProtectedHeader};
//! # use coset::cwt::{ClaimsSetBuilder, Timestamp};
//! # use coset::iana::{Algorithm, CwtClaimName};
//! # use rand::{CryptoRng, RngCore};
//! # use dcaf::{ToCborMap, sign_access_token, verify_access_token, CoseSignCipher};
//! # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! # use dcaf::common::cbor_values::ProofOfPossessionKey::PlainCoseKey;
//! # use dcaf::error::{AccessTokenError, CoseCipherError};
//! # use dcaf::token::ToCoseKey;
//!
//! #[derive(Clone)]
//! # pub(crate) struct FakeKey {
//! #     key: [u8; 5],
//! #     kid: [u8; 2],
//! # }
//! #
//! # impl ToCoseKey for FakeKey {
//! #     fn to_cose_key(&self) -> CoseKey {
//! #         CoseKeyBuilder::new_symmetric_key(self.key.to_vec())
//! #             .key_id(self.kid.to_vec())
//! #             .build()
//! #     }
//! # }
//! #
//! # struct FakeCrypto {}
//! #
//! # #[derive(Clone, Copy)]
//! # pub(crate) struct FakeRng;
//! #
//! # impl RngCore for FakeRng {
//! #     fn next_u32(&mut self) -> u32 {
//! #         0
//! #     }
//! #
//! #     fn next_u64(&mut self) -> u64 {
//! #         0
//! #     }
//! #
//! #     fn fill_bytes(&mut self, dest: &mut [u8]) {
//! #         dest.fill(0);
//! #     }
//! #
//! #     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
//! #         dest.fill(0);
//! #         Ok(())
//! #     }
//! # }
//! #
//! # impl CryptoRng for FakeRng {}
//! #
//! # /// Implements basic operations from the [`CoseSignCipher`] trait without actually using any
//! # /// "real" cryptography.
//! # /// This is purely to be used for testing and obviously offers no security at all.
//! # impl CoseSignCipher for FakeCrypto {
//! #     type Error = String;
//! #     type SignKey = FakeKey;
//! #     type VerifyKey = Self::SignKey;
//! #
//! #     fn set_headers<RNG: RngCore + CryptoRng>(
//! #         key: &FakeKey,
//! #         unprotected_header: &mut Header,
//! #         protected_header: &mut Header,
//! #         rng: RNG
//! #     ) -> Result<(), CoseCipherError<Self::Error>> {
//! #         if let Some(label) = unprotected_header
//! #             .rest
//! #             .iter()
//! #             .find(|x| x.0 == Label::Int(47))
//! #         {
//! #             return Err(CoseCipherError::existing_header_label(&label.0));
//! #         }
//! #         if protected_header.alg != None {
//! #             return Err(CoseCipherError::existing_header("alg"));
//! #         }
//! #         if !protected_header.key_id.is_empty() {
//! #             return Err(CoseCipherError::existing_header("key_id"));
//! #         }
//! #         unprotected_header.rest.push((Label::Int(47), Value::Null));
//! #         protected_header.alg = Some(coset::Algorithm::Assigned(Algorithm::Direct));
//! #         protected_header.key_id = key.kid.to_vec();
//! #         Ok(())
//! #     }
//! #     fn sign(
//! #         key: &Self::SignKey,
//! #         target: &[u8],
//! #         unprotected_header: &Header,
//! #         protected_header: &Header,
//! #     ) -> Vec<u8> {
//! #         // We simply append the key behind the data.
//! #         let mut signature = target.to_vec();
//! #         signature.append(&mut key.key.to_vec());
//! #         signature
//! #     }
//! #
//! #     fn verify(
//! #         key: &Self::VerifyKey,
//! #         signature: &[u8],
//! #         signed_data: &[u8],
//! #         unprotected_header: &Header,
//! #         protected_header: &ProtectedHeader,
//! #         unprotected_signature_header: Option<&Header>,
//! #         protected_signature_header: Option<&ProtectedHeader>,
//! #     ) -> Result<(), CoseCipherError<Self::Error>> {
//! #         let matching_kid = if let Some(protected) = protected_signature_header {
//! #             protected.header.key_id == key.kid
//! #         } else {
//! #             protected_header.header.key_id == key.kid
//! #         };
//! #         let signed_again = Self::sign(key, signed_data, unprotected_header, &protected_header.header);
//! #         if matching_kid && signed_again == signature
//! #         {
//! #             Ok(())
//! #         } else {
//! #             Err(CoseCipherError::VerificationFailure)
//! #         }
//! #     }
//! # }
//!
//! let rng = FakeRng;
//! let key = FakeKey { key: [1,2,3,4,5], kid: [0xDC, 0xAF]};
//! let cose_key: CoseKey = key.to_cose_key();
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, cose_key.to_cbor_value()?)
//!      .build();
//! let token = sign_access_token::<FakeCrypto, FakeRng>(&key, claims, None, None, None, rng)?;
//! assert!(verify_access_token::<FakeCrypto>(&key, &token, None).is_ok());
//! # Ok::<(), AccessTokenError<String>>(())
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use ciborium::value::Value;
use coset::cwt::ClaimsSet;
use coset::{
    AsCborValue, CborSerializable, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder,
    CoseEncryptBuilder, CoseKey, CoseRecipientBuilder, CoseSign, CoseSign1, CoseSign1Builder,
    CoseSignBuilder, CoseSignatureBuilder, EncryptionContext, Header, HeaderBuilder,
    ProtectedHeader,
};
use rand::{CryptoRng, RngCore};

use crate::common::cbor_values::ByteString;
use crate::error::{AccessTokenError, CoseCipherError, MultipleCoseError};

#[cfg(test)]
mod tests;

/// Trait for keys which can be converted to [CoseKey]s from a reference of the original type.
pub trait ToCoseKey {
    /// Converts a reference of itself to a [CoseKey].
    ///
    /// Note that this may lead to fields of the key being copied,
    /// as we merely pass a reference in, even though [CoseKey] is not associated with any lifetime.
    fn to_cose_key(&self) -> CoseKey;
}

// TODO: Examples in here are currently either not run or do not exist because they require too much
//       setup (see crate-level docs). This should be fixed once we have cipher implementations.

macro_rules! add_common_cipher_functionality {
    [$a:ty] => {
        /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
        type Error: Display + Debug;

        /// Sets headers specific to this cipher by adding new header fields to the given
        /// `unprotected_header` and `protected_header`.
        ///
        /// The given `key` may be used to extract information for the headers (e.g., the key ID)
        /// and `rng` may be used to generate random values for the headers (e.g., an IV).
        ///
        /// Before actually changing the headers, it will be verified that none of the header fields
        /// that are about to be set are already set, so as not to overwrite them. In such a
        /// case, an error is returned.
        ///
        /// This will usually not be called by users of `dcaf-rs`, but instead by access methods
        /// such as [`encrypt_access_token`], which will later pass it to [coset]'s methods.
        ///
        /// # Errors
        /// - When the fields that this method would set on the given headers are already set.
        ///
        /// # Example
        /// Let's say our cipher needs to set the content type to
        /// [`Cbor`](coset::iana::CoapContentFormat::Cbor) (in the unprotected header)
        /// and the key ID to the ID of the passed in `key` (in the protected header).
        /// Our implementation would first need to verify that these
        /// header fields haven't already been set, then actually set them, so an implementation
        /// of this function might look like the following:
        /// ```ignore
        /// fn set_headers<RNG: RngCore + CryptoRng>(
        ///     key: &FakeKey,
        ///     unprotected_header: &mut Header,
        ///     protected_header: &mut Header,
        ///     rng: RNG
        /// ) -> Result<(), CoseCipherError<Self::Error>> {
        ///    if unprotected_header.content_type.is_some() {
        ///        return Err(CoseCipherError::existing_header("content_type"));
        ///    }
        ///    if !protected_header.key_id.is_empty() {
        ///        return Err(CoseCipherError::existing_header("kid"));
        ///    }
        ///    unprotected_header.content_type = Some(ContentType::Assigned(coset::iana::CoapContentFormat::Cbor));
        ///    protected_header.key_id = key.kid.to_vec();
        ///    Ok(())
        /// }
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
/// This will be used by [`encrypt_access_token`] and [`decrypt_access_token`] (as well as the
/// variants for multiple recipients: [`encrypt_access_token_multiple`]
/// and [`decrypt_access_token_multiple`]) to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// The [`set_headers` method](CoseEncryptCipher::set_headers) can be used to set parameters this
/// cipher requires to be set.
pub trait CoseEncryptCipher {
    /// Type of the encryption key. Needs to be serializable to a vector of bytes in case
    /// [`encrypt_access_token_multiple`] is used, in which we need to serialize the
    /// Key Encryption Keys.
    type EncryptKey: ToCoseKey + Into<Vec<u8>>;

    /// Type of the decryption key. Needs to be deserializable from a vector of bytes in case
    /// [`decrypt_access_token_multiple`] is used, in which we need to deserialize the
    /// Key Encryption Keys.
    type DecryptKey: ToCoseKey + TryFrom<Vec<u8>>;

    /// Encrypts the `plaintext` and `aad` with the given `key`, returning the result.
    fn encrypt(
        key: &Self::EncryptKey,
        plaintext: &[u8],
        aad: &[u8],
        protected_header: &Header,
        unprotected_header: &Header,
    ) -> Vec<u8>;

    /// Decrypts the `ciphertext` and `aad` with the given `key`, returning the result.
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

/// Intended for ciphers which encrypt for multiple recipients.
/// For this purpose, a method must be provided which generates the Content Encryption Key.
///
/// If these recipients each use different key types, you can use an enum to represent them.
pub trait MultipleEncryptCipher: CoseEncryptCipher {
    /// Randomly generates a new Content Encryption Key (CEK) using the given `rng`.
    /// The content of the `CoseEncrypt` will then be encrypted with the key, while each recipient
    /// will be encrypted with a corresponding Key Encryption Key (KEK) provided by the caller
    /// of [`encrypt_access_token_multiple`].
    fn generate_cek<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self::EncryptKey;
}

/// Provides basic operations for signing and verifying COSE structures.
///
/// This will be used by [`sign_access_token`] and [`verify_access_token`] (as well as the
/// equivalents for multiple recipients: [`sign_access_token_multiple`] and
/// [`verify_access_token_multiple`]) to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// The [`set_headers` method](CoseSignCipher::set_headers) can be used to set parameters
/// this cipher requires to be set.
pub trait CoseSignCipher {
    /// Type of the key used to create signatures.
    type SignKey: ToCoseKey;

    /// Type of the key used to verify signatures.
    type VerifyKey: ToCoseKey;

    /// Cryptographically signs the `target` value with the `key` and returns the signature.
    fn sign(
        key: &Self::SignKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8>;

    /// Verifies the `signature` of the `signed_data` with the `key`.
    ///
    /// Note that, for single recipients (i.e., `CoseSign1`),
    /// `unprotected_signature_header` and `protected_signature_header` will be `None`.
    /// For multiple recipients (i.e., `CoseSign`), `unprotected_signature_header` and
    /// `protected_signature_header` will be the headers of the individual signature for this
    /// recipient, whereas `unprotected_header` and `protected_header` will be the headers
    /// of the `CoseSign` structure as a whole.
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

/// Marker trait intended for ciphers which create signatures for multiple recipients.
///
/// If these recipients each use different key types, you can use an enum to represent them.
pub trait MultipleSignCipher: CoseSignCipher {}

/// Provides basic operations for generating and verifying MAC tags for COSE structures.
///
/// This trait is currently not used by any access token function.
pub trait CoseMacCipher {
    /// Type of the key used to compute MAC tags.
    type ComputeKey: ToCoseKey;

    /// Type of the key used to verify MAC tags.
    type VerifyKey: ToCoseKey;

    /// Generates a MAC tag for the given `target` with the given `key` and returns it.
    fn compute(
        key: &Self::ComputeKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8>;

    /// Verifies the `tag` of the `maced_data` with the `key`.
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

/// Marker trait intended for ciphers which create MAC tags for multiple recipients.
///
/// If these recipients each use different key types, you can use an enum to represent them.
pub trait MultipleMacCipher: CoseMacCipher {}

/// Creates new headers if `unprotected_header` or `protected_header` is `None`, respectively,
/// and passes them to the `cipher`'s `header` function, returning the mutated result.
/// Arguments: key (expr), unprotected (ident), protected (ident), rng (expr), cipher (type)
macro_rules! prepare_headers {
    ($key:expr, $unprotected:ident, $protected:ident, $rng:expr, $t:ty) => {{
        let mut unprotected = $unprotected.unwrap_or_else(|| HeaderBuilder::new().build());
        let mut protected = $protected.unwrap_or_else(|| HeaderBuilder::new().build());
        <$t>::set_headers($key, &mut unprotected, &mut protected, $rng)?;
        Ok::<(Header, Header), CoseCipherError<<$t>::Error>>((unprotected, protected))
    }};
}

/// Encrypts the given `claims` with the given headers and `external_aad` using the
/// `key` and the cipher given by type parameter `T`, returning the token as a serialized
/// bytestring of the [`CoseEncrypt0`] structure.
///
/// Note that this method will create a token intended for a single recipient.
/// If you wish to create a token for more than one recipient, use
/// [`encrypt_access_token_multiple`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt0`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`CoseEncryptCipher`] in `FakeCrypto`, a random number generator
/// in `rng`, a [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey)
/// in `key` and want to associate this key with the access token we are about to create and encrypt:
/// ```ignore
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.to_cose_key().to_cbor_value()?)
///    .build();
/// let token: ByteString = encrypt_access_token::<FakeCrypto, FakeRng>(&key, claims.clone(), None, None, None, rng)?;
/// assert_eq!(decrypt_access_token::<FakeCrypto>(&key, &token, None)?, claims);
/// ```
pub fn encrypt_access_token<T, RNG>(
    key: &T::EncryptKey,
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
        prepare_headers!(key, unprotected_header, protected_header, &mut rng, T)?;
    CoseEncrypt0Builder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .create_ciphertext(
            &claims.to_vec()?[..],
            external_aad.unwrap_or(&[0; 0]),
            |payload, aad| T::encrypt(key, payload, aad, &unprotected, &protected),
        )
        .build()
        .to_vec()
        .map_err(AccessTokenError::from)
}

/// Encrypts the given `claims` with the given headers and `external_aad` for each recipient
/// by using the `keys` with the cipher given by type parameter `T`,
/// returning the token as a serialized bytestring of the [`CoseEncrypt`] structure.
///
/// Note that the given `keys` must each have an associated `kid` (key ID) field when converted
/// to COSE keys, as the recipients inside the [`CoseEncrypt`] are identified in this way.
///
/// The Content Encryption Key (used to encrypt the actual claims) is randomly generated by the
/// given cipher in `T`, whereas the given `keys` are used as Key Encryption Keys, that is,
/// they encrypt the Content Encryption Key for each recipient.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`MultipleEncryptCipher`] in `FakeCrypto`, a random number
/// generator in `rng`, and some `claims`, we can then create a token encrypted for two recipients
/// (with keys `key1` and `key2`, respectively) as follows:
/// ```ignore
/// let encrypted = encrypt_access_token_multiple::<FakeCrypto, FakeRng>(
///    vec![&key1, &key2], claims.clone(), None, None, None rng
/// )?;
/// ```
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
    let (unprotected, protected) =
        prepare_headers!(&key, unprotected_header, protected_header, &mut rng, T)?;
    let mut builder = CoseEncryptBuilder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .create_ciphertext(
            &claims.to_vec()?[..],
            external_aad.unwrap_or(&[0; 0]),
            |payload, aad| T::encrypt(&key, payload, aad, &protected, &unprotected),
        );
    let serialized_key: Vec<u8> = key.into();
    for rec_key in keys {
        let (rec_unprotected, rec_protected) = prepare_headers!(rec_key, None, None, &mut rng, T)?;
        builder = builder.add_recipient(
            CoseRecipientBuilder::new()
                .protected(rec_protected.clone())
                .unprotected(rec_unprotected.clone())
                .create_ciphertext(
                    // TODO: What should AAD be here?
                    EncryptionContext::EncRecipient,
                    &serialized_key,
                    &[0; 0],
                    |payload, aad| {
                        T::encrypt(rec_key, payload, aad, &rec_protected, &rec_unprotected)
                    },
                )
                .build(),
        );
    }
    builder.build().to_vec().map_err(AccessTokenError::from)
}

/// Signs the given `claims` with the given headers and `external_aad` using the `key` and the
/// cipher given by type parameter `T`, returning the token as a serialized bytestring of
/// the [`CoseSign1`] structure.
///
/// Note that this method will create a token intended for a single recipient.
/// If you wish to create a token for more than one recipient, use
/// [`sign_access_token_multiple`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign1`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`CoseSignCipher`] in `FakeCrypto`, a random number generator
/// in `rng`, a [`ProofOfPossessionKey`](crate::common::cbor_values::ProofOfPossessionKey)
/// in `key` and want to associate this key with the access token we are about to create and sign:
/// ```ignore
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.to_cose_key().to_cbor_value()?)
///    .build();
/// let token: ByteString = sign_access_token::<FakeCrypto, FakeRng>(&key, claims, None, None, None, rng)?;
/// assert!(verify_access_token::<FakeCrypto>(&key, &token, None).is_ok());
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
        .payload(claims.to_vec()?)
        .create_signature(external_aad.unwrap_or(&[0; 0]), |x| {
            T::sign(key, x, &unprotected, &protected)
        })
        .build()
        .to_vec()
        .map_err(AccessTokenError::from)
}

/// Signs the given `claims` with the given headers and `external_aad` for each recipient
/// by using the `keys` with the cipher given by type parameter `T`,
/// returning the token as a serialized bytestring of the [`CoseSign`] structure.
///
/// For each key in `keys`, another signature will be added, created with that respective key.
/// The given headers will be used for the [`CoseSign`] structure as a whole, not for each
/// individual signature.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign`] structure.
/// - When the given headers conflict with the headers set by the cipher `T`.
///
/// # Example
/// For example, assuming we have a [`MultipleSignCipher`] in `FakeCrypto`,
/// a random number generator in `rng`, and some `claims`, we can then create a token
/// with signatures for two recipients (with keys `key1` and `key2`, respectively) as follows:
/// ```ignore
/// let signed = sign_access_token_multiple::<FakeCrypto, FakeRng>(
///     vec![&key1, &key2],
///     claims,
///     None, None, None,
///     rng
/// )?;
/// ```
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
    let (unprotected, protected) = (
        unprotected_header.unwrap_or_else(|| HeaderBuilder::default().build()),
        protected_header.unwrap_or_else(|| HeaderBuilder::default().build()),
    );
    let mut builder = CoseSignBuilder::new()
        .unprotected(unprotected.clone())
        .protected(protected.clone())
        .payload(claims.to_vec().map_err(AccessTokenError::from)?);

    for key in keys {
        let (rec_unprotected, rec_protected) = prepare_headers!(key, None, None, &mut rng, T)?;
        let signature = CoseSignatureBuilder::new()
            .unprotected(rec_unprotected.clone())
            .protected(rec_protected.clone())
            .build();
        builder = builder.add_created_signature(signature, external_aad.unwrap_or(&[0; 0]), |x| {
            T::sign(key, x, &unprotected, &protected)
        });
    }

    builder.build().to_vec().map_err(AccessTokenError::from)
}

/// Returns the headers of the given signed ([`CoseSign1`] / [`CoseSign`]),
/// MAC tagged (`CoseMac0` / `CoseMac`), or encrypted ([`CoseEncrypt0`] / [`CoseEncrypt`])
/// access token.
///
/// When the given `token` is none of those structures mentioned above, `None` is returned.
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

/// Verifies the given `token` and `external_aad` with the `key` using the cipher
/// given by type parameter `T`, returning an error in case it could not be verified.
///
/// This method should be used when the given `token` is a [`CoseSign1`] rather than
/// [`CoseSign`] (i.e., if it is intended for a single recipient). In case the token is an
/// instance of the latter, use [`verify_access_token_multiple`] instead.
///
/// NOTE: Protected headers are not verified as of now.
///
/// For an example, see the documentation of [`sign_access_token`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing the given `token`
///   to a [`CoseSign1`] structure
///   (e.g., if it's not in fact a [`CoseSign1`] structure but rather something else).
/// - When there's a verification error coming from the cipher `T`
///   (e.g., if the `token`'s data does not match its signature).
pub fn verify_access_token<T>(
    key: &T::VerifyKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    // TODO: Verify protected headers
    sign.verify_signature(external_aad.unwrap_or(&[0; 0]), |signature, signed_data| {
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
    .map_err(AccessTokenError::from)
}

/// Verifies the given `token` and `external_aad` with the `key` using the cipher
/// given by type parameter `T`, returning an error in case it could not be verified.
///
/// This method should be used when the given `token` is a [`CoseSign`] rather than
/// [`CoseSign1`] (i.e., if it is intended for a multiple recipients). In case the token is an
/// instance of the latter, use [`verify_access_token`] instead.
///
/// NOTE: Protected headers are not verified as of now.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing the given `token`
///   to a [`CoseSign`] structure
///   (e.g., if it's not in fact a [`CoseSign`] structure but rather something else).
/// - When there's a verification error coming from the cipher `T`
///   (e.g., if the `token`'s data does not match its signature).
pub fn verify_access_token_multiple<T>(
    key: &T::VerifyKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSignCipher,
{
    let sign = CoseSign::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    let kid = key.to_cose_key().key_id;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    let matching = sign
        .signatures
        .iter()
        .enumerate()
        .filter(|(_, s)| s.unprotected.key_id == kid || s.protected.header.key_id == kid)
        .map(|(i, _)| i);
    let mut matching_kid = false;
    // We iterate over each signature whose kid matches until it completes successfully.
    // TODO: However: https://www.rfc-editor.org/rfc/rfc9052.html#section-4.1-3
    for index in matching {
        matching_kid = true;
        // TODO: Verify protected headers
        if let Ok(()) = sign.verify_signature(
            index,
            external_aad.unwrap_or(&[0; 0]),
            |signature, signed_data| {
                T::verify(
                    key,
                    signature,
                    signed_data,
                    &unprotected,
                    &protected,
                    Some(&sign.signatures[index].unprotected),
                    Some(&sign.signatures[index].protected),
                )
            },
        ) {
            return Ok(());
        }
    }
    if matching_kid {
        Err(AccessTokenError::from(CoseCipherError::VerificationFailure))
    } else {
        Err(AccessTokenError::NoMatchingRecipient)
    }
}

/// Decrypts the given `token` and `external_aad` using the `key` and the cipher
/// given by type parameter `T`, returning the decrypted [`ClaimsSet`].
///
/// This method should be used when the given `token` is a [`CoseEncrypt0`] rather than
/// [`CoseEncrypt`] (i.e., if it is intended for a single recipient). In case the token is an
/// instance of the latter, use [`decrypt_access_token_multiple`] instead.
///
/// For an example, see the documentation of [`encrypt_access_token`].
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing
///   the given `token` to a [`CoseEncrypt0`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt0`] structure but rather something else).
/// - When there's a decryption error coming from the cipher given by `T`.
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
    let encrypt = CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    // TODO: Verify protected header
    let result = encrypt.decrypt(external_aad.unwrap_or(&[0; 0]), |ciphertext, aad| {
        T::decrypt(key, ciphertext, aad, &unprotected, &protected)
    })?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
}

/// Decrypts the given `token` and `external_aad` using the Key Encryption Key `kek` and the cipher given
/// by type parameter `T`, returning the decrypted [`ClaimsSet`].
///
/// Note that the given `kek` must have an associated `kid` (key ID) field when converted
/// to a COSE key, as the recipient inside the [`CoseEncrypt`] is identified in this way.
///
/// This method should be used when the given `token` is a [`CoseEncrypt`] rather than
/// [`CoseEncrypt0`] (i.e., if it is intended for multiple recipients). In case the token is an
/// instance of the latter, use [`decrypt_access_token`] instead.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while deserializing
///   the given `token` to a [`CoseEncrypt`] structure
///   (e.g., if it's not in fact a [`CoseEncrypt`] structure but rather something else).
/// - When there's a decryption error coming from the cipher given by `T`.
/// - When the deserialized and decrypted [`CoseEncrypt`] structure does not contain a valid
///   [`ClaimsSet`].
/// - When the [`CoseEncrypt`] contains either multiple matching recipients or none at all for
///   the given `kek`.
pub fn decrypt_access_token_multiple<K, C>(
    kek: &K::DecryptKey,
    token: &ByteString,
    external_aad: Option<&[u8]>,
) -> Result<ClaimsSet, AccessTokenError<MultipleCoseError<K::Error, C::Error>>>
where
    K: CoseEncryptCipher,
    C: CoseEncryptCipher,
{
    let encrypt = CoseEncrypt::from_slice(token.as_slice()).map_err(AccessTokenError::from)?;
    let (unprotected, protected) =
        get_token_headers(token).ok_or(AccessTokenError::UnknownCoseStructure)?;
    let aad = external_aad.unwrap_or(&[0; 0]);
    let cose_kek: CoseKey = kek.to_cose_key();
    let kek_id = cose_kek.key_id.as_slice();
    // One of the recipient structures should contain CEK encrypted with our KEK.
    let recipients = encrypt
        .recipients
        .iter()
        .filter(|x| x.unprotected.key_id == kek_id || x.protected.header.key_id == kek_id);
    let mut content_keys = recipients.map(|r| {
        r.decrypt(
            EncryptionContext::EncRecipient,
            &[0; 0],
            |ciphertext, aad| K::decrypt(kek, ciphertext, aad, &r.unprotected, &r.protected),
        )
    });
    // Our CEK must be contained exactly once.
    if let Some(content_key_result) = content_keys.next() {
        if content_keys.next().is_none() {
            let content_key = content_key_result.map_err(CoseCipherError::from_kek_error)?;
            let target_key = C::DecryptKey::try_from(content_key)
                .map_err(|_| CoseCipherError::DecryptionFailure)?;
            // TODO: Verify protected header
            let result = encrypt
                .decrypt(aad, |ciphertext, aad| {
                    C::decrypt(&target_key, ciphertext, aad, &unprotected, &protected)
                })
                .map_err(CoseCipherError::from_cek_error)?;
            ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from)
        } else {
            // TODO: Implement strict mode, where this is prohibited, otherwise allow it
            Err(AccessTokenError::MultipleMatchingRecipients)
        }
    } else {
        Err(AccessTokenError::NoMatchingRecipient)
    }
}
