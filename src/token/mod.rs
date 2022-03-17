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
//! use coset::cwt::{ClaimsSetBuilder, Timestamp};
//! # use coset::iana::{Algorithm, CwtClaimName};
//! # use dcaf::{AsCborMap, CoseCipherCommon, CoseSign1Cipher, sign_access_token, verify_access_token};
//! use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
//! use dcaf::common::cbor_values::ProofOfPossessionKey::PlainCoseKey;
//! # use dcaf::error::{AccessTokenError, CoseCipherError};
//! # struct FakeCrypto {}
//! #
//! # impl CoseCipherCommon for FakeCrypto {
//! #     type Error = String;
//! #
//! #     fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
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
//! let key = ProofOfPossessionKey::KeyId(ByteString::from(vec![0xDC, 0xAF]));
//! let claims = ClaimsSetBuilder::new()
//!      .audience(String::from("coaps://rs.example.com"))
//!      .issuer(String::from("coaps://as.example.com"))
//!      .claim(CwtClaimName::Cnf, key.as_ciborium_value())
//!      .build();
//! let token = sign_access_token(claims, &mut cipher, None, None, None)?;
//! assert!(verify_access_token(&token, &mut cipher, None).is_ok());
//! # Ok::<(), AccessTokenError<String>>(())
//! ```

use crate::common::cbor_values::ByteString;
use core::fmt::{Debug, Display};
use coset::cwt::ClaimsSet;
use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseMac0, CoseSign1, CoseSign1Builder,
    Header, HeaderBuilder, ProtectedHeader,
};

use crate::error::{AccessTokenError, CoseCipherError};

#[cfg(test)]
mod tests;

/// Provides common operations necessary for other COSE cipher types to function.
///
/// This needs to be implemented if [`CoseEncrypt0Cipher`], [`CoseSign1Cipher`], or
/// [`CoseMac0Cipher`] is to be implemented as well.
///
/// See the documentation of [`header`](CoseCipherCommon::header) for an example.
pub trait CoseCipherCommon {
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
    /// fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
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
    fn header(
        &self,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Provides basic operations for encrypting and decrypting COSE structures.
///
/// This will be used by [`encrypt_access_token`] and [`decrypt_access_token`] to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// Since [`CoseCipherCommon`] also needs to be implemented, the
/// [`headers` method](CoseCipherCommon::headers) can be used to set parameters this cipher requires
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
/// # use dcaf::{CoseCipherCommon, CoseEncrypt0Cipher};
/// # use dcaf::error::CoseCipherError;
/// # struct FakeCrypto {};
/// # impl CoseCipherCommon for FakeCrypto {
/// #     type Error = String;
/// #     fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        unimplemented!()
/// #     }
/// # }
/// impl CoseEncrypt0Cipher for FakeCrypto {
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
pub trait CoseEncrypt0Cipher: CoseCipherCommon {
    /// Encrypts the given `plaintext` and `aad`, returning the result.
    ///
    /// For an example, view the documentation of [`CoseEncrypt0Cipher`].
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;

    /// Decrypts the given `ciphertext` and `aad`, returning the result.
    ///
    /// For an example, view the documentation of [`CoseEncrypt0Cipher`].
    ///
    /// # Errors
    /// If the `ciphertext` and `aad` are invalid, i.e., can't be decrypted.
    fn decrypt(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

/// Provides basic operations for signing and verifying COSE structures.
///
/// This will be used by [`sign_access_token`] and [`verify_access_token`] to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// Since [`CoseCipherCommon`] also needs to be implemented, the
/// [`headers` method](CoseCipherCommon::headers) can be used to set parameters this cipher requires
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
/// #     fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
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
pub trait CoseSign1Cipher: CoseCipherCommon {
    /// Cryptographically signs the given `target` value and returns the signature.
    ///
    /// For an example, see the documentation of [`CoseSign1Cipher`].
    fn generate_signature(&mut self, target: &[u8]) -> Vec<u8>;

    /// Verifies the `signature` of the `signed_data`.
    ///
    /// For an example, see the documentation of [`CoseSign1Cipher`].
    ///
    /// # Errors
    /// If the `signature` is invalid or does not belong to the `signed_data`.
    fn verify_signature(
        &mut self,
        signature: &[u8],
        signed_data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Provides basic operations for generating and verifying MAC tags for COSE structures.
///
/// This trait is currently not used by any access token function.
///
/// # Example
/// For example, to simply implement the signing operation as the identity function
/// (which you **clearly should not do**, this is just for illustrative purposes):
/// ```
/// # use coset::Header;
/// # use dcaf::{CoseCipherCommon, CoseMac0Cipher, CoseSign1Cipher};
/// # use dcaf::error::CoseCipherError;
/// # struct FakeTagger {};
/// # impl CoseCipherCommon for FakeTagger {
/// #     type Error = String;
/// #     fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        unimplemented!()
/// #     }
/// # }
/// impl CoseMac0Cipher for FakeTagger {
///    fn generate_tag(&mut self, target: &[u8]) -> Vec<u8> {
///        target.to_vec()
///    }
///
///    fn verify_tag(&mut self, tag: &[u8], signed_data: &[u8]) -> Result<(), CoseCipherError<Self::Error>> {
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
pub trait CoseMac0Cipher: CoseCipherCommon {

    /// Generates a MAC tag for the given `target` and returns it.
    ///
    /// For an example, see the documentation of [`CoseMac0Cipher`].
    fn generate_tag(&mut self, target: &[u8]) -> Vec<u8>;

    /// Verifies the `tag` of the `maced_data`.
    ///
    /// For an example, see the documentation of [`CoseMac0Cipher`].
    ///
    /// # Errors
    /// If the `tag` is invalid or does not belong to the `maced_data`.
    fn verify_tag(
        &mut self,
        tag: &[u8],
        maced_data: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Creates new headers if `unprotected_header` or `protected_header` is `None`, respectively,
/// and passes them to the `cipher`'s `header` function, returning the mutated result.
fn prepare_headers<T>(
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
    cipher: &T,
) -> Result<(Header, Header), AccessTokenError<T::Error>>
where
    T: CoseCipherCommon,
{
    let mut unprotected = unprotected_header.unwrap_or_else(|| HeaderBuilder::new().build());
    let mut protected = protected_header.unwrap_or_else(|| HeaderBuilder::new().build());
    cipher
        .header(&mut unprotected, &mut protected)
        .map_err(AccessTokenError::from_cose_cipher_error)?;
    Ok((unprotected, protected))
}

/// Encrypts the given `claims` with the given headers and `aad` using `cipher` for cryptography,
/// returning the token as a serialized bytestring of the [`CoseEncrypt0`] structure.
///
/// If you need to encode additional fields other than `claims`, use the [`CoseEncrypt0Cipher`] given in
/// `cipher` to store and encrypt them.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseEncrypt0`] structure.
///
/// # Example
/// For example, assuming we have a [`CoseEncrypt0Cipher`] in `cipher`,
/// have a [`ProofOfPossessionKey`] in `key` and want to associate
/// this key with the access token we are about to create and encrypt:
/// ```
/// # use coset::cwt::ClaimsSetBuilder;
/// # use coset::Header;
/// # use coset::iana::CwtClaimName;
/// # use dcaf::{AsCborMap, CoseCipherCommon, CoseEncrypt0Cipher, decrypt_access_token, encrypt_access_token, sign_access_token, verify_access_token};
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::error::{AccessTokenError, CoseCipherError};
/// # struct FakeCrypto {};
/// # impl CoseCipherCommon for FakeCrypto {
/// #     type Error = String;
/// #     fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
/// #        Ok(())
/// #     }
/// # }
/// # impl CoseEncrypt0Cipher for FakeCrypto {
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
/// # let key = ProofOfPossessionKey::KeyId(ByteString::from(vec![0xDC, 0xAF]));
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.as_ciborium_value())
///    .build();
/// let token: ByteString = encrypt_access_token(claims.clone(), &mut cipher, None, None, None)?;
/// assert_eq!(decrypt_access_token(&token, &mut cipher, None)?, claims);
/// # Ok::<(), AccessTokenError<String>>(())
/// ```
pub fn encrypt_access_token<T>(
    claims: ClaimsSet,
    cipher: &mut T,
    aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseEncrypt0Cipher,
{
    let (unprotected, protected) = prepare_headers(unprotected_header, protected_header, cipher)?;
    Ok(ByteString::from(
        CoseEncrypt0Builder::new()
            .unprotected(unprotected)
            .protected(protected)
            .create_ciphertext(
                &claims.to_vec().map_err(AccessTokenError::from_cose_error)?[..],
                aad.unwrap_or(&[0; 0]),
                |payload, aad| cipher.encrypt(payload, aad),
            )
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
}

/// Signs the given `claims` with the given headers and `aad` using `cipher` for cryptography,
/// returning the token as a serialized bytestring of the [`CoseSign1`] structure.
///
/// If you need to encode additional fields other than `claims`, use the [`CoseSign1Cipher`] given
/// in `cipher` to store and sign them.
///
/// # Errors
/// - When there's a [`CoseError`](coset::CoseError) while serializing the given `claims` to CBOR.
/// - When there's a [`CoseError`](coset::CoseError) while serializing the [`CoseSign1`] structure.
///
/// # Example
/// For example, assuming we have a [`CoseEncrypt0Cipher`] in `cipher`,
/// have a [`ProofOfPossessionKey`] in `key` and want to associate
/// this key with the access token we are about to create and sign:
/// ```
/// # use coset::cwt::ClaimsSetBuilder;
/// # use coset::Header;
/// # use coset::iana::CwtClaimName;
/// # use dcaf::{AsCborMap, CoseCipherCommon, CoseSign1Cipher, encrypt_access_token, sign_access_token, verify_access_token};
/// # use dcaf::common::cbor_values::{ByteString, ProofOfPossessionKey};
/// # use dcaf::error::{AccessTokenError, CoseCipherError};
/// # struct FakeSigner {};
/// # impl CoseCipherCommon for FakeSigner {
/// #     type Error = String;
/// #     fn header(&self, unprotected_header: &mut Header, protected_header: &mut Header) -> Result<(), CoseCipherError<Self::Error>> {
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
/// # let key = ProofOfPossessionKey::KeyId(ByteString::from(vec![0xDC, 0xAF]));
/// let claims = ClaimsSetBuilder::new()
///    .audience(String::from("coaps://rs.example.com"))
///    .issuer(String::from("coaps://as.example.com"))
///    .claim(CwtClaimName::Cnf, key.as_ciborium_value())
///    .build();
/// let token: ByteString = sign_access_token(claims, &mut cipher, None, None, None)?;
/// assert!(verify_access_token(&token, &mut cipher, None).is_ok());
/// # Ok::<(), AccessTokenError<String>>(())
/// ```
pub fn sign_access_token<T>(
    claims: ClaimsSet,
    cipher: &mut T,
    aad: Option<&[u8]>,
    unprotected_header: Option<Header>,
    protected_header: Option<Header>,
) -> Result<ByteString, AccessTokenError<T::Error>>
where
    T: CoseSign1Cipher,
{
    let (unprotected, protected) = prepare_headers(unprotected_header, protected_header, cipher)?;
    Ok(ByteString::from(
        CoseSign1Builder::new()
            .unprotected(unprotected)
            .protected(protected)
            .payload(claims.to_vec().map_err(AccessTokenError::from_cose_error)?)
            .create_signature(aad.unwrap_or(&[0; 0]), |x| cipher.generate_signature(x))
            .build()
            .to_vec()
            .map_err(AccessTokenError::from_cose_error)?,
    ))
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
/// # let token = ByteString::from(vec![
/// # 0x84, 0x4b, 0xa2, 0x1, 0x25, 0x4, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0xa2, 0x5, 0x4d,
/// # 0x63, 0x68, 0x98, 0x99, 0x4f, 0xf0, 0xec, 0x7b, 0xfc, 0xf6, 0xd3, 0xf9, 0x5b, 0x18, 0x2f, 0xf6,
/// # 0x58, 0x20, 0xa1, 0x8, 0xa3, 0x1, 0x4, 0x2, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x20,
/// # 0x51, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
/// # 0x71, 0x8, 0x58, 0x40, 0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
/// # 0x4b, 0xa2, 0x1, 0x25, 0x4, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x45, 0x1, 0x2, 0x3, 0x4,
/// # 0x5, 0x58, 0x20, 0xa1, 0x8, 0xa3, 0x1, 0x4, 0x2, 0x46, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x20,
/// # 0x51, 0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
/// # 0x71, 0x8]);
/// if let Some((unprotected_header, protected_header)) = get_token_headers(&token) {
///   assert_eq!(protected_header.header.key_id, vec![0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c])
/// } else {
///   unreachable!("Example token should be valid.")
/// }
/// ```
pub fn get_token_headers(token: &ByteString) -> Option<(Header, ProtectedHeader)> {
    CoseSign1::from_slice(token.as_slice())
        .map(|x| (x.unprotected, x.protected))
        .or_else(|_| {
            CoseEncrypt0::from_slice(token.as_slice()).map(|x| (x.unprotected, x.protected))
        })
        .or_else(|_| CoseMac0::from_slice(token.as_slice()).map(|x| (x.unprotected, x.protected)))
        .ok()
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
    token: &ByteString,
    verifier: &mut T,
    aad: Option<&[u8]>,
) -> Result<(), AccessTokenError<T::Error>>
where
    T: CoseSign1Cipher,
{
    let sign = CoseSign1::from_slice(token.as_slice()).map_err(AccessTokenError::CoseError)?;
    // TODO: Verify protected headers
    sign.verify_signature(aad.unwrap_or(&[0; 0]), |signature, signed_data| {
        verifier.verify_signature(signature, signed_data)
    })
    .map_err(AccessTokenError::from_cose_cipher_error)
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
    token: &ByteString,
    cipher: &mut T,
    aad: Option<&[u8]>,
) -> Result<ClaimsSet, AccessTokenError<T::Error>>
where
    T: CoseEncrypt0Cipher,
{
    let encrypt =
        CoseEncrypt0::from_slice(token.as_slice()).map_err(AccessTokenError::from_cose_error)?;
    let result = encrypt
        .decrypt(aad.unwrap_or(&[0; 0]), |ciphertext, aad| {
            cipher.decrypt(ciphertext, aad)
        })
        .map_err(AccessTokenError::from_cose_cipher_error)?;
    ClaimsSet::from_slice(result.as_slice()).map_err(AccessTokenError::from_cose_error)
}
