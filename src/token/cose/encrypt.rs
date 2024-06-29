use crate::error::CoseCipherError;
use crate::CoseSignCipher;
use core::fmt::{Debug, Display};
use coset::{CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder, CoseEncryptBuilder};

/*/// Provides basic operations for encrypting and decrypting COSE structures.
///
/// This will be used by [`encrypt_access_token`] and [`decrypt_access_token`] (as well as the
/// variants for multiple recipients: [`encrypt_access_token_multiple`]
/// and [`decrypt_access_token_multiple`]) to apply the
/// corresponding cryptographic operations to the constructed token bytestring.
/// The [`set_headers` method](CoseCipher::set_headers) can be used to set parameters this
/// cipher requires to be set.
pub trait CoseEncryptCipher {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;

    /// Encrypts the `plaintext` and `aad` with the given `key`, returning the result.
    fn encrypt(
        key: &CoseKey,
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
        key: &CoseKey,
        ciphertext: &[u8],
        aad: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

/// Intended for ciphers which can encrypt for multiple recipients.
/// For this purpose, a method must be provided which generates the Content Encryption Key.
///
/// If these recipients each use different key types, you can use an enum to represent them.
pub trait MultipleEncryptCipher: CoseEncryptCipher {
    /// Randomly generates a new Content Encryption Key (CEK) using the given `rng`.
    /// The content of the `CoseEncrypt` will then be encrypted with the key, while each recipient
    /// will be encrypted with a corresponding Key Encryption Key (KEK) provided by the caller
    /// of [`encrypt_access_token_multiple`].
    fn generate_cek<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> CoseKey;
}

fn

pub trait CoseEncrypt0BuilderExt {}

impl CoseEncrypt0BuilderExt for CoseEncrypt0Builder {}

pub trait CoseEncrypt0Ext {
    fn try_decrypt<B: CoseEncryptCipher>(
        &self,
        backend: &mut B,
        external_aad: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>>;
}

impl CoseEncrypt0Ext for CoseEncrypt0 {
    fn try_decrypt<B: CoseEncryptCipher>(
        &self,
        backend: &mut B,
        external_aad: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    }
}

pub trait CoseEncryptBuilderExt {}

impl CoseEncryptBuilderExt for CoseEncryptBuilder {}

pub trait CoseEncryptExt {}

impl CoseEncryptExt for CoseEncrypt {}
*/
