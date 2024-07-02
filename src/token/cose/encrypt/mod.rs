mod encrypt;
mod encrypt0;

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseEc2Key, CoseSymmetricKey};
use crate::CoseSignCipher;
use core::fmt::{Debug, Display};
use coset::{
    iana, Algorithm, CoseEncrypt, CoseEncrypt0, CoseEncrypt0Builder, CoseEncryptBuilder, Header,
    HeaderBuilder,
};

/// Provides basic operations for encrypting and decrypting COSE structures.
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

    /// Fill the given buffer with random bytes.
    ///
    /// Mainly used for IV generation if an IV is not provided by the application.
    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>>;

    fn encrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

pub trait CoseKeyDistributionCipher: CoseEncryptCipher {
    fn encrypt_aes_ecb(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;

    fn decrypt_aes_ecb(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>>;
}

pub trait HeaderBuilderExt: Sized {
    fn gen_iv<B: CoseEncryptCipher>(
        self,
        backend: &mut B,
        alg: &Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl HeaderBuilderExt for HeaderBuilder {
    fn gen_iv<B: CoseEncryptCipher>(
        self,
        backend: &mut B,
        alg: &Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let iv_size = match alg {
            // AES-GCM: Nonce is fixed at 96 bits
            Algorithm::Assigned(
                iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM,
            ) => 12,
            v => return Err(CoseCipherError::UnsupportedAlgorithm(v.clone())),
        };
        let mut iv = vec![0; iv_size];
        backend.generate_rand(&mut iv)?;
        Ok(self.iv(iv))
    }
}
/*
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
