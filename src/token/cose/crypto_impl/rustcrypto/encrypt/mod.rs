use coset::iana;
use rand::{CryptoRng, RngCore};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, EncryptCryptoBackend};

#[cfg(feature = "rustcrypto-aes-gcm")]
mod aes_gcm;

impl<RNG: RngCore + CryptoRng> EncryptCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-aes-gcm")]
    fn encrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::encrypt_aes_gcm(algorithm, &key, plaintext, aad, iv)
    }

    #[cfg(feature = "rustcrypto-aes-gcm")]
    fn decrypt_aes_gcm(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::decrypt_aes_gcm(algorithm, &key, ciphertext_with_tag, aad, iv)
    }
}
