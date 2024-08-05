use coset::iana;
use rand::{CryptoRng, RngCore};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, KeyDistributionCryptoBackend};

#[cfg(feature = "rustcrypto-aes-kw")]
mod aes_key_wrap;

impl<RNG: RngCore + CryptoRng> KeyDistributionCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-aes-kw")]
    fn aes_key_wrap(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::aes_key_wrap(algorithm, &key, plaintext, iv)
    }

    #[cfg(feature = "rustcrypto-aes-kw")]
    fn aes_key_unwrap(
        &mut self,
        algorithm: iana::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::aes_key_unwrap(algorithm, &key, ciphertext, iv)
    }
}
