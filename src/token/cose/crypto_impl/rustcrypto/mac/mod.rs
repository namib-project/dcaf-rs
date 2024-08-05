use coset::iana::Algorithm;

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseSymmetricKey, MacCryptoBackend};
use rand::{CryptoRng, RngCore};

#[cfg(feature = "rustcrypto-hmac")]
mod hmac;

impl<RNG: RngCore + CryptoRng> MacCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-hmac")]
    fn compute_hmac(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::compute_hmac(algorithm, &key, payload)
    }

    #[cfg(feature = "rustcrypto-hmac")]
    fn verify_hmac(
        &mut self,
        algorithm: Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        tag: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::verify_hmac(algorithm, &key, tag, payload)
    }
}
