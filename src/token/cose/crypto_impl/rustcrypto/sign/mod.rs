use coset::iana;
use rand::{CryptoRng, RngCore};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::CoseEc2Key;
use crate::token::SignCryptoBackend;

#[cfg(feature = "rustcrypto-ecdsa")]
mod ecdsa;

impl<RNG: RngCore + CryptoRng> SignCryptoBackend for RustCryptoContext<RNG> {
    #[cfg(feature = "rustcrypto-ecdsa")]
    fn sign_ecdsa(
        &mut self,
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        Self::sign_ecdsa(algorithm, key, payload)
    }

    #[cfg(feature = "rustcrypto-ecdsa")]
    fn verify_ecdsa(
        &mut self,
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        sig: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        Self::verify_ecdsa(algorithm, key, sig, payload)
    }
}
