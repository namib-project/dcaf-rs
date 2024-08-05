use aead::{Aead, AeadCore, Key, KeyInit, Nonce, Payload};
use aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use coset::{iana, Algorithm};
use rand::CryptoRng;
use rand::RngCore;
use typenum::consts::U12;

use crate::error::CoseCipherError;
use crate::token::cose::{CoseSymmetricKey, CryptoBackend};

use super::RustCryptoContext;

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Perform an AEAD encryption operation on `plaintext` and the additional authenticated
    /// data `aad` using the given `iv` and `key`.
    fn encrypt_aead<AEAD: Aead + AeadCore + KeyInit>(
        key: &CoseSymmetricKey<'_, <RustCryptoContext<RNG> as CryptoBackend>::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        let aes_key = Key::<AEAD>::from_slice(key.k);
        let cipher = AEAD::new(aes_key);
        let nonce = Nonce::<AEAD>::from_slice(iv);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(CoseCipherError::from)
    }

    /// Perform an AEAD decryption operation on `ciphertext` and the additional authenticated
    /// data `aad` using the given `iv` and `key`.
    fn decrypt_aead<AEAD: Aead + AeadCore + KeyInit>(
        key: &CoseSymmetricKey<'_, <RustCryptoContext<RNG> as CryptoBackend>::Error>,
        ciphertext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        let aes_key = Key::<AEAD>::from_slice(key.k);
        let cipher = AEAD::new(aes_key);
        let nonce = Nonce::<AEAD>::from_slice(iv);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(CoseCipherError::from)
    }

    /// Perform an AES-GCM encryption operation on `plaintext` and the additional authenticated
    /// data `aad` using the given `iv` and `key` with the given `algorithm` variant of AES-GCM.
    pub(super) fn encrypt_aes_gcm(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::A128GCM => Self::encrypt_aead::<Aes128Gcm>(key, plaintext, aad, iv),
            iana::Algorithm::A192GCM => {
                Self::encrypt_aead::<AesGcm<Aes192, U12>>(key, plaintext, aad, iv)
            }
            iana::Algorithm::A256GCM => Self::encrypt_aead::<Aes256Gcm>(key, plaintext, aad, iv),
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }

    /// Perform an AES-GCM decryption operation on `ciphertext` and the additional authenticated
    /// data `aad` using the given `iv` and `key` with the given `algorithm` variant of AES-GCM.
    pub(super) fn decrypt_aes_gcm(
        algorithm: iana::Algorithm,
        key: &CoseSymmetricKey<'_, <Self as CryptoBackend>::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::A128GCM => {
                Self::decrypt_aead::<Aes128Gcm>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::A192GCM => {
                Self::decrypt_aead::<AesGcm<Aes192, U12>>(key, ciphertext_with_tag, aad, iv)
            }
            iana::Algorithm::A256GCM => {
                Self::decrypt_aead::<Aes256Gcm>(key, ciphertext_with_tag, aad, iv)
            }
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }
}
