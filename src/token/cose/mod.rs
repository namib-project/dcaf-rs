use core::fmt::{Debug, Display};

use crate::error::CoseCipherError;

pub mod crypto_impl;
pub mod encrypted;
pub mod header_util;
pub mod key;
pub mod signed;

pub mod maced;
pub mod recipient;
#[cfg(all(test, feature = "std"))]
pub(crate) mod test_helper;

pub trait CoseCipher {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;

    /// Fill the given buffer with random bytes.
    ///
    /// Mainly used for IV or key generation.
    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>>;
}
