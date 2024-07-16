use core::fmt::{Debug, Display};

pub mod crypto_impl;
mod encrypted;
mod header_util;
mod key;
mod signed;

mod maced;
mod recipient;

pub use encrypted::*;
pub use header_util::*;
pub use key::*;
pub use maced::*;
pub use recipient::*;
pub use signed::*;

#[cfg(all(test, feature = "std"))]
pub(crate) mod test_helper;

pub trait CoseCipher {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;

    /// Fill the given buffer with random bytes.
    ///
    /// Mainly used for IV or key generation.
    ///
    /// # Errors
    ///
    /// Implementations may return errors if the generation of random bytes fails for any reason.
    /// If errors can occur, implementors should add the possible errors and the situations under
    /// which they occur to their documentation.
    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}
