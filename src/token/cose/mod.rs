use core::fmt::{Debug, Display};

pub mod crypto_impl;
pub mod encrypt;
pub mod header_util;
pub mod key;
pub mod sign;

pub mod mac;
pub mod recipient;
#[cfg(test)]
mod test_helper;

pub trait CoseCipher {
    /// Error type that this cipher uses in [`Result`]s returned by cryptographic operations.
    type Error: Display + Debug;
}
