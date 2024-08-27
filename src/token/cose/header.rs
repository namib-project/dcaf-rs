use crate::error::CoseCipherError;
use crate::token::cose::util::symmetric_algorithm_iv_len;
use crate::token::cose::{CryptoBackend, EncryptCryptoBackend};
use coset::{iana, HeaderBuilder};

/// Extensions to the [`HeaderBuilder`] type that enable usage of cryptographic backends.
pub trait HeaderBuilderExt: Sized {
    /// Generate an initialization vector for the given `algorithm` using the given
    /// cryptographic `backend`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `algorithm` is unsupported/unknown or the cryptographic backend
    /// returns an error.
    fn gen_iv<B: EncryptCryptoBackend>(
        self,
        backend: &mut B,
        algorithm: iana::Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

impl HeaderBuilderExt for HeaderBuilder {
    fn gen_iv<B: CryptoBackend>(
        self,
        backend: &mut B,
        alg: iana::Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let iv_size = symmetric_algorithm_iv_len(alg)?;
        let mut iv = vec![0; iv_size];
        backend.generate_rand(&mut iv)?;
        Ok(self.iv(iv))
    }
}

/// A header parameter that can be used in a COSE header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderParam {
    /// Generic header parameter applicable to all algorithms.
    Generic(iana::HeaderParameter),
    /// Header parameter that is specific for a set of algorithms.
    Algorithm(iana::HeaderAlgorithmParameter),
}

impl From<iana::HeaderParameter> for HeaderParam {
    fn from(value: iana::HeaderParameter) -> Self {
        HeaderParam::Generic(value)
    }
}

impl From<iana::HeaderAlgorithmParameter> for HeaderParam {
    fn from(value: iana::HeaderAlgorithmParameter) -> Self {
        HeaderParam::Algorithm(value)
    }
}
