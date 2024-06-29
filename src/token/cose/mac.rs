/*/// Provides basic operations for generating and verifying MAC tags for COSE structures.
///
/// This trait is currently not used by any access token function.
pub trait CoseMacCipher {
    /// Generates a MAC tag for the given `target` with the given `key` and returns it.
    fn compute(
        key: &CoseKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Vec<u8>;

    /// Verifies the `tag` of the `maced_data` with the `key`.
    ///
    /// # Errors
    /// If the `tag` is invalid or does not belong to the `maced_data`.
    fn verify(
        key: &CoseKey,
        tag: &[u8],
        maced_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
    ) -> Result<(), CoseCipherError<Self::Error>>;
}

/// Marker trait intended for ciphers which can create MAC tags for multiple recipients.
///
/// If these recipients each use different key types, you can use an enum to represent them.
pub trait MultipleMacCipher: CoseMacCipher {}
*/
