use crate::token::cose::determine_header_param;
use alloc::collections::BTreeMap;
use coset::{EncryptionContext, Header};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A trait for types that can determine the corresponding Additional Authenticated Data to be
/// provided for a given COSE structure.
pub trait AadProvider: Sized {
    /// Look up the additional authenticated data for the given COSE structure.
    ///
    /// # Parameters
    ///
    /// - `context`     - Type of object that should be encrypted with AAD.
    ///                   If the AAD should be provided for a non-encrypted object, `context` is
    ///                   `None`.
    /// - `protected`   - Protected headers for the COSE structure for which AAD should be provided.
    /// - `unprotected` - Unprotected headers for the COSE structure for which AAD should be
    ///                   provided.
    fn lookup_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]>;

    /// Lookup up the additional authenticated data for nested COSE structures nested inside the
    /// one whose decryption was actually requested.
    ///
    /// For the provided implementations, this will usually return an empty slice.
    /// If you want to provide AAD for nested structures, either use a tuple
    /// `(CoseAadProvider, CoseAadProvider)` or provide a tuple `(CoseAadProvider, bool)`.
    ///
    /// In the first case, the second arguments' [`AadProvider::lookup_aad`]
    /// will be used as [`AadProvider::lookup_nested_aad`] if its
    /// [`AadProvider::lookup_nested_aad`] returns `None`.
    ///
    /// In the latter case, the boolean argument specifies whether [`AadProvider::lookup_aad`]
    /// should be used as a fallback if [`AadProvider::lookup_nested_aad`] returns `None`.
    ///
    /// # Parameters
    ///
    /// - `context`     - Type of object that should be encrypted with AAD.
    ///                   If the AAD should be provided for a non-encrypted object, `context` is
    ///                   `None`.
    /// - `protected`   - Protected headers for the COSE structure for which AAD should be provided.
    /// - `unprotected` - Unprotected headers for the COSE structure for which AAD should be
    ///                   provided.
    #[allow(unused)]
    fn lookup_nested_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        None
    }
}

impl AadProvider for Vec<u8> {
    fn lookup_aad(
        &self,
        _context: Option<EncryptionContext>,
        _protected: Option<&Header>,
        _unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        Some(self.as_ref())
    }
}

impl AadProvider for &[u8] {
    fn lookup_aad(
        &self,
        _context: Option<EncryptionContext>,
        _protected: Option<&Header>,
        _unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        Some(self)
    }
}

impl AadProvider for Option<&[u8]> {
    fn lookup_aad(
        &self,
        _context: Option<EncryptionContext>,
        _protected: Option<&Header>,
        _unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        *self
    }
}

/// Look up additional authenticated data based on the key ID
#[cfg(feature = "std")]
impl<AAD: AsRef<[u8]>, S: core::hash::BuildHasher> AadProvider
    for std::collections::HashMap<&[u8], AAD, S>
{
    fn lookup_aad(
        &self,
        _context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        determine_header_param(protected, unprotected, |v| {
            if v.key_id.is_empty() {
                None
            } else {
                Some(v.key_id.clone())
            }
        })
        .and_then(|kid| self.get(kid.as_slice()))
        .map(AsRef::as_ref)
    }
}

/// Look up additional authenticated data based on the key ID
impl<AAD: AsRef<[u8]>> AadProvider for BTreeMap<&[u8], AAD> {
    fn lookup_aad(
        &self,
        _context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        determine_header_param(protected, unprotected, |v| {
            if v.key_id.is_empty() {
                None
            } else {
                Some(v.key_id.clone())
            }
        })
        .and_then(|kid| self.get(kid.as_slice()))
        .map(AsRef::as_ref)
    }
}

/// Look up additional authenticated data based on the key ID
impl<KID: AsRef<[u8]>, AAD: AsRef<[u8]>> AadProvider for Vec<(KID, AAD)> {
    fn lookup_aad(
        &self,
        _context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        let kid = determine_header_param(protected, unprotected, |v| {
            if v.key_id.is_empty() {
                None
            } else {
                Some(v.key_id.clone())
            }
        });
        if let Some(kid) = kid {
            self.iter().find_map(|(key_kid, aad)| {
                if key_kid.as_ref().eq(kid.as_slice()) {
                    Some(aad.as_ref())
                } else {
                    None
                }
            })
        } else {
            None
        }
    }
}

/// Use T's `lookup_aad` for the normal AAD lookup, use U's `lookup_nested_aad` and `lookup_aad` for
/// nested AAD lookups (`lookup_nested_aad` takes precedence, though).
impl<T: AadProvider, U: AadProvider> AadProvider for (T, U) {
    fn lookup_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        self.0.lookup_aad(context, protected, unprotected)
    }

    fn lookup_nested_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        self.1
            .lookup_nested_aad(context, protected, unprotected)
            .or_else(|| self.1.lookup_aad(context, protected, unprotected))
    }
}

/// Swap lookup_aad and lookup_nested_aad of an existing [`AadProvider`] .
pub struct InvertedAadProvider<T: AadProvider>(pub T);

impl<T: AadProvider> AadProvider for InvertedAadProvider<T> {
    fn lookup_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        self.0.lookup_nested_aad(context, protected, unprotected)
    }

    fn lookup_nested_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        self.0.lookup_aad(context, protected, unprotected)
    }
}

impl<T: AadProvider> AadProvider for &T {
    fn lookup_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        (*self).lookup_aad(context, protected, unprotected)
    }
    fn lookup_nested_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        (*self).lookup_nested_aad(context, protected, unprotected)
    }
}

/// Use [`AadProvider::lookup_aad`] as a fallback for [`AadProvider::lookup_nested_aad`]  if the
/// boolean is `true` and [`AadProvider::lookup_nested_aad`]  returns None.
impl<T: AadProvider> AadProvider for (T, bool) {
    fn lookup_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        self.0.lookup_aad(context, protected, unprotected)
    }

    fn lookup_nested_aad(
        &self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> Option<&[u8]> {
        self.0
            .lookup_nested_aad(context, protected, unprotected)
            .or(self
                .1
                .then(|| self.0.lookup_aad(context, protected, unprotected))
                .flatten())
    }
}
