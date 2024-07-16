use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt::Display;

use coset::iana::EnumI64;
use coset::{iana, Algorithm, CoseKey, Header, HeaderBuilder, KeyOperation, Label};

use crate::error::CoseCipherError;
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey};
use crate::token::cose::{CoseCipher, CoseEncryptCipher};

/// A header parameter that can be used in a COSE header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderParam {
    /// Generic header parmeter applicable to all algorithms.
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

fn create_header_parameter_set(header_bucket: &Header) -> BTreeSet<Label> {
    let mut header_bucket_fields = BTreeSet::new();

    if header_bucket.alg.is_some() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Alg.to_i64()));
    }
    if header_bucket.content_type.is_some() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::ContentType.to_i64()));
    }
    if !header_bucket.key_id.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Kid.to_i64()));
    }
    if !header_bucket.crit.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Crit.to_i64()));
    }
    if !header_bucket.counter_signatures.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::CounterSignature.to_i64()));
    }
    if !header_bucket.iv.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Iv.to_i64()));
    }
    if !header_bucket.partial_iv.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::PartialIv.to_i64()));
    }

    header_bucket_fields.extend(header_bucket.rest.iter().map(|(k, _v)| k.clone()));

    header_bucket_fields
}

pub(crate) fn check_for_duplicate_headers<E: Display>(
    protected_header: &Header,
    unprotected_header: &Header,
) -> Result<(), CoseCipherError<E>> {
    let unprotected_header_set = create_header_parameter_set(unprotected_header);
    let protected_header_set = create_header_parameter_set(protected_header);
    let duplicate_header_fields: Vec<&Label> = unprotected_header_set
        .intersection(&protected_header_set)
        .collect();
    if duplicate_header_fields.is_empty() {
        Ok(())
    } else {
        Err(CoseCipherError::DuplicateHeaders(
            duplicate_header_fields.into_iter().cloned().collect(),
        ))
    }
}

/// Determines the algorithm to use for the signing operation based on the supplied key and headers.
pub(crate) fn determine_algorithm<CE: Display>(
    parsed_key: Option<&CoseParsedKey<'_, CE>>,
    unprotected_header: Option<&Header>,
    protected_header: Option<&Header>,
) -> Result<iana::Algorithm, CoseCipherError<CE>> {
    // Check whether the algorithm has been explicitly set...
    let alg = if let Some(Some(alg)) = protected_header.map(|v| v.alg.clone()) {
        // ...in the protected header...
        Ok(alg)
    } else if let Some(Some(alg)) = unprotected_header.map(|v| v.alg.clone()) {
        // ...in the unprotected header...
        Ok(alg)
    } else if let Some(alg) = parsed_key.and_then(|v| v.as_ref().alg.clone()) {
        // ...or the key itself.
        Ok(alg)
    } else {
        Err(CoseCipherError::NoAlgorithmDeterminable)
    }?;

    if let Algorithm::Assigned(alg) = alg {
        Ok(alg)
    } else {
        Err(CoseCipherError::UnsupportedAlgorithm(alg))
    }
}

pub(crate) fn determine_key_candidates<'a, CKP: CoseKeyProvider>(
    key_provider: &'a mut CKP,
    protected: Option<&'a Header>,
    unprotected: Option<&'a Header>,
    operation: BTreeSet<KeyOperation>,
    try_all_keys: bool,
) -> Box<dyn Iterator<Item = CoseKey> + 'a> {
    let key_id = if try_all_keys {
        None
    } else {
        protected
            .map(|v| v.key_id.as_slice())
            .filter(|v| !v.is_empty())
            .or_else(|| unprotected.map(|v| v.key_id.as_slice()))
            .filter(|v| !v.is_empty())
    };

    Box::new(key_provider.lookup_key(key_id).filter(move |k| {
        k.key_ops.is_empty() || k.key_ops.intersection(&operation).next().is_some()
    }))
}

pub trait HeaderBuilderExt: Sized {
    fn gen_iv<B: CoseEncryptCipher>(
        self,
        backend: &mut B,
        alg: iana::Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

const AES_GCM_NONCE_SIZE: usize = 12;

impl HeaderBuilderExt for HeaderBuilder {
    fn gen_iv<B: CoseCipher>(
        self,
        backend: &mut B,
        alg: iana::Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>> {
        let iv_size = match alg {
            // AES-GCM: Nonce is fixed at 96 bits (RFC 9053, Section 4.1)
            iana::Algorithm::A128GCM | iana::Algorithm::A192GCM | iana::Algorithm::A256GCM => {
                AES_GCM_NONCE_SIZE
            }
            v => {
                return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    v,
                )))
            }
        };
        let mut iv = vec![0; iv_size];
        backend.generate_rand(&mut iv)?;
        Ok(self.iv(iv))
    }
}
