use alloc::collections::BTreeSet;
use core::fmt::Display;

use ciborium::Value;
use coset::iana::EnumI64;
use coset::{iana, Algorithm, CoseKey, Header, KeyOperation, Label};

use crate::error::CoseCipherError;
use crate::token::cose::header_util;
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderParam {
    Generic(iana::HeaderParameter),
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

pub(crate) fn find_param_index_by_label(
    label: &Label,
    param_vec: &[(Label, Value)],
) -> Option<usize> {
    // TODO assert that parameters are sorted (Vec::is_sorted is unstable rn).
    param_vec.binary_search_by(|(v, _)| v.cmp(label)).ok()
}

pub(crate) fn find_param_by_label<'a>(
    label: &Label,
    param_vec: &'a Vec<(Label, Value)>,
) -> Option<&'a Value> {
    find_param_index_by_label(label, param_vec).map(|i| &param_vec.get(i).unwrap().1)
}

pub(crate) fn check_for_duplicate_headers<E: Display>(
    protected_header: &Header,
    unprotected_header: &Header,
) -> Result<(), CoseCipherError<E>> {
    let unprotected_header_set = header_util::create_header_parameter_set(unprotected_header);
    let protected_header_set = header_util::create_header_parameter_set(protected_header);
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
) -> Result<Algorithm, CoseCipherError<CE>> {
    // Check whether the algorithm has been explicitly set...
    if let Some(Some(alg)) = protected_header.map(|v| &v.alg) {
        // ...in the protected header...
        Ok(alg.clone())
    } else if let Some(Some(alg)) = unprotected_header.map(|v| &v.alg) {
        // ...in the unprotected header...
        Ok(alg.clone())
    } else if let Some(alg) = &parsed_key.and_then(|v| v.as_ref().alg.clone()) {
        // ...or the key itself.
        Ok(alg.clone())
    } else {
        Err(CoseCipherError::NoAlgorithmDeterminable)
    }
}

pub(crate) fn determine_key_candidates<'a, CE: Display, CKP: CoseKeyProvider>(
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
