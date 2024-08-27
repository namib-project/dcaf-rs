/*
 * Copyright (c) 2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use alloc::borrow::ToOwned;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt::Display;

use alloc::borrow::Borrow;
use coset::iana::EnumI64;
use coset::{iana, Algorithm, CoseKey, Header, KeyOperation, Label};

use crate::error::CoseCipherError;
use crate::token::cose::key::KeyProvider;
/// Returns the set of header parameters that are set in the given `header_bucket`.
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

/// Ensures that there are no duplicate headers in the `protected_header` and `unprotected_header`
/// buckets.
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

/// Determines the value of a header param based on the provided `protected` and `unprotected`
/// header buckets and the `accessor` function that determines the header parameter from a header
/// reference.
pub(crate) fn determine_header_param<'a, F: Fn(&'a Header) -> Option<T>, T: 'a>(
    protected_header: Option<&'a Header>,
    unprotected_header: Option<&'a Header>,
    accessor: F,
) -> Option<T> {
    protected_header
        .into_iter()
        .chain(unprotected_header)
        .find_map(accessor)
}

/// Determines the algorithm to use for the signing operation based on the supplied key and headers.
pub(crate) fn determine_algorithm<CE: Display>(
    parsed_key: Option<&CoseKey>,
    protected_header: Option<&Header>,
    unprotected_header: Option<&Header>,
) -> Result<iana::Algorithm, CoseCipherError<CE>> {
    let alg = determine_header_param(protected_header, unprotected_header, |h| h.alg.clone())
        .or_else(|| parsed_key.and_then(|k| k.alg.clone()))
        .ok_or(CoseCipherError::NoAlgorithmDeterminable)?;

    if let Algorithm::Assigned(alg) = alg {
        Ok(alg)
    } else {
        Err(CoseCipherError::UnsupportedAlgorithm(alg))
    }
}

/// Queries the key provider for keys and checks for each returned key whether it is a possible
/// candidate for the operation and algorithm.
///
/// Returns an iterator that for each key returned by the key provider either returns the key plus
/// algorithm to use or the corresponding error that describes the reason why this key is not
/// suitable.
///
/// This function performs the algorithm-independent checks for whether a key is a suitable
/// candidate, but not any algorithm-specific checks (e.g. required key parameters, key length,
/// etc.). Those will have to be checked by the caller.
pub(crate) fn determine_key_candidates<'a, CKP: KeyProvider, CE: Display>(
    key_provider: &'a CKP,
    protected: Option<&'a Header>,
    unprotected: Option<&'a Header>,
    operation: BTreeSet<KeyOperation>,
) -> impl Iterator<Item = Result<(CoseKey, iana::Algorithm), (CoseKey, CoseCipherError<CE>)>> + 'a {
    let key_id = protected
        .map(|v| v.key_id.as_slice())
        .filter(|v| !v.is_empty())
        .or_else(|| unprotected.map(|v| v.key_id.as_slice()))
        .filter(|v| !v.is_empty());

    key_provider.lookup_key(key_id).map(move |k| {
        let k_borrow: &CoseKey = k.borrow();
        if !k_borrow.key_ops.is_empty()
            && k_borrow.key_ops.intersection(&operation).next().is_some()
        {
            return Err((
                k_borrow.clone(),
                CoseCipherError::KeyOperationNotPermitted(
                    k_borrow.key_ops.clone(),
                    operation.clone(),
                ),
            ));
        }
        let chosen_alg = determine_algorithm(Some(k_borrow), protected, unprotected)
            .map_err(|e| (k_borrow.clone(), e))?;
        if let Some(key_alg) = k_borrow.alg.as_ref() {
            if Algorithm::Assigned(chosen_alg) != *key_alg {
                return Err((
                    k_borrow.clone(),
                    CoseCipherError::KeyAlgorithmMismatch(
                        key_alg.clone(),
                        Algorithm::Assigned(chosen_alg),
                    ),
                ));
            }
        }
        Ok((k_borrow.to_owned(), chosen_alg))
    })
}
