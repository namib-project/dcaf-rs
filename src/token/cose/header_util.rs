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
use coset::{iana, Algorithm, CoseKey, Header, HeaderBuilder, KeyOperation, Label};

use crate::error::CoseCipherError;
use crate::token::cose::key::KeyProvider;
use crate::token::cose::{CryptoBackend, EncryptCryptoBackend};

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

/// Determines the value of a header param based on the provided `protected` and `unprotected`
/// header buckets and the `accessor` function that determines the header parameter from a header
/// reference.
pub(crate) fn determine_header_param<F: Fn(&Header) -> Option<T>, T>(
    protected_header: Option<&Header>,
    unprotected_header: Option<&Header>,
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

/// Extensions to the [`HeaderBuilder`]  type that enable usage of cryptographic backends.
pub trait HeaderBuilderExt: Sized {
    /// Generate an initialization vector for the given `alg` (algorithm) using the given
    /// cryptographic `backend`.
    ///
    /// # Errors
    ///
    /// Returns an error if the algorithm is unsupported/unknown or the cryptographic backend
    /// returns an error.
    fn gen_iv<B: EncryptCryptoBackend>(
        self,
        backend: &mut B,
        alg: iana::Algorithm,
    ) -> Result<Self, CoseCipherError<B::Error>>;
}

const AES_GCM_NONCE_SIZE: usize = 12;

impl HeaderBuilderExt for HeaderBuilder {
    fn gen_iv<B: CryptoBackend>(
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

pub(crate) fn try_cose_crypto_operation<BE: Display, CKP: KeyProvider, F, R>(
    key_provider: &CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    key_ops: BTreeSet<KeyOperation>,
    mut op: F,
) -> Result<R, CoseCipherError<BE>>
where
    F: FnMut(
        &CoseKey,
        iana::Algorithm,
        Option<&Header>,
        Option<&Header>,
    ) -> Result<R, CoseCipherError<BE>>,
{
    if let (Some(protected), Some(unprotected)) = (protected, unprotected) {
        check_for_duplicate_headers(protected, unprotected)?;
    }
    let mut multi_verification_errors = Vec::new();
    for kc in determine_key_candidates::<CKP, BE>(key_provider, protected, unprotected, key_ops) {
        multi_verification_errors.push(match kc {
            Ok((key, alg)) => match op(&key, alg, protected, unprotected) {
                Err(e) => (key, e),
                v => return v,
            },
            Err(e) => e,
        });
    }
    Err(CoseCipherError::NoMatchingKeyFound(
        multi_verification_errors,
    ))
}
