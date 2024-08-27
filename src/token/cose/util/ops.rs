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
use crate::error::CoseCipherError;
use crate::token::cose::util::{check_for_duplicate_headers, determine_key_candidates};
use crate::token::cose::KeyProvider;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt::Display;
use coset::{iana, CoseKey, Header, KeyOperation};

/// Attempts to perform the COSE operation `op` for a COSE structure with the given `protected` and
/// `unprotected` headers after verifying that there are no duplicate headers, using the
/// `key_provider` to determine suitable key candidates.
///
/// `key_ops` should be a set of [`KeyOperation`]s that denote that a key is able to perform the
/// given operation.
/// Only one of these must be set in the key in order for it to be considered a valid candidate.
///
/// If the `key_provider` provides multiple keys, the operation will be attempted for every
/// candidate until one does not return an error or no more candidates are available.
///
/// Errors will be collected into a [`CoseCipherError::NoMatchingKeyFound`], which will be returned
/// if none of the keys can successfully perform the operation.
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
