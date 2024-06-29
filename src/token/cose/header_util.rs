use crate::error::CoseCipherError;
use crate::token::cose::header_util;
use crate::token::cose::key::{CoseKeyProvider, CoseParsedKey, EllipticCurve};
use crate::CoseSignCipher;
use ciborium::Value;
use core::fmt::Display;
use coset::iana::EnumI64;
use coset::{iana, Algorithm, Header, KeyOperation, Label};
use std::collections::BTreeSet;

pub(crate) fn create_header_parameter_set(header_bucket: &Header) -> BTreeSet<Label> {
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

    return header_bucket_fields;
}

pub(crate) fn find_param_by_label<'a>(
    label: &Label,
    param_vec: &'a Vec<(Label, Value)>,
) -> Option<&'a Value> {
    // TODO assert that parameters are sorted (Vec::is_sorted is unstable rn).
    param_vec
        .binary_search_by(|(v, _)| v.cmp(label))
        .map(|i| &param_vec.get(i).unwrap().1)
        .ok()
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
    if !duplicate_header_fields.is_empty() {
        Err(CoseCipherError::DuplicateHeaders(
            duplicate_header_fields
                .into_iter()
                .map(Label::clone)
                .collect(),
        ))
    } else {
        Ok(())
    }
}

/// Determines the algorithm to use for the signing operation based on the supplied key and headers.
pub(crate) fn determine_algorithm<CE: Display>(
    parsed_key: &CoseParsedKey<'_, CE>,
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
    } else if let Some(alg) = &parsed_key.as_ref().alg {
        // ...or the key itself.
        Ok(alg.clone())
    } else {
        // Otherwise, determine a reasonable default from the key type.
        match parsed_key {
            CoseParsedKey::Ec2(ec2_key) => {
                match &ec2_key.crv {
                    // RFC 9053
                    EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES256))
                    }
                    EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES384))
                    }
                    EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES512))
                    }
                    // RFC 8812
                    EllipticCurve::Assigned(iana::EllipticCurve::Secp256k1) => {
                        Ok(Algorithm::Assigned(iana::Algorithm::ES256K))
                    }
                    // TODO brainpool curves (see IANA registry)
                    // For all others, we don't know which algorithm to use.
                    v => Err(CoseCipherError::NoDefaultAlgorithmForKey(
                        ec2_key.as_ref().kty.clone(),
                        Some(v.clone()),
                    )),
                }
            }
            CoseParsedKey::Okp(okp_key) => match &okp_key.crv {
                EllipticCurve::Assigned(
                    iana::EllipticCurve::Ed448 | iana::EllipticCurve::Ed25519,
                ) => Ok(Algorithm::Assigned(iana::Algorithm::EdDSA)),
                v => Err(CoseCipherError::NoDefaultAlgorithmForKey(
                    okp_key.as_ref().kty.clone(),
                    Some(v.clone()),
                )),
            },
            CoseParsedKey::Symmetric(symm_key) => Err(CoseCipherError::NoDefaultAlgorithmForKey(
                symm_key.as_ref().kty.clone(),
                None,
            )),
        }
    }
}

pub(crate) fn determine_key_candidates<'a, CE: Display, CKP: CoseKeyProvider<'a>>(
    key_provider: &mut CKP,
    protected: Option<&Header>,
    unprotected: Option<&Header>,
    operation: &KeyOperation,
    try_all_keys: bool,
) -> Result<Vec<CoseParsedKey<'a, CE>>, CoseCipherError<CE>> {
    let key_id = if try_all_keys {
        None
    } else {
        protected
            .map(|v| v.key_id.as_slice())
            .filter(|v| !v.is_empty())
            .or_else(|| unprotected.map(|v| v.key_id.as_slice()))
            .filter(|v| !v.is_empty())
    };

    key_provider
        .lookup_key(key_id)
        .filter(|k| k.key_ops.is_empty() || k.key_ops.contains(operation))
        .map(CoseParsedKey::try_from)
        .collect()
}
