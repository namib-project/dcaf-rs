/*
 * Copyright (c) 2022-2024 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(feature = "openssl")]
use crate::error::CoseCipherError;
use crate::token::CoseCipher;
use crate::CoseSignCipher;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use ciborium::value::{Integer, Value};
use core::ops::Deref;
use coset::iana::EnumI64;
use coset::{
    iana, Algorithm, CoseKey, CoseKeyBuilder, Header, KeyType, Label, ProtectedHeader,
    RegisteredLabel,
};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use rand::{CryptoRng, RngCore};
use strum_macros::Display;

#[derive(Debug, PartialEq, Clone, Display)]
#[non_exhaustive]
pub enum CoseOpensslCipherError {
    UnsupportedKeyType,
    UnsupportedCurve(Option<iana::EllipticCurve>),
    UnsupportedAlgorithm(Algorithm),
    UnsupportedKeyOperation(iana::KeyOperation),
    KeyTypeAlgorithmMismatch(KeyType, Algorithm),
    KeyTypeCurveMismatch(KeyType, iana::EllipticCurve),
    DuplicateHeaders(Vec<Label>),
    InvalidKeyId(Vec<u8>),
    MissingKeyParam(iana::KeyParameter),
    MissingEc2KeyParam(iana::Ec2KeyParameter),
    // TODO probably better to replace this with ErrorStack, but ErrorStack doesn't support
    //      PartialEq and Eq
    OpensslError(core::ffi::c_ulong),
    TypeMismatch(Value),
    Other(&'static str),
}

impl From<CoseOpensslCipherError> for CoseCipherError<CoseOpensslCipherError> {
    fn from(value: CoseOpensslCipherError) -> Self {
        CoseCipherError::Other(value)
    }
}

impl From<ErrorStack> for CoseOpensslCipherError {
    fn from(value: ErrorStack) -> Self {
        CoseOpensslCipherError::OpensslError(value.errors().first().unwrap().code())
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

    return header_bucket_fields;
}

fn find_param_by_label<'a>(label: &Label, param_vec: &'a Vec<(Label, Value)>) -> Option<&'a Value> {
    // TODO ensure that labels are actually sorted.
    param_vec
        .binary_search_by(|(v, _)| v.cmp(label))
        .map(|i| &param_vec.get(i).unwrap().1)
        .ok()
}

impl CoseCipher for Signer<'_> {
    type Error = CoseOpensslCipherError;

    // TODO it seems like this entire function is non openssl-specific - can we remove set_headers
    //      from the CoseCipher trait and move it into the generic implementation?
    fn set_headers<RNG: RngCore + CryptoRng>(
        key: &CoseKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
        _rng: RNG,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let unprotected_header_set = create_header_parameter_set(unprotected_header);
        let protected_header_set = create_header_parameter_set(protected_header);
        let duplicate_header_fields: Vec<&Label> = unprotected_header_set
            .intersection(&protected_header_set)
            .collect();
        if !duplicate_header_fields.is_empty() {
            return Err(CoseCipherError::Other(
                CoseOpensslCipherError::DuplicateHeaders(
                    duplicate_header_fields
                        .into_iter()
                        .map(Label::clone)
                        .collect(),
                ),
            ));
        }

        match key.kty {
            KeyType::Assigned(iana::KeyType::EC2) => {
                // Key must be an ECDSA key conforming to RFC 9053, Section 2.1.0

                // Key must support the signing operation.
                if !key
                    .key_ops
                    .contains(&RegisteredLabel::Assigned(iana::KeyOperation::Sign))
                {
                    return Err(CoseCipherError::Other(
                        CoseOpensslCipherError::UnsupportedKeyOperation(iana::KeyOperation::Sign),
                    ));
                }

                // Get the value of the curve type parameter.
                let curve_type = find_param_by_label(
                    &Label::Int(iana::Ec2KeyParameter::Crv.to_i64()),
                    &key.params,
                )
                .ok_or(CoseCipherError::Other(
                    CoseOpensslCipherError::MissingEc2KeyParam(iana::Ec2KeyParameter::Crv),
                ))
                .and_then(|v| {
                    v.clone().into_integer().map_err(|e| {
                        CoseCipherError::Other(CoseOpensslCipherError::TypeMismatch(e))
                    })
                })
                .and_then(|v| {
                    i64::try_from(v).map_err(|e| {
                        CoseCipherError::Other(CoseOpensslCipherError::UnsupportedCurve(None))
                    })
                })
                .and_then(|v| {
                    iana::EllipticCurve::from_i64(v).ok_or(CoseCipherError::Other(
                        CoseOpensslCipherError::UnsupportedCurve(None),
                    ))
                })?;

                // Check if key type and curve are consistent RFC 8152, Section 13.1
                match curve_type {
                    iana::EllipticCurve::P_256
                    | iana::EllipticCurve::P_384
                    | iana::EllipticCurve::P_521 => {}
                    v => {
                        return Err(CoseCipherError::Other(
                            CoseOpensslCipherError::KeyTypeCurveMismatch(
                                key.kty.clone(),
                                v.clone(),
                            ),
                        ))
                    }
                }

                // We do actually allow overriding the algorithm in the header, however, this must
                // happen in the protected header.
                // TODO evaluate if this is necessary.
                //if unprotected_header.alg.is_some() {
                //    return Err(CoseCipherError::HeaderAlreadySet {
                //        existing_header_name: String::from("alg"),
                //    });
                //}

                // Check if the chosen algorithm was overridden manually in the headers....
                let algorithm = if let Some(alg) = &protected_header.alg {
                    Some(alg)
                } else if let Some(alg) = &key.alg {
                    // ...or the key itself
                    Some(alg)
                } else {
                    None
                };

                let mut algorithm = match algorithm {
                    Some(Algorithm::Assigned(
                        alg @ (iana::Algorithm::ES256
                        | iana::Algorithm::ES384
                        | iana::Algorithm::ES512),
                    )) => Some(*alg), // TODO check whether key curve matches algorithm
                    Some(v) => {
                        return Err(CoseCipherError::Other(
                            CoseOpensslCipherError::KeyTypeAlgorithmMismatch(
                                key.kty.clone(),
                                v.clone(),
                            ),
                        ))
                    }
                    None => None,
                };

                // If not, set the default algorithm for a given curve.
                let algorithm = match algorithm {
                    Some(v) => v,
                    None => match curve_type {
                        iana::EllipticCurve::P_256 => iana::Algorithm::ES256,
                        iana::EllipticCurve::P_384 => iana::Algorithm::ES384,
                        iana::EllipticCurve::P_521 => iana::Algorithm::ES512,
                        _ => unreachable!(
                            "key type and curve have been asserted to be consistent before"
                        ),
                    },
                };

                if unprotected_header.alg.is_none() {
                    protected_header.alg = Some(Algorithm::Assigned(algorithm));
                } else {
                    unprotected_header.alg = Some(Algorithm::Assigned(algorithm));
                }

                // If the Key ID has been set in any header, we need to check whether it matches the
                // key ID given in the COSE Key object.
                // TODO maybe not necessary if not in strict mode, as recipients may use a
                //      different key id for the same key (but why would you do that?)
                if !protected_header.key_id.is_empty() && protected_header.key_id != key.key_id {
                    Err(CoseCipherError::Other(
                        CoseOpensslCipherError::InvalidKeyId(protected_header.key_id.clone()),
                    ))
                } else if !unprotected_header.key_id.is_empty()
                    && unprotected_header.key_id != key.key_id
                {
                    Err(CoseCipherError::Other(
                        CoseOpensslCipherError::InvalidKeyId(unprotected_header.key_id.clone()),
                    ))
                } else {
                    unprotected_header.key_id = key.key_id.clone();
                    Ok(())
                }
            }
            _ => Err(CoseCipherError::Other(
                CoseOpensslCipherError::UnsupportedKeyType,
            )),
        }
    }
}

impl CoseSignCipher for Signer<'_> {
    fn sign(
        key: &CoseKey,
        target: &[u8],
        unprotected_header: &Header,
        protected_header: &Header,
    ) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
        let algorithm = if protected_header.alg.is_some() {
            &protected_header.alg
        } else {
            &unprotected_header.alg
        };
        match algorithm {
            Some(Algorithm::Assigned(iana::Algorithm::ES256)) => {
                let p256group: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
                sign_ecdsa::<32>(
                    &p256group,
                    MessageDigest::sha256(),
                    key,
                    target,
                    unprotected_header,
                    protected_header,
                )
            }
            Some(Algorithm::Assigned(iana::Algorithm::ES384)) => {
                let p384group: EcGroup = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
                sign_ecdsa::<48>(
                    &p384group,
                    MessageDigest::sha384(),
                    key,
                    target,
                    unprotected_header,
                    protected_header,
                )
            }
            Some(Algorithm::Assigned(iana::Algorithm::ES512)) => {
                let p512group: EcGroup = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
                sign_ecdsa::<66>(
                    &p512group,
                    MessageDigest::sha512(),
                    key,
                    target,
                    unprotected_header,
                    protected_header,
                )
            }
            _ => todo!(),
        }
    }

    fn verify(
        key: &CoseKey,
        signature: &[u8],
        signed_data: &[u8],
        unprotected_header: &Header,
        protected_header: &ProtectedHeader,
        unprotected_signature_header: Option<&Header>,
        protected_signature_header: Option<&ProtectedHeader>,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let algorithm = if protected_header.header.alg.is_some() {
            &protected_header.header.alg
        } else {
            &unprotected_header.alg
        };
        match algorithm {
            Some(Algorithm::Assigned(iana::Algorithm::ES256)) => {
                let p256group: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
                verify_ecdsa::<32>(
                    &p256group,
                    MessageDigest::sha256(),
                    key,
                    signature,
                    signed_data,
                    unprotected_header,
                    protected_header,
                    unprotected_signature_header,
                    protected_signature_header,
                )
            }
            Some(Algorithm::Assigned(iana::Algorithm::ES384)) => {
                let p384group: EcGroup = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
                verify_ecdsa::<48>(
                    &p384group,
                    MessageDigest::sha384(),
                    key,
                    signature,
                    signed_data,
                    unprotected_header,
                    protected_header,
                    unprotected_signature_header,
                    protected_signature_header,
                )
            }
            Some(Algorithm::Assigned(iana::Algorithm::ES512)) => {
                let p521group: EcGroup = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
                verify_ecdsa::<66>(
                    &p521group,
                    MessageDigest::sha512(),
                    key,
                    signature,
                    signed_data,
                    unprotected_header,
                    protected_header,
                    unprotected_signature_header,
                    protected_signature_header,
                )
            }
            _ => todo!(),
        }
    }
}

fn sign_ecdsa<const KS: i32>(
    group: &EcGroup,
    hash: MessageDigest,
    key: &CoseKey,
    target: &[u8],
    unprotected_header: &Header,
    protected_header: &Header,
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let private_key = cose_ec2_to_ec_private_key(key, &group).map_err(CoseCipherError::from)?;

    let mut signer = Signer::new(
        hash,
        PKey::from_ec_key(private_key)
            .map_err(CoseOpensslCipherError::from)?
            .deref(),
    )
    .map_err(CoseOpensslCipherError::from)?;

    // generated signature is of DER format, need to convert it to COSE key format
    let der_signature = signer
        .sign_oneshot_to_vec(target)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;

    let ecdsa_sig = EcdsaSig::from_der(der_signature.as_slice())
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;

    // See RFC 8152, section 8.1
    let mut sig = ecdsa_sig
        .r()
        .to_vec_padded(KS)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    let mut s_vec = ecdsa_sig
        .s()
        .to_vec_padded(KS)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    sig.append(&mut s_vec);

    Ok(sig)
}

fn verify_ecdsa<const KS: usize>(
    group: &EcGroup,
    hash: MessageDigest,
    key: &CoseKey,
    signature: &[u8],
    signed_data: &[u8],
    unprotected_header: &Header,
    protected_header: &ProtectedHeader,
    unprotected_signature_header: Option<&Header>,
    protected_signature_header: Option<&ProtectedHeader>,
) -> Result<(), CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, &group).map_err(CoseCipherError::from)?;
    let pkey = PKey::from_ec_key(public_key).map_err(CoseOpensslCipherError::from)?;

    let mut verifier = Verifier::new(hash, &pkey).map_err(CoseOpensslCipherError::from)?;

    // signature is in COSE format, need to convert to DER format.
    let r = BigNum::from_slice(&signature[..KS]).map_err(CoseOpensslCipherError::from)?;
    let s = BigNum::from_slice(&signature[KS..]).map_err(CoseOpensslCipherError::from)?;
    let signature =
        EcdsaSig::from_private_components(r, s).map_err(CoseOpensslCipherError::from)?;
    // Note: EcdsaSig has its own "verify" method, but it is deprecated since OpenSSL
    // 3.0, which is why it's not used here.
    let der_signature = signature.to_der().map_err(CoseOpensslCipherError::from)?;

    verifier
        .verify_oneshot(der_signature.as_slice(), signed_data)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)
        .and_then(|verification_successful| match verification_successful {
            true => Ok(()),
            false => Err(CoseCipherError::VerificationFailure),
        })
}

fn cose_ec2_to_ec_private_key(
    key: &CoseKey,
    group: &EcGroup,
) -> Result<EcKey<Private>, CoseOpensslCipherError> {
    let public_key = cose_ec2_to_ec_public_key(key, group)?;

    let d = find_param_by_label(&Label::Int(iana::Ec2KeyParameter::D.to_i64()), &key.params)
        .map(Value::as_bytes)
        .flatten()
        .ok_or(CoseOpensslCipherError::MissingEc2KeyParam(
            iana::Ec2KeyParameter::D,
        ))?;

    EcKey::<Private>::from_private_components(
        group,
        &BigNum::from_slice(d)
            .map_err(CoseOpensslCipherError::from)?
            .deref(),
        public_key.public_key(),
    )
    .map_err(CoseOpensslCipherError::from)
}

fn cose_ec2_to_ec_public_key(
    key: &CoseKey,
    group: &EcGroup,
) -> Result<EcKey<Public>, CoseOpensslCipherError> {
    // TODO X and Y can be recomputed and are not strictly required if D is known
    //      (RFC 8152, Section 13.1.1)
    let x = find_param_by_label(&Label::Int(iana::Ec2KeyParameter::X.to_i64()), &key.params)
        .map(Value::as_bytes)
        .flatten()
        .ok_or(CoseOpensslCipherError::MissingEc2KeyParam(
            iana::Ec2KeyParameter::X,
        ))?;
    let y = find_param_by_label(&Label::Int(iana::Ec2KeyParameter::Y.to_i64()), &key.params)
        .map(Value::as_bytes)
        .flatten()
        .ok_or(CoseOpensslCipherError::MissingEc2KeyParam(
            iana::Ec2KeyParameter::Y,
        ))?;

    EcKey::<Public>::from_public_key_affine_coordinates(
        &group,
        &BigNum::from_slice(x)
            .map_err(CoseOpensslCipherError::from)?
            .deref(),
        &BigNum::from_slice(y)
            .map_err(CoseOpensslCipherError::from)?
            .deref(),
    )
    .map_err(CoseOpensslCipherError::from)
}

#[cfg(test)]
mod tests {
    use crate::common::test_helper::FakeRng;
    use crate::token::CoseCipher;
    use crate::CoseSignCipher;
    use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
    use coset::iana::{Algorithm, KeyOperation};
    use coset::{
        iana, AsCborValue, CborSerializable, CoseKey, CoseKeyBuilder, CoseSign1, CoseSign1Builder,
        Header, HeaderBuilder, TaggedCborSerializable,
    };
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::sign::{Signer, Verifier};
    use parameterized::parameterized;
    use serde::Serialize;

    fn p256_testkey() -> CoseKey {
        CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            URL_SAFE_NO_PAD
                .decode("-ZC6FAgf1yptcLLiu-6VRb7a7n3_l2AGoNg29TR03Mw")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("DD-Gx3txJu0VInf1p4tHgDTWOWgGdl2JumUnUZsgJDI")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("6iSKFEJCauf1K5QzyZjJM4iBEAOQqZkwVUeeTUcElRQ")
                .unwrap(),
        )
        .add_key_op(KeyOperation::Sign)
        .add_key_op(KeyOperation::Verify)
        .add_key_op(KeyOperation::Encrypt)
        .add_key_op(KeyOperation::Decrypt)
        .build()
    }

    fn p384_testkey() -> CoseKey {
        CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_384,
            URL_SAFE_NO_PAD
                .decode("95pFzElUJ9UZGA-aumXFzu4gR_2d2elGjE83WPht68An6TEzfiWcbVmuA-_fyVVy")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("2htQSt2Nac-rNDKLswdzC4DcNOJjbfPgHYETK9iE8dwfDSNxfPr3Xz4EeuCuM8Uc")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("9mclx3tODsIseWFdCR5weP-oOqA6NUsTjOmdIkqqCMNBONCCCM_8WcLOId4a3QwI")
                .unwrap(),
        )
        .add_key_op(KeyOperation::Sign)
        .add_key_op(KeyOperation::Verify)
        .add_key_op(KeyOperation::Encrypt)
        .add_key_op(KeyOperation::Decrypt)
        .build()
    }

    fn p521_testkey() -> CoseKey {
        CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_521,
            URL_SAFE_NO_PAD
                .decode("wA6_xLH2RPqAxf7fp1C2kYt9inWujnhVMZieDY9Ikv-jKBQ0EUaqAFIaVHeX9qh_iZ-lz2jM-JHmlVQsK6TpUGk")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("AWXuSZZKUCbLWIQB4xnmjlR-KWRwUgcc2hn2FlHchOKuNWrOiIVQHXYo5R4dLq4iji9MNrnibFh_2MCuch0LuYbR")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("AT8UDI_AkaK1Ra9mSDJ8lCFy2erCOzGeiZtcx1_ZFiIm42nZ-zvKqWzq3p6H1kgMdo5761p-6XDhZU5JD4rhYfiX")
                .unwrap(),
        )
            .add_key_op(KeyOperation::Sign)
            .add_key_op(KeyOperation::Verify)
            .add_key_op(KeyOperation::Encrypt)
            .add_key_op(KeyOperation::Decrypt)
        .build()
    }

    // Code to generate new keys for testing purposes.
    fn gen_key() {
        let group: EcGroup = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let d = URL_SAFE_NO_PAD.encode(key.private_key().to_vec());
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        key.public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut BigNumContext::new().unwrap())
            .unwrap();
        let x = URL_SAFE_NO_PAD.encode(x.to_vec());
        let y = URL_SAFE_NO_PAD.encode(y.to_vec());
        println!("X: {}", x);
        println!("Y: {}", y);
        println!("D: {}", d);
    }

    fn run_sign_verify(
        key: &CoseKey,
        payload: &str,
        unprotected: &mut Header,
        protected: &mut Header,
    ) {
        <Signer as CoseCipher>::set_headers(&key, unprotected, protected, FakeRng).unwrap();
        let sign_struct = CoseSign1Builder::new()
            .unprotected(unprotected.clone())
            .protected(protected.clone())
            .payload(Vec::from(payload));

        let sign_cbor = sign_struct
            .try_create_signature(&[], |tosign| {
                <Signer as CoseSignCipher>::sign(&key, tosign, &unprotected, &protected)
            })
            .unwrap()
            .build();

        let output_cbor = sign_cbor.clone().to_tagged_vec().unwrap();
        println!("Output CBOR of CoseSign1: {}", hex::encode(&output_cbor));

        let reimported_sign = CoseSign1::from_tagged_slice(output_cbor.as_slice()).unwrap();
        assert_eq!(
            sign_cbor.to_cbor_value().unwrap(),
            reimported_sign.clone().to_cbor_value().unwrap()
        );

        reimported_sign
            .verify_signature(&[], |signature, toverify| {
                <Signer as CoseSignCipher>::verify(
                    &key,
                    signature,
                    toverify,
                    &reimported_sign.unprotected,
                    &reimported_sign.protected,
                    None,
                    None,
                )
            })
            .unwrap();
    }

    #[parameterized(keygen = {
        p256_testkey, p384_testkey, p521_testkey
    })]
    fn test_sign_verify(keygen: fn() -> CoseKey) {
        //let keygen = p521_testkey;
        run_sign_verify(
            &keygen(),
            "This is the content.",
            &mut Header::default(),
            &mut Header::default(),
        );
    }

    /// Test case from the cose-wg/Examples repository - sign1-tests/sign-pass-01.json
    /// Sign and Verify using OpenSSL backend.
    /// https://github.com/cose-wg/Examples/blob/master/sign1-tests/sign-pass-01.json
    #[test]
    fn example_test_sign_verify_pass_01() {
        let key = CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            URL_SAFE_NO_PAD
                .decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
                .unwrap(),
        )
        .key_id("11".as_bytes().to_vec())
        .add_key_op(KeyOperation::Sign)
        .add_key_op(KeyOperation::Verify)
        .add_key_op(KeyOperation::Encrypt)
        .add_key_op(KeyOperation::Decrypt)
        .build();
        let mut unprotected = HeaderBuilder::new()
            .key_id("11".as_bytes().to_vec())
            .algorithm(Algorithm::ES256)
            .build();
        run_sign_verify(
            &key,
            "This is the content.",
            &mut unprotected,
            &mut HeaderBuilder::new().build(),
        )
    }

    /// Test case from the cose-wg/Examples repository - sign1-tests/sign-pass-01.json
    /// Verify signature from given example using OpenSSL.
    /// https://github.com/cose-wg/Examples/blob/master/sign1-tests/sign-pass-01.json
    #[test]
    fn example_test_verify_pass_01() {
        let key = CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            URL_SAFE_NO_PAD
                .decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
                .unwrap(),
        )
        .build();
        let plaintext = "This is the content.";

        let unprotected = HeaderBuilder::new()
            .key_id("11".as_bytes().to_vec())
            .algorithm(Algorithm::ES256)
            .build();

        let sign_struct = CoseSign1Builder::new()
            .unprotected(unprotected.clone())
            .protected(HeaderBuilder::new().build())
            .payload(Vec::from(plaintext));

        let sign_cbor = sign_struct
            .try_create_signature(&[], |tosign| {
                let intermediate_tobesigned = hex::decode(
                    "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E",
                )
                .unwrap();
                assert_eq!(tosign, intermediate_tobesigned.as_slice());
                <Signer as CoseSignCipher>::sign(
                    &key,
                    tosign,
                    &unprotected,
                    &HeaderBuilder::new().build(),
                )
            })
            .unwrap()
            .build();

        let example_cbor_raw = hex::decode("D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F").unwrap();
        let example_cbor: ciborium::Value =
            ciborium::from_reader(example_cbor_raw.as_slice()).unwrap();
        let example_sign = CoseSign1::from_tagged_slice(example_cbor_raw.as_slice()).unwrap();

        println!("{:?}", &example_sign);
        example_sign
            .verify_signature(&[], |signature, toverify| {
                let intermediate_tobeverified = hex::decode(
                    "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E",
                )
                .unwrap();
                println!("{}", hex::encode(&toverify));
                // TODO Value for which to verify signature for seems to be mismatched - presumably because the example token has this zero length string encoding with the A0 byte for the protected header.
                assert_eq!(toverify, intermediate_tobeverified.as_slice());
                <Signer as CoseSignCipher>::verify(
                    &key,
                    signature,
                    toverify,
                    &example_sign.unprotected,
                    &example_sign.protected,
                    None,
                    None,
                )
            })
            .unwrap();
    }
}
