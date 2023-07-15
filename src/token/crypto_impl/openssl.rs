use crate::error::CoseCipherError;
use crate::token::CoseCipher;
use crate::CoseSignCipher;
use alloc::collections::BTreeSet;
use ciborium::value::{Integer, Value};
use coset::iana::EnumI64;
use coset::{
    iana, Algorithm, CoseKey, Header, KeyType, Label, ProtectedHeader, RegisteredLabel,
    RegisteredLabelWithPrivate,
};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcKeyRef};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Signer;
use rand::{CryptoRng, RngCore};
use strum_macros::Display;

const P256CURVE_ID: Integer = Integer::from(iana::EllipticCurve::P_256.to_i64());
const P384CURVE_ID: Integer = Integer::from(iana::EllipticCurve::P_384.to_i64());
const P521CURVE_ID: Integer = Integer::from(iana::EllipticCurve::P_521.to_i64());

const P256GROUP: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

#[derive(Debug, PartialEq, Eq, Clone, Display)]
#[non_exhaustive]
pub enum CoseOpensslCipherError {
    UnsupportedKeyType,
    UnsupportedCurve(Option<iana::EllipticCurve>),
    UnsupportedAlgorithm(Option<iana::Algorithm>),
    UnsupportedKeyOperation(iana::KeyOperation),
    DuplicateHeaders(Vec<Label>),
    InvalidKeyId(Vec<u8>),
    MissingEc2KeyParam(iana::Ec2KeyParameter),
    OpensslError(core::ffi::c_ulong),
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
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Alg.to_i64()))
    }
    if header_bucket.content_type.is_some() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::ContentType.to_i64()))
    }
    if !header_bucket.key_id.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Kid.to_i64()))
    }
    if !header_bucket.crit.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Crit.to_i64()))
    }
    if !header_bucket.counter_signatures.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::CounterSignature.to_i64()))
    }
    if !header_bucket.iv.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::Iv.to_i64()))
    }
    if !header_bucket.partial_iv.is_empty() {
        header_bucket_fields.insert(Label::Int(iana::HeaderParameter::PartialIv.to_i64()))
    }

    header_bucket_fields.extend(header_bucket.rest.iter().map(|(k, _v)| k.clone()));

    return header_bucket_fields;
}

fn find_param_by_label<'a>(label: &Label, param_vec: &'a Vec<(Label, Value)>) -> Option<&'a Value> {
    param_vec
        .binary_search_by(|(v, _)| v.cmp(label))
        .map(|i| &param_vec.get(i).unwrap().1)
        .ok()
}

impl CoseCipher for Signer<'_> {
    type Error = CoseOpensslCipherError;

    fn set_headers<RNG: RngCore + CryptoRng>(
        key: &CoseKey,
        unprotected_header: &mut Header,
        protected_header: &mut Header,
        rng: RNG,
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let duplicate_header_fields = create_header_parameter_set(unprotected_header)
            .intersection(&create_header_parameter_set(protected_header))
            .collect();
        if duplicate_header_fields.is_empty() {
            return Err(CoseCipherError::Other(
                CoseOpensslCipherError::DuplicateHeaders(duplicate_header_fields),
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
                );

                // We do actually allow overriding the algorithm in the header, however, this must
                // happen in the protected header.
                if unprotected_header.alg.is_some() {
                    return Err(CoseCipherError::HeaderAlreadySet {
                        existing_header_name: String::from("alg"),
                    });
                }

                // Check if the chosen algorithm was overridden manually in the headers.
                // TODO check if alg matches key type.
                let mut algorithm = match &protected_header.alg {
                    Some(Algorithm::Assigned(
                        alg @ (iana::Algorithm::ES256
                        | iana::Algorithm::ES384
                        | iana::Algorithm::ES512),
                    )) => Some(*alg),
                    Some(Algorithm::Assigned(v)) => {
                        return Err(CoseCipherError::Other(
                            CoseOpensslCipherError::UnsupportedAlgorithm(Some(*v)),
                        ))
                    }
                    Some(_) => {
                        return Err(CoseCipherError::Other(
                            CoseOpensslCipherError::UnsupportedAlgorithm(None),
                        ))
                    }
                    None => None,
                };

                // If not, check if the chosen algorithm was overridden manually in the key.
                // TODO check if alg matches key type.
                if algorithm.is_none() {
                    algorithm = match &key.alg {
                        Some(Algorithm::Assigned(
                            alg @ (iana::Algorithm::ES256
                            | iana::Algorithm::ES384
                            | iana::Algorithm::ES512),
                        )) => Some(*alg),
                        Some(Algorithm::Assigned(v)) => {
                            return Err(CoseCipherError::Other(
                                CoseOpensslCipherError::UnsupportedAlgorithm(Some(*v)),
                            ))
                        }
                        Some(_) => {
                            return Err(CoseCipherError::Other(
                                CoseOpensslCipherError::UnsupportedAlgorithm(None),
                            ))
                        }
                        None => None,
                    }
                }

                // If not, set the default algorithm for a given curve.
                if algorithm.is_none() {
                    algorithm = match curve_type {
                        Some(Value::Integer(P256CURVE_ID)) => Some(iana::Algorithm::ES256),
                        Some(Value::Integer(P384CURVE_ID)) => Some(iana::Algorithm::ES384),
                        Some(Value::Integer(P521CURVE_ID)) => Some(iana::Algorithm::ES512),
                        Some(Value::Integer(v)) => {
                            let curve_id = i64::try_from(i128::from(v.clone()))
                                .map(iana::EllipticCurve::from_i64)
                                .ok()
                                .flatten();
                            return Err(CoseCipherError::Other(
                                CoseOpensslCipherError::UnsupportedCurve(curve_id),
                            ));
                        }
                        None => {
                            return Err(CoseCipherError::Other(
                                CoseOpensslCipherError::UnsupportedCurve(None),
                            ))
                        }
                    }
                }
                debug_assert!(algorithm.is_some());
                // At this point, due to the last match clause, we have either found an algorithm
                // or returned with an error code, so it is reasonable to unwrap().
                protected_header.alg = Some(Algorithm::Assigned(algorithm.unwrap()));

                if !protected_header.is_empty() && protected_header.key_id != key.key_id {
                    return Err(CoseCipherError::Other(
                        CoseOpensslCipherError::InvalidKeyId(protected_header.key_id.clone()),
                    ));
                } else if !unprotected_header.is_empty() && unprotected_header.key_id != key.key_id
                {
                    return Err(CoseCipherError::Other(
                        CoseOpensslCipherError::InvalidKeyId(unprotected_header.key_id.clone()),
                    ));
                } else {
                    unprotected_header.key_id = key.key_id.clone();
                }

                Ok(())
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
        let mut signer = match &protected_header.alg {
            Algorithm::Assigned(iana::Algorithm::ES256) => {
                let x = find_param_by_label(
                    &Label::Int(iana::Ec2KeyParameter::X.to_i64()),
                    &key.params,
                )
                .map(Value::as_bytes)
                .flatten()
                .ok_or(CoseCipherError::Other(
                    CoseOpensslCipherError::MissingEc2KeyParam(iana::Ec2KeyParameter::X),
                ))?;
                let y = find_param_by_label(
                    &Label::Int(iana::Ec2KeyParameter::Y.to_i64()),
                    &key.params,
                )
                .map(Value::as_bytes)
                .flatten()
                .ok_or(CoseCipherError::Other(
                    CoseOpensslCipherError::MissingEc2KeyParam(iana::Ec2KeyParameter::X),
                ))?;
                let d = find_param_by_label(
                    &Label::Int(iana::Ec2KeyParameter::D.to_i64()),
                    &key.params,
                )
                .map(Value::as_bytes)
                .flatten()
                .ok_or(CoseCipherError::Other(
                    CoseOpensslCipherError::MissingEc2KeyParam(iana::Ec2KeyParameter::X),
                ))?;
                let public_key = EcKey::<Public>::from_public_key_affine_coordinates(
                    &P256GROUP,
                    &BigNum::from_slice(x)?,
                    &BigNum::from_slice(y)?,
                )?;
                let private_key = EcKey::<Private>::from_private_components(
                    &P256GROUP,
                    &BigNum::from_slice(d)?,
                    public_key.public_key(),
                )?;
                Signer::new(MessageDigest::sha256(), &PKey::from_ec_key(private_key)?)?
            }
            _ => todo!(),
        };

        Ok(signer.sign_oneshot_to_vec(target)?)
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
        todo!()
    }
}
