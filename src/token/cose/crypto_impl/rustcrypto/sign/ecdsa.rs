use core::ops::Add;

use coset::{iana, Algorithm};
use digest::const_oid::ObjectIdentifier;
use digest::Digest;
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use ecdsa::signature::{DigestSigner, Verifier};
use ecdsa::{
    PrimeCurve, RecoveryId, Signature, SignatureWithOid, SigningKey, VerifyingKey,
    ECDSA_SHA256_OID, ECDSA_SHA384_OID, ECDSA_SHA512_OID,
};
use elliptic_curve::{
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    CurveArithmetic, PublicKey, SecretKey,
};
use p256::NistP256;
use p384::NistP384;
use rand::{CryptoRng, RngCore};
use sha2::{Sha256, Sha384, Sha512};

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::rustcrypto::CoseRustCryptoCipherError;
use crate::token::cose::crypto_impl::rustcrypto::RustCryptoContext;
use crate::token::cose::{CoseEc2Key, CryptoBackend, EllipticCurve};

impl<RNG: RngCore + CryptoRng> RustCryptoContext<RNG> {
    /// Perform an ECDSA signature operation with the ECDSA variant given in `algorithm` for the
    /// given `payload` using the provided `key`.
    pub(super) fn sign_ecdsa(
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match algorithm {
            iana::Algorithm::ES256 => Self::sign_ecdsa_with_digest::<Sha256>(key, payload),
            iana::Algorithm::ES384 => Self::sign_ecdsa_with_digest::<Sha384>(key, payload),
            iana::Algorithm::ES512 => Self::sign_ecdsa_with_digest::<Sha512>(key, payload),
            a => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                a,
            ))),
        }
    }

    /// Perform an ECDSA verification operation with the ECDSA variant given in `algorithm` for the
    /// given `payload` and `sig`nature using the provided `key`.
    pub(super) fn verify_ecdsa(
        algorithm: iana::Algorithm,
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
        sig: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<<Self as CryptoBackend>::Error>> {
        let oid = match algorithm {
            iana::Algorithm::ES256 => ECDSA_SHA256_OID,
            iana::Algorithm::ES384 => ECDSA_SHA384_OID,
            iana::Algorithm::ES512 => ECDSA_SHA512_OID,
            a => {
                return Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
                    a,
                )))
            }
        };

        match &key.crv {
            EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
                Self::verify_ecdsa_with_curve::<NistP256>(key, oid, sig, payload)
            }
            EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
                Self::verify_ecdsa_with_curve::<NistP384>(key, oid, sig, payload)
            }
            // P-521 must implement DigestPrimitive in order to be usable in ECDSA, which was only
            // recently added and is not released yet (will come with p521 0.14.0).
            /*EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
                Self::ecdsa_sign_with_curve::<D, NistP521>(key, payload)
            }*/
            v => Err(CoseCipherError::UnsupportedCurve(v.clone())),
        }
    }

    /// Perform an ECDSA signature operation with the ECDSA hash function `D` for the
    /// given `payload` using the provided `key`.
    fn sign_ecdsa_with_digest<D: Digest>(
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>> {
        match &key.crv {
            EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
                Self::sign_ecdsa_with_digest_and_curve::<D, NistP256>(key, payload)
            }
            EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
                Self::sign_ecdsa_with_digest_and_curve::<D, NistP384>(key, payload)
            }
            // P-521 must implement DigestPrimitive in order to be usable in ECDSA, which was only
            // recently added and is not released yet (will come with p521 0.14.0).
            /*EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
                Self::ecdsa_sign_with_curve::<D, NistP521>(key, payload)
            }*/
            v => Err(CoseCipherError::UnsupportedCurve(v.clone())),
        }
    }

    /// Perform an ECDSA signature operation with the ECDSA hash function `D` and curve `CRV` for
    /// the given `payload` using the provided `key`.
    fn sign_ecdsa_with_digest_and_curve<
        D: Digest,
        CRV: PrimeCurve + CurveArithmetic + DigestPrimitive,
    >(
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<<Self as CryptoBackend>::Error>>
    where
        <CRV as CurveArithmetic>::Scalar: SignPrimitive<CRV>,
        <<CRV as ecdsa::elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    {
        let digest = Digest::new_with_prefix(payload);
        let sign_key = Self::cose_ec2_to_ec_private_key::<CRV>(key)?;
        let (signature, _recid) = <SigningKey<CRV> as DigestSigner<
            D,
            (Signature<CRV>, RecoveryId),
        >>::sign_digest(&sign_key, digest);
        Ok(signature.to_vec())
    }

    /// Perform an ECDSA verification operation with the ECDSA hash function given in `oid` for the
    /// given `payload` and `sig`nature using the provided `key`.
    fn verify_ecdsa_with_curve<CRV: PrimeCurve + CurveArithmetic + DigestPrimitive>(
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
        oid: ObjectIdentifier,
        sig: &[u8],
        payload: &[u8],
    ) -> Result<(), CoseCipherError<<Self as CryptoBackend>::Error>>
    where
        <CRV as CurveArithmetic>::AffinePoint: VerifyPrimitive<CRV>,
        <<CRV as ecdsa::elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
        <CRV as ecdsa::elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <CRV as CurveArithmetic>::AffinePoint: FromEncodedPoint<CRV>,
        <CRV as CurveArithmetic>::AffinePoint: ToEncodedPoint<CRV>,
    {
        let sign_key = Self::cose_ec2_to_ec_public_key::<CRV>(key)?;
        let signature = SignatureWithOid::new(Signature::<CRV>::from_slice(sig)?, oid)?;
        <VerifyingKey<CRV> as Verifier<SignatureWithOid<CRV>>>::verify(
            &sign_key, payload, &signature,
        )
        .map_err(CoseCipherError::from)
    }

    /// Convert a public or private COSE EC2 key to its public key RustCrypto representation.
    fn cose_ec2_to_ec_public_key<CRV: PrimeCurve + CurveArithmetic>(
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
    ) -> Result<VerifyingKey<CRV>, CoseCipherError<<Self as CryptoBackend>::Error>>
    where
        <CRV as ecdsa::elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <CRV as CurveArithmetic>::AffinePoint: FromEncodedPoint<CRV>,
        <CRV as CurveArithmetic>::AffinePoint: ToEncodedPoint<CRV>,
    {
        if key.x.is_none() || (key.y.is_none() && key.sign.is_none()) {
            // According to the contract provided by the calling COSE library, D must be set, so we
            // can attempt to reconstruct the public key from the private key.
            SecretKey::from_slice(key.d.expect(
                "invalid EC2 key was provided, at least one of the key parameters must be set",
            ))
            .map(|sc| VerifyingKey::from(sc.public_key()))
            .map_err(CoseCipherError::from)
        } else {
            // x must be Some here due to the previous condition.
            let pubkey_coord = if let Some(y) = key.y {
                EncodedPoint::<CRV>::from_affine_coordinates(key.x.unwrap().into(), y.into(), false)
            } else {
                EncodedPoint::<CRV>::from_affine_coordinates(
                    key.x.unwrap().into(),
                    u8::from(key.sign.unwrap()).to_be_bytes().as_slice().into(),
                    true,
                )
            };
            let pubkey = PublicKey::from_encoded_point(&pubkey_coord);
            if pubkey.is_some().into() {
                Ok(VerifyingKey::from(pubkey.unwrap()))
            } else {
                Err(CoseCipherError::Other(
                    CoseRustCryptoCipherError::InvalidPoint,
                ))
            }
        }
    }

    /// Convert a private COSE EC2 key to its RustCrypto representation.
    fn cose_ec2_to_ec_private_key<CRV: PrimeCurve + CurveArithmetic>(
        key: &CoseEc2Key<'_, <Self as CryptoBackend>::Error>,
    ) -> Result<SigningKey<CRV>, CoseCipherError<<Self as CryptoBackend>::Error>>
    where
        <CRV as CurveArithmetic>::Scalar: SignPrimitive<CRV>,
        <<CRV as ecdsa::elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    {
        SecretKey::<CRV>::from_slice(
            key.d
                .expect("invalid EC2 private key was provided, key parameter d must be set"),
        )
        .map(SigningKey::<CRV>::from)
        .map_err(CoseCipherError::from)
    }
}
