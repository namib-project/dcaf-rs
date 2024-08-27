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

use crate::error::CoseCipherError;
use crate::token::cose::crypto_impl::openssl::{CoseOpensslCipherError, OpensslContext};
use crate::token::cose::{crypto_impl, CoseEc2Key, EllipticCurve};
use crate::token::SignCryptoBackend;
use alloc::vec::Vec;
use coset::iana;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};

impl SignCryptoBackend for OpensslContext {
    fn sign_ecdsa(
        &mut self,
        alg: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        target: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = super::get_algorithm_hash_function(alg)?;

        // Possible truncation is fine, the key size will never exceed the size of an i32.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        sign_ecdsa(&group, pad_size as i32, hash, key, target)
    }

    fn verify_ecdsa(
        &mut self,
        alg: iana::Algorithm,
        key: &CoseEc2Key<'_, Self::Error>,
        signature: &[u8],
        target: &[u8],
    ) -> Result<(), CoseCipherError<Self::Error>> {
        let (pad_size, group) = get_ecdsa_group_params(key)?;
        let hash = crypto_impl::openssl::get_algorithm_hash_function(alg)?;

        verify_ecdsa(&group, pad_size, hash, key, signature, target)
    }
}

/// Determine the openssl [`EcGroup`] instance and coordinate size that should be used for the given
/// ECDSA key (based on its curve).
fn get_ecdsa_group_params(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
) -> Result<(usize, EcGroup), CoseCipherError<CoseOpensslCipherError>> {
    match &key.crv {
        EllipticCurve::Assigned(iana::EllipticCurve::P_256) => {
            // ECDSA using P-256 curve, coordinates are padded to 256 bits
            Ok((32, EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()))
        }
        EllipticCurve::Assigned(iana::EllipticCurve::P_384) => {
            // ECDSA using P-384 curve, coordinates are padded to 384 bits
            Ok((48, EcGroup::from_curve_name(Nid::SECP384R1).unwrap()))
        }
        EllipticCurve::Assigned(iana::EllipticCurve::P_521) => {
            // ECDSA using P-521 curve, coordinates are padded to 528 bits (521 bits rounded up
            // to the nearest full bytes).
            Ok((66, EcGroup::from_curve_name(Nid::SECP521R1).unwrap()))
        }
        v => Err(CoseCipherError::UnsupportedCurve(v.clone())),
    }
}

/// Perform an ECDSA signature operation with the given parameters.
fn sign_ecdsa(
    group: &EcGroup,
    pad_size: i32,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    target: &[u8],
) -> Result<Vec<u8>, CoseCipherError<CoseOpensslCipherError>> {
    let private_key = cose_ec2_to_ec_private_key(key, group).map_err(CoseCipherError::from)?;

    let mut signer = Signer::new(
        hash,
        &*PKey::from_ec_key(private_key).map_err(CoseOpensslCipherError::from)?,
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
        .to_vec_padded(pad_size)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    let mut s_vec = ecdsa_sig
        .s()
        .to_vec_padded(pad_size)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)?;
    sig.append(&mut s_vec);

    Ok(sig)
}

/// Perform an ECDSA verification operation with the given parameters.
fn verify_ecdsa(
    group: &EcGroup,
    pad_size: usize,
    hash: MessageDigest,
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    signature: &[u8],
    signed_data: &[u8],
) -> Result<(), CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, group).map_err(CoseCipherError::from)?;
    let pkey = PKey::from_ec_key(public_key).map_err(CoseOpensslCipherError::from)?;

    let mut verifier = Verifier::new(hash, &pkey).map_err(CoseOpensslCipherError::from)?;

    // signature is in COSE format, need to convert to DER format.
    let r = BigNum::from_slice(&signature[..pad_size]).map_err(CoseOpensslCipherError::from)?;
    let s = BigNum::from_slice(&signature[pad_size..]).map_err(CoseOpensslCipherError::from)?;
    let signature =
        EcdsaSig::from_private_components(r, s).map_err(CoseOpensslCipherError::from)?;
    // Note: EcdsaSig has its own "verify" method, but it is deprecated since OpenSSL
    // 3.0, which is why it's not used here.
    let der_signature = signature.to_der().map_err(CoseOpensslCipherError::from)?;

    verifier
        .verify_oneshot(der_signature.as_slice(), signed_data)
        .map_err(CoseOpensslCipherError::from)
        .map_err(CoseCipherError::from)
        .and_then(|verification_successful| {
            verification_successful
                .then_some(())
                .ok_or(CoseCipherError::VerificationFailure)
        })
}

/// Converts a private [`CoseEc2Key`] instance to its corresponding representation as an [`EcKey`]
/// in `openssl`.
fn cose_ec2_to_ec_private_key(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    group: &EcGroup,
) -> Result<EcKey<Private>, CoseCipherError<CoseOpensslCipherError>> {
    let public_key = cose_ec2_to_ec_public_key(key, group)?;

    EcKey::<Private>::from_private_components(
        group,
        &*BigNum::from_slice(
            // According to the contract of the trait, this should be ensured by the caller, so it's
            // fine to panic here.
            key.d
                .expect("key provided to backend has no private component"),
        )
        .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
        public_key.public_key(),
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}

/// Converts a public [`CoseEc2Key`] instance to its corresponding representation as an [`EcKey`]
/// in `openssl`.
fn cose_ec2_to_ec_public_key(
    key: &CoseEc2Key<'_, CoseOpensslCipherError>,
    group: &EcGroup,
) -> Result<EcKey<Public>, CoseCipherError<CoseOpensslCipherError>> {
    // TODO X and Y can be recomputed and are not strictly required if D is known
    //      (RFC 8152, Section 13.1.1)
    if key.x.is_none() || key.y.is_none() {
        return Err(CoseCipherError::UnsupportedKeyDerivation);
    }

    EcKey::<Public>::from_public_key_affine_coordinates(
        group,
        &*BigNum::from_slice(key.x.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
        &*BigNum::from_slice(key.y.unwrap())
            .map_err(CoseCipherError::<CoseOpensslCipherError>::from)?,
    )
    .map_err(CoseCipherError::<CoseOpensslCipherError>::from)
}
