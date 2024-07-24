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
use alloc::vec::Vec;
use ciborium::Value;
use core::borrow::Borrow;
use core::fmt::Display;
use core::marker::PhantomData;
use coset::iana::EnumI64;
use coset::{iana, Algorithm, AsCborValue, CoseKey, KeyType, Label, RegisteredLabelWithPrivate};

use crate::error::CoseCipherError;
use crate::token::cose::CryptoBackend;

/// Finds a key parameter by its label.
fn find_param_by_label<'a>(label: &Label, param_vec: &'a [(Label, Value)]) -> Option<&'a Value> {
    param_vec
        .iter()
        .find_map(|(l, v)| if l == label { Some(v) } else { None })
}

/// An IANA-defined key parameter for a [CoseKey].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyParam {
    /// Key parameters that are not specific for a certain key type.
    Common(iana::KeyParameter),
    /// Key parameters specific to EC2 elliptic curve keys.
    Ec2(iana::Ec2KeyParameter),
    /// Key parameters specific to OKP elliptic curve keys.
    Okp(iana::OkpKeyParameter),
    /// Key parameters specific to symmetric keys.
    Symmetric(iana::SymmetricKeyParameter),
}

impl From<iana::KeyParameter> for KeyParam {
    fn from(value: iana::KeyParameter) -> Self {
        KeyParam::Common(value)
    }
}

impl From<iana::Ec2KeyParameter> for KeyParam {
    fn from(value: iana::Ec2KeyParameter) -> Self {
        KeyParam::Ec2(value)
    }
}

impl From<iana::OkpKeyParameter> for KeyParam {
    fn from(value: iana::OkpKeyParameter) -> Self {
        KeyParam::Okp(value)
    }
}

impl From<iana::SymmetricKeyParameter> for KeyParam {
    fn from(value: iana::SymmetricKeyParameter) -> Self {
        KeyParam::Symmetric(value)
    }
}

#[derive(Clone, Debug, PartialEq)]

/// A parsed view into a [CoseKey] instance.
///
/// Allows for easier access to the key's parameters.
pub enum CoseParsedKey<'a, OE: Display> {
    /// An EC2 elliptic curve key.
    Ec2(CoseEc2Key<'a, OE>),
    /// An OKP elliptic curve key.
    Okp(CoseOkpKey<'a, OE>),
    /// A symmetric key.
    Symmetric(CoseSymmetricKey<'a, OE>),
}

impl<'a, OE: Display> TryFrom<&'a CoseKey> for CoseParsedKey<'a, OE> {
    type Error = CoseCipherError<OE>;

    fn try_from(key: &'a CoseKey) -> Result<Self, Self::Error> {
        match &key.kty {
            KeyType::Assigned(iana::KeyType::EC2) => CoseEc2Key::try_from(key).map(Into::into),
            KeyType::Assigned(iana::KeyType::OKP) => CoseOkpKey::try_from(key).map(Into::into),
            KeyType::Assigned(iana::KeyType::Symmetric) => {
                CoseSymmetricKey::try_from(key).map(Into::into)
            }
            v => Err(CoseCipherError::UnsupportedKeyType(v.clone())),
        }
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseParsedKey<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        match self {
            CoseParsedKey::Ec2(v) => v.as_ref(),
            CoseParsedKey::Okp(v) => v.as_ref(),
            CoseParsedKey::Symmetric(v) => v.as_ref(),
        }
    }
}

impl<'a, OE: Display> From<CoseEc2Key<'a, OE>> for CoseParsedKey<'a, OE> {
    fn from(value: CoseEc2Key<'a, OE>) -> Self {
        CoseParsedKey::Ec2(value)
    }
}

impl<'a, OE: Display> From<CoseOkpKey<'a, OE>> for CoseParsedKey<'a, OE> {
    fn from(value: CoseOkpKey<'a, OE>) -> Self {
        CoseParsedKey::Okp(value)
    }
}

impl<'a, OE: Display> From<CoseSymmetricKey<'a, OE>> for CoseParsedKey<'a, OE> {
    fn from(value: CoseSymmetricKey<'a, OE>) -> Self {
        CoseParsedKey::Symmetric(value)
    }
}

/// Types of elliptic curves.
pub type EllipticCurve = RegisteredLabelWithPrivate<iana::EllipticCurve>;

/// A parsed view into a parsed EC2 elliptic curve [CoseKey].
///
/// If this key contains public key information, the public key component will be either defined
/// using the X and Y coordinates or using the X coordinate and the sign of the public key point.
///
/// In the CBOR representation of this key, the sign and Y coordinate are both represented as
/// different types of the same map field (`y`), see
/// <https://datatracker.ietf.org/doc/html/rfc9053#section-7.1.1>.
#[derive(Clone, Debug, PartialEq)]
pub struct CoseEc2Key<'a, OE: Display> {
    /// Key that is referenced by this view.
    generic: &'a CoseKey,
    /// Elliptic curve this key belongs to.
    pub crv: EllipticCurve,
    /// The private key coordinate of this EC2 key.
    pub d: Option<&'a [u8]>,
    /// The X public key coordinate of this EC2 key.
    pub x: Option<&'a [u8]>,
    /// The Y public key coordinate of this EC2 key.
    ///
    /// Mutually exclusive with the `sign` field, i.e. only one of them should be set.
    pub y: Option<&'a [u8]>,
    /// The sign of the public key coordinate of this EC2 key.
    ///
    /// Mutually exclusive with the `y` field, i.e. only one of them should be set.
    pub sign: Option<bool>,
    _backend_error_type: PhantomData<OE>,
}

impl<'a, OE: Display> TryFrom<&'a CoseKey> for CoseEc2Key<'a, OE> {
    type Error = CoseCipherError<OE>;

    fn try_from(key: &'a CoseKey) -> Result<Self, Self::Error> {
        // Unless stated otherwise, these checks are according to RFC 9053, Section 7.1.1.

        // Curve must be set
        let crv = find_param_by_label(
            &Label::Int(iana::Ec2KeyParameter::Crv.to_i64()),
            &key.params,
        )
        .ok_or(CoseCipherError::MissingKeyParam(vec![
            iana::Ec2KeyParameter::Crv.into(),
        ]))?;
        // Curve must be of correct type
        let crv = EllipticCurve::from_cbor_value(crv.clone()).map_err(|_e| {
            // TODO e as error source (as soon as we use core::error::Error).
            CoseCipherError::InvalidKeyParam(iana::Ec2KeyParameter::Crv.into(), crv.clone())
        })?;

        // Check whether curve and key type are consistent (RFC 9053, Section 7.1)
        match &crv {
            EllipticCurve::Assigned(
                iana::EllipticCurve::P_256
                | iana::EllipticCurve::P_384
                | iana::EllipticCurve::P_521
                | iana::EllipticCurve::Secp256k1,
                // TODO these are also part of the IANA registry, and should be added to coset
                // | iana::EllipticCurve::BrainpoolP256r1
                // | iana::EllipticCurve::BrainpoolP320r1
                // | iana::EllipticCurve::BrainpoolP384r1
                // | iana::EllipticCurve::BrainpoolP512r1
            ) => {}
            // Any other assigned values must not be encoded as EC2 values.
            v @ EllipticCurve::Assigned(_) => {
                return Err(CoseCipherError::KeyTypeCurveMismatch(
                    KeyType::Assigned(iana::KeyType::EC2),
                    v.clone(),
                ))
            }
            // Anything else is private use/custom, and we assume that the caller knows what they
            // are doing.
            _v => {}
        }

        // Parse parameters d and x (private key and part of the public key), must be of type
        // bstr.
        let d = find_param_by_label(&Label::Int(iana::Ec2KeyParameter::D.to_i64()), &key.params)
            .map(|v| match v.as_bytes() {
                None => Err(CoseCipherError::InvalidKeyParam(
                    iana::Ec2KeyParameter::D.into(),
                    v.clone(),
                )),
                Some(b) => Ok(b.as_slice()),
            })
            .transpose()?;
        let x = find_param_by_label(&Label::Int(iana::Ec2KeyParameter::X.to_i64()), &key.params)
            .map(|v| match v.as_bytes() {
                None => Err(CoseCipherError::InvalidKeyParam(
                    iana::Ec2KeyParameter::X.into(),
                    v.clone(),
                )),
                Some(b) => Ok(b.as_slice()),
            })
            .transpose()?;

        // Parse parameter y (other half of public key), is either a bstr containing the Y
        // coordinate or a boolean indicating the sign.
        let y = find_param_by_label(&Label::Int(iana::Ec2KeyParameter::Y.to_i64()), &key.params);
        let (y, sign) = match y {
            None => (None, None),
            Some(Value::Bytes(b)) => (Some(b.as_slice()), None),
            Some(Value::Bool(b)) => (None, Some(*b)),
            Some(value) => {
                return Err(CoseCipherError::InvalidKeyParam(
                    iana::Ec2KeyParameter::Y.into(),
                    value.clone(),
                ))
            }
        };

        // For public keys, X and Y must be set, for private keys, at least D must be set.
        if d.is_none() && !(x.is_some() && (y.is_some() || sign.is_some())) {
            return Err(CoseCipherError::MissingKeyParam(vec![
                iana::Ec2KeyParameter::D.into(),
                iana::Ec2KeyParameter::X.into(),
                iana::Ec2KeyParameter::Y.into(),
            ]));
        }

        Ok(CoseEc2Key {
            generic: key,
            crv,
            d,
            x,
            y,
            sign,
            _backend_error_type: PhantomData,
        })
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseEc2Key<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        self.generic
    }
}

/// A parsed view into an OKP elliptic curve [CoseKey].
#[derive(Clone, Debug, PartialEq)]
pub struct CoseOkpKey<'a, OE: Display> {
    /// Key that is referenced by this view.
    generic: &'a CoseKey,
    /// Elliptic curve that this key belongs to.
    pub crv: EllipticCurve,
    /// Private key component of this elliptic curve key.
    pub d: Option<&'a [u8]>,
    /// Public key component of this elliptic curve key.
    pub x: Option<&'a [u8]>,
    _backend_error_type: PhantomData<OE>,
}

impl<'a, OE: Display> TryFrom<&'a CoseKey> for CoseOkpKey<'a, OE> {
    type Error = CoseCipherError<OE>;

    fn try_from(key: &'a CoseKey) -> Result<Self, Self::Error> {
        // Unless stated otherwise, these checks are according to RFC 9053, Section 7.2.

        // Curve must be set
        let crv = find_param_by_label(
            &Label::Int(iana::OkpKeyParameter::Crv.to_i64()),
            &key.params,
        )
        .ok_or(CoseCipherError::MissingKeyParam(vec![
            iana::OkpKeyParameter::Crv.into(),
        ]))?;

        // Curve must be of correct type
        let crv = EllipticCurve::from_cbor_value(crv.clone()).map_err(|_e| {
            // TODO e as error source (as soon as we use core::error::Error).
            CoseCipherError::InvalidKeyParam(iana::OkpKeyParameter::Crv.into(), crv.clone())
        })?;

        // Check whether curve and key type are consistent (RFC 9053, Section 7.1)
        match crv {
            EllipticCurve::Assigned(
                iana::EllipticCurve::X448
                | iana::EllipticCurve::X25519
                | iana::EllipticCurve::Ed448
                | iana::EllipticCurve::Ed25519,
            ) => {}
            v => return Err(CoseCipherError::UnsupportedCurve(v)),
        }

        // Parse parameters d and x (private key and public key), must be of type bstr.
        let d = find_param_by_label(&Label::Int(iana::OkpKeyParameter::D.to_i64()), &key.params)
            .map(|v| match v.as_bytes() {
                None => Err(CoseCipherError::InvalidKeyParam(
                    iana::OkpKeyParameter::D.into(),
                    v.clone(),
                )),
                Some(b) => Ok(b.as_slice()),
            })
            .transpose()?;
        let x = find_param_by_label(&Label::Int(iana::OkpKeyParameter::X.to_i64()), &key.params)
            .map(|v| match v.as_bytes() {
                None => Err(CoseCipherError::InvalidKeyParam(
                    iana::OkpKeyParameter::X.into(),
                    v.clone(),
                )),
                Some(b) => Ok(b.as_slice()),
            })
            .transpose()?;

        // For public keys, at least X must be set, for private keys, at least D must be set.
        if d.is_none() && x.is_none() {
            return Err(CoseCipherError::MissingKeyParam(vec![
                iana::OkpKeyParameter::D.into(),
                iana::OkpKeyParameter::X.into(),
            ]));
        }

        Ok(CoseOkpKey {
            generic: key,
            crv,
            d,
            x,
            _backend_error_type: PhantomData,
        })
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseOkpKey<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        self.generic
    }
}

/// A parsed view into a symmetric [CoseKey].
#[derive(Clone, Debug, PartialEq)]
pub struct CoseSymmetricKey<'a, OE: Display> {
    /// Key that is referenced by this view.
    generic: &'a CoseKey,
    /// Key data of this key.
    pub k: &'a [u8],
    _backend_error_type: PhantomData<OE>,
}
impl<'a, OE: Display> TryFrom<&'a CoseKey> for CoseSymmetricKey<'a, OE> {
    type Error = CoseCipherError<OE>;

    fn try_from(key: &'a CoseKey) -> Result<Self, Self::Error> {
        // Unless stated otherwise, these checks are according to RFC 9053, Section 7.3.

        // Parse key value, must be of type bstr and be set.
        let k = find_param_by_label(
            &Label::Int(iana::SymmetricKeyParameter::K.to_i64()),
            &key.params,
        )
        .ok_or(CoseCipherError::MissingKeyParam(vec![
            iana::SymmetricKeyParameter::K.into(),
        ]))?;

        let k = k
            .as_bytes()
            .ok_or_else(|| {
                CoseCipherError::InvalidKeyParam(iana::SymmetricKeyParameter::K.into(), k.clone())
            })?
            .as_slice();

        Ok(CoseSymmetricKey {
            generic: key,
            k,
            _backend_error_type: PhantomData,
        })
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseSymmetricKey<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        self.generic
    }
}

/// A trait for types that can provide [CoseKey]s for COSE structure operations.
pub trait KeyProvider: Sized {
    /// Look up a key for the signature based on the provided `key_id` hint.
    ///
    /// The iterator returned should contain all [CoseKey]s of the provider that have a key ID
    /// matching the one provided, or all [CoseKey]s available if key_id is None.
    fn lookup_key(&self, key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>>;

    /// Create a [KeyProvider] filtering this key providers output for keys with key IDs
    /// matching the COSE structure's header.
    fn match_key_ids(self) -> KeyProviderFilterMatchingKeyId<Self> {
        KeyProviderFilterMatchingKeyId(self)
    }
}

// Unfortunately, this implementation is exclusive with the implementation for &CoseKey, because at
// some point, upstream coset may implement IntoIterator for &CoseKey, which would cause conflicting
// implementations.
// See https://github.com/rust-lang/rfcs/issues/2758
// One solution would be the specialization feature, which is unfortunately not stabilized yet.
// See: https://rust-lang.github.io/rfcs/1210-impl-specialization.html
/*impl<'a, T: IntoIterator<Item = &'a CoseKey> + Clone + 'a> CoseKeyProvider for &T {
    fn lookup_key(&mut self, key_id: Option<Vec<u8>>) -> impl Iterator<Item = &'a CoseKey> {
        let mut iter: Box<dyn Iterator<Item = &'a CoseKey>> = Box::new(self.clone().into_iter());

        if let Some(kid) = key_id {
            iter = Box::new(iter.filter(move |k| k.key_id.as_slice() == kid));
        }
        iter
    }
}*/

impl KeyProvider for Vec<&CoseKey> {
    fn lookup_key(&self, _key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        self.clone().into_iter()
    }
}

impl KeyProvider for Vec<CoseKey> {
    fn lookup_key(&self, _key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        self.iter()
    }
}

impl KeyProvider for Option<&CoseKey> {
    fn lookup_key(&self, _key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        self.iter().copied()
    }
}

impl KeyProvider for Option<CoseKey> {
    fn lookup_key(&self, _key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        self.iter()
    }
}

impl KeyProvider for CoseKey {
    fn lookup_key(&self, _key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        core::iter::once(self)
    }
}

/// [KeyProvider] that filters another [KeyProvider]s output to only output keys with
/// key IDs matching the ones provided in the COSE structure's headers.
pub struct KeyProviderFilterMatchingKeyId<T: KeyProvider>(T);

impl<T: KeyProvider> KeyProvider for KeyProviderFilterMatchingKeyId<T> {
    fn lookup_key(&self, key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        self.0.lookup_key(key_id).filter(move |k| {
            let k: &CoseKey = k.borrow();
            key_id.map_or(true, |lookup_kid| k.key_id.as_slice().eq(lookup_kid))
        })
    }
}

impl<T: KeyProvider> KeyProvider for &T {
    fn lookup_key(&self, key_id: Option<&[u8]>) -> impl Iterator<Item = impl Borrow<CoseKey>> {
        (*self).lookup_key(key_id)
    }
}

fn symmetric_key_size<BE: Display>(
    algorithm: iana::Algorithm,
) -> Result<usize, CoseCipherError<BE>> {
    match algorithm {
        iana::Algorithm::A128GCM
        | iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_64_128_128
        | iana::Algorithm::A128KW => Ok(16),
        iana::Algorithm::A192GCM | iana::Algorithm::A192KW => Ok(24),
        iana::Algorithm::A256GCM
        | iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_64_64_256
        | iana::Algorithm::AES_CCM_16_128_256
        | iana::Algorithm::AES_CCM_64_128_256
        | iana::Algorithm::A256KW => Ok(32),
        _ => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            algorithm,
        ))),
    }
}

pub(crate) fn ensure_valid_aes_key<BE: Display>(
    algorithm: iana::Algorithm,
    parsed_key: CoseParsedKey<BE>,
) -> Result<CoseSymmetricKey<BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 4.1 and 4.2.

    // Key type must be symmetric.
    let symm_key = if let CoseParsedKey::Symmetric(symm_key) = parsed_key {
        symm_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            Algorithm::Assigned(algorithm),
        ));
    };

    // Algorithm in key must match algorithm to use.
    if let Some(key_alg) = &symm_key.as_ref().alg {
        if key_alg != &Algorithm::Assigned(algorithm) {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                key_alg.clone(),
                Algorithm::Assigned(algorithm),
            ));
        }
    }

    // For algorithms that we know, check the key length (would lead to a cipher error later on).
    let key_len = symmetric_key_size(algorithm)?;
    if symm_key.k.len() != key_len {
        return Err(CoseCipherError::InvalidKeyParam(
            KeyParam::Symmetric(iana::SymmetricKeyParameter::K),
            Value::Bytes(symm_key.k.to_vec()),
        ));
    }

    Ok(symm_key)
}

pub(crate) fn generate_cek_for_alg<B: CryptoBackend>(
    backend: &mut B,
    alg: iana::Algorithm,
) -> Result<Vec<u8>, CoseCipherError<B::Error>> {
    match alg {
        iana::Algorithm::A128GCM
        | iana::Algorithm::AES_CCM_16_64_128
        | iana::Algorithm::AES_CCM_64_64_128
        | iana::Algorithm::AES_CCM_16_128_128
        | iana::Algorithm::AES_CCM_64_128_128
        | iana::Algorithm::A192GCM
        | iana::Algorithm::A256GCM
        | iana::Algorithm::AES_CCM_16_64_256
        | iana::Algorithm::AES_CCM_64_64_256
        | iana::Algorithm::AES_CCM_16_128_256
        | iana::Algorithm::AES_CCM_64_128_256 => {
            let key_len = symmetric_key_size(alg)?;
            let mut key = vec![0u8; key_len];
            backend.generate_rand(key.as_mut_slice())?;
            Ok(key)
        }
        v => Err(CoseCipherError::UnsupportedAlgorithm(Algorithm::Assigned(
            v,
        ))),
    }
}

pub(crate) fn ensure_valid_ecdsa_key<BE: Display>(
    algorithm: iana::Algorithm,
    parsed_key: CoseParsedKey<BE>,
    key_should_be_private: bool,
) -> Result<CoseEc2Key<BE>, CoseCipherError<BE>> {
    // Checks according to RFC 9053, Section 2.1 or RFC 8812, Section 3.2.

    // Key type must be EC2
    let ec2_key = if let CoseParsedKey::Ec2(ec2_key) = parsed_key {
        ec2_key
    } else {
        return Err(CoseCipherError::KeyTypeAlgorithmMismatch(
            parsed_key.as_ref().kty.clone(),
            Algorithm::Assigned(algorithm),
        ));
    };

    // If algorithm in key is set, it must match our algorithm
    if let Some(key_alg) = &ec2_key.as_ref().alg {
        if key_alg != &Algorithm::Assigned(algorithm) {
            return Err(CoseCipherError::KeyAlgorithmMismatch(
                key_alg.clone(),
                Algorithm::Assigned(algorithm),
            ));
        }
    }

    // Key must contain private key information to perform signature, and either D or X and Y to
    // verify a signature.
    if key_should_be_private && ec2_key.d.is_none() {
        return Err(CoseCipherError::MissingKeyParam(vec![
            iana::Ec2KeyParameter::D.into(),
        ]));
    } else if !key_should_be_private && ec2_key.d.is_none() {
        if ec2_key.x.is_none() {
            return Err(CoseCipherError::MissingKeyParam(vec![
                iana::Ec2KeyParameter::X.into(),
            ]));
        }
        if ec2_key.y.is_none() {
            return Err(CoseCipherError::MissingKeyParam(vec![
                iana::Ec2KeyParameter::Y.into(),
            ]));
        }
    }

    Ok(ec2_key)
}
