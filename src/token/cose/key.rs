use crate::error::CoseCipherError;
use crate::token::cose::header_util::find_param_by_label;
use ciborium::Value;
use core::borrow::BorrowMut;
use core::fmt::Display;
use coset::iana::EnumI64;
use coset::{
    iana, AsCborValue, CoseKey, EncryptionContext, Header, KeyType, Label,
    RegisteredLabelWithPrivate,
};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyParam {
    Common(iana::KeyParameter),
    Ec2(iana::Ec2KeyParameter),
    Okp(iana::OkpKeyParameter),
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

pub enum CoseParsedKey<'a, OE: Display> {
    Ec2(CoseEc2Key<'a, OE>),
    Okp(CoseOkpKey<'a, OE>),
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

pub type EllipticCurve = RegisteredLabelWithPrivate<iana::EllipticCurve>;

#[derive(Clone, Debug, PartialEq)]
pub struct CoseEc2Key<'a, OE: Display> {
    generic: &'a CoseKey,
    pub crv: EllipticCurve,
    pub d: Option<&'a [u8]>,
    pub x: Option<&'a [u8]>,
    pub y: Option<&'a [u8]>,
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
        .ok_or(CoseCipherError::MissingKeyParam(
            iana::Ec2KeyParameter::Crv.into(),
        ))?;
        // Curve must be of correct type
        let crv = EllipticCurve::from_cbor_value(crv.clone()).map_err(|e| {
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

        // Parse parameters y (other half of public key), is either a bstr containing the Y
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
            return Err(CoseCipherError::MissingKeyParam(
                iana::Ec2KeyParameter::D.into(),
            ));
        }

        Ok(CoseEc2Key {
            generic: key,
            crv,
            d,
            x,
            y,
            sign,
            _backend_error_type: Default::default(),
        })
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseEc2Key<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        self.generic
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoseOkpKey<'a, OE: Display> {
    generic: &'a CoseKey,
    pub crv: EllipticCurve,
    pub d: Option<&'a [u8]>,
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
        .ok_or(CoseCipherError::MissingKeyParam(
            iana::Ec2KeyParameter::Crv.into(),
        ))?;

        // Curve must be of correct type
        let crv = EllipticCurve::from_cbor_value(crv.clone()).map_err(|e| {
            CoseCipherError::InvalidKeyParam(iana::Ec2KeyParameter::Crv.into(), crv.clone())
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
            return Err(CoseCipherError::MissingKeyParam(
                iana::OkpKeyParameter::D.into(),
            ));
        }

        Ok(CoseOkpKey {
            generic: key,
            crv,
            d,
            x,
            _backend_error_type: Default::default(),
        })
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseOkpKey<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        self.generic
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoseSymmetricKey<'a, OE: Display> {
    generic: &'a CoseKey,
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
        .ok_or(CoseCipherError::MissingKeyParam(
            iana::SymmetricKeyParameter::K.into(),
        ))?;

        let k = k
            .as_bytes()
            .ok_or_else(|| {
                CoseCipherError::InvalidKeyParam(iana::SymmetricKeyParameter::K.into(), k.clone())
            })?
            .as_slice();

        Ok(CoseSymmetricKey {
            generic: key,
            k,
            _backend_error_type: Default::default(),
        })
    }
}

impl<'a, OE: Display> AsRef<CoseKey> for CoseSymmetricKey<'a, OE> {
    fn as_ref(&self) -> &CoseKey {
        self.generic
    }
}

pub trait CoseKeyProvider {
    /// Look up a key for the signature based on the provided Key ID hint.
    ///
    /// The iterator returned should contain all [CoseKey]s of the provider that have a key ID
    /// matching the one provided, or all [CoseKey]s available if key_id is None.
    fn lookup_key(&mut self, key_id: Option<&[u8]>) -> impl Iterator<Item = CoseKey>;
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

impl CoseKeyProvider for &Vec<&CoseKey> {
    fn lookup_key(&mut self, key_id: Option<&[u8]>) -> impl Iterator<Item = CoseKey> {
        let mut iter: Box<dyn Iterator<Item = &CoseKey>> = Box::new(self.clone().into_iter());
        if let Some(kid) = key_id {
            let test = Vec::from(kid);
            iter = Box::new(iter.filter(move |k| k.key_id.as_slice() == test));
        }
        iter.cloned()
    }
}

impl CoseKeyProvider for &Vec<CoseKey> {
    fn lookup_key(&mut self, key_id: Option<&[u8]>) -> impl Iterator<Item = CoseKey> {
        let mut iter: Box<dyn Iterator<Item = &CoseKey>> = Box::new(self.iter());

        if let Some(kid) = key_id {
            let kid = Vec::from(kid);
            iter = Box::new(iter.filter(move |k| k.key_id.as_slice() == kid));
        }
        iter.cloned()
    }
}

impl CoseKeyProvider for Option<&CoseKey> {
    fn lookup_key(&mut self, key_id: Option<&[u8]>) -> impl Iterator<Item = CoseKey> {
        let ret: Box<dyn Iterator<Item = &CoseKey>> = match (self, &key_id) {
            (Some(key), Some(key_id)) if key.key_id.as_slice() != *key_id => {
                Box::new(std::iter::empty())
            }
            (Some(key), Some(key_id)) => Box::new(std::iter::once(*key)),
            (v, _) => Box::new(v.iter().copied()),
        };
        ret.cloned()
    }
}

impl CoseKeyProvider for &CoseKey {
    fn lookup_key(&mut self, _key_id: Option<&[u8]>) -> impl Iterator<Item = CoseKey> {
        std::iter::once(self.clone())
    }
}

pub trait CoseAadProvider: BorrowMut<Self> {
    /// Look up the additional authenticated data to verify for a given signature.
    fn lookup_aad(
        &mut self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> &[u8];
}

// See above, impossible due to missing specialization feature.
/*impl<'a, T: Iterator<Item = &'a [u8]>> CoseAadProvider for &mut T {
    fn lookup_aad(&mut self, _signature: &CoseSignature) -> &'a [u8] {
        self.next().map(|v| v.as_ref()).unwrap_or(&[] as &[u8])
    }
}*/

impl CoseAadProvider for &[u8] {
    fn lookup_aad(
        &mut self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> &[u8] {
        match context {
            Some(EncryptionContext::CoseEncrypt | EncryptionContext::CoseEncrypt0) | None => self,
            Some(
                EncryptionContext::EncRecipient
                | EncryptionContext::MacRecipient
                | EncryptionContext::RecRecipient,
            ) => &[] as &[u8],
        }
    }
}

impl CoseAadProvider for Option<&[u8]> {
    fn lookup_aad(
        &mut self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> &[u8] {
        match context {
            Some(EncryptionContext::CoseEncrypt | EncryptionContext::CoseEncrypt0) | None => {
                self.unwrap_or(&[] as &[u8])
            }
            Some(
                EncryptionContext::EncRecipient
                | EncryptionContext::MacRecipient
                | EncryptionContext::RecRecipient,
            ) => &[] as &[u8],
        }
    }
}

impl<'a, 'b: 'a> CoseAadProvider for std::slice::Iter<'a, &'b [u8]> {
    fn lookup_aad(
        &mut self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> &[u8] {
        match context {
            Some(EncryptionContext::CoseEncrypt | EncryptionContext::CoseEncrypt0) | None => {
                self.next().copied().unwrap_or(&[] as &[u8])
            }
            Some(
                EncryptionContext::EncRecipient
                | EncryptionContext::MacRecipient
                | EncryptionContext::RecRecipient,
            ) => &[] as &[u8],
        }
    }
}

impl<'a, 'b: 'a, I: Iterator, F> CoseAadProvider for &'a mut std::iter::Map<I, F>
where
    F: FnMut(I::Item) -> &'b [u8],
{
    fn lookup_aad(
        &mut self,
        context: Option<EncryptionContext>,
        protected: Option<&Header>,
        unprotected: Option<&Header>,
    ) -> &[u8] {
        match context {
            Some(EncryptionContext::CoseEncrypt | EncryptionContext::CoseEncrypt0) | None => {
                self.next().unwrap_or(&[] as &[u8])
            }
            Some(
                EncryptionContext::EncRecipient
                | EncryptionContext::MacRecipient
                | EncryptionContext::RecRecipient,
            ) => &[] as &[u8],
        }
    }
}
