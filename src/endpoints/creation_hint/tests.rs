/// Tests for CBOR serialization and deserialization of ACE-OAuth data models.
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana,
    ProtectedHeader,
};
use coset::iana::Algorithm;

use crate::common::scope::TextEncodedScope;
use crate::common::test_helper::expect_ser_de;
use crate::error::InvalidTextEncodedScopeError;

use super::*;

/// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 3 and 4.
#[test]
fn test_creation_hint() -> Result<(), String> {
    let hint = AuthServerRequestCreationHintBuilder::default()
        .auth_server("coaps://as.example.com/token")
        .audience("coaps://rs.example.com")
        .scope(TextEncodedScope::try_from("rTempC").map_err(|x| x.to_string())?)
        .client_nonce(hex::decode("e0a156bb3f").map_err(|x| x.to_string())?)
        .build()
        .map_err(|x| x.to_string())?;
    expect_ser_de(hint, None, "a401781c636f6170733a2f2f61732e6578616d706c652e636f6d2f746f6b656e0576636f6170733a2f2f72732e6578616d706c652e636f6d09667254656d7043182745e0a156bb3f")
}

