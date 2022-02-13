use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use ciborium::value::Value;
use erased_serde::Serialize as ErasedSerialize;

use crate::model::cbor_values::ProofOfPossessionKey;

use super::cbor_map::AsCborMap;
use super::cbor_values::{ByteString, TextOrByteString};

// Macro adapted from https://github.com/enarx/ciborium/blob/main/ciborium/tests/macro.rs#L13
macro_rules! cbor_map_vec {
   ($($key:expr => $val:expr),* $(,)*) => {
        vec![$(
            (
                $key,
                $val.map(|x| {
                        // It's unclear to me why `Box::<dyn ErasedSerialize>` doesn't work.
                        let a_box: Box<dyn ErasedSerialize> = Box::new(x);
                        a_box
                        // Box::<dyn ErasedSerialize>::new(x)
                    })
            )
        ),*]
    };
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct AuthServerRequestCreationHint {
    auth_server: Option<String>,
    kid: Option<ByteString>,
    audience: Option<String>,
    scope: Option<TextOrByteString>,
    client_nonce: Option<ByteString>,
}

impl AsCborMap for AuthServerRequestCreationHint {
    fn as_cbor_map(&self) -> Vec<(u16, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            1 => self.auth_server.as_ref(),
            2 => self.kid.as_ref(),
            5 => self.audience.as_ref(),
            9 => self.scope.as_ref(),
            39 => self.client_nonce.as_ref()
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut hint = AuthServerRequestCreationHint::default();
        for entry in map {
            match (entry.0, entry.1) {
                (1, Value::Text(x)) => hint.auth_server = Some(x),
                (2, Value::Bytes(x)) => hint.kid = Some(ByteString::from(x)),
                (5, Value::Text(x)) => hint.audience = Some(x),
                (9, Value::Text(x)) => hint.scope = Some(TextOrByteString::from(x)),
                (9, Value::Bytes(x)) => hint.scope = Some(TextOrByteString::from(x)),
                (39, Value::Bytes(x)) => hint.client_nonce = Some(ByteString::from(x)),
                (_, _) => return None,
            };
        }
        Some(hint)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct AccessTokenRequest {
    /// Grant type used for this request. Defaults to `client_credentials`.
    grant_type: Option<u32>,

    /// The logical name of the target service where the client intends to use the requested security token.
    audience: Option<String>,

    /// URI to redirect the client to after authorization is complete.
    redirect_uri: Option<String>,

    /// Client nonce to ensure the token is still fresh.
    client_nonce: Option<ByteString>,

    /// Scope of the access request as described by section 3.3 of RFC 6749.
    scope: Option<TextOrByteString>,

    /// Included in the request if the AS shall include the `ace_profile` parameter in its
    /// response.
    ace_profile: Option<()>,

    /// Contains information about the key the client would like to bind to the
    /// access token for proof-of-possession.
    req_cnf: Option<ProofOfPossessionKey>,

    /// The client identifier as described in section 2.2 of RFC 6749.
    client_id: String,
}

impl AsCborMap for AccessTokenRequest {
    fn as_cbor_map(&self) -> Vec<(u16, Option<Box<dyn ErasedSerialize + '_>>)> {
        cbor_map_vec! {
            4 => self.req_cnf.as_ref().map(|x| x.to_ciborium_map()),
            5 => self.audience.as_ref(),
            9 => self.scope.as_ref(),
            24 => Some(&self.client_id),
            27 => self.redirect_uri.as_ref(),
            33 => self.grant_type.as_ref(),
            38 => self.ace_profile.as_ref(),
            39 => self.client_nonce.as_ref(),
        }
    }

    fn try_from_cbor_map(map: Vec<(i128, Value)>) -> Option<Self>
    where
        Self: Sized + AsCborMap,
    {
        let mut request = AccessTokenRequest::default();
        for entry in map {
            match (entry.0, entry.1) {
                (4, Value::Map(x)) => {
                    if let Ok(pop_map) = Self::cbor_map_from_int(x) {
                        request.req_cnf = ProofOfPossessionKey::try_from_cbor_map(pop_map)
                    } else {
                        return None;
                    }
                }
                (5, Value::Text(x)) => request.audience = Some(x),
                (9, Value::Text(x)) => request.scope = Some(TextOrByteString::TextString(x)),
                (9, Value::Bytes(x)) => {
                    request.scope = Some(TextOrByteString::ByteString(ByteString::from(x)))
                }
                (24, Value::Text(x)) => request.client_id = x,
                (27, Value::Text(x)) => request.redirect_uri = Some(x),
                (33, Value::Integer(x)) => {
                    if let Ok(i) = x.try_into() {
                        request.grant_type = Some(i)
                    } else {
                        return None;
                    }
                }
                (38, Value::Null) => request.ace_profile = Some(()),
                (39, Value::Bytes(x)) => request.client_nonce = Some(ByteString::from(x)),
                (_, _) => return None,
            };
        }
        Some(request)
    }
}

pub struct AccessTokenResponse {
    // TODO
}

// TODO: Introspection data structures

#[cfg(test)]
mod tests {
    use ciborium::de::from_reader;
    use ciborium::ser::{into_writer};
    use coset::{CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana, ProtectedHeader};
    use coset::iana::Algorithm;

    use crate::model::cbor_map::CborMap;
    use crate::model::cbor_values::{ByteString, TextOrByteString};

    use super::*;

    macro_rules! test_ser_de {
        ($value:ident$(;$transform_value:expr)? => $hex:literal) => {{
            let mut result = Vec::new();
            into_writer(&$value, &mut result).map_err(|x| x.to_string())?;
            #[cfg(feature = "std")]
            println!(
                "Result: {:?}, Original: {:?}",
                hex::encode(&result),
                &$value
            );
            assert_eq!(result, hex::decode($hex).map_err(|x| x.to_string())?);
            let decoded = from_reader(&result[..]).map_err(|x| x.to_string());
            if let Ok(CborMap(decoded_value)) = decoded {
                $(let decoded_value = $transform_value(decoded_value);)?
                assert_eq!(*$value, decoded_value);
                Ok(())
            } else if let Err(e) = decoded {
                return Err(e);
            } else {
                return Err("Invalid value: Not a CBOR map!".to_string());
            }
        }};
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 3 and 4.
    #[test]
    fn test_creation_hint() -> Result<(), String> {
        let hint = CborMap(AuthServerRequestCreationHint {
            auth_server: Some("coaps://as.example.com/token".to_string()),
            audience: Some("coaps://rs.example.com".to_string()),
            scope: Some(TextOrByteString::TextString("rTempC".to_string())),
            client_nonce: Some(ByteString::from(
                hex::decode("e0a156bb3f").map_err(|x| x.to_string())?,
            )),
            ..Default::default()
        });
        test_ser_de!(hint => "a401781c636f6170733a2f2f61732e6578616d706c652e636f6d2f746f6b656e0576636f6170733a2f2f72732e6578616d706c652e636f6d09667254656d7043182745e0a156bb3f")
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 5.
    #[test]
    fn test_access_token_request_symmetric() -> Result<(), String> {
        let request = CborMap(AccessTokenRequest {
            client_id: "myclient".to_string(),
            audience: Some("tempSensor4711".to_string()),
            ..Default::default()
        });
        test_ser_de!(request => "A2056E74656D7053656E736F72343731311818686D79636C69656E74")
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 6.
    #[test]
    fn test_access_token_request_asymmetric() -> Result<(), String> {
        let key = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            vec![
                0xba, 0xc5, 0xb1, 0x1c, 0xad, 0x8f, 0x99, 0xf9, 0xc7, 0x2b, 0x05, 0xcf, 0x4b, 0x9e,
                0x26, 0xd2, 0x44, 0xdc, 0x18, 0x9f, 0x74, 0x52, 0x28, 0x25, 0x5a, 0x21, 0x9a, 0x86,
                0xd6, 0xa0, 0x9e, 0xff,
            ],
            vec![
                0x20, 0x13, 0x8b, 0xf8, 0x2d, 0xc1, 0xb6, 0xd5, 0x62, 0xbe, 0x0f, 0xa5, 0x4a, 0xb7,
                0x80, 0x4a, 0x3a, 0x64, 0xb6, 0xd7, 0x2c, 0xcf, 0xed, 0x6b, 0x6f, 0xb6, 0xed, 0x28,
                0xbb, 0xfc, 0x11, 0x7e,
            ],
        )
        .key_id(vec![0x11])
        .build();
        let request = CborMap(AccessTokenRequest {
            client_id: "myclient".to_string(),
            req_cnf: Some(ProofOfPossessionKey::CoseKey(key)),
            ..Default::default()
        });
        test_ser_de!(request => "A204A101A501020241112001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E1818686D79636C69656E74")
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 7.
    #[test]
    fn test_access_token_request_reference() -> Result<(), String> {
        let request = CborMap(AccessTokenRequest {
            client_id: "myclient".to_string(),
            audience: Some("valve424".to_string()),
            scope: Some(TextOrByteString::from("read".to_string())),
            req_cnf: Some(ProofOfPossessionKey::KeyId(ByteString::from(vec![
                0xea, 0x48, 0x34, 0x75, 0x72, 0x4c, 0xd7, 0x75,
            ]))),
            ..Default::default()
        });
        test_ser_de!(request => "A404A10348EA483475724CD775056876616C76653432340964726561641818686D79636C69656E74")
    }

    #[test]
    fn test_access_token_request_encrypted() -> Result<(), String> {
        let unprotected_header = HeaderBuilder::new()
            .iv(vec![
                    0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC, 0x7B, 0xFC, 0xF6, 0xD3, 0xF9,
                    0x5B,
                ])
            .build();
        let protected_header = HeaderBuilder::new()
            .algorithm(Algorithm::AES_CCM_16_64_128)
            .build();
        let encrypted = CoseEncrypt0Builder::new()
            .protected(protected_header)
            .unprotected(unprotected_header)
            .ciphertext(vec![
                0x05, 0x73, 0x31, 0x8A, 0x35, 0x73, 0xEB, 0x98, 0x3E, 0x55, 0xA7, 0xC2, 0xF0, 0x6C,
                0xAD, 0xD0, 0x79, 0x6C, 0x9E, 0x58, 0x4F, 0x1D, 0x0E, 0x3E, 0xA8, 0xC5, 0xB0, 0x52,
                0x59, 0x2A, 0x8B, 0x26, 0x94, 0xBE, 0x96, 0x54, 0xF0, 0x43, 0x1F, 0x38, 0xD5, 0xBB,
                0xC8, 0x04, 0x9F, 0xA7, 0xF1, 0x3F,
            ])
            .build();
        assert_eq!(hex::encode_upper(encrypted.clone().to_vec().map_err(|x| x.to_string())?),
                   "8343A1010AA1054D636898994FF0EC7BFCF6D3F95B58300573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F");
        let request = CborMap(AccessTokenRequest {
            client_id: "myclient".to_string(),
            req_cnf: Some(ProofOfPossessionKey::EncryptedCoseKey(Box::new(encrypted))),
            ..Default::default()
        });

        // Extract relevant part for comparison (i.e. no protected headers' original data,
        // which can change after serialization)
        fn transform_header(mut request: AccessTokenRequest) -> AccessTokenRequest {
            let enc = request.req_cnf
                .expect( "No req_cnf present")
                .try_as_encrypted_cose_key()
                .expect("Key is not encrypted")
                .clone();
            request.req_cnf = Some(ProofOfPossessionKey::EncryptedCoseKey(Box::new(
                CoseEncrypt0 {
                    protected: ProtectedHeader {
                        original_data: None,
                        ..enc.protected
                    },
                    ..enc
                }
            )));
            request
        }

        test_ser_de!(request; transform_header => "A204A1028343A1010AA1054D636898994FF0EC7BFCF6D3F95B58300573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F1818686D79636C69656E74")
    }

    #[test]
    fn test_access_token_other_fields() -> Result<(), String> {
        let request = CborMap(AccessTokenRequest {
            client_id: "myclient".to_string(),
            redirect_uri: Some("coaps://server.example.com".to_string()),
            grant_type: Some(2),
            ace_profile: Some(()),
            client_nonce: Some(ByteString::from(vec![0, 1, 2, 3, 4])),
            ..Default::default()
        });
        test_ser_de!(request => "A51818686D79636C69656E74181B781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D1821021826F61827450001020304")
    }
}
