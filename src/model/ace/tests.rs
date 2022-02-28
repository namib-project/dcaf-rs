/// Tests for Scopes.
mod scope {
    /// Tests for text encoded scopes.
    mod text {
        use crate::ace::TextEncodedScope;
        use crate::error::{InvalidTextEncodedScopeError, WrongSourceTypeError};

        #[test]
        fn test_scope_element_normal() -> Result<(), InvalidTextEncodedScopeError> {
            let simple = TextEncodedScope::try_from("this is a test")?;
            assert!(simple.elements().eq(vec!["this", "is", "a", "test"]));

            let single = TextEncodedScope::try_from("single")?;
            assert!(single.elements().eq(vec!["single"]));

            let third = TextEncodedScope::try_from("another quick test")?;
            assert!(third.elements().eq(vec!["another", "quick", "test"]));

            let array = TextEncodedScope::try_from(vec!["array", "test"])?;
            assert!(array.elements().eq(vec!["array", "test"]));

            let array_single = TextEncodedScope::try_from(vec!["justme"])?;
            assert!(array_single.elements().eq(vec!["justme"]));
            Ok(())
        }

        #[test]
        fn test_scope_elements_empty() {
            let empty_inputs: Vec<&str> = vec!["    ", " ", ""];

            for input in empty_inputs {
                assert!(TextEncodedScope::try_from(input).is_err())
            }

            let empty_arrays: Vec<Vec<&str>> = vec![
                vec![],
                vec![""],
                vec![" "],
                vec!["   "],
                vec!["", ""],
                vec!["", " "],
                vec!["", "   "],
                vec![" ", " "],
                vec![" ", ""],
                vec![" ", "   "],
                vec!["   ", "   "],
                vec!["   ", " "],
                vec!["   ", ""],
            ];

            for input in empty_arrays {
                assert!(TextEncodedScope::try_from(input).is_err())
            }
        }

        #[test]
        fn test_scope_elements_invalid_spaces() {
            let invalid_inputs = vec![
                "space at the end ",
                "spaces at the end   ",
                " space at the start",
                "   spaces at the start",
                " spaces at both ends ",
                "   spaces at both ends    ",
                "spaces   in the       middle",
                "   spaces   wherever  you    look   ",
            ];
            for input in invalid_inputs {
                assert!(TextEncodedScope::try_from(input).is_err())
            }
        }

        #[test]
        fn test_scope_elements_invalid_characters() {
            let invalid_inputs = vec![
                "\"",
                "\\",
                "a \" in between",
                "a \\ in between",
                " \" ",
                " \\ ",
                "within\"word",
                "within\\word",
            ];
            for input in invalid_inputs {
                assert!(TextEncodedScope::try_from(input).is_err())
            }

            let invalid_arrays = vec![
                vec!["space within"],
                vec!["more spaces within"],
                vec!["normal", "array", "but space"],
                vec!["normal", "but space", "array"],
                vec!["but space", "normal", "array"],
                vec!["\""],
                vec!["\\"],
                vec!["\"\\"],
                vec!["\" \\"],
                vec!["\\ \\"],
                vec!["\" \""],
                vec!["\\", "\\"],
                vec!["\"", "\""],
                vec!["\\", "\""],
                vec!["\"", "\\"],
                vec!["normal", "\\", "almost"],
                vec!["normal", "\"", "allowed"],
                vec!["normal", "in\"word\""],
                vec!["normal", "in\\word"],
            ];
            for input in invalid_arrays {
                assert!(TextEncodedScope::try_from(input).is_err())
            }
        }
    }

    /// Tests for binary encoded scopes.
    mod binary {
        use crate::ace::BinaryEncodedScope;
        use crate::error::InvalidBinaryEncodedScopeError;

        #[test]
        fn test_scope_elements_normal() -> Result<(), InvalidBinaryEncodedScopeError> {
            let single = BinaryEncodedScope::try_from(vec![0].as_slice())?;
            assert!(single.elements(0x20)?.eq(vec![vec![0]]));

            let simple1 = BinaryEncodedScope::try_from(vec![0, 1, 2].as_slice())?;
            assert!(simple1.elements(0x20)?.eq(vec![vec![0, 1, 2]]));
            assert!(simple1.elements(1)?.eq(vec![vec![0], vec![2]]));

            let simple2 = BinaryEncodedScope::try_from(vec![0xDC, 0x20, 0xAF].as_slice())?;
            assert!(simple2.elements(0x20)?.eq(vec![vec![0xDC], vec![0xAF]]));
            assert!(simple2.elements(0)?.eq(vec![vec![0xDC, 0x20, 0xAF]]));

            let simple3 = BinaryEncodedScope::try_from(vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0xDC, 0xAF, 0, 1].as_slice())?;
            assert!(simple3.elements(0)?.eq(vec![vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0xDC, 0xAF], vec![1]]));
            assert!(simple3.elements(0xEF)?.eq(vec![vec![0xDE, 0xAD, 0xBE], vec![0, 0xDC, 0xAF, 0, 1]]));
            assert!(simple3.elements(2)?.eq(vec![vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0xDC, 0xAF, 0, 1]]));
            Ok(())
        }

        #[test]
        fn test_scope_elements_empty() -> Result<(), InvalidBinaryEncodedScopeError> {
            assert!(BinaryEncodedScope::try_from(vec![].as_slice()).is_err());
            // Assuming 0 is separator
            let empty_vecs = vec![
                vec![0], vec![0, 0], vec![0, 0, 0],
            ];
            for vec in empty_vecs {
                assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(0).is_err());
                // If the separator is something else, the result should just contain the vec
                // as a single element.
                assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(1)?.eq(vec![vec]));
            }
            Ok(())
        }

        #[test]
        fn test_scope_elements_invalid_separators() -> Result<(), InvalidBinaryEncodedScopeError> {
            // Assuming 0 is separator
            let invalid = vec![
                vec![0xDC, 0xAF, 0],
                vec![0xDC, 0xAF, 0, 0],
                vec![0, 0xDC, 0xAF],
                vec![0, 0, 0xDC, 0xAF],
                vec![0, 0xDC, 0xAF, 0],
                vec![0, 0, 0xDC, 0xAF, 0, 0],
                vec![0, 0, 0xDC, 0xAF, 0, 0],
                vec![0xDC, 0, 0, 0xAF],
                vec![0, 0xDC, 0, 0xAF, 0],
                vec![0, 0, 0xDC, 0, 0xAF, 0],
                vec![0, 0xDC, 0, 0, 0xAF, 0],
                vec![0, 0xDC, 0, 0xAF, 0, 0],
                vec![0, 0, 0xDC, 0, 0, 0xAF, 0, 0],
            ];
            for vec in invalid {
                assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(0).is_err());
                // If the separator is something else, the result should just contain the vec
                // as a single element.
                assert!(BinaryEncodedScope::try_from(vec.as_slice())?.elements(1)?.eq(vec![vec]));
            }
            Ok(())
        }
    }
}

/// Tests for CBOR serialization and deserialization of ACE-OAuth data models.
mod serde {
    use ciborium::de::from_reader;
    use ciborium::ser::into_writer;
    use coset::{
        CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder, iana,
        ProtectedHeader,
    };
    use coset::iana::Algorithm;

    use crate::ace::AceProfile::CoapDtls;
    use crate::error::InvalidTextEncodedScopeError;
    use crate::model::cbor_map::CborMap;
    use crate::model::cbor_values::ByteString;

    use super::super::*;

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
        let hint = CborMap(
            AuthServerRequestCreationHintBuilder::default()
                .auth_server("coaps://as.example.com/token")
                .audience("coaps://rs.example.com")
                .scope(TextEncodedScope::try_from("rTempC").map_err(|x| x.to_string())?)
                .client_nonce(hex::decode("e0a156bb3f").map_err(|x| x.to_string())?)
                .build()
                .map_err(|x| x.to_string())?,
        );
        test_ser_de!(hint => "a401781c636f6170733a2f2f61732e6578616d706c652e636f6d2f746f6b656e0576636f6170733a2f2f72732e6578616d706c652e636f6d09667254656d7043182745e0a156bb3f")
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 5.
    #[test]
    fn test_access_token_request_symmetric() -> Result<(), String> {
        let request = CborMap(
            AccessTokenRequestBuilder::default()
                .client_id("myclient")
                .audience("tempSensor4711")
                .build()
                .map_err(|x| x.to_string())?,
        );
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
        let request = CborMap(
            AccessTokenRequestBuilder::default()
                .client_id("myclient")
                .req_cnf(key)
                .build()
                .map_err(|x| x.to_string())?,
        );
        test_ser_de!(request => "A204A101A501020241112001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E1818686D79636C69656E74")
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 7.
    #[test]
    fn test_access_token_request_reference() -> Result<(), String> {
        let request = CborMap(
            AccessTokenRequestBuilder::default()
                .client_id("myclient")
                .audience("valve424")
                .scope(TextEncodedScope::try_from("read").map_err(|x| x.to_string())?)
                .req_cnf(ByteString::from(vec![
                    0xea, 0x48, 0x34, 0x75, 0x72, 0x4c, 0xd7, 0x75,
                ]))
                .build()
                .map_err(|x| x.to_string())?,
        );
        test_ser_de!(request => "A404A10348EA483475724CD775056876616C76653432340964726561641818686D79636C69656E74")
    }

    #[test]
    fn test_access_token_request_encrypted() -> Result<(), String> {
        let unprotected_header = HeaderBuilder::new()
            .iv(vec![
                0x63, 0x68, 0x98, 0x99, 0x4F, 0xF0, 0xEC, 0x7B, 0xFC, 0xF6, 0xD3, 0xF9, 0x5B,
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
        let request = CborMap(
            AccessTokenRequestBuilder::default()
                .client_id("myclient")
                .req_cnf(encrypted)
                .build()
                .map_err(|x| x.to_string())?,
        );

        // Extract relevant part for comparison (i.e. no protected headers' original data,
        // which can change after serialization)
        fn transform_header(mut request: AccessTokenRequest) -> AccessTokenRequest {
            let enc: CoseEncrypt0 = request
                .req_cnf
                .expect("No req_cnf present")
                .try_into()
                .expect("Key is not encrypted");
            request.req_cnf = Some(ProofOfPossessionKey::EncryptedCoseKey(CoseEncrypt0 {
                protected: ProtectedHeader {
                    original_data: None,
                    ..enc.protected
                },
                ..enc
            }));
            request
        }

        test_ser_de!(request; transform_header => "A204A1028343A1010AA1054D636898994FF0EC7BFCF6D3F95B58300573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F1818686D79636C69656E74")
    }

    #[test]
    fn test_access_token_request_other_fields() -> Result<(), String> {
        let request = CborMap(
            AccessTokenRequestBuilder::default()
                .client_id("myclient")
                .redirect_uri("coaps://server.example.com")
                .grant_type(GrantType::ClientCredentials)
                .ace_profile()
                .client_nonce(vec![0, 1, 2, 3, 4])
                .build()
                .map_err(|x| x.to_string())?,
        );
        test_ser_de!(request => "A51818686D79636C69656E74181B781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D1821021826F61827450001020304")
    }

    #[test]
    fn test_access_token_response() -> Result<(), String> {
        let key = CoseKeyBuilder::new_symmetric_key(vec![
            0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c,
            0x42, 0x71, 0x08,
        ])
            .key_id(vec![0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c])
            .build();
        // We need to specify this here because otherwise it'd be typed as an i32.
        let expires_in: u32 = 3600;
        let response = CborMap(
            AccessTokenResponseBuilder::default()
                .access_token(hex::decode("4a5015df686428").map_err(|x| x.to_string())?)
                .ace_profile(CoapDtls)
                .expires_in(expires_in)
                .cnf(key)
                .build()
                .map_err(|x| x.to_string())?,
        );
        test_ser_de!(response => "A401474A5015DF68642802190E1008A101A301040246849B5786457C2051849B5786457C1491BE3A76DCEA6C427108182601")
    }
}
