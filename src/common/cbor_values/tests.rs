/*
 * Copyright (c) 2022 The NAMIB Project Developers.
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

mod pop {
    use alloc::{string::String, string::ToString, vec};
    use core::marker::PhantomData;

    use ciborium::value::Value;
    use coset::iana::Algorithm;
    use coset::{
        iana, CoseEncrypt0, CoseEncrypt0Builder, CoseKey, CoseKeyBuilder, HeaderBuilder,
        ProtectedHeader,
    };

    use crate::common::cbor_values::KeyId;
    use crate::common::test_helper::expect_ser_de;
    use crate::error::WrongSourceTypeError;
    use crate::ProofOfPossessionKey::{EncryptedCoseKey, PlainCoseKey};
    use crate::{ByteString, ProofOfPossessionKey, ToCborMap};

    #[test]
    fn test_key_id() -> Result<(), String> {
        let pop = ProofOfPossessionKey::KeyId(vec![0xDC, 0xAF]);
        assert_eq!(pop.key_id(), &vec![0xDC, 0xAF]);
        assert_eq!(
            KeyId::try_from(pop.clone()).expect("must be KeyId"),
            vec![0xDC, 0xAF].as_slice()
        );
        assert_eq!(
            CoseKey::try_from(pop.clone()).expect_err("must be error"),
            WrongSourceTypeError {
                expected_type: "PlainCoseKey",
                actual_type: "KeyId",
                general_type: PhantomData::default(),
            }
        );
        expect_ser_de(pop, None, "A10342DCAF")?;
        Ok(())
    }

    #[test]
    fn test_plain_key() -> Result<(), String> {
        let key = CoseKeyBuilder::new_ec2_pub_key(
            iana::EllipticCurve::P_256,
            vec![
                0xd7, 0xcc, 0x07, 0x2d, 0xe2, 0x20, 0x5b, 0xdc, 0x15, 0x37, 0xa5, 0x43, 0xd5, 0x3c,
                0x60, 0xa6, 0xac, 0xb6, 0x2e, 0xcc, 0xd8, 0x90, 0xc7, 0xfa, 0x27, 0xc9, 0xe3, 0x54,
                0x08, 0x9b, 0xbe, 0x13,
            ],
            vec![
                0xf9, 0x5e, 0x1d, 0x4b, 0x85, 0x1a, 0x2c, 0xc8, 0x0f, 0xff, 0x87, 0xd8, 0xe2, 0x3f,
                0x22, 0xaf, 0xb7, 0x25, 0xd5, 0x35, 0xe5, 0x15, 0xd0, 0x20, 0x73, 0x1e, 0x79, 0xa3,
                0xb4, 0xe4, 0x71, 0x20,
            ],
        )
        .key_id(vec![0xDC, 0xAF])
        .build();
        let pop = PlainCoseKey(key.clone());
        assert_eq!(pop.key_id(), &vec![0xDC, 0xAF]);
        assert_eq!(
            CoseKey::try_from(pop.clone()).expect("must be CoseKey"),
            key
        );
        assert_eq!(
            CoseEncrypt0::try_from(pop.clone()).expect_err("must be error"),
            WrongSourceTypeError {
                expected_type: "EncryptedCoseKey",
                actual_type: "PlainCoseKey",
                general_type: PhantomData::default(),
            }
        );
        expect_ser_de(pop, None, "A101A501020242DCAF2001215820D7CC072DE2205BDC1537A543D53C60A6ACB62ECCD890C7FA27C9E354089BBE13225820F95E1D4B851A2CC80FFF87D8E23F22AFB725D535E515D020731E79A3B4E47120")?;
        Ok(())
    }

    #[test]
    fn test_encrypted_key() -> Result<(), String> {
        // Extract relevant part for comparison (i.e. no protected headers' original data,
        // which can change after serialization)
        fn transform_header(key: ProofOfPossessionKey) -> ProofOfPossessionKey {
            if let EncryptedCoseKey(enc) = key {
                ProofOfPossessionKey::EncryptedCoseKey(CoseEncrypt0 {
                    protected: ProtectedHeader {
                        original_data: None,
                        ..enc.protected
                    },
                    ..enc
                })
            } else {
                unreachable!("key must be EncryptedCoseKey")
            }
        }

        // From section 3.3 of RFC 8747. Should contain the above key.
        let encrypted = CoseEncrypt0Builder::new().ciphertext(hex::decode("0573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F")
            .expect("invalid hex"))
            .unprotected(HeaderBuilder::new().key_id(vec![0xDC, 0xAF]).iv(hex::decode("636898994FF0EC7BFCF6D3F95B").expect("invalid hex")).build())
            .protected(HeaderBuilder::new().algorithm(Algorithm::AES_CCM_16_64_128).build())
            .build();
        let pop = EncryptedCoseKey(encrypted.clone());
        assert_eq!(pop.key_id(), &vec![0xDC, 0xAF]);
        assert_eq!(
            CoseEncrypt0::try_from(pop.clone()).expect("must be CoseEncrypt0"),
            encrypted
        );
        assert_eq!(
            ByteString::try_from(pop.clone()).expect_err("must be error"),
            WrongSourceTypeError {
                expected_type: "KeyId",
                actual_type: "EncryptedCoseKey",
                general_type: PhantomData::default(),
            }
        );
        expect_ser_de(pop, Some(transform_header), "A1028343A1010AA20442DCAF054D636898994FF0EC7BFCF6D3F95B58300573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F")?;

        let encrypted_protected = CoseEncrypt0Builder::new().ciphertext(hex::decode("0573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F")
            .expect("invalid hex"))
            .unprotected(HeaderBuilder::new().iv(hex::decode("636898994FF0EC7BFCF6D3F95B").expect("invalid hex")).build())
            .protected(HeaderBuilder::new().key_id(vec![0xDC, 0xAF]).algorithm(Algorithm::AES_CCM_16_64_128).build())
            .build();
        let pop_protected = EncryptedCoseKey(encrypted_protected);
        assert_eq!(pop_protected.key_id(), &vec![0xDC, 0xAF]);
        Ok(())
    }

    #[test]
    fn test_try_from_invalid_cbor_map() {
        // This example is alright
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![(
            3_i128,
            Value::Bytes(vec![0xDC, 0xAF])
        )])
        .is_ok());
        // Invalid CBOR
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![]).is_err());
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![
            (3_i128, Value::Bytes(vec![0xDC, 0xAF])),
            (3_i128, Value::Bytes(vec![0xDC, 0xAF]))
        ])
        .is_err());
        // Invalid CBOR type for the respective key type
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![(
            1_i128,
            Value::Bytes(vec![0xDC, 0xAF])
        )])
        .is_err());
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![(
            2_i128,
            Value::Bytes(vec![0xDC, 0xAF])
        )])
        .is_err());
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![(
            3_i128,
            Value::Text("Hello".to_string())
        )])
        .is_err());
        // And an invalid key type
        assert!(ProofOfPossessionKey::try_from_cbor_map(vec![(
            4_i128,
            Value::Bytes(vec![0xDC, 0xAF])
        )])
        .is_err());
    }
}

mod other {
    use ciborium::value::Integer;

    use crate::common::cbor_map::decode_number;

    #[test]
    fn test_decode_integer() {
        assert_eq!(
            decode_number::<u8>(Integer::from(u8::MAX), "number").expect("conversion must work"),
            255_u8
        );
        assert_eq!(
            decode_number::<i16>(Integer::from(i16::MIN), "number").expect("conversion must work"),
            i16::MIN
        );
        assert_eq!(
            decode_number::<u64>(Integer::from(u64::MAX), "number").expect("conversion must work"),
            u64::MAX
        );
        assert_eq!(
            decode_number::<i64>(Integer::from(i64::MIN), "number").expect("conversion must work"),
            i64::MIN
        );
    }

    #[test]
    fn test_decode_integer_invalid() {
        assert!(decode_number::<u8>(Integer::from(u16::MAX), "number").is_err());
        assert!(decode_number::<i16>(Integer::from(i32::MIN), "number").is_err());
        assert!(decode_number::<u32>(Integer::from(i32::MIN), "number").is_err());
        assert!(decode_number::<i64>(Integer::from(u64::MAX), "number").is_err());
    }
}
