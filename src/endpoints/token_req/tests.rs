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

#[cfg(not(feature = "std"))]
use {alloc::string::ToString, alloc::vec};

use coset::cwt::Timestamp;
use coset::iana::Algorithm;
use coset::{
    iana, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, CoseKeyBuilder, HeaderBuilder,
    ProtectedHeader,
};
use enumflags2::{make_bitflags, BitFlags};

use crate::common::scope::{
    AifEncodedScopeElement, AifRestMethod, LibdcafEncodedScope, TextEncodedScope,
};
use crate::common::test_helper::expect_ser_de;
use crate::endpoints::token_req::AceProfile::CoapDtls;
use crate::{AifEncodedScope, BinaryEncodedScope};

use super::*;


mod request {
    use super::*;

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 5.
    #[test]
    fn test_access_token_request_symmetric() -> Result<(), String> {
        let request = AccessTokenRequestBuilder::default()
            .client_id("myclient")
            .audience("tempSensor4711")
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(
            request,
            None,
            "A2056E74656D7053656E736F72343731311818686D79636C69656E74",
        )
    }

    #[test]
    fn test_access_token_request_binary() -> Result<(), String> {
        let request = AccessTokenRequestBuilder::default()
            .client_id("myclient")
            .audience("tempSensor4711")
            .scope(
                BinaryEncodedScope::try_from(vec![0xDC, 0xAF].as_slice()).map_err(|x| x.to_string())?,
            )
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(
            request,
            None,
            "A3056E74656D7053656E736F72343731310942DCAF1818686D79636C69656E74",
        )
    }

    #[test]
    fn test_access_token_request_aif() -> Result<(), String> {
        let request = AccessTokenRequest::builder()
            .client_id("testclient")
            .audience("coaps://localhost")
            .scope(AifEncodedScope::new(vec![
                AifEncodedScopeElement::new("restricted".to_string(), AifRestMethod::Get),
                AifEncodedScopeElement::new(
                    "extended".to_string(),
                    AifRestMethod::Get | AifRestMethod::Post | AifRestMethod::Put,
                ),
                AifEncodedScopeElement::new(
                    "dynamic".to_string(),
                    AifRestMethod::DynamicGet | AifRestMethod::DynamicPost | AifRestMethod::DynamicPut,
                ),
                AifEncodedScopeElement::new("unrestricted".to_string(), BitFlags::all()),
                AifEncodedScopeElement::new("useless".to_string(), BitFlags::empty()),
            ]))
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(request,
                      None,
                      "A30571636F6170733A2F2F6C6F63616C686F73740985826A72657374726963746564018268657874656E64656407826764796E616D69631B0000000700000000826C756E726573747269637465641B0000007F0000007F82677573656C6573730018186A74657374636C69656E74")
    }

    #[test]
    fn test_access_token_request_libdcaf() -> Result<(), String> {
        let request = AccessTokenRequest::builder()
            .audience("coaps://localhost")
            .scope(LibdcafEncodedScope::new(
                "restricted",
                make_bitflags!(AifRestMethod::{Get}),
            ))
            .issuer("coaps://127.0.0.1:7744/authorize")
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(request,
                      None,
                      "A3017820636F6170733A2F2F3132372E302E302E313A373734342F617574686F72697A650571636F6170733A2F2F6C6F63616C686F737409826A7265737472696374656401")
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
        let request = AccessTokenRequestBuilder::default()
            .client_id("myclient")
            .req_cnf(key)
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(request, None, "A204A101A501020241112001215820BAC5B11CAD8F99F9C72B05CF4B9E26D244DC189F745228255A219A86D6A09EFF22582020138BF82DC1B6D562BE0FA54AB7804A3A64B6D72CCFED6B6FB6ED28BBFC117E1818686D79636C69656E74")
    }

    /// Example data taken from draft-ietf-ace-oauth-authz-46, Figure 7.
    #[test]
    fn test_access_token_request_reference() -> Result<(), String> {
        let request = AccessTokenRequestBuilder::default()
            .client_id("myclient")
            .audience("valve424")
            .scope(TextEncodedScope::try_from("read").map_err(|x| x.to_string())?)
            .req_cnf(vec![0xea, 0x48, 0x34, 0x75, 0x72, 0x4c, 0xd7, 0x75])
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(
            request,
            None,
            "A404A10348EA483475724CD775056876616C76653432340964726561641818686D79636C69656E74",
        )
    }

    #[test]
    fn test_access_token_request_encrypted() -> Result<(), String> {
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
        let request = AccessTokenRequestBuilder::default()
            .client_id("myclient")
            .req_cnf(encrypted)
            .build()
            .map_err(|x| x.to_string())?;

        expect_ser_de(request, Some(transform_header), "A204A1028343A1010AA1054D636898994FF0EC7BFCF6D3F95B58300573318A3573EB983E55A7C2F06CADD0796C9E584F1D0E3EA8C5B052592A8B2694BE9654F0431F38D5BBC8049FA7F13F1818686D79636C69656E74")
    }

    #[test]
    fn test_access_token_request_other_fields() -> Result<(), String> {
        let request = AccessTokenRequestBuilder::default()
            .client_id("myclient")
            .redirect_uri("coaps://server.example.com")
            .grant_type(GrantType::ClientCredentials)
            .scope(
                BinaryEncodedScope::try_from(vec![0xDC, 0xAF].as_slice()).map_err(|x| x.to_string())?,
            )
            .ace_profile()
            .client_nonce(vec![0, 1, 2, 3, 4])
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(request, None, "A60942DCAF1818686D79636C69656E74181B781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D1821021826F61827450001020304")
    }


}

mod response {
    use super::*;

    #[test]
    fn test_access_token_response_aif() -> Result<(), String> {
        let request = AccessTokenResponse::builder()
            .access_token(vec![0xDC, 0xAF])
            .scope(AifEncodedScope::new(vec![
                AifEncodedScopeElement::new("restricted".to_string(), AifRestMethod::Get),
                AifEncodedScopeElement::new(
                    "extended".to_string(),
                    AifRestMethod::Get | AifRestMethod::Post | AifRestMethod::Put,
                ),
                AifEncodedScopeElement::new(
                    "dynamic".to_string(),
                    AifRestMethod::DynamicGet | AifRestMethod::DynamicPost | AifRestMethod::DynamicPut,
                ),
                AifEncodedScopeElement::new("unrestricted".to_string(), BitFlags::all()),
                AifEncodedScopeElement::new("useless".to_string(), BitFlags::empty()),
            ]))
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(request,
                      None,
                      "A20142DCAF0985826A72657374726963746564018268657874656E64656407826764796E616D69631B0000000700000000826C756E726573747269637465641B0000007F0000007F82677573656C65737300")
    }

    #[test]
    fn test_access_token_response_whole_libdcaf() -> Result<(), String> {
        let response = AccessTokenResponse::builder()
            .access_token(vec![0xDC, 0xAF])
            .scope(LibdcafEncodedScope::new(
                "restricted",
                make_bitflags!(AifRestMethod::{Get}),
            ))
            .issued_at(Timestamp::WholeSeconds(10))
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(response, None, "A30142DCAF060A09826A7265737472696374656401")
    }

    #[test]
    fn test_access_token_response_fraction_libdcaf() -> Result<(), String> {
        let response = AccessTokenResponse::builder()
            .access_token(vec![0xDC, 0xAF])
            .scope(LibdcafEncodedScope::new("empty", BitFlags::empty()))
            .issued_at(Timestamp::FractionalSeconds(1.5))
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(response, None, "A30142DCAF06F93E00098265656D70747900")
    }

    #[test]
    fn test_access_token_response() -> Result<(), String> {
        let key = CoseKeyBuilder::new_symmetric_key(vec![
            0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c, 0x14, 0x91, 0xbe, 0x3a, 0x76, 0xdc, 0xea, 0x6c, 0x42,
            0x71, 0x08,
        ])
            .key_id(vec![0x84, 0x9b, 0x57, 0x86, 0x45, 0x7c])
            .build();
        // We need to specify this here because otherwise it'd be typed as an i32.
        let expires_in: u32 = 3600;
        let response = AccessTokenResponseBuilder::default()
            .access_token(hex::decode("4a5015df686428").map_err(|x| x.to_string())?)
            .ace_profile(CoapDtls)
            .expires_in(expires_in)
            .cnf(key)
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(response, None, "A401474A5015DF68642802190E1008A101A301040246849B5786457C2051849B5786457C1491BE3A76DCEA6C427108182601")
    }
}

mod error {
    use super::*;

    #[test]
    fn test_error_response() -> Result<(), String> {
        let error = ErrorResponse::builder()
            .error(ErrorCode::UnauthorizedClient)
            .description("You are not authorized to receive this token.")
            .uri("https://http.cat/401")
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(error, None, "A3181E04181F782D596F7520617265206E6F7420617574686F72697A656420746F2072656365697665207468697320746F6B656E2E18207468747470733A2F2F687474702E6361742F343031")
    }

    #[test]
    fn test_error_response_other() -> Result<(), String> {
        let error = ErrorResponse::builder()
            .error(ErrorCode::Other(418))
            .description("I can't help you, I'm just a teapot.")
            .uri("https://http.cat/418")
            .build()
            .map_err(|x| x.to_string())?;
        expect_ser_de(error, None, "A3181E1901A2181F7824492063616E27742068656C7020796F752C2049276D206A757374206120746561706F742E18207468747470733A2F2F687474702E6361742F343138")
    }
}

