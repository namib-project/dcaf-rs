use std::fmt::Debug;
use dcaf::common::scope::{TextEncodedScope};
use dcaf::endpoints::creation_hint::AuthServerRequestCreationHint;
use dcaf::common::{AsCborMap};

/// We assume the following scenario here:
/// 1. The client tries to access a protected resource. Since it's still unauthorized,
///    this is an Unauthorized Resource Request message. The RS replies with an error response
///    which contains proper creation hints, which we will create, "send" (i.e. serialize) and
///    "receive" (deserialize) here.
/// 2. The client then sends an AccessTokenRequest to the AS based on the creation hints.
///    It also requests that the AS reply with the `ace_profile` attached.
/// 3. The AS replies with an AccessTokenResponse, containing the signed token_req as well as all
///    other necessary fields.
/// 4. Finally, the client tries to send an invalid request, which is met by an ErrorResponse.
#[test]
fn test_scenario() -> Result<(), String> {
    let nonce = vec![0xDC, 0xAF];
    let auth_server = "as.example.org";
    let resource_server = "rs.example.org";
    let client_id = "test client";
    let scope = TextEncodedScope::try_from("first second").map_err(|x| x.to_string())?;
    assert!(scope.elements().eq(["first", "second"]));
    // Taken from RFC 8747, section 3.2.
    let key = CoseKeyBuilder::new_ec2_pub_key(
        P_256,
        hex::decode("d7cc072de2205bdc1537a543d53c60a6acb62eccd890c7fa27c9e354089bbe13").map_err(|x| x.to_string())?,
        hex::decode("f95e1d4b851a2cc80fff87d8e23f22afb725d535e515d020731e79a3b4e47120").map_err(|x| x.to_string())?,
    ).build();
    let (unprotected_headers, protected_headers) = example_headers();
    let mut crypto = FakeCrypto {};
    let aad = example_aad();

    let hint: AuthServerRequestCreationHint = AuthServerRequestCreationHint::builder()
        .auth_server("as.example.org")
        .scope(scope)
        .token_type(TokenType::ProofOfPossession)
        .build()
        .map_err(|x| x.to_string())?;
    let result = pseudo_send_receive(response.clone())?;
    assert_eq!(response, result);

    let error = ErrorResponse::builder()
        .error(ErrorCode::InvalidRequest)
        .error_description("You sent an invalid request.")
        .error_uri("https://example.org/400")
        .build().map_err(|x| x.to_string())?;
    let result = pseudo_send_receive(error.clone())?;
    assert_eq!(error, result);
    Ok(())
}

fn pseudo_send_receive<T>(input: T) -> Result<T, String>
    where
        T: AsCborMap + Debug + PartialEq + Clone,
{
    let mut serialized: Vec<u8> = Vec::new();
    input
        .serialize_into(&mut serialized)
        .map_err(|x| x.to_string())?;
    T::deserialize_from(serialized.as_slice()).map_err(|x| x.to_string())
}
