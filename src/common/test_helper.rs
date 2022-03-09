use crate::common::AsCborMap;
use core::fmt::Debug;
use core::convert::identity;
use crate::CipherProvider;

/// Helper function for tests which ensures that [`value`] serializes to the hexadecimal bytestring
/// [expected_hex] and deserializes back to [`value`].
///
/// If [`transform_value`] is given, it will be applied to the deserialized value before comparing it
/// to [`value`]. `assert` statements are used to validate postconditions.
///
/// ## Postconditions
/// If no error occurred:
/// - The serialized [`value`] is equal to the bytestring given in [`expected_hex`].
/// - The deserialized value is equal to [`value`], with [`transform_value`] applied to it.
///   If [`transform_value`] is `None`, it will be equal to the identity function.
///
/// # Errors
/// This will return an error message if any of the following is true:
/// - Serialization of [`value`] failed.
/// - Deserializing of the serialized [`value`] failed.
/// - Deserializing of the serialized [`value`] does not result in a CBOR map.
/// - Given [`expected_hex`] is not valid hexadecimal.
///
/// # Panics
/// If any of the postconditions (verified as assertions) fail.
pub(crate) fn expect_ser_de<T>(
    value: T,
    transform_value: Option<fn(T) -> T>,
    expected_hex: &str,
) -> Result<(), String>
    where
        T: AsCborMap + Clone + Debug + PartialEq
{
    let copy = value.clone();
    let mut result = Vec::new();
    value
        .serialize_into(&mut result)
        .map_err(|x| x.to_string())?;
    #[cfg(feature = "std")]
    println!("Result: {:?}, Original: {:?}", hex::encode(&result), &copy);
    assert_eq!(
        &result,
        &hex::decode(expected_hex).map_err(|x| x.to_string())?
    );
    let decoded = T::deserialize_from(result.as_slice()).map_err(|x| x.to_string());
    if let Ok(decoded_value) = decoded {
        let decoded_value = transform_value.unwrap_or(identity)(decoded_value);
        assert_eq!(copy, decoded_value);
        Ok(())
    } else if let Err(e) = decoded {
        Err(e)
    } else {
        Err("Invalid value: Not a CBOR map!".to_string())
    }
}

/// Used to implement a basic [`CipherProvider`] for tests.
#[derive(Copy, Clone)]
pub(crate) struct FakeCrypto {}

/// Implements basic operations from the [`CipherProvider`] trait without actually using any "real"
/// cryptography. This is purely to be used for testing and obviously offers no security at all.
impl CipherProvider for FakeCrypto {
    fn encrypt(&mut self, data: &[u8], aad: &[u8]) -> Vec<u8> {
        // We simply put AAD behind the data and call it a day.
        let mut result: Vec<u8> = vec![];
        result.append(&mut data.to_vec());
        result.append(&mut aad.to_vec());
        result
    }

    fn decrypt(&mut self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        // Now we just split off the AAD we previously put at the end of the data.
        // We return an error if it does not match.
        if data.len() < aad.len() {
            return Err("Encrypted data must be at least as long as AAD!".to_string());
        }
        let mut result: Vec<u8> = data.to_vec();
        let aad_result = result.split_off(data.len() - aad.len());
        if aad != aad_result {
            Err("AADs don't match!".to_string())
        } else {
            Ok(result)
        }
    }

    fn sign(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn verify(&mut self, sig: &[u8], data: &[u8]) -> Result<(), String> {
        if sig != self.sign(data) {
            Err("failed to verify".to_string())
        } else {
            Ok(())
        }
    }
}
