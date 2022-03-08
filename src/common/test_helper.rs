use crate::common::AsCborMap;
use core::fmt::Debug;
use core::convert::identity;
use crate::CipherProvider;

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

#[derive(Copy, Clone)]
pub(crate) struct FakeCrypto {}

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
