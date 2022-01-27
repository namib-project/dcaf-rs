use coset::{iana, CborSerializable, CoseSign1};
use ciborium::{cbor, ser};
use ciborium::value::{Value};
use ciborium::value::Value::Integer;
use serde::{Serialize, Deserialize, Serializer};

// Code starting from here is taken from: https://github.com/google/coset/blob/main/examples/signature.rs

#[derive(Copy, Clone)]
struct FakeSigner {}

// Use a fake signer/verifier (to avoid pulling in lots of dependencies).
impl FakeSigner {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), String> {
        if sig != self.sign(data) {
            Err("failed to verify".to_owned())
        } else {
            Ok(())
        }
    }
}

// Code starting from here is our own.

// Macro adapted from https://github.com/enarx/ciborium/blob/main/ciborium/tests/macro.rs#L13
macro_rules! cbor_map {
   ($($key:expr => $val:expr),* $(,)*) => {
        Value::Map(vec![$(
            (
                Value::serialized(&$key).expect("Invalid map key"),
                Value::serialized(&$val).expect("Invalid map value")
            )
        ),*])
    };
}

type ByteString = Vec<u8>;

#[derive(Debug)]
struct ASRequestCreationHint {
    AS: Option<String>,
    kid: Option<ByteString>,
    audience: Option<ByteString>,
    scope: Option<ByteString>, // TODO: "Text or byte string"
    cnonce: Option<ByteString>
}

impl Serialize for ASRequestCreationHint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let map = cbor_map!{
            1 => self.AS, 2 => self.kid, 5 => self.audience, 9 => self.scope, 39 => self.cnonce
        };
        Serialize::serialize(&map, serializer)
    }
}

impl ASRequestCreationHint {
    fn empty() -> ASRequestCreationHint {
        ASRequestCreationHint {
            AS: None,
            kid: None,
            audience: None,
            scope: None,
            cnonce: None
        }
    }
}

struct BearerToken {
    content: Vec<u8>,
    token_type: String,
    expires_in: u16,
    refresh_token: Vec<u8>
}

/// The main function will only exist temporarily to test a few things.
fn main() {
    let testHint = ASRequestCreationHint::empty();
    let mut result = Vec::new();
    let serialized = ser::into_writer(&testHint, &mut result);
    println!("Result: {:?}, Original: {:?}", &result, &testHint);
    unimplemented!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
