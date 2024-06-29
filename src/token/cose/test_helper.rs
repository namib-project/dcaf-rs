use crate::error::CoseCipherError;
use crate::token::cose::encrypt::CoseEncryptCipher;
use crate::token::cose::key::CoseSymmetricKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use coset::iana::{Algorithm, EnumI64};
use coset::{
    iana, AsCborValue, CborSerializable, CoseError, CoseKey, CoseKeyBuilder, Header, HeaderBuilder,
    Label, TaggedCborSerializable,
};
use serde::de::Error;
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;

fn deserialize_key<'de, D>(deserializer: D) -> Result<CoseKey, D::Error>
where
    D: Deserializer<'de>,
{
    let key_obj = serde_json::Map::deserialize(deserializer)?;
    match key_obj.get("kty").map(Value::as_str).flatten() {
        Some("EC") => {
            let curve = match key_obj.get("crv").map(Value::as_str).flatten() {
                Some("P-256") => iana::EllipticCurve::P_256,
                Some("P-384") => iana::EllipticCurve::P_384,
                Some("P-521") => iana::EllipticCurve::P_521,
                _ => return Err(de::Error::custom("COSE key does not have valid curve")),
            };

            let x = if let Some(v) = key_obj
                .get("x")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };

            let y = if let Some(v) = key_obj
                .get("y")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };
            let d = if let Some(v) = key_obj
                .get("d")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid x"));
            };

            let mut builder = CoseKeyBuilder::new_ec2_priv_key(curve, x, y, d);

            if let Some(v) = key_obj.get("kid").map(Value::as_str).flatten() {
                builder = builder.key_id(v.to_string().into_bytes())
            }

            Ok(builder.build())
        }
        Some("oct") => {
            let k = if let Some(v) = key_obj
                .get("k")
                .map(Value::as_str)
                .flatten()
                .map(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .flatten()
            {
                v
            } else {
                return Err(de::Error::custom("COSE key does not have valid k"));
            };

            let mut builder = CoseKeyBuilder::new_symmetric_key(k);

            if let Some(v) = key_obj.get("kid").map(Value::as_str).flatten() {
                builder = builder.key_id(v.to_string().into_bytes())
            }

            Ok(builder.build())
        }
        _ => Err(de::Error::custom("COSE key does not have valid key type")),
    }
}

fn deserialize_header<'de, D>(deserializer: D) -> Result<Option<Header>, D::Error>
where
    D: Deserializer<'de>,
{
    let hdr_obj =
        if let Some(hdr) = Option::<serde_json::Map<String, Value>>::deserialize(deserializer)? {
            hdr
        } else {
            return Ok(None);
        };

    let mut builder = HeaderBuilder::new();

    if let Some(v) = hdr_obj.get("kid").map(Value::as_str).flatten() {
        builder = builder.key_id(v.to_string().into_bytes());
    }
    if let Some(v) = hdr_obj
        .get("kid_hex")
        .map(Value::as_str)
        .flatten()
        .map(hex::decode)
    {
        builder = builder
            .key_id(v.map_err(|e| de::Error::custom("could not parse test case key ID hex"))?);
    }

    builder = match hdr_obj.get("alg").map(Value::as_str).flatten() {
        Some("ES256") => builder.algorithm(Algorithm::ES256),
        Some("ES384") => builder.algorithm(Algorithm::ES384),
        Some("ES512") => builder.algorithm(Algorithm::ES512),
        Some("A128GCM") => builder.algorithm(Algorithm::A128GCM),
        Some("A192GCM") => builder.algorithm(Algorithm::A192GCM),
        Some("A256GCM") => builder.algorithm(Algorithm::A256GCM),
        Some("direct") => builder.algorithm(Algorithm::Direct),
        Some(_) => return Err(de::Error::custom("could not parse test case algorithm")),
        None => builder,
    };

    builder = match hdr_obj.get("ctyp").map(Value::as_i64).flatten() {
        Some(v) => {
            let content_format = iana::CoapContentFormat::from_i64(v)
                .ok_or(de::Error::custom("could not parse test case algorithm"))?;
            builder.content_format(content_format)
        }
        None => builder,
    };

    Ok(Some(builder.build()))
}

fn deserialize_algorithm<'de, D>(deserializer: D) -> Result<Option<Algorithm>, D::Error>
where
    D: Deserializer<'de>,
{
    let alg = if let Some(alg) = Option::<Value>::deserialize(deserializer)? {
        alg
    } else {
        return Ok(None);
    };
    match alg.as_str() {
        Some("ES256") => Ok(Some(Algorithm::ES256)),
        Some("ES384") => Ok(Some(Algorithm::ES384)),
        Some("ES512") => Ok(Some(Algorithm::ES512)),
        Some("A128GCM") => Ok(Some(Algorithm::A128GCM)),
        Some("A192GCM") => Ok(Some(Algorithm::A192GCM)),
        Some("A256GCM") => Ok(Some(Algorithm::A256GCM)),
        Some("direct") => Ok(Some(Algorithm::Direct)),
        _ => Err(de::Error::custom("could not parse test case algorithm")),
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCase {
    pub title: String,
    pub description: Option<String>,
    #[serde(default)]
    pub fail: bool,
    pub input: TestCaseInput,
    pub intermediates: Option<TestCaseIntermediates>,
    pub output: TestCaseOutput,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct TestCaseFailures {
    #[serde(rename = "ChangeTag")]
    pub change_tag: Option<u64>,
    #[serde(rename = "ChangeCBORTag")]
    pub change_cbor_tag: Option<u64>,
    #[serde(rename = "ChangeAttr")]
    pub change_attribute: Option<HashMap<String, Value>>,
    #[serde(
        rename = "AddProtected",
        deserialize_with = "deserialize_header",
        default
    )]
    pub add_protected_headers: Option<Header>,
    #[serde(
        rename = "RemoveProtected",
        deserialize_with = "deserialize_header",
        default
    )]
    pub remove_protected_headers: Option<Header>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseInput {
    pub plaintext: String,
    #[serde(default)]
    pub detached: bool,
    pub sign0: Option<TestCaseRecipient>,
    pub sign: Option<TestCaseSign>,
    pub encrypted: Option<TestCaseEncrypted>,
    #[serde(default)]
    pub failures: TestCaseFailures,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseSign {
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    pub signers: Vec<TestCaseRecipient>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseEncrypted {
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    #[serde(deserialize_with = "hex::deserialize", default)]
    pub external: Vec<u8>,
    pub recipients: Vec<TestCaseRecipient>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseRecipient {
    #[serde(deserialize_with = "deserialize_key")]
    pub key: CoseKey,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    #[serde(deserialize_with = "deserialize_algorithm", default)]
    pub alg: Option<Algorithm>,
    #[serde(deserialize_with = "hex::deserialize", default)]
    pub external: Vec<u8>,
    #[serde(default)]
    pub failures: TestCaseFailures,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseIntermediates {}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseOutput {
    #[serde(deserialize_with = "hex::deserialize")]
    pub cbor: Vec<u8>,
}

pub(crate) fn apply_header_failures(hdr: &mut Header, failures: &TestCaseFailures) {
    if let Some(headers_to_remove) = &failures.remove_protected_headers {
        if !headers_to_remove.key_id.is_empty() {
            hdr.key_id = Vec::new();
        }
        if !headers_to_remove.counter_signatures.is_empty() {
            hdr.counter_signatures = Vec::new();
        }
        if let Some(new_val) = &headers_to_remove.alg {
            hdr.alg = None
        }
        if let Some(new_val) = &headers_to_remove.content_type {
            hdr.content_type = None
        }
        if !headers_to_remove.crit.is_empty() {
            hdr.crit = Vec::new();
        }
        if !headers_to_remove.iv.is_empty() {
            hdr.iv = Vec::new();
        }
        if !headers_to_remove.partial_iv.is_empty() {
            hdr.partial_iv = Vec::new()
        }
        let removed_fields = headers_to_remove
            .rest
            .iter()
            .map(|(label, _hdr)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let new_headers = hdr
            .rest
            .iter()
            .filter(|(label, _hdr)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        hdr.rest = new_headers
    }

    if let Some(headers_to_add) = &failures.add_protected_headers {
        if !headers_to_add.key_id.is_empty() {
            hdr.key_id = headers_to_add.key_id.clone();
        }
        if !headers_to_add.counter_signatures.is_empty() {
            hdr.counter_signatures = headers_to_add.counter_signatures.clone();
        }
        if let Some(new_val) = &headers_to_add.alg {
            hdr.alg = Some(new_val.clone())
        }
        if let Some(new_val) = &headers_to_add.content_type {
            hdr.content_type = Some(new_val.clone())
        }
        if !headers_to_add.crit.is_empty() {
            hdr.crit = headers_to_add.crit.clone();
        }
        if !headers_to_add.iv.is_empty() {
            hdr.iv = headers_to_add.iv.clone();
        }
        if !headers_to_add.partial_iv.is_empty() {
            hdr.partial_iv = headers_to_add.partial_iv.clone();
        }

        let removed_fields = headers_to_add
            .rest
            .iter()
            .map(|(label, _hdr)| label)
            .cloned()
            .collect::<Vec<Label>>();
        let mut new_headers = hdr
            .rest
            .iter()
            .filter(|(label, _hdr)| !removed_fields.contains(label))
            .cloned()
            .collect::<Vec<(Label, ciborium::Value)>>();
        new_headers.append(&mut headers_to_add.rest.clone());
        hdr.rest = new_headers
    }
}

pub(crate) fn serialize_cose_with_failures<T: AsCborValue + TaggedCborSerializable>(
    value: T,
    failures: &TestCaseFailures,
) -> Vec<u8> {
    if let Some(new_tag) = &failures.change_cbor_tag {
        let untagged_value = value
            .to_cbor_value()
            .expect("unable to generate CBOR value of CoseSign1");
        ciborium::Value::Tag(*new_tag, Box::new(untagged_value))
            .to_vec()
            .expect("unable to serialize CBOR value")
    } else {
        value
            .to_tagged_vec()
            .expect("unable to generate CBOR value of CoseSign1")
    }
}

pub(crate) fn apply_attribute_failures(
    key: &mut CoseKey,
    failures: &TestCaseFailures,
) -> Option<CoseError> {
    if let Some(attribute_changes) = &failures.change_attribute {
        match attribute_changes.get("alg") {
            None => None,
            Some(Value::Number(v)) => {
                let cbor_value = ciborium::Value::Integer(ciborium::value::Integer::from(
                    v.as_i64().expect("unable to parse algorithm number"),
                ));
                match coset::Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        key.alg = Some(value);
                        None
                    }
                    Err(e) => Some(e),
                }
            }
            Some(Value::String(v)) => {
                let cbor_value = ciborium::Value::Text(v.to_string());
                match coset::Algorithm::from_cbor_value(cbor_value) {
                    Ok(value) => {
                        key.alg = Some(value);
                        None
                    }
                    Err(e) => Some(e),
                }
            }
            v => panic!("unable to set algorithm to {:?}", v),
        }
    } else {
        None
    }
}

pub struct RngMockCipher<T: CoseEncryptCipher> {
    rng_outputs: Vec<Vec<u8>>,
    cipher: T,
}

impl<T: CoseEncryptCipher> CoseEncryptCipher for RngMockCipher<T> {
    type Error = T::Error;

    // TODO reproducible outputs by mocking the RNG
    fn generate_rand(&mut self, buf: &mut [u8]) -> Result<(), CoseCipherError<Self::Error>> {
        todo!()
    }

    fn encrypt_aes_gcm(
        &mut self,
        algorithm: coset::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        self.cipher
            .encrypt_aes_gcm(algorithm, key, plaintext, aad, iv)
    }

    fn decrypt_aes_gcm(
        &mut self,
        algorithm: coset::Algorithm,
        key: CoseSymmetricKey<'_, Self::Error>,
        ciphertext_with_tag: &[u8],
        aad: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, CoseCipherError<Self::Error>> {
        self.cipher
            .decrypt_aes_gcm(algorithm, key, ciphertext_with_tag, aad, iv)
    }
}
