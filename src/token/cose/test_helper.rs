use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use coset::iana::{Algorithm, EnumI64};
use coset::{iana, CoseKey, CoseKeyBuilder, Header, HeaderBuilder};
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
    pub sign0: Option<TestCaseSigner>,
    pub sign: Option<TestCaseSign>,
    #[serde(default)]
    pub failures: TestCaseFailures,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseSign {
    #[serde(deserialize_with = "deserialize_header", default)]
    pub unprotected: Option<Header>,
    #[serde(deserialize_with = "deserialize_header", default)]
    pub protected: Option<Header>,
    pub signers: Vec<TestCaseSigner>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseSigner {
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
