//! `CoreServices.Crypto.EncryptField` and `DecryptField` (Rust only, CXZ-1961): keep a value in app data
//! encrypted (`crate::field_crypto`). The client and the app the value belongs to, and a field label, are
//! bound into the ciphertext, so a copy in another client, app or field does not open.
//!
//! `DecryptField` needs the `authority` the calling function names, and the platform checks the caller
//! holds it; its output is the plain text, so a function must put it only where it is meant to go (a
//! generated document), never in an answer to a screen.

use async_trait::async_trait;
use kirun::json::schema::Schema;
use kirun::model::{Event, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::{arg_string, output, CoreFunction};
use crate::context;
use crate::error::CoreError;
use crate::field_crypto::{check_reader, decrypt_with, encrypt_with, installed};

const NAMESPACE: &str = "CoreServices.Crypto";

fn result_event() -> Map<Event> {
    Map::from([Event::output_event_map_entry(Map::from([("result".to_string(), Schema::of_string("result"))]))])
}

fn text_param(name: &str) -> (String, Parameter) {
    Parameter::of_entry(name, Schema::of_string(name).set_minimum(0.0), false)
}

pub struct EncryptField {
    signature: FunctionSignature,
}

impl EncryptField {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("EncryptField")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([
                    text_param("value"),
                    text_param("clientCode"),
                    text_param("appCode"),
                    text_param("field"),
                ]))
                .set_events(result_event()),
        }
    }
}

impl Default for EncryptField {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for EncryptField {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// `result`: the stored form (`v1.` + base64url); an empty `value` gives an empty `result`.
    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let value = arg_string(args, "value")?;
        // nothing to protect: no key is needed (a caller may pass an empty value on every environment)
        if value.is_empty() {
            return Ok(output("result", Value::String(String::new())));
        }
        let (client, app, field) = (arg_string(args, "clientCode")?, arg_string(args, "appCode")?, arg_string(args, "field")?);
        let key = installed()?;
        Ok(output("result", Value::String(encrypt_with(key, &client, &app, &field, &value)?)))
    }
}

pub struct DecryptField {
    signature: FunctionSignature,
}

impl DecryptField {
    pub fn new() -> Self {
        Self {
            signature: FunctionSignature::new("DecryptField")
                .set_namespace(NAMESPACE)
                .set_parameters(Map::from([
                    text_param("value"),
                    text_param("clientCode"),
                    text_param("appCode"),
                    text_param("field"),
                    text_param("authority"),
                ]))
                .set_events(result_event()),
        }
    }
}

impl Default for DecryptField {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreFunction for DecryptField {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    /// `result`: the plain text. 403 unless the caller is signed in and holds `authority`; 400 when the
    /// value does not open for this client, app and field; 503 when this environment has no key.
    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let value = arg_string(args, "value")?;
        // nothing stored: nothing to read, so neither a key nor the authority is asked for
        if value.is_empty() {
            return Ok(output("result", Value::String(String::new())));
        }
        let (client, app, field) = (arg_string(args, "clientCode")?, arg_string(args, "appCode")?, arg_string(args, "field")?);
        let authority = arg_string(args, "authority")?;
        let auth = context::authentication();
        check_reader(auth.is_authenticated(), auth.authorities(), &authority)?;
        let key = installed()?;
        Ok(output("result", Value::String(decrypt_with(key, &client, &app, &field, &value)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_crypto::{install, CryptoConfig};
    use base64::Engine as _;

    fn args(pairs: &[(&str, &str)]) -> Map<Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect()
    }

    fn text(o: FunctionOutput) -> String {
        let mut o = o;
        let r = o.next().expect("one result");
        r.get_result().get("result").and_then(|v| v.as_str()).unwrap_or_default().to_string()
    }

    #[tokio::test]
    async fn encrypting_works_for_anyone_and_reading_needs_a_signed_in_holder() {
        install(&CryptoConfig { field_key: base64::engine::general_purpose::STANDARD.encode([9u8; 32]) }).unwrap();
        let enc = EncryptField::new()
            .internal_execute(&args(&[("value", "123456789012"), ("clientCode", "FIN"), ("appCode", "cxzump"), ("field", "cxParty.aadhaar")]))
            .await
            .unwrap();
        let enc = text(enc);
        assert!(enc.starts_with("v1.") && !enc.contains("123456789012"));
        // outside a request the caller is anonymous: refused, and the refusal does not say the value
        let e = DecryptField::new()
            .internal_execute(&args(&[
                ("value", &enc),
                ("clientCode", "FIN"),
                ("appCode", "cxzump"),
                ("field", "cxParty.aadhaar"),
                ("authority", "Authorities.ROLE_Owner"),
            ]))
            .await
            .unwrap_err();
        assert_eq!(e.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(!e.text().contains("123456789012"));
        // an empty value is empty in and out for anyone, with or without a key or an authority
        let none = text(
            DecryptField::new()
                .internal_execute(&args(&[("value", ""), ("clientCode", "FIN"), ("appCode", "cxzump"), ("field", "f"), ("authority", "")]))
                .await
                .unwrap(),
        );
        assert_eq!(none, "");
        let none = text(EncryptField::new().internal_execute(&args(&[("value", ""), ("clientCode", "FIN"), ("appCode", "cxzump"), ("field", "f")])).await.unwrap());
        assert_eq!(none, "");
    }
}
