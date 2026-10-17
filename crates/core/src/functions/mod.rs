//! core's own KIRun functions (`CoreFunctionRepository`): the families that need only the
//! request context so far. Each keeps the Java signature exactly (namespace, name, parameter
//! names and schemas, events), since stored definitions call them by name.

pub mod caller_security;
pub mod crypto;
pub mod file;
pub mod hash;
pub mod integration_fns;
pub mod java_sig;
pub mod platform;
pub mod schedule;
pub mod message;
pub mod security;
pub mod security_fns;
pub mod securitycontext;
pub mod storage;
pub mod support;

#[cfg(test)]
mod platform_tests;
#[cfg(test)]
mod security_tests;
#[cfg(test)]
pub(crate) mod security_world;

use async_trait::async_trait;
use kirun::function::{validate_arguments, Function};
use kirun::model::{EventResult, FunctionOutput, FunctionSignature};
use kirun::runtime::FunctionExecutionParameters;
use kirun::{Map, Value};

use crate::context;
use crate::error::CoreError;

/// A Java `AbstractReactiveFunction` subclass. The arguments are validated against the
/// signature first (a failure is wrapped with the function's name, as Java wraps what the
/// validation throws); what `internal_execute` fails with is passed up unwrapped, the way a
/// `Mono.error` travels in Java, keeping a `GenericException`'s status.
#[async_trait]
pub trait CoreFunction: Send + Sync {
    fn signature(&self) -> &FunctionSignature;

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError>;
}

/// Wraps a [`CoreFunction`] as a KIRun [`Function`].
pub struct Core<F>(pub F);

#[async_trait]
impl<F: CoreFunction> Function for Core<F> {
    fn get_signature(&self) -> &FunctionSignature {
        self.0.signature()
    }

    async fn execute(&self, context: &mut FunctionExecutionParameters) -> kirun::Result<FunctionOutput> {
        let args = validate_arguments(
            self.0.signature(),
            context.get_arguments().cloned().unwrap_or_default(),
            context.get_schema_repository().as_ref(),
            context.get_statement_execution().map(|s| s.as_ref()),
        )
        .await?;
        context.set_arguments_in_place(args.clone());
        self.0.internal_execute(&args).await.map_err(context::raise)
    }
}

/// `new FunctionOutput(List.of(EventResult.outputOf(Map.of(name, value))))`.
pub fn output(name: &str, value: Value) -> FunctionOutput {
    let mut m = Map::new();
    m.insert(name.to_string(), value);
    FunctionOutput::new(vec![EventResult::output_of(m)])
}

/// `args.get(name).getAsString()`: a string as is, a number or boolean as its text; null (or
/// an object) fails as Gson's `getAsString` does.
pub fn arg_string(args: &Map<Value>, name: &str) -> Result<String, CoreError> {
    match args.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(crate::gson::number_to_java_string(n)),
        Some(Value::Bool(b)) => Ok(b.to_string()),
        Some(Value::Null) => Err(CoreError::unknown("JsonNull")),
        Some(_) => Err(CoreError::unknown(format!("{} is not a JSON primitive", name))),
        None => Err(CoreError::unknown(format!(
            "Cannot invoke \"com.google.gson.JsonElement.getAsString()\" because the return value of \"java.util.Map.get(Object)\" is null"
        ))),
    }
}

/// The arguments' `JsonElement` for `name` (`JsonNull` when absent).
pub fn arg<'a>(args: &'a Map<Value>, name: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    args.get(name).unwrap_or(&NULL)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use ::platform::upstream::Upstream;
    use serde_json::json;

    use super::crypto::{HmacAlgo, SignatureValidator, Signer, StringEncoder};
    use super::hash::HashData;
    use super::security::GetAppUrl;
    use super::securitycontext::{GetAuthentication, GetUser, HasAuthority};
    use super::*;
    use crate::clients::SecurityCalls;
    use crate::testing::{request, user};

    async fn run(f: &dyn Function, args: serde_json::Value) -> (kirun::Result<FunctionOutput>, Option<CoreError>) {
        let mut fep = FunctionExecutionParameters::new(
            Arc::new(KIRunFunctionRepository::new()),
            Arc::new(KIRunSchemaRepository::new()),
        )
        .set_arguments(args.as_object().cloned().unwrap_or_default().into_iter().collect());
        let r = f.execute(&mut fep).await;
        let raised = context::request().and_then(|c| c.raised.lock().take());
        (r, raised)
    }

    fn result(r: kirun::Result<FunctionOutput>) -> Map<Value> {
        r.unwrap().next().unwrap().get_result().clone()
    }

    #[tokio::test]
    async fn security_context_functions() {
        let ctx = request(user(&["Authorities.ROLE_Owner", "Authorities.Logged_IN"]), false, None);
        context::with_request(ctx, async {
            let has = Core(HasAuthority::default());
            assert_eq!(result(run(&has, json!({"authority": "Authorities.ROLE_Owner"})).await.0)["result"], json!(true));
            assert_eq!(result(run(&has, json!({"authority": "Authorities.ROLE_X"})).await.0)["result"], json!(false));
            assert_eq!(result(run(&has, json!({"authority": ""})).await.0)["result"], json!(true));
            let (r, raised) = run(&has, json!({"authority": "Authorities.ROLE_Owner +"})).await;
            assert!(r.is_err());
            assert_eq!(raised.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);

            let auth = result(run(&Core(GetAuthentication::default()), json!({})).await.0);
            assert_eq!(auth["auth"]["isAuthenticated"], json!(true));
            assert!(auth["auth"].get("accessToken").is_none());
            let user_out = result(run(&Core(GetUser::default()), json!({})).await.0);
            assert_eq!(user_out["user"]["grantedAuthorities"].as_array().unwrap().len(), 2);
            assert_eq!(GetUser::default().signature().get_full_name(), "CoreServices.SecurityContext.GetUser");
        })
        .await;
    }

    #[tokio::test]
    async fn get_app_url() {
        let base = crate::clients::tests::stub().await;
        let f = Core(GetAppUrl::new(Arc::new(SecurityCalls::new(Upstream::fixed(&[&base])).unwrap())));
        assert_eq!(result(run(&f, json!({"appCode": "appbuilder", "clientCode": "C1"})).await.0)["result"], json!("https://C1.example"));
        // clientCode defaults to "", an unknown app answers nothing, which is "".
        assert_eq!(result(run(&f, json!({"appCode": "unknown"})).await.0)["result"], json!(""));
        let ctx = request(user(&[]), false, None);
        context::with_request(ctx, async {
            let (r, raised) = run(&f, json!({"appCode": "broken"})).await;
            assert!(r.is_err());
            assert!(raised.is_some());
        })
        .await;
        assert_eq!(f.0.signature().get_parameters().len(), 2);
    }

    #[tokio::test]
    async fn signer_and_validator() {
        let key = "0123456789abcdef0123456789abcdef";
        let signer = Core(Signer::default());
        let signed = result(run(&signer, json!({"alg": "HmacSHA256", "secretKey": key, "data": {"x": [1, null]}})).await.0);
        let sig = signed["result"].as_str().unwrap().to_string();
        let expected = StringEncoder::Base64.encode(&HmacAlgo::Hs256.sign(key.as_bytes(), br#"{"x":[1,null]}"#));
        assert_eq!(sig, expected);
        let hex = result(run(&signer, json!({"alg": "HmacSHA512", "secretKey": key.repeat(2), "data": true, "signatureEncoder": "Hex"})).await.0);
        assert_eq!(hex["result"], json!(StringEncoder::Hex.encode(&HmacAlgo::Hs512.sign(key.repeat(2).as_bytes(), b"true"))));
        let n = result(run(&signer, json!({"alg": "HmacSHA384", "secretKey": key.repeat(2), "data": 1.5})).await.0);
        assert_eq!(n["result"], json!(StringEncoder::Base64.encode(&HmacAlgo::Hs384.sign(key.repeat(2).as_bytes(), b"1.5"))));

        let ctx = request(user(&[]), false, None);
        context::with_request(ctx, async {
            let (r, raised) = run(&signer, json!({"alg": "HmacSHA256", "secretKey": "short", "data": "x"})).await;
            assert_eq!(r.unwrap_err().to_string(), "The signing key's size is 40 bits which is not secure enough for the HS256 algorithm.");
            assert_eq!(raised.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
            let (r, _) = run(&signer, json!({"alg": "HmacSHA256", "secretKey": "", "data": "x"})).await;
            assert_eq!(r.unwrap_err().to_string(), "Empty key");
            // Argument validation fails before the function runs, with the function's name.
            let (r, raised) = run(&signer, json!({"alg": "RS256", "secretKey": key, "data": "x"})).await;
            assert!(r.unwrap_err().to_string().starts_with("Error while executing the function CoreServices.Crypto.Signer"));
            assert!(raised.is_none());

            let validator = Core(SignatureValidator::default());
            let ok = result(run(&validator, json!({"alg": "HmacSHA256", "secretKey": key, "data": {"x": [1, null]}, "signature": sig})).await.0);
            assert_eq!(ok["isValid"], json!(true));
            let bad = result(run(&validator, json!({"alg": "HmacSHA256", "secretKey": key, "data": "y", "signature": sig})).await.0);
            assert_eq!(bad["isValid"], json!(false));
            let (r, _) = run(&validator, json!({"alg": "HmacSHA256", "secretKey": key, "data": "y", "signature": "!!"})).await;
            assert_eq!(r.unwrap_err().to_string(), "Illegal base64 character 21");
            let (r, _) = run(&validator, json!({"alg": "HmacSHA256", "secretKey": "x", "data": "y", "signature": "AA"})).await;
            assert_eq!(r.unwrap_err().to_string(), "The verification key's size is 8 bits which is not secure enough for the HS256 algorithm.");
        })
        .await;

        // Paths the signature's enums keep out of reach of a call: an algorithm Java has no
        // signer for, and a null data.
        let args = |alg: &str, data: Value| -> Map<Value> {
            json!({"alg": alg, "charset": "UTF-8", "secretKey": key, "data": data, "signatureEncoder": "base64", "signature": "AA"})
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect()
        };
        let mut o = Signer::default().internal_execute(&args("RS256", json!("x"))).await.unwrap();
        assert_eq!(o.next().unwrap().get_result()["result"], json!(""));
        let mut o = Signer::default().internal_execute(&args("HmacSHA256", Value::Null)).await.unwrap();
        assert_eq!(o.next().unwrap().get_result()["result"], json!(""));
        let mut o = SignatureValidator::default().internal_execute(&args("RS256", json!("x"))).await.unwrap();
        assert_eq!(o.next().unwrap().get_result()["isValid"], json!(false));
        let mut o = SignatureValidator::default().internal_execute(&args("HmacSHA256", Value::Null)).await.unwrap();
        assert_eq!(o.next().unwrap().get_result()["isValid"], json!(false));
        let mut bad_encoder = args("HmacSHA256", json!("x"));
        bad_encoder.insert("signatureEncoder".into(), json!("base32"));
        assert!(Signer::default().internal_execute(&bad_encoder).await.is_err());
        let mut bad_charset = args("HmacSHA256", json!("x"));
        bad_charset.insert("charset".into(), json!("EBCDIC"));
        assert!(Signer::default().internal_execute(&bad_charset).await.is_err());
    }

    #[tokio::test]
    async fn hash_data() {
        let h = Core(HashData::default());
        let r = result(run(&h, json!({"data": "abc", "algorithm": "SHA-1"})).await.0);
        // The JSON text of the string, quotes included, as Java's JsonElement.toString().
        use sha1::Digest;
        assert_eq!(r["result"], json!(hex::encode(sha1::Sha1::digest(b"\"abc\""))));
        let r = result(run(&h, json!({"data": null})).await.0);
        assert_eq!(r["result"].as_str().unwrap().len(), 64);
        let ctx = request(user(&[]), false, None);
        context::with_request(ctx, async {
            let (r, raised) = run(&h, json!({"data": 1, "algorithm": "MD4"})).await;
            assert_eq!(r.unwrap_err().to_string(), "Hash algorithm not supported: MD4");
            let raised = raised.unwrap();
            assert_eq!(raised.status(), StatusCode::BAD_REQUEST);
        })
        .await;
        assert!(super::hash::digest("", b"x").is_err());
        assert_eq!(super::hash::digest("sha256", b"").unwrap().len(), 32);
        assert_eq!(super::hash::digest("SHA512", b"").unwrap().len(), 64);
        assert_eq!(super::hash::digest("SHA384", b"").unwrap().len(), 48);
        assert_eq!(super::hash::digest("SHA", b"").unwrap().len(), 20);
    }

    #[test]
    fn argument_helpers() {
        let args: Map<Value> = json!({"s": "x", "n": 1.5, "i": 2, "b": true, "z": null, "o": {}})
            .as_object()
            .unwrap()
            .clone()
            .into_iter()
            .collect();
        assert_eq!(arg_string(&args, "s").unwrap(), "x");
        assert_eq!(arg_string(&args, "n").unwrap(), "1.5");
        assert_eq!(arg_string(&args, "i").unwrap(), "2");
        assert_eq!(arg_string(&args, "b").unwrap(), "true");
        assert_eq!(arg_string(&args, "z").unwrap_err().text(), "JsonNull");
        assert!(arg_string(&args, "o").is_err());
        assert!(arg_string(&args, "missing").unwrap_err().text().contains("getAsString"));
        assert_eq!(arg(&args, "missing"), &Value::Null);
        assert_eq!(output("k", json!(1)).next().unwrap().get_name(), "output");
    }
}
