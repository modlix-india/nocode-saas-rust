//! Word templates before and after they are filled (Rust only): `CoreServices.File.DocxInspect`
//! (the blanks a builder left in a Word file), `CoreServices.File.DocxPrepare` (the file with
//! field tags written in place of its blanks, saved as a new file) and `CoreServices.File.PdfStamp`
//! (signatures drawn onto a PDF already made, at the markers a prepared template left, then
//! optionally sealed). The work is done by the pdf-render sidecar (`/docx/inspect`,
//! `/docx/prepare`, `/pdf/stamp`); see `deploy/pdf-render/docx_edit.py` and `pdf_stamp.py`.
//!
//! What keeps them from reading or writing another organisation's files (the sidecar reads files
//! without asking who is calling):
//! - they run only inside a server function;
//! - `clientCode` is the caller's own client (blank: that one) or a client it manages (a builder's
//!   staff writing into a buyer's client; a co-applicant signing through a link on the builder's
//!   address, whose URL client manages the buyer's), else `CORE.FILE_CLIENT_FORBIDDEN`;
//! - the file read must be in that client's secured files (`CORE.FILE_NOT_CLIENTS`), and what is
//!   written goes to that client's secured files.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use kirun::json::schema::Schema;
use kirun::model::{Event, EventResult, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::support::{forbidden, server_function_only};
use super::CoreFunction;
use crate::clients::SecurityCalls;
use crate::context;
use crate::error::CoreError;
use crate::files_calls::FilesCalls;
use crate::integrations::caller;
use crate::pdf_render::{self, EditError};

const NAMESPACE: &str = "CoreServices.File";

pub fn all(security: &Arc<SecurityCalls>, files: &Arc<FilesCalls>) -> Vec<Arc<dyn kirun::function::Function>> {
    let deps = || Shared { security: security.clone(), files: files.clone() };
    vec![
        Arc::new(super::Core(DocxFn::new(Kind::Inspect, deps()))),
        Arc::new(super::Core(DocxFn::new(Kind::Prepare, deps()))),
        Arc::new(super::Core(DocxFn::new(Kind::Stamp, deps()))),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Inspect,
    Prepare,
    Stamp,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Inspect => "DocxInspect",
            Kind::Prepare => "DocxPrepare",
            Kind::Stamp => "PdfStamp",
        }
    }

    fn route(self) -> &'static str {
        match self {
            Kind::Inspect => "/docx/inspect",
            Kind::Prepare => "/docx/prepare",
            Kind::Stamp => "/pdf/stamp",
        }
    }
}

struct Shared {
    security: Arc<SecurityCalls>,
    files: Arc<FilesCalls>,
}

pub struct DocxFn {
    kind: Kind,
    signature: FunctionSignature,
    deps: Shared,
}

fn param(name: &str, s: Schema) -> (String, Parameter) {
    Parameter::of_entry(name, s, false)
}

fn text(name: &str, default: &str) -> (String, Parameter) {
    param(name, Schema::of_string(name).set_default_value(Value::from(default)))
}

impl DocxFn {
    fn new(kind: Kind, deps: Shared) -> Self {
        let mut params = vec![text("clientCode", ""), text("file", "")];
        let mut out = vec![("result".to_string(), Schema::of_any("result"))];
        let any_list = |n: &str| Schema::of_array(n, vec![Schema::of_any("item")]).set_default_value(Value::Array(vec![]));
        match kind {
            Kind::Inspect => {}
            Kind::Prepare => {
                params.push(param("fields", any_list("fields")));
                params.push(param("conditions", any_list("conditions")));
                params.push(param("options", Schema::of_object("options").set_default_value(Value::Object(Default::default()))));
            }
            Kind::Stamp => {
                params.push(param("stamps", any_list("stamps")));
                params.push(param("recordPage", Schema::of_boolean("recordPage").set_default_value(Value::Bool(false))));
                params.push(param("seal", Schema::of_boolean("seal").set_default_value(Value::Bool(false))));
            }
        }
        if kind != Kind::Inspect {
            params.extend([text("fileName", ""), text("fileLocation", "")]);
            out.push(("fileData".to_string(), Schema::of_object("fileData")));
        }
        let signature = FunctionSignature::new(kind.name())
            .set_namespace(NAMESPACE)
            .set_parameters(Map::from_iter(params))
            .set_events(Map::from([Event::output_event_map_entry(Map::from_iter(out))]));
        Self { kind, signature, deps }
    }
}

fn arg_text(args: &Map<Value>, name: &str) -> String {
    match args.get(name) {
        Some(Value::String(s)) => s.trim().to_string(),
        _ => String::new(),
    }
}

fn arg_json(args: &Map<Value>, name: &str, empty: serde_json::Value) -> serde_json::Value {
    match args.get(name) {
        Some(Value::Null) | None => empty,
        Some(v) => v.clone(),
    }
}

fn arg_true(args: &Map<Value>, name: &str) -> bool {
    match args.get(name) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// The client a call is for (`asked`, else `acting`, the caller's own or URL client): the caller's
/// own, or one `manages(acting, client)` says it manages; refused otherwise.
async fn decide_client<F, Fut>(full: &str, acting: &str, asked: &str, manages: F) -> Result<String, CoreError>
where
    F: FnOnce(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<bool, CoreError>>,
{
    let client = if asked.is_empty() { acting.to_string() } else { asked.to_string() };
    if client.is_empty() || acting.is_empty() {
        return Err(forbidden("CORE.FILE_CLIENT_FORBIDDEN", format!("{full}: no client to act for")).param("client", client.as_str()));
    }
    if client == acting || manages(acting.to_string(), client.clone()).await? {
        return Ok(client);
    }
    Err(forbidden("CORE.FILE_CLIENT_FORBIDDEN", format!("{full}: {acting} may not use the files of {client}")).param("client", client.as_str()))
}

fn refused(full: &str, reason: String) -> CoreError {
    CoreError::coded(StatusCode::BAD_REQUEST, "CORE.DOCX_REQUEST_REFUSED", format!("{full}: {reason}"))
        .param("function", full)
        .param("reason", reason.as_str())
}

impl DocxFn {
    /// The client the call is for: `clientCode`, else the caller's; refused unless it is the
    /// caller's own or one the caller's client manages.
    async fn client(&self, full: &str, asked: &str) -> Result<String, CoreError> {
        let c = caller();
        let acting = c.client_code.clone().filter(|s| !s.is_empty()).or_else(|| c.url_client_code.clone()).unwrap_or_default();
        let security = self.deps.security.clone();
        decide_client(full, &acting, asked, |acting, client| async move {
            Ok(security.filter_managed_client_codes(&acting, std::slice::from_ref(&client)).await?.is_some_and(|m| m.contains(&client)))
        })
        .await
    }

    /// The bytes written to the client's secured files: `fileData` (the files service's details
    /// plus `sha256`).
    async fn write(&self, client: &str, args: &Map<Value>, default_name: &str, bytes: Vec<u8>) -> Result<serde_json::Map<String, Value>, CoreError> {
        let location = arg_text(args, "fileLocation");
        let mut name = arg_text(args, "fileName");
        if name.is_empty() {
            name = default_name.to_string();
        }
        if location.is_empty() || location.contains("..") || name.contains('/') || name.contains("..") {
            return Err(refused(&format!("{NAMESPACE}.{}", self.kind.name()), "fileLocation (a folder) and fileName (no slashes) are required".into()));
        }
        use sha2::Digest;
        let sha = hex::encode(sha2::Sha256::digest(&bytes));
        let mut details = self
            .deps
            .files
            .create("secured", client, true, &location, &name, bytes)
            .await?
            .ok_or_else(|| CoreError::unknown("the files service stored nothing"))?;
        details.insert("sha256".into(), Value::String(sha));
        Ok(details)
    }
}

#[async_trait]
impl CoreFunction for DocxFn {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let full = format!("{NAMESPACE}.{}", self.kind.name());
        if !context::in_kirun() {
            return Err(server_function_only(&full));
        }
        let client = self.client(&full, &arg_text(args, "clientCode")).await?;
        let file = pdf_render::secured_file_of(&arg_text(args, "file"), &client)
            .map_err(|why| CoreError::coded(StatusCode::BAD_REQUEST, "CORE.FILE_NOT_CLIENTS", format!("{full}: {why}")).param("client", client.as_str()))?;
        let mut body = serde_json::json!({"file": file});
        match self.kind {
            Kind::Inspect => {}
            Kind::Prepare => {
                body["fields"] = arg_json(args, "fields", serde_json::json!([]));
                body["conditions"] = arg_json(args, "conditions", serde_json::json!([]));
                body["options"] = arg_json(args, "options", serde_json::json!({}));
            }
            Kind::Stamp => {
                body["stamps"] = arg_json(args, "stamps", serde_json::json!([]));
                body["recordPage"] = Value::Bool(arg_true(args, "recordPage"));
            }
        }
        let answer = match pdf_render::edit(self.kind.route(), &body).await {
            Ok(a) => a,
            Err(EditError::Refused(why)) => return Err(refused(&full, why)),
            Err(EditError::Failed(why)) => return Err(CoreError::unknown(why)),
        };
        let mut m = Map::new();
        match self.kind {
            Kind::Inspect => {
                let found: Value = serde_json::from_slice(&answer.body).map_err(|e| CoreError::unknown(format!("{full}: {e}")))?;
                m.insert("result".to_string(), found);
            }
            Kind::Prepare => {
                let details = self.write(&client, args, "template.docx", answer.body).await?;
                m.insert("result".to_string(), answer.result);
                m.insert("fileData".to_string(), Value::Object(details));
            }
            Kind::Stamp => {
                let mut pdf = answer.body;
                // Sealed last, over the finished file: a later stamp starts again from the unsigned
                // file (the caller passes every signature so far), so no seal is ever stamped over.
                let mut seal_note: Option<(bool, Value)> = None;
                if arg_true(args, "seal") {
                    seal_note = Some(match pdf_render::seal(pdf.clone()).await {
                        Ok(pdf_render::Sealed::Yes(sealed, info)) => {
                            pdf = sealed;
                            (true, info)
                        }
                        Ok(pdf_render::Sealed::NotConfigured) => (false, Value::String("no seal certificate on this environment".into())),
                        Err(e) => {
                            tracing::warn!(error = %e, "PdfStamp: the PDF is stored without the seal");
                            (false, Value::String(e))
                        }
                    });
                }
                let mut details = self.write(&client, args, "signed.pdf", pdf).await?;
                if let Some((sealed, info)) = seal_note {
                    details.insert("sealed".into(), Value::Bool(sealed));
                    details.insert(if sealed { "seal" } else { "sealNote" }.into(), info);
                }
                m.insert("result".to_string(), answer.result);
                m.insert("fileData".to_string(), Value::Object(details));
            }
        }
        Ok(FunctionOutput::new(vec![EventResult::output_of(m)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(e: &CoreError) -> String {
        e.coded_answer().map(|c| c.code.to_string()).unwrap_or_default()
    }

    #[tokio::test]
    async fn a_call_is_for_the_callers_client_or_one_it_manages() {
        let manages = |yes: bool| move |_: String, _: String| async move { Ok(yes) };
        assert_eq!(decide_client("F", "ANTER", "", manages(false)).await.unwrap(), "ANTER", "blank: the caller's own");
        assert_eq!(decide_client("F", "ANTER", "ANTER", manages(false)).await.unwrap(), "ANTER");
        assert_eq!(decide_client("F", "ANTER", "BUYER1", manages(true)).await.unwrap(), "BUYER1", "a managed client");
        let e = decide_client("F", "ANTER", "OTHER", manages(false)).await.unwrap_err();
        assert_eq!(code(&e), "CORE.FILE_CLIENT_FORBIDDEN");
        let e = decide_client("F", "", "ANTER", manages(true)).await.unwrap_err();
        assert_eq!(code(&e), "CORE.FILE_CLIENT_FORBIDDEN", "nobody to act for");
        // the managed lookup is not even asked for the caller's own client
        let never = |_: String, _: String| async move { Err::<bool, _>(CoreError::unknown("asked")) };
        assert_eq!(decide_client("F", "ANTER", "ANTER", never).await.unwrap(), "ANTER");
    }

    #[test]
    fn the_three_functions_and_their_arguments() {
        let deps = || Shared {
            security: Arc::new(SecurityCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap()),
            files: Arc::new(FilesCalls::new(platform::upstream::Upstream::fixed(&["http://127.0.0.1:1"])).unwrap()),
        };
        let names = |k: Kind| {
            let f = DocxFn::new(k, deps());
            let mut p: Vec<String> = f.signature.get_parameters().keys().cloned().collect();
            p.sort();
            (f.signature.get_full_name(), p)
        };
        assert_eq!(names(Kind::Inspect), ("CoreServices.File.DocxInspect".to_string(), vec!["clientCode".to_string(), "file".to_string()]));
        let (n, p) = names(Kind::Prepare);
        assert_eq!(n, "CoreServices.File.DocxPrepare");
        assert_eq!(p, ["clientCode", "conditions", "fields", "file", "fileLocation", "fileName", "options"]);
        let (n, p) = names(Kind::Stamp);
        assert_eq!(n, "CoreServices.File.PdfStamp");
        assert_eq!(p, ["clientCode", "file", "fileLocation", "fileName", "recordPage", "seal", "stamps"]);
    }
}
