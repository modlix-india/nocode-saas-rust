//! `CoreServices.File`: `FileToBase64` (a stored file as base64, from the files service) and
//! `TemplateToPdf` (`TemplateConversionService` and `PdfConversionService`: a template rendered
//! with the data given, as a PDF written to the files service).
//!
//! The template is read and rendered as the email path does it (`AbstractTemplateService`: the
//! language, then every part of that language's set through FreeMarker, both from the
//! `connections` crate); the HTML `body` part becomes the PDF in [`crate::pdf`], which stands in
//! for openhtmltopdf (see there for what it draws).

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use connections::email::{self, EmailTemplate};
use connections::error::ConnError;
use connections::java::{hash_map_order_deep, is_blank};
use kirun::model::FunctionOutput;
use kirun::{Map, Value};
use overridable::{JMap, JValue};

use super::message::gson_tree;
use super::support::{empty_result, event_output, require_context_key, Java, JavaFunction};
use super::{arg_string, output};
use crate::context;
use crate::error::CoreError;
use crate::files_calls::FilesCalls;
use crate::repos::core_functions::Deps;
use crate::storage::defs::StorageDefs;

pub const NAMESPACE: &str = "CoreServices.File";

/// core's `messages_en`: `file_format_invalid`, `template_details_missing`.
pub use crate::catalogue::keys::{FILE_FORMAT_INVALID, TEMPLATE_DETAILS_MISSING};

/// `context.getArguments().get(name).getAsBoolean()`.
fn arg_bool(args: &Map<Value>, name: &str) -> Result<bool, CoreError> {
    match args.get(name) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::String(s)) => Ok(s.eq_ignore_ascii_case("true")),
        Some(Value::Number(_)) => Ok(false),
        Some(Value::Null) => Err(CoreError::unknown("JsonNull")),
        Some(Value::Object(_)) => Err(CoreError::unknown("JsonObject")),
        Some(Value::Array(_)) => Err(CoreError::unknown("JsonArray")),
        None => Err(CoreError::unknown(
            "Cannot invoke \"com.google.gson.JsonElement.getAsBoolean()\" because the return value of \"java.util.Map.get(Object)\" is null",
        )),
    }
}

/// An error of the template rendering, as the Java services raise it.
fn conn_error(e: ConnError) -> CoreError {
    crate::integrations::core_error(e)
}

// -------------------------------------------------------------------------------------------
// FileToBase64

const FILE_TO_BASE64: &str = "CoreServices.File.FileToBase64";

/// A stored file as base64 (a data URL with `metadataRequired`), read for the caller's client.
/// Output `result`; the `error` event when the path is blank or the files service answers
/// nothing.
pub struct FileToBase64 {
    pub files: Arc<FilesCalls>,
}

#[async_trait]
impl JavaFunction for FileToBase64 {
    fn full_name(&self) -> &'static str {
        FILE_TO_BASE64
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let path = arg_string(args, "filePath")?;
        let file_type = arg_string(args, "fileType")?;
        let metadata_required = arg_bool(args, "metadataRequired")?;
        if is_blank(&path) {
            return Ok(event_output("error", [("error", Value::String("Please provide the valid file path.".into()))]));
        }
        let Some(req) = context::request() else { return Err(empty_result(FILE_TO_BASE64)) };
        // `CommonsUtil.nonNullValue(ca.getClientCode(), ca.getUrlClientCode())`.
        let client = req.auth.client_code().or(req.auth.url_client_code());
        match self.files.read_file_as_base64(&file_type, client, &path, Some(metadata_required)).await? {
            Some(base64) => Ok(output("result", Value::String(base64))),
            None => Ok(event_output("error", [("result", Value::String("File cannot be converted to base64".into()))])),
        }
    }
}

// -------------------------------------------------------------------------------------------
// TemplateToPdf

const TEMPLATE_TO_PDF: &str = "CoreServices.File.TemplateToPdf";

/// `TemplateService.read(name, appCode, clientCode)`: the resolved template document.
#[async_trait]
pub trait TemplateSource: Send + Sync {
    async fn template(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError>;
}

#[async_trait]
impl TemplateSource for StorageDefs {
    async fn template(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
        StorageDefs::template(self, name, app_code, client_code).await
    }
}

/// `SecurityContextUtil.resolveAppAndClientCode`: both given, or the blank ones from the caller
/// (the URL's app, the caller's client). `None` without a security context; a code the caller
/// does not have either is `Tuples.of`'s null check.
fn resolve_app_and_client(app_code: &str, client_code: &str) -> Result<Option<(String, String)>, CoreError> {
    if !is_blank(app_code) && !is_blank(client_code) {
        return Ok(Some((app_code.to_string(), client_code.to_string())));
    }
    let Some(req) = context::request() else { return Ok(None) };
    let app = if is_blank(app_code) { req.auth.url_app_code().map(str::to_string) } else { Some(app_code.to_string()) };
    let client = if is_blank(client_code) { req.auth.client_code().map(str::to_string) } else { Some(client_code.to_string()) };
    match (app, client) {
        (None, _) => Err(CoreError::unknown("t1")),
        (_, None) => Err(CoreError::unknown("t2")),
        (Some(a), Some(c)) => Ok(Some((a, c))),
    }
}

/// `Path.of(location).getFileName().toString()`: the last name of the path; a root alone has
/// none, and Java then fails on the null.
fn last_name(location: &str) -> Result<String, CoreError> {
    if location.contains('\0') {
        return Err(CoreError::unknown(format!("Nul character not allowed: {location}")));
    }
    match location.split('/').rfind(|s| !s.is_empty()) {
        Some(name) => Ok(name.to_string()),
        None => Err(CoreError::unknown(
            "Cannot invoke \"java.nio.file.Path.toString()\" because the return value of \"java.nio.file.Path.getFileName()\" is null",
        )),
    }
}

/// `TemplateToPdf.extractFileName`.
fn extract_file_name(location: &str, template_name: &str, client_code: &str) -> Result<String, CoreError> {
    if is_blank(location) {
        return Ok(format!("{template_name}_{client_code}"));
    }
    let name = last_name(location)?;
    Ok(if name.is_empty() { format!("{template_name}_{client_code}") } else { name })
}

/// A template rendered with the data given and written to the files service as a PDF. Output
/// `fileData`: the files service's details of the file.
pub struct TemplateToPdf {
    pub templates: Arc<dyn TemplateSource>,
    pub files: Arc<FilesCalls>,
}

impl TemplateToPdf {
    /// `TemplateConversionService.convert`: the template's bytes in `output_format`; only
    /// `pdf` has a converter. `None` is Java's empty.
    pub async fn convert(
        &self,
        template_name: &str,
        app_code: &str,
        client_code: &str,
        output_format: &str,
        data: &serde_json::Map<String, Value>,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let Some((app, client)) = resolve_app_and_client(app_code, client_code)? else { return Ok(None) };
        if output_format != "pdf" {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, FILE_FORMAT_INVALID, &[output_format]));
        }
        let Some(doc) = self.templates.template(template_name, &app, &client).await? else {
            return Err(CoreError::msg(StatusCode::NOT_FOUND, TEMPLATE_DETAILS_MISSING, &[template_name]));
        };
        let json = serde_json::to_value(JValue::Object(doc)).map_err(|e| CoreError::unknown(e.to_string()))?;
        let template = EmailTemplate::from_json(json).map_err(conn_error)?;
        // AbstractTemplateConversionService.convertTemplate: the language, the parts, the format.
        let language = email::language(&template, data).map_err(conn_error)?;
        let parts = email::processed_parts(language.as_deref(), &template, data).map_err(conn_error)?;
        let html = match parts.get("body").and_then(Value::as_str) {
            Some(body) if !is_blank(body) => body.to_string(),
            // PdfConversionService sends the message key itself.
            _ => return Err(CoreError::coded(StatusCode::INTERNAL_SERVER_ERROR, "CORE.TEMPLATE_BODY_MISSING", "template_details_missing")),
        };
        let pdf = tokio::task::spawn_blocking(move || crate::pdf::html_to_pdf(&html))
            .await
            .map_err(|e| CoreError::unknown(e.to_string()))?;
        Ok(Some(pdf))
    }

    /// `makeFileInFiles`: the PDF written under the location, named `fileName`, else the
    /// location's last name, else `<template>_<client>`, else `file`.
    #[allow(clippy::too_many_arguments)]
    async fn make_file_in_files(
        &self,
        client_code: &str,
        template_name: &str,
        file_name: &str,
        file_location: &str,
        file_type: &str,
        overwrite: bool,
        bytes: Vec<u8>,
    ) -> Result<Option<serde_json::Map<String, Value>>, CoreError> {
        let mut name = file_name.to_string();
        if is_blank(&name) {
            name = extract_file_name(file_location, template_name, client_code)?;
        }
        if is_blank(&name) {
            name = "file".into();
        }
        self.files.create(file_type, client_code, overwrite, file_location, &name, bytes).await
    }
}

/// `getAsJsonObject()` read by `JsonUtil.toMap` (`HashMap`s all the way down).
fn data_of(args: &Map<Value>, name: &str) -> Result<serde_json::Map<String, Value>, CoreError> {
    match args.get(name) {
        Some(Value::Object(o)) => Ok(hash_map_order_deep(Value::Object(o.clone())).as_object().cloned().unwrap_or_default()),
        Some(other) => Err(CoreError::unknown(format!("Not a JSON Object: {other}"))),
        None => Err(CoreError::unknown(
            "Cannot invoke \"com.google.gson.JsonElement.getAsJsonObject()\" because the return value of \"java.util.Map.get(Object)\" is null",
        )),
    }
}

#[async_trait]
impl JavaFunction for TemplateToPdf {
    fn full_name(&self) -> &'static str {
        TEMPLATE_TO_PDF
    }

    async fn run(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let app_code = arg_string(args, "appCode")?;
        let client_code = arg_string(args, "clientCode")?;
        let template_name = arg_string(args, "templateName")?;
        let data = data_of(args, "templateData")?;
        let file_name = arg_string(args, "fileName")?;
        let file_location = arg_string(args, "fileLocation")?;
        let file_type = arg_string(args, "fileType")?;
        let overwrite = arg_bool(args, "fileOverride")?;
        require_context_key()?;

        let Some((app, client)) = resolve_app_and_client(&app_code, &client_code)? else {
            return Err(empty_result(TEMPLATE_TO_PDF));
        };
        let Some(bytes) = self.convert(&template_name, &app, &client, "pdf", &data).await? else {
            return Err(empty_result(TEMPLATE_TO_PDF));
        };
        let Some(details) =
            self.make_file_in_files(&client, &template_name, &file_name, &file_location, &file_type, overwrite, bytes).await?
        else {
            return Err(empty_result(TEMPLATE_TO_PDF));
        };
        Ok(output("fileData", gson_tree(Value::Object(details))))
    }
}

/// `makeFileFunctions`: FileToBase64, then TemplateToPdf.
pub fn all(deps: &Deps) -> Vec<Arc<dyn kirun::function::Function>> {
    vec![
        Java::function(FileToBase64 { files: deps.files.clone() }),
        Java::function(TemplateToPdf { templates: deps.defs.clone(), files: deps.files.clone() }),
    ]
}

#[cfg(test)]
mod tests {
    //! No Java tests cover these functions or the conversion services; these follow the Java
    //! code path by path, over a fake files service and templates held in memory.

    use std::collections::HashMap;

    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use kirun::runtime::FunctionExecutionParameters;
    use parking_lot::Mutex;
    use platform::upstream::Upstream;
    use serde_json::json;

    use super::*;
    use crate::files_calls::tests::{fake, Uploads};
    use crate::functions::CoreFunction;
    use crate::pdf::tests::{assert_valid, pdf_text};
    use crate::testing::{auth, request, user};

    #[derive(Default)]
    struct Templates {
        docs: HashMap<String, JMap>,
        lookups: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl TemplateSource for Templates {
        async fn template(&self, name: &str, app_code: &str, client_code: &str) -> Result<Option<JMap>, CoreError> {
            self.lookups.lock().push(format!("{name} {app_code} {client_code}"));
            Ok(self.docs.get(name).cloned())
        }
    }

    fn doc(v: serde_json::Value) -> JMap {
        match serde_json::from_value::<JValue>(v).unwrap() {
            JValue::Object(m) => m,
            _ => panic!("an object"),
        }
    }

    struct Fixture {
        templates: Arc<Templates>,
        uploads: Uploads,
        files: Arc<FilesCalls>,
    }

    async fn fixture() -> Fixture {
        let (base, uploads) = fake().await;
        let mut t = Templates::default();
        t.docs.insert(
            "invoice".into(),
            doc(json!({"name": "invoice", "appCode": "appbuilder", "templateParts": {
                "en": {"subject": "Invoice", "body": "<h1>Invoice ${number}</h1><p>Dear ${name}, &amp; thanks.</p>"},
                "fr": {"body": "<p>Bonjour ${name}</p>"}
            }, "languageExpression": "${lang!''}", "defaultLanguage": "en"})),
        );
        t.docs.insert("blank".into(), doc(json!({"templateParts": {"en": {"body": "  ", "subject": "s"}}})));
        t.docs.insert("bodiless".into(), doc(json!({"templateParts": {"en": {"subject": "s"}}})));
        t.docs.insert("partless".into(), doc(json!({"templateParts": {}})));
        t.docs.insert("broken".into(), doc(json!({"templateParts": {"en": {"body": "<#macro x></#macro>"}}})));
        t.docs.insert("odd".into(), doc(json!({"templateParts": "not a map"})));
        Fixture { templates: Arc::new(t), uploads, files: Arc::new(FilesCalls::new(Upstream::fixed(&[&base])).unwrap()) }
    }

    impl Fixture {
        fn to_pdf(&self) -> Java<TemplateToPdf> {
            Java::new(TemplateToPdf { templates: self.templates.clone(), files: self.files.clone() })
        }

        fn to_base64(&self) -> Java<FileToBase64> {
            Java::new(FileToBase64 { files: self.files.clone() })
        }
    }

    fn args(v: serde_json::Value) -> Map<Value> {
        v.as_object().unwrap().clone().into_iter().collect()
    }

    /// TemplateToPdf's arguments with the signature's defaults, `over` replacing some.
    fn pdf_args(over: serde_json::Value) -> Map<Value> {
        let mut a = args(json!({"appCode": "", "clientCode": "", "templateName": "invoice", "templateData": {"number": 42, "name": "Ann"},
                                "fileName": "", "fileLocation": "/", "fileType": "secured", "fileOverride": false}));
        a.extend(args(over));
        a
    }

    async fn in_run<F: JavaFunction>(f: &Java<F>, a: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        context::with_request(request(user(&[]), false, None), context::with_run(context::RunScope::default(), f.internal_execute(a))).await
    }

    fn event(o: Result<FunctionOutput, CoreError>) -> (String, Map<Value>) {
        let e = o.unwrap().next().unwrap();
        (e.get_name().to_string(), e.get_result().clone())
    }

    #[tokio::test]
    async fn file_to_base64() {
        let f = fixture().await;
        let b = f.to_base64();
        let a = |path: &str, meta: bool| args(json!({"filePath": path, "fileType": "static", "metadataRequired": meta}));

        let (name, r) = event(b.internal_execute(&a(" ", false)).await);
        assert_eq!((name.as_str(), r), ("error", args(json!({"error": "Please provide the valid file path."}))));

        let ctx = || request(user(&[]), false, None);
        let (name, r) = event(context::with_request(ctx(), b.internal_execute(&a("a/b.png", true))).await);
        assert_eq!((name.as_str(), r), ("output", args(json!({"result": "data:a/b.png;client=SYSTEM;meta=true"}))));
        let (name, r) = event(context::with_request(ctx(), b.internal_execute(&a("missing", false))).await);
        assert_eq!((name.as_str(), r), ("error", args(json!({"result": "File cannot be converted to base64"}))));
        let e = context::with_request(ctx(), b.internal_execute(&a("broken", false))).await.err().unwrap();
        assert_eq!((e.status(), e.text()), (StatusCode::INTERNAL_SERVER_ERROR, "cannot convert".to_string()));

        // The caller's client, else the URL's, else none at all.
        let url_only = request(auth(json!({}), Some("URLC"), None), false, None);
        let (_, r) = event(context::with_request(url_only, b.internal_execute(&a("x", false))).await);
        assert_eq!(r["result"], json!("data:x;client=URLC;meta=false"));
        let nobody = request(auth(json!({}), None, None), false, None);
        let (_, r) = event(context::with_request(nobody, b.internal_execute(&a("x", false))).await);
        assert_eq!(r["result"], json!("data:x;client=-;meta=false"));

        // Without a security context Java's chain is empty.
        assert_eq!(b.internal_execute(&a("x", false)).await.err().unwrap().text(), "Function with id CoreServices.File.FileToBase64 not found");
        assert!(b.internal_execute(&args(json!({"filePath": "x", "fileType": "static"}))).await.is_err());
    }

    #[tokio::test]
    async fn template_to_pdf_writes_the_rendered_template() {
        let f = fixture().await;
        let r = event(in_run(&f.to_pdf(), &pdf_args(json!({"fileName": "inv.pdf", "fileLocation": "/docs", "fileOverride": true}))).await);
        assert_eq!(r.0, "output");
        let detail = &r.1["fileData"];
        assert_eq!(detail["filePath"], json!("/docs/inv.pdf"));
        assert!(detail.get("lastModified").is_none(), "Gson leaves nulls out");
        // The blank codes are the caller's: the URL's app and the caller's client.
        assert_eq!(*f.templates.lookups.lock(), ["invoice appbuilder SYSTEM"]);
        let up = f.uploads.lock()[0].clone();
        assert_eq!(up.path, "/api/files/internal/secured");
        assert_eq!(up.query, "clientCode=SYSTEM&override=true&filePath=%2Fdocs&fileName=inv.pdf");
        assert_eq!(up.content_type, None);
        assert_eq!(detail["size"], json!(up.bytes.len()));
        assert_eq!(assert_valid(&up.bytes), 1);
        assert_eq!(pdf_text(&up.bytes), ["Invoice 42\nDear Ann, & thanks."]);

        // The language expression picks the set; explicit codes are used as they are.
        let a = pdf_args(json!({"appCode": "app2", "clientCode": "C9", "templateData": {"lang": "fr", "name": "Zoe"}, "fileName": "x"}));
        in_run(&f.to_pdf(), &a).await.unwrap();
        assert_eq!(f.templates.lookups.lock()[1], "invoice app2 C9");
        let up = f.uploads.lock()[1].clone();
        assert_eq!(up.query, "clientCode=C9&override=false&filePath=%2F&fileName=x");
        assert_eq!(pdf_text(&up.bytes), ["Bonjour Zoe"]);
    }

    #[tokio::test]
    async fn file_names() {
        let f = fixture().await;
        let name_of = |i: usize| f.uploads.lock()[i].query.split("fileName=").nth(1).unwrap().to_string();
        in_run(&f.to_pdf(), &pdf_args(json!({"fileLocation": "/reports/out/"}))).await.unwrap();
        assert_eq!(name_of(0), "out");
        in_run(&f.to_pdf(), &pdf_args(json!({"fileLocation": " "}))).await.unwrap();
        assert_eq!(name_of(1), "invoice_SYSTEM");
        // The default location is a root, which has no file name: Java fails on the null.
        let e = in_run(&f.to_pdf(), &pdf_args(json!({}))).await.err().unwrap();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(e.text().contains("getFileName()"), "{}", e.text());
        let e = in_run(&f.to_pdf(), &pdf_args(json!({"fileLocation": "a\u{0}b"}))).await.err().unwrap();
        assert_eq!(e.text(), "Nul character not allowed: a\u{0}b");
        assert_eq!(f.uploads.lock().len(), 2);
        // A blank last name is no name at all.
        in_run(&f.to_pdf(), &pdf_args(json!({"fileLocation": "/ /"}))).await.unwrap();
        assert_eq!(name_of(2), "file");
        assert_eq!(extract_file_name("", "t", "C").unwrap(), "t_C");
        assert_eq!(extract_file_name("/a//b", "t", "C").unwrap(), "b");
    }

    #[tokio::test]
    async fn template_failures() {
        let f = fixture().await;
        let fails = |over: serde_json::Value| {
            let pdf = f.to_pdf();
            async move { in_run(&pdf, &pdf_args(over)).await.err().unwrap() }
        };
        let e = fails(json!({"templateName": "nope", "fileName": "x"})).await;
        assert_eq!((e.status(), e.text()), (StatusCode::NOT_FOUND, "Template details missing : nope".to_string()));
        let e = fails(json!({"templateName": "partless", "fileName": "x"})).await;
        assert_eq!((e.status(), e.text()), (StatusCode::INTERNAL_SERVER_ERROR, "Unable to send the email: No template parts found".to_string()));
        for name in ["blank", "bodiless"] {
            let e = fails(json!({"templateName": name, "fileName": "x"})).await;
            assert_eq!((e.status(), e.text()), (StatusCode::INTERNAL_SERVER_ERROR, "template_details_missing".to_string()));
        }
        let e = fails(json!({"templateName": "broken", "fileName": "x"})).await;
        assert!(matches!(e, CoreError::Unknown { .. }), "{e:?}");
        let e = fails(json!({"templateName": "odd", "fileName": "x"})).await;
        assert!(e.text().starts_with("Unable to read the template"), "{}", e.text());
        // The files service refusing, or answering nothing.
        let e = fails(json!({"fileName": "refused"})).await;
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, "no write".to_string()));
        let e = fails(json!({"fileName": "empty"})).await;
        assert_eq!(e.text(), "Function with id CoreServices.File.TemplateToPdf not found");
        assert!(f.uploads.lock().len() == 2);
        // Bad arguments, as Gson reads them.
        assert_eq!(fails(json!({"templateData": [1]})).await.text(), "Not a JSON Object: [1]");
        let mut a = pdf_args(json!({}));
        a.shift_remove("templateData");
        assert!(in_run(&f.to_pdf(), &a).await.err().unwrap().text().contains("getAsJsonObject()"));
    }

    #[tokio::test]
    async fn only_inside_a_definition_and_a_security_context() {
        let f = fixture().await;
        let pdf = f.to_pdf();
        let a = pdf_args(json!({"fileName": "x"}));
        let e = context::with_request(request(user(&[]), false, None), pdf.internal_execute(&a)).await.err().unwrap();
        assert_eq!(e.text(), "Context does not contain key: KIRun Runtime");
        // No security context: blank codes resolve to nothing; given ones need none.
        let e = context::with_run(context::RunScope::default(), pdf.internal_execute(&a)).await.err().unwrap();
        assert_eq!(e.status(), StatusCode::NOT_FOUND);
        let given = pdf_args(json!({"fileName": "x", "appCode": "a", "clientCode": "c"}));
        context::with_run(context::RunScope::default(), pdf.internal_execute(&given)).await.unwrap();
        // A caller without a URL app or a client: `Tuples.of` refuses the null.
        let no_app = request(auth(json!({"clientCode": "C"}), Some("C"), None), false, None);
        let run = |ctx| context::with_request(ctx, context::with_run(context::RunScope::default(), pdf.internal_execute(&a)));
        assert_eq!(run(no_app).await.err().unwrap().text(), "t1");
        let no_client = request(auth(json!({}), None, Some("app")), false, None);
        assert_eq!(run(no_client).await.err().unwrap().text(), "t2");
    }

    #[tokio::test]
    async fn only_pdf_converts() {
        let f = fixture().await;
        let t = TemplateToPdf { templates: f.templates.clone(), files: f.files.clone() };
        let e = t.convert("invoice", "a", "c", "docx", &serde_json::Map::new()).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::NOT_FOUND, "The given file format docx is invalid.".to_string()));
        assert_eq!(t.convert("invoice", "", "", "pdf", &serde_json::Map::new()).await.unwrap(), None);
    }

    #[test]
    fn arguments_and_errors_as_java_reads_them() {
        let a = args(json!({"t": true, "s": "TRUE", "n": 1, "z": null, "o": {}, "l": []}));
        assert!(arg_bool(&a, "t").unwrap());
        assert!(arg_bool(&a, "s").unwrap());
        assert!(!arg_bool(&a, "n").unwrap());
        assert_eq!(arg_bool(&a, "z").unwrap_err().text(), "JsonNull");
        assert_eq!(arg_bool(&a, "o").unwrap_err().text(), "JsonObject");
        assert_eq!(arg_bool(&a, "l").unwrap_err().text(), "JsonArray");
        assert!(arg_bool(&a, "missing").unwrap_err().text().contains("getAsBoolean()"));
        let e = conn_error(ConnError::Feign { status: 409, message: "taken".into(), body: None });
        assert_eq!((e.status(), e.text()), (StatusCode::CONFLICT, "taken".to_string()));
        assert_eq!(conn_error(ConnError::new(StatusCode::BAD_REQUEST, "b")).status(), StatusCode::BAD_REQUEST);
        // The data is read into HashMaps, as JsonUtil.toMap reads it.
        let d = data_of(&args(json!({"d": {"zeta": 1, "alpha": {"b": 1, "a": 2}}})), "d").unwrap();
        assert_eq!(d, *json!({"zeta": 1, "alpha": {"a": 2, "b": 1}}).as_object().unwrap());
    }

    /// Through the KIRun wrapper with Java's signatures, and over the real definitions reader
    /// (offline here, so the template read fails).
    #[tokio::test]
    async fn as_kirun_functions() {
        let f = fixture().await;
        let storage = crate::testing::offline_storage_service().await;
        let mut deps = crate::testing::offline_deps("http://127.0.0.1:1", storage).await;
        deps.files = f.files.clone();
        let all = all(&deps);
        let names: Vec<String> = all.iter().map(|x| x.get_signature().get_full_name()).collect();
        assert_eq!(names, ["CoreServices.File.FileToBase64", "CoreServices.File.TemplateToPdf"]);
        let fep = |a: Map<Value>| {
            FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new())).set_arguments(a)
        };
        context::with_request(request(user(&[]), false, None), async {
            // The defaults: a static file, no metadata.
            let mut out = all[0].execute(&mut fep(args(json!({"filePath": "p"})))).await.unwrap();
            assert_eq!(out.next().unwrap().get_result()["result"], json!("data:p;client=SYSTEM;meta=false"));
            // An unknown file type is refused by the signature's enum.
            assert!(all[0].execute(&mut fep(args(json!({"filePath": "p", "fileType": "other"})))).await.is_err());
            let r = context::with_run(context::RunScope::default(), all[1].execute(&mut fep(args(json!({"templateName": "t", "fileName": "x"}))))).await;
            assert!(r.is_err());
        })
        .await;
        assert!(TemplateSource::template(deps.defs.as_ref(), "t", "a", "c").await.is_err());
    }
}
