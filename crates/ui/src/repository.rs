//! `GET /api/ui/functions/repositoryFind|repositoryFilter` and the `schemas` pair
//! (`FunctionController`, `SchemaController`, `AbstractFunctionService`,
//! `AbstractSchemaService`).
//!
//! The repository for an app is the app's own objects, then each app it depends on
//! (`getDependencies`), each read through the ordinary overridable path for the client. With
//! `includeKIRunRepos=true` the KIRun built-ins come first; their answers are the snapshot in
//! `kirun_catalog.json` (see `tools/capture_kirun_catalog.py`).

use std::collections::HashMap;
use std::sync::OnceLock;

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use mongodb::bson::{doc, Bson, Document, Regex};
use mongodb::options::FindOptions;
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};

use crate::docs::{FunctionDoc, SchemaDoc};
use crate::engine::Engine;
use crate::kirun::{self, read_class, schema_to_jackson, FUNCTION_DEFINITION, SCHEMA};
use crate::respond::{empty_ok, json_ok};
use crate::state::{AppState, Caller};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Function,
    Schema,
}

impl Kind {
    fn collection(self) -> &'static str {
        match self {
            Kind::Function => "function",
            Kind::Schema => "schema",
        }
    }

    fn catalog_key(self) -> &'static str {
        match self {
            Kind::Function => "functions",
            Kind::Schema => "schemas",
        }
    }
}

struct CatalogEntry {
    status: u16,
    body: String,
}

struct Catalog {
    names: Vec<String>,
    find: HashMap<String, CatalogEntry>,
}

fn catalog(kind: Kind) -> &'static Catalog {
    static FUNCTIONS: OnceLock<Catalog> = OnceLock::new();
    static SCHEMAS: OnceLock<Catalog> = OnceLock::new();
    let cell = match kind {
        Kind::Function => &FUNCTIONS,
        Kind::Schema => &SCHEMAS,
    };
    cell.get_or_init(|| {
        let all: serde_json::Value =
            serde_json::from_str(include_str!("kirun_catalog.json")).unwrap_or(serde_json::Value::Null);
        let part = &all[kind.catalog_key()];
        let names = part["names"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let find = part["find"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            CatalogEntry {
                                status: v["status"].as_u64().unwrap_or(500) as u16,
                                body: v["body"].as_str().unwrap_or_default().to_string(),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Catalog { names, find }
    })
}

/// Spring's `boolean` request parameter conversion.
fn flag(q: &HashMap<String, String>, name: &str) -> AppResult<bool> {
    match q.get(name).map(|s| s.trim().to_ascii_lowercase()) {
        None => Ok(false),
        Some(s) if s.is_empty() => Ok(false),
        Some(s) if ["true", "on", "yes", "1"].contains(&s.as_str()) => Ok(true),
        Some(s) if ["false", "off", "no", "0"].contains(&s.as_str()) => Ok(false),
        Some(s) => {
            let c = crate::catalogue::literal("UI.PARAM_NOT_BOOLEAN", StatusCode::BAD_REQUEST, format!("Invalid boolean value [{s}]"));
            Err(c.param("field", name).param("value", s).into())
        }
    }
}

/// `nonNullValue(param, ca.getUrlAppCode())` / `(param, ca.getUrlClientCode())`.
fn codes(caller: &Caller, q: &HashMap<String, String>) -> (String, String) {
    let app = q.get("appCode").cloned().or_else(|| caller.app_code.clone()).unwrap_or_default();
    let client = q.get("clientCode").cloned().or_else(|| caller.client_code.clone()).unwrap_or_default();
    (app, client)
}

async fn repos(st: &AppState, app: &str) -> AppResult<Vec<String>> {
    let mut out = vec![app.to_string()];
    out.extend(st.app_dependencies(app).await?.iter().cloned());
    Ok(out)
}

/// `repositoryFind`.
pub async fn find(st: &AppState, caller: &Caller, kind: Kind, q: &HashMap<String, String>) -> AppResult<Response> {
    let (app, client) = codes(caller, q);
    let include = flag(q, "includeKIRunRepos")?;
    let namespace = q.get("namespace").cloned();
    let name = q.get("name").cloned();

    if include {
        if let Some(r) = builtin_find(kind, namespace.as_deref(), name.as_deref())? {
            return Ok(r);
        }
    }

    let full = match (kind, namespace.as_deref()) {
        // `AbstractFunctionService`: a blank namespace means the name is already full.
        (Kind::Function, None) | (Kind::Function, Some("")) => name.clone().unwrap_or_else(|| "null".into()),
        (Kind::Function, Some(ns)) if ns.trim().is_empty() => name.clone().unwrap_or_else(|| "null".into()),
        _ => format!(
            "{}.{}",
            namespace.as_deref().unwrap_or("null"),
            name.as_deref().unwrap_or("null")
        ),
    };
    let engine = Engine::new(st, caller);
    for repo_app in repos(st, &app).await? {
        let found = match kind {
            Kind::Function => engine.read_def(&FunctionDoc, &full, &repo_app, &client).await?,
            Kind::Schema => engine.read_def(&SchemaDoc, &full, &repo_app, &client).await?,
        };
        let Some(r) = found else { continue };
        let definition = r.entity.get("definition").and_then(JValue::as_object).cloned().unwrap_or_default();
        return match kind {
            Kind::Function => Ok(function_body(&r.entity, &definition)?),
            Kind::Schema => {
                let s = read_class(&SCHEMA, &definition).map_err(gson_error)?;
                Ok(json_ok(&schema_to_jackson(&s).map_err(gson_error)?))
            }
        };
    }
    // An empty Mono<ResponseEntity>.
    Ok(empty_ok())
}

fn gson_error(e: kirun::GsonError) -> AppError {
    AppError::Internal(anyhow::anyhow!(e.0))
}

/// `gson.toJson(new DefinitionFunction(fd, executeAuth))` with its owner app.
fn function_body(entity: &JMap, definition: &JMap) -> AppResult<Response> {
    let fd = read_class(&FUNCTION_DEFINITION, definition).map_err(gson_error)?;
    let mut out = String::from("{\"definition\":");
    kirun::write_gson(&FUNCTION_DEFINITION, &fd, &mut out);
    if let Some(JValue::Str(auth)) = entity.get("executeAuth") {
        out.push_str(",\"executionAuthorization\":");
        out.push_str(&overridable::json::to_gson(&JValue::Str(auth.clone())));
    }
    if let Some(JValue::Str(owner)) = entity.get("appCode") {
        out.push_str(",\"ownerAppCode\":");
        out.push_str(&overridable::json::to_gson(&JValue::Str(owner.clone())));
    }
    out.push('}');
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], out).into_response())
}

fn builtin_find(kind: Kind, namespace: Option<&str>, name: Option<&str>) -> AppResult<Option<Response>> {
    if kind == Kind::Schema && !matches!(namespace, Some("System") | Some("System.Date")) {
        return Ok(None);
    }
    let key = format!("{}.{}", namespace.unwrap_or("null"), name.unwrap_or("null"));
    match catalog(kind).find.get(&key) {
        None if kind == Kind::Schema => {
            // `Mono.just(map.get(name))` with no such name.
            Err(AppError::Internal(anyhow::anyhow!("The value of Mono.just was null")))
        }
        None => Ok(None),
        Some(e) if e.status == 200 => {
            Ok(Some((StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], e.body.clone()).into_response()))
        }
        Some(_) => Err(AppError::Internal(anyhow::anyhow!("the Java ui cannot serialize the built-in {key}"))),
    }
}

/// `repositoryFilter`.
pub async fn filter(st: &AppState, caller: &Caller, kind: Kind, q: &HashMap<String, String>) -> AppResult<Response> {
    let (app, client) = codes(caller, q);
    let include = flag(q, "includeKIRunRepos")?;
    // Functions default the parameter to ""; schemas pass null through.
    let filter = match kind {
        Kind::Function => Some(q.get("filter").cloned().unwrap_or_default()),
        Kind::Schema => q.get("filter").cloned(),
    };
    let mut names: Vec<JValue> = Vec::new();
    if include {
        let Some(f) = filter.as_deref() else {
            return Err(AppError::Internal(anyhow::anyhow!(
                "Cannot invoke \"String.toLowerCase()\" because \"name\" is null"
            )));
        };
        let lower = f.to_lowercase();
        names.extend(
            catalog(kind)
                .names
                .iter()
                .filter(|n| n.to_lowercase().contains(&lower))
                .map(|n| JValue::Str(n.clone())),
        );
    }
    for repo_app in repos(st, &app).await? {
        for n in filter_in_repo(st, kind, &repo_app, &client, filter.as_deref()).await? {
            names.push(JValue::Str(n));
        }
    }
    Ok(json_ok(&JValue::Array(names)))
}

/// `filterInRepo`: the names of the objects the client can see in the app, matching the
/// filter as a case-insensitive regex. Not de-duplicated, as in Java.
async fn filter_in_repo(st: &AppState, kind: Kind, app: &str, client: &str, filter: Option<&str>) -> AppResult<Vec<String>> {
    let order = st.store().inheritance_order(app, client, client).await?;
    let codes: Vec<Bson> = order.iter().map(|c| Bson::String(c.clone())).collect();
    let mut q: Document = doc! {"appCode": app, "clientCode": {"$in": codes}};
    if let Some(f) = filter.filter(|f| !f.trim().is_empty()) {
        q.insert("name", Bson::RegularExpression(Regex { pattern: f.to_string(), options: "i".into() }));
    }
    let cursor = st
        .store()
        .db()
        .collection::<Document>(kind.collection())
        .find(q)
        .with_options(FindOptions::builder().projection(doc! {"name": 1}).build())
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let docs: Vec<Document> = cursor.try_collect().await.map_err(|e| AppError::Internal(e.into()))?;
    Ok(docs
        .iter()
        .map(|d| match d.get("name") {
            Some(Bson::String(s)) => s.clone(),
            _ => "null".to_string(),
        })
        .collect())
}
