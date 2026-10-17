//! `AbstractPublishService`: what is pending in an app, and publishing all of it, across every
//! draftable service of the process. Each object goes through its own service's `publish`, so
//! every per-kind eviction runs; one failure is reported and does not stop the rest.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use mongodb::bson::Document;
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::java_map;
use crate::json::{JMap, JValue};
use crate::pojo::str_field;
use crate::write::draft::DraftStore;
use crate::write::messages::{self as msg, error_message};
use crate::write::service::Commons;
use crate::write::AnyService;

pub struct PublishService {
    cx: Commons,
    by_type: HashMap<String, Arc<dyn AnyService>>,
}

impl PublishService {
    /// `services` are keyed by their upper-cased object name, as Java keys them.
    pub fn new(cx: Commons, services: Vec<Arc<dyn AnyService>>) -> Self {
        let by_type = services.into_iter().map(|s| (s.object_name().to_uppercase(), s)).collect();
        Self { cx, by_type }
    }

    /// The object types registered (upper-cased).
    pub fn object_types(&self) -> Vec<String> {
        let mut t: Vec<String> = self.by_type.keys().cloned().collect();
        t.sort();
        t
    }

    /// `pending`: the client's drafts in the app, grouped by object type in the order first
    /// met, each summarized as a `HashMap` (so in that map's key order).
    pub async fn pending(&self, ca: &ContextAuthentication, app: &str, client: Option<&str>) -> AppResult<JMap> {
        let cc = self.authorized_client_code(ca, app, client, false).await?;
        let drafts = self.cx.drafts.pending(app, &cc).await?;
        let mut by_type = JMap::new();
        for d in &drafts {
            let t = str_field(&DraftStore::decode(d), "objectType").map(str::to_string).unwrap_or_else(|| "null".into());
            let entry = by_type.entry(t).or_insert_with(|| JValue::Array(Vec::new()));
            if let JValue::Array(list) = entry {
                list.push(JValue::Object(summarize(d)));
            }
        }
        Ok(by_type)
    }

    /// `publishAll`: every pending draft, one after another, each outcome reported.
    pub async fn publish_all(&self, ca: &ContextAuthentication, app: &str, client: Option<&str>) -> AppResult<JMap> {
        let cc = self.authorized_client_code(ca, app, client, true).await?;
        let drafts = self.cx.drafts.pending(app, &cc).await?;
        let mut results = Vec::with_capacity(drafts.len());
        for d in &drafts {
            results.push(self.publish_one(ca, &DraftStore::decode(d)).await);
        }
        let published = results.iter().filter(|r| r.get("published") == Some(&JValue::Bool(true))).count();
        let mut out = JMap::new();
        out.insert("appCode".into(), JValue::Str(app.to_string()));
        out.insert("clientCode".into(), JValue::Str(cc));
        out.insert("attempted".into(), JValue::Int(results.len() as i64));
        out.insert("published".into(), JValue::Int(published as i64));
        out.insert("results".into(), JValue::Array(results.into_iter().map(JValue::Object).collect()));
        Ok(out)
    }

    async fn publish_one(&self, ca: &ContextAuthentication, draft: &JMap) -> JMap {
        let object_type = str_field(draft, "objectType").unwrap_or_default().to_string();
        let mut result = JMap::new();
        result.insert("objectType".into(), draft.get("objectType").cloned().unwrap_or_default());
        result.insert("name".into(), draft.get("objectName").cloned().unwrap_or_default());
        result.insert("objectId".into(), draft.get("objectId").cloned().unwrap_or_default());
        let Some(service) = self.by_type.get(&object_type) else {
            result.insert("published".into(), JValue::Bool(false));
            result.insert("error".into(), JValue::Str(format!("No publishable service for object type {object_type}")));
            return result;
        };
        match service.publish(ca, str_field(draft, "objectId").unwrap_or_default(), str_field(draft, "message")).await {
            Ok(_) => {
                result.insert("published".into(), JValue::Bool(true));
            }
            Err(e) => {
                result.insert("published".into(), JValue::Bool(false));
                result.insert("error".into(), JValue::Str(error_message(&e)));
            }
        }
        result
    }

    /// `authorizedClientCode`: the client to act on (the caller's own unless it names one it
    /// manages, or it is a system client) and the caller's read (list) or write (publish)
    /// access to the app. Every refusal is the same 403, which names nothing.
    async fn authorized_client_code(&self, ca: &ContextAuthentication, app: &str, client: Option<&str>, write: bool) -> AppResult<String> {
        let refused = || -> AppError { self.cx.messages.refusal(ca, StatusCode::FORBIDDEN, msg::FORBIDDEN_APP_ACCESS, &[app]) };
        if !ca.authenticated {
            return Err(refused());
        }
        let dir = self.cx.directory();
        let cc = match client.filter(|c| !c.trim().is_empty()) {
            None => ca.client_code().to_string(),
            Some(c) if c == ca.client_code() || ca.is_system_client() => c.to_string(),
            Some(c) => {
                if !dir.does_client_manage_client_code(ca.client_code(), c).await? {
                    return Err(refused());
                }
                c.to_string()
            }
        };
        let allowed = if write {
            dir.has_write_access(app, ca.client_code()).await?
        } else {
            dir.has_read_access(app, ca.client_code()).await?
        };
        if !allowed {
            return Err(refused());
        }
        Ok(cc)
    }
}

/// `summarize`: a `HashMap` of the draft's headers.
fn summarize(d: &Document) -> JMap {
    let draft = DraftStore::decode(d);
    let mut m = JMap::new();
    for (k, from) in [
        ("objectType", "objectType"),
        ("name", "objectName"),
        ("objectId", "objectId"),
        ("clientCode", "clientCode"),
        ("baseVersion", "baseVersion"),
        ("message", "message"),
        ("updatedAt", "updatedAt"),
        ("updatedBy", "updatedBy"),
    ] {
        m.insert(k.to_string(), draft.get(from).cloned().unwrap_or_default());
    }
    java_map::by_puts(m)
}
