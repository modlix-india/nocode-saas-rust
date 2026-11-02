//! `AbstractVersionService`: the `version` collection. A row is written on every create and
//! update of a versionable object (by the service, which has already checked access); the
//! caller-facing reads check access themselves, against the object type's authority.

use mongodb::bson::{doc, Document};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::backend::Find;
use crate::json::{JMap, JValue};
use crate::pojo::{decode_bson, str_field, to_jackson, CloneRule as C, Field, Kind as K, Pojo};
use crate::store::Store;
use crate::write::condition::{Condition, FilterCondition, Operator, Query};
use crate::write::persist::{to_document, Clock};
use crate::write::service::user_id;
use crate::write::spring::{known_total, page_json, Order, Pageable, Sort};

/// The `Version` document class.
pub const VERSION: Pojo = Pojo {
    name: "Version",
    parts: &[
        &[
            Field::new("id", K::Str, C::Copy),
            Field::new("createdAt", K::DateTime, C::Copy),
            Field::new("createdBy", K::Str, C::Copy),
        ],
        &[
            Field::new("objectName", K::Str, C::Copy),
            Field::new("objectAppCode", K::Str, C::Copy),
            Field::new("clientCode", K::Str, C::Copy),
            Field::new("message", K::Str, C::Copy),
            Field::new("objectType", K::Str, C::Copy),
            Field::new("object", K::MapObject, C::Copy),
            Field::new("versionNumber", K::PrimInt(1), C::Copy),
            Field::new("subElementKey", K::Str, C::Copy),
        ],
    ],
};

const COLLECTION: &str = "version";

/// ui's `VersionService.mapAuthName`.
pub const UI_AUTH_NAMES: &[(&str, &str)] = &[
    ("APPLICATION", "Application"),
    ("PAGE", "Page"),
    ("PERSONALIZATION", "Personalization"),
    ("STYLE", "Style"),
    ("THEME", "Theme"),
    ("FUNCTION", "Function"),
    ("SCHEMA", "Schema"),
];

/// core's `VersionService.mapAuthName`.
pub const CORE_AUTH_NAMES: &[(&str, &str)] = &[
    ("ACTION", "Action"),
    ("CONNECTION", "Connection"),
    ("FUNCTION", "Function"),
    ("SCHEMA", "Schema"),
    ("EVENTACTION", "EventAction"),
    ("EVENTDEFINITION", "EventDefinition"),
    ("STORAGE", "Storage"),
    ("TEMPLATE", "Template"),
];

/// A row to write.
#[derive(Debug, Clone)]
pub struct NewVersion {
    pub client_code: Option<String>,
    pub object_name: Option<String>,
    pub object_app_code: Option<String>,
    pub object_type: String,
    pub version_number: i64,
    pub message: Option<String>,
    /// The object as Jackson maps it (dates as `Long`s).
    pub object: Document,
}

/// Rust only: how one object type's history is held back in replies, as its kind's
/// [`crate::write::kind::Kind::redact`] holds back the object (core's connections).
#[derive(Clone, Copy)]
pub struct VersionRedaction {
    /// The rows' `objectType` (`CONNECTION`).
    pub object_type: &'static str,
    /// The row's `object` as a reply carries it.
    pub redact: fn(JMap) -> JMap,
    /// Whether a history query may filter or sort on a field of the row (`object.<path>`).
    pub filterable: fn(&str) -> bool,
}

#[derive(Clone)]
pub struct VersionStore {
    store: Store,
    auth_names: &'static [(&'static str, &'static str)],
    redactions: &'static [VersionRedaction],
}

impl VersionStore {
    pub fn new(store: Store, auth_names: &'static [(&'static str, &'static str)]) -> Self {
        Self { store, auth_names, redactions: &[] }
    }

    /// The store whose replies hold back what `redactions` say.
    pub fn with_redactions(mut self, redactions: &'static [VersionRedaction]) -> Self {
        self.redactions = redactions;
        self
    }

    fn redaction(&self, object_type: Option<&str>) -> Option<&'static VersionRedaction> {
        let t = object_type?;
        self.redactions.iter().find(|r| r.object_type == t)
    }

    /// The row as a reply carries it.
    fn redacted(&self, mut v: JMap) -> JMap {
        if let Some(r) = self.redaction(str_field(&v, "objectType")) {
            if let Some(JValue::Object(o)) = v.get_mut("object") {
                *o = (r.redact)(std::mem::take(o));
            }
        }
        v
    }

    fn auth_name(&self, object_type: &str) -> &'static str {
        // A type the map lacks checks `Authorities.null_READ`, which nobody holds.
        self.auth_names.iter().find(|(t, _)| *t == object_type).map(|(_, n)| *n).unwrap_or("null")
    }

    /// `create`: stamped with the caller and the time. Answers the row.
    pub async fn create(&self, ca: &ContextAuthentication, v: NewVersion) -> AppResult<JMap> {
        let clock = Clock::now();
        let s = |x: &Option<String>| x.clone().map(JValue::Str).unwrap_or_default();
        let mut e = JMap::new();
        e.insert("objectName".into(), s(&v.object_name));
        e.insert("objectAppCode".into(), s(&v.object_app_code));
        e.insert("clientCode".into(), s(&v.client_code));
        e.insert("message".into(), s(&v.message));
        e.insert("objectType".into(), JValue::Str(v.object_type.clone()));
        e.insert("object".into(), JValue::Object(crate::bson_conv::doc_to_j(&v.object)));
        e.insert("versionNumber".into(), JValue::Int(v.version_number));
        e.insert("createdAt".into(), clock.value());
        e.insert("createdBy".into(), user_id(ca).map(JValue::Str).unwrap_or_default());
        let mut d = to_document(&VERSION, &e, Some(&clock), &[]);
        d.insert("object", v.object);
        let id = self.store.backend().insert(COLLECTION, d).await?;
        e.insert("id".into(), crate::bson_conv::to_java_string(&id));
        Ok(e)
    }

    /// `read(id)`: the row for a caller who may read it, `None` otherwise (Java answers an
    /// empty 200 either way).
    pub async fn read(&self, ca: &ContextAuthentication, id: &str) -> AppResult<Option<JMap>> {
        let Some(d) = self.store.backend().find_one(COLLECTION, Store::id_filter(id), None).await? else {
            return Ok(None);
        };
        let v = decode_bson(&VERSION, &d);
        Ok(self.access_check(ca, &v).await?.then(|| self.redacted(v)))
    }

    /// `accessCheck`: the type's `_READ` authority, then the caller's own client or a client in
    /// its inheritance chain, then read access to the app. Java looks only for the caller in its
    /// own chain, which is always there, so any client could read any other's history; here the
    /// version's client must be in the chain (see `DIFFERENCES.md`).
    async fn access_check(&self, ca: &ContextAuthentication, v: &JMap) -> AppResult<bool> {
        let Some(object_type) = str_field(v, "objectType").filter(|t| !t.trim().is_empty()) else {
            return Ok(false);
        };
        if !ca.has_authority(&format!("Authorities.{}_READ", self.auth_name(object_type))) {
            return Ok(false);
        }
        let app = str_field(v, "objectAppCode").unwrap_or_default();
        let mine = ca.client_code();
        let managed = if str_field(v, "clientCode") == Some(mine) {
            true
        } else {
            let url = ca.url_client_code.as_deref().unwrap_or("");
            let theirs = str_field(v, "clientCode").unwrap_or_default();
            let order = self.store.inheritance_order(app, url, mine).await?;
            order.iter().any(|c| c == mine) && order.iter().any(|c| c == theirs)
        };
        if !managed {
            return Ok(false);
        }
        Ok(self.store.directory().has_read_access(app, mine).await?)
    }

    /// `readPagePerObjectId`: one object's history, newest first unless the query sorts
    /// otherwise, as a `Page`. Java checks nothing here; this answers an empty page unless the
    /// caller passes [`Self::read`]'s check on the object's history (see `DIFFERENCES.md`).
    pub async fn read_page_per_object_id(&self, ca: &ContextAuthentication, id: &str, query: &Query) -> AppResult<JValue> {
        let id_condition = Condition::Filter(FilterCondition::new("object.id", Operator::Equals, JValue::Str(id.to_string())));
        let condition = match &query.condition {
            Some(c) if !query.condition_is_empty() => Condition::and(vec![id_condition, c.clone()]),
            _ => id_condition,
        };
        let sort = if query.sort == Query::default_sort() { Sort::by(vec![Order::desc("createdAt")]) } else { query.sort.clone() };
        if query.page < 0 || query.size < 1 {
            return Err(AppError::Internal(anyhow::anyhow!("Page index must not be less than zero and page size must not be less than one")));
        }
        let pageable = Pageable::of(query.page, query.size, sort);
        let any = self.store.backend().find_one(COLLECTION, doc! {"object.id": id}, None).await?;
        let any = any.map(|d| decode_bson(&VERSION, &d));
        let allowed = match &any {
            Some(v) => self.access_check(ca, v).await?,
            None => true,
        };
        // A type whose objects are held back cannot be filtered or sorted on what is held back
        // (a projection is harmless: the rows are held back after it).
        let refused = |r: &VersionRedaction| {
            let condition_fields = query.condition.as_ref().map(Condition::fields).unwrap_or_default();
            let sorted = pageable.sort.0.iter().map(|o| o.property.as_str());
            !condition_fields.into_iter().chain(sorted).all(r.filterable)
        };
        let held_back = any.as_ref().and_then(|v| self.redaction(str_field(v, "objectType")));
        if !allowed || held_back.is_some_and(refused) {
            return Ok(page_json(Vec::new(), &pageable, 0));
        }
        let filter = Condition::to_mongo(Some(&condition))?;
        let mut find = Find::new(filter.clone()).sort(pageable.sort.to_mongo()).skip(pageable.offset() as u64).limit(pageable.size);
        if let Some(fields) = query.fields.as_ref().filter(|f| !f.is_empty()) {
            let flag = if query.exclude_fields { 0 } else { 1 };
            let mut p = Document::new();
            for f in fields {
                p.insert(f.clone(), flag);
            }
            find = find.projection(p);
        }
        let docs = self.store.backend().find(COLLECTION, find).await?;
        let content: Vec<JValue> = docs.iter().map(|d| JValue::Object(to_jackson(&VERSION, &self.redacted(decode_bson(&VERSION, d))))).collect();
        let total = match known_total(content.len(), &pageable) {
            Some(t) => t,
            None => self.store.backend().count(COLLECTION, filter).await? as i64,
        };
        Ok(page_json(content, &pageable, total))
    }

    /// `deleteBy`: an app's history of one type for one client.
    pub async fn delete_by(&self, app: &str, client: &str, object_type: &str) -> AppResult<u64> {
        Ok(self
            .store
            .backend()
            .delete_many(COLLECTION, doc! {"objectAppCode": app, "clientCode": client, "objectType": object_type})
            .await?)
    }

    /// `contentAt`: the object as it stood at one version (the newest such row), if kept.
    pub async fn content_at(&self, object_type: &str, app: &str, name: &str, client: &str, version_number: i64) -> AppResult<Option<JMap>> {
        let filter = doc! {"objectType": object_type, "objectAppCode": app, "objectName": name, "clientCode": client, "versionNumber": version_number};
        let d = self.store.backend().find_one(COLLECTION, filter, Some(doc! {"createdAt": -1})).await?;
        Ok(d.and_then(|d| decode_bson(&VERSION, &d).get("object").and_then(JValue::as_object).cloned()))
    }
}
