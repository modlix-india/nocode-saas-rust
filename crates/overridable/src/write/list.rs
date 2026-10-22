//! The list reads of `AbstractOverridableDataService`: `readPageFilterLRO` (the `GET` list
//! route: one header row per name across the caller's inheritance chain, paged after the
//! override chain is resolved), `readIndexLRO`, and `readForTransport`.

use std::collections::HashSet;
use std::sync::Arc;

use axum::http::StatusCode;
use mongodb::bson::{doc, Bson, Document};
use platform::error::AppResult;
use platform::security::ContextAuthentication;

use crate::backend::Find;
use crate::json::{JMap, JValue};
use crate::pojo::{decode_bson, str_field, to_jackson, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use crate::write::condition::{Condition, FilterCondition, Operator};
use crate::write::kind::Kind;
use crate::write::messages as msg;
use crate::write::service::OverridableService;
use crate::write::spring::{page_json, Pageable, Params, Sort};

/// `ListResultObject`: the header fields, and `data` when the list is eager.
pub const LRO: Pojo = Pojo { name: "ListResultObject", parts: &[OVERRIDABLE_BASE, &[Field::new("data", K::Object, C::Copy)]] };

/// The persisted fields a list row carries (`LRO_FIELDS`); the definitions stay in Mongo.
const LRO_FIELDS: &[&str] = &[
    "_id", "name", "message", "clientCode", "permission", "appCode", "baseClientCode", "notOverridable", "description", "title",
    "published", "version", "createdAt", "createdBy", "updatedAt", "updatedBy",
];

/// Parameters that are never turned into a filter. `clientOnly` is added to Java's list (see
/// `DIFFERENCES.md`): Java filters on a `clientOnly` field no document has, so asking for it
/// answered nothing at all.
const IGNORED: &[&str] = &["clientCode", "appCode", "size", "page", "sort", "eager", "clientOnly"];

/// One index: rows a client sees in an app, as headers.
const INDEX_PAGE_SIZE: i64 = 1000;

/// A computed list page: its rows (Jackson maps) and the total before paging.
#[derive(Debug, Clone)]
pub struct LroPage {
    pub content: Vec<JMap>,
    pub total: i64,
}

impl LroPage {
    /// The `Page` JSON for `pageable`.
    pub fn to_json(&self, pageable: &Pageable) -> JValue {
        page_json(self.content.iter().cloned().map(JValue::Object).collect(), pageable, self.total)
    }
}

impl<K: Kind> OverridableService<K> {
    /// `readPageFilterLRO`. Cached (per caller's client, page, size, eager, sort and
    /// `clientOnly`) when the request carries nothing but the app and paging; a managed
    /// client's list and a filtered one are not. The access check runs before the cache is
    /// consulted (Java checks only on a miss; see `DIFFERENCES.md`).
    pub async fn read_page_filter_lro(&self, ca: &ContextAuthentication, eager: bool, client_only: bool, pageable: &Pageable, params: &Params) -> AppResult<LroPage> {
        let app = params.first("appCode").unwrap_or("").to_string();
        let ignore_count = 1 + ["page", "size", "sort", "eager", "clientOnly"].iter().filter(|k| params.contains(k)).count();
        if params.len() == ignore_count || params.is_empty() {
            self.list_access(ca, &app, params.first("clientCode"), false).await?;
            let key = format!(
                "{}:{}:{}:{}:{}:{}",
                ca.client_code(),
                pageable.page,
                pageable.size,
                eager,
                pageable.sort.java_string(),
                client_only
            );
            let (this, ca2, p, pg) = (self.clone(), ca.clone(), params.clone(), pageable.clone());
            let a = app.clone();
            let page = self
                .lro_cache()
                .get_or_load(&self.read_page_cache_name(&app), key, || async move {
                    Ok::<_, platform::error::AppError>(Some(Arc::new(this.compute_lro(&ca2, eager, client_only, &pg, &p, &a).await?)))
                })
                .await?;
            return Ok(page.map(|p| (*p).clone()).unwrap_or(LroPage { content: Vec::new(), total: 0 }));
        }
        self.compute_lro(ca, eager, client_only, pageable, params, &app).await
    }

    /// `readIndexLRO`: every object of this type the client sees in the app, one row per name.
    pub async fn read_index_lro(&self, ca: &ContextAuthentication, app: &str, client: Option<&str>) -> AppResult<LroPage> {
        let mut params = Params::of(&[("appCode", app)]);
        if let Some(c) = client.filter(|c| !c.trim().is_empty()) {
            params.add("clientCode", c);
        }
        self.read_page_filter_lro(ca, false, false, &Pageable::of(0, INDEX_PAGE_SIZE, Sort::unsorted()), &params).await
    }

    /// The access check of the list: read access to the app for the caller's own client, or
    /// for a client it manages. Answers the client listed.
    async fn list_access(&self, ca: &ContextAuthentication, app: &str, client: Option<&str>, system_skips_read: bool) -> AppResult<String> {
        let refused = || self.commons().messages.refusal(ca, StatusCode::FORBIDDEN, msg::FORBIDDEN_APP_ACCESS, &[app]);
        if !ca.authenticated {
            return Err(refused());
        }
        let dir = self.commons().directory();
        let (allowed, cc) = match client {
            Some(c) if system_skips_read && ca.is_system_client() => (true, c.to_string()),
            None => (dir.has_read_access(app, ca.client_code()).await?, ca.client_code().to_string()),
            Some(c) if c == ca.client_code() => (dir.has_read_access(app, ca.client_code()).await?, ca.client_code().to_string()),
            Some(c) => {
                if !dir.does_client_manage_client_code(ca.client_code(), c).await? {
                    return Err(refused());
                }
                (dir.has_read_access(app, c).await?, c.to_string())
            }
        };
        if !allowed {
            return Err(refused());
        }
        Ok(cc)
    }

    /// `paramToConditionLRO`: the inheritance chain of the listed client and one condition
    /// per parameter. `None` when a named client is not the caller's to list.
    async fn param_to_condition_lro(&self, ca: &ContextAuthentication, params: &Params, app: &str) -> AppResult<Option<(Condition, Vec<String>)>> {
        let dir = self.commons().directory();
        if let Some(c) = params.first("clientCode") {
            if !ca.is_system_client() && !dir.does_client_manage_client_code(ca.client_code(), c).await? {
                return Ok(None);
            }
        }
        let fin = params.first("clientCode").unwrap_or(ca.client_code()).to_string();
        let order = self.commons().store.inheritance_order(app, ca.client_code(), &fin).await?;
        let mut conditions = Vec::new();
        conditions.push(Condition::Filter(match order.as_slice() {
            [one] => FilterCondition::new("clientCode", Operator::Equals, JValue::Str(one.clone())),
            many => FilterCondition::new("clientCode", Operator::In, JValue::Str(many.join(","))),
        }));
        let mut app_condition = FilterCondition::new("appCode", Operator::Equals, JValue::Null);
        app_condition.value = params.first("appCode").map(|a| JValue::Str(a.to_string()));
        conditions.push(Condition::Filter(app_condition));
        for k in params.keys() {
            if IGNORED.contains(&k) {
                continue;
            }
            let values = params.all(k);
            conditions.push(Condition::Filter(match values.as_slice() {
                [one] => FilterCondition::new(k, Operator::StringLooseEqual, JValue::Str(one.to_string())),
                many => FilterCondition::multi(k, many.iter().map(|v| JValue::Str(v.to_string())).collect()),
            }));
        }
        Ok(Some((Condition::and(conditions), order.to_vec())))
    }

    async fn compute_lro(&self, ca: &ContextAuthentication, eager: bool, client_only: bool, pageable: &Pageable, params: &Params, app: &str) -> AppResult<LroPage> {
        let listed = self.list_access(ca, app, params.first("clientCode"), false).await?;
        let Some((condition, inheritance)) = self.param_to_condition_lro(ca, params, app).await? else {
            return Ok(LroPage { content: Vec::new(), total: 0 });
        };
        let mut all: Vec<Bson> = vec![
            Bson::Document(Condition::to_mongo(Some(&condition))?),
            Bson::Document(doc! {"$or": [{"notOverridable": {"$ne": true}}, {"clientCode": &listed}]}),
        ];
        if client_only {
            all.push(Bson::Document(doc! {"clientCode": &listed}));
        }
        let mut projection = Document::new();
        for f in LRO_FIELDS {
            projection.insert(*f, 1);
        }
        let find = Find::new(doc! {"$and": all}).sort(pageable.sort.to_mongo()).projection(projection);
        let rows: Vec<JMap> = self
            .commons()
            .backend()
            .find(self.collection(), find)
            .await?
            .iter()
            .map(|d| decode_bson(&LRO, d))
            .collect();

        let in_client = inheritance.last().cloned();
        let mut chosen: indexmap::IndexMap<String, String> = indexmap::IndexMap::new();
        for r in &rows {
            let name = r.get("name").cloned().unwrap_or_default().java_to_string();
            let id = str_field(r, "id").unwrap_or_default().to_string();
            match chosen.get(&name) {
                None => {
                    chosen.insert(name, id);
                }
                Some(_) if str_field(r, "clientCode") == in_client.as_deref() => {
                    chosen.insert(name, id);
                }
                Some(_) => {}
            }
        }
        let ids: HashSet<&String> = chosen.values().collect();
        let kept: Vec<&JMap> = rows.iter().filter(|r| str_field(r, "id").is_some_and(|i| ids.contains(&i.to_string()))).collect();
        let total = kept.len() as i64;
        let from = pageable.offset().max(0) as usize;
        let to = (from + pageable.size.max(0) as usize).min(kept.len());
        let slice: Vec<&JMap> = if kept.len() > from { kept[from..to].to_vec() } else { Vec::new() };
        let mut content = Vec::with_capacity(slice.len());
        for row in slice {
            let mut row = row.clone();
            if eager {
                let id = str_field(&row, "id").unwrap_or_default().to_string();
                let data = self.read(ca, &id).await?;
                row.insert("data".into(), JValue::Object(to_jackson(self.kind().pojo(), &data)));
            }
            content.push(to_jackson(&LRO, &row));
        }
        Ok(LroPage { content, total })
    }

    /// `readForTransport`: the objects of `client` in `app` (only `names`, when given), merged,
    /// as a transport carries them.
    pub async fn read_for_transport(&self, ca: &ContextAuthentication, app: &str, client: &str, names: Option<&[String]>) -> AppResult<Vec<JMap>> {
        if app.trim().is_empty() || client.trim().is_empty() {
            return Err(self.commons().messages.refusal(ca, StatusCode::FORBIDDEN, msg::FORBIDDEN_APP_ACCESS, &[app]));
        }
        self.list_access(ca, app, Some(client), true).await?;
        let mut params = Params::of(&[("clientCode", client), ("appCode", app)]);
        for n in names.unwrap_or_default() {
            params.add("name", n);
        }
        let Some((condition, _)) = self.param_to_condition_lro(ca, &params, app).await? else {
            return Ok(Vec::new());
        };
        let filter = doc! {"$and": [
            Condition::to_mongo(Some(&condition))?,
            {"$or": [{"notOverridable": {"$ne": true}}, {"clientCode": client}]},
        ]};
        let find = Find::new(filter).projection(doc! {"_id": 1});
        let docs = self.commons().backend().find(self.collection(), find).await?;
        let mut out = Vec::new();
        for d in docs {
            let id = crate::bson_conv::to_java_string(d.get("_id").unwrap_or(&Bson::Null)).java_to_string();
            if let Some(e) = self.read_internal(&id).await? {
                if str_field(&e, "clientCode") == Some(client) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }

    /// `readToTransport`: the version and id of the client's own row of `name`, for an import
    /// to update rather than create; `None` when there is none or the caller may not create.
    /// A nameless object (`name` None) finds the stored `name: null` row: looking it up as ""
    /// misses it, and the create that follows then 409s on every import.
    pub async fn read_to_transport(&self, ca: &ContextAuthentication, name: Option<&str>, app: &str, client: &str) -> AppResult<Option<(i64, String)>> {
        if !self.access_check(ca, crate::write::kind::Method::Create, Some(app), Some(client), true).await? {
            return Ok(None);
        }
        Ok(self
            .find_one_named(name, app, client)
            .await?
            .map(|e| (crate::write::service::version_of(&e), str_field(&e, "id").unwrap_or_default().to_string())))
    }
}
