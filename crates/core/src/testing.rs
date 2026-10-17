//! Helpers for the tests: a stand-in HTTP service, a caller, and the switch for the tests that
//! need the local stack.

use std::sync::Arc;

use axum::Router;
use serde_json::Value;

use crate::auth::Authentication;
use crate::context::RequestContext;

/// Serves `router` on a free local port and gives its base URL.
pub async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

/// An `Authentication` from security's JSON and the two header codes.
pub fn auth(raw: Value, client_code: Option<&str>, app_code: Option<&str>) -> Authentication {
    let raw = raw.as_object().cloned().unwrap_or_default();
    let mut ca: platform::security::ContextAuthentication =
        serde_json::from_value(Value::Object(raw.clone())).expect("context authentication");
    ca.url_client_code = client_code.map(String::from);
    ca.url_app_code = app_code.map(String::from);
    Authentication { ca, raw }
}

/// A signed-in SYSTEM user with `authorities`.
pub fn user(authorities: &[&str]) -> Authentication {
    auth(
        serde_json::json!({
            "user": {"id": 142, "clientId": 1, "userName": "tester", "stringAuthorities": authorities,
                     "accountNonExpired": true},
            "authenticated": true, "loggedInFromClientId": 1, "loggedInFromClientCode": "SYSTEM",
            "clientTypeCode": "SYS", "clientCode": "SYSTEM", "accessToken": "token-1",
            "accessTokenExpiryAt": 1, "verifiedAppCode": "appbuilder"
        }),
        Some("SYSTEM"),
        Some("appbuilder"),
    )
}

/// A request context around `auth`.
pub fn request(auth: Authentication, draft: bool, debug: Option<&str>) -> Arc<RequestContext> {
    Arc::new(RequestContext {
        auth: Arc::new(auth),
        app_code: Some("appbuilder".into()),
        client_code: Some("SYSTEM".into()),
        forwarded_host: "localhost".into(),
        forwarded_port: "8080".into(),
        draft,
        debug: debug.map(String::from),
        raised: Default::default(),
    })
}

/// The tests against the local stack (Mongo, MySQL, security, entity-processor) run with
/// `CORE_LOCAL_STACK=1` and `--include-ignored`, and the secrets of `config/local.env` in the
/// environment.
pub fn local_stack() -> bool {
    std::env::var("CORE_LOCAL_STACK").is_ok_and(|v| v == "1")
}

/// The storage service over services nobody listens on: Mongo, MySQL and security are only
/// reached when an operation needs them, so what is decided before that can be tested.
pub async fn offline_storage_service() -> Arc<crate::storage::service::AppDataService> {
    use platform::upstream::Upstream;
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).expect("cache");
    let mongo = mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=300&connectTimeoutMS=300")
        .await
        .expect("client")
        .database("core");
    let security = platform::security::SecurityClient::new(Upstream::fixed(&["http://127.0.0.1:1"]), 0).expect("security");
    let store = overridable::Store::new(mongo, security.clone(), &cache);
    let defs = Arc::new(crate::repos::app::Definitions::new(
        store,
        security.clone(),
        cache.family(),
        std::time::Duration::from_secs(5),
    ));
    let mut cfg = crate::config::CoreConfig::default();
    cfg.mongo.uri = "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=300&connectTimeoutMS=300".into();
    cfg.database.host = "127.0.0.1".into();
    cfg.database.port = 1;
    let defs = crate::storage_defs(&cache, defs, crate::state::Builtins::core_schemas());
    let events = Arc::new(crate::integrations::MqEvents { mq: Arc::new(crate::integrations::Mq::with(Arc::new(crate::integrations::Dropped), &cfg.mq)) });
    Arc::new(crate::storage_service(&cfg, &cache, defs, security, crate::state::Builtins::kirun_schemas(), events))
}

/// Everything the core functions are built over, offline: security at `security_base`,
/// Mongo, MySQL and Redis unreachable (and lazy).
pub async fn offline_deps(security_base: &str, storage: Arc<crate::storage::service::AppDataService>) -> crate::repos::core_functions::Deps {
    use platform::upstream::Upstream;
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).expect("cache");
    let mongo = mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=300&connectTimeoutMS=300")
        .await
        .expect("client")
        .database("core");
    let security = platform::security::SecurityClient::new(Upstream::fixed(&[security_base]), 0).expect("security");
    let store = overridable::Store::new(mongo.clone(), security.clone(), &cache);
    let definitions = Arc::new(crate::repos::app::Definitions::new(store, security, cache.family(), std::time::Duration::from_secs(5)));
    let calls = Arc::new(crate::clients::SecurityCalls::new(Upstream::fixed(&[security_base])).expect("calls"));
    let defs = crate::storage_defs(&cache, definitions, crate::state::Builtins::core_schemas());
    let cfg = crate::config::CoreConfig::default();
    let mq = Arc::new(crate::integrations::Mq::with(Arc::new(crate::integrations::Dropped), &cfg.mq));
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("mysql://root@127.0.0.1:1/core")
        .expect("pool");
    let files = Arc::new(crate::files_calls::FilesCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).expect("files"));
    let integrations = Arc::new(
        crate::integrations::Integrations::new(
            &cfg,
            Arc::new(crate::integrations::StoreDocs { defs: defs.clone() }),
            calls.clone(),
            crate::integrations::token_dao(&cfg, pool).expect("tokens"),
            cache.clone(),
            mq,
            Some(files.clone() as Arc<dyn crate::integrations::FileCreate>),
        )
        .expect("integrations"),
    );
    let message = Arc::new(crate::message_calls::MessageCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).expect("message"));
    let platform = Arc::new(
        crate::platform_calls::PlatformCalls::new(crate::platform_calls::Upstreams::all(Upstream::fixed(&["http://127.0.0.1:1"])))
            .expect("platform"),
    );
    crate::repos::core_functions::Deps {
        security: calls,
        storage,
        defs,
        mongo,
        cache,
        integrations,
        message,
        files,
        scheduler: Default::default(),
        platform,
    }
}

pub use doubles::*;

/// Stand-ins for the definitions, the engines, security, events and triggers, so the storage
/// policy layer can be driven without the stack.
mod doubles {
    use std::collections::HashMap;
    use std::sync::Arc;

    use appdata::engine::{AppDataEngine, Ctx};
    use appdata::model::{
        AggregateQuery, Condition, Connection, DataObject, DraftCopyFilter, FilterOperator, Page, Query, Storage, StorageRelation,
    };
    use appdata::value::{Document, Value};
    use appdata::{AppDataError, AppDataResult};
    use async_trait::async_trait;
    use axum::extract::RawQuery;
    use axum::routing::get;
    use axum::Router;
    use indexmap::IndexMap;
    use overridable::JMap;
    use parking_lot::Mutex;

    use crate::error::CoreError;
    use crate::repos::SchemaSource;
    use crate::storage::defs::Catalog;
    use crate::storage::service::{AppDataService, Backends, EventSink, TriggerRunner};

    #[derive(Default)]
    pub struct MemoryCatalog {
        pub storages: Mutex<Vec<Storage>>,
        pub connection: Mutex<Option<Connection>>,
        pub events: Mutex<HashMap<String, JMap>>,
        pub lookups: Mutex<Vec<String>>,
        pub fail_storage: Mutex<Option<CoreError>>,
    }

    impl MemoryCatalog {
        pub fn with(storages: Vec<Storage>) -> Arc<Self> {
            let c = Self::default();
            *c.storages.lock() = storages;
            Arc::new(c)
        }
    }

    #[async_trait]
    impl Catalog for MemoryCatalog {
        async fn storage(&self, name: &str, _app: &str, _client: &str) -> Result<Option<Storage>, CoreError> {
            if let Some(e) = self.fail_storage.lock().clone() {
                return Err(e);
            }
            Ok(self.storages.lock().iter().find(|s| s.name == name).cloned())
        }
        async fn connection(&self, _: &str, _: &str, _: &str, _: &str) -> Result<Option<Connection>, CoreError> {
            Ok(self.connection.lock().clone())
        }
        async fn raw_connection(&self, _: &str, _: &str, _: &str) -> Result<Option<Connection>, CoreError> {
            Ok(self.connection.lock().clone())
        }
        async fn all_app_data(&self, _: &str, _: &str) -> Result<Vec<Connection>, CoreError> {
            Ok(self.connection.lock().clone().into_iter().collect())
        }
        async fn storages_referencing(&self, _app: &str, target: &str) -> Result<Vec<String>, CoreError> {
            Ok(self
                .storages
                .lock()
                .iter()
                .filter(|s| {
                    s.relations
                        .as_ref()
                        .is_some_and(|r| r.values().any(|x| x.storage_name.as_deref() == Some(target)))
                })
                .map(|s| s.name.clone())
                .collect())
        }
        async fn storage_names(&self, _: &str) -> Result<Vec<String>, CoreError> {
            let mut n: Vec<String> = self.storages.lock().iter().map(|s| s.name.clone()).collect();
            n.sort();
            Ok(n)
        }
        async fn event_definition(&self, name: &str, app: &str, client: &str) -> Result<Option<JMap>, CoreError> {
            self.lookups.lock().push(format!("{app}/{client}/{name}"));
            Ok(self.events.lock().get(name).cloned())
        }
        async fn schema_source(&self, _: &str, _: &str) -> Result<Arc<dyn SchemaSource>, CoreError> {
            Ok(crate::state::Builtins::core_schemas())
        }
    }

    /// Rows by storage name, in insertion order; every call recorded.
    #[derive(Default)]
    pub struct MemoryEngine {
        pub rows: Mutex<IndexMap<String, IndexMap<String, Document>>>,
        pub calls: Mutex<Vec<String>>,
        pub updates: Mutex<Vec<(Document, Option<bool>)>>,
        pub next: Mutex<u64>,
        /// What `update` answers when the row is missing: Mongo's 404, or MySQL's empty.
        pub empty_update: Mutex<bool>,
        pub enforces: Mutex<bool>,
    }

    fn matches(row: &Document, c: &Option<Condition>) -> bool {
        match c {
            Some(Condition::Filter(f)) => {
                let v = f.field.as_deref().and_then(|k| row.get(k));
                match f.operator {
                    Some(FilterOperator::In) => {
                        let ids = f.multi_value.clone().unwrap_or_default();
                        v.is_some_and(|v| ids.iter().any(|i| i.java_string() == v.java_string()))
                    }
                    _ => v.is_some_and(|v| Some(v.java_string()) == f.value.as_ref().map(Value::java_string)),
                }
            }
            _ => true,
        }
    }

    /// Where a storage's rows are on a surface.
    fn key(cx: &Ctx, storage: &Storage) -> String {
        if cx.draft {
            format!("{}#draft", storage.name)
        } else {
            storage.name.clone()
        }
    }

    impl MemoryEngine {
        pub fn insert_draft(&self, storage: &str, id: &str, mut row: Document) {
            row.insert("_id".into(), Value::String(id.into()));
            self.rows.lock().entry(format!("{storage}#draft")).or_default().insert(id.into(), row);
        }

        pub fn draft_count(&self, storage: &str) -> usize {
            self.count(&format!("{storage}#draft"))
        }

        fn log(&self, s: String) {
            self.calls.lock().push(s);
        }

        pub fn insert(&self, storage: &str, id: &str, mut row: Document) {
            row.insert("_id".into(), Value::String(id.into()));
            self.rows.lock().entry(storage.into()).or_default().insert(id.into(), row);
        }

        pub fn count(&self, storage: &str) -> usize {
            self.rows.lock().get(storage).map(IndexMap::len).unwrap_or(0)
        }

        fn page(&self, storage: &str, query: &Query) -> AppDataResult<Page<Document>> {
            let rows = self.list(storage, query);
            let total = rows.len() as i64;
            Ok(Page::of(rows, query.pageable()?, || total))
        }

        fn list(&self, storage: &str, query: &Query) -> Vec<Document> {
            self.rows
                .lock()
                .get(storage)
                .map(|m| m.values().filter(|r| matches(r, &query.condition)).cloned().collect())
                .unwrap_or_default()
        }

        fn referencing(&self, child: &str, field: &str, id: &str) -> Vec<String> {
            self.rows
                .lock()
                .get(child)
                .map(|m| {
                    m.iter()
                        .filter(|(_, r)| match r.get(field) {
                            Some(Value::Array(a)) => a.iter().any(|x| x.java_string() == id),
                            Some(v) => v.java_string() == id,
                            None => false,
                        })
                        .map(|(k, _)| k.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    #[async_trait]
    impl AppDataEngine for MemoryEngine {
        fn backend(&self) -> &'static str {
            "memory"
        }

        async fn create(&self, cx: &Ctx, client: &str, _: Option<&Connection>, storage: &Storage, data: DataObject)
            -> AppDataResult<Document> {
            self.log(format!("create {client} {} draft={}", storage.name, cx.draft));
            let mut row = data.data.unwrap_or_default();
            let id = match row.shift_remove("_id") {
                Some(Value::String(s)) if !s.is_empty() => s,
                _ => {
                    let mut n = self.next.lock();
                    *n += 1;
                    format!("{:024x}", *n)
                }
            };
            row.insert("_id".into(), Value::String(id.clone()));
            self.rows.lock().entry(key(cx, storage)).or_default().insert(id, row.clone());
            Ok(row)
        }

        async fn update(
            &self,
            cx: &Ctx,
            _: &str,
            _: Option<&Connection>,
            storage: &Storage,
            data: DataObject,
            override_: Option<bool>,
        ) -> AppDataResult<Document> {
            let row = data.data.unwrap_or_default();
            self.updates.lock().push((row.clone(), override_));
            let id = row.get("_id").map(Value::java_string).unwrap_or_default();
            let mut all = self.rows.lock();
            let Some(existing) = all.entry(key(cx, storage)).or_default().get_mut(&id) else {
                if *self.empty_update.lock() {
                    return Err(AppDataError::Empty);
                }
                return Err(AppDataError::object_not_found_to_update(&storage.name, &id));
            };
            if override_ == Some(true) {
                *existing = row.clone();
            } else {
                for (k, v) in row {
                    existing.insert(k, v);
                }
            }
            Ok(existing.clone())
        }

        async fn read(&self, cx: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, id: &str) -> AppDataResult<Document> {
            self.log(format!("read {} {id}", storage.name));
            self.rows
                .lock()
                .get(&key(cx, storage))
                .and_then(|m| m.get(id).cloned())
                .ok_or_else(|| AppDataError::object_not_found(&storage.name, id))
        }

        async fn read_page(&self, cx: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, query: &Query)
            -> AppDataResult<Page<Document>> {
            self.page(&key(cx, storage), query)
        }

        async fn read_page_rows(&self, cx: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, query: &Query)
            -> AppDataResult<Vec<Document>> {
            self.log(format!("rows {}", storage.name));
            Ok(self.list(&key(cx, storage), query))
        }

        async fn aggregate(&self, cx: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, query: &AggregateQuery)
            -> AppDataResult<Page<Document>> {
            let mut d = Document::new();
            d.insert("n".into(), Value::Int(self.count(&key(cx, storage)) as i64));
            Ok(Page::of(vec![d], query.pageable()?, || 1))
        }

        async fn delete(
            &self,
            cx: &Ctx,
            _: &str,
            _: Option<&Connection>,
            storage: &Storage,
            id: &str,
            _: Option<bool>,
        ) -> AppDataResult<bool> {
            self.log(format!("delete {} {id}", storage.name));
            match self.rows.lock().get_mut(&key(cx, storage)).and_then(|m| m.shift_remove(id)) {
                Some(_) => Ok(true),
                None => Err(AppDataError::object_not_found(&storage.name, id)),
            }
        }

        async fn delete_by_filter(
            &self,
            cx: &Ctx,
            _: &str,
            _: Option<&Connection>,
            storage: &Storage,
            query: &Query,
            dev_mode: Option<bool>,
            _: Option<bool>,
        ) -> AppDataResult<i64> {
            let ids: Vec<String> =
                self.list(&key(cx, storage), query).iter().filter_map(|r| r.get("_id").map(Value::java_string)).collect();
            if dev_mode != Some(true) {
                if let Some(m) = self.rows.lock().get_mut(&key(cx, storage)) {
                    for id in &ids {
                        m.shift_remove(id);
                    }
                }
            }
            Ok(ids.len() as i64)
        }

        async fn read_version(&self, _: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, id: &str)
            -> AppDataResult<Document> {
            Err(AppDataError::generic_not_found(&storage.name, id))
        }

        async fn read_page_version(
            &self,
            _: &Ctx,
            _: &str,
            _: Option<&Connection>,
            _: &Storage,
            _: &str,
            query: &Query,
            _: Option<bool>,
        ) -> AppDataResult<Page<Document>> {
            Ok(Page::of(Vec::new(), query.pageable()?, || 0))
        }

        async fn check_if_exists(&self, cx: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, id: &str)
            -> AppDataResult<bool> {
            Ok(self.rows.lock().get(&key(cx, storage)).is_some_and(|m| m.contains_key(id)))
        }

        async fn enforces_relation_constraint(
            &self,
            _: &Ctx,
            _: &str,
            _: Option<&Connection>,
            _: &Storage,
            _: &str,
            _: &StorageRelation,
        ) -> AppDataResult<bool> {
            Ok(*self.enforces.lock())
        }

        async fn count_referencing(
            &self,
            _: &Ctx,
            _: &str,
            _: Option<&Connection>,
            child: &Storage,
            field: &str,
            _: bool,
            id: &str,
        ) -> AppDataResult<i64> {
            Ok(self.referencing(&child.name, field, id).len() as i64)
        }

        async fn ids_referencing(
            &self,
            _: &Ctx,
            _: &str,
            _: Option<&Connection>,
            child: &Storage,
            field: &str,
            _: bool,
            id: &str,
            limit: i64,
        ) -> AppDataResult<Vec<String>> {
            Ok(self.referencing(&child.name, field, id).into_iter().take(limit as usize).collect())
        }

        async fn delete_storage(&self, cx: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage) -> AppDataResult<bool> {
            self.rows.lock().shift_remove(&key(cx, storage));
            Ok(true)
        }

        async fn drop_draft_storage(&self, _: &Ctx, _: &str, _: Option<&Connection>, _: &Storage) -> AppDataResult<bool> {
            Ok(true)
        }

        async fn drop_draft_database(&self, _: Option<&Connection>, _: &str, _: &str) -> AppDataResult<bool> {
            Ok(true)
        }

        async fn copy_live_to_draft(&self, _: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage, replace: Option<bool>)
            -> AppDataResult<i64> {
            let live = self.rows.lock().get(&storage.name).cloned().unwrap_or_default();
            if live.is_empty() {
                return Ok(0);
            }
            let mut all = self.rows.lock();
            let draft = all.entry(format!("{}#draft", storage.name)).or_default();
            if replace == Some(true) {
                draft.clear();
            }
            for (id, row) in &live {
                draft.insert(id.clone(), row.clone());
            }
            Ok(live.len() as i64)
        }

        async fn clear_draft_rows(&self, _: &Ctx, _: &str, _: Option<&Connection>, storage: &Storage) -> AppDataResult<i64> {
            let mut all = self.rows.lock();
            let n = all.get(&format!("{}#draft", storage.name)).map(IndexMap::len).unwrap_or(0);
            all.shift_remove(&format!("{}#draft", storage.name));
            Ok(n as i64)
        }

        async fn copy_live_to_draft_filtered(
            &self,
            cx: &Ctx,
            client: &str,
            conn: Option<&Connection>,
            storage: &Storage,
            _: Option<&DraftCopyFilter>,
            _: &std::collections::HashMap<String, Storage>,
        ) -> AppDataResult<i64> {
            self.copy_live_to_draft(cx, client, conn, storage, Some(true)).await
        }
    }

    #[derive(Default)]
    pub struct RecordingEvents {
        pub raised: Mutex<Vec<(String, Document)>>,
    }

    #[async_trait]
    impl EventSink for RecordingEvents {
        async fn create_event(&self, app: &str, client: &str, name: &str, data: Document) -> Result<bool, CoreError> {
            self.raised.lock().push((format!("{app}/{client}/{name}"), data));
            Ok(true)
        }
    }

    #[derive(Default)]
    pub struct RecordingTriggers {
        pub ran: Mutex<Vec<(String, serde_json::Value)>>,
        pub fail: Mutex<Option<CoreError>>,
    }

    #[async_trait]
    impl TriggerRunner for RecordingTriggers {
        async fn run(&self, ns: &str, name: &str, app: &str, client: &str, args: kirun::Map<serde_json::Value>)
            -> Result<(), CoreError> {
            if let Some(e) = self.fail.lock().clone() {
                return Err(e);
            }
            let args: serde_json::Map<String, serde_json::Value> = args.into_iter().collect();
            self.ran.lock().push((format!("{ns}.{name} {app}/{client}"), serde_json::Value::Object(args)));
            Ok(())
        }
    }

    /// The caller security answers for: `Basic user` (or any bearer) is a signed-in SYSTEM
    /// user with the storage authorities, no `Authorization` the anonymous one; the codes are
    /// the headers'.
    async fn context_authentication(headers: axum::http::HeaderMap) -> axum::response::Response {
        use axum::response::IntoResponse;
        let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        // `wrong:wrong` is a refused sign-in: security answers the anonymous caller.
        let signed_in = !h("authorization").is_empty() && !h("authorization").eq_ignore_ascii_case("basic d3Jvbmc6d3Jvbmc=");
        let body = if signed_in {
            serde_json::json!({"user": {"id": 142, "clientId": 1, "userName": "u",
                                        "stringAuthorities": ["Authorities.Logged_IN", "Authorities.Storage_READ"]},
                               "authenticated": true, "clientCode": "SYSTEM", "clientTypeCode": "SYS",
                               "verifiedAppCode": "appbuilder"})
        } else {
            serde_json::json!({"user": {"id": 0, "clientId": 1, "stringAuthorities": ["Authorities._Anonymous"]},
                               "authenticated": false, "clientCode": "SYSTEM"})
        };
        let _ = (h("clientcode"), h("appcode"));
        axum::Json(body).into_response()
    }

    /// Security's two internal answers the policy layer asks for: `doesClientManageClientCode`
    /// (`managing>client` pairs; `GHOST` answers nothing) and `hasWriteAccess` (apps listed).
    pub async fn security_stub(manages: &'static [(&'static str, &'static str)], writable: &'static [&'static str]) -> String {
        let pairs = move |q: Option<String>| -> std::collections::HashMap<String, String> {
            crate::exec::parse_query(q.as_deref()).into_iter().collect()
        };
        let router = Router::new()
            .route("/api/security/internal/securityContextAuthentication", get(context_authentication))
            .route(
                "/api/security/clients/internal/doesClientManageClientCode",
                get(move |RawQuery(q): RawQuery| async move {
                    let p = pairs(q);
                    let (m, c) = (p.get("managingClientCode").cloned().unwrap_or_default(), p.get("clientCode").cloned().unwrap_or_default());
                    if m == "GHOST" || c == "GHOST" {
                        return String::new();
                    }
                    (m == c || manages.iter().any(|(a, b)| *a == m && *b == c)).to_string()
                }),
            )
            .route(
                "/api/security/applications/internal/hasWriteAccess",
                get(move |RawQuery(q): RawQuery| async move {
                    let p = crate::exec::parse_query(q.as_deref());
                    let app = p.iter().find(|(k, _)| k == "appCode").map(|(_, v)| v.clone()).unwrap_or_default();
                    writable.contains(&app.as_str()).to_string()
                }),
            );
        super::serve(router).await
    }

    /// The policy layer over `catalog` and `engine` (both backends), with security at
    /// `security_base`, events recorded.
    pub fn policy(
        catalog: Arc<MemoryCatalog>,
        engine: Arc<MemoryEngine>,
        security_base: &str,
        events: Arc<RecordingEvents>,
    ) -> AppDataService {
        let security = platform::security::SecurityClient::new(
            platform::upstream::Upstream::fixed(&[security_base]),
            0,
        )
        .expect("security");
        let backends = Backends { mongo: engine.clone(), mysql: engine, mysql_admin: Arc::new(NoMySql) };
        AppDataService::new(catalog, security, backends, vec!["appbuilder".into(), "sitezump".into()], events)
    }

    pub struct NoMySql;

    #[async_trait]
    impl crate::storage::service::MySqlAdmin for NoMySql {
        async fn migration_status(&self, _: &Connection, app: &str, _: &Storage)
            -> AppDataResult<Vec<appdata::mysql::migration::TenantProgress>> {
            Ok(vec![appdata::mysql::migration::TenantProgress {
                database: format!("SYSTEM_{app}"),
                state: Some(appdata::mysql::journal::MigrationState::Failed),
                statement_index: 1,
                total: 2,
                attempt: 3,
            }])
        }
        async fn drift(&self, _: &Connection, _: &str, _: &Storage) -> AppDataResult<Vec<appdata::mysql::drift::Report>> {
            Ok(Vec::new())
        }
        async fn repair_drift(&self, _: &Connection, _: &str, _: &Storage, _: bool)
            -> AppDataResult<Vec<appdata::mysql::drift::DriftRepair>> {
            Ok(Vec::new())
        }
    }
}

/// An execution state over the given storage service and the security stub at
/// `security_base`; definitions, entity-processor and MySQL are unreachable (and lazy).
pub async fn offline_state(appdata: Arc<crate::storage::service::AppDataService>, security_base: &str) -> crate::state::AppState {
    offline_state_with(appdata, security_base, None).await
}

/// [`offline_state`] with the given integrations (documents, publishers, outbound targets).
pub async fn offline_state_with(
    appdata: Arc<crate::storage::service::AppDataService>,
    security_base: &str,
    integrations: Option<Arc<crate::integrations::Integrations>>,
) -> crate::state::AppState {
    use platform::upstream::Upstream;
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).expect("cache");
    let mongo = mongodb::Client::with_uri_str("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=300&connectTimeoutMS=300")
        .await
        .expect("client")
        .database("core");
    let security = platform::security::SecurityClient::new(Upstream::fixed(&[security_base]), 0).expect("security");
    let store = overridable::Store::new(mongo, security.clone(), &cache);
    let definitions = Arc::new(crate::repos::app::Definitions::new(store, security, cache.family(), std::time::Duration::from_secs(5)));
    let pool = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://root@127.0.0.1:1/core").expect("pool");
    let ep = Arc::new(crate::clients::EntityProcessor::new(Upstream::fixed(&["http://127.0.0.1:1"])).expect("ep"));
    let mut deps = offline_deps(security_base, appdata.clone()).await;
    if let Some(i) = integrations {
        deps.integrations = i;
    }
    let builtins = crate::state::Builtins::new(crate::repos::core_functions::CoreFunctions::new(&deps));
    let state = crate::state::AppState::new(crate::state::Inner {
        config: crate::config::CoreConfig::default(),
        auth: crate::auth::AuthClient::new(Upstream::fixed(&[security_base])).expect("auth"),
        definitions,
        remote: crate::repos::remote::RemoteRepositories::new(pool, cache.family(), ep),
        kirun_functions: builtins.kirun_functions,
        kirun_schemas: builtins.kirun_schemas,
        core_functions: builtins.core_functions,
        core_schemas: builtins.core_schemas,
        appdata: appdata.clone(),
        integrations: deps.integrations.clone(),
        event_runs: Arc::new(crate::event_runs::EventRunService::new(
            Arc::new(crate::event_runs::MemoryEventRunDao::default()),
            Arc::new(crate::scheduler::EventDefinitionService::new(deps.defs.definitions().store().clone(), cache.clone())),
            deps.security.clone(),
            true,
        )),
    });
    deps.integrations.attach(&state);
    state
}
