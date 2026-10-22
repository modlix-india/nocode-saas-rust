//! The live write path on the in-memory harness: create, read, update, plan update, delete,
//! the access checks, the list reads and the evictions, ported from the Java
//! `AbstractOverridableAccessCheckTest`, `UpdateAuthorizationIntegrationTest`,
//! `OverrideChainIntegrationTest` and `StorageOverrideChainIntegrationTest`.

mod common;

use axum::http::StatusCode;
use common::*;
use overridable::backend::ExplicitApp;
use overridable::pojo::{convert_json, map_field, str_field};
use overridable::write::kind::Method;
use overridable::write::messages::error_message;
use overridable::write::spring::{Order, Pageable, Params, Sort};
use overridable::write::{Messages, OverridableService};
use overridable::JValue;
use platform::error::AppError;

fn status(e: AppError) -> (StatusCode, String) {
    (e.status(), error_message(&e))
}

// ── Access checks (AbstractOverridableAccessCheckTest) ───────────────────

mod access {
    use super::*;

    fn ca(auth: &[&str]) -> platform::security::ContextAuthentication {
        let mut ca = auth_for(SYSTEM, &auth.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        ca.client_type_code = None;
        ca
    }

    async fn check(e: &Env, method: Method, auth: &[&str], client: &str) -> bool {
        e.pages.access_check(&ca(auth), method, Some("appbuilder"), Some(client), false).await.unwrap()
    }

    fn managed(e: &Env, clients: &[&str]) {
        let set = clients.iter().map(|c| (SYSTEM.to_string(), c.to_string())).collect();
        e.dir.set(|a| {
            a.manages_all = false;
            a.managed = set;
        });
    }

    #[tokio::test]
    async fn a_manager_reads_a_managed_clients_override() {
        let e = env();
        managed(&e, &["FIN"]);
        assert!(check(&e, Method::Read, &["Authorities.Page_READ"], "FIN").await);
    }

    #[tokio::test]
    async fn a_manager_without_write_access_still_cannot_read_it() {
        let e = env();
        managed(&e, &["FIN"]);
        e.dir.set(|a| a.write_access = false);
        assert!(!check(&e, Method::Read, &["Authorities.Page_READ"], "FIN").await);
    }

    #[tokio::test]
    async fn a_client_not_managed_is_still_refused() {
        let e = env();
        managed(&e, &["FIN"]);
        assert!(!check(&e, Method::Read, &["Authorities.Page_READ"], "AKASH").await);
    }

    #[tokio::test]
    async fn the_read_authority_is_still_required() {
        let e = env();
        managed(&e, &["FIN"]);
        assert!(!check(&e, Method::Read, &["Authorities.Page_UPDATE"], "FIN").await);
    }

    #[tokio::test]
    async fn the_chain_still_answers_first() {
        let e = env();
        managed(&e, &[]);
        e.dir.chain(&[SYSTEM, "FIN"]);
        e.dir.set(|a| a.write_access = false);
        assert!(check(&e, Method::Read, &["Authorities.Page_READ"], "FIN").await);
    }

    #[tokio::test]
    async fn only_a_read_falls_back() {
        let e = env();
        managed(&e, &["FIN"]);
        assert!(!check(&e, Method::Create, &["Authorities.Page_CREATE"], "FIN").await);
    }

    async fn write_check(e: &Env, method: Method, auth: &[&str], client: &str) -> bool {
        e.pages.access_check(&ca(auth), method, Some("appbuilder"), Some(client), true).await.unwrap()
    }

    /// Java 3cf6ebc54 (tested by 7a1766ef6): a write needs write access to the app for the
    /// caller and for the client whose object it is.
    #[tokio::test]
    async fn a_write_for_another_client_needs_that_clients_write_access_too() {
        let e = env();
        managed(&e, &["FIN"]);
        let all = ["Authorities.Page_CREATE", "Authorities.Page_UPDATE", "Authorities.Page_DELETE", "Authorities.Page_READ"];
        for m in [Method::Create, Method::Update, Method::Delete] {
            assert!(write_check(&e, m, &all, "FIN").await, "{m:?} with write access on both sides");
        }
        e.dir.set(|a| {
            a.write_by.insert(("appbuilder".into(), "FIN".into()), false);
        });
        for m in [Method::Create, Method::Update, Method::Delete] {
            assert!(!write_check(&e, m, &all, "FIN").await, "{m:?} for a read-only client");
        }
        assert!(write_check(&e, Method::Update, &all, SYSTEM).await, "the caller's own object asks only the caller");
        // A refused read retried as a write is still a read: the target's access is not asked.
        e.dir.set(|a| a.read_access = false);
        assert!(check(&e, Method::Read, &all, "FIN").await);
        // And the caller's own write access is still needed first.
        e.dir.set(|a| {
            a.write_by.clear();
            a.write_by.insert(("appbuilder".into(), SYSTEM.into()), false);
        });
        assert!(!write_check(&e, Method::Create, &all, "FIN").await);
    }

    #[tokio::test]
    async fn an_explicit_app_keeps_its_rule() {
        let e = env();
        managed(&e, &["FIN"]);
        e.dir.set(|a| a.app = Some(ExplicitApp { app_access_type: Some("EXPLICIT".into()), client_code: Some(SYSTEM.into()), explicit_owner_client_code: None }));
        assert!(!check(&e, Method::Read, &["Authorities.Page_READ"], "FIN").await);
        e.dir.set(|a| a.app.as_mut().unwrap().explicit_owner_client_code = Some("FIN".into()));
        assert!(check(&e, Method::Read, &["Authorities.Page_READ"], "FIN").await, "the explicit owner is managed");
    }

    #[tokio::test]
    async fn unknown_apps_blank_codes_and_read_access() {
        let e = env();
        e.dir.set(|a| {
            a.apps.insert("appbuilder".into(), None);
        });
        assert!(!check(&e, Method::Read, &["Authorities.Page_READ"], SYSTEM).await, "an unknown app is no app");
        let e = env();
        let c = ca(&["Authorities.Page_READ"]);
        assert!(!e.pages.access_check(&c, Method::Read, Some(" "), Some(SYSTEM), false).await.unwrap());
        assert!(!e.pages.access_check(&c, Method::Read, Some("a"), None, false).await.unwrap());
        assert!(e.pages.access_check(&c, Method::Read, Some("a"), Some(SYSTEM), false).await.unwrap());
        e.dir.set(|a| a.read_access = false);
        assert!(e.pages.access_check(&c, Method::Read, Some("a"), Some(SYSTEM), false).await.unwrap(), "falls back to write");
        e.dir.set(|a| a.write_access = false);
        assert!(!e.pages.access_check(&c, Method::Read, Some("a"), Some(SYSTEM), false).await.unwrap());
        e.dir.set(|a| a.failing = true);
        assert_eq!(e.pages.access_check(&c, Method::Read, Some("a"), Some(SYSTEM), false).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

// ── Create ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_stamps_saves_snapshots_and_evicts() {
    let e = env();
    for c in ["PageCache_testapp_home", "PageCache_testapp_home_DRAFT", "PageCache_testapp_Page_READ_PAGE"] {
        e.warm(c, SYSTEM).await;
    }
    let body = convert_json(&PAGE, &obj(r#"{"name":"home","appCode":"testapp","rootComponent":"root","properties":{"title":"t"},"published":false,"message":"m1"}"#));
    let created = e.pages.create(&system(), body).await.unwrap();
    assert_eq!(str_field(&created, "clientCode"), Some(SYSTEM), "the caller's client when none is given");
    assert_eq!(str_field(&created, "createdBy"), Some("1"));
    assert!(created["createdAt"].as_i64().is_some() && created["createdAt"] == created["updatedAt"]);
    assert_eq!(created["published"], JValue::Null, "published is never read from a body");
    for c in ["PageCache_testapp_home", "PageCache_testapp_home_DRAFT", "PageCache_testapp_Page_READ_PAGE"] {
        assert!(!e.is_warm(c, SYSTEM).await, "{c} evicted");
    }
    assert_eq!(e.calls(), ["evict_recursively testapp SYSTEM home", "after_create home"]);
    let versions = e.raw("version");
    assert_eq!(versions.len(), 1);
    let v = &versions[0];
    assert_eq!(v.get_str("objectType").unwrap(), "PAGE");
    assert_eq!(v.get_str("message").unwrap(), "m1");
    assert_eq!(v.get_str("createdBy").unwrap(), "1");
    assert_eq!(v.get_i32("versionNumber").unwrap(), 1);
    let object = v.get_document("object").unwrap();
    assert_eq!(object.get_str("id").unwrap(), str_field(&created, "id").unwrap());
    assert!(matches!(object.get("createdAt"), Some(mongodb::bson::Bson::Int64(_))), "dates as longs, as Jackson maps them");
    let stored = e.raw("page");
    assert!(matches!(stored[0].get("_id"), Some(mongodb::bson::Bson::ObjectId(_))));
    assert!(matches!(stored[0].get("createdAt"), Some(mongodb::bson::Bson::DateTime(_))));
}

#[tokio::test]
async fn create_refuses_a_name_taken_and_a_caller_without_the_authority() {
    let e = env();
    e.page(&page_json("home", SYSTEM, "t", "r", ""));
    let err = e.pages.create(&system(), obj(r#"{"name":"home","appCode":"testapp"}"#)).await.unwrap_err();
    assert_eq!(status(err), (StatusCode::CONFLICT, "Page home already exists".into()));
    let nameless = e.pages.create(&system(), obj(r#"{"appCode":"testapp","clientCode":"X"}"#)).await.unwrap();
    assert_eq!(nameless["name"], JValue::Null, "Java creates a nameless object for a client it manages");
    let reader = auth_for(SYSTEM, &["Authorities.Page_READ".into()]);
    let err = e.pages.create(&reader, obj(r#"{"name":"other","appCode":"testapp"}"#)).await.unwrap_err();
    assert_eq!(status(err), (StatusCode::FORBIDDEN, "Cannot create Page for the selected client".into()));
}

#[tokio::test]
async fn create_never_takes_an_id_from_the_body() {
    let e = env();
    let victim = e.page(&page_json("victim", "LZCLB", "victim live", "r", ""));
    let body = obj(&format!(r#"{{"id":"{victim}","name":"mine","appCode":"testapp","properties":{{"title":"attacker"}}}}"#));
    let created = e.pages.create(&system(), body).await.unwrap();
    assert_ne!(str_field(&created, "id"), Some(victim.as_str()));
    assert_eq!(prop_str(&e.raw_page(&victim), "title"), Some("victim live"), "the document the id named is untouched");
    assert_eq!(e.count("page"), 2);
}

#[tokio::test]
async fn a_derived_create_stores_only_its_difference() {
    let e = env();
    e.page(&page_json("p", SYSTEM, "base", "rootComp", r#","fromBase":"b""#));
    e.dir.chain(&[SYSTEM, "LZCLA"]);
    let mid = auth_for("LZCLA", &all_for("Page"));
    let body = obj(r#"{"name":"p","appCode":"testapp","baseClientCode":"SYSTEM","rootComponent":"rootComp","properties":{"title":"base","fromBase":"b","fromChild":"c"}}"#);
    let created = e.pages.create(&mid, body).await.unwrap();
    assert_eq!(prop_str(&created, "fromBase"), Some("b"), "the read merges the chain");
    let stored = e.raw_page(str_field(&created, "id").unwrap());
    let props = map_field(&stored, "properties").unwrap();
    assert_eq!(props.keys().collect::<Vec<_>>(), ["fromChild"], "only the difference is stored");
    assert_eq!(stored["rootComponent"], JValue::Null);
    let v = &e.raw("version")[0];
    assert!(!v.get_document("object").unwrap().get_document("properties").unwrap().contains_key("fromBase"), "Java snapshots the delta of a derived object");
}

// ── Read ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reads_refuse_with_404() {
    let e = env();
    let err = e.pages.read(&system(), "64b7f1c2e4b0a1c2d3e4f5a6").await.unwrap_err();
    assert_eq!(status(err), (StatusCode::NOT_FOUND, "Page with id 64b7f1c2e4b0a1c2d3e4f5a6 not found".into()));
    let id = e.page(&page_json("p", "LZCLB", "t", "r", ""));
    e.dir.isolate_tenants();
    let outsider = auth_for("LZCLA", &all_for("Page"));
    assert_eq!(e.pages.read(&outsider, &id).await.unwrap_err().status(), StatusCode::NOT_FOUND);
    assert_eq!(e.pages.read(&anonymous(), &id).await.unwrap_err().status(), StatusCode::NOT_FOUND);
}

// ── Update (UpdateAuthorizationIntegrationTest) ──────────────────────────

#[tokio::test]
async fn cross_tenant_update_is_refused_and_writes_nothing() {
    let e = env();
    let victim = e.page(&page_json("testPage", "LZCLB", "victim live", "r", ""));
    e.dir.chain(&["LZCLB", "LZCLA"]);
    e.dir.isolate_tenants();
    let attacker = auth_for("LZCLA", &all_for("Page"));
    let body = obj(&format!(r#"{{"id":"{victim}","name":"testPage","appCode":"testapp","clientCode":"LZCLA","version":1,"properties":{{"title":"hijacked"}}}}"#));
    let err = e.pages.update(&attacker, body).await.unwrap_err();
    assert_eq!(status(err), (StatusCode::FORBIDDEN, "Permission/Role Page is required to use this operation ".into()));
    let stored = e.raw_page(&victim);
    assert_eq!(prop_str(&stored, "title"), Some("victim live"));
    assert_eq!(stored["version"], JValue::Int(1));
}

#[tokio::test]
async fn identity_comes_from_the_stored_document() {
    let e = env();
    let id = e.page(&page_json("testPage", SYSTEM, "live", "r", ""));
    let body = obj(&format!(r#"{{"id":"{id}","name":"someOtherName","appCode":"elsewhere","clientCode":"LZCLA","baseClientCode":"LZCLA","version":1,"properties":{{"title":"edited"}}}}"#));
    let saved = e.pages.update(&system(), body).await.unwrap();
    assert_eq!(prop_str(&saved, "title"), Some("edited"));
    let stored = e.raw_page(&id);
    assert_eq!((str_field(&stored, "name"), str_field(&stored, "clientCode"), str_field(&stored, "appCode")), (Some("testPage"), Some(SYSTEM), Some(APP)));
    assert_eq!(stored["baseClientCode"], JValue::Null);
    assert_eq!(stored["version"], JValue::Int(2));
    assert_eq!(str_field(&stored, "updatedBy"), Some("1"));
}

#[tokio::test]
async fn an_unknown_or_missing_id_is_refused() {
    let e = env();
    for body in [r#"{"id":"64b7f1c2e4b0a1c2d3e4f5a6","version":1}"#, r#"{"version":1}"#] {
        assert_eq!(e.pages.update(&system(), obj(body)).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn a_stale_version_is_refused_with_412() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    let body = obj(&format!(r#"{{"id":"{id}","version":7,"properties":{{"title":"x"}}}}"#));
    let err = e.pages.update(&system(), body).await.unwrap_err();
    assert_eq!(status(err), (StatusCode::PRECONDITION_FAILED, "Please reload to get the new version before making changes".into()));
    let e = env_with(Messages::core());
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    let body = obj(&format!(r#"{{"id":"{id}","version":7}}"#));
    assert!(error_message(&e.pages.update(&system(), body).await.unwrap_err()).ends_with("changes."), "core's bundle");
}

#[tokio::test]
async fn update_keeps_dates_snapshots_and_evicts_both_surfaces() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    let created_at = mongodb::bson::DateTime::from_millis(1_600_000_000_456);
    let mut raw = e.raw("page").remove(0);
    raw.insert("createdAt", created_at);
    e.mem.put_raw("page", raw);
    for c in ["PageCache_testapp_p", "PageCache_testapp_p_DRAFT", "PageCache_testapp_Page_READ_PAGE", "pageOUICache-testapp"] {
        e.warm(c, "SYSTEM").await;
    }
    let mut page = e.pages.read(&system(), &id).await.unwrap();
    page.get_mut("properties").unwrap().as_object_mut().unwrap().insert("title".into(), JValue::Str("t2".into()));
    page.insert("message".into(), JValue::Str("edit".into()));
    let saved = e.pages.update(&system(), page).await.unwrap();
    assert_eq!(saved["version"], JValue::Int(2));
    for c in ["PageCache_testapp_p", "PageCache_testapp_p_DRAFT", "PageCache_testapp_Page_READ_PAGE", "pageOUICache-testapp"] {
        assert!(!e.is_warm(c, SYSTEM).await, "{c} evicted");
    }
    let stored = e.raw("page").remove(0);
    assert_eq!(stored.get("createdAt"), Some(&mongodb::bson::Bson::DateTime(created_at)), "milliseconds survive a save");
    let v = &e.raw("version")[0];
    assert_eq!((v.get_i32("versionNumber").unwrap(), v.get_str("message").unwrap()), (2, "edit"));
    assert!(e.calls().contains(&"after_update p".to_string()));
}

#[tokio::test]
async fn published_is_not_settable_from_the_body() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    let mut page = e.pages.read(&system(), &id).await.unwrap();
    page.insert("published".into(), JValue::Bool(false));
    e.pages.update(&system(), page).await.unwrap();
    assert_eq!(e.raw_page(&id)["published"], JValue::Null);
    assert!(e.pages.read_resolved(&system(), "p", APP, SYSTEM, false).await.unwrap().is_some());
}

#[tokio::test]
async fn an_ordinary_save_does_not_publish() {
    let e = env();
    let id = e.page(&format!(r#"{{"name":"p","appCode":"{APP}","clientCode":"SYSTEM","version":1,"published":false}}"#));
    let page = e.pages.read(&system(), &id).await.unwrap();
    e.pages.update(&system(), page).await.unwrap();
    assert_eq!(e.raw_page(&id)["published"], JValue::Bool(false));
}

// ── The override chain (OverrideChainIntegrationTest) ────────────────────

fn chain_env(levels: usize) -> (Env, Vec<String>) {
    let e = env();
    let clients = [SYSTEM, "LZCLA", "LZACP1", "LZACP1X"];
    let props = [
        r#"{"fromRoot":"r","shared":"root","sharedRootMid":"root","sharedAll":"root"}"#,
        r#"{"fromMid":"m","shared":"mid","sharedRootMid":"mid","sharedAll":"mid"}"#,
        r#"{"fromLeaf":"l","sharedAll":"leaf"}"#,
        r#"{"fromLeaf2":"l2","sharedAll":"leaf2"}"#,
    ];
    let mut ids = Vec::new();
    for i in 0..levels {
        let base = if i == 0 { "null".to_string() } else { format!("\"{}\"", clients[i - 1]) };
        let root = if i == 0 { r#""rootComponent":"rootComp","# } else { "" };
        ids.push(e.page(&format!(
            r#"{{"name":"chain","appCode":"{APP}","clientCode":"{}","baseClientCode":{base},"version":1,{root}"properties":{}}}"#,
            clients[i], props[i]
        )));
    }
    e.dir.chain(&clients[..levels]);
    (e, ids)
}

#[tokio::test]
async fn reads_merge_every_level() {
    let (e, ids) = chain_env(1);
    let p = e.pages.read(&system(), &ids[0]).await.unwrap();
    assert_eq!((prop_str(&p, "fromRoot"), prop_str(&p, "shared"), str_field(&p, "rootComponent")), (Some("r"), Some("root"), Some("rootComp")));

    let (e, ids) = chain_env(2);
    let p = e.pages.read(&auth_for("LZCLA", &all_for("Page")), &ids[1]).await.unwrap();
    assert_eq!((prop_str(&p, "fromRoot"), prop_str(&p, "fromMid"), prop_str(&p, "shared")), (Some("r"), Some("m"), Some("mid")));

    let (e, ids) = chain_env(3);
    let p = e.pages.read(&auth_for("LZACP1", &all_for("Page")), &ids[2]).await.unwrap();
    assert_eq!(prop_str(&p, "sharedRootMid"), Some("mid"));
    assert_eq!(prop_str(&p, "sharedAll"), Some("leaf"));
    assert_eq!(str_field(&p, "rootComponent"), Some("rootComp"));
    let stored = e.raw_page(&ids[2]);
    assert_eq!(map_field(&stored, "properties").unwrap().len(), 2, "a read does not collapse the stored delta");

    let (e, ids) = chain_env(4);
    let p = e.pages.read(&auth_for("LZACP1X", &all_for("Page")), &ids[3]).await.unwrap();
    assert_eq!((prop_str(&p, "fromLeaf"), prop_str(&p, "fromLeaf2"), prop_str(&p, "sharedAll")), (Some("l"), Some("l2"), Some("leaf2")));
}

#[tokio::test]
async fn updates_keep_the_delta_and_round_trip() {
    let (e, ids) = chain_env(3);
    let leaf = auth_for("LZACP1", &all_for("Page"));
    let mut p = e.pages.read(&leaf, &ids[2]).await.unwrap();
    p.get_mut("properties").unwrap().as_object_mut().unwrap().insert("fromLeaf".into(), JValue::Str("changed".into()));
    e.pages.update(&leaf, p).await.unwrap();
    let stored = e.raw_page(&ids[2]);
    let props = map_field(&stored, "properties").unwrap();
    assert_eq!(props.get("fromLeaf"), Some(&JValue::Str("changed".into())));
    assert!(!props.contains_key("fromRoot") && !props.contains_key("fromMid"), "inherited keys stay inherited");
    let again = e.pages.read(&leaf, &ids[2]).await.unwrap();
    assert_eq!((prop_str(&again, "fromLeaf"), prop_str(&again, "fromRoot"), prop_str(&again, "fromMid")), (Some("changed"), Some("r"), Some("m")));
}

// ── StorageOverrideChainIntegrationTest (the override layer) ─────────────

#[tokio::test]
async fn derived_storages_save_and_inherit() {
    let e = env();
    let storages = e.storages();
    e.insert_raw(&STORAGE, "storage", r#"{"name":"testStorage","appCode":"testapp","clientCode":"SYSTEM","version":1,"uniqueName":"testapp_system_teststorage","schema":{"title":"t","fromRoot":"r","shared":"root"},"indexes":{"byTitle":{"field":"title"}}}"#);
    let mid = e.insert_raw(&STORAGE, "storage", r#"{"name":"testStorage","appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1,"uniqueName":"testapp_lzcla_teststorage","schema":{"fromMid":"m","shared":"mid"}}"#);
    e.dir.chain(&[SYSTEM, "LZCLA"]);
    let ca = auth_for("LZCLA", &all_for("Storage"));
    let s = storages.read(&ca, &mid).await.unwrap();
    let schema = map_field(&s, "schema").unwrap();
    assert_eq!((schema.get("fromRoot"), schema.get("fromMid"), schema.get("shared")), (Some(&JValue::Str("r".into())), Some(&JValue::Str("m".into())), Some(&JValue::Str("mid".into()))));
    assert_eq!(str_field(&s, "uniqueName"), Some("testapp_lzcla_teststorage"), "uniqueName is not inherited");
    let mut s2 = s.clone();
    s2.get_mut("indexes").unwrap().as_object_mut().unwrap().insert("byTitleTwo".into(), crate::JValue::Object(obj(r#"{"field":"title"}"#)));
    let saved = storages.update(&ca, s2).await.unwrap();
    let idx = map_field(&saved, "indexes").unwrap();
    assert!(idx.contains_key("byTitleTwo") && idx.contains_key("byTitle"));
    let stored = e.raw("storage").into_iter().find(|d| d.get_str("clientCode") == Ok("LZCLA")).unwrap();
    assert_eq!(stored.get_document("indexes").unwrap().keys().collect::<Vec<_>>(), ["byTitleTwo"]);
    assert!(stored.get_document("schema").unwrap().keys().all(|k| k == "fromMid" || k == "shared"));
}

// ── Plan update ──────────────────────────────────────────────────────────

#[tokio::test]
async fn the_plan_has_its_own_door() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    e.warm("PageCache_testapp_p", SYSTEM).await;
    let saved = e.pages.update_blueprint(&system(), &id, Some(obj(r#"{"plan":{"sections":{"a":{"order":1}}}}"#))).await.unwrap();
    assert_eq!(saved["version"], JValue::Int(2));
    assert!(!e.is_warm("PageCache_testapp_p", SYSTEM).await);
    let stored = e.raw_page(&id);
    assert!(map_field(&stored, "blueprint").unwrap().contains_key("plan"));
    assert_eq!(prop_str(&stored, "title"), Some("t"), "content untouched");
    assert_eq!(stored["updatedBy"], JValue::Null, "only updatedAt moves");
    let cleared = e.pages.update_blueprint(&system(), &id, None).await.unwrap();
    assert_eq!(cleared["blueprint"], JValue::Null);
    assert_eq!(e.pages.update_blueprint(&system(), " ", None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(e.pages.update_blueprint(&system(), "64b7f1c2e4b0a1c2d3e4f5a6", None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    let reader = auth_for(SYSTEM, &["Authorities.Page_READ".into()]);
    assert_eq!(e.pages.update_blueprint(&reader, &id, None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
}

// ── Delete ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_evicts_the_owners_keys_and_the_list() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    for (c, k) in [("PageCache_testapp_p", SYSTEM), ("PageCache_testapp_p", "OTHER"), ("PageCache_testapp_p_DRAFT", SYSTEM), ("PageCache_testapp_Page_READ_PAGE", "x")] {
        e.warm(c, k).await;
    }
    assert!(e.pages.delete(&system(), &id).await.unwrap());
    assert_eq!(e.count("page"), 0);
    assert!(!e.is_warm("PageCache_testapp_p", SYSTEM).await);
    assert!(e.is_warm("PageCache_testapp_p", "OTHER").await, "Java evicts the deleting client's key only");
    assert!(!e.is_warm("PageCache_testapp_p_DRAFT", SYSTEM).await);
    assert!(!e.is_warm("PageCache_testapp_Page_READ_PAGE", "x").await);
    assert!(e.calls().contains(&"after_delete p".to_string()));
}

#[tokio::test]
async fn delete_refusals() {
    let e = env();
    let storages = e.storages();
    let base = e.insert_raw(&STORAGE, "storage", r#"{"name":"s","appCode":"testapp","clientCode":"SYSTEM","version":1}"#);
    e.insert_raw(&STORAGE, "storage", r#"{"name":"s","appCode":"testapp","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1}"#);
    let ca = auth_for(SYSTEM, &all_for("Storage"));
    let err = storages.delete(&ca, &base).await.unwrap_err();
    assert_eq!(status(err), (StatusCode::FORBIDDEN, format!("Unable to delete Storage with id {base} ")));
    let reader = auth_for(SYSTEM, &["Authorities.Storage_READ".into()]);
    assert_eq!(storages.delete(&reader, &base).await.unwrap_err().status(), StatusCode::NOT_FOUND);
    let err = storages.delete(&ca, "64b7f1c2e4b0a1c2d3e4f5a6").await.unwrap_err();
    assert_eq!(status(err), (StatusCode::NOT_FOUND, "Storage with id 64b7f1c2e4b0a1c2d3e4f5a6 not found".into()));
    let page = e.page(&page_json("p", "LZCLB", "t", "r", ""));
    e.dir.isolate_tenants();
    assert_eq!(e.pages.delete(&auth_for("LZCLA", &all_for("Page")), &page).await.unwrap_err().status(), StatusCode::NOT_FOUND, "the page reads first");
}

// ── Whole apps ───────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_everything_is_scoped_and_evicts() {
    let e = env();
    e.page(&page_json("a", SYSTEM, "t", "r", ""));
    e.page(&page_json("b", SYSTEM, "t", "r", ""));
    e.page(&format!(r#"{{"name":"c","appCode":"otherapp","clientCode":"SYSTEM","version":1}}"#));
    e.page(&page_json("d", "LZCLA", "t", "r", ""));
    e.mem.put_raw("version", mongodb::bson::doc! {"objectAppCode": APP, "clientCode": SYSTEM, "objectType": "PAGE"});
    e.mem.put_raw("version", mongodb::bson::doc! {"objectAppCode": APP, "clientCode": SYSTEM, "objectType": "STYLE"});
    e.mem.put_raw("draft", mongodb::bson::doc! {"objectAppCode": APP, "clientCode": SYSTEM, "objectType": "PAGE", "objectName": "a"});
    for c in ["PageCache_testapp_a", "PageCache_testapp_b_DRAFT", "PageCache_testapp_Page_READ_PAGE"] {
        e.warm(c, SYSTEM).await;
    }
    assert_eq!(e.pages.delete_everything(&system(), APP, SYSTEM).await.unwrap(), Some(true));
    let names: Vec<String> = e.raw("page").iter().map(|d| d.get_str("name").unwrap().to_string()).collect();
    assert_eq!(names, ["c", "d"]);
    assert_eq!(e.count("version"), 1, "other types' history stays");
    assert_eq!(e.count("draft"), 0);
    for c in ["PageCache_testapp_a", "PageCache_testapp_b_DRAFT", "PageCache_testapp_Page_READ_PAGE"] {
        assert!(!e.is_warm(c, SYSTEM).await, "{c} evicted");
    }
    assert!(e.calls().contains(&"delete_everything testapp SYSTEM".to_string()));
    e.dir.set(|a| a.write_access = false);
    assert_eq!(e.pages.delete_everything(&system(), APP, SYSTEM).await.unwrap(), None);
}

#[tokio::test]
async fn base_app_codes_are_repointed() {
    let e = env();
    e.mem.put_raw("page", mongodb::bson::doc! {"name": "a", "appCode": APP, "clientCode": SYSTEM, "baseAppCode": "old"});
    e.mem.put_raw("page", mongodb::bson::doc! {"name": "b", "appCode": APP, "clientCode": SYSTEM});
    assert!(e.pages.updated_base_app_code(&system(), APP, "newbase", SYSTEM).await.unwrap());
    let docs = e.raw("page");
    assert_eq!(docs[0].get_str("baseAppCode").unwrap(), "newbase");
    assert!(!docs[1].contains_key("baseAppCode"));
    let reader = auth_for(SYSTEM, &["Authorities.Page_READ".into()]);
    assert!(!e.pages.updated_base_app_code(&reader, APP, "x", SYSTEM).await.unwrap());
}

#[tokio::test]
async fn create_for_client_makes_a_live_derived_copy() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "base", "rootComp", r#","fromBase":"b""#));
    assert!(e.pages.create_for_client(&system(), "64b7f1c2e4b0a1c2d3e4f5a6", "LZCLA").await.unwrap().is_none());
    let copy = e.pages.create_for_client(&system(), &id, "LZCLA").await.unwrap().unwrap();
    assert_eq!((str_field(&copy, "clientCode"), str_field(&copy, "baseClientCode")), (Some("LZCLA"), Some(SYSTEM)));
    assert_eq!(copy["published"], JValue::Null);
    assert_eq!(copy["version"], JValue::Int(1));
    let stored = e.raw_page(str_field(&copy, "id").unwrap());
    assert!(map_field(&stored, "properties").unwrap().is_empty(), "a fresh copy differs in nothing");
}

// ── Lists ────────────────────────────────────────────────────────────────

fn list_params(extra: &[(&str, &str)]) -> Params {
    let mut p = Params::of(&[("appCode", APP)]);
    for (k, v) in extra {
        p.add(k, v);
    }
    p
}

#[tokio::test]
async fn the_list_is_one_row_per_name_across_the_chain() {
    let e = env();
    e.page(&page_json("home", SYSTEM, "t", "r", ""));
    e.page(&page_json("about", SYSTEM, "t", "r", ""));
    let mid_home = e.page(&format!(r#"{{"name":"home","appCode":"{APP}","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1}}"#));
    e.page(&page_json("other", "LZOUT", "t", "r", ""));
    e.page(&format!(r#"{{"name":"locked","appCode":"{APP}","clientCode":"SYSTEM","version":1,"notOverridable":true}}"#));
    e.dir.chain(&[SYSTEM, "LZCLA"]);
    let mid = auth_for("LZCLA", &all_for("Page"));
    let pageable = Pageable::of(0, 20, Sort::by(vec![Order::asc("name")]));
    let page = e.pages.read_page_filter_lro(&mid, false, false, &pageable, &list_params(&[])).await.unwrap();
    let rows: Vec<(String, String)> = page
        .content
        .iter()
        .map(|r| (str_field(r, "name").unwrap().to_string(), str_field(r, "clientCode").unwrap().to_string()))
        .collect();
    assert_eq!(rows, [("about".into(), "SYSTEM".into()), ("home".into(), "LZCLA".into())]);
    assert_eq!(page.total, 2);
    assert_eq!(str_field(&page.content[1], "id"), Some(mid_home.as_str()));
    assert!(page.content[0].get("rootComponent").is_none(), "headers only");
    let json = page.to_json(&pageable);
    assert_eq!(json.as_object().unwrap()["totalElements"], JValue::Int(2));

    let second = e.pages.read_page_filter_lro(&mid, false, false, &Pageable::of(1, 1, Sort::by(vec![Order::asc("name")])), &list_params(&[])).await.unwrap();
    assert_eq!((second.total, second.content.len()), (2, 1));
    let beyond = e.pages.read_page_filter_lro(&mid, false, false, &Pageable::of(5, 1, Sort::unsorted()), &list_params(&[])).await.unwrap();
    assert!(beyond.content.is_empty());

    let own = e.pages.read_page_filter_lro(&mid, false, true, &pageable, &list_params(&[("clientOnly", "true")])).await.unwrap();
    assert_eq!(own.content.len(), 1, "clientOnly keeps the caller's own rows (Java filtered everything out)");
}

#[tokio::test]
async fn filters_eager_data_and_managed_clients() {
    let e = env();
    e.page(&page_json("home", SYSTEM, "t", "r", ""));
    e.page(&page_json("homework", SYSTEM, "t", "r", ""));
    e.page(&page_json("about", SYSTEM, "t", "r", ""));
    let sys = system();
    let p = Pageable::of(0, 20, Sort::by(vec![Order::asc("name")]));
    let one = e.pages.read_page_filter_lro(&sys, true, false, &p, &list_params(&[("name", "home")])).await.unwrap();
    assert_eq!(one.content.len(), 2, "a single value is a regular expression, as Java's");
    assert!(one.content[0]["data"].as_object().unwrap().contains_key("rootComponent"), "eager rows carry the object");
    let two = e.pages.read_page_filter_lro(&sys, false, false, &p, &list_params(&[("name", "home"), ("name", "about")])).await.unwrap();
    assert_eq!(two.content.len(), 2, "several values are an IN");
    e.page(&page_json("theirs", "LZCLB", "t", "r", ""));
    e.dir.set(|a| {
        a.chains.insert("LZCLB".into(), vec!["LZCLB".into()]);
    });
    let mgr = auth_for("LZMGR", &all_for("Page"));
    let theirs = e.pages.read_page_filter_lro(&mgr, false, false, &p, &list_params(&[("clientCode", "LZCLB")])).await.unwrap();
    assert_eq!(theirs.content.len(), 1);
    let idx = e.pages.read_index_lro(&sys, APP, None).await.unwrap();
    assert_eq!(idx.total, 3);
    let idx = e.pages.read_index_lro(&mgr, APP, Some("LZCLB")).await.unwrap();
    assert_eq!(idx.total, 1);
}

#[tokio::test]
async fn list_refusals() {
    let e = env();
    let p = Pageable::of(0, 20, Sort::unsorted());
    let err = e.pages.read_page_filter_lro(&anonymous(), false, false, &p, &list_params(&[])).await.unwrap_err();
    assert_eq!(status(err), (StatusCode::FORBIDDEN, "Forbidden access to the application with code testapp".into()));
    e.dir.isolate_tenants();
    let outsider = auth_for("LZCLA", &all_for("Page"));
    assert_eq!(e.pages.read_page_filter_lro(&outsider, false, false, &p, &list_params(&[("clientCode", "LZCLB")])).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    e.dir.set(|a| a.read_access = false);
    assert_eq!(e.pages.read_page_filter_lro(&system(), false, false, &p, &list_params(&[])).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    e.dir.set(|a| {
        a.read_access = true;
        a.managers.insert("LZMGR".into());
    });
    let mut sys_named = system();
    sys_named.client_type_code = Some("BUS".into());
    sys_named.client_code = Some("LZMGR".into());
    e.dir.set(|a| {
        a.managers.clear();
        a.managed.insert(("LZMGR".into(), "LZCLB".into()));
    });
    let r = e.pages.read_page_filter_lro(&sys_named, false, false, &p, &list_params(&[("clientCode", "LZCLB")])).await.unwrap();
    assert!(r.content.is_empty());
}

#[tokio::test]
async fn the_unfiltered_list_is_cached_until_a_write() {
    let e = env();
    e.page(&page_json("a", SYSTEM, "t", "r", ""));
    let p = Pageable::of(0, 20, Sort::unsorted());
    let sys = system();
    assert_eq!(e.pages.read_page_filter_lro(&sys, false, false, &p, &list_params(&[])).await.unwrap().total, 1);
    e.page(&page_json("b", SYSTEM, "t", "r", ""));
    assert_eq!(e.pages.read_page_filter_lro(&sys, false, false, &p, &list_params(&[])).await.unwrap().total, 1, "served from PageCache_testapp_Page_READ_PAGE");
    assert_eq!(e.pages.read_page_filter_lro(&sys, false, false, &p, &list_params(&[("name", "b")])).await.unwrap().total, 1, "a filtered list is not cached");
    let err = e.pages.read_page_filter_lro(&anonymous(), false, false, &p, &list_params(&[])).await.unwrap_err();
    assert_eq!(err.status(), StatusCode::FORBIDDEN, "an anonymous caller is never answered from the cache");
    e.pages.create(&sys, obj(r#"{"name":"c","appCode":"testapp"}"#)).await.unwrap();
    assert_eq!(e.pages.read_page_filter_lro(&sys, false, false, &p, &list_params(&[])).await.unwrap().total, 3);
}

#[tokio::test]
async fn transport_reads() {
    let e = env();
    e.page(&page_json("home", SYSTEM, "t", "r", ""));
    e.page(&page_json("about", SYSTEM, "t", "r", ""));
    e.page(&format!(r#"{{"name":"x","appCode":"{APP}","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":3}}"#));
    let sys = system();
    let all = e.pages.read_for_transport(&sys, APP, SYSTEM, None).await.unwrap();
    assert_eq!(all.len(), 2);
    let named = e.pages.read_for_transport(&sys, APP, SYSTEM, Some(&["home".to_string()])).await.unwrap();
    assert_eq!(named.len(), 1);
    assert_eq!(e.pages.read_for_transport(&sys, " ", SYSTEM, None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(e.pages.read_for_transport(&anonymous(), APP, SYSTEM, None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    let (v, id) = e.pages.read_to_transport(&sys, Some("x"), APP, "LZCLA").await.unwrap().unwrap();
    assert_eq!(v, 3);
    assert!(!id.is_empty());
    assert!(e.pages.read_to_transport(&sys, Some("nope"), APP, SYSTEM).await.unwrap().is_none());
    // A nameless row is found as `name: null`, so an import updates it instead of 409ing.
    assert!(e.pages.read_to_transport(&sys, None, APP, SYSTEM).await.unwrap().is_none());
    e.page(&format!(r#"{{"name":null,"appCode":"{APP}","clientCode":"SYSTEM","version":5}}"#));
    assert_eq!(e.pages.read_to_transport(&sys, None, APP, SYSTEM).await.unwrap().unwrap().0, 5);
    let reader = auth_for(SYSTEM, &["Authorities.Page_READ".into()]);
    assert!(e.pages.read_to_transport(&reader, Some("x"), APP, "LZCLA").await.unwrap().is_none());
    let bus = auth_for("LZCLA", &all_for("Page"));
    e.dir.chain(&[SYSTEM, "LZCLA"]);
    assert_eq!(e.pages.read_for_transport(&bus, APP, "LZCLA", None).await.unwrap().len(), 1);
}

// ── A kind with its own access rule (PersonalizationService) ──────────────

#[tokio::test]
async fn an_access_override_and_an_unversioned_kind() {
    let e = env();
    let prefs = OverridableService::new(PrefKind, e.cx.clone());
    let nobody = auth_for("ANY", &[]);
    let created = prefs.create(&nobody, obj(r#"{"name":"p","appCode":"testapp"}"#)).await.unwrap();
    assert_eq!(e.count("version"), 0, "not versionable");
    let id = str_field(&created, "id").unwrap().to_string();
    let mut other = auth_for("ANY", &[]);
    other.user.id = 2;
    let err = prefs.update(&other, created.clone()).await.unwrap_err();
    assert_eq!(err.status(), StatusCode::FORBIDDEN, "another user's row is refused before the version check");
    assert_eq!(prefs.delete(&other, &id).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    prefs.update(&nobody, created).await.unwrap();
    assert!(prefs.delete(&nobody, &id).await.unwrap());
}

// ── Failures underneath ──────────────────────────────────────────────────

#[tokio::test]
async fn storage_and_security_failures_are_500s() {
    let e = env();
    let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
    e.mem.fail("version", true);
    let err = e.pages.create(&system(), obj(r#"{"name":"q","appCode":"testapp"}"#)).await.unwrap_err();
    assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    e.mem.fail("version", false);
    e.mem.fail("page", true);
    assert_eq!(e.pages.read(&system(), &id).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    e.mem.fail("page", false);
    e.dir.set(|a| a.failing = true);
    let fresh = auth_for("LZNEW", &all_for("Page"));
    assert_eq!(e.pages.read(&fresh, &id).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
}
