//! Drafts, forks and publish on the in-memory harness, ported from the Java ui
//! `DraftPublishIntegrationTest`, `DraftReconciliationIntegrationTest`,
//! `ConcurrentDraftEditIntegrationTest`, `DraftBaseVersionIntegrationTest`,
//! `DraftAuthorizationIntegrationTest`, `DraftReadAuthorizationIntegrationTest`,
//! `DeletedObjectDraftIntegrationTest`, `DraftSurfaceIntegrationTest`,
//! `DraftSaveEvictionIntegrationTest` (its page case) and `CrossClientForkIntegrationTest`.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use common::*;
use mongodb::bson::{doc, Bson, Document};
use overridable::backend::{Backend, DuplicateKey, Find, MemBackend};
use overridable::pojo::{map_field, str_field};
use overridable::write::draft::DraftStore;
use overridable::write::messages::error_message;
use overridable::write::publish::PublishService;
use overridable::write::version::UI_AUTH_NAMES;
use overridable::write::{AnyService, Commons, Messages, OverridableService};
use overridable::{JMap, JValue, Store};
use platform::cache::CacheService;
use platform::security::ContextAuthentication;

fn set_prop(e: &mut JMap, k: &str, v: Option<&str>) {
    let props = e.entry("properties".to_string()).or_insert_with(|| JValue::Object(JMap::new()));
    if !matches!(props, JValue::Object(_)) {
        *props = JValue::Object(JMap::new());
    }
    let p = props.as_object_mut().unwrap();
    match v {
        Some(v) => {
            p.insert(k.into(), JValue::Str(v.into()));
        }
        None => {
            p.shift_remove(k);
        }
    }
}

async fn draft_edit(e: &Env, ca: &ContextAuthentication, id: &str, k: &str, v: &str) -> JMap {
    let (mut d, _) = e.pages.read_draft_with_version(ca, id).await.unwrap();
    set_prop(&mut d, k, Some(v));
    d.insert("id".into(), JValue::Str(id.into()));
    e.pages.save_draft(ca, d, None).await.unwrap()
}

async fn live_edit(e: &Env, ca: &ContextAuthentication, id: &str, k: &str, v: Option<&str>) {
    let mut p = e.pages.read(ca, id).await.unwrap();
    set_prop(&mut p, k, v);
    e.pages.update(ca, p).await.unwrap();
}

/// Makes the client's draft a legacy one, saved before drafts recorded their base content.
fn forget_base(e: &Env) {
    for mut raw in e.raw("draft") {
        raw.remove("baseContent");
        e.mem.put_raw("draft", raw);
    }
}

fn drafts(e: &Env) -> Vec<JMap> {
    e.raw("draft").iter().map(DraftStore::decode).collect()
}

fn content(d: &JMap) -> &JMap {
    d["content"].as_object().unwrap()
}

async fn runtime(e: &Env, ca: &ContextAuthentication, name: &str, client: &str, draft: bool) -> Option<JMap> {
    e.pages.read_resolved(ca, name, APP, client, draft).await.unwrap().map(|r| r.entity.clone())
}

// ── DraftPublishIntegrationTest ──────────────────────────────────────────

mod saving {
    use super::*;

    #[tokio::test]
    async fn does_not_touch_live_and_is_invisible_to_runtime() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "original", "r", ""));
        let d = draft_edit(&e, &system(), &id, "title", "drafted").await;
        assert_eq!(str_field(&d, "objectType"), Some("PAGE"));
        let stored = e.raw_page(&id);
        assert_eq!((prop_str(&stored, "title"), &stored["version"]), (Some("original"), &JValue::Int(1)));
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, false).await.unwrap(), "title"), Some("original"));
        let (editor, version) = e.pages.read_draft_with_version(&system(), &id).await.unwrap();
        assert_eq!((prop_str(&editor, "title"), version), (Some("drafted"), 1));
        assert_eq!(prop_str(&e.pages.read(&system(), &id).await.unwrap(), "title"), Some("original"));
        assert_eq!(e.count("version"), 0);
    }

    #[tokio::test]
    async fn replaces_the_previous_draft_and_falls_back_to_live() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "original", "r", ""));
        let (live, v) = e.pages.read_draft_with_version(&system(), &id).await.unwrap();
        assert_eq!((prop_str(&live, "title"), v), (Some("original"), 0));
        draft_edit(&e, &system(), &id, "title", "draft one").await;
        draft_edit(&e, &system(), &id, "title", "draft two").await;
        assert_eq!(e.count("draft"), 1);
        assert_eq!(prop_str(&e.pages.read_draft_with_version(&system(), &id).await.unwrap().0, "title"), Some("draft two"));
    }
}

mod publishing {
    use super::*;

    #[tokio::test]
    async fn promotes_removes_and_writes_a_version() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "original", "r", ""));
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        assert_eq!(e.count("version"), 0);
        let published = e.pages.publish(&system(), &id, Some("shipping it")).await.unwrap();
        assert_eq!(prop_str(&published, "title"), Some("drafted"));
        let stored = e.raw_page(&id);
        assert_eq!((prop_str(&stored, "title"), &stored["version"]), (Some("drafted"), &JValue::Int(2)));
        assert_eq!(str_field(&stored, "message"), Some("shipping it"));
        assert_eq!(e.count("draft"), 0);
        assert_eq!(e.count("version"), 1);
    }

    #[tokio::test]
    async fn rejects_an_unreconcilable_stale_publish() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "original", "r", ""));
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        live_edit(&e, &system(), &id, "title", Some("live edit")).await;
        forget_base(&e);
        let err = e.pages.publish(&system(), &id, None).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::PRECONDITION_FAILED, "a legacy draft with no v1 snapshot: the frozen base version meets the lock");
        assert_eq!(e.count("draft"), 1);
    }

    #[tokio::test]
    async fn fails_with_no_draft() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "original", "r", ""));
        let err = e.pages.publish(&system(), &id, None).await.unwrap_err();
        assert_eq!((err.status(), error_message(&err)), (StatusCode::NOT_FOUND, format!("Draft with id {id} not found")));
        assert_eq!(e.raw_page(&id)["version"], JValue::Int(1));
    }

    #[tokio::test]
    async fn discarding_removes_the_draft_only() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "original", "r", ""));
        assert!(!e.pages.discard_draft(&system(), &id).await.unwrap(), "false when there is nothing");
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        assert!(e.pages.discard_draft(&system(), &id).await.unwrap());
        assert_eq!(e.count("draft"), 0);
        assert_eq!(prop_str(&e.raw_page(&id), "title"), Some("original"));
        assert_eq!(e.pages.discard_draft(&system(), "64b7f1c2e4b0a1c2d3e4f5a6").await.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_base_draft_does_not_reach_the_child_and_a_child_publish_leaves_the_base() {
        let e = env();
        let base = e.page(&format!(r#"{{"name":"p","appCode":"{APP}","clientCode":"SYSTEM","version":1,"properties":{{"fromRoot":"r"}}}}"#));
        let child = e.page(&format!(r#"{{"name":"p","appCode":"{APP}","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1,"properties":{{"fromMid":"m"}}}}"#));
        e.dir.chain(&[SYSTEM, "LZCLA"]);
        draft_edit(&e, &system(), &base, "fromRoot", "drafted").await;
        let mid = auth_for("LZCLA", &all_for("Page"));
        assert_eq!(prop_str(&e.pages.read(&mid, &child).await.unwrap(), "fromRoot"), Some("r"));
        draft_edit(&e, &mid, &child, "fromMid", "m2").await;
        e.pages.publish(&mid, &child, None).await.unwrap();
        let b = e.raw_page(&base);
        assert_eq!((&b["version"], prop_str(&b, "fromRoot")), (&JValue::Int(1), Some("r")));
    }

    #[tokio::test]
    async fn never_published_objects() {
        let e = env();
        let created = e.pages.create_unpublished(&system(), obj(r#"{"name":"wipPage","appCode":"testapp","properties":{"title":"wip"}}"#)).await.unwrap();
        let id = str_field(&created, "id").unwrap().to_string();
        assert_eq!(created["published"], JValue::Bool(false));
        assert!(runtime(&e, &system(), "wipPage", SYSTEM, false).await.is_none(), "invisible at runtime");
        assert_eq!(prop_str(&runtime(&e, &system(), "wipPage", SYSTEM, true).await.unwrap(), "title"), Some("wip"), "the draft surface shows it");
        assert_eq!(prop_str(&e.pages.read(&system(), &id).await.unwrap(), "title"), Some("wip"));
        draft_edit(&e, &system(), &id, "title", "ready").await;
        e.pages.publish(&system(), &id, Some("go live")).await.unwrap();
        assert_eq!(e.raw_page(&id)["published"], JValue::Bool(true));
        assert_eq!(prop_str(&runtime(&e, &system(), "wipPage", SYSTEM, false).await.unwrap(), "title"), Some("ready"));
        e.page(&page_json("legacy", SYSTEM, "existing", "r", ""));
        assert!(runtime(&e, &system(), "legacy", SYSTEM, false).await.is_some(), "null published is published");
    }

    /// `createUnpublished` tracks the new object with a draft row of its full content (as sent,
    /// the id and version of the created document added), so publish-all lists it.
    #[tokio::test]
    async fn a_never_published_object_has_a_draft_row_of_its_full_content() {
        let e = env();
        let created = e
            .pages
            .create_unpublished(&system(), obj(r#"{"name":"wip2","appCode":"testapp","message":"first","properties":{"title":"wip"}}"#))
            .await
            .unwrap();
        let id = str_field(&created, "id").unwrap().to_string();
        let rows = e.raw("draft");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!((row.get_str("objectType").ok(), row.get_str("objectId").ok(), row.get_str("message").ok()), (Some("PAGE"), Some(id.as_str()), Some("first")));
        let content = row.get_document("content").unwrap();
        assert_eq!(content.get_str("id").ok(), Some(id.as_str()));
        assert_eq!(content.get_document("properties").unwrap().get_str("title").ok(), Some("wip"));
        assert_eq!(content.get_bool("published").ok(), Some(false));
        assert_eq!(e.pages.read_draft_with_version(&system(), &id).await.unwrap().1, 1, "the editor reads it back as the draft");
    }
}

// ── DraftReconciliationIntegrationTest ───────────────────────────────────

async fn created_page(e: &Env, props: &str) -> String {
    let body = obj(&format!(r#"{{"name":"reconcilePage","appCode":"{APP}","rootComponent":"root","properties":{props}}}"#));
    let c = e.pages.create(&system(), body).await.unwrap();
    str_field(&c, "id").unwrap().to_string()
}

mod reconciliation {
    use super::*;

    #[tokio::test]
    async fn a_disjoint_live_change_is_carried_in_and_recorded() {
        let e = env();
        let id = created_page(&e, r#"{"shared":"same"}"#).await;
        draft_edit(&e, &system(), &id, "fromDraft", "d").await;
        live_edit(&e, &system(), &id, "fromLive", Some("L")).await;
        let draft_surface = runtime(&e, &system(), "reconcilePage", SYSTEM, true).await.unwrap();
        assert_eq!((prop_str(&draft_surface, "fromDraft"), prop_str(&draft_surface, "fromLive")), (Some("d"), Some("L")), "the draft surface shows what a publish would");
        let live_surface = runtime(&e, &system(), "reconcilePage", SYSTEM, false).await.unwrap();
        assert!(prop(&live_surface, "fromDraft").is_none());
        e.pages.publish(&system(), &id, Some("shipping")).await.unwrap();
        let s = e.raw_page(&id);
        assert_eq!((prop_str(&s, "fromDraft"), prop_str(&s, "fromLive"), prop_str(&s, "shared")), (Some("d"), Some("L"), Some("same")));
        assert_eq!(str_field(&s, "message"), Some("shipping [reconciled from v1 onto live v2]"));
        assert_eq!(e.count("draft"), 0);
    }

    #[tokio::test]
    async fn drift_anywhere_and_live_deletions() {
        let e = env();
        let id = created_page(&e, r#"{"keep":"k","doomed":"d"}"#).await;
        draft_edit(&e, &system(), &id, "keep", "k2").await;
        let mut p = e.pages.read(&system(), &id).await.unwrap();
        set_prop(&mut p, "doomed", None);
        p.insert("rootComponent".into(), JValue::Str("newRoot".into()));
        e.pages.update(&system(), p).await.unwrap();
        e.pages.publish(&system(), &id, Some("shipping")).await.unwrap();
        let s = e.raw_page(&id);
        assert_eq!(prop_str(&s, "keep"), Some("k2"));
        assert!(prop(&s, "doomed").is_none(), "a live deletion survives");
        assert_eq!(str_field(&s, "rootComponent"), Some("newRoot"));
    }

    #[tokio::test]
    async fn a_real_conflict_keeps_the_draft_and_says_so() {
        let e = env();
        let id = created_page(&e, r#"{"title":"t"}"#).await;
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        live_edit(&e, &system(), &id, "title", Some("live edit")).await;
        e.pages.publish(&system(), &id, Some("shipping")).await.unwrap();
        let s = e.raw_page(&id);
        assert_eq!(prop_str(&s, "title"), Some("drafted"));
        assert_eq!(str_field(&s, "message"), Some("shipping [reconciled from v1 onto live v2; draft kept over live at properties.title]"));
    }

    #[tokio::test]
    async fn a_clean_publish_keeps_the_message_verbatim() {
        let e = env();
        let id = created_page(&e, r#"{"title":"t"}"#).await;
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        e.pages.publish(&system(), &id, Some("shipping")).await.unwrap();
        assert_eq!(str_field(&e.raw_page(&id), "message"), Some("shipping"));
    }

    #[tokio::test]
    async fn no_base_snapshot_still_refuses() {
        let e = env();
        let id = e.page(&format!(r#"{{"name":"reconcilePage","appCode":"{APP}","clientCode":"SYSTEM","version":7,"properties":{{"title":"t"}}}}"#));
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        let mut raw = e.raw("page").remove(0);
        raw.insert("version", 9);
        raw.get_document_mut("properties").unwrap().insert("title", "live edit");
        e.mem.put_raw("page", raw);
        forget_base(&e);
        assert!(e.pages.publish(&system(), &id, None).await.is_err());
        assert_eq!(prop_str(&e.raw_page(&id), "title"), Some("live edit"));
        assert_eq!(e.count("draft"), 1);
    }

    #[tokio::test]
    async fn merges_from_the_frozen_base() {
        let e = env();
        let id = created_page(&e, r#"{"title":"t"}"#).await;
        draft_edit(&e, &system(), &id, "draftOnly", "d").await;
        live_edit(&e, &system(), &id, "liveOne", Some("1")).await;
        live_edit(&e, &system(), &id, "liveTwo", Some("2")).await;
        e.pages.publish(&system(), &id, None).await.unwrap();
        let s = e.raw_page(&id);
        assert_eq!((prop_str(&s, "draftOnly"), prop_str(&s, "liveOne"), prop_str(&s, "liveTwo")), (Some("d"), Some("1"), Some("2")));
        assert_eq!(str_field(&s, "message"), Some("[reconciled from v1 onto live v3]"), "a note alone when there is no message");
    }

    #[tokio::test]
    async fn reconciles_across_an_override_chain() {
        let e = env();
        e.dir.chain(&[SYSTEM, "LZCLA"]);
        created_page(&e, r#"{"fromBase":"b"}"#).await;
        let mid = auth_for("LZCLA", &all_for("Page"));
        let body = obj(&format!(r#"{{"name":"reconcilePage","appCode":"{APP}","baseClientCode":"SYSTEM","properties":{{"fromBase":"b","fromChild":"c"}}}}"#));
        let child = str_field(&e.pages.create(&mid, body).await.unwrap(), "id").unwrap().to_string();
        draft_edit(&e, &mid, &child, "fromDraft", "d").await;
        live_edit(&e, &mid, &child, "fromLive", Some("L")).await;
        e.pages.publish(&mid, &child, None).await.unwrap();
        let merged = e.pages.read(&mid, &child).await.unwrap();
        for (k, v) in [("fromDraft", "d"), ("fromLive", "L"), ("fromBase", "b"), ("fromChild", "c")] {
            assert_eq!(prop_str(&merged, k), Some(v), "{k}");
        }
        assert!(prop(&e.raw_page(&child), "fromBase").is_none(), "the stored child is still a delta");
    }

    #[tokio::test]
    async fn the_draft_surface_matches_the_published_result() {
        let e = env();
        let id = created_page(&e, r#"{"shared":"s","contested":"orig"}"#).await;
        let (mut d, _) = e.pages.read_draft_with_version(&system(), &id).await.unwrap();
        set_prop(&mut d, "fromDraft", Some("d"));
        set_prop(&mut d, "contested", Some("draftWins"));
        e.pages.save_draft(&system(), d, None).await.unwrap();
        let mut p = e.pages.read(&system(), &id).await.unwrap();
        set_prop(&mut p, "fromLive", Some("L"));
        set_prop(&mut p, "contested", Some("liveLoses"));
        e.pages.update(&system(), p).await.unwrap();
        let preview = runtime(&e, &system(), "reconcilePage", SYSTEM, true).await.unwrap();
        e.pages.publish(&system(), &id, None).await.unwrap();
        let stored = e.raw_page(&id);
        assert_eq!(map_field(&preview, "properties"), map_field(&stored, "properties"));
    }

    #[tokio::test]
    async fn identity_is_not_mergeable() {
        let e = env();
        let id = created_page(&e, r#"{"title":"t"}"#).await;
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        let mut raw = e.raw("draft").remove(0);
        let c = raw.get_document_mut("content").unwrap();
        c.insert("clientCode", "ELSEWHERE");
        c.insert("name", "someOtherPage");
        c.insert("version", 999);
        e.mem.put_raw("draft", raw);
        live_edit(&e, &system(), &id, "fromLive", Some("L")).await;
        e.pages.publish(&system(), &id, None).await.unwrap();
        let s = e.raw_page(&id);
        assert_eq!((str_field(&s, "clientCode"), str_field(&s, "name")), (Some(SYSTEM), Some("reconcilePage")));
        assert!(e.raw("page").iter().all(|d| d.get_str("name") != Ok("someOtherPage")));
    }
}

// ── A client's draft publish over a base that moved (Rust only) ───────────
// A client's draft holds the whole merged document. Publishing it used to store, as the
// client's override, every change its base shipped while the draft was open (old values, and
// deletions of what the base added). The draft records the merged document it started from,
// and only what the client changed against that is written.

mod client_publish {
    use super::*;

    const TENANT: &str = "LZCLA";

    fn tenant() -> ContextAuthentication {
        auth_for(TENANT, &all_for("Page"))
    }

    /// SYSTEM's page and the tenant's own (published) copy holding nothing yet.
    async fn pages(e: &Env) -> (String, String) {
        e.dir.chain(&[SYSTEM, TENANT]);
        let body = obj(&format!(r#"{{"name":"shared","appCode":"{APP}","rootComponent":"root","properties":{{"title":"t","style":"old","keep":"k"}}}}"#));
        let sys = str_field(&e.pages.create(&system(), body).await.unwrap(), "id").unwrap().to_string();
        let body = obj(&format!(r#"{{"name":"shared","appCode":"{APP}","baseClientCode":"SYSTEM","properties":{{"title":"t","style":"old","keep":"k"}}}}"#));
        let own = str_field(&e.pages.create(&tenant(), body).await.unwrap(), "id").unwrap().to_string();
        assert!(stored_props(e, &own).is_empty(), "the copy starts as an empty difference");
        (sys, own)
    }

    fn stored_props(e: &Env, id: &str) -> JMap {
        map_field(&e.raw_page(id), "properties").cloned().unwrap_or_default()
    }

    async fn ships(e: &Env, sys: &str) {
        live_edit(e, &system(), sys, "style", Some("new")).await;
        live_edit(e, &system(), sys, "added", Some("A")).await;
    }

    #[tokio::test]
    async fn only_the_clients_edit_is_stored_and_what_the_base_shipped_shows_through() {
        let e = env();
        let (sys, own) = pages(&e).await;
        draft_edit(&e, &tenant(), &own, "title", "Tenant title").await;
        ships(&e, &sys).await;
        e.pages.publish(&tenant(), &own, None).await.unwrap();
        assert_eq!(stored_props(&e, &own), obj(r#"{"title":"Tenant title"}"#), "no stale base value and no deletion of what the base added");
        let merged = e.pages.read(&tenant(), &own).await.unwrap();
        for (k, v) in [("title", "Tenant title"), ("style", "new"), ("added", "A"), ("keep", "k")] {
            assert_eq!(prop_str(&merged, k), Some(v), "{k}");
        }
        live_edit(&e, &system(), &sys, "style", Some("newer")).await;
        assert_eq!(prop_str(&e.pages.read(&tenant(), &own).await.unwrap(), "style"), Some("newer"), "later base changes keep reaching the client");
    }

    #[tokio::test]
    async fn the_draft_surface_shows_the_same() {
        let e = env();
        let (sys, own) = pages(&e).await;
        draft_edit(&e, &tenant(), &own, "title", "Tenant title").await;
        ships(&e, &sys).await;
        let preview = runtime(&e, &tenant(), "shared", TENANT, true).await.unwrap();
        e.pages.publish(&tenant(), &own, None).await.unwrap();
        let live = runtime(&e, &tenant(), "shared", TENANT, false).await.unwrap();
        assert_eq!(map_field(&preview, "properties"), map_field(&live, "properties"));
        assert_eq!(prop_str(&preview, "style"), Some("new"));
    }

    #[tokio::test]
    async fn a_client_deletion_is_kept_while_base_changes_show_through() {
        let e = env();
        let (sys, own) = pages(&e).await;
        let (mut d, _) = e.pages.read_draft_with_version(&tenant(), &own).await.unwrap();
        set_prop(&mut d, "keep", None);
        e.pages.save_draft(&tenant(), d, None).await.unwrap();
        ships(&e, &sys).await;
        e.pages.publish(&tenant(), &own, None).await.unwrap();
        assert_eq!(stored_props(&e, &own), obj(r#"{"keep":null}"#), "the deletion, and only it");
        let merged = e.pages.read(&tenant(), &own).await.unwrap();
        assert!(prop(&merged, "keep").is_none());
        assert_eq!((prop_str(&merged, "style"), prop_str(&merged, "added")), (Some("new"), Some("A")));
    }

    #[tokio::test]
    async fn the_client_wins_a_key_both_changed_and_the_note_says_so() {
        let e = env();
        let (sys, own) = pages(&e).await;
        draft_edit(&e, &tenant(), &own, "style", "tenant").await;
        ships(&e, &sys).await;
        e.pages.publish(&tenant(), &own, Some("ship")).await.unwrap();
        assert_eq!(stored_props(&e, &own), obj(r#"{"style":"tenant"}"#));
        let merged = e.pages.read(&tenant(), &own).await.unwrap();
        assert_eq!((prop_str(&merged, "style"), prop_str(&merged, "added")), (Some("tenant"), Some("A")));
        assert_eq!(str_field(&e.raw_page(&own), "message"), Some("ship [reconciled from v1 onto live v1; draft kept over live at properties.style]"));
    }

    #[tokio::test]
    async fn the_clients_earlier_overrides_survive() {
        let e = env();
        let (sys, own) = pages(&e).await;
        live_edit(&e, &tenant(), &own, "keep", Some("mine")).await;
        draft_edit(&e, &tenant(), &own, "title", "Tenant title").await;
        ships(&e, &sys).await;
        e.pages.publish(&tenant(), &own, None).await.unwrap();
        assert_eq!(stored_props(&e, &own), obj(r#"{"keep":"mine","title":"Tenant title"}"#));
    }

    #[tokio::test]
    async fn a_legacy_draft_is_rebuilt_from_the_base_history() {
        let e = env();
        let (sys, own) = pages(&e).await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        draft_edit(&e, &tenant(), &own, "title", "Tenant title").await;
        forget_base(&e);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        ships(&e, &sys).await;
        e.pages.publish(&tenant(), &own, None).await.unwrap();
        assert_eq!(stored_props(&e, &own), obj(r#"{"title":"Tenant title"}"#));
        assert_eq!(prop_str(&e.pages.read(&tenant(), &own).await.unwrap(), "added"), Some("A"));
    }

    #[tokio::test]
    async fn a_legacy_draft_with_no_history_keeps_the_old_behaviour() {
        let e = env();
        e.dir.chain(&[SYSTEM, TENANT]);
        e.page(&page_json("shared", SYSTEM, "t", "root", r#","style":"old""#));
        let own = e.page(&format!(r#"{{"name":"shared","appCode":"{APP}","clientCode":"{TENANT}","baseClientCode":"SYSTEM","version":1,"properties":{{}}}}"#));
        draft_edit(&e, &tenant(), &own, "title", "Tenant title").await;
        forget_base(&e);
        let mut raw = e.raw("page").into_iter().find(|d| d.get_str("clientCode") == Ok(SYSTEM)).unwrap();
        raw.insert("updatedAt", mongodb::bson::DateTime::from_millis(i64::MAX / 2));
        raw.get_document_mut("properties").unwrap().insert("style", "new");
        e.mem.put_raw("page", raw);
        e.pages.publish(&tenant(), &own, None).await.unwrap();
        assert_eq!(stored_props(&e, &own), obj(r#"{"title":"Tenant title","style":"old"}"#), "nothing to tell the base's change from the client's");
    }
}

// ── ConcurrentDraftEditIntegrationTest and DraftBaseVersionIntegrationTest ─

mod versions {
    use super::*;

    fn shared(e: &Env, version: i32) -> String {
        e.page(&format!(r#"{{"name":"sharedDraftPage","appCode":"{APP}","clientCode":"SYSTEM","version":{version},"rootComponent":"liveRoot"}}"#))
    }

    async fn save(e: &Env, id: &str, root: &str, expected: Option<i64>) -> Result<JMap, platform::error::AppError> {
        let body = obj(&format!(r#"{{"id":"{id}","name":"sharedDraftPage","appCode":"{APP}","rootComponent":"{root}","properties":{{"title":"{root}"}}}}"#));
        e.pages.save_draft(&system(), body, expected).await
    }

    #[tokio::test]
    async fn the_draft_version_moves_and_the_base_does_not() {
        let e = env();
        let id = shared(&e, 7);
        let (live, v) = e.pages.read_draft_with_version(&system(), &id).await.unwrap();
        assert_eq!((str_field(&live, "rootComponent"), v), (Some("liveRoot"), 0));
        let d1 = save(&e, &id, "one", None).await.unwrap();
        assert_eq!((&d1["version"], &d1["baseVersion"]), (&JValue::Int(1), &JValue::Int(7)));
        let (read, v) = e.pages.read_draft_with_version(&system(), &id).await.unwrap();
        assert_eq!((str_field(&read, "rootComponent"), v), (Some("one"), 1));
        let d2 = save(&e, &id, "two", None).await.unwrap();
        assert_eq!((&d2["version"], &d2["baseVersion"]), (&JValue::Int(2), &JValue::Int(7)));
    }

    #[tokio::test]
    async fn a_second_editor_is_refused_until_it_rereads() {
        let e = env();
        let id = shared(&e, 7);
        save(&e, &id, "fromA", Some(0)).await.unwrap();
        let err = save(&e, &id, "fromB", Some(0)).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::PRECONDITION_FAILED);
        let d = &drafts(&e)[0];
        assert_eq!((str_field(content(d), "rootComponent"), &d["version"]), (Some("fromA"), &JValue::Int(1)));
        let (_, seen) = e.pages.read_draft_with_version(&system(), &id).await.unwrap();
        save(&e, &id, "fromB", Some(seen)).await.unwrap();
        let d = &drafts(&e)[0];
        assert_eq!((str_field(content(d), "rootComponent"), &d["version"]), (Some("fromB"), &JValue::Int(2)));
    }

    #[tokio::test]
    async fn the_check_is_opt_in() {
        let e = env();
        let id = shared(&e, 7);
        save(&e, &id, "fromA", None).await.unwrap();
        save(&e, &id, "fromB", None).await.unwrap();
        assert_eq!(str_field(content(&drafts(&e)[0]), "rootComponent"), Some("fromB"));
    }

    #[tokio::test]
    async fn the_base_version_is_frozen_until_a_discard() {
        let e = env();
        let id = shared(&e, 7);
        save(&e, &id, "draftOne", None).await.unwrap();
        let mut raw = e.raw("page").remove(0);
        raw.insert("version", 9);
        raw.insert("rootComponent", "liveMovedOn");
        e.mem.put_raw("page", raw);
        let d = save(&e, &id, "draftTwo", None).await.unwrap();
        assert_eq!((&d["baseVersion"], str_field(content(&d), "rootComponent")), (&JValue::Int(7), Some("draftTwo")));
        let base = e.raw("draft").remove(0);
        assert_eq!(base.get_document("baseContent").unwrap().get_str("rootComponent").ok(), Some("liveRoot"), "the base content is frozen too");
        forget_base(&e);
        assert!(e.pages.publish(&system(), &id, None).await.is_err());
        assert_eq!(str_field(&e.raw_page(&id), "rootComponent"), Some("liveMovedOn"));
        assert_eq!(e.count("draft"), 1);
        e.pages.discard_draft(&system(), &id).await.unwrap();
        let d = save(&e, &id, "again", None).await.unwrap();
        assert_eq!(d["baseVersion"], JValue::Int(9));
    }
}

// ── DraftAuthorization and DraftReadAuthorization ────────────────────────

mod authorization {
    use super::*;

    const ATTACKER: &str = "LZCLA";
    const VICTIM: &str = "LZCLB";
    const MANAGER: &str = "LZMGR";

    fn isolated(e: &Env) {
        e.dir.set(|a| {
            a.manages_all = false;
            a.managers.insert(MANAGER.into());
        });
    }

    #[tokio::test]
    async fn a_cross_tenant_draft_is_refused_and_destroys_nothing() {
        let e = env();
        e.dir.chain(&[VICTIM]);
        let id = e.page(&page_json("testPage", VICTIM, "victim live", "r", ""));
        isolated(&e);
        let victim = auth_for(VICTIM, &all_for("Page"));
        draft_edit(&e, &victim, &id, "title", "victim draft").await;
        let attacker = auth_for(ATTACKER, &all_for("Page"));
        let payload = obj(&format!(r#"{{"id":"{id}","clientCode":"{ATTACKER}","properties":{{"title":"attacker payload"}}}}"#));
        let err = e.pages.save_draft(&attacker, payload, None).await.unwrap_err();
        assert_eq!((err.status(), error_message(&err)), (StatusCode::FORBIDDEN, "Permission/Role Page is required to use this operation ".into()));
        assert_eq!(e.count("draft"), 1);
        assert_eq!(prop_str(content(&drafts(&e)[0]), "title"), Some("victim draft"));
        assert_eq!(prop_str(&e.pages.read_draft_with_version(&victim, &id).await.unwrap().0, "title"), Some("victim draft"));
    }

    #[tokio::test]
    async fn a_manager_drafts_and_identity_comes_from_the_stored_document() {
        let e = env();
        e.dir.chain(&[VICTIM]);
        let id = e.page(&page_json("testPage", VICTIM, "victim live", "r", ""));
        isolated(&e);
        let manager = auth_for(MANAGER, &all_for("Page"));
        let payload = obj(&format!(r#"{{"id":"{id}","clientCode":"{VICTIM}","properties":{{"title":"managed"}}}}"#));
        let d = e.pages.save_draft(&manager, payload, None).await.unwrap();
        assert_eq!(str_field(&d, "clientCode"), Some(VICTIM));
        let mut raw = e.raw("draft").remove(0);
        let c = raw.get_document_mut("content").unwrap();
        c.insert("clientCode", ATTACKER);
        c.insert("appCode", "someotherapp");
        c.insert("name", "someOtherPage");
        e.mem.put_raw("draft", raw);
        e.pages.publish(&manager, &id, None).await.unwrap();
        let s = e.raw_page(&id);
        assert_eq!((str_field(&s, "clientCode"), str_field(&s, "appCode"), str_field(&s, "name")), (Some(VICTIM), Some(APP), Some("testPage")));
    }

    #[tokio::test]
    async fn delete_evicts_the_draft_cache() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "live", "r", ""));
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        assert!(runtime(&e, &system(), "testPage", SYSTEM, true).await.is_some());
        e.pages.delete(&system(), &id).await.unwrap();
        assert!(runtime(&e, &system(), "testPage", SYSTEM, true).await.is_none());
    }

    #[tokio::test]
    async fn a_derived_client_never_sees_the_base_clients_draft() {
        let e = env();
        e.dir.chain(&["LZBASE", "LZDERIV"]);
        let id = e.page(&page_json("testPage", "LZBASE", "base live", "rootComp", ""));
        let base = auth_for("LZBASE", &all_for("Page"));
        draft_edit(&e, &base, &id, "title", "base UNPUBLISHED secret").await;
        isolated(&e);
        let derived = auth_for("LZDERIV", &all_for("Page"));
        let (seen, v) = e.pages.read_draft_with_version(&derived, &id).await.unwrap();
        assert_eq!((prop_str(&seen, "title"), v), (Some("base live"), 0));
        let (own, v) = e.pages.read_draft_with_version(&base, &id).await.unwrap();
        assert_eq!((prop_str(&own, "title"), v), (Some("base UNPUBLISHED secret"), 1));
        e.dir.chain(&["LZBASE", MANAGER]);
        let (managed, _) = e.pages.read_draft_with_version(&auth_for(MANAGER, &all_for("Page")), &id).await.unwrap();
        assert_eq!(prop_str(&managed, "title"), Some("base UNPUBLISHED secret"));
    }
}

// ── DeletedObjectDraftIntegrationTest ────────────────────────────────────

mod deleted {
    use super::*;

    fn publisher(e: &Env) -> PublishService {
        PublishService::new(e.cx.clone(), vec![Arc::new(e.pages.clone()) as Arc<dyn AnyService>])
    }

    #[tokio::test]
    async fn the_draft_goes_with_its_object() {
        let e = env();
        let id = e.page(&page_json("deletedDraftPage", SYSTEM, "t", "liveRoot", ""));
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        let p = publisher(&e);
        assert!(!p.pending(&system(), APP, Some(SYSTEM)).await.unwrap().is_empty());
        e.pages.delete(&system(), &id).await.unwrap();
        assert_eq!(e.count("draft"), 0);
        assert!(p.pending(&system(), APP, Some(SYSTEM)).await.unwrap().is_empty());
        let recreated = e.page(&page_json("deletedDraftPage", SYSTEM, "t", "recreatedRoot", ""));
        let r = e.pages.read_resolved(&system(), "deletedDraftPage", APP, SYSTEM, true).await.unwrap().unwrap();
        assert_eq!((str_field(&r.entity, "rootComponent"), str_field(&r.entity, "id")), (Some("recreatedRoot"), Some(recreated.as_str())));
    }

    #[tokio::test]
    async fn delete_everything_sweeps_drafts_of_the_app_only() {
        let e = env();
        let a = e.page(&page_json("p", SYSTEM, "t", "r", ""));
        let b = e.page(&format!(r#"{{"name":"p","appCode":"otherapp","clientCode":"SYSTEM","version":1}}"#));
        draft_edit(&e, &system(), &a, "title", "x").await;
        draft_edit(&e, &system(), &b, "title", "y").await;
        assert_eq!(e.count("draft"), 2);
        e.pages.delete_everything(&system(), APP, SYSTEM).await.unwrap();
        let left = drafts(&e);
        assert_eq!(left.len(), 1);
        assert_eq!(str_field(&left[0], "objectAppCode"), Some("otherapp"));
    }

    #[tokio::test]
    async fn an_orphaned_draft_is_reported() {
        let e = env();
        let id = e.page(&page_json("p", SYSTEM, "t", "r", ""));
        draft_edit(&e, &system(), &id, "title", "x").await;
        e.mem.delete_many("page", doc! {}).await.unwrap();
        let r = publisher(&e).publish_all(&system(), APP, None).await.unwrap();
        assert_eq!((&r["attempted"], &r["published"]), (&JValue::Int(1), &JValue::Int(0)));
        let JValue::Array(results) = &r["results"] else { panic!("results") };
        let first = results[0].as_object().unwrap().clone();
        assert_eq!(first["published"], JValue::Bool(false));
        assert_eq!(first["error"], JValue::Str(format!("Page with id {id} not found")));
    }
}

// ── DraftSurfaceIntegrationTest and DraftSaveEvictionIntegrationTest ─────

mod surface {
    use super::*;

    #[tokio::test]
    async fn the_runtime_read_follows_the_surface() {
        let e = env();
        let id = e.page(&page_json("testPage", SYSTEM, "live", "r", ""));
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, true).await.unwrap(), "title"), Some("live"), "falls back to live");
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, false).await.unwrap(), "title"), Some("live"));
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, true).await.unwrap(), "title"), Some("drafted"), "the save evicted the warmed draft cache");
        draft_edit(&e, &system(), &id, "title", "second").await;
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, true).await.unwrap(), "title"), Some("second"));
        e.pages.discard_draft(&system(), &id).await.unwrap();
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, true).await.unwrap(), "title"), Some("live"));
        draft_edit(&e, &system(), &id, "title", "drafted").await;
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, true).await.unwrap(), "title"), Some("drafted"));
        e.pages.publish(&system(), &id, Some("ship")).await.unwrap();
        for draft in [false, true] {
            assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, draft).await.unwrap(), "title"), Some("drafted"), "both surfaces agree after a publish");
        }
        assert!(e.calls().iter().any(|c| c == "evict_draft testapp SYSTEM testPage"));
    }

    #[tokio::test]
    async fn drafts_stay_with_their_client() {
        let e = env();
        e.dir.chain(&[SYSTEM, "LZCLA", "LZACP1"]);
        let base = e.page(&page_json("testPage", SYSTEM, "base live", "r", ""));
        draft_edit(&e, &system(), &base, "title", "base draft").await;
        let mid = auth_for("LZCLA", &all_for("Page"));
        assert_eq!(prop_str(&runtime(&e, &mid, "testPage", "LZCLA", true).await.unwrap(), "title"), Some("base live"));
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, true).await.unwrap(), "title"), Some("base draft"));
        let mid_id = e.page(&format!(r#"{{"name":"testPage","appCode":"{APP}","clientCode":"LZCLA","baseClientCode":"SYSTEM","version":1,"properties":{{"title":"mid live"}}}}"#));
        draft_edit(&e, &mid, &mid_id, "title", "mid draft").await;
        assert_eq!(prop_str(&runtime(&e, &mid, "testPage", "LZCLA", true).await.unwrap(), "title"), Some("mid draft"));
        let leaf = auth_for("LZACP1", &all_for("Page"));
        assert_eq!(prop_str(&runtime(&e, &leaf, "testPage", "LZACP1", true).await.unwrap(), "title"), Some("mid live"));
    }
}

// ── CrossClientForkIntegrationTest ───────────────────────────────────────

mod fork {
    use super::*;

    const TENANT: &str = "LZCLB";

    fn tenant_env() -> (Env, String, ContextAuthentication) {
        let e = env();
        e.dir.chain(&[SYSTEM, TENANT]);
        let id = e.page(&page_json("testPage", SYSTEM, "system live", "systemRoot", ""));
        e.dir.set(|a| a.manages_all = false);
        (e, id, auth_for(TENANT, &all_for("Page")))
    }

    fn rows_of(e: &Env, client: &str) -> Vec<JMap> {
        e.raw("page").iter().map(|d| overridable::pojo::decode_bson(&PAGE, d)).filter(|p| str_field(p, "clientCode") == Some(client)).collect()
    }

    #[tokio::test]
    async fn the_first_draft_forks_an_override() {
        let (e, base, tenant) = tenant_env();
        let d = draft_edit(&e, &tenant, &base, "title", "tenant draft").await;
        assert_eq!(str_field(&d, "clientCode"), Some(TENANT));
        let forks = rows_of(&e, TENANT);
        assert_eq!(forks.len(), 1);
        let fork = &forks[0];
        assert_eq!((str_field(fork, "baseClientCode"), &fork["published"]), (Some(SYSTEM), &JValue::Bool(false)));
        let fork_id = str_field(fork, "id").unwrap().to_string();
        assert_eq!(str_field(&d, "objectId"), Some(fork_id.as_str()));
        assert_ne!(fork_id, base);
        assert_eq!(fork["rootComponent"], JValue::Null, "a delta");
        assert_eq!(prop_str(&runtime(&e, &tenant, "testPage", TENANT, false).await.unwrap(), "title"), Some("system live"), "live unchanged");
        assert_eq!(prop_str(&runtime(&e, &tenant, "testPage", TENANT, true).await.unwrap(), "title"), Some("tenant draft"));
        let b = e.raw_page(&base);
        assert_eq!((prop_str(&b, "title"), &b["version"]), (Some("system live"), &JValue::Int(1)));

        draft_edit(&e, &tenant, &base, "title", "again").await;
        assert_eq!(rows_of(&e, TENANT).len(), 1, "a stale ancestor id lands on the fork");
        let again = e.pages.fork_for_caller(&tenant, &base).await.unwrap();
        assert_eq!(str_field(&again, "id"), Some(fork_id.as_str()), "idempotent");

        let mut raw = e.raw("page").into_iter().find(|d| d.get_str("clientCode") == Ok(SYSTEM)).unwrap();
        raw.insert("rootComponent", "newRootFromOwner");
        e.mem.put_raw("page", raw);
        assert_eq!(str_field(&e.pages.read(&tenant, &fork_id).await.unwrap(), "rootComponent"), Some("newRootFromOwner"));

        e.pages.publish(&tenant, &fork_id, None).await.unwrap();
        assert_eq!(rows_of(&e, TENANT)[0]["published"], JValue::Bool(true));
        assert_eq!(e.count("draft"), 0);
        assert_eq!(prop_str(&runtime(&e, &tenant, "testPage", TENANT, false).await.unwrap(), "title"), Some("again"));
        e.dir.chain(&[SYSTEM]);
        assert_eq!(prop_str(&runtime(&e, &system(), "testPage", SYSTEM, false).await.unwrap(), "title"), Some("system live"));
    }

    #[tokio::test]
    async fn refusals_leave_no_row() {
        let (e, base, tenant) = tenant_env();
        e.dir.set(|a| a.write_access = false);
        assert_eq!(e.pages.fork_for_caller(&tenant, &base).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let (e2, base2, tenant2) = tenant_env();
        e2.dir.chain(&[TENANT]);
        assert_eq!(e2.pages.fork_for_caller(&tenant2, &base2).await.unwrap_err().status(), StatusCode::FORBIDDEN, "outside the caller's chain");
        let (e3, _, tenant3) = tenant_env();
        let locked = e3.page(&format!(r#"{{"name":"locked","appCode":"{APP}","clientCode":"SYSTEM","version":1,"notOverridable":true}}"#));
        let err = e3.pages.fork_for_caller(&tenant3, &locked).await.unwrap_err();
        assert_eq!(error_message(&err), "Page locked cannot be overridden, so it cannot be edited by a client that does not own it");
        let (e4, _, tenant4) = tenant_env();
        let wip = e4.page(&format!(r#"{{"name":"wip","appCode":"{APP}","clientCode":"SYSTEM","version":1,"published":false}}"#));
        assert_eq!(e4.pages.fork_for_caller(&tenant4, &wip).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        let (e5, base5, _) = tenant_env();
        let no_create = auth_for(TENANT, &["Authorities.Page_UPDATE".into(), "Authorities.Page_READ".into()]);
        assert_eq!(e5.pages.fork_for_caller(&no_create, &base5).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        for env in [&e, &e2, &e3, &e4, &e5] {
            assert!(rows_of(env, TENANT).is_empty());
        }
        assert_eq!(e.pages.fork_for_caller(&tenant, " ").await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(e.pages.fork_for_caller(&tenant, "64b7f1c2e4b0a1c2d3e4f5a6").await.unwrap_err().status(), StatusCode::FORBIDDEN);
        assert_eq!(e.pages.discard_draft(&tenant, &base).await.unwrap_err().status(), StatusCode::FORBIDDEN, "a discard never forks");
    }

    #[tokio::test]
    async fn forks_base_off_the_most_derived_ancestor() {
        let (e, base, tenant) = tenant_env();
        e.dir.chain(&[SYSTEM, "LZMID", TENANT]);
        e.page(&format!(r#"{{"name":"testPage","appCode":"{APP}","clientCode":"LZMID","baseClientCode":"SYSTEM","version":1,"properties":{{"fromMid":"m"}}}}"#));
        let fork = e.pages.fork_for_caller(&tenant, &base).await.unwrap();
        assert_eq!(str_field(&fork, "baseClientCode"), Some("LZMID"));
        assert_eq!(prop_str(&e.pages.read(&tenant, str_field(&fork, "id").unwrap()).await.unwrap(), "fromMid"), Some("m"));
        draft_edit(&e, &tenant, str_field(&fork, "id").unwrap(), "title", "x").await;
        assert!(e.pages.discard_draft(&tenant, &base).await.unwrap(), "a discard against the ancestor's id finds the caller's own row");
    }

    #[tokio::test]
    async fn a_manager_still_writes_in_place() {
        let e = env();
        e.dir.chain(&[TENANT]);
        let target = e.page(&page_json("testPage", TENANT, "t", "r", ""));
        let mid = auth_for("LZMID", &all_for("Page"));
        let d = draft_edit(&e, &mid, &target, "title", "x").await;
        assert_eq!((str_field(&d, "clientCode"), str_field(&d, "objectId")), (Some(TENANT), Some(target.as_str())));
        assert!(rows_of(&e, "LZMID").is_empty());
    }

    /// A backend on which every page insert loses a race: another editor's row lands first.
    struct Racing {
        mem: Arc<MemBackend>,
        winner: Document,
    }

    #[async_trait]
    impl Backend for Racing {
        async fn find(&self, c: &str, q: Find) -> anyhow::Result<Vec<Document>> {
            self.mem.find(c, q).await
        }
        async fn count(&self, c: &str, f: Document) -> anyhow::Result<u64> {
            self.mem.count(c, f).await
        }
        async fn insert(&self, c: &str, d: Document) -> anyhow::Result<Bson> {
            if c == "page" {
                self.mem.put_raw(c, self.winner.clone());
                return Err(DuplicateKey { collection: c.into() }.into());
            }
            self.mem.insert(c, d).await
        }
        async fn replace(&self, c: &str, id: Bson, d: Document) -> anyhow::Result<()> {
            self.mem.replace(c, id, d).await
        }
        async fn delete_one(&self, c: &str, f: Document) -> anyhow::Result<u64> {
            self.mem.delete_one(c, f).await
        }
        async fn delete_many(&self, c: &str, f: Document) -> anyhow::Result<u64> {
            self.mem.delete_many(c, f).await
        }
        async fn update_many(&self, c: &str, f: Document, s: Document) -> anyhow::Result<u64> {
            self.mem.update_many(c, f, s).await
        }
    }

    #[tokio::test]
    async fn a_fork_that_loses_the_race_adopts_the_winner() {
        let mem = Arc::new(MemBackend::new());
        let dir = Arc::new(overridable::backend::FakeDirectory::new());
        dir.chain(&[SYSTEM, TENANT]);
        dir.set(|a| a.manages_all = false);
        let winner = doc! {"_id": "winner", "name": "testPage", "appCode": APP, "clientCode": TENANT, "baseClientCode": SYSTEM, "version": 1};
        let racing = Arc::new(Racing { mem: mem.clone(), winner });
        let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
        let cx = Commons::new(Store::with_parts(racing, dir, &cache).unwrap(), cache, Messages::ui(), UI_AUTH_NAMES);
        let pages = OverridableService::new(PageKind::default(), cx);
        let base = mem.put_raw("page", doc! {"name": "testPage", "appCode": APP, "clientCode": SYSTEM, "version": 1});
        let base = overridable::bson_conv::to_java_string(&base).java_to_string();
        let target = pages.fork_for_caller(&auth_for(TENANT, &all_for("Page")), &base).await.unwrap();
        assert_eq!(str_field(&target, "id"), Some("winner"));
    }

    #[tokio::test]
    async fn a_fork_that_loses_to_a_named_row_adopts_it_and_other_failures_surface() {
        let (e, base, tenant) = tenant_env();
        // Another editor's row appears between the chain read and the create: checkIfExists
        // answers 409, which converges on that row.
        let other = OverridableService::new(Racer, e.cx.clone());
        let fork = other.fork_for_caller(&tenant, &base).await.unwrap();
        assert_eq!(str_field(&fork, "clientCode"), Some(TENANT));
        let (e2, base2, tenant2) = tenant_env();
        e2.mem.fail("version", true);
        assert_eq!(e2.pages.fork_for_caller(&tenant2, &base2).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// A page kind whose create finds that someone else just made the caller's row.
    struct Racer;

    impl overridable::DocType for Racer {
        fn object_name(&self) -> &'static str {
            "Page"
        }
        fn collection(&self) -> &'static str {
            "page"
        }
        fn pojo(&self) -> &'static overridable::pojo::Pojo {
            &PAGE
        }
        fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
            Some(this)
        }
    }

    #[async_trait]
    impl overridable::write::Kind for Racer {
        async fn before_create(&self, cx: &Commons, _ca: &ContextAuthentication, entity: &mut JMap) -> platform::error::AppResult<()> {
            let d = doc! {"name": str_field(entity, "name").unwrap_or(""), "appCode": APP, "clientCode": TENANT, "baseClientCode": SYSTEM, "version": 1};
            cx.backend().insert("page", d).await?;
            Ok(())
        }
    }
}

// ── A kind that does not draft ───────────────────────────────────────────

#[tokio::test]
async fn draft_routes_answer_405_for_a_kind_that_does_not_draft() {
    let e = env();
    let prefs = OverridableService::new(PrefKind, e.cx.clone());
    let ca = system();
    let checks = [
        prefs.save_draft(&ca, obj(r#"{"id":"x"}"#), None).await.unwrap_err(),
        prefs.fork_for_caller(&ca, "x").await.unwrap_err(),
        prefs.read_draft_with_version(&ca, "x").await.unwrap_err(),
        prefs.publish(&ca, "x", None).await.unwrap_err(),
        prefs.discard_draft(&ca, "x").await.unwrap_err(),
        prefs.create_unpublished(&ca, obj("{}")).await.unwrap_err(),
    ];
    for err in checks {
        assert_eq!((err.status(), error_message(&err)), (StatusCode::METHOD_NOT_ALLOWED, "Draft with id Personalization not found".into()));
    }
    assert_eq!(e.pages.save_draft(&ca, obj("{}"), None).await.unwrap_err().status(), StatusCode::FORBIDDEN, "no id");
    assert_eq!(e.pages.save_draft(&ca, obj(r#"{"id":"64b7f1c2e4b0a1c2d3e4f5a6"}"#), None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
}
