//! The engine routes end to end against a scratch MongoDB: the Java ui's
//! `EngineServiceRevalidationTest`, `EngineDraftSurfaceIntegrationTest`, the engine halves of
//! `DraftSurfaceIntegrationTest`, `DraftSaveEvictionIntegrationTest` and
//! `CrossClientForkIntegrationTest`, and the page, application, style and theme rules.
//!
//! Gated: `#[ignore]` and `MODLIX__MONGO__URI`; see `common`.

mod common;

use axum::http::StatusCode;
use common::*;
use mongodb::bson::{doc, oid::ObjectId, Document};
use overridable::JValue;
use platform::security::ContextAuthentication;
use ui::engine::Engine;
use ui::state::Caller;

const IGNORE: &str = "needs the local MongoDB (MODLIX__MONGO__URI)";

fn name_of(a: &Answer) -> String {
    a.obj()["name"].java_to_string()
}

// EngineServiceRevalidationTest

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn page_no_cache() {
    let _ = IGNORE;
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let r = e.call(get_req("/api/ui/page/campaigns").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-cache"));
    assert!(r.etag().starts_with("W/lg-"), "{}", r.etag());
    assert_eq!(name_of(&r), "campaigns");
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn page_not_modified() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let first = e.call(get_req("/api/ui/page/campaigns").user("SYSTEM", "Authorities.Logged_IN")).await;
    let r = e.call(get_req("/api/ui/page/campaigns").user("SYSTEM", "Authorities.Logged_IN").etag(&first.etag())).await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-cache"));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn page_after_logout() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let first = e.call(get_req("/api/ui/page/campaigns").user("SYSTEM", "Authorities.Logged_IN")).await;
    let r = e.call(get_req("/api/ui/page/campaigns").etag(&first.etag())).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(name_of(&r), "login");
    assert_eq!(r.header("cache-control").as_deref(), Some("no-cache"));
    // A miss in the eTag branch answers with the page's own id, without the login prefix.
    assert!(!r.etag().contains("lg-"), "{}", r.etag());
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn application_no_cache() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let r = e.call(get_req("/api/ui/application").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-cache"));
    let app = r.obj();
    assert_eq!(app["urlClientCode"], s("SYSTEM"));
    assert!(app.get("blueprint").is_none(), "the plan never leaves the builder");
    let nm = e.call(get_req("/api/ui/application").user("SYSTEM", "Authorities.Logged_IN").etag(&r.etag())).await;
    assert_eq!(nm.status, StatusCode::NOT_MODIFIED);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn application_after_logout() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let signed_in = e.call(get_req("/api/ui/application").user("SYSTEM", "Authorities.Logged_IN")).await;
    let r = e.call(get_req("/api/ui/application").etag(&signed_in.etag())).await;
    assert_eq!(r.status, StatusCode::OK, "the signed-in tag must not answer the anonymous read");
    let shell = prop(&r.obj(), "shellPageDefinition").and_then(JValue::as_object).cloned().unwrap();
    assert_eq!(shell["name"], s("forbidden"), "anonymous callers get the forbidden page as the shell");
    assert_ne!(r.etag(), signed_in.etag());
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn application_e_tag_miss_keeps_url_client_code() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let r = e.call(get_req("/api/ui/application").user("SYSTEM", "Authorities.Logged_IN").etag("W/STALE")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.obj()["urlClientCode"], s("SYSTEM"));
    e.done().await;
}

// The application read in full

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn application_inlines_shell_consent_and_filler() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let r = e.call(get_req("/api/ui/application").user("SYSTEM", "Authorities.Logged_IN")).await;
    let app = r.obj();
    assert_eq!(prop(&app, "shellPageDefinition").unwrap().as_object().unwrap()["name"], s("shell"));
    assert_eq!(prop(&app, "consentPageDefinition").unwrap().as_object().unwrap()["name"], s("consent"));
    assert_eq!(prop(&app, "fillerValues").unwrap().as_object().unwrap()["brand"], s("Acme"));
    assert!(prop(&app, "mobileApps").is_none());
    assert!(prop(&app, "manifest").is_none());
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn application_status_gate_and_missing_app() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    e.status(APP, "INACTIVE");
    let r = e.call(get_req("/api/ui/application")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.is_empty(), "an inactive app answers an empty 200");
    assert_eq!(r.header("cache-control").as_deref(), Some("no-cache, no-store, max-age=0, must-revalidate"));
    e.status("nostatus", "");
    assert!(e.call(get_req("/api/ui/application").app("nostatus")).await.body.is_empty());
    let r = e.call(get_req("/api/ui/application").app("noapp")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // An app with no shell, consent or filler, and no properties at all.
    e.insert("application", doc! {"name": "bare", "appCode": "bare", "clientCode": "SYSTEM"}).await;
    let r = e.call(get_req("/api/ui/application").app("bare")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.obj().get("properties").is_none());
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn the_empty_if_none_match_quirk() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    for path in ["/api/ui/application", "/api/ui/page/home", "/api/ui/theme", "/api/ui/style"] {
        let r = e.call(get_req(path).etag("")).await;
        assert_eq!(r.status, StatusCode::NOT_MODIFIED, "{path}");
    }
    e.done().await;
}

// The page read

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn protected_unknown_and_forbidden_pages() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    // Anonymous on a protected page: the login page.
    assert_eq!(name_of(&e.call(get_req("/api/ui/page/campaigns")).await), "login");
    // Unknown: the not-found page.
    assert_eq!(name_of(&e.call(get_req("/api/ui/page/nosuch")).await), "notfound");
    // Signed in without the permission: the forbidden page.
    let r = e.call(get_req("/api/ui/page/secret").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(name_of(&r), "forbidden");
    // With it: the page.
    let r = e.call(get_req("/api/ui/page/secret").user("SYSTEM", "Authorities.Logged_IN,Authorities.ROLE_Owner")).await;
    assert_eq!(name_of(&r), "secret");
    // The forbidden page asking for a permission the caller lacks is served as itself.
    e.db.collection::<Document>("page")
        .update_one(doc! {"name": "forbidden"}, doc! {"$set": {"permission": "Authorities.ROLE_Owner"}})
        .await
        .unwrap();
    e.evict(&["PageCache_testapp_forbidden"]).await;
    let r = e.call(get_req("/api/ui/page/forbidden").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(name_of(&r), "forbidden");
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn pages_of_an_app_without_the_special_pages() {
    let Some(e) = env().await else { return };
    e.insert("application", doc! {"name": "plain", "appCode": "plain", "clientCode": "SYSTEM", "properties": {"x": 1_i32}})
        .await;
    e.insert("page", doc! {"name": "p", "appCode": "plain", "clientCode": "SYSTEM", "permission": "Authorities.ROLE_Owner"})
        .await;
    // No login page: the protected page itself.
    let r = e.call(get_req("/api/ui/page/p").app("plain")).await;
    assert_eq!(name_of(&r), "p");
    // No not-found page: 404.
    assert_eq!(e.call(get_req("/api/ui/page/q").app("plain")).await.status, StatusCode::NOT_FOUND);
    // No forbidden page: Java's 403, naming the page's permission (Java's text for support).
    let r = e.call(get_req("/api/ui/page/p").app("plain").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.obj()["code"], s("UI.PAGE_PERMISSION_REQUIRED"));
    assert_eq!(r.obj()["message"], s("You can't open this page: your account does not have the Owner role."));
    assert_eq!(
        r.obj()["debugMessage"],
        s("[forbidden_permission] Permission/Role Authorities.ROLE_Owner is required to use this operation ")
    );
    // A forbidden page that does not exist: the protected page after all.
    e.db.collection::<Document>("application")
        .update_one(doc! {"name": "plain"}, doc! {"$set": {"properties.forbiddenPage": "gone", "properties.loginPage": "gone"}})
        .await
        .unwrap();
    e.evict(&["ApplicationCache_plain_cacheProperties_plain"]).await;
    let r = e.call(get_req("/api/ui/page/p").app("plain").user("SYSTEM", "Authorities.Logged_IN")).await;
    assert_eq!(name_of(&r), "p");
    // A login page that does not exist: the not-found path, and there is none.
    assert_eq!(e.call(get_req("/api/ui/page/p").app("plain")).await.status, StatusCode::NOT_FOUND);
    e.done().await;
}

// Style and theme

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn style_and_theme_follow_the_selected_theme() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let css = e.call(get_req("/api/ui/style")).await;
    assert_eq!(css.text(), "body{}\n.l{}", "the default theme's own style goes last");
    assert_eq!(css.header("content-type").as_deref(), Some("text/css;charset=UTF-8"));
    assert_eq!(css.header("cache-control").as_deref(), Some("max-age=604800, must-revalidate"));
    let dark = e.call(get_req("/api/ui/style?theme=dark")).await;
    assert_eq!(dark.text(), "body{}");
    let nm = e.call(get_req("/api/ui/style").etag(&css.etag())).await;
    assert_eq!(nm.status, StatusCode::NOT_MODIFIED);
    let stale = e.call(get_req("/api/ui/style").etag("W/old")).await;
    assert_eq!(stale.status, StatusCode::OK);
    let theme = e.call(get_req("/api/ui/theme")).await;
    assert_eq!(theme.obj()["ALL"].as_object().unwrap()["c"], s("white"));
    let dark = e.call(get_req("/api/ui/theme?theme=dark")).await;
    assert_eq!(dark.obj()["ALL"].as_object().unwrap()["c"], s("black"));
    let gone = e.call(get_req("/api/ui/theme?theme=gone")).await;
    assert_eq!(gone.obj()["ALL"].as_object().unwrap()["c"], s("white"));
    assert_eq!(e.call(get_req("/api/ui/theme").etag(&theme.etag())).await.status, StatusCode::NOT_MODIFIED);
    assert_eq!(e.call(get_req("/api/ui/theme").etag("W/old")).await.status, StatusCode::OK);
    assert_eq!(e.call(get_req("/api/ui/theme").app("noapp")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(e.call(get_req("/api/ui/style").app("noapp")).await.status, StatusCode::NOT_FOUND);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn style_and_theme_edges() {
    let Some(e) = env().await else { return };
    // No themes, a style that does not exist, a style with no styleString.
    e.insert(
        "application",
        doc! {"name": "s", "appCode": "s", "clientCode": "SYSTEM",
        "properties": {"styles": {"a": {"name": "missing", "order": 1_i32}, "b": {"name": "nostring", "order": 2_i32}}}},
    )
    .await;
    let r = e.call(get_req("/api/ui/theme").app("s")).await;
    assert_eq!(r.text(), "{ }");
    let r = e.call(get_req("/api/ui/style").app("s")).await;
    assert_eq!(r.text(), "", "missing styles only");
    e.insert("style", doc! {"name": "nostring", "appCode": "s", "clientCode": "SYSTEM"}).await;
    e.evict(&["StyleCache_s_nostring"]).await;
    assert_eq!(e.call(get_req("/api/ui/style").app("s")).await.text(), "null", "StringBuilder.append(null)");
    // No styles at all.
    e.insert("application", doc! {"name": "n", "appCode": "n", "clientCode": "SYSTEM", "properties": {"x": 1_i32}}).await;
    assert_eq!(e.call(get_req("/api/ui/style").app("n")).await.text(), "");
    // An order that is not an integer fails like Integer.valueOf.
    e.insert(
        "application",
        doc! {"name": "o", "appCode": "o", "clientCode": "SYSTEM",
        "properties": {"themes": {"a": {"name": "x", "order": 1.5}, "b": {"name": "y", "order": 2_i32}}}},
    )
    .await;
    assert_eq!(e.call(get_req("/api/ui/theme").app("o")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    e.done().await;
}

// Functions on the engine route

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn engine_function_route() {
    let Some(e) = env().await else { return };
    e.insert(
        "function",
        doc! {"name": "Ns.fn", "appCode": APP, "clientCode": "SYSTEM", "definition": {"name": "fn", "namespace": "Ns"}},
    )
    .await;
    let r = e.call(get_req("/api/ui/function/Ns/fn")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("cache-control").as_deref(), Some("max-age=604800, must-revalidate"));
    assert_eq!(r.obj()["definition"].as_object().unwrap()["name"], s("fn"));
    assert_eq!(e.call(get_req("/api/ui/function/Ns/fn").etag(&r.etag())).await.status, StatusCode::NOT_MODIFIED);
    let d = e.call(get_req("/api/ui/function/Ns/fn").draft()).await;
    assert_eq!(d.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(e.call(get_req("/api/ui/function/Ns/none")).await.status, StatusCode::NOT_FOUND);
    e.done().await;
}

// EngineDraftSurfaceIntegrationTest

fn caller(draft: bool) -> Caller {
    let mut ca = ContextAuthentication::default();
    ca.url_client_code = Some("SYSTEM".into());
    ca.client_code = Some("SYSTEM".into());
    Caller { ca, client_code: Some("SYSTEM".into()), app_code: Some(APP.into()), draft }
}

async fn app_draft(e: &Env, home: &str) {
    let app = e.db.collection::<Document>("application").find_one(doc! {"name": APP}).await.unwrap().unwrap();
    let id = app.get_object_id("_id").unwrap().to_hex();
    e.insert(
        "draft",
        doc! {"objectType": "APPLICATION", "objectAppCode": APP, "objectName": APP, "clientCode": "SYSTEM",
        "objectId": id, "baseVersion": 1_i32, "version": 1_i32,
        "content": {"name": APP, "properties": {"defaultPage": home, "shellPage": "shell"}}},
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn read_properties_follows_the_surface() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    app_draft(&e, "draftHome").await;
    let draft = caller(true);
    let live = caller(false);
    let d = Engine::new(&e.state, &draft).read_properties(APP, "SYSTEM").await.unwrap();
    assert_eq!(d["defaultPage"], s("draftHome"));
    let l = Engine::new(&e.state, &live).read_properties(APP, "SYSTEM").await.unwrap();
    assert_eq!(l["defaultPage"], s("home"));
    assert!(Engine::new(&e.state, &live).read_properties("noapp", "SYSTEM").await.unwrap().is_empty());
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn read_properties_live_first() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    app_draft(&e, "draftHome").await;
    let l = Engine::new(&e.state, &caller(false)).read_properties(APP, "SYSTEM").await.unwrap();
    assert_eq!(l["defaultPage"], s("home"));
    let d = Engine::new(&e.state, &caller(true)).read_properties(APP, "SYSTEM").await.unwrap();
    assert_eq!(d["defaultPage"], s("draftHome"));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn application_cache_headers() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    assert_eq!(e.call(get_req("/api/ui/application").draft()).await.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(e.call(get_req("/api/ui/application")).await.header("cache-control").as_deref(), Some("no-cache"));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn e_tags_carry_the_surface() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let d = e.call(get_req("/api/ui/application").draft()).await;
    let l = e.call(get_req("/api/ui/application")).await;
    assert!(d.etag().starts_with("W/d-"), "{}", d.etag());
    assert!(!l.etag().starts_with("W/d-"));
    // A live tag replayed on the draft host is re-marked, never a hit on the live entry.
    let replay = e.call(get_req("/api/ui/application").draft().etag(&l.etag())).await;
    assert_eq!(replay.status, StatusCode::NOT_MODIFIED, "the same content on both surfaces");
    let p = e.call(get_req("/api/ui/page/home").draft()).await;
    assert!(p.etag().starts_with("W/dnlg-"), "{}", p.etag());
    let p = e.call(get_req("/api/ui/page/home").draft().user("SYSTEM", "Authorities.Logged_IN")).await;
    assert!(p.etag().starts_with("W/dlg-"), "{}", p.etag());
    let st = e.call(get_req("/api/ui/style").draft()).await;
    assert!(st.etag().starts_with("W/d-"));
    assert_eq!(e.call(get_req("/api/ui/style").draft().etag(&st.etag())).await.status, StatusCode::NOT_MODIFIED);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn theme_and_style_headers() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    for path in ["/api/ui/theme", "/api/ui/style"] {
        assert_eq!(e.call(get_req(path).draft()).await.header("cache-control").as_deref(), Some("no-store"), "{path}");
    }
    e.done().await;
}

// DraftSurfaceIntegrationTest (the engine response)

async fn page_draft(e: &Env, name: &str, title: &str) {
    let page = e.db.collection::<Document>("page").find_one(doc! {"name": name}).await.unwrap().unwrap();
    let id = page.get_object_id("_id").unwrap().to_hex();
    e.db.collection::<Document>("draft")
        .delete_many(doc! {"objectName": name})
        .await
        .unwrap();
    e.insert(
        "draft",
        doc! {"objectType": "PAGE", "objectAppCode": APP, "objectName": name, "clientCode": "SYSTEM",
        "objectId": id, "baseVersion": 1_i32, "version": 1_i32,
        "content": {"name": name, "properties": {"title": title}}},
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn distinct_e_tag_and_no_store() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    page_draft(&e, "home", "Draft home").await;
    let d = e.call(get_req("/api/ui/page/home").draft()).await;
    let l = e.call(get_req("/api/ui/page/home")).await;
    assert_ne!(d.etag(), l.etag());
    assert_eq!(d.header("cache-control").as_deref(), Some("no-store"));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn right_body_per_surface() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    page_draft(&e, "home", "Draft home").await;
    assert_eq!(prop(&e.call(get_req("/api/ui/page/home").draft()).await.obj(), "title"), Some(&s("Draft home")));
    assert_eq!(prop(&e.call(get_req("/api/ui/page/home")).await.obj(), "title"), Some(&s("home")));
    e.done().await;
}

// DraftSaveEvictionIntegrationTest: a Java draft save publishes the _DRAFT evictions.

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn app_properties_after_a_read_then_a_save() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let before = Engine::new(&e.state, &caller(true)).read_properties(APP, "SYSTEM").await.unwrap();
    assert_eq!(before["defaultPage"], s("home"));
    app_draft(&e, "builderHome").await;
    e.evict(&["ApplicationCache_testapp_testapp_DRAFT", "ApplicationCache_testapp_cacheProperties_testapp_DRAFT"]).await;
    let after = Engine::new(&e.state, &caller(true)).read_properties(APP, "SYSTEM").await.unwrap();
    assert_eq!(after["defaultPage"], s("builderHome"));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn engine_application_after_a_read_then_a_save() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let before = e.call(get_req("/api/ui/application").draft()).await;
    assert_eq!(prop(&before.obj(), "defaultPage"), Some(&s("home")));
    app_draft(&e, "builderHome").await;
    e.evict(&["ApplicationCache_testapp_testapp_DRAFT", "ApplicationCache_testapp_cacheProperties_testapp_DRAFT"]).await;
    let after = e.call(get_req("/api/ui/application").draft().etag(&before.etag())).await;
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(prop(&after.obj(), "defaultPage"), Some(&s("builderHome")));
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn page_after_a_read_then_a_save() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    assert_eq!(prop(&e.call(get_req("/api/ui/page/home").draft()).await.obj(), "title"), Some(&s("home")));
    page_draft(&e, "home", "Saved").await;
    e.evict(&["PageCache_testapp_home_DRAFT"]).await;
    assert_eq!(prop(&e.call(get_req("/api/ui/page/home").draft()).await.obj(), "title"), Some(&s("Saved")));
    // second_save_over_an_existing_draft
    page_draft(&e, "home", "Saved again").await;
    e.evict(&["PageCache_testapp_home_DRAFT"]).await;
    assert_eq!(prop(&e.call(get_req("/api/ui/page/home").draft()).await.obj(), "title"), Some(&s("Saved again")));
    // discard_is_seen_too
    e.db.collection::<Document>("draft").delete_many(doc! {"objectName": "home"}).await.unwrap();
    e.evict(&["PageCache_testapp_home_DRAFT"]).await;
    assert_eq!(prop(&e.call(get_req("/api/ui/page/home").draft()).await.obj(), "title"), Some(&s("home")));
    e.done().await;
}

// CrossClientForkIntegrationTest: the surfaces after a fork (the fork row seeded).

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn fork_is_draft_only_until_published() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    e.chain("TENANT", &["SYSTEM", "TENANT"]);
    e.insert(
        "page",
        doc! {"name": "home", "appCode": APP, "clientCode": "TENANT", "baseClientCode": "SYSTEM",
        "published": false, "version": 1_i32, "properties": {"title": "Tenant fork"}},
    )
    .await;
    // live_unchanged
    let live = e.call(get_req("/api/ui/page/home").client("TENANT")).await;
    assert_eq!(prop(&live.obj(), "title"), Some(&s("home")));
    // draft_surface_serves_it
    let draft = e.call(get_req("/api/ui/page/home").client("TENANT").draft()).await;
    assert_eq!(prop(&draft.obj(), "title"), Some(&s("Tenant fork")));
    assert_eq!(draft.obj()["rootComponent"], s("root"), "the fork's delta merges over the owner's page");
    e.done().await;
}

// Requests the routes refuse

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn refused_and_odd_requests() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    let r = e.call(get_req("/api/ui/application").no_header("appCode")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.obj()["debugMessage"], s("400 BAD_REQUEST \"Required header 'appCode' is not present.\""));
    assert_eq!(r.obj()["code"], s("DEF.HEADER_MISSING"));
    assert_eq!(r.obj()["message"], s("The request is missing the appCode header."));
    for path in ["/api/ui/page/home", "/api/ui/style", "/api/ui/theme", "/api/ui/function/a/b", "/api/ui/urlDetails"] {
        let r = e.call(get_req(path).no_header("clientCode")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{path}");
    }
    let r = e.call(get_req("/api/ui/urlDetails")).await;
    assert_eq!(r.obj()["appCode"], s(APP));
    assert_eq!(r.obj()["clientCode"], s("SYSTEM"));
    let r = e.call(get_req("/api/ui/page/")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = e.call(get_req("/api/ui/nothing-here").header("X-Forwarded-Host", "apps.local")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Security refusing the caller: its status and message, or its status alone.
    for path in ["/api/ui/application", "/api/ui/page/home", "/api/ui/style", "/api/ui/theme", "/api/ui/function/a/b", "/api/ui/urlDetails"] {
        let r = e.call(get_req(path).header("Authorization", "refuse")).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(r.obj()["message"], s("Unknown client information requested"));
    }
    let r = e.call(get_req("/api/ui/page/home").header("Authorization", "refuse-silent")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.obj()["code"], s("COMMON.SIGNED_OUT"), "Java's empty refusal, said plainly");
    let r = e.call(get_req("/api/ui/page/home").header("Authorization", "broken")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    e.done().await;
}

#[tokio::test]
#[ignore = "needs the local MongoDB (MODLIX__MONGO__URI)"]
async fn a_derived_client_inherits_the_app_and_its_pages() {
    let Some(e) = env().await else { return };
    e.seed_app().await;
    e.chain("CHILD", &["SYSTEM", "CHILD"]);
    e.insert(
        "application",
        doc! {"name": APP, "appCode": APP, "clientCode": "CHILD", "baseClientCode": "SYSTEM",
        "properties": {"defaultPage": "childHome"}},
    )
    .await;
    let r = e.call(get_req("/api/ui/application").client("CHILD").user("CHILD", "Authorities.Logged_IN")).await;
    let app = r.obj();
    assert_eq!(prop(&app, "defaultPage"), Some(&s("childHome")));
    assert_eq!(prop(&app, "loginPage"), Some(&s("login")), "the rest comes from the base");
    assert_eq!(app["urlClientCode"], s("CHILD"));
    let id = ObjectId::new();
    assert!(!id.to_hex().is_empty());
    e.done().await;
}
