//! The services that span kinds, on the in-memory harness: app-wide publish (the Java
//! `PublishAuthorizationIntegrationTest`, core's `CorePublishAuthorizationIntegrationTest` and
//! `CoreDraftableIntegrationTest`), an app's wipe, transport export and import, the fillers,
//! and version history.

mod common;

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use mongodb::bson::doc;
use overridable::json::{parse, JMap, JValue};
use overridable::pojo::{map_field, str_field};
use overridable::write::condition::Query;
use overridable::write::deletion::DeletionService;
use overridable::write::filler::Filler;
use overridable::write::messages::error_message;
use overridable::write::publish::PublishService;
use overridable::write::transport::{base64_encode, days_ago, TransportRequest, TransportService};
use overridable::write::{AnyService, Messages, OverridableService};
use platform::security::OnBehalfOf;

fn arr(v: &JValue) -> &Vec<JValue> {
    match v {
        JValue::Array(a) => a,
        other => panic!("not an array: {other:?}"),
    }
}

async fn seed_draft(e: &Env, client: &str) -> String {
    let id = e.page(&page_json("testPage", client, "live", "r", ""));
    let ca = auth_for(client, &all_for("Page"));
    let body = obj(&format!(r#"{{"id":"{id}","properties":{{"title":"drafted"}},"message":"wip"}}"#));
    e.pages.save_draft(&ca, body, None).await.unwrap();
    id
}

fn publisher(e: &Env) -> PublishService {
    let storages: Arc<dyn AnyService> = Arc::new(e.storages());
    PublishService::new(e.cx.clone(), vec![Arc::new(e.pages.clone()) as Arc<dyn AnyService>, storages])
}

// ── Publish ──────────────────────────────────────────────────────────────

mod publish {
    use super::*;

    const OWNER: &str = "LZCLA";
    const OUTSIDER: &str = "LZCLB";

    #[tokio::test]
    async fn anonymous_and_unmanaged_callers_are_refused_and_told_nothing() {
        let e = env();
        e.dir.chain(&[OWNER]);
        seed_draft(&e, OWNER).await;
        let p = publisher(&e);
        for err in [p.pending(&anonymous(), APP, Some(OWNER)).await.unwrap_err(), p.publish_all(&anonymous(), APP, Some(OWNER)).await.unwrap_err()] {
            assert_eq!((err.status(), error_message(&err)), (StatusCode::FORBIDDEN, "Forbidden access to the application with code testapp".into()));
        }
        e.dir.isolate_tenants();
        let outsider = auth_for(OUTSIDER, &all_for("Page"));
        let err = p.pending(&outsider, APP, Some(OWNER)).await.unwrap_err();
        assert!(!error_message(&err).contains("objectId") && !error_message(&err).contains("testPage"));
        assert_eq!(e.count("draft"), 1);
    }

    #[tokio::test]
    async fn listing_needs_read_and_publishing_needs_write() {
        let e = env();
        e.dir.chain(&[OWNER]);
        let id = seed_draft(&e, OWNER).await;
        let p = publisher(&e);
        let owner = auth_for(OWNER, &all_for("Page"));
        let pending = p.pending(&owner, APP, None).await.unwrap();
        let rows = arr(&pending["PAGE"]);
        assert_eq!(rows.len(), 1);
        let row = rows[0].as_object().unwrap();
        assert_eq!(row.keys().collect::<Vec<_>>(), ["updatedBy", "baseVersion", "clientCode", "name", "message", "objectId", "objectType", "updatedAt"], "a HashMap's order");
        assert_eq!((str_field(row, "objectId"), str_field(row, "clientCode"), &row["updatedBy"]), (Some(id.as_str()), Some(OWNER), &JValue::Null));
        e.dir.set(|a| a.write_access = false);
        assert!(p.pending(&owner, APP, Some(OWNER)).await.is_ok());
        assert_eq!(p.publish_all(&owner, APP, None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
        e.dir.set(|a| {
            a.write_access = true;
            a.read_access = false;
        });
        assert_eq!(p.pending(&owner, APP, None).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_authorized_caller_publishes_everything() {
        let e = env();
        e.dir.chain(&[OWNER]);
        let id = seed_draft(&e, OWNER).await;
        let p = publisher(&e);
        let r = p.publish_all(&auth_for(OWNER, &all_for("Page")), APP, None).await.unwrap();
        assert_eq!(r.keys().collect::<Vec<_>>(), ["appCode", "clientCode", "attempted", "published", "results"]);
        assert_eq!((&r["attempted"], &r["published"]), (&JValue::Int(1), &JValue::Int(1)));
        let first = arr(&r["results"])[0].as_object().unwrap().clone();
        assert_eq!(first.keys().collect::<Vec<_>>(), ["objectType", "name", "objectId", "published"]);
        assert_eq!(prop_str(&e.raw_page(&id), "title"), Some("drafted"));
        assert_eq!(str_field(&e.raw_page(&id), "message"), Some("wip"), "the draft's own message");
        assert_eq!(e.count("draft"), 0);
    }

    #[tokio::test]
    async fn a_system_client_or_a_manager_may_name_the_client() {
        let e = env();
        e.dir.chain(&[OWNER]);
        seed_draft(&e, OWNER).await;
        let p = publisher(&e);
        assert_eq!(arr(&p.pending(&system(), APP, Some(OWNER)).await.unwrap()["PAGE"]).len(), 1);
        e.dir.set(|a| {
            a.manages_all = false;
            a.managers.insert("LZMGR".into());
        });
        let mgr = auth_for("LZMGR", &all_for("Page"));
        assert_eq!(arr(&p.pending(&mgr, APP, Some(OWNER)).await.unwrap()["PAGE"]).len(), 1);
        assert!(p.pending(&mgr, APP, Some(" ")).await.unwrap().is_empty(), "a blank client is the caller's own");
    }

    #[tokio::test]
    async fn unknown_types_and_failures_are_reported_not_fatal() {
        let e = env();
        e.mem.put_raw("draft", doc! {"objectType": "WIDGET", "objectAppCode": APP, "objectName": "w", "clientCode": SYSTEM, "objectId": "w1", "content": {}});
        let id = seed_draft(&e, SYSTEM).await;
        let mut raw = e.raw("page").remove(0);
        raw.insert("version", 5);
        e.mem.put_raw("page", raw);
        let r = publisher(&e).publish_all(&system(), APP, None).await.unwrap();
        let results = arr(&r["results"]);
        assert_eq!((&r["attempted"], &r["published"]), (&JValue::Int(2), &JValue::Int(0)));
        assert_eq!(results[0].as_object().unwrap()["error"], JValue::Str("No publishable service for object type WIDGET".into()));
        assert_eq!(results[1].as_object().unwrap()["error"], JValue::Str("Please reload to get the new version before making changes".into()));
        assert!(e.raw_page(&id)["properties"].as_object().is_some());
        assert_eq!(publisher(&e).object_types(), ["PAGE", "STORAGE"]);
    }

    #[tokio::test]
    async fn a_storage_draft_publishes_through_core_messages() {
        let e = env_with(Messages::core());
        let storages = e.storages();
        let id = e.insert_raw(&STORAGE, "storage", r#"{"name":"draftableStorage","appCode":"testapp","clientCode":"SYSTEM","version":1,"uniqueName":"testapp_system_draftablestorage","schema":{"name":"Draftable","type":"OBJECT","properties":{"title":{"type":"STRING"}}}}"#);
        let ca = auth_for(SYSTEM, &all_for("Storage"));
        let body = obj(&format!(r#"{{"id":"{id}","schema":{{"name":"Draftable","type":"OBJECT","properties":{{"draftedField":{{"type":"STRING"}}}}}}}}"#));
        storages.save_draft(&ca, body, None).await.unwrap();
        let drafts = e.raw("draft");
        assert_eq!(drafts[0].get_str("objectType").unwrap(), "STORAGE");
        let live = storages.read(&ca, &id).await.unwrap();
        assert!(map_field(map_field(&live, "schema").unwrap(), "properties").unwrap().contains_key("title"));
        let (draft, _) = storages.read_draft_with_version(&ca, &id).await.unwrap();
        assert!(map_field(map_field(&draft, "schema").unwrap(), "properties").unwrap().contains_key("draftedField"));
        let p = publisher(&e);
        let pending = p.pending(&ca, APP, None).await.unwrap();
        assert_eq!(pending.keys().collect::<Vec<_>>(), ["STORAGE"]);
        let r = p.publish_all(&ca, APP, None).await.unwrap();
        assert_eq!(r["published"], JValue::Int(1));
        let live = storages.read(&ca, &id).await.unwrap();
        assert!(map_field(map_field(&live, "schema").unwrap(), "properties").unwrap().contains_key("draftedField"));
    }
}

// ── Deleting an app ──────────────────────────────────────────────────────

#[tokio::test]
async fn an_apps_wipe_needs_delete_access_and_reaches_every_service() {
    let e = env();
    e.page(&page_json("p", SYSTEM, "t", "r", ""));
    e.insert_raw(&STORAGE, "storage", r#"{"name":"s","appCode":"testapp","clientCode":"SYSTEM","version":1}"#);
    let d = DeletionService::new(e.dir.clone(), vec![Arc::new(e.pages.clone()) as Arc<dyn AnyService>, Arc::new(e.storages())]);
    let ob = OnBehalfOf { forwarded_host: "localhost".into(), forwarded_port: "8080".into(), client_code: SYSTEM.into(), app_code: APP.into(), access_token: None };
    e.dir.set(|a| a.delete_access = false);
    assert_eq!(d.delete_everything(&system(), &ob, APP).await.unwrap(), None);
    assert_eq!(e.count("page"), 1);
    e.dir.set(|a| a.delete_access = true);
    assert_eq!(d.delete_everything(&system(), &ob, APP).await.unwrap(), Some(true));
    assert_eq!((e.count("page"), e.count("storage")), (0, 0));
    e.dir.set(|a| a.write_access = false);
    assert_eq!(d.delete_everything(&system(), &ob, APP).await.unwrap(), None, "no service had anything to do");
    e.dir.set(|a| a.failing = true);
    assert!(d.delete_everything(&system(), &ob, APP).await.is_err());
}

// ── Transport ────────────────────────────────────────────────────────────

fn transporter(e: &Env) -> TransportService {
    let services: Vec<Arc<dyn AnyService>> = vec![Arc::new(e.storages()), Arc::new(e.pages.clone())];
    TransportService::new(e.cx.clone(), services, "ui", "umodl")
}

fn transport_ca() -> platform::security::ContextAuthentication {
    let mut auths = all_for("Page");
    auths.extend(all_for("Storage"));
    auths.extend(all_for("Transport"));
    auth_for(SYSTEM, &auths)
}

fn ob() -> OnBehalfOf {
    OnBehalfOf { forwarded_host: "localhost".into(), forwarded_port: "8080".into(), client_code: SYSTEM.into(), app_code: APP.into(), access_token: None }
}

mod transport {
    use super::*;

    #[tokio::test]
    async fn json_export_then_import_into_another_app() {
        let e = env();
        e.page(&page_json("home", SYSTEM, "t", "r", ""));
        e.insert_raw(&STORAGE, "storage", r#"{"name":"orders","appCode":"testapp","clientCode":"SYSTEM","version":1,"relations":{"c":{"storageName":"customers"}}}"#);
        e.insert_raw(&STORAGE, "storage", r#"{"name":"customers","appCode":"testapp","clientCode":"SYSTEM","version":1}"#);
        let t = transporter(&e);
        assert_eq!(t.transport_types(), ["Storage", "Page"]);
        let ca = transport_ca();
        let req = TransportRequest::from_json(&parse(br#"{"appCode":"testapp","clientCode":"SYSTEM","name":"exp","fileType":"JSON"}"#).unwrap()).unwrap();
        let file = t.make_transport(&ca, false, &req).await.unwrap();
        assert_eq!(file.content_type, "application/json");
        let JValue::Object(json) = parse(&file.bytes).unwrap() else { panic!() };
        assert_eq!((str_field(&json, "type"), str_field(&json, "name")), (Some("ui"), Some("exp")));
        let objects = arr(&json["objects"]);
        assert_eq!(objects.len(), 3);
        assert_eq!(objects[0].as_object().unwrap()["objectType"], JValue::Str("Storage".into()));

        let mut t_json = json.clone();
        t_json.insert("uniqueTransportCode".into(), JValue::Str("CODE1".into()));
        let stored = t.create(&ca, overridable::pojo::convert_json(&overridable::write::transport::TRANSPORT, &t_json)).await.unwrap();
        assert_eq!(str_field(&stored, "name"), Some("expCODE1"));
        let again = t.create(&ca, overridable::pojo::convert_json(&overridable::write::transport::TRANSPORT, &t_json)).await.unwrap();
        assert_eq!(str_field(&again, "id"), str_field(&stored, "id"), "the same code answers the stored row");

        assert!(t.apply_transport(&ca, &ob(), str_field(&stored, "id").unwrap(), Some("otherapp"), false).await.unwrap());
        let imported: Vec<String> = e.raw("storage").iter().filter(|d| d.get_str("appCode") == Ok("otherapp")).map(|d| d.get_str("name").unwrap().to_string()).collect();
        assert_eq!(imported, ["customers", "orders"], "a storage is saved after the storage it relates to");
        let page = e.raw("page").into_iter().find(|d| d.get_str("appCode") == Ok("otherapp")).unwrap();
        assert_eq!(page.get_str("message").unwrap(), "From transport : expCODE1");

        assert!(t.apply_transport_with_code(&ca, &ob(), "CODE1").await.unwrap(), "a second apply updates in place");
        assert_eq!(e.raw("page").iter().filter(|d| d.get_str("name") == Ok("home")).count(), 2);
        let err = t.apply_transport_with_code(&ca, &ob(), "NOPE").await.unwrap_err();
        assert_eq!(error_message(&err), "Transport with id NOPE not found");
    }

    #[tokio::test]
    async fn zip_export_then_import_with_a_base_client() {
        let e = env();
        e.page(&page_json("api/route", SYSTEM, "t", "r", ""));
        e.insert_raw(&STORAGE, "storage", r#"{"name":"a","appCode":"testapp","clientCode":"SYSTEM","version":1,"relations":{"x":{"storageName":"b"}}}"#);
        e.insert_raw(&STORAGE, "storage", r#"{"name":"b","appCode":"testapp","clientCode":"SYSTEM","version":1,"relations":{"x":{"storageName":"a"}}}"#);
        let t = transporter(&e);
        let ca = transport_ca();
        let req = TransportRequest::from_json(&parse(br#"{"appCode":"testapp","clientCode":"SYSTEM","objectList":{"Storage":[],"Page":[]}}"#).unwrap()).unwrap();
        let file = t.make_transport(&ca, true, &req).await.unwrap();
        assert_eq!(file.content_disposition.as_deref(), Some("attachment; filename=testapp_SYSTEM.umodl"));
        let mut zip = zip::ZipArchive::new(Cursor::new(file.bytes.clone())).unwrap();
        let names: Vec<String> = (0..zip.len()).map(|i| zip.by_index(i).unwrap().name().to_string()).collect();
        assert!(names.contains(&"transport.json".to_string()));
        assert!(names.contains(&"Page/api__slash__route.json".to_string()), "{names:?}");
        let mut tj = String::new();
        zip.by_name("transport.json").unwrap().read_to_string(&mut tj).unwrap();
        assert!(tj.contains("\"type\" : \"ui\""));

        e.dir.set(|a| a.base_client = Some(("BASE".into(), false)));
        let created = t.create_and_apply(&ca, &ob(), "x.umodl", &file.bytes, false, Some("zipapp"), false).await.unwrap();
        assert!(str_field(&created, "encodedModl").is_some_and(|m| !m.is_empty()));
        let imported: Vec<(String, String)> = e
            .raw("storage")
            .iter()
            .filter(|d| d.get_str("appCode") == Ok("zipapp"))
            .map(|d| (d.get_str("clientCode").unwrap().to_string(), d.get_str("baseClientCode").unwrap_or("-").to_string()))
            .collect();
        assert_eq!(imported.len(), 2, "a cycle is saved in two passes");
        assert!(imported.iter().all(|(c, b)| c == SYSTEM && b == "BASE"));
        let stored_relations = e.raw("storage").into_iter().filter(|d| d.get_str("appCode") == Ok("zipapp")).filter(|d| d.get_document("relations").is_ok()).count();
        assert_eq!(stored_relations, 2, "the second pass saves the links");

        e.dir.set(|a| a.base_client = Some(("OWNER".into(), true)));
        let json_body = br#"{"name":"j","appCode":"testapp","clientCode":"SYSTEM","uniqueTransportCode":"J1","objects":[{"objectType":"Page","data":{"name":"fromJson","appCode":"testapp"}}]}"#;
        t.create_and_apply(&ca, &ob(), "t.json", json_body, false, Some("jsonapp"), true).await.unwrap();
        let page = e.raw("page").into_iter().find(|d| d.get_str("name") == Ok("fromJson")).unwrap();
        assert_eq!((page.get_str("clientCode").unwrap(), page.get_str("appCode").unwrap()), ("OWNER", "jsonapp"));
        assert!(!page.contains_key("baseClientCode"));
    }

    #[tokio::test]
    async fn refusals_and_bad_uploads() {
        let e = env();
        let t = transporter(&e);
        let reader = auth_for("LZCLA", &all_for("Page"));
        let req = TransportRequest::from_json(&parse(br#"{"appCode":"testapp","clientCode":"SYSTEM","fileType":"JSON"}"#).unwrap()).unwrap();
        let err = t.make_transport(&reader, false, &req).await.unwrap_err();
        assert_eq!(error_message(&err), "Cannot create Transport for the selected client");
        assert_eq!(t.make_transport(&reader, true, &req).await.unwrap_err().status(), StatusCode::FORBIDDEN, "internal JSON is for system clients");
        let ca = transport_ca();
        for (name, body, json) in [("x.zip", &b"not a zip"[..], false), ("x.json", &b"[1]"[..], false), ("x", &b"{"[..], true)] {
            let err = t.create_and_apply(&ca, &ob(), name, body, json, None, false).await.unwrap_err();
            assert!(error_message(&err).starts_with("Error while Creating transport : "), "{name}");
        }
        let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
        z.start_file("transport.json", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b"[]").unwrap();
        let bytes = z.finish().unwrap().into_inner();
        assert!(t.create_and_apply(&ca, &ob(), "x.zip", &bytes, false, None, false).await.is_err());
        let empty = t.create(&ca, obj(r#"{"name":"e","appCode":"testapp","uniqueTransportCode":"E1"}"#)).await.unwrap();
        assert!(t.apply_transport(&ca, &ob(), str_field(&empty, "id").unwrap(), None, false).await.unwrap(), "nothing to apply");
        let bad = t.create(&ca, obj(r#"{"name":"b","appCode":"testapp","uniqueTransportCode":"B1","encodedModl":"!!"}"#)).await.unwrap();
        assert!(t.apply_transport(&ca, &ob(), str_field(&bad, "id").unwrap(), None, false).await.is_err());
        let notzip = t.create(&ca, obj(&format!(r#"{{"name":"n","appCode":"testapp","uniqueTransportCode":"N1","encodedModl":"{}"}}"#, base64_encode(b"plain")))).await.unwrap();
        assert!(t.apply_transport(&ca, &ob(), str_field(&notzip, "id").unwrap(), None, false).await.is_err());
        assert_eq!(t.documents().update(&ca, empty).await.unwrap_err().status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn old_receipts_are_swept_with_their_versions() {
        let e = env();
        let t = transporter(&e);
        for (name, days) in [("old1", 200), ("old2", 100), ("young", 1)] {
            e.mem.put_raw("transport", doc! {"name": name, "appCode": APP, "clientCode": SYSTEM, "createdAt": days_ago(days), "encodedModl": "x"});
            e.mem.put_raw("version", doc! {"objectAppCode": APP, "clientCode": SYSTEM, "objectType": "TRANSPORT", "objectName": name});
        }
        let r = t.cleanup_older_than(0, 1).await.unwrap();
        assert_eq!((&r["transportsRemoved"], &r["versionsRemoved"]), (&JValue::Int(1), &JValue::Int(1)), "at most `limit` per run");
        let r = t.cleanup_older_than(90, 1000).await.unwrap();
        assert_eq!((&r["transportsRemoved"], &r["versionsRemoved"]), (&JValue::Int(1), &JValue::Int(1)));
        let r = t.cleanup_older_than(90, 10).await.unwrap();
        assert_eq!(r["transportsRemoved"], JValue::Int(0));
        assert_eq!(e.count("transport"), 1);
    }
}

// ── Fillers ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn fillers_are_named_after_their_app_and_read_through_their_own_cache() {
    let e = env();
    let kind = Filler::ui(&e.cache);
    assert_eq!(kind.read_cache_name(APP), "UIFillerCache_testapp_testapp_FILLER_READ");
    let fillers = OverridableService::new(kind, e.cx.clone());
    let ca = auth_for(SYSTEM, &all_for("Application"));
    let f = Filler::ui(&e.cache);
    assert!(f.read(&fillers, &ca, APP, SYSTEM, false).await.unwrap().is_none(), "none yet, and that is cached");
    let created = fillers.create(&ca, obj(r#"{"name":"ignored","appCode":"testapp","definition":{"a":1},"values":{"v":1}}"#)).await.unwrap();
    assert_eq!(str_field(&created, "name"), Some(APP));
    let read = f.read(&fillers, &ca, APP, SYSTEM, false).await.unwrap().unwrap();
    assert_eq!(map_field(&read.entity, "values").unwrap()["v"], JValue::Int(1));
    let mut edit = created.clone();
    edit.insert("values".into(), JValue::Object(obj(r#"{"v":2}"#)));
    edit.insert("permission".into(), JValue::Str("Authorities.X".into()));
    let saved = fillers.update(&ca, edit).await.unwrap();
    assert_eq!(str_field(&saved, "permission"), Some("Authorities.X"));
    assert_eq!(map_field(&f.read(&fillers, &ca, APP, SYSTEM, false).await.unwrap().unwrap().entity, "values").unwrap()["v"], JValue::Int(2));
    let id = str_field(&created, "id").unwrap().to_string();
    let body = obj(&format!(r#"{{"id":"{id}","values":{{"v":3}}}}"#));
    fillers.save_draft(&ca, body, None).await.unwrap();
    assert_eq!(map_field(&f.read(&fillers, &ca, APP, SYSTEM, true).await.unwrap().unwrap().entity, "values").unwrap()["v"], JValue::Int(3), "the draft surface has its own entry");
    assert_eq!(map_field(&f.read(&fillers, &ca, APP, SYSTEM, false).await.unwrap().unwrap().entity, "values").unwrap()["v"], JValue::Int(2));
    assert!(fillers.delete(&ca, &id).await.unwrap());
    assert!(f.read(&fillers, &ca, APP, SYSTEM, false).await.unwrap().is_none());
}

#[tokio::test]
async fn a_derived_filler_merges_and_an_empty_merge_is_none() {
    let e = env();
    let core = Filler::core(&e.cache);
    assert_eq!(overridable::DocType::cache_name(&core, "a", "b"), "FillerCache_a_b");
    let fillers = OverridableService::new(core, e.cx.clone());
    e.dir.chain(&[SYSTEM, "LZCLA"]);
    let ca = auth_for(SYSTEM, &all_for("Application"));
    fillers.create(&ca, obj(r#"{"appCode":"testapp","definition":{"a":1,"b":2},"values":{"x":1}}"#)).await.unwrap();
    let mid = auth_for("LZCLA", &all_for("Application"));
    let child = fillers.create(&mid, obj(r#"{"appCode":"testapp","baseClientCode":"SYSTEM","definition":{"a":1,"b":3},"values":{"x":1}}"#)).await.unwrap();
    assert_eq!(map_field(&child, "definition").unwrap()["b"], JValue::Int(3));
    let raw = e.raw("filler").into_iter().find(|d| d.get_str("clientCode") == Ok("LZCLA")).unwrap();
    assert_eq!(raw.get_document("definition").unwrap(), &doc! {"b": 3});
    let kind = Filler::core(&e.cache);
    assert!(overridable::DocType::apply_override(&kind, JMap::new(), &JMap::new()).is_none());
}

// ── Version history ──────────────────────────────────────────────────────

#[tokio::test]
async fn version_history_reads_and_pages() {
    let e = env();
    let created = e.pages.create(&system(), obj(r#"{"name":"p","appCode":"testapp","properties":{"t":1}}"#)).await.unwrap();
    let id = str_field(&created, "id").unwrap().to_string();
    let mut page = created.clone();
    for i in 2..=3 {
        page.insert("properties".into(), JValue::Object(obj(&format!(r#"{{"t":{i}}}"#))));
        page = e.pages.update(&system(), page).await.unwrap();
    }
    let versions = &e.cx.versions;
    let all = versions.read_page_per_object_id(&system(), &id, &Query::from_json(&JValue::Null).unwrap()).await.unwrap();
    let all = all.as_object().unwrap();
    assert_eq!(all["totalElements"], JValue::Int(3));
    let numbers: Vec<JValue> = arr(&all["content"]).iter().map(|v| v.as_object().unwrap()["versionNumber"].clone()).collect();
    assert_eq!(numbers.len(), 3);
    let q = Query::from_json(&parse(br#"{"size":1,"page":1,"fields":["versionNumber"],"sort":[{"property":"versionNumber","direction":"ASC"}],"condition":{"field":"versionNumber","operator":"GREATER_THAN","value":1}}"#).unwrap()).unwrap();
    let paged = versions.read_page_per_object_id(&system(), &id, &q).await.unwrap();
    let paged = paged.as_object().unwrap();
    assert_eq!(paged["totalElements"], JValue::Int(2));
    let row = arr(&paged["content"])[0].as_object().unwrap().clone();
    assert_eq!(row["versionNumber"], JValue::Int(3));
    assert!(!row.contains_key("object"), "only the asked-for fields");
    let excl = Query::from_json(&parse(br#"{"fields":["object"],"excludeFields":true}"#).unwrap()).unwrap();
    let excl = versions.read_page_per_object_id(&system(), &id, &excl).await.unwrap();
    assert!(!arr(&excl.as_object().unwrap()["content"])[0].as_object().unwrap().contains_key("object"));
    let bad = Query::from_json(&parse(br#"{"size":0}"#).unwrap()).unwrap();
    assert!(versions.read_page_per_object_id(&system(), &id, &bad).await.is_err());

    let outsider = auth_for("LZOUT", &all_for("Page"));
    let hidden = versions.read_page_per_object_id(&outsider, &id, &Query::from_json(&JValue::Null).unwrap()).await.unwrap();
    assert_eq!(hidden.as_object().unwrap()["totalElements"], JValue::Int(0), "another client's history is not listed (Java lists it to anyone)");
    let none = versions.read_page_per_object_id(&outsider, "nothing", &Query::from_json(&JValue::Null).unwrap()).await.unwrap();
    assert_eq!(none.as_object().unwrap()["totalElements"], JValue::Int(0));
    let vid = overridable::bson_conv::to_java_string(e.raw("version")[0].get("_id").unwrap()).java_to_string();
    assert!(versions.read(&system(), &vid).await.unwrap().is_some());
    assert!(versions.read(&system(), "64b7f1c2e4b0a1c2d3e4f5a6").await.unwrap().is_none());
    let other = auth_for("LZCLA", &all_for("Page"));
    assert!(versions.read(&other, &vid).await.unwrap().is_none(), "the version's client is not in the caller's chain");
    let loner = auth_for("LZLONE", &all_for("Page"));
    e.dir.set(|a| {
        a.chains.insert("LZLONE".into(), vec!["LZLONE".into()]);
    });
    assert!(versions.read(&loner, &vid).await.unwrap().is_none(), "a chain holding only the caller does not open SYSTEM's history (it did in Java)");
    e.dir.chain(&[SYSTEM, "LZCLA"]);
    e.cache.evict_all_everywhere("inheritanceOrder").await;
    assert!(versions.read(&other, &vid).await.unwrap().is_some());
    assert!(versions.read(&auth_for(SYSTEM, &[]), &vid).await.unwrap().is_none(), "the type's _READ authority");
    e.mem.put_raw("version", doc! {"_id": "untyped", "objectType": "URIPATH", "clientCode": SYSTEM});
    assert!(versions.read(&system(), "untyped").await.unwrap().is_none(), "a type mapAuthName lacks needs Authorities.null_READ");
    e.mem.put_raw("version", doc! {"_id": "blank", "clientCode": SYSTEM});
    assert!(versions.read(&system(), "blank").await.unwrap().is_none());
    let at = versions.content_at("PAGE", APP, "p", SYSTEM, 2).await.unwrap().unwrap();
    assert_eq!(map_field(&at, "properties").unwrap()["t"], JValue::Int(2));
    assert!(versions.content_at("PAGE", APP, "p", SYSTEM, 9).await.unwrap().is_none());
}
