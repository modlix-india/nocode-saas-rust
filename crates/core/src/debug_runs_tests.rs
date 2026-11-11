//! The stored debug runs: masking, the caps, the rollover and age rules, access, the day
//! counts, and the nested logs put back under their steps.

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::{NaiveDate, TimeDelta};
use overridable::write::spring::{Pageable, Sort};
use serde_json::{json, Value};

use super::*;
use crate::auth::Authentication;
use crate::error::CoreError;
use crate::event_runs::RunAccess;

const APP: &str = "leadzump";

/// SYSTEM manages FIN; nobody manages anything else.
struct Access;

#[async_trait]
impl RunAccess for Access {
    async fn has_read_access(&self, _: &str, _: &str) -> Result<Option<bool>, CoreError> {
        Ok(Some(true))
    }
    async fn filter_managed_client_codes(&self, _: &str, c: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        Ok(Some(c.to_vec()))
    }
    async fn does_client_manage_client_code(&self, managing: &str, client: &str) -> Result<Option<bool>, CoreError> {
        Ok(Some(managing == "SYSTEM" && client == "FIN"))
    }
}

fn service() -> (Arc<MemoryDebugRunDao>, Arc<FunctionDebugRunService>) {
    let dao = Arc::new(MemoryDebugRunDao::default());
    (dao.clone(), Arc::new(FunctionDebugRunService::new(dao, Arc::new(Access))))
}

fn editor() -> Authentication {
    crate::testing::user(&[FUNCTION_UPDATE])
}

fn fin_editor() -> Authentication {
    crate::testing::auth(
        json!({"user": {"id": 7, "clientId": 2, "userName": "fin", "stringAuthorities": [FUNCTION_UPDATE], "accountNonExpired": true},
               "authenticated": true, "loggedInFromClientId": 2, "loggedInFromClientCode": "FIN",
               "clientTypeCode": "BUS", "clientCode": "FIN", "accessToken": "t", "accessTokenExpiryAt": 1}),
        Some("FIN"),
        Some(APP),
    )
}

fn info(client: &str, name: &str, debug: &str) -> RunInfo {
    RunInfo {
        execution_id: "x".into(),
        debug_id: debug.into(),
        app_code: APP.into(),
        client_code: client.into(),
        namespace: "Ns".into(),
        name: name.into(),
        user_id: Some(142),
        user_name: Some("Test User".into()),
        draft: false,
        failed: false,
    }
}

fn entry(stmt: &str, arguments: Value, result: Value) -> Value {
    json!({"stepId": format!("s_{stmt}"), "timestamp": 1, "functionName": "System.Make", "statementName": stmt,
           "duration": 1, "arguments": arguments, "result": result, "eventName": "output", "children": []})
}

fn log_of(entries: Vec<Value>, start_ms: i64) -> Value {
    json!({"executionId": "x", "startTime": start_ms, "endTime": start_ms + 5, "errored": false, "logs": entries, "definitions": {}})
}

fn now_ms() -> i64 {
    crate::event_runs::now().and_utc().timestamp_millis()
}

fn filter(name: Option<&str>) -> DebugRunFilter {
    DebugRunFilter { app_code: APP.into(), name: name.map(String::from), ..Default::default() }
}

fn page() -> Pageable {
    Pageable::of(0, 200, Sort::unsorted())
}

// ------------------------------------------------------------------ masking and caps

#[test]
fn secrets_are_masked_at_any_depth() {
    let mut v = json!({"user": "a", "Password": "p", "nested": [{"api_key": "k", "APIKEY": "k2", "x": {"clientSecret": {"deep": 1}}}],
                       "headers": {"Authorization": "Bearer x", "accessToken": "t", "privateKey": "pk", "passwd": "pw", "ok": 1}});
    mask(&mut v);
    assert_eq!(v["user"], json!("a"));
    assert_eq!(v["Password"], json!(MASK));
    assert_eq!(v["nested"][0]["api_key"], json!(MASK));
    assert_eq!(v["nested"][0]["APIKEY"], json!(MASK));
    assert_eq!(v["nested"][0]["x"]["clientSecret"], json!(MASK));
    for k in ["Authorization", "accessToken", "privateKey", "passwd"] {
        assert_eq!(v["headers"][k], json!(MASK), "{k}");
    }
    assert_eq!(v["headers"]["ok"], json!(1));
}

#[test]
fn steps_are_masked_and_capped_unless_full() {
    let big = "a".repeat(20 * 1024);
    let child = entry("inner", json!({"token": "secret-value"}), json!({"value": big.clone()}));
    let mut top = entry("outer", json!({"value": big.clone(), "secret": "s"}), json!(1));
    top["children"] = json!([child]);
    let log = log_of(vec![top], 0);

    let (stored, steps, bytes) = prepare_log(log.clone(), false);
    assert_eq!(steps, 2);
    let outer = &stored["logs"][0];
    assert_eq!(outer["truncated"], json!(true));
    assert!(outer["arguments"].is_string());
    assert_eq!(outer["arguments"].as_str().unwrap().len(), STEP_CAP_BYTES);
    assert!(!outer["arguments"].as_str().unwrap().contains("\"s\""), "masked before it is cut");
    assert_eq!(outer["result"], json!(1));
    let inner = &outer["children"][0];
    assert_eq!(inner["arguments"]["token"], json!(MASK));
    assert_eq!(inner["truncated"], json!(true));
    assert!(bytes < 3 * STEP_CAP_BYTES);

    let (full, _, _) = prepare_log(log, true);
    assert_eq!(full["logs"][0]["arguments"]["value"].as_str().unwrap().len(), big.len());
    assert_eq!(full["logs"][0]["arguments"]["secret"], json!(MASK), "full mode still masks");
    assert!(full["logs"][0].get("truncated").is_none());
}

#[test]
fn the_whole_log_is_capped_even_in_full_mode() {
    let entries: Vec<Value> = (0..300).map(|i| entry(&format!("s{i}"), json!({"v": "b".repeat(8 * 1024)}), Value::Null)).collect();
    let mut log = log_of(entries, 0);
    log["definitions"] = json!({"Ns.f": {"big": "c".repeat(1000)}});
    for full in [false, true] {
        let (stored, steps, bytes) = prepare_log(log.clone(), full);
        assert_eq!(steps, 300);
        assert!(bytes <= LOG_CAP_BYTES, "{bytes}");
        assert_eq!(bytes, serde_json::to_string(&stored).unwrap().len());
        assert_eq!(stored["truncated"], json!(true));
        assert!(stored.get("definitions").is_none());
        let kept = stored["logs"].as_array().unwrap().len();
        assert!(kept > 100 && kept < 300, "{kept}");
    }
    let small = log_of(vec![entry("a", json!({}), json!({}))], 0);
    let (stored, _, _) = prepare_log(small, false);
    assert!(stored.get("truncated").is_none());
    assert!(stored.get("definitions").is_some());
}

// ------------------------------------------------------------------ rollover and expiry

#[tokio::test]
async fn keeps_the_newest_hundred_per_client_and_function() {
    let (dao, s) = service();
    let start = now_ms() - 10_000_000;
    s.store(info("FIN", "f", "d"), log_of(vec![], start), false).await.unwrap();
    s.store(info("FIN", "g", "d"), log_of(vec![], start), false).await.unwrap();
    for i in 0..105 {
        s.store(info("SYSTEM", "f", &format!("d{i}")), log_of(vec![], start + i * 1000), false).await.unwrap();
    }
    let rows = dao.rows();
    let mine: Vec<_> = rows.iter().filter(|r| r.client_code == "SYSTEM").collect();
    assert_eq!(mine.len(), KEEP_PER_FUNCTION as usize);
    assert!(mine.iter().all(|r| r.debug_id != "d0" && r.debug_id != "d4"));
    assert!(mine.iter().any(|r| r.debug_id == "d104"));
    assert_eq!(rows.iter().filter(|r| r.client_code == "FIN").count(), 2, "another client's and another function's rows are untouched");
}

#[tokio::test]
async fn expired_rows_go_at_insert_and_in_the_sweep() {
    let (dao, s) = service();
    let old = now_ms() - (RETENTION_DAYS + 1) * 86_400_000;
    let old_at = chrono::DateTime::from_timestamp_millis(old).unwrap().naive_utc();
    for (client, d) in [("SYSTEM", "old"), ("FIN", "old-fin")] {
        let row = DebugRun { debug_id: d.into(), app_code: APP.into(), client_code: client.into(), namespace: "Ns".into(), name: "f".into(),
                             started_at: old_at, ..Default::default() };
        dao.insert(&row).await.unwrap();
    }
    s.store(info("SYSTEM", "f", "new"), log_of(vec![], now_ms()), false).await.unwrap();
    let ids: Vec<String> = dao.rows().into_iter().map(|r| r.debug_id).collect();
    assert_eq!(ids, vec!["old-fin".to_string(), "new".to_string()]);
    assert_eq!(s.cleanup_older_than(1, 10).await.unwrap(), 1, "never younger than the retention");
    assert_eq!(dao.rows().len(), 1);
}

#[tokio::test]
async fn the_row_describes_the_run() {
    let (dao, s) = service();
    let start = now_ms();
    let mut log = log_of(vec![entry("a", json!({"password": "p"}), json!({"x": 1}))], start);
    log["errored"] = json!(true);
    let mut i = info("FIN", "f", "full-abc");
    i.draft = true;
    let id = s.store(i, log, true).await.unwrap();
    let r = dao.read(id).await.unwrap().unwrap();
    assert!(r.errored && r.draft);
    assert_eq!(r.step_count, 1);
    assert_eq!(r.duration_ms, Some(5));
    assert_eq!(r.log.as_ref().unwrap()["logs"][0]["arguments"]["password"], json!(MASK));
    assert_eq!(r.log_bytes as usize, serde_json::to_string(r.log.as_ref().unwrap()).unwrap().len());
    let j = r.to_json(true);
    for k in ["id", "debugId", "appCode", "clientCode", "namespace", "name", "userId", "userName", "draft", "errored", "stepCount", "startedAt",
              "finishedAt", "durationMs", "logBytes", "log"] {
        assert!(j.get(k).is_some(), "{k}");
    }
    assert!(r.to_json(false).get("log").is_none());
}

#[test]
fn the_display_name_falls_back_to_the_user_name() {
    assert_eq!(display_name(&editor()).as_deref(), Some("tester"));
    let named = crate::testing::auth(
        json!({"user": {"id": 1, "userName": "u1", "firstName": "Kay", "lastName": " Gee ", "stringAuthorities": []}, "authenticated": true, "clientCode": "SYSTEM"}),
        Some("SYSTEM"),
        None,
    );
    assert_eq!(display_name(&named).as_deref(), Some("Kay Gee"));
}

#[test]
fn only_function_editors_with_a_debug_id_are_stored() {
    assert!(FunctionDebugRunService::wanted(&editor(), Some("abc")));
    assert!(!FunctionDebugRunService::wanted(&editor(), None));
    assert!(!FunctionDebugRunService::wanted(&editor(), Some("  ")));
    assert!(!FunctionDebugRunService::wanted(&crate::testing::user(&["Authorities.Function_READ"]), Some("abc")));
    assert!(!FunctionDebugRunService::wanted(&Authentication::default(), Some("abc")));
}

// ------------------------------------------------------------------ reading

#[tokio::test]
async fn access_is_own_client_or_a_managed_one() {
    let (_, s) = service();
    let fin = s.store(info("FIN", "f", "d1"), log_of(vec![], now_ms()), false).await.unwrap();
    let sys = s.store(info("SYSTEM", "f", "d2"), log_of(vec![], now_ms()), false).await.unwrap();
    let other = s.store(info("OTHER", "f", "d3"), log_of(vec![], now_ms()), false).await.unwrap();

    // SYSTEM reads its own, FIN (managed), not OTHER.
    assert_eq!(s.read(&editor(), sys).await.unwrap().client_code, "SYSTEM");
    assert_eq!(s.read(&editor(), fin).await.unwrap().client_code, "FIN");
    assert_eq!(s.read(&editor(), other).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(s.read(&editor(), 999).await.unwrap_err().status(), StatusCode::NOT_FOUND);
    // FIN reads only its own.
    assert_eq!(s.read(&fin_editor(), fin).await.unwrap().client_code, "FIN");
    assert_eq!(s.read(&fin_editor(), sys).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    // No authority: refused.
    let reader = crate::testing::user(&["Authorities.Function_READ"]);
    assert_eq!(s.read(&reader, sys).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(s.read_page(&reader, filter(None), None, &page()).await.unwrap_err().status(), StatusCode::FORBIDDEN);

    let p = s.read_page(&editor(), filter(Some("f")), None, &page()).await.unwrap();
    assert_eq!(p["totalElements"], json!(1));
    assert_eq!(p["content"][0]["clientCode"], json!("SYSTEM"));
    assert!(p["content"][0].get("log").is_none());
    let own = s.read_page(&editor(), filter(Some("f")), Some("SYSTEM"), &page()).await.unwrap();
    assert_eq!(own["content"][0]["debugId"], json!("d2"), "the caller's own code is the same as none");
    assert_eq!(own["content"][0]["userName"], json!("Test User"));
    let p = s.read_page(&editor(), filter(Some("f")), Some("FIN"), &page()).await.unwrap();
    assert_eq!(p["content"][0]["debugId"], json!("d1"));
    assert_eq!(s.read_page(&editor(), filter(None), Some("OTHER"), &page()).await.unwrap_err().status(), StatusCode::FORBIDDEN);
    assert_eq!(s.days(&fin_editor(), filter(None), Some("SYSTEM")).await.unwrap_err().status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pages_newest_first_and_filter_by_day_and_debug_id() {
    let (_, s) = service();
    let today = now_ms();
    let yesterday = today - 86_400_000;
    for (i, (t, failed)) in [(yesterday, true), (today - 2000, false), (today - 1000, true), (yesterday + 10, false)].iter().enumerate() {
        let mut inf = info("SYSTEM", "f", &format!("d{i}"));
        inf.failed = *failed;
        s.store(inf, log_of(vec![], *t), false).await.unwrap();
    }
    let p = s.read_page(&editor(), filter(Some("f")), None, &page()).await.unwrap();
    let ids: Vec<&str> = p["content"].as_array().unwrap().iter().map(|r| r["debugId"].as_str().unwrap()).collect();
    assert_eq!(ids, ["d2", "d1", "d3", "d0"]);
    assert_eq!(p["totalElements"], json!(4));

    let day = |ms: i64| chrono::DateTime::from_timestamp_millis(ms).unwrap().date_naive();
    let mut f = filter(Some("f"));
    f.day = Some(day(yesterday));
    let p = s.read_page(&editor(), f, None, &page()).await.unwrap();
    assert_eq!(p["totalElements"], json!(2));
    let mut f = filter(Some("f"));
    f.debug_id = Some("d1".into());
    assert_eq!(s.read_page(&editor(), f, None, &page()).await.unwrap()["content"][0]["debugId"], json!("d1"));

    let days = s.days(&editor(), filter(Some("f")), None).await.unwrap();
    // The two "today" runs may straddle midnight only if the test runs at 00:00:01 UTC.
    if day(today - 2000) == day(today) {
        assert_eq!(days, vec![
            DayCount { day: day(today), runs: 2, errored: 1 },
            DayCount { day: day(yesterday), runs: 2, errored: 1 },
        ]);
        assert_eq!(days[0].to_json(), json!({"day": day(today).format("%Y-%m-%d").to_string(), "runs": 2, "errored": 1}));
    }
    assert!(s.days(&editor(), filter(Some("nothing")), None).await.unwrap().is_empty());
    let _ = NaiveDate::from_ymd_opt(2026, 1, 1);
    let _ = TimeDelta::days(1);
}

// ------------------------------------------------------------------ the collector

#[test]
fn nested_definition_logs_go_under_their_steps() {
    let c = DebugCollector::get_instance();
    c.enable();
    let top = format!("dbgtest{}", now_ms());
    c.start_execution(&top, "Ns.outer", Some(json!({"name": "outer"})));
    let s1 = c.start_step(&top, "callInner", "Ns.inner", Some(json!({"apiKey": "k"})), None).unwrap();
    let nested = format!("{top}_callInner");
    c.start_execution(&nested, "Ns.inner", Some(json!({"name": "inner"})));
    let s2 = c.start_step(&nested, "make", "System.Make", Some(json!({"v": 1})), None).unwrap();
    c.end_step(&nested, &s2, "output", Some(json!({"v": 1})), Some("boom"));
    c.end_execution(&nested);
    c.end_step(&top, &s1, "output", Some(json!({})), None);
    c.end_execution(&top);

    let (log, errored) = collect_execution(&top).unwrap();
    assert!(errored, "an error in a nested call marks the run");
    assert_eq!(log["executionId"], json!(top));
    let step = &log["logs"][0];
    assert_eq!(step["statementName"], json!("callInner"));
    assert_eq!(step["children"][0]["statementName"], json!("make"));
    assert_eq!(step["children"][0]["error"], json!("boom"));
    assert!(log["definitions"].get("Ns.inner").is_some());
    for k in ["startTime", "endTime", "errored", "logs"] {
        assert!(log.get(k).is_some(), "{k}");
    }
    let (stored, steps, _) = prepare_log(log, false);
    assert_eq!(steps, 2);
    assert_eq!(stored["logs"][0]["arguments"]["apiKey"], json!(MASK));
    assert!(collect_execution("no-such-execution").is_none());
}
