//! CoreServices.Report tests: validation codes, periods, ISO text buckets, the financial year,
//! derived measures, caps and "Other", the currency split, the cache, lists, function sources,
//! and a run through a KIRun definition.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{NaiveDate, TimeZone, Utc};
use parking_lot::Mutex;
use serde_json::{json, Value};

use super::exec::{self, FunctionCaller, ReportBackend, RunRequest};
use super::period::{self, Bucket, Zone};
use super::spec::{self, Catalog, Obj};
use super::*;

#[derive(Default)]
struct Fake {
    aggregates: Mutex<Vec<Value>>,
    reads: Mutex<Vec<(String, Value)>>,
    answers: Mutex<VecDeque<Vec<Obj>>>,
    read_answers: Mutex<HashMap<String, Vec<Obj>>>,
    records: Mutex<Vec<(String, Value)>>,
    total: i64,
    users: HashMap<u64, String>,
    cache: Mutex<HashMap<String, String>>,
    claims: Mutex<HashSet<String>>,
    fail: bool,
}

fn rows(v: Value) -> Vec<Obj> {
    v.as_array().unwrap().iter().map(|r| r.as_object().unwrap().clone()).collect()
}

impl Fake {
    fn answering(answers: Vec<Value>) -> Fake {
        Fake { answers: Mutex::new(answers.into_iter().map(rows).collect()), ..Default::default() }
    }
}

#[async_trait]
impl ReportBackend for Fake {
    async fn aggregate(&self, _: Option<&str>, _: Option<&str>, _: &str, query: &Value) -> Result<Vec<Obj>, String> {
        if self.fail {
            return Err("the storage is down".into());
        }
        self.aggregates.lock().push(query.clone());
        Ok(self.answers.lock().pop_front().unwrap_or_default())
    }
    async fn read_page(&self, _: Option<&str>, _: Option<&str>, storage: &str, query: &Value) -> Result<Vec<Obj>, String> {
        self.reads.lock().push((storage.to_string(), query.clone()));
        Ok(self.read_answers.lock().get(storage).cloned().unwrap_or_default())
    }
    async fn read_records(&self, _: Option<&str>, _: Option<&str>, storage: &str, query: &Value) -> Result<(Vec<Obj>, i64), String> {
        self.records.lock().push((storage.to_string(), query.clone()));
        let found = self.read_answers.lock().get(storage).cloned().unwrap_or_default();
        let total = if self.total > 0 { self.total } else { found.len() as i64 };
        Ok((found, total))
    }
    async fn user_names(&self, ids: &[u64]) -> Result<HashMap<u64, String>, String> {
        Ok(ids.iter().filter_map(|i| self.users.get(i).map(|n| (*i, n.clone()))).collect())
    }
    async fn cache_get(&self, key: &str) -> Option<String> {
        self.cache.lock().get(key).cloned()
    }
    async fn cache_put(&self, key: &str, value: &str, _: u64) {
        self.cache.lock().insert(key.to_string(), value.to_string());
    }
    async fn claim(&self, key: &str, _: u64) -> Option<bool> {
        Some(self.claims.lock().insert(key.to_string()))
    }
}

struct Functions(Value);

#[async_trait]
impl FunctionCaller for Functions {
    async fn call(&self, full_name: &str, args: Obj) -> Result<Obj, String> {
        if full_name != "CxZump.moneySummary" {
            return Err(format!("no {full_name}"));
        }
        let mut out = self.0.as_object().unwrap().clone();
        out.insert("args".into(), Value::Object(args));
        Ok(out)
    }
}

fn catalog() -> Value {
    json!({"v": 1, "app": "cxzump", "timeZone": "Asia/Kolkata", "locale": "en-IN", "fyStartMonth": 4,
        "hierarchies": {"stage": {"label": "Stage", "levels": ["stageGroup", "status"]}},
        "groups": {"dashboard": {"label": "Dashboard", "order": 1}, "money": {"label": "Money", "order": 2, "authorityAny": ["Authorities.CXZUMP.ROLE_Report_READ"]}},
        "defaults": [{"id": "totalBookings", "name": "Total bookings", "group": "dashboard", "spec": {}, "countLink": {"path": "/cases?dash=BOOKING"}},
                     {"id": "noGroup", "name": "No group (= dashboard)", "spec": {}}],
        "sources": {
            "cases": {"kind": "STORAGE", "storage": "cxCase", "label": "Cases", "scope": "REQUIRED",
                "fields": {
                    "productId": {"kind": "DIMENSION", "label": "Project", "lookup": {"source": "products", "key": "_id", "label": "name"}},
                    "assignedUserId": {"kind": "DIMENSION", "label": "RM", "lookup": {"type": "USER"}},
                    "status": {"kind": "DIMENSION", "label": "Status", "lookup": {"values": {"OPEN": "Open", "CLOSED": "Closed"}}},
                    "stageGroup": {"kind": "DIMENSION", "label": "Stage"},
                    "caseNo": {"kind": "DIMENSION", "label": "Case no"},
                    "bookedAt": {"kind": "DATE", "label": "Booked on", "stringDate": true},
                    "agreementValue": {"kind": "MEASURE", "label": "Agreement value", "format": "MONEY", "currencyField": "currency",
                                       "fns": ["SUM", "AVG", "MIN", "MAX"], "authority": "Authorities.CXZUMP.ROLE_Report_READ"},
                    "paidAmount": {"kind": "MEASURE", "label": "Paid", "format": "MONEY", "currencyField": "payCurrency"},
                    "customerEmail": {"kind": "DIMENSION", "label": "Email", "pii": true}},
                "link": {"path": "/caseView/{_id}"}, "moreLink": {"path": "/cases", "label": "View all"},
                "records": {"fields": ["caseNo", "status", "productId", "customerEmail", "agreementValue", "assignedUserId", "gone"],
                            "sort": [{"by": "bookedAt", "dir": "DESC"}], "link": {"path": "/caseView/{_id}"},
                            "authorityAny": ["Authorities.CXZUMP.ROLE_Case_READ", "Authorities.CXZUMP.ROLE_Case_READ_ASSIGNED"]},
                "segments": {"bookings": {"label": "Bookings", "condition": {"field": "milestone", "operator": "EQUALS", "value": "BOOKED"},
                                          "countLink": {"path": "/cases?dash=BOOKING&product={filter.productId}&from={period.from}&to={period.to}"}},
                             "eois": {"label": "EOIs", "dateField": "eoiAt", "condition": {"field": "milestones", "operator": "MATCH", "matchOperator": "EQUALS", "value": "EOI_PAID"}},
                             "converted": {"label": "Converted", "condition": {"field": "milestones", "operator": "MATCH", "matchOperator": "EQUALS", "value": "EOI_CONVERTED"}}}},
            "products": {"kind": "STORAGE", "storage": "cxProduct", "label": "Projects", "lookupOnly": true, "scope": "REQUIRED", "fields": {"name": {"label": "Name"}}},
            "fixedCases": {"kind": "STORAGE", "storage": "cxCase", "label": "Cases", "scope": "REQUIRED",
                "fields": {"agreementValue": {"kind": "MEASURE", "label": "Agreement value", "format": "MONEY", "currency": "INR"},
                           "assignedUserId": {"kind": "DIMENSION", "label": "RM"}}},
            "tasks": {"kind": "FUNCTION", "function": "CxZump.moneySummary", "resultPath": "page.content", "totalPath": "page.total", "label": "My tasks",
                "link": {"path": "/caseView/{caseId}"}, "moreLink": {"path": "/approvals", "label": "View all"}, "paging": {"param": "page", "size": 20},
                "params": {"mine": true, "page": 0}, "allowedParams": ["page"],
                "columns": {"title": {"kind": "DIMENSION", "label": "Task"},
                            "caseId": {"kind": "DIMENSION", "label": "Case", "labelMapPath": "caseNumbers"},
                            "_id": {"kind": "DIMENSION", "hidden": true}}},
            "moneySummary": {"kind": "FUNCTION", "function": "CxZump.moneySummary", "resultPath": "summary", "label": "Money",
                "columns": {"collected": {"kind": "MEASURE", "label": "Collected", "format": "MONEY"},
                            "pending": {"kind": "MEASURE", "label": "Pending", "format": "MONEY"}},
                "params": {"productId": ""}}}})
}

const REPORT: &str = "Authorities.CXZUMP.ROLE_Report_READ";

fn now() -> chrono::DateTime<Utc> {
    // 17 Nov 2026, 10:00 in Kolkata.
    Utc.with_ymd_and_hms(2026, 11, 17, 4, 30, 0).unwrap()
}

fn scope() -> Value {
    json!({"field": "productId", "operator": "IN", "multiValue": ["P1", "P2"]})
}

async fn go(spec: Value, auths: &[&str], backend: &Fake, dry: bool, force: bool, scope: Value) -> Value {
    let auths: Vec<String> = auths.iter().map(|s| s.to_string()).collect();
    let cat = catalog();
    exec::run(
        RunRequest {
            spec: &spec,
            catalog: &cat,
            scope: &scope,
            force,
            dry_run: dry,
            app_code: None,
            client_code: Some("FIN".into()),
            user_id: 7,
            authorities: &auths,
            now: now(),
        },
        backend,
        &Functions(json!({"summary": {"collected": 1500.5, "pending": 200}})),
    )
    .await
}

async fn code_of(spec: Value, auths: &[&str]) -> (String, String) {
    let out = go(spec, auths, &Fake::default(), true, false, scope()).await;
    assert_eq!(out["ok"], json!(false), "{out}");
    (out["error"]["code"].as_str().unwrap().to_string(), out["error"]["path"].as_str().unwrap().to_string())
}

fn sales() -> Value {
    json!({"v": 1, "source": "cases", "segment": "bookings",
        "measures": [{"fn": "COUNT", "as": "bookings"}, {"fn": "SUM", "field": "agreementValue", "as": "value"}],
        "derived": [{"as": "avgTicket", "ratio": ["value", "bookings"]}],
        "groupBy": [{"field": "assignedUserId", "as": "rm"}],
        "filters": [{"field": "productId", "op": "IN", "values": ["P1"]}, {"field": "bookedAt", "period": "THIS_QUARTER"}],
        "sort": [{"by": "value", "dir": "DESC"}], "limit": 10,
        "view": {"type": "BAR", "x": "rm", "y": ["bookings", "value"], "title": "Sales performance", "style": {"legend": "top", "palette": "_primary"}}})
}

#[tokio::test]
async fn every_validation_code() {
    let with = |patch: Value| {
        let mut s = sales();
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                s.as_object_mut().unwrap().remove(k);
            } else {
                s[k] = v.clone();
            }
        }
        s
    };
    let r = &[REPORT];
    assert_eq!(code_of(with(json!({"source": "nope"})), r).await, ("UNKNOWN_SOURCE".into(), "source".into()));
    assert_eq!(code_of(with(json!({"segment": "nope"})), r).await.0, "UNKNOWN_SEGMENT");
    assert_eq!(code_of(with(json!({"groupBy": [{"field": "tower"}]})), r).await, ("UNKNOWN_FIELD".into(), "groupBy[0].field".into()));
    assert_eq!(code_of(with(json!({"groupBy": [{"field": "stageGroup", "bucket": "MONTH"}]})), r).await, ("BAD_KIND".into(), "groupBy[0].bucket".into()));
    assert_eq!(code_of(with(json!({"groupBy": [{"field": "agreementValue"}]})), r).await.0, "BAD_KIND");
    assert_eq!(code_of(with(json!({"measures": [{"fn": "COUNT_DISTINCT", "field": "agreementValue", "as": "x"}], "derived": null})), r).await.0, "FN_NOT_ALLOWED");
    assert_eq!(code_of(with(json!({"measures": [{"fn": "SUM", "field": "stageGroup", "as": "x"}], "derived": null})), r).await.0, "FN_NOT_ALLOWED");
    assert_eq!(code_of(with(json!({"measures": [{"fn": "MEDIAN", "as": "x"}], "derived": null})), r).await.0, "FN_NOT_ALLOWED");
    // The money field needs Report_READ: without it, refused by name.
    assert_eq!(code_of(sales(), &[]).await, ("FORBIDDEN_FIELD".into(), "measures[1].field".into()));
    assert_eq!(code_of(with(json!({"groupBy": [{"field": "customerEmail"}]})), r).await, ("PII_GROUP".into(), "groupBy[0].field".into()));
    let four = json!([{"fn": "COUNT", "as": "a"}, {"fn": "COUNT", "as": "b"}, {"fn": "COUNT", "as": "c"}, {"fn": "COUNT", "as": "d"}]);
    assert_eq!(code_of(with(json!({"measures": four})), r).await, ("TOO_MANY".into(), "measures".into()));
    let nine: Vec<Value> = (0..9).map(|_| json!({"field": "status", "op": "EQ", "value": "OPEN"})).collect();
    assert_eq!(code_of(with(json!({"filters": nine})), r).await.0, "TOO_MANY");
    assert_eq!(code_of(with(json!({"groupBy": [{"field": "status"}, {"field": "stageGroup"}, {"field": "productId"}]})), r).await.0, "TOO_MANY");
    assert_eq!(code_of(with(json!({"view": {"type": "KPI"}})), r).await, ("BAD_VIEW".into(), "view.type".into()));
    assert_eq!(code_of(with(json!({"view": {"type": "PIE", "x": "nope"}})), r).await, ("BAD_VIEW".into(), "view.x".into()));
    assert_eq!(code_of(with(json!({"filters": [{"field": "bookedAt", "period": "NEXT_YEAR"}]})), r).await, ("BAD_PERIOD".into(), "filters[0].period".into()));
    assert_eq!(code_of(with(json!({"filters": [{"field": "bookedAt", "period": "CUSTOM", "from": "2026-12-01", "to": "2026-11-01"}]})), r).await.0, "BAD_PERIOD");
    assert_eq!(code_of(with(json!({"filters": [{"field": "bookedAt", "period": "CUSTOM", "from": "2026-12-01"}]})), r).await.0, "BAD_PERIOD");
    assert_eq!(code_of(with(json!({"filters": [{"field": "status", "period": "TODAY"}]})), r).await.0, "BAD_KIND");
    assert_eq!(code_of(with(json!({"filters": [{"field": "status", "op": "LIKE", "value": "%"}]})), r).await.0, "BAD_KIND");
    assert_eq!(code_of(with(json!({"filters": [{"field": "status", "op": "EQ", "value": {"x": 1}}]})), r).await.0, "BAD_KIND");
    assert_eq!(code_of(with(json!({"sort": [{"by": "nope"}]})), r).await, ("UNKNOWN_FIELD".into(), "sort[0].by".into()));
    assert_eq!(code_of(with(json!({"derived": [{"as": "x", "ratio": ["value", "nope"]}]})), r).await.0, "UNKNOWN_FIELD");
    assert_eq!(code_of(with(json!({"measures": [{"fn": "COUNT", "as": "a b"}], "derived": null, "sort": null})), r).await.0, "BAD_KIND");
    let mixed = json!([{"fn": "SUM", "field": "agreementValue", "as": "v"}, {"fn": "SUM", "field": "paidAmount", "as": "p"}]);
    assert_eq!(code_of(with(json!({"measures": mixed, "derived": null, "sort": null})), r).await.0, "MIXED_CURRENCY");

    // Scope is required for the source: null is refused, {} (everything) is not.
    let out = go(sales(), r, &Fake::default(), true, false, Value::Null).await;
    assert_eq!(out["error"]["code"], json!("SCOPE_REQUIRED"));
    let out = go(sales(), r, &Fake::default(), true, false, json!({})).await;
    assert_eq!(out["ok"], json!(true), "{out}");
}

#[tokio::test]
async fn a_dry_run_reads_nothing_and_predicts_the_columns() {
    let fake = Fake::default();
    let out = go(sales(), &[REPORT], &fake, true, false, scope()).await;
    assert_eq!(out["ok"], json!(true));
    assert_eq!(out["dryRun"], json!(true));
    assert!(fake.aggregates.lock().is_empty());
    let keys: Vec<&str> = out["columns"].as_array().unwrap().iter().map(|c| c["key"].as_str().unwrap()).collect();
    assert_eq!(keys, ["rm", "rm_label", "bookings", "value", "avgTicket"]);
    assert_eq!(out["columns"][2]["label"], json!("Bookings"), "COUNT is named after the segment");
    assert_eq!(out["columns"][3]["format"], json!("MONEY"));
    assert_eq!(out["columns"][4]["format"], json!("MONEY"), "money per booking is money");
    assert_eq!(out["period"], json!({"from": "2026-10-01", "to": "2026-12-31", "label": "This quarter"}));
    assert_eq!(out["fits"]["BAR"], json!({"ok": true}));
    assert_eq!(out["fits"]["KPI"]["ok"], json!(false));
    assert_eq!(out["view"]["style"], json!({"legend": "top", "palette": "_primary"}), "style is passed through untouched");
}

#[test]
fn periods_in_the_catalog_zone_and_financial_year() {
    let z = Zone::parse("Asia/Kolkata").unwrap();
    // 20:00 UTC on the 16th is already the 17th in Kolkata.
    assert_eq!(z.today(Utc.with_ymd_and_hms(2026, 11, 16, 20, 0, 0).unwrap()), NaiveDate::from_ymd_opt(2026, 11, 17).unwrap());
    assert_eq!(period::mysql_offset(z.offset_at(now())), "+05:30");
    assert_eq!(Zone::parse("-08:00").map(|z| period::mysql_offset(z.offset_at(now()))), Some("-08:00".into()));
    assert!(Zone::parse("Mars/Base").is_none());
    let d = NaiveDate::from_ymd_opt(2026, 11, 17).unwrap();
    let r = |name: &str| period::resolve(name, d, 4, None).unwrap().to_json();
    assert_eq!(r("THIS_QUARTER"), json!({"from": "2026-10-01", "to": "2026-12-31", "label": "This quarter"}));
    assert_eq!(r("LAST_QUARTER")["from"], json!("2026-07-01"));
    assert_eq!(r("THIS_FY"), json!({"from": "2026-04-01", "to": "2027-03-31", "label": "This FY"}));
    assert_eq!(r("LAST_FY")["to"], json!("2026-03-31"));
    assert_eq!(r("THIS_WEEK")["from"], json!("2026-11-16"), "weeks start on Monday");
    assert_eq!(r("LAST_12_MONTHS"), json!({"from": "2025-12-01", "to": "2026-11-30", "label": "Last 12 months"}));
    assert_eq!(r("LAST_30_DAYS")["from"], json!("2026-10-19"));
    assert_eq!(r("ALL_TIME")["from"], Value::Null);
    // A calendar year catalog: quarters on calendar months.
    assert_eq!(period::resolve("THIS_FY", d, 1, None).unwrap().to_json()["from"], json!("2026-01-01"));
    assert!(period::resolve("CUSTOM", d, 4, None).is_err());
    assert!(period::resolve("CUSTOM", d, 4, Some(("2026-13-01", "2026-12-01"))).is_err());
    assert_eq!(period::resolve("CUSTOM", d, 4, Some(("2026-11-01", "2026-11-17T10:00:00Z"))).unwrap().label, "1 Nov 2026 to 17 Nov 2026");
}

#[test]
fn financial_year_buckets_and_labels() {
    let d = |y, m, day| NaiveDate::from_ymd_opt(y, m, day).unwrap();
    assert_eq!(Bucket::Quarter.start(d(2026, 11, 17), 4), d(2026, 10, 1));
    assert_eq!(Bucket::Quarter.start(d(2027, 2, 1), 4), d(2027, 1, 1));
    assert_eq!(Bucket::Year.start(d(2027, 2, 1), 4), d(2026, 4, 1));
    assert_eq!(Bucket::Quarter.label(d(2026, 10, 1), true, 4), "Q3 FY27", "an FY is named by the year it ends in");
    assert_eq!(Bucket::Quarter.label(d(2026, 4, 1), true, 4), "Q1 FY27");
    assert_eq!(Bucket::Year.label(d(2026, 4, 1), true, 4), "FY27");
    assert_eq!(Bucket::Quarter.label(d(2026, 10, 1), false, 1), "Q4 2026");
    assert_eq!(Bucket::Month.label(d(2026, 11, 1), false, 1), "Nov 2026");
    assert_eq!(Bucket::Day.label(d(2026, 11, 17), false, 1), "17 Nov");
}

#[test]
fn string_date_periods_and_buckets_need_no_zone_tables() {
    let cat = Catalog::parse(&catalog()).unwrap();
    let caller = spec::Caller { authorities: &[REPORT.to_string()], now: now() };
    let mut s = sales();
    s["groupBy"] = json!([{"field": "bookedAt", "bucket": "QUARTER", "fy": true, "as": "q"}]);
    s["view"] = json!({"type": "LINE"});
    s["sort"] = json!([]);
    let plan = spec::validate(&s, &cat, &scope(), &caller).unwrap();
    // segment AND product filter AND the period AND the scope.
    let conds = plan.condition["conditions"].as_array().unwrap();
    assert_eq!(conds.len(), 4);
    assert_eq!(conds[0]["field"], json!("milestone"));
    assert_eq!(conds[3], scope());
    let period = &conds[2];
    assert_eq!(period["operator"], json!("OR"));
    // A bare local date compares with the local dates; an instant with the UTC bounds.
    assert_eq!(period["conditions"][0]["conditions"][1]["value"], json!("2026-10-01"));
    assert_eq!(period["conditions"][0]["conditions"][2]["value"], json!("2026-12-31"));
    assert_eq!(period["conditions"][1]["conditions"][1]["value"], json!("2026-09-30T18:30:00"));
    assert_eq!(period["conditions"][1]["conditions"][2], json!({"field": "bookedAt", "operator": "LESS_THAN", "value": "2026-12-31T18:30:00"}));

    let q = exec::aggregate_query(&plan, &cat, now(), None);
    assert_eq!(q["groupBy"][0], json!({"field": "bookedAt", "alias": "q", "bucket": "QUARTER", "timezone": "+05:30", "isoString": true, "yearStartMonth": 4}));
    assert_eq!(q["sort"], json!([{"property": "q", "direction": "ASC"}]), "a time series reads in time order");
    // It reads as an AggregateQuery with the Rust-only options.
    let aq = appdata::model::AggregateQuery::from_value(&crate::storage::values::storage_value(&q)).unwrap();
    let g = &aq.group_by.as_ref().unwrap()[0];
    assert!(g.iso_string);
    assert_eq!(g.year_shift_months(), 3);
    assert_eq!(g.timezone.as_deref(), Some("+05:30"));
}

/// Keep only / drill on a date bucket sends a CUSTOM period with from / to (the UI's way).
#[test]
fn custom_periods_on_iso_text() {
    let cat = Catalog::parse(&catalog()).unwrap();
    let caller = spec::Caller { authorities: &[], now: now() };
    let s = json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}], "view": {"type": "KPI"},
                   "filters": [{"field": "bookedAt", "period": "CUSTOM", "from": "2026-11-01", "to": "2026-11-30"}]});
    let plan = spec::validate(&s, &cat, &json!({}), &caller).unwrap();
    assert_eq!(plan.period.as_ref().unwrap().to_json(), json!({"from": "2026-11-01", "to": "2026-11-30", "label": "1 Nov 2026 to 30 Nov 2026"}));
    let c = &plan.condition;
    assert_eq!(c["conditions"][0]["conditions"][1]["value"], json!("2026-11-01"));
    assert_eq!(c["conditions"][1]["conditions"][1]["value"], json!("2026-10-31T18:30:00"));
    assert_eq!(c["conditions"][1]["conditions"][2]["value"], json!("2026-11-30T18:30:00"));
}

#[tokio::test]
async fn sales_by_rm_with_labels_derived_cache_and_force() {
    let mut fake = Fake::answering(vec![
        json!([{"currency": "INR", "n": 5}]),
        json!([{"rm": 11, "bookings": 2, "value": 9000000.0}, {"rm": 12, "bookings": 0, "value": null}, {"rm": 13, "bookings": 3, "value": 15000000.0}]),
    ]);
    fake.users = HashMap::from([(11, "Asha Rao".to_string()), (13, "Vikram".to_string())]);
    let out = go(sales(), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let aggs = fake.aggregates.lock().clone();
    assert_eq!(aggs.len(), 2, "the currency probe, then the report");
    assert_eq!(aggs[0]["groupBy"], json!([{"field": "currency", "alias": "currency"}]));
    assert_eq!(aggs[1]["groupBy"], json!([{"field": "assignedUserId", "alias": "rm"}]));
    assert_eq!(aggs[1]["aggregations"], json!([{"function": "COUNT", "alias": "bookings"}, {"function": "SUM", "field": "agreementValue", "alias": "value"}]));
    assert_eq!(out["columns"][3]["currency"], json!("INR"));
    assert_eq!(out["currencySplit"], json!(false));
    let r = out["rows"].as_array().unwrap();
    // Sorted by value, nulls last; labels from security, a missing name is the key.
    assert_eq!(r.iter().map(|r| r["rm_label"].clone()).collect::<Vec<_>>(), [json!("Vikram"), json!("Asha Rao"), json!("12")]);
    assert_eq!(r[0]["avgTicket"], json!(5000000));
    assert_eq!(r[2]["avgTicket"], Value::Null, "a ratio over zero is null");
    assert_eq!(out["cached"], json!(false));
    assert!(out["refreshedAt"].as_str().unwrap().ends_with('Z'));

    // The second run is the cached copy.
    let again = go(sales(), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(again["cached"], json!(true));
    assert_eq!(again["rows"], out["rows"]);
    assert_eq!(fake.aggregates.lock().len(), 2);
    // Another scope is another key.
    fake.answers.lock().extend([rows(json!([])), rows(json!([]))]);
    let other = go(sales(), &[REPORT], &fake, false, false, json!({"field": "productId", "operator": "EQUALS", "value": "P9"})).await;
    assert_eq!(other["cached"], json!(false));
    assert_eq!(fake.aggregates.lock().len(), 4);
    // force: the first forced run reads again, a second within 10 s is served from the cache.
    fake.answers.lock().extend([rows(json!([{"currency": "INR", "n": 1}])), rows(json!([{"rm": 11, "bookings": 9, "value": 1.0}]))]);
    let forced = go(sales(), &[REPORT], &fake, false, true, scope()).await;
    assert_eq!(forced["cached"], json!(false));
    assert_eq!(forced["rows"][0]["bookings"], json!(9));
    let forced_again = go(sales(), &[REPORT], &fake, false, true, scope()).await;
    assert_eq!(forced_again["cached"], json!(true));
    assert_eq!(fake.aggregates.lock().len(), 6);
}

#[tokio::test]
async fn mixed_currencies_are_grouped_not_summed() {
    let fake = Fake::answering(vec![
        json!([{"currency": "INR", "n": 5}, {"currency": "AED", "n": 2}]),
        json!([{"rm": 11, "currency": "INR", "bookings": 2, "value": 900.0}, {"rm": 11, "currency": "AED", "bookings": 1, "value": 50.0}]),
    ]);
    let out = go(sales(), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["currencySplit"], json!(true));
    let aggs = fake.aggregates.lock().clone();
    assert_eq!(aggs[1]["groupBy"][1], json!({"field": "currency", "alias": "currency"}));
    let keys: Vec<&str> = out["columns"].as_array().unwrap().iter().map(|c| c["key"].as_str().unwrap()).collect();
    assert_eq!(keys, ["rm", "rm_label", "currency", "bookings", "value", "avgTicket"]);
    assert_eq!(out["columns"][4]["currency"], Value::Null);
    assert_eq!(out["rows"].as_array().unwrap().len(), 2);

    // A filter that pins one currency skips the probe and the split.
    let fake = Fake::answering(vec![json!([{"rm": 11, "bookings": 2, "value": 900.0}])]);
    let mut s = sales();
    s["filters"].as_array_mut().unwrap().push(json!({"field": "currency", "op": "EQ", "value": "AED"}));
    let out = go(s, &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(fake.aggregates.lock().len(), 1);
    assert_eq!(out["columns"][3]["currency"], json!("AED"));
}

#[tokio::test]
async fn monthly_buckets_on_iso_text_are_local_and_filled() {
    let fake = Fake::answering(vec![json!([{"month": "2026-09-30T18:30:00Z", "bookings": 3}, {"month": "2026-11-30T18:30:00Z", "bookings": 1}])]);
    let spec = json!({"source": "cases", "segment": "bookings", "measures": [{"fn": "COUNT", "as": "bookings"}],
        "groupBy": [{"field": "bookedAt", "bucket": "MONTH", "as": "month"}],
        "filters": [{"field": "bookedAt", "period": "THIS_QUARTER"}], "view": {"type": "LINE"}});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let r = out["rows"].as_array().unwrap();
    assert_eq!(
        r.iter().map(|r| (r["month"].clone(), r["month_label"].clone(), r["bookings"].clone())).collect::<Vec<_>>(),
        [
            (json!("2026-10-01"), json!("Oct 2026"), json!(3)),
            (json!("2026-11-01"), json!("Nov 2026"), json!(0)),
            (json!("2026-12-01"), json!("Dec 2026"), json!(1)),
        ]
    );
    assert_eq!(out["columns"][0], json!({"key": "month", "label": "Booked on", "kind": "DATE", "bucket": "MONTH", "fy": false}));
}

fn spec_by(field: &str, ty: &str) -> Value {
    json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}, {"fn": "MAX", "field": "agreementValue", "as": "top"}],
           "groupBy": [{"field": field, "as": "k"}], "view": {"type": ty}})
}

#[tokio::test]
async fn chart_groups_cap_at_50_with_other_and_tables_at_500() {
    let many: Vec<Value> = (0..60).map(|i| json!({"k": format!("S{i:02}"), "n": 100 - i, "top": i})).collect();
    let fake = Fake::answering(vec![json!([{"currency": "INR", "n": 1}]), Value::Array(many.clone())]);
    let out = go(spec_by("stageGroup", "BAR"), &[REPORT], &fake, false, false, scope()).await;
    let r = out["rows"].as_array().unwrap();
    assert_eq!(r.len(), 51);
    let other = &r[50];
    assert_eq!(other["k"], json!(exec::OTHER_KEY));
    assert_eq!(other["_other"], json!(true));
    assert_eq!(other["n"], json!((50..60).map(|i| 100 - i).sum::<i64>()), "counts are added");
    assert_eq!(other["top"], json!(59), "MAX takes the largest");
    assert_eq!(out["truncated"], json!(false), "summed, not dropped");

    // topN from the style.
    let fake = Fake::answering(vec![json!([{"currency": "INR", "n": 1}]), Value::Array(many.clone())]);
    let mut s = spec_by("stageGroup", "PIE");
    s["view"]["style"] = json!({"topN": 5});
    let out = go(s, &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["rows"].as_array().unwrap().len(), 6);

    // A lookup dimension's Other is labelled "Other".
    let fake = Fake::answering(vec![json!([{"currency": "INR", "n": 1}]), Value::Array(many.clone())]);
    let mut s = spec_by("status", "PIE");
    s["view"]["style"] = json!({"topN": 2});
    let out = go(s, &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["rows"][2]["k_label"], json!("Other"));

    // A table keeps 500 rows; the spec's limit comes first.
    let rows600: Vec<Value> = (0..600).map(|i| json!({"k": format!("S{i:03}"), "n": i, "top": 1})).collect();
    let fake = Fake::answering(vec![json!([]), Value::Array(rows600.clone())]);
    let out = go(spec_by("stageGroup", "TABLE"), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["rows"].as_array().unwrap().len(), 500);
    assert_eq!(out["truncated"], json!(true));
    let fake = Fake::answering(vec![json!([]), Value::Array(rows600)]);
    let mut s = spec_by("stageGroup", "TABLE");
    s["limit"] = json!(7);
    let out = go(s, &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["rows"].as_array().unwrap().len(), 7);
    assert_eq!(out["truncated"], json!(false));
}

#[test]
fn derived_measures() {
    let cat = Catalog::parse(&catalog()).unwrap();
    let caller = spec::Caller { authorities: &[REPORT.to_string()], now: now() };
    let s = json!({"source": "cases", "measures": [{"fn": "SUM", "field": "agreementValue", "as": "a"}, {"fn": "COUNT", "as": "b"}],
        "derived": [{"as": "r", "ratio": ["a", "b"]}, {"as": "d", "difference": ["a", "b"]}, {"as": "p", "percent": ["b", "a"]}], "view": {"type": "KPI"}});
    let plan = spec::validate(&s, &cat, &json!({}), &caller).unwrap();
    assert_eq!(plan.derived.iter().map(|d| d.format.as_str()).collect::<Vec<_>>(), ["MONEY", "MONEY", "PERCENT"]);
    let mut r = rows(json!([{"a": 50.0, "b": 4}, {"a": null, "b": 0}, {"a": 10, "b": null}]));
    exec::apply_derived(&plan, &mut r);
    assert_eq!((r[0]["r"].clone(), r[0]["d"].clone(), r[0]["p"].clone()), (json!(12.5), json!(46), json!(8)));
    assert_eq!((r[1]["r"].clone(), r[1]["d"].clone(), r[1]["p"].clone()), (Value::Null, json!(0), Value::Null));
    assert_eq!((r[2]["r"].clone(), r[2]["d"].clone()), (Value::Null, json!(10)));
    // KPI shows every derived measure too: 3 measures + derived is still one row.
    assert_eq!(plan.shape, shape::Shape { group_by: 0, values: 5 });
}

#[tokio::test]
async fn lists_read_a_page_without_personal_data() {
    let fake = Fake::default();
    fake.read_answers.lock().insert(
        "cxCase".into(),
        rows(json!([{"_id": "C1", "status": "OPEN", "stageGroup": "Booking", "customerEmail": "a@b.c", "productId": "P1", "assignedUserId": 11}])),
    );
    fake.read_answers.lock().insert("cxProduct".into(), rows(json!([{"_id": "P1", "name": "Tower A"}])));
    let spec = json!({"source": "cases", "view": {"type": "LIST"}, "fields": ["status", "productId", "stageGroup"],
                      "sort": [{"by": "status", "dir": "DESC"}], "limit": 5});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let reads = fake.reads.lock().clone();
    assert_eq!(reads[0].0, "cxCase");
    assert_eq!(reads[0].1["size"], json!(6));
    assert_eq!(reads[0].1["sort"], json!([{"property": "status", "direction": "DESC"}]));
    assert_eq!(reads[0].1["condition"], scope());
    assert_eq!(reads[1].0, "cxProduct", "the project names in one read");
    assert_eq!(reads[1].1["condition"], json!({"field": "_id", "operator": "IN", "multiValue": ["P1"]}));
    let row = &out["rows"][0];
    assert_eq!(row["_id"], json!("C1"));
    assert_eq!(row["status_label"], json!("Open"));
    assert_eq!(row["productId_label"], json!("Tower A"));
    assert!(row.get("customerEmail").is_none());
    assert_eq!(out["shape"]["records"], json!(true));

    // Asking for personal data in a list is refused; the default fields leave it out.
    assert_eq!(code_of(json!({"source": "cases", "view": {"type": "LIST"}, "fields": ["customerEmail"]}), &[]).await.0, "PII_GROUP");
    let out = go(json!({"source": "cases", "view": {"type": "LIST"}}), &[], &Fake::default(), true, false, scope()).await;
    let keys: Vec<&str> = out["columns"].as_array().unwrap().iter().map(|c| c["key"].as_str().unwrap()).collect();
    assert!(!keys.contains(&"customerEmail") && !keys.contains(&"agreementValue"), "{keys:?}");
}

#[tokio::test]
async fn function_sources_map_the_declared_columns() {
    let fake = Fake::default();
    let spec = json!({"source": "moneySummary", "params": {"productId": "P1"}, "view": {"type": "KPI"}});
    let out = go(spec, &[], &fake, false, false, Value::Null).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["rows"], json!([{"collected": 1500.5, "pending": 200}]));
    assert_eq!(out["columns"][0], json!({"key": "collected", "label": "Collected", "kind": "MEASURE", "format": "MONEY", "currency": null}));
    assert_eq!(code_of(json!({"source": "moneySummary", "params": {"x": 1}}), &[]).await, ("UNKNOWN_FIELD".into(), "params.x".into()));
    assert_eq!(code_of(json!({"source": "moneySummary", "measures": [{"fn": "COUNT"}]}), &[]).await.0, "BAD_KIND");
    assert_eq!(code_of(json!({"source": "moneySummary", "view": {"type": "PIE"}}), &[]).await.0, "BAD_VIEW");
}

#[tokio::test]
async fn a_failing_source_is_an_answer_not_an_error() {
    let fake = Fake { fail: true, ..Default::default() };
    let out = go(sales(), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(false));
    assert_eq!(out["error"]["code"], json!("SOURCE_FAILED"));
    assert!(out["error"]["message"].as_str().unwrap().contains("the storage is down"));
    assert!(fake.cache.lock().is_empty(), "refusals are not cached");
}

#[test]
fn display_names() {
    assert_eq!(display_name(&json!({"firstName": "Asha", "lastName": " Rao "})), Some("Asha Rao".into()));
    assert_eq!(display_name(&json!({"firstName": "", "userName": "asha", "emailId": "a@b.c"})), Some("asha".into()));
    assert_eq!(display_name(&json!({"emailId": "NONE"})), None);
}

#[tokio::test]
async fn a_measure_with_its_own_segment_counts_only_those_rows() {
    // EOI conversion: EOIs, and of them the converted ones, in one report.
    let fake = Fake::answering(vec![
        json!([{"rm": 11, "eois": 10}, {"rm": 12, "eois": 4}]),
        json!([{"rm": 11, "converted": 3}]),
    ]);
    let spec = json!({"source": "cases", "segment": "eois",
        "measures": [{"fn": "COUNT", "as": "eois"}, {"fn": "COUNT", "segment": "converted", "as": "converted"}],
        "derived": [{"as": "rate", "percent": ["converted", "eois"]}],
        "groupBy": [{"field": "assignedUserId", "as": "rm"}], "view": {"type": "BAR"}});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let aggs = fake.aggregates.lock().clone();
    assert_eq!(aggs.len(), 2);
    assert_eq!(aggs[0]["aggregations"], json!([{"function": "COUNT", "alias": "eois"}]));
    assert_eq!(aggs[1]["aggregations"], json!([{"function": "COUNT", "alias": "converted"}]));
    // The segment measure's query is the report's condition AND its own segment.
    assert_eq!(aggs[1]["condition"]["conditions"][0], aggs[0]["condition"]);
    assert_eq!(aggs[1]["condition"]["conditions"][1]["value"], json!("EOI_CONVERTED"));
    let r = out["rows"].as_array().unwrap();
    assert_eq!((r[0]["converted"].clone(), r[0]["rate"].clone()), (json!(3), json!(30)));
    assert_eq!((r[1]["converted"].clone(), r[1]["rate"].clone()), (json!(0), json!(0)), "a group with none is 0, not 100%");
    assert_eq!(out["columns"][3]["label"], json!("Converted"));
    assert_eq!(out["columns"][3]["segment"], json!("converted"));

    // A KPI where every measure has a segment: a hidden row count keeps the groups.
    let fake = Fake::answering(vec![json!([{"_rows": 20}]), json!([{"c": 5}])]);
    let spec = json!({"source": "cases", "measures": [{"fn": "COUNT", "segment": "converted", "as": "c"}], "view": {"type": "KPI"}});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["rows"], json!([{"c": 5}]));
    assert_eq!(fake.aggregates.lock()[0]["aggregations"], json!([{"function": "COUNT", "alias": "_rows"}]));

    assert_eq!(
        code_of(json!({"source": "cases", "measures": [{"fn": "COUNT", "segment": "nope", "as": "c"}], "view": {"type": "KPI"}}), &[]).await,
        ("UNKNOWN_SEGMENT".into(), "measures[0].segment".into())
    );
}

#[tokio::test]
async fn unknown_keys_are_refused_never_ignored() {
    let k = |spec: Value| async move { code_of(spec, &[]).await };
    assert_eq!(
        k(json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "c", "segmnt": "x"}], "view": {"type": "KPI"}})).await,
        ("BAD_KIND".into(), "measures[0].segmnt".into())
    );
    assert_eq!(
        k(json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "c"}], "filters": [{"field": "status", "value": "OPEN", "negate": true}], "view": {"type": "KPI"}})).await.1,
        "filters[0].negate"
    );
    assert_eq!(
        k(json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "c"}], "groupBy": [{"field": "status", "alias": "s"}], "view": {"type": "BAR"}})).await.1,
        "groupBy[0].alias"
    );
    // A lookup-only source is not a report source.
    assert_eq!(k(json!({"source": "products", "view": {"type": "LIST"}})).await.0, "UNKNOWN_SOURCE");
}

#[tokio::test]
async fn a_fixed_currency_is_one_currency() {
    let fake = Fake::answering(vec![json!([{"rm": 1, "value": 10.0}])]);
    let spec = json!({"source": "fixedCases", "measures": [{"fn": "SUM", "field": "agreementValue", "as": "value"}],
                      "groupBy": [{"field": "assignedUserId", "as": "rm"}], "view": {"type": "BAR"}});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(fake.aggregates.lock().len(), 1, "no currency probe");
    assert_eq!(out["columns"][1]["currency"], json!("INR"));
    assert_eq!(out["currencySplit"], json!(false));
}

#[tokio::test]
async fn function_sources_take_only_allowed_params_and_keep_hidden_columns() {
    struct Tasks;
    #[async_trait]
    impl FunctionCaller for Tasks {
        async fn call(&self, _: &str, args: Obj) -> Result<Obj, String> {
            assert_eq!(Value::Object(args), json!({"mine": true, "page": 2}), "fixed params plus the allowed one");
            Ok(json!({"page": {"content": [{"_id": "T1", "title": "Call back", "caseId": "C9"}], "total": 41}, "caseNumbers": {"C9": "CX-9"}})
                .as_object().unwrap().clone())
        }
    }
    let cat = catalog();
    let spec = json!({"source": "tasks", "params": {"page": 2}, "view": {"type": "TABLE"}});
    let out = exec::run(
        RunRequest { spec: &spec, catalog: &cat, scope: &Value::Null, force: false, dry_run: false, app_code: None, client_code: None,
                     user_id: 1, authorities: &[], now: now() },
        &Fake::default(),
        &Tasks,
    )
    .await;
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["rows"][0]["caseId_label"], json!("CX-9"));
    assert_eq!(out["total"], json!(41));
    let cols = out["columns"].as_array().unwrap();
    assert!(cols.contains(&json!({"key": "_id", "hidden": true})));
    assert!(cols.contains(&json!({"key": "caseId_label", "hidden": true})));
    assert_eq!(out["shape"]["groupBy"], json!(2), "the hidden id is not part of the shape");
    assert_eq!(out["fits"]["BAR"]["ok"], json!(false));
    // A fixed param that is not allowed cannot be set by a spec.
    assert_eq!(code_of(json!({"source": "tasks", "params": {"mine": false}}), &[]).await, ("UNKNOWN_FIELD".into(), "params.mine".into()));
}

// --- P1b: catalog keys, View records, compare, PDF ---------------------------------------------

const CASE_READ: &str = "Authorities.CXZUMP.ROLE_Case_READ";

fn with_source_key(path: &str, v: Value) -> Value {
    let mut c = catalog();
    let (parent, key) = path.rsplit_once('/').unwrap();
    let slot = c.pointer_mut(parent).unwrap();
    match slot {
        Value::Array(a) => a[key.parse::<usize>().unwrap()] = v,
        other => {
            other[key] = v;
        }
    }
    c
}

async fn go_with(cat: Value, spec: Value, auths: &[&str], backend: &Fake) -> Value {
    let auths: Vec<String> = auths.iter().map(|s| s.to_string()).collect();
    exec::run(
        RunRequest { spec: &spec, catalog: &cat, scope: &scope(), force: false, dry_run: false, app_code: None, client_code: None,
                     user_id: 7, authorities: &auths, now: now() },
        backend,
        &Functions(json!({"summary": {"collected": 1, "pending": 2}})),
    )
    .await
}

#[tokio::test]
async fn catalog_groups_are_accepted_and_only_their_shape_is_checked() {
    let kpi = json!({"source": "cases", "segment": "bookings", "measures": [{"fn": "COUNT", "as": "bookings"}], "view": {"type": "KPI"}});
    // The fixture carries groups and grouped defaults: a run is unaffected.
    let out = go_with(catalog(), kpi.clone(), &[], &Fake::answering(vec![json!([{"bookings": 4}])])).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    // No groups at all: any default group id is fine (the app's own name).
    let mut cat = catalog();
    cat.as_object_mut().unwrap().remove("groups");
    cat["defaults"][0]["group"] = json!("anything");
    let out = go_with(cat, kpi.clone(), &[], &Fake::answering(vec![json!([{"bookings": 4}])])).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    // groups: null is the same as none.
    let out = go_with(with_source_key("/groups", Value::Null), kpi, &[], &Fake::answering(vec![json!([{"bookings": 4}])])).await;
    assert_eq!(out["ok"], json!(true), "{out}");
}

#[tokio::test]
async fn catalog_links_paging_and_hierarchies_are_accepted_and_passed_through() {
    let fake = Fake::answering(vec![json!([{"bookings": 4}])]);
    let spec = json!({"source": "cases", "segment": "bookings", "measures": [{"fn": "COUNT", "as": "bookings"}], "view": {"type": "KPI"}});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["links"]["row"], json!({"path": "/caseView/{_id}"}));
    assert_eq!(out["links"]["more"], json!({"path": "/cases", "label": "View all"}));
    assert_eq!(out["links"]["count"]["path"], json!("/cases?dash=BOOKING&product={filter.productId}&from={period.from}&to={period.to}"));
    // A function source passes its paging and links on.
    let out = go(json!({"source": "tasks", "view": {"type": "TABLE"}}), &[], &Fake::default(), true, false, Value::Null).await;
    assert_eq!(out["paging"], json!({"param": "page", "size": 20}), "{out}");
    assert_eq!(out["links"]["row"], json!({"path": "/caseView/{caseId}"}));

    // Shapes are checked: a bad one is the catalog's error, named by path.
    let kpi = json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}], "view": {"type": "KPI"}});
    for (path, bad, at) in [
        ("/sources/cases/link", json!({"path": "https://evil.example/x"}), "catalog.sources.cases.link.path"),
        ("/sources/cases/link", json!({"path": "//evil.example/x"}), "catalog.sources.cases.link.path"),
        ("/sources/cases/link", json!({"path": "/x", "target": "_blank"}), "catalog.sources.cases.link.target"),
        ("/sources/cases/moreLink", json!("/cases"), "catalog.sources.cases.moreLink"),
        ("/sources/cases/paging", json!({"param": "page", "size": 0}), "catalog.sources.cases.paging.size"),
        ("/sources/cases/records/fields", json!([]), "catalog.sources.cases.records.fields"),
        ("/sources/cases/records/sort", json!([{"by": "nope"}]), "catalog.sources.cases.records.sort[0].by"),
        ("/sources/cases/records/authorityAny", json!("x"), "catalog.sources.cases.records.authorityAny"),
        ("/sources/cases/segments/bookings/countLink", json!({"label": "x"}), "catalog.sources.cases.segments.bookings.countLink.path"),
        ("/hierarchies/stage/levels", json!(["stageGroup"]), "catalog.hierarchies.stage.levels"),
        ("/hierarchies/stage/levels", json!(["status", "status"]), "catalog.hierarchies.stage.levels"),
        ("/hierarchies/stage", json!({"levels": ["a", "b"], "lvl": 1}), "catalog.hierarchies.stage.lvl"),
        ("/defaults/0/countLink", json!({"path": "cases"}), "catalog.defaults[0].countLink.path"),
        ("/groups", json!(["dashboard"]), "catalog.groups"),
        ("/groups/u_mine", json!({"label": "Mine"}), "catalog.groups.u_mine"),
        ("/groups/dashboard", json!("Dashboard"), "catalog.groups.dashboard"),
        ("/groups/dashboard", json!({"order": 1}), "catalog.groups.dashboard.label"),
        ("/groups/dashboard", json!({"label": " "}), "catalog.groups.dashboard.label"),
        ("/groups/dashboard", json!({"label": "x".repeat(41)}), "catalog.groups.dashboard.label"),
        ("/groups/dashboard", json!({"label": "Dashboard", "order": "1"}), "catalog.groups.dashboard.order"),
        ("/groups/dashboard", json!({"label": "Dashboard", "authorityAny": "x"}), "catalog.groups.dashboard.authorityAny"),
        ("/groups/dashboard", json!({"label": "Dashboard", "icon": "x"}), "catalog.groups.dashboard.icon"),
        ("/defaults/0/group", json!(3), "catalog.defaults[0].group"),
        ("/defaults/0/group", json!(""), "catalog.defaults[0].group"),
        ("/defaults/0/group", json!("nowhere"), "catalog.defaults[0].group"),
    ] {
        let out = go_with(with_source_key(path, bad.clone()), kpi.clone(), &[], &Fake::default()).await;
        assert_eq!((out["error"]["code"].as_str(), out["error"]["path"].as_str()), (Some("SOURCE_FAILED"), Some(at)), "{path} {bad}: {out}");
    }
}

fn records_spec(page: Value) -> Value {
    json!({"v": 1, "source": "cases", "segment": "bookings",
           "filters": [{"field": "productId", "op": "IN", "values": ["P1"]}, {"field": "bookedAt", "period": "THIS_QUARTER"}],
           "records": page})
}

#[tokio::test]
async fn records_read_one_page_of_the_listed_fields_in_scope() {
    let mut fake = Fake { total: 241, ..Default::default() };
    fake.users = HashMap::from([(11, "Asha Rao".to_string())]);
    fake.read_answers.lock().insert(
        "cxCase".into(),
        rows(json!([{"_id": "C1", "caseNo": "CX-1", "status": "OPEN", "productId": "P1", "customerEmail": "a@b.c", "agreementValue": 900,
                     "assignedUserId": 11, "stageGroup": "Booking", "secret": "x"}])),
    );
    fake.read_answers.lock().insert("cxProduct".into(), rows(json!([{"_id": "P1", "name": "Tower A"}])));
    let out = go(records_spec(json!({"page": 2, "size": 20})), &[CASE_READ], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let (storage, q) = fake.records.lock()[0].clone();
    assert_eq!(storage, "cxCase");
    // segment AND filters AND scope, one page, the default sort, only the listed columns.
    let conds = q["condition"]["conditions"].as_array().unwrap();
    assert_eq!(conds.len(), 4);
    assert_eq!(conds[0]["value"], json!("BOOKED"));
    assert_eq!(conds[3], scope());
    assert_eq!((q["page"].clone(), q["size"].clone()), (json!(2), json!(20)));
    assert_eq!(q["sort"], json!([{"property": "bookedAt", "direction": "DESC"}]));
    assert_eq!(q["fields"], json!(["caseNo", "status", "productId", "customerEmail", "assignedUserId"]), "agreementValue needs Report_READ; 'gone' is not a field");
    let row = out["rows"][0].as_object().unwrap();
    let mut keys: Vec<&str> = row.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["_id", "assignedUserId", "assignedUserId_label", "caseNo", "customerEmail", "productId", "productId_label", "status", "status_label"]);
    assert_eq!(row["productId_label"], json!("Tower A"));
    assert_eq!(row["assignedUserId_label"], json!("Asha Rao"));
    assert_eq!(row["customerEmail"], json!("a@b.c"), "personal data only because records lists it");
    assert_eq!((out["total"].clone(), out["page"].clone(), out["size"].clone()), (json!(241), json!(2), json!(20)));
    assert_eq!(out["truncated"], json!(true), "more pages after this one");
    assert_eq!(out["links"]["row"], json!({"path": "/caseView/{_id}"}));
    assert_eq!(out["period"]["from"], json!("2026-10-01"));
    let email = out["columns"].as_array().unwrap().iter().find(|c| c["key"] == "customerEmail").unwrap().clone();
    assert_eq!(email, json!({"key": "customerEmail", "label": "Email", "kind": "DIMENSION", "pii": true}));
    assert_eq!(out["columns"][0], json!({"key": "_id", "hidden": true}));

    // With Report_READ the money field comes too; a spec sort replaces the catalog's.
    let fake2 = Fake::default();
    let mut s = records_spec(json!({}));
    s["sort"] = json!([{"by": "caseNo", "dir": "ASC"}]);
    let out = go(s, &[CASE_READ, REPORT], &fake2, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let q = fake2.records.lock()[0].1.clone();
    assert!(q["fields"].as_array().unwrap().contains(&json!("agreementValue")));
    assert_eq!(q["size"], json!(100), "100 a page by default");
    assert_eq!(q["sort"], json!([{"property": "caseNo", "direction": "ASC"}]));
}

#[tokio::test]
async fn records_caps_scope_and_refusals() {
    let r = &[CASE_READ];
    let refused = |spec: Value, auths: &'static [&'static str]| async move {
        let out = go(spec, auths, &Fake::default(), true, false, scope()).await;
        assert_eq!(out["ok"], json!(false), "{out}");
        (out["error"]["code"].as_str().unwrap().to_string(), out["error"]["path"].as_str().unwrap().to_string())
    };
    // The same scope rule as aggregates.
    let out = go(records_spec(json!({})), r, &Fake::default(), true, false, Value::Null).await;
    assert_eq!(out["error"]["code"], json!("SCOPE_REQUIRED"));
    // 100 a page on screen, 5000 for an export.
    assert_eq!(refused(records_spec(json!({"size": 101})), &[CASE_READ]).await, ("TOO_MANY".into(), "records.size".into()));
    assert_eq!(refused(records_spec(json!({"size": 5001, "export": true})), &[CASE_READ]).await, ("TOO_MANY".into(), "records.size".into()));
    assert_eq!(refused(records_spec(json!({"size": 0})), &[CASE_READ]).await.0, "BAD_KIND");
    assert_eq!(refused(records_spec(json!({"page": -1})), &[CASE_READ]).await.0, "BAD_KIND");
    assert_eq!(refused(records_spec(json!({"pages": 1})), &[CASE_READ]).await, ("BAD_KIND".into(), "records.pages".into()));
    assert_eq!(refused(records_spec(json!({"export": "yes"})), &[CASE_READ]).await.0, "BAD_KIND");
    // Records are their own run: no measures, group by or compare beside them.
    let mut s = records_spec(json!({}));
    s["measures"] = json!([{"fn": "COUNT"}]);
    assert_eq!(refused(s, &[CASE_READ]).await, ("BAD_KIND".into(), "measures".into()));
    // Who may see records at all, and which sources have them.
    assert_eq!(refused(records_spec(json!({})), &[REPORT]).await, ("RECORDS_NOT_ALLOWED".into(), "records".into()));
    let mut s = records_spec(json!({}));
    s["source"] = json!("fixedCases");
    s["segment"] = Value::Null;
    s["filters"] = json!([]);
    assert_eq!(refused(s, &[CASE_READ]).await.0, "RECORDS_NOT_ALLOWED");
    assert_eq!(refused(json!({"source": "moneySummary", "records": {}}), &[CASE_READ]).await.0, "RECORDS_NOT_ALLOWED");
    // A spec sort on a field the caller may not use.
    let mut s = records_spec(json!({}));
    s["sort"] = json!([{"by": "agreementValue"}]);
    assert_eq!(refused(s, &[CASE_READ]).await, ("FORBIDDEN_FIELD".into(), "sort[0].by".into()));

    // An export of 5000 is read in one page and never cached.
    let fake = Fake::default();
    let out = go(records_spec(json!({"size": 5000, "export": true})), r, &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["export"], json!(true));
    assert_eq!(fake.records.lock()[0].1["size"], json!(5000));
    assert!(fake.cache.lock().is_empty());
    // A screen page is cached like any run.
    let fake = Fake::default();
    go(records_spec(json!({"size": 50})), r, &fake, false, false, scope()).await;
    assert_eq!(fake.cache.lock().len(), 1);
}

#[test]
fn compare_periods() {
    let d = NaiveDate::from_ymd_opt(2026, 11, 17).unwrap();
    let cmp = |name: &str, to: &str, custom: Option<(&str, &str)>| {
        let p = period::resolve(name, d, 4, custom).unwrap();
        period::compare_period(&p, to).map(|c| (period::iso_date(c.range.unwrap().0), period::iso_date(c.range.unwrap().1), c.label))
    };
    let pp = "PREVIOUS_PERIOD";
    let ly = "SAME_PERIOD_LAST_YEAR";
    assert_eq!(cmp("THIS_QUARTER", pp, None).unwrap(), ("2026-07-01".into(), "2026-09-30".into(), "Previous period".into()));
    assert_eq!(cmp("THIS_QUARTER", ly, None).unwrap(), ("2025-10-01".into(), "2025-12-31".into(), "Same period last year".into()));
    // Whole months step back by months: November against all of October.
    assert_eq!(cmp("THIS_MONTH", pp, None).unwrap().0, "2026-10-01");
    assert_eq!(cmp("THIS_MONTH", pp, None).unwrap().1, "2026-10-31");
    assert_eq!(cmp("THIS_FY", pp, None).unwrap().0, "2025-04-01");
    assert_eq!(cmp("LAST_12_MONTHS", pp, None).unwrap().0, "2024-12-01");
    // Other ranges step back by their days.
    assert_eq!(cmp("LAST_7_DAYS", pp, None).unwrap(), ("2026-11-04".into(), "2026-11-10".into(), "Previous period".into()));
    assert_eq!(cmp("THIS_WEEK", pp, None).unwrap().0, "2026-11-09", "the week before, Monday to Sunday");
    assert_eq!(cmp("TODAY", pp, None).unwrap().0, "2026-11-16");
    assert_eq!(cmp("CUSTOM", pp, Some(("2026-11-05", "2026-11-14"))).unwrap(), ("2026-10-26".into(), "2026-11-04".into(), "Previous period".into()));
    // Leap days: whole months keep February whole; a single 29 February is the 28th.
    assert_eq!(cmp("CUSTOM", ly, Some(("2028-02-01", "2028-02-29"))).unwrap().1, "2027-02-28");
    assert_eq!(cmp("CUSTOM", ly, Some(("2029-02-01", "2029-02-28"))).unwrap().1, "2028-02-29");
    assert_eq!(cmp("CUSTOM", ly, Some(("2028-02-29", "2028-02-29"))).unwrap().0, "2027-02-28");
    assert!(cmp("ALL_TIME", pp, None).is_err());
    assert!(cmp("THIS_MONTH", "LAST_WEEK", None).is_err());
}

fn compare_spec(to: &str) -> Value {
    let mut s = sales();
    s["compare"] = json!({"to": to});
    s["limit"] = Value::Null;
    s
}

#[tokio::test]
async fn compare_joins_the_previous_period_on_group_keys() {
    let fake = Fake::answering(vec![
        json!([{"currency": "INR", "n": 5}]),
        json!([{"rm": 11, "bookings": 2, "value": 900.0}, {"rm": 12, "bookings": 3, "value": 600.0}, {"rm": 13, "bookings": 1, "value": 50.0}]),
        // The compare run: no currency probe (the report's currency is used).
        json!([{"rm": 11, "bookings": 1, "value": 600}, {"rm": 12, "bookings": 0, "value": 0}, {"rm": 99, "bookings": 7, "value": 1}]),
    ]);
    let out = go(compare_spec("PREVIOUS_PERIOD"), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let aggs = fake.aggregates.lock().clone();
    assert_eq!(aggs.len(), 3, "probe, report, compare");
    // The compare run's period condition is the previous quarter; everything else the same.
    let period_of = |q: &Value| q["condition"]["conditions"][2]["conditions"][0]["conditions"][1]["value"].clone();
    assert_eq!(period_of(&aggs[1]), json!("2026-10-01"));
    assert_eq!(period_of(&aggs[2]), json!("2026-07-01"));
    assert_eq!(aggs[1]["condition"]["conditions"][0], aggs[2]["condition"]["conditions"][0]);
    assert_eq!(aggs[1]["condition"]["conditions"][3], aggs[2]["condition"]["conditions"][3], "the same scope");
    assert_eq!(out["comparePeriod"], json!({"from": "2026-07-01", "to": "2026-09-30", "label": "Previous period", "compare": "PREVIOUS_PERIOD"}));
    let r = out["rows"].as_array().unwrap();
    let by = |rm: i64| r.iter().find(|x| x["rm"] == json!(rm)).unwrap().clone();
    let a = by(11);
    assert_eq!((a["value_cmp"].clone(), a["value_delta_pct"].clone()), (json!(600), json!(50)));
    assert_eq!((a["bookings_cmp"].clone(), a["bookings_delta_pct"].clone()), (json!(1), json!(100)));
    // Derived measures for both periods: 450 a booking now, 600 then.
    assert_eq!((a["avgTicket"].clone(), a["avgTicket_cmp"].clone(), a["avgTicket_delta_pct"].clone()), (json!(450), json!(600), json!(-25)));
    let b = by(12);
    assert_eq!((b["value_cmp"].clone(), b["value_delta_pct"].clone()), (json!(0), Value::Null), "a change from 0 is null");
    let c = by(13);
    assert_eq!((c["value_cmp"].clone(), c["value_delta_pct"].clone()), (Value::Null, Value::Null), "no compare row");
    assert_eq!(r.len(), 3, "a group only in the compare period is not added");
    let keys: Vec<&str> = out["columns"].as_array().unwrap().iter().map(|c| c["key"].as_str().unwrap()).collect();
    assert_eq!(keys, ["rm", "rm_label", "bookings", "value", "avgTicket", "bookings_cmp", "bookings_delta_pct", "value_cmp", "value_delta_pct", "avgTicket_cmp", "avgTicket_delta_pct"]);
    let vc = out["columns"].as_array().unwrap().iter().find(|c| c["key"] == "value_cmp").unwrap().clone();
    assert_eq!((vc["label"].clone(), vc["format"].clone(), vc["currency"].clone(), vc["compareOf"].clone()), (json!("Agreement value (previous period)"), json!("MONEY"), json!("INR"), json!("value")));
    let vd = out["columns"].as_array().unwrap().iter().find(|c| c["key"] == "value_delta_pct").unwrap().clone();
    assert_eq!(vd, json!({"key": "value_delta_pct", "label": "Agreement value change", "kind": "MEASURE", "format": "PERCENT", "deltaOf": "value"}));

    // The cache key includes the comparison: the same spec without it is another run.
    let without = go(sales(), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(without["cached"], json!(false));
    let again = go(compare_spec("PREVIOUS_PERIOD"), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(again["cached"], json!(true));
    let ly = go(compare_spec("SAME_PERIOD_LAST_YEAR"), &[REPORT], &fake, false, false, scope()).await;
    assert_eq!(ly["cached"], json!(false));
}

#[tokio::test]
async fn compare_aligns_date_buckets_by_position() {
    // This quarter by month against the same quarter last year, and against the previous quarter.
    let spec = |to: &str| {
        json!({"source": "cases", "segment": "bookings", "measures": [{"fn": "COUNT", "as": "bookings"}],
               "groupBy": [{"field": "bookedAt", "bucket": "MONTH", "as": "month"}],
               "filters": [{"field": "bookedAt", "period": "THIS_QUARTER"}], "compare": {"to": to}, "view": {"type": "LINE"}})
    };
    let fake = Fake::answering(vec![
        json!([{"month": "2026-09-30T18:30:00Z", "bookings": 3}, {"month": "2026-11-30T18:30:00Z", "bookings": 1}]),
        json!([{"month": "2025-09-30T18:30:00Z", "bookings": 6}, {"month": "2025-10-31T18:30:00Z", "bookings": 2}]),
    ]);
    let out = go(spec("SAME_PERIOD_LAST_YEAR"), &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let r = out["rows"].as_array().unwrap();
    let got: Vec<(Value, Value, Value)> = r.iter().map(|x| (x["month"].clone(), x["bookings_cmp"].clone(), x["bookings_delta_pct"].clone())).collect();
    assert_eq!(got, [(json!("2026-10-01"), json!(6), json!(-50)), (json!("2026-11-01"), json!(2), json!(-100)), (json!("2026-12-01"), json!(0), Value::Null)]);

    // The previous quarter: October meets July, by position.
    let fake = Fake::answering(vec![json!([{"month": "2026-09-30T18:30:00Z", "bookings": 4}]), json!([{"month": "2026-06-30T18:30:00Z", "bookings": 2}])]);
    let out = go(spec("PREVIOUS_PERIOD"), &[], &fake, false, false, scope()).await;
    assert_eq!(out["rows"][0]["bookings_cmp"], json!(2), "{out}");
    assert_eq!(out["rows"][0]["bookings_delta_pct"], json!(100));
    assert_eq!(out["rows"][1]["bookings_cmp"], json!(0), "August was filled with 0");
    assert_eq!(out["comparePeriod"]["from"], json!("2026-07-01"));

    // A dry run predicts the compare columns and period without reading.
    let fake = Fake::default();
    let out = go(spec("PREVIOUS_PERIOD"), &[], &fake, true, false, scope()).await;
    assert!(fake.aggregates.lock().is_empty());
    assert_eq!(out["comparePeriod"]["to"], json!("2026-09-30"));
    assert!(out["columns"].as_array().unwrap().iter().any(|c| c["key"] == "bookings_delta_pct"));
}

#[tokio::test]
async fn compare_sums_the_other_row_too() {
    let main: Vec<Value> = (0..5).map(|i| json!({"k": format!("S{i}"), "n": 10 - i})).collect();
    let prev: Vec<Value> = (0..5).map(|i| json!({"k": format!("S{i}"), "n": 2})).collect();
    let fake = Fake::answering(vec![Value::Array(main), Value::Array(prev)]);
    let spec = json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}], "groupBy": [{"field": "stageGroup", "as": "k"}],
                      "filters": [{"field": "bookedAt", "period": "THIS_MONTH"}], "compare": {"to": "PREVIOUS_PERIOD"},
                      "view": {"type": "BAR", "style": {"topN": 2}}});
    let out = go(spec, &[], &fake, false, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
    let other = out["rows"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(other["_other"], json!(true));
    assert_eq!((other["n"].clone(), other["n_cmp"].clone(), other["n_delta_pct"].clone()), (json!(8 + 7 + 6), json!(6), json!(250)));
}

#[tokio::test]
async fn compare_refusals() {
    let r = &[REPORT];
    let with_filters = |filters: Value, to: &str| {
        let mut s = compare_spec(to);
        s["filters"] = filters;
        s
    };
    let bad = |s: Value| async move { code_of(s, &[REPORT]).await };
    assert_eq!(bad(with_filters(json!([]), "PREVIOUS_PERIOD")).await, ("BAD_PERIOD".into(), "compare".into()));
    assert_eq!(bad(with_filters(json!([{"field": "bookedAt", "period": "ALL_TIME"}]), "PREVIOUS_PERIOD")).await, ("BAD_PERIOD".into(), "compare".into()));
    let two = json!([{"field": "bookedAt", "period": "THIS_FY"}, {"field": "bookedAt", "period": "THIS_QUARTER"}]);
    assert_eq!(bad(with_filters(two, "PREVIOUS_PERIOD")).await, ("BAD_PERIOD".into(), "compare".into()));
    assert_eq!(bad(compare_spec("LAST_WEEK")).await, ("BAD_PERIOD".into(), "compare.to".into()));
    let mut s = compare_spec("PREVIOUS_PERIOD");
    s["compare"] = json!({"to": "PREVIOUS_PERIOD", "shift": 1});
    assert_eq!(bad(s).await, ("BAD_KIND".into(), "compare.shift".into()));
    assert_eq!(code_of(json!({"source": "moneySummary", "compare": {"to": "PREVIOUS_PERIOD"}, "view": {"type": "KPI"}}), &[]).await.0, "BAD_PERIOD");
    // A name the comparison's columns need is refused.
    let mut s = compare_spec("PREVIOUS_PERIOD");
    s["derived"] = json!([{"as": "value_cmp", "ratio": ["value", "bookings"]}]);
    s["sort"] = Value::Null;
    s["view"] = json!({"type": "TABLE"});
    assert_eq!(bad(s).await.0, "BAD_KIND");
    let out = go(compare_spec("PREVIOUS_PERIOD"), r, &Fake::default(), true, false, scope()).await;
    assert_eq!(out["ok"], json!(true), "{out}");
}

#[tokio::test]
async fn new_view_types_through_the_runner() {
    let base = |ty: &str, groups: Value| json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}], "groupBy": groups, "view": {"type": ty}});
    let one = json!([{"field": "stageGroup", "as": "s"}]);
    let two = json!([{"field": "stageGroup", "as": "s"}, {"field": "status", "as": "t"}]);
    for (ty, g, ok) in [
        ("HEATMAP", two.clone(), true),
        ("HEATMAP", one.clone(), false),
        ("TREEMAP", one.clone(), true),
        ("TREEMAP", two.clone(), true),
        ("WATERFALL", one.clone(), true),
        ("WATERFALL", two.clone(), false),
    ] {
        let out = go(base(ty, g.clone()), &[], &Fake::default(), true, false, scope()).await;
        assert_eq!(out["ok"], json!(ok), "{ty} {g}: {out}");
        if !ok {
            assert_eq!(out["error"]["code"], json!("BAD_VIEW"));
        }
    }
    let out = go(base("BAR", one), &[], &Fake::default(), true, false, scope()).await;
    assert_eq!(out["fits"]["WATERFALL"], json!({"ok": true}));
    assert_eq!(out["fits"]["TREEMAP"], json!({"ok": true}));
    assert_eq!(out["fits"]["HEATMAP"]["ok"], json!(false));
}

mod pdf_doc {
    use super::*;
    use crate::report::pdf;

    struct Renderer(parking_lot::Mutex<Vec<String>>, Result<Vec<u8>, String>);

    #[async_trait]
    impl pdf::HtmlToPdf for Renderer {
        async fn render(&self, html: String) -> Result<Vec<u8>, String> {
            self.0.lock().push(html);
            self.1.clone()
        }
    }

    /// A 1x1 PNG.
    pub fn png() -> String {
        let bytes: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63,
            0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        use base64::Engine as _;
        format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn doc() -> Value {
        json!({"title": "Sales <dashboard> & \"more\"", "subtitle": "This quarter", "generatedAt": "2026-11-21T17:42:00+05:30", "locale": "en-IN",
               "items": [
                 {"name": "Sales by RM", "subtitle": "<b>bold</b>", "image": png(),
                  "columns": [{"key": "rm", "label": "RM", "kind": "DIMENSION"}, {"key": "rm_label", "hidden": true},
                              {"key": "value", "label": "Value", "kind": "MEASURE", "format": "MONEY", "currency": "INR"},
                              {"key": "rate", "label": "Rate", "format": "PERCENT"}],
                  "rows": [{"rm": "11", "rm_label": "Asha <script>alert(1)</script>", "value": 12345678.5, "rate": 12.345},
                           {"rm": "12", "value": null, "rate": -3}]},
                 {"name": "Plain", "columns": ["a", "b"], "rows": [["x & y", 1234567], [true, null]]},
                 {"name": "Chart only", "image": png()}]})
    }

    #[test]
    fn the_html_escapes_every_text_and_formats_numbers() {
        let d = pdf::parse(&doc()).unwrap();
        let h = pdf::html(&d, now());
        assert!(h.contains("<title>Sales &lt;dashboard&gt; &amp; &quot;more&quot;</title>"), "{h}");
        assert!(h.contains("<h1>Sales &lt;dashboard&gt; &amp; &quot;more&quot;</h1>"));
        assert!(h.contains("&lt;b&gt;bold&lt;/b&gt;"));
        assert!(!h.contains("<script>") && h.contains("Asha &lt;script&gt;alert(1)&lt;/script&gt;"), "a label is preferred and escaped");
        assert!(h.contains("Generated on 21 Nov 2026, 17:42 (UTC+05:30)"));
        assert!(h.contains("<th>RM</th>") && !h.contains("rm_label"), "hidden columns are left out");
        assert!(h.contains("INR 1,23,45,678.5"), "en-IN groups digits in pairs");
        assert!(h.contains("12.3%") && h.contains("-3%"));
        assert!(h.contains("<td class=\"num\">12,34,567</td>"));
        assert!(h.contains("x &amp; y") && h.contains(">Yes<"));
        assert_eq!(h.matches("<img ").count(), 2);
        assert!(h.contains("src=\"data:image/png;base64,iVBOR"));
        assert_eq!(pdf::file_name(&d, now()), "Sales dashboard more 2026-11-21.pdf");
        assert_eq!(pdf::group(1234567.0, 2, false), "1,234,567");
        assert_eq!(pdf::group(-0.004, 2, false), "0");
        assert_eq!(pdf::escape("a'b\u{7}"), "a&#39;b");
    }

    #[test]
    fn the_limits() {
        let code = |d: Value| pdf::parse(&d).map(|_| ()).unwrap_err();
        let items: Vec<Value> = (0..25).map(|i| json!({"name": format!("w{i}")})).collect();
        assert_eq!(code(json!({"items": items})).code, "TOO_MANY");
        let items: Vec<Value> = (0..24).map(|i| json!({"name": format!("w{i}")})).collect();
        assert!(pdf::parse(&json!({"items": items})).is_ok());
        let rows: Vec<Value> = (0..201).map(|i| json!([i])).collect();
        let e = code(json!({"items": [{"columns": ["n"], "rows": rows}]}));
        assert_eq!((e.code, e.path.as_str()), ("TOO_MANY", "document.items[0].rows"));
        let cols: Vec<Value> = (0..41).map(|i| json!(format!("c{i}"))).collect();
        assert_eq!(code(json!({"items": [{"columns": cols}]})).code, "TOO_MANY");
        let big = "x".repeat(8 * 1024 * 1024);
        assert_eq!(code(json!({"title": big})).code, "TOO_LARGE");
        // Images are PNG data URLs only.
        for bad in ["https://cdn.example.com/a.png", "data:image/jpeg;base64,/9j/4AAQ", "data:image/svg+xml;base64,PHN2Zz4=", "data:image/png;base64,PHN2Zz4=", "data:image/png;base64,\"><script>"] {
            let e = code(json!({"items": [{"image": bad}]}));
            assert_eq!((e.code, e.path.as_str()), ("BAD_KIND", "document.items[0].image"), "{bad}");
        }
        assert_eq!(code(json!({"items": [{"rows": [[1]]}]})).path, "document.items[0].columns");
        assert_eq!(code(json!({"titel": "x"})).path, "document.titel");
        assert_eq!(code(json!({"items": [{"name": "x", "chart": 1}]})).path, "document.items[0].chart");
        assert_eq!(code(json!({"title": 5})).code, "BAD_KIND");
        assert_eq!(code(json!("x")).code, "BAD_KIND");
    }

    #[tokio::test]
    async fn make_answers_a_downloadable_data_url() {
        let r = Renderer(Default::default(), Ok(b"%PDF-1.7 fake".to_vec()));
        let out = pdf::make(&doc(), now(), &r).await;
        assert_eq!(out["ok"], json!(true), "{out}");
        assert_eq!(out["fileName"], json!("Sales dashboard more 2026-11-21.pdf"));
        assert_eq!(out["contentType"], json!("application/pdf"));
        assert_eq!(out["size"], json!(13));
        assert_eq!(out["data"], json!("data:application/pdf;base64,JVBERi0xLjcgZmFrZQ=="));
        assert_eq!(out["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(r.0.lock().len(), 1);
        // A refusal renders nothing; a renderer failure is PDF_FAILED.
        let out = pdf::make(&json!({"items": [{"image": "data:image/gif;base64,R0lG"}]}), now(), &r).await;
        assert_eq!(out["error"]["code"], json!("BAD_KIND"));
        assert_eq!(r.0.lock().len(), 1);
        let failing = Renderer(Default::default(), Err("pdf-render failed: 500".into()));
        let out = pdf::make(&doc(), now(), &failing).await;
        assert_eq!(out["error"]["code"], json!("PDF_FAILED"));
        assert!(out["error"]["message"].as_str().unwrap().contains("500"));
    }

    /// One local run through a real sidecar: `PDF_RENDER_URL=http://127.0.0.1:8120 cargo test ... -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a running pdf-render: PDF_RENDER_URL (PDF_RENDER_OUT to keep the file)"]
    async fn renders_through_a_running_sidecar() {
        struct Sidecar(crate::pdf_render::PdfRenderer);
        #[async_trait]
        impl pdf::HtmlToPdf for Sidecar {
            async fn render(&self, html: String) -> Result<Vec<u8>, String> {
                self.0.render(html).await
            }
        }
        let url = std::env::var("PDF_RENDER_URL").expect("PDF_RENDER_URL is not set");
        let cfg = crate::pdf_render::PdfConfig { upstream: platform::config::UpstreamConfig::One(url), timeout_seconds: 30, fallback_on_error: false };
        let r = Sidecar(crate::pdf_render::PdfRenderer::from_config(&cfg, None).unwrap());
        let out = pdf::make(&doc(), now(), &r).await;
        assert_eq!(out["ok"], json!(true), "{out}");
        use base64::Engine as _;
        let b64 = out["data"].as_str().unwrap().strip_prefix("data:application/pdf;base64,").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert!(bytes.starts_with(b"%PDF") && !bytes.starts_with(b"%PDF-1.4"), "made by the sidecar, not the text renderer");
        if let Ok(path) = std::env::var("PDF_RENDER_OUT") {
            std::fs::write(path, &bytes).unwrap();
        }
        eprintln!("PDF {} bytes", bytes.len());
    }
}

/// A cached answer is the caller's own: the user id from the security context is in every key.
#[tokio::test]
async fn two_users_never_share_a_cached_answer() {
    struct Mine(parking_lot::Mutex<u32>);
    #[async_trait]
    impl FunctionCaller for Mine {
        async fn call(&self, _: &str, _: Obj) -> Result<Obj, String> {
            let mut n = self.0.lock();
            *n += 1;
            Ok(json!({"page": {"content": [{"_id": format!("T{n}"), "title": format!("task of call {n}"), "caseId": "C1"}], "total": 1}})
                .as_object().unwrap().clone())
        }
    }
    let cat = catalog();
    let fake = Fake::default();
    let calls = Mine(Default::default());
    let auths = vec![CASE_READ.to_string()];
    let run = |user: u64, spec: Value, scope: Value| {
        let (cat, fake, calls, auths) = (&cat, &fake, &calls, &auths);
        async move {
            exec::run(
                RunRequest { spec: &spec, catalog: cat, scope: &scope, force: false, dry_run: false, app_code: None, client_code: Some("FIN".into()),
                             user_id: user, authorities: auths, now: now() },
                fake,
                calls,
            )
            .await
        }
    };
    // A FUNCTION source (null scope): "my tasks" of user 110 is never served to user 4640.
    let tasks = json!({"source": "tasks", "view": {"type": "TABLE"}});
    let a = run(110, tasks.clone(), Value::Null).await;
    let b = run(4640, tasks.clone(), Value::Null).await;
    assert_eq!((a["cached"].clone(), b["cached"].clone()), (json!(false), json!(false)), "{b}");
    assert_ne!(a["rows"], b["rows"]);
    assert_eq!(*calls.0.lock(), 2);
    let a2 = run(110, tasks.clone(), Value::Null).await;
    assert_eq!((a2["cached"].clone(), a2["rows"].clone()), (json!(true), a["rows"].clone()), "the same user is served from the cache");
    // The same for a storage report, View records and a comparison with the same scope.
    for spec in [
        json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}], "view": {"type": "KPI"}}),
        json!({"source": "cases", "records": {}}),
        json!({"source": "cases", "measures": [{"fn": "COUNT", "as": "n"}], "filters": [{"field": "bookedAt", "period": "THIS_MONTH"}],
               "compare": {"to": "PREVIOUS_PERIOD"}, "view": {"type": "KPI"}}),
    ] {
        let x = run(110, spec.clone(), scope()).await;
        let y = run(4640, spec.clone(), scope()).await;
        assert_eq!((x["cached"].clone(), y["cached"].clone()), (json!(false), json!(false)), "{spec}: {y}");
    }
    let keys = fake.cache.lock().len();
    assert_eq!(keys, 8, "one entry per user per spec");
}

// --- Through KIRun ----------------------------------------------------------------------------

mod kirun_run {
    use std::time::Duration;

    use kirun::hybrid_repository::HybridRepository;
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository, Repository};

    use super::*;
    use crate::repos::definition::DefinitionFunction;

    struct Repo(HashMap<String, Arc<dyn Function>>);

    #[async_trait]
    impl Repository<dyn Function> for Repo {
        async fn find(&self, namespace: &str, name: &str) -> Option<Arc<dyn Function>> {
            self.0.get(&format!("{namespace}.{name}")).cloned()
        }
        async fn filter(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
    }

    fn value(v: Value) -> Value {
        json!({"one": {"key": "one", "type": "VALUE", "value": v}})
    }

    /// `Test.dash`: runs one report spec through CoreServices.Report.Run, as an app's reportRun does.
    fn dash(spec: Value, scope: Value) -> Value {
        json!({"name": "dash", "namespace": "Test",
            "events": {"output": {"name": "output", "parameters": {"report": {"type": "OBJECT"}}}},
            "steps": {
                "run": {"statementName": "run", "namespace": "CoreServices.Report", "name": "Run",
                        "parameterMap": {"spec": value(spec), "catalog": value(catalog()), "scope": value(scope)}},
                "out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                        "parameterMap": {
                            "eventName": value(json!("output")),
                            "results": value(json!({"name": "report", "value": {"isExpression": true, "value": "Steps.run.output.result"}}))}}}})
    }

    /// `CxZump.moneySummary`: a definition answering the money cards.
    fn money() -> Value {
        json!({"name": "moneySummary", "namespace": "CxZump",
            "parameters": {"productId": {"parameterName": "productId", "schema": {"type": "STRING", "defaultValue": ""}}},
            "events": {"output": {"name": "output", "parameters": {"summary": {"type": "OBJECT"}}}},
            "steps": {"out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                "parameterMap": {
                    "eventName": value(json!("output")),
                    "results": value(json!({"name": "summary", "value": {"isExpression": false, "value": {"collected": 700, "pending": 30}}}))}}}})
    }

    fn repo(backend: Arc<Fake>, extra: Vec<(&str, Value)>) -> Arc<dyn Repository<dyn Function>> {
        let b: Arc<dyn ReportBackend> = backend;
        let mut m: HashMap<String, Arc<dyn Function>> = HashMap::new();
        m.insert("CoreServices.Report.Run".into(), Arc::new(ReportFunction::run(b.clone())));
        m.insert("CoreServices.Report.Validate".into(), Arc::new(ReportFunction::validate(b)));
        for (name, def) in extra {
            m.insert(name.into(), Arc::new(DefinitionFunction::new(def, None, Some("cxzump".into()), Duration::from_secs(5)).unwrap()));
        }
        Arc::new(HybridRepository::new(vec![Arc::new(KIRunFunctionRepository::new()) as Arc<dyn Repository<dyn Function>>, Arc::new(Repo(m))]))
    }

    async fn run_def(repo: Arc<dyn Repository<dyn Function>>, def: Value) -> kirun::Result<Value> {
        let f = DefinitionFunction::new(def, None, Some("cxzump".into()), Duration::from_secs(5)).unwrap();
        let mut fep = FunctionExecutionParameters::new(repo, Arc::new(KIRunSchemaRepository::new()));
        let mut out = f.execute(&mut fep).await?;
        Ok(out.next().unwrap().get_result()["report"].clone())
    }

    #[tokio::test]
    async fn a_definition_runs_a_storage_report_and_a_function_report() {
        let ctx = crate::testing::request(crate::testing::user(&[REPORT, "Authorities.Logged_IN"]), false, None);
        crate::context::with_request(ctx, async {
            let backend = Arc::new(Fake::answering(vec![
                json!([{"currency": "INR", "n": 2}]),
                json!([{"rm": 11, "bookings": 2, "value": 900.0}]),
            ]));
            let r = repo(backend.clone(), vec![("CxZump.moneySummary", money())]);
            let report = run_def(r.clone(), dash(sales(), scope())).await.unwrap();
            assert_eq!(report["ok"], json!(true), "{report}");
            assert_eq!(report["rows"][0]["avgTicket"], json!(450));
            assert_eq!(backend.aggregates.lock().len(), 2);

            // A FUNCTION source: the catalog's function is called through the same repository.
            let report = run_def(r.clone(), dash(json!({"source": "moneySummary", "view": {"type": "KPI"}}), Value::Null)).await.unwrap();
            assert_eq!(report["rows"], json!([{"collected": 700, "pending": 30}]), "{report}");

            // A refusal comes back as the output, not as a failed step.
            let report = run_def(r, dash(sales(), Value::Null)).await.unwrap();
            assert_eq!(report["error"]["code"], json!("SCOPE_REQUIRED"));
        })
        .await;
    }

    #[tokio::test]
    async fn outside_kirun_it_is_refused() {
        let ctx = crate::testing::request(crate::testing::user(&[REPORT]), false, None);
        crate::context::with_request(ctx, async {
            let f = ReportFunction::run(Arc::new(Fake::default()));
            let args: kirun::Map<Value> = json!({"spec": sales(), "catalog": catalog(), "scope": scope()}).as_object().unwrap().clone().into_iter().collect();
            let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new())).set_arguments(args);
            let e = f.execute(&mut fep).await.err().unwrap();
            assert!(e.to_string().contains("can only be called from a server function"), "{e}");
            let raised = crate::context::request().and_then(|c| c.raised.lock().take()).unwrap();
            assert_eq!(raised.status(), axum::http::StatusCode::FORBIDDEN);
        })
        .await;
    }

    struct OkRenderer;

    #[async_trait]
    impl crate::report::pdf::HtmlToPdf for OkRenderer {
        async fn render(&self, html: String) -> Result<Vec<u8>, String> {
            assert!(html.contains("<h1>Board</h1>"));
            Ok(b"%PDF-1.7".to_vec())
        }
    }

    #[tokio::test]
    async fn pdf_runs_inside_a_definition_and_is_refused_outside() {
        let ctx = crate::testing::request(crate::testing::user(&[REPORT, "Authorities.Logged_IN"]), false, None);
        crate::context::with_request(ctx, async {
            let mut m: HashMap<String, Arc<dyn Function>> = HashMap::new();
            m.insert("CoreServices.Report.Pdf".into(), Arc::new(PdfFunction::new(Arc::new(OkRenderer))));
            let r: Arc<dyn Repository<dyn Function>> =
                Arc::new(HybridRepository::new(vec![Arc::new(KIRunFunctionRepository::new()) as Arc<dyn Repository<dyn Function>>, Arc::new(Repo(m))]));
            let def = json!({"name": "pdf", "namespace": "Test",
                "events": {"output": {"name": "output", "parameters": {"report": {"type": "OBJECT"}}}},
                "steps": {
                    "pdf": {"statementName": "pdf", "namespace": "CoreServices.Report", "name": "Pdf",
                            "parameterMap": {"document": value(json!({"title": "Board", "items": [{"name": "n", "columns": ["a"], "rows": [[1]]}]}))}},
                    "out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                            "parameterMap": {
                                "eventName": value(json!("output")),
                                "results": value(json!({"name": "report", "value": {"isExpression": true, "value": "Steps.pdf.output.result"}}))}}}});
            let out = run_def(r, def).await.unwrap();
            assert_eq!(out["ok"], json!(true), "{out}");
            assert_eq!(out["data"], json!("data:application/pdf;base64,JVBERi0xLjc="));

            let f = PdfFunction::new(Arc::new(OkRenderer));
            let args: kirun::Map<Value> = json!({"document": {"title": "Board"}}).as_object().unwrap().clone().into_iter().collect();
            let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new())).set_arguments(args);
            let e = f.execute(&mut fep).await.err().unwrap();
            assert!(e.to_string().contains("can only be called from a server function"), "{e}");
        })
        .await;
    }

    #[tokio::test]
    async fn view_types_answer_the_rule_table() {
        let mut out = ViewTypes::default().internal_execute(&kirun::Map::new()).await.unwrap();
        let r = out.next().unwrap().get_result()["result"].clone();
        assert_eq!(r["types"].as_array().unwrap().len(), shape::VIEW_RULES.len());
        assert_eq!(ViewTypes::default().signature().get_full_name(), "CoreServices.Report.ViewTypes");
        assert_eq!(ReportFunction::validate(Arc::new(Fake::default())).get_signature().get_full_name(), "CoreServices.Report.Validate");
    }
}
