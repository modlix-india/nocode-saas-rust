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
        "sources": {
            "cases": {"kind": "STORAGE", "storage": "cxCase", "label": "Cases", "scope": "REQUIRED",
                "fields": {
                    "productId": {"kind": "DIMENSION", "label": "Project", "lookup": {"source": "products", "key": "_id", "label": "name"}},
                    "assignedUserId": {"kind": "DIMENSION", "label": "RM", "lookup": {"type": "USER"}},
                    "status": {"kind": "DIMENSION", "label": "Status", "lookup": {"values": {"OPEN": "Open", "CLOSED": "Closed"}}},
                    "stageGroup": {"kind": "DIMENSION", "label": "Stage"},
                    "bookedAt": {"kind": "DATE", "label": "Booked on", "stringDate": true},
                    "agreementValue": {"kind": "MEASURE", "label": "Agreement value", "format": "MONEY", "currencyField": "currency",
                                       "fns": ["SUM", "AVG", "MIN", "MAX"], "authority": "Authorities.CXZUMP.ROLE_Report_READ"},
                    "paidAmount": {"kind": "MEASURE", "label": "Paid", "format": "MONEY", "currencyField": "payCurrency"},
                    "customerEmail": {"kind": "DIMENSION", "label": "Email", "pii": true}},
                "segments": {"bookings": {"label": "Bookings", "condition": {"field": "milestone", "operator": "EQUALS", "value": "BOOKED"}},
                             "eois": {"label": "EOIs", "dateField": "eoiAt", "condition": {"field": "milestones", "operator": "MATCH", "matchOperator": "EQUALS", "value": "EOI_PAID"}},
                             "converted": {"label": "Converted", "condition": {"field": "milestones", "operator": "MATCH", "matchOperator": "EQUALS", "value": "EOI_CONVERTED"}}}},
            "products": {"kind": "STORAGE", "storage": "cxProduct", "label": "Projects", "lookupOnly": true, "scope": "REQUIRED", "fields": {"name": {"label": "Name"}}},
            "fixedCases": {"kind": "STORAGE", "storage": "cxCase", "label": "Cases", "scope": "REQUIRED",
                "fields": {"agreementValue": {"kind": "MEASURE", "label": "Agreement value", "format": "MONEY", "currency": "INR"},
                           "assignedUserId": {"kind": "DIMENSION", "label": "RM"}}},
            "tasks": {"kind": "FUNCTION", "function": "CxZump.moneySummary", "resultPath": "page.content", "totalPath": "page.total", "label": "My tasks",
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

    #[tokio::test]
    async fn view_types_answer_the_rule_table() {
        let mut out = ViewTypes::default().internal_execute(&kirun::Map::new()).await.unwrap();
        let r = out.next().unwrap().get_result()["result"].clone();
        assert_eq!(r["types"].as_array().unwrap().len(), shape::VIEW_RULES.len());
        assert_eq!(ViewTypes::default().signature().get_full_name(), "CoreServices.Report.ViewTypes");
        assert_eq!(ReportFunction::validate(Arc::new(Fake::default())).get_signature().get_full_name(), "CoreServices.Report.Validate");
    }
}
