//! The Rust builders against what the Java builders produced for the same inputs.
//!
//! `tests/fixtures/java_oracle.json` is written by `tools/parity_appdata/oracle/run.sh`,
//! which runs the real `MySQLFilterBuilder`, `MongoAppDataService.filter`,
//! `MySQLAggregateBuilder` and the Mongo group/project stages over
//! `java_oracle_cases.json`, and writes the drift / migration records with the services'
//! ObjectMapper settings. Every case must come out the same, or be one of the
//! differences listed in DIFFERENCES.md (checked by name here, with the reason).

use appdata::model::{AggregateQuery, Condition, Storage, StorageRelation};
use appdata::mongo::{aggregate as mongo_aggregate, filter as mongo_filter};
use appdata::mysql::aggregate_builder;
use appdata::mysql::field_resolver::FieldResolver;
use appdata::mysql::filter_builder::{self, FilterError};
use appdata::mysql::sql::{Bind, Sql};
use appdata::value::Value;
use indexmap::IndexSet;
use mongodb::bson::Bson;
use serde_json::{json, Value as Json};

fn load(name: &str) -> Json {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn set(v: &Json) -> IndexSet<String> {
    v.as_array().map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

fn bind_json(b: &Bind) -> Json {
    match b {
        Bind::Null => Json::Null,
        Bind::Bool(x) => json!(x),
        Bind::Int(i) => json!(i),
        Bind::Double(d) => json!(d),
        Bind::Float(f) => json!(*f as f64),
        Bind::Decimal(d) => serde_json::from_str(&d.to_java_string()).unwrap(),
        Bind::Text(s) => json!(s),
        Bind::DateTime(dt) => json!(dt.to_string()),
    }
}

/// Numbers compared by value, so 3 and 3.0 from two JSON writers are the same bind.
fn same_json(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number(x), Json::Number(y)) => x.as_f64() == y.as_f64() && x.is_f64() == y.is_f64(),
        (Json::Array(x), Json::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_json(p, q)),
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same_json(v, w)))
        }
        _ => a == b,
    }
}

fn render(sql: &Sql) -> (String, Vec<Json>) {
    let (text, binds) = sql.render();
    (text, binds.iter().map(bind_json).collect())
}

#[test]
fn mysql_filters_match_java() {
    let cases = load("java_oracle_cases.json");
    let expected = load("java_oracle.json");
    let mut checked = 0;
    let mut mismatches = Vec::new();

    for (case, want) in cases["mysqlFilters"].as_array().unwrap().iter().zip(expected["mysqlFilters"].as_array().unwrap()) {
        let name = case["name"].as_str().unwrap();
        assert_eq!(name, want["name"].as_str().unwrap());
        let resolver = FieldResolver::of(set(&case["json"]))
            .with_text_columns(set(&case["text"]))
            .with_stemming(case.get("stemming").and_then(Json::as_bool).unwrap_or(true));
        let cond = match Condition::from_value(&Value::from_json(&case["condition"])) {
            Ok(c) => c,
            Err(e) => {
                mismatches.push(format!("{name}: condition did not parse: {e}"));
                continue;
            }
        };
        let built = if case["mode"] == "delete" {
            filter_builder::build(cond.as_ref(), &resolver)
        } else {
            filter_builder::build_for_read(cond.as_ref(), &resolver)
        };
        checked += 1;
        match (built, want.get("error")) {
            (Ok(c), None) => {
                let (sql, binds) = render(&c.to_sql());
                let inlined = c.inlined();
                let want_binds = want["binds"].as_array().unwrap();
                if inlined != want["inlined"].as_str().unwrap()
                    || sql != want["sql"].as_str().unwrap()
                    || binds.len() != want_binds.len()
                    || !binds.iter().zip(want_binds).all(|(a, b)| same_json(a, b))
                {
                    mismatches.push(format!(
                        "{name}:\n  rust {inlined}\n  java {}\n  rust binds {binds:?}\n  java binds {want_binds:?}",
                        want["inlined"]
                    ));
                }
            }
            (Err(FilterError::Unbindable(_)), None) => {
                // Java builds and renders a list or map value and fails only when the driver
                // binds it (a 500 from the read); the Rust builder refuses it up front with the
                // same 500. DIFFERENCES.md: "list or map compared in a MySQL filter".
                let binds = want["binds"].as_array().unwrap();
                if !binds.iter().any(|b| b.is_array() || b.is_object()) {
                    mismatches.push(format!("{name}: rust refused an unbindable value java bound: {binds:?}"));
                }
            }
            (Err(e), Some(err)) => {
                let malformed = err.get("malformed").and_then(Json::as_bool);
                let same_kind = match malformed {
                    Some(m) => m == e.is_malformed() && !matches!(e, FilterError::Unbindable(_)),
                    None => false,
                };
                if !same_kind || err["detail"].as_str() != Some(e.detail()) {
                    mismatches.push(format!("{name}: rust error {e:?} / java {err}"));
                }
            }
            (Ok(c), Some(err)) => mismatches.push(format!("{name}: rust built {} but java failed {err}", c.inlined())),
            (Err(e), None) => mismatches.push(format!("{name}: rust failed {e:?} but java built {}", want["inlined"])),
        }
    }
    assert!(mismatches.is_empty(), "{} of {checked} differ:\n{}", mismatches.len(), mismatches.join("\n"));
    println!("mysql filters: {checked} cases identical to java");
}

fn storage_with(relations: &Json) -> Storage {
    let mut s = Storage { name: "s".into(), ..Default::default() };
    let mut rel = indexmap::IndexMap::new();
    for f in set(relations) {
        rel.insert(f, StorageRelation::to_one("t"));
    }
    s.relations = Some(rel);
    s
}

#[test]
fn mongo_filters_match_java() {
    let cases = load("java_oracle_cases.json");
    let expected = load("java_oracle.json");
    let mut checked = 0;
    let mut mismatches = Vec::new();

    for (case, want) in cases["mongoFilters"].as_array().unwrap().iter().zip(expected["mongoFilters"].as_array().unwrap()) {
        let name = case["name"].as_str().unwrap();
        let storage = storage_with(&case["relations"]);
        let cond = match Condition::from_value(&Value::from_json(&case["condition"])) {
            Ok(c) => c,
            Err(e) => {
                if want.get("error").is_none() {
                    mismatches.push(format!("{name}: condition did not parse: {e}"));
                }
                continue;
            }
        };
        checked += 1;
        match (mongo_filter::filter(&storage, cond.as_ref()), want.get("error")) {
            (Ok(doc), None) => {
                let got = Bson::Document(doc).into_canonical_extjson();
                if !same_json(&got, &want["bson"]) {
                    mismatches.push(format!("{name}:\n  rust {got}\n  java {}", want["bson"]));
                }
            }
            (Err(e), Some(err)) => {
                let status_ok = err.get("status").and_then(Json::as_u64).map(|s| s == e.status().as_u16() as u64);
                // An exception that is not a GenericException (an ObjectId that will not parse,
                // a null match operator) is a 500 in Java; compare the status only.
                let ok = match status_ok {
                    Some(true) => err["detail"].as_str() == Some(e.message().as_str()),
                    Some(false) => false,
                    None => e.status().as_u16() == 500,
                };
                if !ok {
                    mismatches.push(format!("{name}: rust error {} {} / java {err}", e.status(), e.message()));
                }
            }
            (Ok(doc), Some(err)) => mismatches.push(format!("{name}: rust built {doc} but java failed {err}")),
            (Err(e), None) => mismatches.push(format!("{name}: rust failed {e:?} but java built {}", want["bson"])),
        }
    }
    assert!(mismatches.is_empty(), "{} of {checked} differ:\n{}", mismatches.len(), mismatches.join("\n"));
    println!("mongo filters: {checked} cases identical to java");
}

#[test]
fn mysql_aggregates_match_java() {
    let cases = load("java_oracle_cases.json");
    let expected = load("java_oracle.json");
    let table = Sql::name(&["db", "orders"]);
    let mut mismatches = Vec::new();
    for (case, want) in cases["mysqlAggregates"].as_array().unwrap().iter().zip(expected["mysqlAggregates"].as_array().unwrap()) {
        let name = case["name"].as_str().unwrap();
        let q = AggregateQuery::from_value(&Value::from_json(&case["query"])).unwrap();
        let resolver = FieldResolver::of(set(&case["json"]));
        let where_ = filter_builder::build_for_read(q.condition.as_ref(), &resolver).unwrap();
        let having = q.having.as_ref().map(|h| filter_builder::build_json(Some(h), IndexSet::new()).unwrap());
        let page = aggregate_builder::page(&table, &q, where_.clone(), having.clone(), &q.pageable().unwrap(), &resolver)
            .unwrap()
            .to_sql()
            .inlined();
        let count = aggregate_builder::count(&table, &q, where_, having, &resolver).unwrap().to_sql().inlined();
        if page != want["page"].as_str().unwrap() {
            mismatches.push(format!("{name} page:\n  rust {page}\n  java {}", want["page"]));
        }
        if count != want["count"].as_str().unwrap() {
            mismatches.push(format!("{name} count:\n  rust {count}\n  java {}", want["count"]));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn mongo_aggregates_match_java() {
    let cases = load("java_oracle_cases.json");
    let expected = load("java_oracle.json");
    let mut mismatches = Vec::new();
    for (case, want) in cases["mongoAggregates"].as_array().unwrap().iter().zip(expected["mongoAggregates"].as_array().unwrap()) {
        let name = case["name"].as_str().unwrap();
        let q = AggregateQuery::from_value(&Value::from_json(&case["query"])).unwrap();
        let group = Bson::Document(mongo_aggregate::group_stage(&q)).into_canonical_extjson();
        let project = Bson::Document(mongo_aggregate::project_stage(&q)).into_canonical_extjson();
        if let Some(err) = want.get("error") {
            let distinct = case["query"]["aggregations"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["function"] == "COUNT_DISTINCT"))
                .and_then(|x| x["alias"].as_str());
            if let Some(alias) = distinct {
                // Java's projectStage builds `List.of("$$this", null)`, which throws, so every
                // Mongo COUNT_DISTINCT is a 500 there. Rust builds the stage Java meant.
                // DIFFERENCES.md: "Mongo COUNT_DISTINCT".
                let size = &project["$project"][alias]["$size"]["$filter"];
                if err["class"] != "NullPointerException" || size["cond"] != json!({"$ne": ["$$this", null]}) {
                    mismatches.push(format!("{name}: java {err} / rust project {project}"));
                }
            }
            // Otherwise a bucket with no encoding: the harness skips validateAggregate, which
            // stamps the encoding before the stages are built, so there is nothing to compare.
            continue;
        }
        if !same_json(&group, &want["group"]) {
            mismatches.push(format!("{name} group:\n  rust {group}\n  java {}", want["group"]));
        }
        if !same_json(&project, &want["project"]) {
            mismatches.push(format!("{name} project:\n  rust {project}\n  java {}", want["project"]));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn drift_and_migration_json_match_java() {
    use appdata::mysql::drift::{DriftRepair, Report};
    use appdata::mysql::journal::MigrationState;
    use appdata::mysql::migration::MigrationOutcome;
    use appdata::mysql::table_planner::{Kind, SchemaChange};

    let want = &load("java_oracle.json")["jsonShapes"];
    let change = |kind, column: &str, from: &str, to: Option<&str>, reason: &str, collation: Option<&str>| SchemaChange {
        kind,
        column: column.into(),
        from: Some(from.into()),
        to: to.map(Into::into),
        reason: reason.into(),
        collation: collation.map(Into::into),
    };
    let changes = vec![
        change(Kind::Destructive, "old", "VARCHAR(10)", None, "not in the definition", None),
        change(Kind::Widening, "n", "INT", Some("BIGINT"), "wider", None),
        change(Kind::Narrowing, "s", "VARCHAR(50)", Some("VARCHAR(20)"), "shorter", Some("utf8mb4_bin")),
    ];
    let report = |exists, columns: Vec<SchemaChange>, idx: &[&str], fks: &[&str]| Report {
        db: "A_app".into(),
        table: "app_t".into(),
        table_exists: exists,
        columns,
        index_statements: idx.iter().map(|s| s.to_string()).collect(),
        foreign_key_statements: fks.iter().map(|s| s.to_string()).collect(),
    };
    let repair = |missing, applied: &[&str], withheld: &[&str], failed: &[&str]| DriftRepair {
        db: "A_app".into(),
        table_missing: missing,
        applied: applied.iter().map(|s| s.to_string()).collect(),
        withheld: withheld.iter().map(|s| s.to_string()).collect(),
        failed: failed.iter().map(|s| s.to_string()).collect(),
    };
    let outcome = |state, applied, skipped, resumed_from, blocked_by: Option<&str>, offending, error: Option<&str>| MigrationOutcome {
        state,
        applied,
        skipped,
        resumed_from,
        blocked_by: blocked_by.map(Into::into),
        offending,
        error: error.map(Into::into),
    };
    let cases = [
        ("reportClean", report(true, vec![], &[], &[]).to_value()),
        ("reportMissing", report(false, vec![], &[], &[]).to_value()),
        (
            "reportDirty",
            report(
                true,
                changes.clone(),
                &["ALTER TABLE `A_app`.`app_t` DROP INDEX `i`", "CREATE INDEX `j` ON `A_app`.`app_t` (`n`)"],
                &["ALTER TABLE `A_app`.`app_t` DROP FOREIGN KEY `fk`"],
            )
            .to_value(),
        ),
        ("reportWidenOnly", report(true, vec![changes[1].clone()], &[], &[]).to_value()),
        ("repairComplete", repair(false, &["s1"], &[], &[]).to_value()),
        ("repairPartial", repair(true, &[], &["w1"], &["f1"]).to_value()),
        ("outcomeApplied", outcome(MigrationState::Applied, 2, 1, -1, None, 0, None).to_value()),
        ("outcomeResumed", outcome(MigrationState::Applied, 3, 0, 1, None, 0, None).to_value()),
        ("outcomeBlocked", outcome(MigrationState::NeedsAttention, 0, 0, -1, Some("n fits INT"), 3, None).to_value()),
        ("outcomeFailed", outcome(MigrationState::Failed, 1, 0, -1, None, 0, Some("Duplicate column")).to_value()),
    ];
    let mismatches: Vec<String> = cases
        .iter()
        .filter(|(name, v)| v.to_java_json() != want[*name].as_str().unwrap())
        .map(|(name, v)| format!("{name}:\n  rust {}\n  java {}", v.to_java_json(), want[*name]))
        .collect();
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    println!("drift/migration json: {} shapes identical to java", cases.len());
}
