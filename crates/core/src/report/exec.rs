//! Running a validated [`Plan`]: one storage aggregate (a page read for a list, or the catalog's
//! function), then labels, derived measures, sort, limit, caps and "Other", the currency split,
//! and the output with column metadata. The storage, security and Redis sit behind
//! [`ReportBackend`] so the whole path is tested without them.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{json, Map, Value};

use super::period::{self, Bucket};
use super::shape;
use super::spec::{self, Caller, Catalog, DerivedOp, FieldKind, Lookup, Obj, Plan, ReportError, SourceKind, CMP_SUFFIX, DELTA_SUFFIX, R};

/// How long one source call may take before the run answers TIMEOUT.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a result is kept.
pub const CACHE_TTL_SECS: u64 = 60;
/// One forced run per widget spec per user in this many seconds.
pub const FORCE_WINDOW_SECS: u64 = 10;
/// The key the "Other" row's dimension holds.
pub const OTHER_KEY: &str = "__OTHER__";
/// The hidden row count of a report whose every measure has its own segment.
const ROWS_ALIAS: &str = "_rows";

/// What the runner reads through. `query` is the aggregate / page query as the storage
/// functions take it (JSON).
#[async_trait]
pub trait ReportBackend: Send + Sync {
    async fn aggregate(&self, app: Option<&str>, client: Option<&str>, storage: &str, query: &Value) -> Result<Vec<Obj>, String>;
    async fn read_page(&self, app: Option<&str>, client: Option<&str>, storage: &str, query: &Value) -> Result<Vec<Obj>, String>;
    /// One page of rows and the total count (View records): `query` has `condition`, `page`,
    /// `size`, `sort` and `fields` (the columns to read).
    async fn read_records(&self, app: Option<&str>, client: Option<&str>, storage: &str, query: &Value) -> Result<(Vec<Obj>, i64), String>;
    /// Display names of users by id.
    async fn user_names(&self, ids: &[u64]) -> Result<HashMap<u64, String>, String>;
    async fn cache_get(&self, key: &str) -> Option<String>;
    async fn cache_put(&self, key: &str, value: &str, ttl_secs: u64);
    /// Claims `key` for `ttl_secs` unless held; `None` when there is no cache.
    async fn claim(&self, key: &str, ttl_secs: u64) -> Option<bool>;
}

/// Calls a function definition by full name (a FUNCTION source); answers the output event's
/// result, or why it failed.
#[async_trait]
pub trait FunctionCaller: Send + Sync {
    async fn call(&self, full_name: &str, args: Obj) -> Result<Obj, String>;
}

/// One run's request.
pub struct RunRequest<'a> {
    pub spec: &'a Value,
    pub catalog: &'a Value,
    pub scope: &'a Value,
    pub force: bool,
    pub dry_run: bool,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub user_id: u64,
    pub authorities: &'a [String],
    pub now: DateTime<Utc>,
}

async fn timed<T>(f: impl std::future::Future<Output = Result<T, String>>) -> R<T> {
    match tokio::time::timeout(SOURCE_TIMEOUT, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(why)) => Err(ReportError::new("SOURCE_FAILED", "source", format!("The data could not be read: {why}"))),
        Err(_) => Err(ReportError::new("TIMEOUT", "source", format!("The data took longer than {} seconds to read.", SOURCE_TIMEOUT.as_secs()))),
    }
}

/// Runs (or, with `dry_run`, only validates) a report. Never fails: a refusal is the output.
pub async fn run(req: RunRequest<'_>, backend: &dyn ReportBackend, functions: &dyn FunctionCaller) -> Value {
    match run_inner(req, backend, functions).await {
        Ok(v) => v,
        Err(e) => e.to_json(),
    }
}

async fn run_inner(req: RunRequest<'_>, backend: &dyn ReportBackend, functions: &dyn FunctionCaller) -> R<Value> {
    let catalog = Catalog::parse(req.catalog)?;
    let caller = Caller { authorities: req.authorities, now: req.now };
    let plan = spec::validate(req.spec, &catalog, req.scope, &caller)?;
    let app = req.app_code.clone().filter(|s| !s.is_empty()).or_else(|| catalog.app.clone());
    let client = req.client_code.clone().filter(|s| !s.is_empty()).or_else(|| catalog.client_code.clone());

    if req.dry_run {
        let mut out = base_output(&plan, &catalog, predicted_columns(&plan, None, false));
        out.insert("dryRun".into(), Value::Bool(true));
        return Ok(Value::Object(out));
    }

    let key = cache_key(&plan, &catalog, req.spec, req.scope, app.as_deref(), client.as_deref(), req.user_id);
    let fresh = if req.force {
        // One forced run per spec per user per window; otherwise the cached copy.
        backend.claim(&format!("report:force:{}:{}", req.user_id, key_hash(&key)), FORCE_WINDOW_SECS).await != Some(false)
    } else {
        false
    };
    if !fresh {
        if let Some(text) = backend.cache_get(&key).await {
            if let Ok(Value::Object(mut cached)) = serde_json::from_str::<Value>(&text) {
                cached.insert("cached".into(), Value::Bool(true));
                return Ok(Value::Object(cached));
            }
        }
    }

    let mut out = match plan.source.kind {
        SourceKind::Function => run_function(&plan, &catalog, backend, functions, app.as_deref(), client.as_deref()).await?,
        SourceKind::Storage if plan.records_page.is_some() => run_record_page(&plan, &catalog, backend, app.as_deref(), client.as_deref()).await?,
        SourceKind::Storage if plan.records => run_records(&plan, &catalog, backend, app.as_deref(), client.as_deref()).await?,
        SourceKind::Storage => run_aggregate(&plan, &catalog, backend, app.as_deref(), client.as_deref(), req.now).await?,
    };
    out.insert("refreshedAt".into(), Value::String(req.now.format("%Y-%m-%dT%H:%M:%SZ").to_string()));
    out.insert("cached".into(), Value::Bool(false));
    let out = Value::Object(out);
    // An export (up to 5000 records) is read once, never kept in the cache.
    if !plan.records_page.is_some_and(|p| p.export) {
        backend.cache_put(&key, &out.to_string(), CACHE_TTL_SECS).await;
    }
    Ok(out)
}

/// The cache key: app + client + the caller + a hash of everything the answer depends on (the
/// spec, the scope, the resolved periods, the source's catalog entry and the catalog's zone
/// settings). The caller's user id (from the security context, never a param) is part of every
/// key: a FUNCTION source has no scope (it reads the caller itself, "my tasks"), and two users
/// with the same scope must still never share an answer.
pub fn cache_key(plan: &Plan, catalog: &Catalog, spec: &Value, scope: &Value, app: Option<&str>, client: Option<&str>, user_id: u64) -> String {
    let mut basis = json!({
        "user": user_id, "spec": spec, "scope": scope, "source": plan.source.raw,
        "period": plan.period.as_ref().map(|p| p.to_json()),
        "compare": plan.compare.as_ref().map(|c| json!({"to": c.to, "period": c.period.to_json()})),
        "tz": catalog.time_zone, "fy": catalog.fy_start, "currency": catalog.currency,
    });
    // CONTRACT 8.7: the catalog-wide periodEndsYesterday changes the answer without being in the
    // source's entry (the resolved period above already differs; this keeps the key honest for
    // ALL_TIME and a function source's params). Only when set, so older keys stay as they were.
    if catalog.period_ends_yesterday {
        basis["endsYesterday"] = json!(true);
    }
    format!("report:{}:{}:{}", app.unwrap_or("-"), client.unwrap_or("-"), key_hash(&basis.to_string()))
}

fn key_hash(text: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))[..32].to_string()
}

fn base_output(plan: &Plan, catalog: &Catalog, columns: Vec<Value>) -> Obj {
    let mut out = Map::new();
    out.insert("ok".into(), Value::Bool(true));
    out.insert("columns".into(), Value::Array(columns));
    out.insert("period".into(), plan.period.as_ref().map(|p| p.to_json()).unwrap_or(Value::Null));
    out.insert("view".into(), plan.view.clone());
    out.insert("shape".into(), json!({"groupBy": plan.shape.group_by, "values": plan.shape.values, "records": plan.records}));
    let measures = if plan.source.kind == SourceKind::Storage && !plan.records { plan.measures.len() } else { 0 };
    out.insert("fits".into(), shape::fits_with_measures(plan.shape, measures));
    out.insert("locale".into(), catalog.locale.clone().map(Value::String).unwrap_or(Value::Null));
    out.insert("timeZone".into(), Value::String(catalog.time_zone.clone()));
    if let Some(c) = &plan.compare {
        let mut cp = c.period.to_json();
        cp["compare"] = json!(c.to);
        out.insert("comparePeriod".into(), cp);
    }
    if !plan.links.is_empty() {
        out.insert("links".into(), Value::Object(plan.links.clone()));
    }
    if let Some(p) = &plan.paging {
        out.insert("paging".into(), p.clone());
    }
    out
}

/// The output columns. `currency` is the one currency of every money column (none when split or
/// unknown); `split` adds the `currency` column.
pub fn predicted_columns(plan: &Plan, currency: Option<&str>, split: bool) -> Vec<Value> {
    let mut cols = Vec::new();
    if plan.records {
        cols.push(json!({"key": "_id", "hidden": true}));
        for f in &plan.list_fields {
            let mut c = json!({"key": f.key, "label": f.label, "kind": f.kind.name()});
            if let Some(fmt) = &f.format {
                c["format"] = json!(fmt);
            }
            if f.pii {
                c["pii"] = json!(true);
            }
            cols.push(c);
            if f.lookup.is_some() || f.labels.is_some() {
                cols.push(json!({"key": format!("{}_label", f.key), "hidden": true}));
            }
        }
        return cols;
    }
    for g in &plan.group_by {
        if g.field.hidden {
            cols.push(json!({"key": g.alias, "hidden": true}));
            continue;
        }
        let mut c = json!({"key": g.alias, "label": g.field.label, "kind": if g.bucket.is_some() { "DATE" } else { "DIMENSION" }});
        if g.field.pii {
            c["pii"] = json!(true);
        }
        if let Some(b) = g.bucket {
            c["bucket"] = json!(b.name());
            c["fy"] = json!(g.fy);
        }
        cols.push(c);
        if g.labelled() {
            cols.push(json!({"key": format!("{}_label", g.alias), "hidden": true}));
        }
    }
    if split {
        cols.push(json!({"key": "currency", "label": "Currency", "kind": "DIMENSION"}));
    }
    for m in &plan.measures {
        if m.field.as_ref().is_some_and(|f| f.hidden) {
            cols.push(json!({"key": m.alias, "hidden": true}));
            continue;
        }
        let mut c = json!({"key": m.alias, "label": m.label, "kind": "MEASURE", "format": m.format, "fn": m.func});
        if let Some((n, _)) = &m.segment {
            c["segment"] = json!(n);
        }
        if let Some(f) = &m.field {
            c["field"] = json!(f.key);
        }
        if m.format == "MONEY" {
            c["currency"] = currency.map(|s| json!(s)).unwrap_or(Value::Null);
        }
        cols.push(c);
    }
    for d in &plan.derived {
        let mut c = json!({"key": d.alias, "label": d.label, "kind": "MEASURE", "format": d.format, "derived": true});
        if d.format == "MONEY" {
            c["currency"] = currency.map(|s| json!(s)).unwrap_or(Value::Null);
        }
        cols.push(c);
    }
    // compare: per value column, its value in the compare period and the change in percent.
    if let Some(cmp) = &plan.compare {
        let values: Vec<Value> = cols.iter().filter(|c| c["kind"] == "MEASURE" && c.get("hidden").is_none()).cloned().collect();
        let when = if cmp.to == "SAME_PERIOD_LAST_YEAR" { "last year" } else { "previous period" };
        for v in values {
            let key = v["key"].as_str().unwrap_or_default().to_string();
            let label = v["label"].as_str().unwrap_or(&key).to_string();
            let mut c = v.clone();
            c["key"] = json!(format!("{key}{CMP_SUFFIX}"));
            c["label"] = json!(format!("{label} ({when})"));
            c["compareOf"] = json!(key);
            cols.push(c);
            cols.push(json!({"key": format!("{key}{DELTA_SUFFIX}"), "label": format!("{label} change"), "kind": "MEASURE",
                             "format": "PERCENT", "deltaOf": key}));
        }
    }
    cols
}

/// The aggregate query (as `CoreServices.Storage.Aggregate` takes it, plus the Rust-only
/// `isoString` / `yearStartMonth` bucket options). Buckets are cut in a fixed UTC offset (the
/// zone's offset in the middle of the period), so no MySQL time zone tables are needed.
pub fn aggregate_query(plan: &Plan, catalog: &Catalog, now: DateTime<Utc>, currency_group: Option<&str>) -> Value {
    aggregate_query_for(plan, catalog, now, currency_group, None)
}

/// The aggregate for the measures of one `measures[].segment` (`Some(name)`: its condition ANDed
/// to the report's), or for the plain measures (`None`; a hidden row count stands in when every
/// measure has a segment, so the groups are still the report's).
pub fn aggregate_query_for(plan: &Plan, catalog: &Catalog, now: DateTime<Utc>, currency_group: Option<&str>, segment: Option<&str>) -> Value {
    let offset = period::mysql_offset(bucket_offset(plan, catalog, now));
    let mut groups: Vec<Value> = plan
        .group_by
        .iter()
        .map(|g| {
            let mut o = json!({"field": g.field.column, "alias": g.alias});
            if let Some(b) = g.bucket {
                o["bucket"] = json!(b.query_name());
                // A calendar date is a local day already: cut with no zone (CONTRACT 8.7, R3).
                o["timezone"] = json!(if g.field.date_only { "UTC".to_string() } else { offset.clone() });
                if g.field.string_date {
                    o["isoString"] = json!(true);
                } else if let Some(e) = &g.field.encoding {
                    o["encoding"] = json!(e);
                }
                if g.fy && catalog.fy_start != 1 && matches!(b, Bucket::Quarter | Bucket::Year) {
                    o["yearStartMonth"] = json!(catalog.fy_start);
                }
            }
            o
        })
        .collect();
    if let Some(c) = currency_group {
        groups.push(json!({"field": c, "alias": "currency"}));
    }
    let mut aggs: Vec<Value> = plan
        .measures
        .iter()
        .filter(|m| m.segment.as_ref().map(|(n, _)| n.as_str()) == segment)
        .map(|m| match &m.field {
            Some(f) => json!({"function": m.func, "field": f.column, "alias": m.alias}),
            None => json!({"function": "COUNT", "alias": m.alias}),
        })
        .collect();
    // The storage sorts on one column the report sorts on (so the groups kept when there are
    // more than it reads are the right ones); the full sort is done after the derived measures.
    let mut condition = plan.condition.clone();
    let mut sort: Vec<Value> = Vec::new();
    match segment {
        Some(name) => {
            let seg = plan.measures.iter().find_map(|m| m.segment.as_ref().filter(|(n, _)| n == name).map(|(_, c)| c.clone())).unwrap_or(Value::Null);
            condition = match (condition.is_null(), seg.is_null()) {
                (_, true) => condition,
                (true, false) => seg,
                (false, false) => json!({"operator": "AND", "conditions": [condition, seg]}),
            };
        }
        None => {
            if aggs.is_empty() {
                aggs.push(json!({"function": "COUNT", "alias": ROWS_ALIAS}));
            }
            sort = db_sort(plan).into_iter().map(|(p, desc)| json!({"property": p, "direction": if desc { "DESC" } else { "ASC" }})).collect();
        }
    }
    with_scope_reads(plan, json!({"condition": condition, "groupBy": groups, "aggregations": aggs, "sort": sort,
           "page": 0, "size": spec::READ_GROUPS, "count": false}))
}

/// Adds the row scope's joins and subQueries (CONTRACT 8.7, R1) to a read of the report's source;
/// a scope without them leaves the query exactly as before.
pub fn with_scope_reads(plan: &Plan, mut q: Value) -> Value {
    if !plan.joins.is_empty() {
        q["joins"] = Value::Array(plan.joins.clone());
    }
    if !plan.sub_queries.is_empty() {
        q["subQueries"] = Value::Array(plan.sub_queries.clone());
    }
    q
}

/// The fixed offset buckets are cut in: the zone's offset in the middle of the period (now for
/// ALL_TIME).
pub fn bucket_offset(plan: &Plan, catalog: &Catalog, now: DateTime<Utc>) -> chrono::FixedOffset {
    let at = match plan.period.as_ref().and_then(|p| p.range) {
        Some((f, t)) => catalog.zone.midnight_utc(f + (t - f) / 2),
        None => now,
    };
    catalog.zone.offset_at(at)
}

/// The report's sort (or its default), as aliases and descending flags.
pub fn effective_sort(plan: &Plan) -> Vec<(String, bool)> {
    if !plan.sort.is_empty() {
        return plan.sort.clone();
    }
    if let Some(g) = plan.group_by.iter().find(|g| g.bucket.is_some()) {
        return vec![(g.alias.clone(), false)];
    }
    if let Some(v) = plan.value_aliases().first() {
        return vec![(v.clone(), true)];
    }
    plan.group_by.first().map(|g| vec![(g.alias.clone(), false)]).unwrap_or_default()
}

fn db_sort(plan: &Plan) -> Vec<(String, bool)> {
    // Only what the plain aggregate holds: no derived measure, no segment measure.
    let derived: Vec<&str> = plan
        .derived
        .iter()
        .map(|d| d.alias.as_str())
        .chain(plan.measures.iter().filter(|m| m.segment.is_some()).map(|m| m.alias.as_str()))
        .collect();
    effective_sort(plan).into_iter().filter(|(a, _)| !derived.contains(&a.as_str())).take(1).collect()
}

/// The rows of one aggregate run, through the derived measures (before sort and caps).
struct Aggregated {
    rows: Vec<Obj>,
    truncated: bool,
    /// The one currency of the money measures (none when split or unknown).
    currency: Option<String>,
    /// The currency column the rows are split by.
    split: Option<String>,
}

async fn run_aggregate(
    plan: &Plan,
    catalog: &Catalog,
    backend: &dyn ReportBackend,
    app: Option<&str>,
    client: Option<&str>,
    now: DateTime<Utc>,
) -> R<Obj> {
    let main = aggregate_rows(plan, catalog, backend, app, client, now, None).await?;
    let mut rows = main.rows;
    if let Some(cplan) = plan.for_compare() {
        // The same currency handling as the report's, so the rows join on the same keys.
        let cmp = aggregate_rows(&cplan, catalog, backend, app, client, now, Some((main.currency.clone(), main.split.clone()))).await?;
        join_compare(plan, catalog, &mut rows, &cmp.rows, main.split.is_some());
    }
    sort_rows(&mut rows, &effective_sort(plan));
    let truncated = main.truncated | apply_caps(plan, &mut rows);

    let mut out = base_output(plan, catalog, predicted_columns(plan, main.currency.as_deref(), main.split.is_some()));
    out.insert("rows".into(), Value::Array(rows.into_iter().map(Value::Object).collect()));
    out.insert("truncated".into(), Value::Bool(truncated));
    out.insert("currencySplit".into(), Value::Bool(main.split.is_some()));
    Ok(out)
}

/// The key a row joins its compare row on: each group by's value, a date bucket by its position
/// in its own period (so October 2026 meets October 2025, and week 1 meets week 1), and the
/// currency when split.
fn compare_key(plan: &Plan, catalog: &Catalog, r: &Obj, split: bool) -> String {
    let from = plan.period.as_ref().and_then(|p| p.range).map(|(f, _)| f);
    let mut parts: Vec<String> = plan
        .group_by
        .iter()
        .map(|g| match (g.bucket, from) {
            (Some(b), Some(from)) => {
                let fy_start = if g.fy { catalog.fy_start } else { 1 };
                r.get(&g.alias)
                    .and_then(Value::as_str)
                    .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
                    .and_then(|d| period::bucket_index(b, fy_start, from, d))
                    .map(|i| format!("#{i}"))
                    .unwrap_or_else(|| "#-".into())
            }
            _ => r.get(&g.alias).map(|v| v.to_string()).unwrap_or_default(),
        })
        .collect();
    if split {
        parts.push(r.get("currency").map(|v| v.to_string()).unwrap_or_default());
    }
    parts.join("\u{1}")
}

/// Adds `<m>_cmp` and `<m>_delta_pct` for every measure and derived measure to each row of the
/// report from the matching compare row (none: `_cmp` null, and the change null).
pub fn join_compare(plan: &Plan, catalog: &Catalog, rows: &mut [Obj], cmp_rows: &[Obj], split: bool) {
    let Some(cplan) = plan.for_compare() else { return };
    let by_key: HashMap<String, &Obj> = cmp_rows.iter().map(|r| (compare_key(&cplan, catalog, r, split), r)).collect();
    let values = plan.value_aliases();
    for r in rows.iter_mut() {
        let hit = by_key.get(&compare_key(plan, catalog, r, split));
        for v in &values {
            r.insert(format!("{v}{CMP_SUFFIX}"), hit.and_then(|h| h.get(v)).cloned().unwrap_or(Value::Null));
        }
        apply_deltas(plan, r);
    }
}

/// `<m>_delta_pct` = 100 * (m - cmp) / |cmp|; null when cmp is 0 or missing, or m is missing.
fn apply_deltas(plan: &Plan, r: &mut Obj) {
    for v in plan.value_aliases() {
        let (cur, cmp) = (num(r.get(&v)), num(r.get(&format!("{v}{CMP_SUFFIX}"))));
        let d = match (cur, cmp) {
            (Some(c), Some(p)) if p != 0.0 => number(100.0 * (c - p) / p.abs()),
            _ => Value::Null,
        };
        r.insert(format!("{v}{DELTA_SUFFIX}"), d);
    }
}

/// One aggregate run's rows. `decided`: the currency and split column to use (the compare run
/// takes the report's), else they are probed.
async fn aggregate_rows(
    plan: &Plan,
    catalog: &Catalog,
    backend: &dyn ReportBackend,
    app: Option<&str>,
    client: Option<&str>,
    now: DateTime<Utc>,
    decided: Option<(Option<String>, Option<String>)>,
) -> R<Aggregated> {
    let storage = plan.source.storage.clone().unwrap_or_default();

    // The currency of the money measures: pinned by a filter, read from the data, or split.
    let money = plan.measures.iter().find(|m| m.format == "MONEY").and_then(|m| m.field.clone());
    let mut currency: Option<String> = money.as_ref().and_then(|f| f.currency.clone()).or_else(|| catalog.currency.clone());
    let mut split: Option<String> = None;
    if let Some((c, s)) = decided {
        currency = c;
        split = s;
    } else if let Some(cf) = money.as_ref().filter(|f| f.currency.is_none()).and_then(|f| f.currency_field.clone()) {
        // A fixed currency on the field is one currency: no probe, no split.
        if let Some(pinned) = plan.pinned_currency.get(&cf) {
            currency = Some(pinned.clone());
        } else {
            let probe = with_scope_reads(plan, json!({"condition": plan.condition, "groupBy": [{"field": cf, "alias": "currency"}],
                               "aggregations": [{"function": "COUNT", "alias": "n"}], "page": 0, "size": 3, "count": false}));
            let found = timed(backend.aggregate(app, client, &storage, &probe)).await?;
            let codes: BTreeSet<String> = found.iter().filter_map(|r| r.get("currency").and_then(Value::as_str).map(str::to_string)).collect();
            match codes.len() {
                0 => {}
                1 => currency = codes.into_iter().next(),
                _ => {
                    split = Some(cf.clone());
                    currency = None;
                }
            }
        }
    }

    let query = aggregate_query(plan, catalog, now, split.as_deref());
    let mut rows = timed(backend.aggregate(app, client, &storage, &query)).await?;
    let truncated = rows.len() >= spec::READ_GROUPS;
    // Each `measures[].segment`: one more aggregate over the same groups, merged by group key.
    let mut segments: Vec<&str> = Vec::new();
    for m in &plan.measures {
        if let Some((n, _)) = &m.segment {
            if !segments.contains(&n.as_str()) {
                segments.push(n);
            }
        }
    }
    for seg in segments {
        let q = aggregate_query_for(plan, catalog, now, split.as_deref(), Some(seg));
        let found = timed(backend.aggregate(app, client, &storage, &q)).await?;
        let key_of = |r: &Obj| -> String {
            plan.group_by.iter().map(|g| g.alias.as_str()).chain(split.iter().map(|_| "currency")).map(|a| r.get(a).map(|v| v.to_string()).unwrap_or_default()).collect::<Vec<_>>().join("\u{1}")
        };
        let by_key: HashMap<String, &Obj> = found.iter().map(|r| (key_of(r), r)).collect();
        let mine: Vec<&spec::Measure> = plan.measures.iter().filter(|m| m.segment.as_ref().is_some_and(|(n, _)| n == seg)).collect();
        for r in rows.iter_mut() {
            let hit = by_key.get(&key_of(r));
            for m in &mine {
                let v = hit.and_then(|h| h.get(&m.alias).cloned()).unwrap_or_else(|| {
                    if matches!(m.func.as_str(), "COUNT" | "COUNT_DISTINCT" | "SUM") { json!(0) } else { Value::Null }
                });
                r.insert(m.alias.clone(), v);
            }
        }
    }
    for r in rows.iter_mut() {
        r.shift_remove(ROWS_ALIAS);
    }

    let offset = bucket_offset(plan, catalog, now);
    // Date buckets: the local ISO date the bucket starts on, and its label.
    for g in plan.group_by.iter().filter(|g| g.bucket.is_some()) {
        let b = g.bucket.unwrap_or(Bucket::Day);
        let fy = g.fy && catalog.fy_start != 1;
        // A calendar date came back uncut by any zone.
        let offset = if g.field.date_only { chrono::FixedOffset::east_opt(0).unwrap_or(offset) } else { offset };
        for r in rows.iter_mut() {
            let local = r.get(&g.alias).and_then(|v| period::bucket_local_date(v, offset, millis(&g.field.encoding)));
            match local {
                Some(d) => {
                    r.insert(g.alias.clone(), json!(period::iso_date(d)));
                    r.insert(format!("{}_label", g.alias), json!(b.label(d, fy, catalog.fy_start)));
                }
                None => {
                    r.insert(format!("{}_label", g.alias), json!("Not set"));
                }
            }
        }
    }
    if split.is_none() {
        fill_buckets(plan, catalog, &mut rows);
    }
    resolve_labels(plan, backend, app, client, &mut rows).await?;
    apply_derived(plan, &mut rows);
    Ok(Aggregated { rows, truncated, currency, split })
}

fn millis(encoding: &Option<String>) -> Option<bool> {
    encoding.as_deref().map(|e| e == "EPOCH_MILLIS")
}

/// A time series over a bounded period gets every bucket, the empty ones at zero (counts and
/// sums) or null.
pub fn fill_buckets(plan: &Plan, catalog: &Catalog, rows: &mut Vec<Obj>) {
    let [g] = plan.group_by.as_slice() else { return };
    let (Some(b), Some((from, to))) = (g.bucket, plan.period.as_ref().and_then(|p| p.range)) else { return };
    let fy_start = if g.fy { catalog.fy_start } else { 1 };
    let fy = g.fy && catalog.fy_start != 1;
    let have: BTreeSet<String> = rows.iter().filter_map(|r| r.get(&g.alias).and_then(Value::as_str).map(str::to_string)).collect();
    let mut d: NaiveDate = b.start(from, fy_start);
    let mut n = 0;
    while d <= to && n < spec::BUCKETS {
        let key = period::iso_date(d);
        if !have.contains(&key) {
            let mut r = Map::new();
            r.insert(g.alias.clone(), json!(key));
            r.insert(format!("{}_label", g.alias), json!(b.label(d, fy, fy_start)));
            for m in &plan.measures {
                r.insert(m.alias.clone(), if matches!(m.func.as_str(), "COUNT" | "COUNT_DISTINCT" | "SUM") { json!(0) } else { Value::Null });
            }
            rows.push(r);
        }
        d = b.next(d);
        n += 1;
    }
}

fn key_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.as_i64().map(|i| i.to_string()).unwrap_or_else(|| n.to_string())),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `<as>_label` for every dimension with a lookup or inline `labels`: one read per lookup, by the
/// keys present the inline map does not already name.
async fn resolve_labels(plan: &Plan, backend: &dyn ReportBackend, app: Option<&str>, client: Option<&str>, rows: &mut [Obj]) -> R<()> {
    type Target = (String, Option<Lookup>, Option<Obj>);
    let targets: Vec<Target> = if plan.records {
        plan.list_fields.iter().filter(|f| f.lookup.is_some() || f.labels.is_some()).map(|f| (f.key.clone(), f.lookup.clone(), f.labels.clone())).collect()
    } else {
        plan.group_by
            .iter()
            .filter(|g| g.bucket.is_none() && (g.field.lookup.is_some() || g.field.labels.is_some()))
            .map(|g| (g.alias.clone(), g.field.lookup.clone(), g.field.labels.clone()))
            .collect()
    };
    for (alias, lookup, inline) in targets {
        let inline: HashMap<String, String> = inline.iter().flatten().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect();
        let keys: BTreeSet<String> = rows.iter().filter_map(|r| r.get(&alias).and_then(key_text)).filter(|k| k != OTHER_KEY && !inline.contains_key(k)).collect();
        let mut labels: HashMap<String, String> = match (&lookup, keys.is_empty()) {
            (None, _) | (_, true) => HashMap::new(),
            (Some(lookup), false) => match lookup {
                Lookup::Values(m) => m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect(),
                Lookup::User => {
                    let ids: Vec<u64> = keys.iter().filter_map(|k| k.parse().ok()).collect();
                    let names = timed(backend.user_names(&ids)).await.unwrap_or_default();
                    names.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
                }
                Lookup::Storage { storage, key, label } => {
                    let q = json!({"condition": {"field": key, "operator": "IN", "multiValue": keys.iter().collect::<Vec<_>>()},
                                   "page": 0, "size": keys.len().min(spec::READ_GROUPS)});
                    // A label that cannot be read is shown as its key.
                    let found = timed(backend.read_page(app, client, storage, &q)).await.unwrap_or_default();
                    found
                        .iter()
                        .filter_map(|r| Some((r.get(key).and_then(key_text)?, r.get(label).and_then(key_text)?)))
                        .collect()
                }
            },
        };
        labels.extend(inline);
        for r in rows.iter_mut() {
            let text = match r.get(&alias).and_then(key_text) {
                Some(k) if k == OTHER_KEY => "Other".to_string(),
                Some(k) => labels.get(&k).cloned().unwrap_or(k),
                None => "Not set".to_string(),
            };
            r.insert(format!("{alias}_label"), Value::String(text));
        }
    }
    Ok(())
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64)
}

fn number(x: f64) -> Value {
    if x.is_finite() {
        if x.fract() == 0.0 && x.abs() < 9e15 {
            json!(x as i64)
        } else {
            json!(x)
        }
    } else {
        Value::Null
    }
}

/// ratio a/b (null when b is 0 or missing), difference a-b (a missing side counts 0, both
/// missing is null), percent 100*a/b.
pub fn apply_derived(plan: &Plan, rows: &mut [Obj]) {
    apply_derived_with(plan, rows, "");
}

/// [`apply_derived`] over the columns named with `suffix` (`_cmp`: the compare values).
fn apply_derived_with(plan: &Plan, rows: &mut [Obj], suffix: &str) {
    for r in rows.iter_mut() {
        for d in &plan.derived {
            let (a, b) = (num(r.get(&format!("{}{suffix}", d.a))), num(r.get(&format!("{}{suffix}", d.b))));
            let v = match d.op {
                DerivedOp::Ratio => match (a, b) {
                    (Some(a), Some(b)) if b != 0.0 => number(a * d.scale.unwrap_or(1.0) / b),
                    _ => Value::Null,
                },
                DerivedOp::Percent => match (a, b) {
                    (Some(a), Some(b)) if b != 0.0 => number(100.0 * a / b),
                    _ => Value::Null,
                },
                DerivedOp::Difference => match (a, b) {
                    (None, None) => Value::Null,
                    (a, b) => number(a.unwrap_or(0.0) - b.unwrap_or(0.0)),
                },
            };
            r.insert(format!("{}{suffix}", d.alias), v);
        }
    }
}

fn cmp_values(a: Option<&Value>, b: Option<&Value>) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let null = |v: Option<&Value>| v.is_none_or(Value::is_null);
    match (null(a), null(b)) {
        (true, true) => return Equal,
        (true, false) => return Greater,
        (false, true) => return Less,
        _ => {}
    }
    let (a, b) = (a.unwrap_or(&Value::Null), b.unwrap_or(&Value::Null));
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Equal),
        _ => key_text(a).unwrap_or_default().cmp(&key_text(b).unwrap_or_default()),
    }
}

/// Sorts on each key in turn; nulls last either way.
pub fn sort_rows(rows: &mut [Obj], sort: &[(String, bool)]) {
    rows.sort_by(|x, y| {
        for (k, desc) in sort {
            let (xv, yv) = (x.get(k), y.get(k));
            let nulls = xv.is_none_or(Value::is_null) || yv.is_none_or(Value::is_null);
            let o = cmp_values(xv, yv);
            let o = if *desc && !nulls { o.reverse() } else { o };
            if o != std::cmp::Ordering::Equal {
                return o;
            }
        }
        std::cmp::Ordering::Equal
    });
}

/// The spec's limit, then the view's caps: table 500 rows, list 100, chart time buckets 400,
/// other charts 50 groups (or `view.style.topN`) with the rest summed as "Other". Answers
/// whether rows were dropped (not summed).
pub fn apply_caps(plan: &Plan, rows: &mut Vec<Obj>) -> bool {
    let mut dropped = false;
    let mut cut = |rows: &mut Vec<Obj>, n: usize| {
        if rows.len() > n {
            rows.truncate(n);
            dropped = true;
        }
    };
    if let Some(l) = plan.limit {
        if rows.len() > l {
            rows.truncate(l);
        }
    }
    let ty = plan.view_type.as_str();
    if plan.records || ty == "LIST" {
        cut(rows, spec::LIST_ROWS);
        return dropped;
    }
    if shape::is_table(ty) {
        cut(rows, spec::TABLE_ROWS);
        return dropped;
    }
    if shape::is_number(ty) {
        return dropped;
    }
    let Some(first) = plan.group_by.first() else { return dropped };
    if first.bucket.is_some() {
        cut(rows, spec::BUCKETS);
        return dropped;
    }
    let keep_n = plan.top_n.unwrap_or(spec::CHART_GROUPS).min(spec::CHART_GROUPS);
    let mut kept: Vec<String> = Vec::new();
    for r in rows.iter() {
        let k = r.get(&first.alias).map(|v| v.to_string()).unwrap_or_default();
        if !kept.contains(&k) {
            kept.push(k);
        }
    }
    if kept.len() <= keep_n {
        return dropped;
    }
    let kept: BTreeSet<String> = kept.into_iter().take(keep_n).collect();
    let (stay, rest): (Vec<Obj>, Vec<Obj>) = rows.drain(..).partition(|r| kept.contains(&r.get(&first.alias).map(|v| v.to_string()).unwrap_or_default()));
    *rows = stay;
    // One "Other" row per value of the second group by (and per currency).
    let mut others: Vec<(String, Obj)> = Vec::new();
    for r in rest {
        let series: String = plan.group_by.iter().skip(1).map(|g| g.alias.as_str()).chain(["currency"]).map(|a| r.get(a).map(|v| v.to_string()).unwrap_or_default()).collect::<Vec<_>>().join("|");
        let slot = match others.iter().position(|(s, _)| *s == series) {
            Some(i) => i,
            None => {
                let mut o = Map::new();
                o.insert(first.alias.clone(), json!(OTHER_KEY));
                if first.labelled() {
                    o.insert(format!("{}_label", first.alias), json!("Other"));
                }
                o.insert("_other".into(), Value::Bool(true));
                for g in plan.group_by.iter().skip(1) {
                    for k in [g.alias.clone(), format!("{}_label", g.alias)] {
                        if let Some(v) = r.get(&k) {
                            o.insert(k, v.clone());
                        }
                    }
                }
                if let Some(c) = r.get("currency") {
                    o.insert("currency".into(), c.clone());
                }
                for m in &plan.measures {
                    o.insert(m.alias.clone(), Value::Null);
                    if plan.compare.is_some() {
                        o.insert(format!("{}{CMP_SUFFIX}", m.alias), Value::Null);
                    }
                }
                others.push((series, o));
                others.len() - 1
            }
        };
        let o = &mut others[slot].1;
        let suffixes: &[&str] = if plan.compare.is_some() { &["", CMP_SUFFIX] } else { &[""] };
        for (m, suffix) in plan.measures.iter().flat_map(|m| suffixes.iter().map(move |s| (m, *s))) {
            let key = format!("{}{suffix}", m.alias);
            let (cur, add) = (num(o.get(&key)), num(r.get(&key)));
            let v = match m.func.as_str() {
                "COUNT" | "SUM" => match (cur, add) {
                    (None, None) => Value::Null,
                    (c, a) => number(c.unwrap_or(0.0) + a.unwrap_or(0.0)),
                },
                "MIN" => match (cur, add) {
                    (Some(c), Some(a)) => number(c.min(a)),
                    (c, a) => c.or(a).map(number).unwrap_or(Value::Null),
                },
                "MAX" => match (cur, add) {
                    (Some(c), Some(a)) => number(c.max(a)),
                    (c, a) => c.or(a).map(number).unwrap_or(Value::Null),
                },
                // An average or a distinct count of a group of groups cannot be added up.
                _ => Value::Null,
            };
            o.insert(key, v);
        }
    }
    let mut other_rows: Vec<Obj> = others.into_iter().map(|(_, o)| o).collect();
    apply_derived(plan, &mut other_rows);
    if plan.compare.is_some() {
        apply_derived_with(plan, &mut other_rows, CMP_SUFFIX);
        for r in other_rows.iter_mut() {
            apply_deltas(plan, r);
        }
    }
    rows.extend(other_rows);
    dropped
}

async fn run_records(plan: &Plan, catalog: &Catalog, backend: &dyn ReportBackend, app: Option<&str>, client: Option<&str>) -> R<Obj> {
    let storage = plan.source.storage.clone().unwrap_or_default();
    let size = plan.limit.unwrap_or(spec::LIST_ROWS).min(spec::LIST_ROWS);
    let sort: Vec<Value> = plan
        .sort
        .iter()
        .filter_map(|(k, desc)| {
            let col = plan.list_fields.iter().find(|f| &f.key == k)?.column.clone();
            Some(json!({"property": col, "direction": if *desc { "DESC" } else { "ASC" }}))
        })
        .collect();
    let q = with_scope_reads(plan, json!({"condition": plan.condition, "page": 0, "size": size + 1, "sort": sort}));
    let found = timed(backend.read_page(app, client, &storage, &q)).await?;
    let truncated = found.len() > size;
    let mut rows: Vec<Obj> = found
        .into_iter()
        .take(size)
        .map(|r| {
            let mut o = Map::new();
            o.insert("_id".into(), r.get("_id").cloned().unwrap_or(Value::Null));
            for f in &plan.list_fields {
                o.insert(f.key.clone(), lookup_path(&Value::Object(r.clone()), &f.column).cloned().unwrap_or(Value::Null));
            }
            o
        })
        .collect();
    resolve_labels(plan, backend, app, client, &mut rows).await?;
    let mut out = base_output(plan, catalog, predicted_columns(plan, None, false));
    out.insert("rows".into(), Value::Array(rows.into_iter().map(Value::Object).collect()));
    out.insert("truncated".into(), Value::Bool(truncated));
    out.insert("currencySplit".into(), Value::Bool(false));
    Ok(out)
}

/// View records (P1b): one page of the source's rows with the total, only the records fields
/// (plus the hidden `_id` for the row link), labels resolved as for aggregates.
async fn run_record_page(plan: &Plan, catalog: &Catalog, backend: &dyn ReportBackend, app: Option<&str>, client: Option<&str>) -> R<Obj> {
    let storage = plan.source.storage.clone().unwrap_or_default();
    let Some(page) = plan.records_page else { return Err(ReportError::new("SOURCE_FAILED", "records", "No records page was asked for.")) };
    let sort: Vec<Value> = plan
        .sort
        .iter()
        .filter_map(|(k, desc)| {
            let col = plan.source.fields.get(k)?.column.clone();
            Some(json!({"property": col, "direction": if *desc { "DESC" } else { "ASC" }}))
        })
        .collect();
    // Only the columns shown are read (a JSON path reads its whole top column).
    let mut fields: Vec<String> = Vec::new();
    for f in &plan.list_fields {
        let top = f.column.split('.').next().unwrap_or(&f.column).to_string();
        if !fields.contains(&top) {
            fields.push(top);
        }
    }
    let q = with_scope_reads(plan, json!({"condition": plan.condition, "page": page.page, "size": page.size, "sort": sort, "fields": fields}));
    let (found, total) = timed(backend.read_records(app, client, &storage, &q)).await?;
    let mut rows: Vec<Obj> = found
        .into_iter()
        .take(page.size)
        .map(|r| {
            let row = Value::Object(r);
            let mut o = Map::new();
            o.insert("_id".into(), row.get("_id").cloned().unwrap_or(Value::Null));
            for f in &plan.list_fields {
                o.insert(f.key.clone(), lookup_path(&row, &f.column).cloned().unwrap_or(Value::Null));
            }
            o
        })
        .collect();
    resolve_labels(plan, backend, app, client, &mut rows).await?;
    let shown = rows.len();
    let mut out = base_output(plan, catalog, predicted_columns(plan, None, false));
    out.insert("rows".into(), Value::Array(rows.into_iter().map(Value::Object).collect()));
    out.insert("total".into(), json!(total));
    out.insert("page".into(), json!(page.page));
    out.insert("size".into(), json!(page.size));
    if page.export {
        out.insert("export".into(), Value::Bool(true));
    }
    out.insert("truncated".into(), Value::Bool(((page.page * page.size + shown) as i64) < total));
    out.insert("currencySplit".into(), Value::Bool(false));
    Ok(out)
}

fn lookup_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(v);
    }
    let mut cur = v;
    for part in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get(part)?,
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

async fn run_function(
    plan: &Plan,
    catalog: &Catalog,
    backend: &dyn ReportBackend,
    functions: &dyn FunctionCaller,
    app: Option<&str>,
    client: Option<&str>,
) -> R<Obj> {
    let full = plan.source.function.clone().unwrap_or_default();
    let result = timed(functions.call(&full, plan.params.clone())).await?;
    let root = Value::Object(result);
    let found = lookup_path(&root, plan.source.result_path.as_deref().unwrap_or("")).cloned().unwrap_or(Value::Null);
    let raw_rows: Vec<Value> = match found {
        Value::Array(a) => a,
        Value::Object(o) => vec![Value::Object(o)],
        Value::Null => Vec::new(),
        _ => return Err(ReportError::new("SOURCE_FAILED", "source", format!("{} did not answer rows.", plan.source.label))),
    };
    let mut currencies: BTreeSet<String> = BTreeSet::new();
    let mut rows: Vec<Obj> = raw_rows
        .iter()
        .map(|r| {
            let mut o = Map::new();
            for (k, c) in &plan.source.columns {
                o.insert(k.clone(), lookup_path(r, c.path.as_deref().unwrap_or(k)).cloned().unwrap_or(Value::Null));
                if let Some(cf) = &c.currency_field {
                    if let Some(code) = lookup_path(r, cf).and_then(Value::as_str) {
                        currencies.insert(code.to_string());
                        o.insert("currency".into(), json!(code));
                    }
                }
            }
            o
        })
        .collect();
    let split = currencies.len() > 1;
    let currency = if split {
        None
    } else {
        currencies.into_iter().next().or_else(|| plan.source.columns.values().find_map(|c| c.currency.clone())).or_else(|| catalog.currency.clone())
    };
    resolve_labels(plan, backend, app, client, &mut rows).await?;
    // Labels from a map in the answer (`labelMapPath`), the key when it has none.
    for g in plan.group_by.iter().filter(|g| g.field.label_map_path.is_some()) {
        let map = lookup_path(&root, g.field.label_map_path.as_deref().unwrap_or("")).cloned().unwrap_or(Value::Null);
        for r in rows.iter_mut() {
            let label = match r.get(&g.alias).and_then(key_text) {
                Some(k) => map.get(&k).and_then(key_text).unwrap_or(k),
                None => "Not set".into(),
            };
            r.insert(format!("{}_label", g.alias), Value::String(label));
        }
    }
    let total = plan.source.total_path.as_deref().and_then(|p| lookup_path(&root, p)).cloned();
    apply_derived(plan, &mut rows);
    if !plan.sort.is_empty() {
        sort_rows(&mut rows, &plan.sort);
    }
    let truncated = apply_caps(plan, &mut rows);
    let mut cols = predicted_columns(plan, currency.as_deref(), split);
    // A function's columns keep their catalog kinds (a DATE column stays DATE).
    for c in cols.iter_mut() {
        if let Some(f) = c.get("key").and_then(Value::as_str).and_then(|k| plan.source.columns.get(k)) {
            if f.kind == FieldKind::Date {
                c["kind"] = json!("DATE");
            }
            if let Some(o) = c.as_object_mut() {
                o.remove("fn");
                o.remove("field");
            }
        }
    }
    let mut out = base_output(plan, catalog, cols);
    out.insert("rows".into(), Value::Array(rows.into_iter().map(Value::Object).collect()));
    out.insert("truncated".into(), Value::Bool(truncated));
    out.insert("currencySplit".into(), Value::Bool(split));
    if let Some(t) = total {
        out.insert("total".into(), t);
    }
    Ok(out)
}
