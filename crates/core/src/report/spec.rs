//! The report spec (v1) and the app's catalog (CXZ-1780 CONTRACT sections 1 and 2), validated into
//! a [`Plan`] the runner executes. Nothing outside the catalog can reach a query: every field is a
//! catalog key, every value a scalar bound by the storage layer, every alias an identifier.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use super::period::{self, Bucket, Period, Zone};
use super::shape::{self, Shape};

pub type Obj = Map<String, Value>;

pub const MAX_MEASURES: usize = 3;
pub const MAX_GROUP_BY: usize = 2;
pub const MAX_FILTERS: usize = 8;
pub const MAX_DERIVED: usize = 3;
pub const MAX_SORT: usize = 3;
pub const MAX_LIST_FIELDS: usize = 12;
pub const MAX_IN_VALUES: usize = 500;
/// View records (P1b): rows per page on screen, and per CSV export (`records.export`).
pub const RECORDS_PAGE: usize = 100;
pub const RECORDS_EXPORT: usize = 5000;
/// Fields a source's `records` may list.
pub const MAX_RECORD_FIELDS: usize = 30;
/// Chart groups kept before the rest is summed as "Other".
pub const CHART_GROUPS: usize = 50;
pub const TABLE_ROWS: usize = 500;
pub const LIST_ROWS: usize = 100;
pub const BUCKETS: usize = 400;
/// Groups read from the storage at most (its page size cap).
pub const READ_GROUPS: usize = 1000;

/// A refusal: `{"ok":false,"error":{"code","message","path"}}`.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportError {
    pub code: &'static str,
    pub message: String,
    pub path: String,
}

impl ReportError {
    pub fn new(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> Self {
        ReportError { code, message: message.into(), path: path.into() }
    }

    pub fn to_json(&self) -> Value {
        json!({"ok": false, "error": {"code": self.code, "message": self.message, "path": self.path}})
    }
}

pub type R<T> = Result<T, ReportError>;

fn err<T>(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> R<T> {
    Err(ReportError::new(code, path, message))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Dimension,
    Date,
    Measure,
}

impl FieldKind {
    pub fn name(&self) -> &'static str {
        match self {
            FieldKind::Dimension => "DIMENSION",
            FieldKind::Date => "DATE",
            FieldKind::Measure => "MEASURE",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    /// Labels from one read of another storage: `key` matched, `label` shown.
    Storage { storage: String, key: String, label: String },
    /// User display names from security.
    User,
    /// A fixed map from value to label.
    Values(Obj),
}

/// A catalog field (or a FUNCTION source's column).
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub key: String,
    /// The storage column (or JSON path); the key unless the catalog says `column`.
    pub column: String,
    pub kind: FieldKind,
    pub label: String,
    pub pii: bool,
    pub authority: Option<String>,
    pub string_date: bool,
    /// `EPOCH_SECONDS` / `EPOCH_MILLIS` for a date kept as a number.
    pub encoding: Option<String>,
    pub format: Option<String>,
    pub currency_field: Option<String>,
    pub currency: Option<String>,
    pub fns: Option<Vec<String>>,
    pub lookup: Option<Lookup>,
    /// A FUNCTION column's path in each result row.
    pub path: Option<String>,
    /// A column the UI keeps but does not show (a FUNCTION source's ids, a currency code).
    pub hidden: bool,
    /// A FUNCTION column whose labels come from a map in the function's answer (`caseNumbers`).
    pub label_map_path: Option<String>,
}

fn s_of(o: &Obj, k: &str) -> Option<String> {
    match o.get(k) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

fn b_of(o: &Obj, k: &str) -> bool {
    matches!(o.get(k), Some(Value::Bool(true)))
}

impl Field {
    fn parse(key: &str, v: &Value, catalog_sources: &Obj, path: &str) -> R<Field> {
        let Value::Object(o) = v else { return err("SOURCE_FAILED", path, format!("The catalog field '{key}' is not an object.")) };
        let kind = match s_of(o, "kind").as_deref().unwrap_or("DIMENSION") {
            "DIMENSION" => FieldKind::Dimension,
            "DATE" => FieldKind::Date,
            "MEASURE" => FieldKind::Measure,
            other => return err("SOURCE_FAILED", path, format!("The catalog field '{key}' has an unknown kind '{other}'.")),
        };
        let lookup = match o.get("lookup") {
            Some(Value::Object(l)) => {
                if s_of(l, "type").as_deref() == Some("USER") {
                    Some(Lookup::User)
                } else if let Some(Value::Object(vals)) = l.get("values") {
                    Some(Lookup::Values(vals.clone()))
                } else {
                    let storage = s_of(l, "storage").or_else(|| {
                        let src = s_of(l, "source")?;
                        match catalog_sources.get(&src) {
                            Some(Value::Object(so)) => s_of(so, "storage"),
                            _ => Some(src),
                        }
                    });
                    match storage {
                        Some(storage) => Some(Lookup::Storage {
                            storage,
                            key: s_of(l, "key").unwrap_or_else(|| "_id".into()),
                            label: s_of(l, "label").unwrap_or_else(|| "name".into()),
                        }),
                        None => None,
                    }
                }
            }
            _ => None,
        };
        let fns = match o.get("fns") {
            Some(Value::Array(a)) => Some(a.iter().filter_map(|f| f.as_str().map(str::to_string)).collect()),
            _ => None,
        };
        Ok(Field {
            key: key.to_string(),
            column: s_of(o, "column").unwrap_or_else(|| key.to_string()),
            kind,
            label: s_of(o, "label").unwrap_or_else(|| key.to_string()),
            pii: b_of(o, "pii"),
            authority: s_of(o, "authority"),
            string_date: b_of(o, "stringDate"),
            encoding: s_of(o, "encoding"),
            format: s_of(o, "format"),
            currency_field: s_of(o, "currencyField"),
            currency: s_of(o, "currency"),
            fns,
            lookup,
            path: s_of(o, "path"),
            hidden: b_of(o, "hidden"),
            label_map_path: s_of(o, "labelMapPath"),
        })
    }

    pub fn is_money(&self) -> bool {
        self.format.as_deref() == Some("MONEY")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Storage,
    Function,
}

#[derive(Debug, Clone)]
pub struct Source {
    pub name: String,
    pub kind: SourceKind,
    pub storage: Option<String>,
    pub function: Option<String>,
    pub label: String,
    pub scope_required: bool,
    pub authority: Option<String>,
    pub fields: IndexMap<String, Field>,
    pub segments: Obj,
    pub result_path: Option<String>,
    pub columns: IndexMap<String, Field>,
    /// A FUNCTION source's allowed params with their defaults.
    pub params: Obj,
    /// The param a FUNCTION source receives the scope in, when it takes one.
    pub scope_param: Option<String>,
    /// The params a spec may set (`allowedParams`; else every key of `params`).
    pub allowed_params: Vec<String>,
    /// Where a FUNCTION source's answer holds the full row count (`totalPath`).
    pub total_path: Option<String>,
    /// Usable only as a label lookup, never as a report's source.
    pub lookup_only: bool,
    /// P1b (CONTRACT 8.0): the row link template, the "View all" link, a function source's paging.
    pub link: Option<Value>,
    pub more_link: Option<Value>,
    pub paging: Option<Value>,
    /// P1b (CONTRACT 8.1): what View records may show.
    pub records: Option<RecordsDef>,
    pub raw: Value,
}

/// A source's `records`: the fields View records shows, its default sort, the row link, and who
/// may see records at all (`authorityAny`: any one of them; none listed is everyone).
#[derive(Debug, Clone)]
pub struct RecordsDef {
    pub fields: Vec<String>,
    pub sort: Vec<(String, bool)>,
    pub link: Option<Value>,
    pub authority_any: Vec<String>,
}

fn catalog_err<T>(path: impl Into<String>, message: impl Into<String>) -> R<T> {
    err("SOURCE_FAILED", path, message)
}

fn catalog_keys(o: &Obj, known: &[&str], path: &str) -> R<()> {
    match o.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => catalog_err(format!("{path}.{k}"), format!("The catalog's {path} has '{k}', which is not one of {}.", known.join(", "))),
        None => Ok(()),
    }
}

/// A link (`link`, `moreLink`, `countLink`, `records.link`): `{"path": "/caseView/{_id}", "label"?}`.
/// The path is inside the app (starts with one `/`); its `{placeholders}` are the UI's to fill.
pub fn check_link(v: &Value, path: &str) -> R<Value> {
    let Value::Object(o) = v else { return catalog_err(path, format!("The catalog's {path} must be an object like {{\"path\": \"/caseView/{{_id}}\"}}.")) };
    catalog_keys(o, &["path", "label"], path)?;
    let Some(p) = s_of(o, "path") else { return catalog_err(format!("{path}.path"), format!("The catalog's {path} names no path.")) };
    if !p.starts_with('/') || p.starts_with("//") || p.contains('\\') || p.chars().any(char::is_control) {
        return catalog_err(format!("{path}.path"), format!("The catalog's {path}.path '{p}' must be a path inside the app, starting with one /."));
    }
    if o.get("label").is_some_and(|l| !l.is_string()) {
        return catalog_err(format!("{path}.label"), format!("The catalog's {path}.label must be a text."));
    }
    Ok(v.clone())
}

fn check_paging(v: &Value, path: &str) -> R<Value> {
    let Value::Object(o) = v else { return catalog_err(path, format!("The catalog's {path} must be an object like {{\"param\": \"page\", \"size\": 20}}.")) };
    catalog_keys(o, &["param", "size"], path)?;
    if !s_of(o, "param").is_some_and(|p| is_alias(&p)) {
        return catalog_err(format!("{path}.param"), format!("The catalog's {path}.param must name a param (letters, digits and _)."));
    }
    match o.get("size") {
        None | Some(Value::Null) => {}
        Some(Value::Number(n)) if n.as_u64().is_some_and(|n| (1..=TABLE_ROWS as u64).contains(&n)) => {}
        Some(_) => return catalog_err(format!("{path}.size"), format!("The catalog's {path}.size must be a whole number from 1 to {TABLE_ROWS}.")),
    }
    Ok(v.clone())
}

/// `[{"by": "openedAt", "dir": "DESC"}]` (`field` is taken for `by`).
fn parse_sort_list(v: &Value, path: &str, refuse: fn(String, String) -> ReportError) -> R<Vec<(String, bool)>> {
    let Value::Array(a) = v else { return Err(refuse(path.to_string(), format!("{path} must be a list."))) };
    if a.len() > MAX_SORT {
        return Err(refuse(path.to_string(), format!("{path} takes at most {MAX_SORT} entries.")));
    }
    let mut out = Vec::new();
    for (i, e) in a.iter().enumerate() {
        let p = format!("{path}[{i}]");
        let Value::Object(o) = e else { return Err(refuse(p.clone(), format!("{p} must be an object like {{\"by\": \"openedAt\", \"dir\": \"DESC\"}}."))) };
        if let Some(k) = o.keys().find(|k| !["by", "field", "dir"].contains(&k.as_str())) {
            return Err(refuse(format!("{p}.{k}"), format!("'{k}' is not something a sort takes (by, dir).")));
        }
        let Some(by) = s_of(o, "by").or_else(|| s_of(o, "field")) else { return Err(refuse(format!("{p}.by"), format!("{p} names no field."))) };
        let dir = s_of(o, "dir").unwrap_or_else(|| "ASC".into());
        if !dir.eq_ignore_ascii_case("ASC") && !dir.eq_ignore_ascii_case("DESC") {
            return Err(refuse(format!("{p}.dir"), format!("{p}.dir must be ASC or DESC.")));
        }
        out.push((by, dir.eq_ignore_ascii_case("DESC")));
    }
    Ok(out)
}

fn check_records(v: &Value, fields: &IndexMap<String, Field>, path: &str) -> R<RecordsDef> {
    let Value::Object(o) = v else { return catalog_err(path, format!("The catalog's {path} must be an object with fields.")) };
    catalog_keys(o, &["fields", "sort", "link", "authorityAny"], path)?;
    let names = match o.get("fields") {
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_RECORD_FIELDS => a,
        _ => return catalog_err(format!("{path}.fields"), format!("The catalog's {path}.fields must list 1 to {MAX_RECORD_FIELDS} fields.")),
    };
    let mut list = Vec::new();
    for (i, n) in names.iter().enumerate() {
        match n.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) if !list.iter().any(|x| x == s) => list.push(s.to_string()),
            _ => return catalog_err(format!("{path}.fields[{i}]"), format!("The catalog's {path}.fields[{i}] must be a field name, listed once.")),
        }
    }
    let sort = match o.get("sort") {
        None | Some(Value::Null) => Vec::new(),
        Some(s) => parse_sort_list(s, &format!("{path}.sort"), |p, m| ReportError::new("SOURCE_FAILED", p, m))?,
    };
    for (i, (by, _)) in sort.iter().enumerate() {
        if !fields.contains_key(by) {
            return catalog_err(format!("{path}.sort[{i}].by"), format!("The catalog's {path}.sort names '{by}', which is not a field of the source."));
        }
    }
    let link = match o.get("link") {
        None | Some(Value::Null) => None,
        Some(l) => Some(check_link(l, &format!("{path}.link"))?),
    };
    let authority_any = match o.get("authorityAny") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) if a.iter().all(|x| x.as_str().is_some_and(|s| !s.trim().is_empty())) => {
            a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).collect()
        }
        Some(_) => return catalog_err(format!("{path}.authorityAny"), format!("The catalog's {path}.authorityAny must be a list of authorities.")),
    };
    Ok(RecordsDef { fields: list, sort, link, authority_any })
}

/// `hierarchies: {"location": {"label": "Location", "levels": ["productId", "tower", "unit"]}}`:
/// the UI drills down them; the runner checks only their shape (each level is checked as a field
/// when a spec uses it).
fn check_hierarchies(v: &Value) -> R<()> {
    let path = "catalog.hierarchies";
    let Value::Object(o) = v else { return catalog_err(path, "The catalog's hierarchies must be an object of named hierarchies.") };
    for (name, h) in o {
        let p = format!("{path}.{name}");
        let Value::Object(ho) = h else { return catalog_err(p, format!("The hierarchy '{name}' must be an object with levels.")) };
        catalog_keys(ho, &["label", "levels"], &p)?;
        if ho.get("label").is_some_and(|l| !l.is_string()) {
            return catalog_err(format!("{p}.label"), format!("The hierarchy '{name}' label must be a text."));
        }
        let levels: Vec<&str> = match ho.get("levels") {
            Some(Value::Array(a)) => a.iter().filter_map(|l| l.as_str().map(str::trim).filter(|s| !s.is_empty())).collect(),
            _ => Vec::new(),
        };
        let listed = ho.get("levels").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
        let unique = levels.iter().enumerate().all(|(i, l)| !levels[..i].contains(l));
        if levels.len() < 2 || levels.len() != listed || !unique {
            return catalog_err(format!("{p}.levels"), format!("The hierarchy '{name}' needs 2 or more levels, each a field name listed once."));
        }
    }
    Ok(())
}

/// `groups: {"dashboard": {"label": "Dashboard", "order": 1, "authorityAny": [...]}}`: the app's
/// report groups. The app trims them to the caller; the runner checks only their shape. Ids that
/// start with `u_` belong to user groups, so an app group may not use one.
fn check_groups(v: &Value) -> R<Vec<String>> {
    let path = "catalog.groups";
    let Value::Object(o) = v else { return catalog_err(path, "The catalog's groups must be an object of named groups.") };
    let mut ids = Vec::new();
    for (id, g) in o {
        let p = format!("{path}.{id}");
        if id.trim().is_empty() || id.trim() != id || id.starts_with("u_") || id.chars().any(char::is_control) {
            return catalog_err(p, format!("The group id '{id}' must be a plain name that does not start with u_ (user groups use u_)."));
        }
        let Value::Object(go) = g else { return catalog_err(p, format!("The group '{id}' must be an object with a label.")) };
        catalog_keys(go, &["label", "order", "authorityAny"], &p)?;
        match go.get("label") {
            Some(Value::String(l)) if !l.trim().is_empty() && l.chars().count() <= 40 => {}
            _ => return catalog_err(format!("{p}.label"), format!("The group '{id}' needs a label of 1 to 40 characters.")),
        }
        match go.get("order") {
            None | Some(Value::Null) => {}
            Some(Value::Number(n)) if n.as_f64().is_some_and(f64::is_finite) => {}
            Some(_) => return catalog_err(format!("{p}.order"), format!("The group '{id}' order must be a number.")),
        }
        match go.get("authorityAny") {
            None | Some(Value::Null) => {}
            Some(Value::Array(a)) if a.iter().all(|x| x.as_str().is_some_and(|s| !s.trim().is_empty())) => {}
            Some(_) => return catalog_err(format!("{p}.authorityAny"), format!("The group '{id}' authorityAny must be a list of authorities.")),
        }
        ids.push(id.clone());
    }
    Ok(ids)
}

/// The catalog the app hands in (already trimmed to the caller).
#[derive(Debug, Clone)]
pub struct Catalog {
    pub app: Option<String>,
    pub client_code: Option<String>,
    pub zone: Zone,
    pub time_zone: String,
    pub locale: Option<String>,
    pub fy_start: u32,
    pub currency: Option<String>,
    pub sources: Obj,
}

impl Catalog {
    pub fn parse(v: &Value) -> R<Catalog> {
        let Value::Object(o) = v else { return err("SOURCE_FAILED", "catalog", "The catalog is not an object.") };
        let time_zone = s_of(o, "timeZone").unwrap_or_else(|| "UTC".into());
        let Some(zone) = Zone::parse(&time_zone) else {
            return err("SOURCE_FAILED", "catalog.timeZone", format!("The catalog time zone '{time_zone}' is not known."));
        };
        let fy_start = match o.get("fyStartMonth") {
            None | Some(Value::Null) => 1,
            Some(Value::Number(n)) if n.as_u64().is_some_and(|m| (1..=12).contains(&m)) => n.as_u64().unwrap_or(1) as u32,
            Some(_) => return err("SOURCE_FAILED", "catalog.fyStartMonth", "The catalog fyStartMonth must be 1 to 12."),
        };
        let sources = match o.get("sources") {
            Some(Value::Object(s)) => s.clone(),
            _ => Obj::new(),
        };
        if let Some(h) = o.get("hierarchies").filter(|h| !h.is_null()) {
            check_hierarchies(h)?;
        }
        let groups = match o.get("groups").filter(|g| !g.is_null()) {
            Some(g) => Some(check_groups(g)?),
            None => None,
        };
        if let Some(Value::Array(defaults)) = o.get("defaults") {
            for (i, d) in defaults.iter().enumerate() {
                if let Some(l) = d.get("countLink").filter(|l| !l.is_null()) {
                    check_link(l, &format!("catalog.defaults[{i}].countLink"))?;
                }
                // A default's `group` (missing = "dashboard") names one of the catalog's groups.
                match d.get("group") {
                    None | Some(Value::Null) => {}
                    Some(Value::String(g)) if !g.trim().is_empty() => {
                        if groups.as_ref().is_some_and(|ids| !ids.iter().any(|x| x == g)) {
                            return catalog_err(format!("catalog.defaults[{i}].group"), format!("The default's group '{g}' is not one of the catalog's groups."));
                        }
                    }
                    Some(_) => return catalog_err(format!("catalog.defaults[{i}].group"), "A default's group must be a group id (text)."),
                }
            }
        }
        Ok(Catalog {
            app: s_of(o, "app"),
            client_code: s_of(o, "clientCode"),
            zone,
            time_zone,
            locale: s_of(o, "locale"),
            fy_start,
            currency: s_of(o, "currency"),
            sources,
        })
    }

    pub fn source(&self, name: &str) -> R<Source> {
        let Some(Value::Object(o)) = self.sources.get(name) else {
            return err("UNKNOWN_SOURCE", "source", format!("There is no report source '{name}' you can use."));
        };
        let path = format!("catalog.sources.{name}");
        let kind = match s_of(o, "kind").as_deref().unwrap_or("STORAGE") {
            "STORAGE" => SourceKind::Storage,
            "FUNCTION" => SourceKind::Function,
            other => return err("SOURCE_FAILED", path, format!("The source '{name}' has an unknown kind '{other}'.")),
        };
        let mut fields = IndexMap::new();
        if let Some(Value::Object(f)) = o.get("fields") {
            for (k, v) in f {
                fields.insert(k.clone(), Field::parse(k, v, &self.sources, &format!("{path}.fields.{k}"))?);
            }
        }
        let mut columns = IndexMap::new();
        if let Some(Value::Object(f)) = o.get("columns") {
            for (k, v) in f {
                columns.insert(k.clone(), Field::parse(k, v, &self.sources, &format!("{path}.columns.{k}"))?);
            }
        }
        let storage = s_of(o, "storage");
        let function = s_of(o, "function");
        if kind == SourceKind::Storage && storage.is_none() {
            return err("SOURCE_FAILED", path, format!("The source '{name}' names no storage."));
        }
        if kind == SourceKind::Function && function.as_deref().is_none_or(|f| !f.contains('.')) {
            return err("SOURCE_FAILED", path, format!("The source '{name}' names no function (Namespace.name)."));
        }
        // `params`: fixed values (an object) or the names a spec may set (a list).
        let (params, listed): (Obj, Vec<String>) = match o.get("params") {
            Some(Value::Object(p)) => (p.clone(), p.keys().cloned().collect()),
            Some(Value::Array(a)) => (Obj::new(), a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect()),
            _ => (Obj::new(), Vec::new()),
        };
        let allowed_params = match o.get("allowedParams") {
            Some(Value::Array(a)) => a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect(),
            _ => listed,
        };
        let opt_link = |k: &str| -> R<Option<Value>> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(l) => check_link(l, &format!("{path}.{k}")).map(Some),
            }
        };
        let link = opt_link("link")?;
        let more_link = opt_link("moreLink")?;
        let paging = match o.get("paging") {
            None | Some(Value::Null) => None,
            Some(p) => Some(check_paging(p, &format!("{path}.paging"))?),
        };
        let records = match o.get("records") {
            None | Some(Value::Null) => None,
            Some(r) => Some(check_records(r, &fields, &format!("{path}.records"))?),
        };
        let segments = match o.get("segments") {
            Some(Value::Object(s)) => s.clone(),
            _ => Obj::new(),
        };
        for (k, seg) in &segments {
            if let Some(l) = seg.get("countLink").filter(|l| !l.is_null()) {
                check_link(l, &format!("{path}.segments.{k}.countLink"))?;
            }
        }
        Ok(Source {
            name: name.to_string(),
            kind,
            storage,
            function,
            label: s_of(o, "label").unwrap_or_else(|| name.to_string()),
            scope_required: s_of(o, "scope").as_deref() == Some("REQUIRED"),
            authority: s_of(o, "authority"),
            fields,
            segments,
            result_path: s_of(o, "resultPath"),
            columns,
            params,
            scope_param: s_of(o, "scopeParam"),
            allowed_params,
            total_path: s_of(o, "totalPath"),
            lookup_only: b_of(o, "lookupOnly"),
            link,
            more_link,
            paging,
            records,
            raw: Value::Object(o.clone()),
        })
    }
}

/// A validated measure.
#[derive(Debug, Clone)]
pub struct Measure {
    pub alias: String,
    pub func: String,
    pub field: Option<Field>,
    pub label: String,
    pub format: String,
    /// `measures[].segment`: the measure counts only the rows that also meet this segment's
    /// condition (name, condition).
    pub segment: Option<(String, Value)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedOp {
    Ratio,
    Difference,
    Percent,
}

#[derive(Debug, Clone)]
pub struct Derived {
    pub alias: String,
    pub op: DerivedOp,
    pub a: String,
    pub b: String,
    pub label: String,
    pub format: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub alias: String,
    pub field: Field,
    pub bucket: Option<Bucket>,
    pub fy: bool,
}

impl Group {
    /// A label column (`<as>_label`) goes with it.
    pub fn labelled(&self) -> bool {
        self.bucket.is_some() || self.field.lookup.is_some() || self.field.label_map_path.is_some()
    }
}

/// What the runner executes.
#[derive(Debug, Clone)]
pub struct Plan {
    pub source: Source,
    pub segment_label: Option<String>,
    pub measures: Vec<Measure>,
    pub derived: Vec<Derived>,
    pub group_by: Vec<Group>,
    /// The AbstractCondition: segment AND filters AND scope; null for none.
    pub condition: Value,
    /// The first period filter, for the output.
    pub period: Option<Period>,
    pub sort: Vec<(String, bool)>,
    pub limit: Option<usize>,
    pub view_type: String,
    pub view: Value,
    pub top_n: Option<usize>,
    /// A list of rows rather than an aggregate (LIST or TABLE without measures or group by).
    pub records: bool,
    pub list_fields: Vec<Field>,
    pub params: Obj,
    /// Currencies a filter pins, by currency field.
    pub pinned_currency: IndexMap<String, String>,
    pub shape: Shape,
    /// `compare` (P1b): the second run's period and condition.
    pub compare: Option<Compare>,
    /// `records` (P1b, View records): the page asked for; `list_fields` are the source's records fields.
    pub records_page: Option<RecordsPage>,
    /// The catalog's links for this run (`row`, `more`, `count`), passed through for the UI.
    pub links: Obj,
    /// A function source's `paging`, passed through.
    pub paging: Option<Value>,
}

/// `compare: {"to": "PREVIOUS_PERIOD" | "SAME_PERIOD_LAST_YEAR"}`, resolved.
#[derive(Debug, Clone)]
pub struct Compare {
    pub to: String,
    pub period: Period,
    /// segment AND filters (the period filter moved to the compare period) AND scope.
    pub condition: Value,
}

/// `records: {"page": 0, "size": 100, "export": false}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordsPage {
    pub page: usize,
    pub size: usize,
    pub export: bool,
}

/// The suffixes compare adds to every value column.
pub const CMP_SUFFIX: &str = "_cmp";
pub const DELTA_SUFFIX: &str = "_delta_pct";

impl Plan {
    /// Every value column alias: measures then derived.
    pub fn value_aliases(&self) -> Vec<String> {
        self.measures.iter().map(|m| m.alias.clone()).chain(self.derived.iter().map(|d| d.alias.clone())).collect()
    }

    /// The plan the compare run executes: the same report over the compare period.
    pub fn for_compare(&self) -> Option<Plan> {
        let c = self.compare.as_ref()?;
        let mut p = self.clone();
        p.condition = c.condition.clone();
        p.period = Some(c.period.clone());
        p.compare = None;
        Some(p)
    }
}

/// What validation needs beyond the spec and the catalog.
pub struct Caller<'a> {
    pub authorities: &'a [String],
    pub now: DateTime<Utc>,
}

impl Caller<'_> {
    fn allowed(&self, authority: Option<&str>) -> bool {
        match authority {
            None => true,
            Some(a) => crate::authorities::has_authority(Some(a), self.authorities).unwrap_or(false),
        }
    }
}

fn is_alias(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 40 && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn default_alias(field: &str) -> String {
    let a: String = field.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if a.as_bytes().first().is_some_and(|c| c.is_ascii_digit()) {
        format!("_{a}")
    } else {
        a
    }
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn humanize(alias: &str) -> String {
    let mut out = String::new();
    for (i, ch) in alias.chars().enumerate() {
        if ch == '_' {
            out.push(' ');
        } else if i > 0 && ch.is_ascii_uppercase() {
            out.push(' ');
            out.push(ch.to_ascii_lowercase());
        } else if i == 0 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn array<'a>(spec: &'a Obj, key: &str) -> R<&'a [Value]> {
    match spec.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a.as_slice()),
        Some(_) => err("BAD_KIND", key, format!("{key} must be a list.")),
    }
}

fn obj<'a>(v: &'a Value, path: &str) -> R<&'a Obj> {
    match v {
        Value::Object(o) => Ok(o),
        _ => err("BAD_KIND", path, format!("{path} must be an object.")),
    }
}

fn scalar(v: &Value, path: &str) -> R<Value> {
    match v {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => Ok(v.clone()),
        _ => err("BAD_KIND", path, format!("{path} must be a text, a number or true/false.")),
    }
}

/// Refuses a key the runner does not know, so nothing in a spec is ever silently ignored.
fn known_keys(o: &Obj, known: &[&str], path: &str, what: &str) -> R<()> {
    match o.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => err("BAD_KIND", format!("{path}.{k}"), format!("'{k}' is not something {what} takes ({}).", known.join(", "))),
        None => Ok(()),
    }
}

const FNS: [&str; 6] = ["COUNT", "COUNT_DISTINCT", "SUM", "AVG", "MIN", "MAX"];

fn fn_allowed_for(kind: FieldKind, f: &str) -> bool {
    match kind {
        FieldKind::Measure => true,
        FieldKind::Date => matches!(f, "COUNT" | "COUNT_DISTINCT" | "MIN" | "MAX"),
        FieldKind::Dimension => matches!(f, "COUNT" | "COUNT_DISTINCT"),
    }
}

/// A catalog field the caller may use, by key.
fn source_field(source: &Source, caller: &Caller, key: &str, path: &str) -> R<Field> {
    let Some(f) = source.fields.get(key) else {
        return err("UNKNOWN_FIELD", path, format!("{} has no field '{key}' you can use.", source.label));
    };
    if !caller.allowed(f.authority.as_deref()) {
        return err("FORBIDDEN_FIELD", path, format!("You cannot report on {}.", f.label));
    }
    Ok(f.clone())
}

/// The rows a spec reads: its segment and filters (the scope is added by [`and_all`]).
struct Where {
    conditions: Vec<Value>,
    segment_label: Option<String>,
    segment_count_link: Option<Value>,
    /// The first period filter, for the output.
    period: Option<Period>,
    /// Every period filter: its condition's index (none for ALL_TIME), its field, its period.
    periods: Vec<(Option<usize>, Field, Period)>,
    pinned_currency: IndexMap<String, String>,
}

fn where_of(spec: &Obj, source: &Source, catalog: &Catalog, caller: &Caller) -> R<Where> {
    let field = |key: &str, path: &str| source_field(source, caller, key, path);
    let mut conditions: Vec<Value> = Vec::new();
    let mut segment_label = None;
    let mut segment_count_link = None;
    if let Some(seg) = s_of(spec, "segment") {
        let Some(Value::Object(so)) = source.segments.get(&seg) else {
            return err("UNKNOWN_SEGMENT", "segment", format!("{} has no segment '{seg}'.", source.label));
        };
        segment_label = s_of(so, "label").or(Some(seg.clone()));
        segment_count_link = so.get("countLink").filter(|l| !l.is_null()).cloned();
        match so.get("condition") {
            Some(c @ Value::Object(co)) if !co.is_empty() => conditions.push(c.clone()),
            _ => {}
        }
    }

    let filters_in = array(spec, "filters")?;
    let mut period_out = None;
    let mut periods = Vec::new();
    let mut pinned_currency = IndexMap::new();
    for (i, fv) in filters_in.iter().enumerate() {
        let path = format!("filters[{i}]");
        let fo = obj(fv, &path)?;
        known_keys(fo, &["field", "op", "value", "values", "period", "from", "to", "label"], &path, "a filter")?;
        let Some(key) = s_of(fo, "field") else { return err("UNKNOWN_FIELD", format!("{path}.field"), "Each filter names a field.") };
        // A filter on a money measure's currency field pins the currency; that field need not be
        // a catalog field of its own.
        let currency_column = source.fields.values().any(|f| f.currency_field.as_deref() == Some(key.as_str())) && !source.fields.contains_key(&key);
        let f = if currency_column {
            Field {
                key: key.clone(),
                column: key.clone(),
                kind: FieldKind::Dimension,
                label: "Currency".into(),
                pii: false,
                authority: None,
                string_date: false,
                encoding: None,
                format: None,
                currency_field: None,
                currency: None,
                fns: None,
                lookup: None,
                path: None,
                hidden: false,
                label_map_path: None,
            }
        } else {
            field(&key, &format!("{path}.field"))?
        };
        if let Some(p) = s_of(fo, "period") {
            if f.kind != FieldKind::Date {
                return err("BAD_KIND", format!("{path}.field"), format!("{} is not a date, so it takes no period.", f.label));
            }
            let today = catalog.zone.today(caller.now);
            let custom = match (s_of(fo, "from"), s_of(fo, "to")) {
                (Some(a), Some(b)) => Some((a, b)),
                _ => None,
            };
            let resolved = period::resolve(&p, today, catalog.fy_start, custom.as_ref().map(|(a, b)| (a.as_str(), b.as_str())))
                .map_err(|why| ReportError::new("BAD_PERIOD", format!("{path}.period"), why))?;
            let slot = match period_condition(&f, &resolved, &catalog.zone) {
                Some(c) => {
                    conditions.push(c);
                    Some(conditions.len() - 1)
                }
                None => None,
            };
            if period_out.is_none() {
                period_out = Some(resolved.clone());
            }
            periods.push((slot, f, resolved));
            continue;
        }
        let op = s_of(fo, "op").unwrap_or_else(|| "EQ".into()).to_uppercase();
        let col = f.column.clone();
        let one = |fo: &Obj| -> R<Value> {
            match (fo.get("value"), fo.get("values")) {
                (Some(v), _) if !v.is_null() => scalar(v, &format!("{path}.value")),
                (_, Some(Value::Array(a))) if a.len() == 1 => scalar(&a[0], &format!("{path}.values[0]")),
                _ => err("BAD_KIND", format!("{path}.value"), format!("{op} needs one value.")),
            }
        };
        let many = |fo: &Obj| -> R<Vec<Value>> {
            match fo.get("values") {
                Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_IN_VALUES => {
                    a.iter().enumerate().map(|(j, v)| scalar(v, &format!("{path}.values[{j}]"))).collect()
                }
                Some(Value::Array(a)) if a.len() > MAX_IN_VALUES => err("TOO_MANY", format!("{path}.values"), format!("{op} takes at most {MAX_IN_VALUES} values.")),
                _ => err("BAD_KIND", format!("{path}.values"), format!("{op} needs a list of values.")),
            }
        };
        let c = match op.as_str() {
            "EQ" | "NE" => {
                let v = one(fo)?;
                if currency_column || source.fields.values().any(|m| m.currency_field.as_deref() == Some(col.as_str())) {
                    if op == "EQ" {
                        if let Some(s) = v.as_str() {
                            pinned_currency.insert(col.clone(), s.to_string());
                        }
                    }
                }
                json!({"field": col, "operator": "EQUALS", "value": v, "negate": op == "NE"})
            }
            "IN" | "NOT_IN" => {
                let vals = many(fo)?;
                if op == "IN" && vals.len() == 1 {
                    if let Some(s) = vals[0].as_str() {
                        if source.fields.values().any(|m| m.currency_field.as_deref() == Some(col.as_str())) {
                            pinned_currency.insert(col.clone(), s.to_string());
                        }
                    }
                }
                json!({"field": col, "operator": "IN", "multiValue": vals, "negate": op == "NOT_IN"})
            }
            "GT" => json!({"field": col, "operator": "GREATER_THAN", "value": one(fo)?}),
            "GTE" => json!({"field": col, "operator": "GREATER_THAN_EQUAL", "value": one(fo)?}),
            "LT" => json!({"field": col, "operator": "LESS_THAN", "value": one(fo)?}),
            "LTE" => json!({"field": col, "operator": "LESS_THAN_EQUAL", "value": one(fo)?}),
            "BETWEEN" => match fo.get("values") {
                Some(Value::Array(a)) if a.len() == 2 => json!({"field": col, "operator": "BETWEEN",
                    "value": scalar(&a[0], &format!("{path}.values[0]"))?, "toValue": scalar(&a[1], &format!("{path}.values[1]"))?}),
                _ => return err("BAD_KIND", format!("{path}.values"), "BETWEEN needs values: [low, high]."),
            },
            "IS_NULL" => json!({"field": col, "operator": "IS_NULL"}),
            "NOT_NULL" => json!({"field": col, "operator": "IS_NULL", "negate": true}),
            other => {
                return err(
                    "BAD_KIND",
                    format!("{path}.op"),
                    format!("'{other}' is not a filter: EQ, NE, IN, NOT_IN, GT, GTE, LT, LTE, BETWEEN, IS_NULL, NOT_NULL, or a period."),
                )
            }
        };
        conditions.push(c);
    }
    Ok(Where { conditions, segment_label, segment_count_link, period: period_out, periods, pinned_currency })
}

/// The conditions AND the scope, as one AbstractCondition (null for none).
fn and_all(mut conditions: Vec<Value>, scope: &Value) -> Value {
    if scope.as_object().is_some_and(|o| !o.is_empty()) {
        conditions.push(scope.clone());
    }
    match conditions.len() {
        0 => Value::Null,
        1 => conditions.pop().unwrap_or(Value::Null),
        _ => json!({"operator": "AND", "conditions": conditions}),
    }
}

/// `compare`: one period filter (not ALL_TIME) moved to the compare period.
fn compare_of(spec: &Obj, w: &Where, catalog: &Catalog, scope: &Value) -> R<Option<Compare>> {
    let v = match spec.get("compare") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let o = obj(v, "compare")?;
    known_keys(o, &["to"], "compare", "compare")?;
    let to = s_of(o, "to").unwrap_or_default();
    if !period::COMPARE_TO.contains(&to.as_str()) {
        return err("BAD_PERIOD", "compare.to", format!("'{to}' is not a comparison: {}.", period::COMPARE_TO.join(" or ")));
    }
    let (slot, field, p) = match w.periods.as_slice() {
        [one] => one,
        [] => return err("BAD_PERIOD", "compare", "A comparison needs a period filter (a date with a period)."),
        more => return err("BAD_PERIOD", "compare", format!("A comparison needs exactly one period filter; this report has {}.", more.len())),
    };
    let Some(slot) = slot else {
        return err("BAD_PERIOD", "compare", "All time has nothing to compare with; pick another period.");
    };
    let cp = period::compare_period(p, &to).map_err(|why| ReportError::new("BAD_PERIOD", "compare.to", why))?;
    let mut conditions = w.conditions.clone();
    if let Some(c) = period_condition(field, &cp, &catalog.zone) {
        conditions[*slot] = c;
    }
    Ok(Some(Compare { to, period: cp, condition: and_all(conditions, scope) }))
}

/// The links of this run, for the UI: the row link, "View all", the KPI count link.
fn links_of(row: Option<&Value>, source: &Source, count: Option<&Value>) -> Obj {
    let mut m = Obj::new();
    for (k, v) in [("row", row), ("more", source.more_link.as_ref()), ("count", count)] {
        if let Some(v) = v {
            m.insert(k.to_string(), v.clone());
        }
    }
    m
}

/// Validates `spec` against `catalog` for `caller`; `scope` is the app wrapper's row scope.
pub fn validate(spec: &Value, catalog: &Catalog, scope: &Value, caller: &Caller) -> R<Plan> {
    let spec = obj(spec, "spec")?;
    match spec.get("v") {
        None | Some(Value::Null) => {}
        Some(v) if v.as_i64() == Some(1) => {}
        Some(_) => return err("BAD_KIND", "v", "Only spec version 1 is known."),
    }
    let Some(source_name) = s_of(spec, "source") else { return err("UNKNOWN_SOURCE", "source", "The spec names no source.") };
    let source = catalog.source(&source_name)?;
    if source.lookup_only {
        return err("UNKNOWN_SOURCE", "source", format!("{} is only used for labels, not as a report source.", source.label));
    }
    if !caller.allowed(source.authority.as_deref()) {
        return err("FORBIDDEN_FIELD", "source", format!("You cannot report on {}.", source.label));
    }
    let scope_given = !scope.is_null();
    if scope_given && !scope.is_object() {
        return err("BAD_KIND", "scope", "The scope must be a condition object or null.");
    }
    if source.scope_required && !scope_given {
        return err("SCOPE_REQUIRED", "scope", format!("The source {} needs a row scope from the app, and none was given.", source.label));
    }

    let measures_in = array(spec, "measures")?;
    let group_in = array(spec, "groupBy")?;
    let filters_in = array(spec, "filters")?;
    let derived_in = array(spec, "derived")?;
    let sort_in = array(spec, "sort")?;
    for (key, n, max) in [
        ("measures", measures_in.len(), MAX_MEASURES),
        ("groupBy", group_in.len(), MAX_GROUP_BY),
        ("filters", filters_in.len(), MAX_FILTERS),
        ("derived", derived_in.len(), MAX_DERIVED),
        ("sort", sort_in.len(), MAX_SORT),
    ] {
        if n > max {
            return err("TOO_MANY", key, format!("A report takes at most {max} {key}; this one has {n}."));
        }
    }

    if spec.get("records").is_some_and(|r| !r.is_null()) {
        return validate_records(spec, source, catalog, scope, caller);
    }

    let view = match spec.get("view") {
        None | Some(Value::Null) => json!({"type": "TABLE"}),
        Some(v) => Value::Object(obj(v, "view")?.clone()),
    };
    let view_type = view.get("type").and_then(Value::as_str).unwrap_or("TABLE").to_string();
    if shape::rule(&view_type).is_none() {
        return err("BAD_VIEW", "view.type", shape::check(&view_type, Shape { group_by: 0, values: 0 }).unwrap_err());
    }
    let top_n = match view.pointer("/style/topN") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) if n.as_u64().is_some_and(|n| n >= 1) => Some((n.as_u64().unwrap_or(1) as usize).min(CHART_GROUPS)),
        Some(_) => return err("BAD_VIEW", "view.style.topN", "topN must be a whole number of 1 or more."),
    };
    let limit = match spec.get("limit") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) if n.as_u64().is_some_and(|n| n >= 1) => Some(n.as_u64().unwrap_or(1) as usize),
        Some(_) => return err("BAD_KIND", "limit", "limit must be a whole number of 1 or more."),
    };

    if source.kind == SourceKind::Function {
        if spec.get("compare").is_some_and(|c| !c.is_null()) {
            return err("BAD_PERIOD", "compare", format!("{} is a function source: it has no period filter to compare.", source.label));
        }
        return validate_function_source(spec, source, catalog, scope, caller, view, view_type, top_n, limit, derived_in, sort_in);
    }

    let field = |key: &str, path: &str| source_field(&source, caller, key, path);

    let mut aliases: Vec<String> = Vec::new();
    let mut take_alias = |a: &str, path: &str| -> R<()> {
        if !is_alias(a) {
            return err("BAD_KIND", path, format!("'{a}' is not a usable name: letters, digits and _ only, starting with a letter."));
        }
        if aliases.iter().any(|x| x == a) || a == "currency" || a.ends_with("_label") {
            return err("BAD_KIND", path, format!("The name '{a}' is used twice or is kept for the runner."));
        }
        aliases.push(a.to_string());
        Ok(())
    };

    // Segment and filters.
    let w = where_of(spec, &source, catalog, caller)?;
    let segment_label = w.segment_label.clone();

    // Group by.
    let mut group_by = Vec::new();
    for (i, g) in group_in.iter().enumerate() {
        let path = format!("groupBy[{i}]");
        let go = obj(g, &path)?;
        known_keys(go, &["field", "as", "bucket", "fy", "label"], &path, "a group by")?;
        let Some(key) = s_of(go, "field") else { return err("UNKNOWN_FIELD", format!("{path}.field"), "Each group by names a field.") };
        let f = field(&key, &format!("{path}.field"))?;
        if f.pii {
            return err("PII_GROUP", format!("{path}.field"), format!("{} is personal data, so it cannot be grouped or listed.", f.label));
        }
        if f.kind == FieldKind::Measure {
            return err("BAD_KIND", format!("{path}.field"), format!("{} is a measure; group by takes a dimension or a date.", f.label));
        }
        let bucket = match s_of(go, "bucket") {
            None if f.kind == FieldKind::Date => Some(Bucket::Day),
            None => None,
            Some(b) => {
                if f.kind != FieldKind::Date {
                    return err("BAD_KIND", format!("{path}.bucket"), format!("{} is not a date, so it takes no bucket.", f.label));
                }
                Some(Bucket::parse(&b).ok_or_else(|| {
                    ReportError::new("BAD_KIND", format!("{path}.bucket"), format!("'{b}' is not a bucket: DAY, WEEK, MONTH, QUARTER or YEAR."))
                })?)
            }
        };
        let alias = s_of(go, "as").unwrap_or_else(|| default_alias(&key));
        take_alias(&alias, &format!("{path}.as"))?;
        group_by.push(Group { alias, field: f, bucket, fy: b_of(go, "fy") });
    }

    // Measures.
    let mut measures = Vec::new();
    for (i, m) in measures_in.iter().enumerate() {
        let path = format!("measures[{i}]");
        let mo = obj(m, &path)?;
        known_keys(mo, &["fn", "field", "as", "label", "segment"], &path, "a measure")?;
        let measure_segment = match s_of(mo, "segment") {
            None => None,
            Some(name) => match source.segments.get(&name) {
                Some(Value::Object(so)) => Some((name.clone(), so.get("condition").cloned().unwrap_or(Value::Null), s_of(so, "label"))),
                _ => return err("UNKNOWN_SEGMENT", format!("{path}.segment"), format!("{} has no segment '{name}'.", source.label)),
            },
        };
        let func = s_of(mo, "fn").unwrap_or_default().to_uppercase();
        if !FNS.contains(&func.as_str()) {
            return err("FN_NOT_ALLOWED", format!("{path}.fn"), format!("'{func}' is not a measure function: {}.", FNS.join(", ")));
        }
        let f = match s_of(mo, "field") {
            None if func == "COUNT" => None,
            None => return err("UNKNOWN_FIELD", format!("{path}.field"), format!("{func} needs a field.")),
            Some(k) => Some(field(&k, &format!("{path}.field"))?),
        };
        if let Some(f) = &f {
            if !fn_allowed_for(f.kind, &func) || f.fns.as_ref().is_some_and(|l| !l.iter().any(|x| x == &func)) {
                return err("FN_NOT_ALLOWED", format!("{path}.fn"), format!("{func} cannot be used on {}.", f.label));
            }
        }
        let alias = s_of(mo, "as").unwrap_or_else(|| match &f {
            Some(f) => default_alias(&format!("{}_{}", func.to_lowercase(), f.key)),
            None => "count".into(),
        });
        take_alias(&alias, &format!("{path}.as"))?;
        let label = s_of(mo, "label").unwrap_or_else(|| match (&f, func.as_str()) {
            (None, _) => measure_segment.as_ref().and_then(|s| s.2.clone()).or_else(|| segment_label.clone()).unwrap_or_else(|| "Count".into()),
            (Some(f), "SUM") => f.label.clone(),
            (Some(f), "AVG") => format!("Average {}", lower_first(&f.label)),
            (Some(f), "MIN") => format!("Lowest {}", lower_first(&f.label)),
            (Some(f), "MAX") => format!("Highest {}", lower_first(&f.label)),
            (Some(f), "COUNT_DISTINCT") => format!("Distinct {}", lower_first(&f.label)),
            (Some(f), _) => format!("Count of {}", lower_first(&f.label)),
        });
        let format = match (&f, func.as_str()) {
            (_, "COUNT" | "COUNT_DISTINCT") => "NUMBER".to_string(),
            (Some(f), _) if f.kind == FieldKind::Date => "DATE".to_string(),
            (Some(f), _) => f.format.clone().unwrap_or_else(|| "NUMBER".into()),
            (None, _) => "NUMBER".into(),
        };
        let segment = measure_segment.map(|(n, c, _)| (n, c));
        measures.push(Measure { alias, func, field: f, label, format, segment });
    }

    // Derived.
    let mut derived: Vec<Derived> = Vec::new();
    for (i, d) in derived_in.iter().enumerate() {
        let path = format!("derived[{i}]");
        let o = obj(d, &path)?;
        known_keys(o, &["as", "label", "ratio", "difference", "percent"], &path, "a derived measure")?;
        let ops: Vec<(DerivedOp, &str)> = [(DerivedOp::Ratio, "ratio"), (DerivedOp::Difference, "difference"), (DerivedOp::Percent, "percent")]
            .into_iter()
            .filter(|(_, k)| o.contains_key(*k))
            .collect();
        let [(op, key)] = ops.as_slice() else {
            return err("BAD_KIND", path, "A derived measure has exactly one of ratio, difference or percent.");
        };
        let pair = match o.get(*key) {
            Some(Value::Array(a)) if a.len() == 2 => (a[0].as_str().unwrap_or("").to_string(), a[1].as_str().unwrap_or("").to_string()),
            _ => return err("BAD_KIND", format!("{path}.{key}"), format!("{key} takes two measure names, like [\"value\", \"bookings\"].")),
        };
        let fmt_of = |a: &str| -> Option<String> {
            measures.iter().find(|m| m.alias == a).map(|m| m.format.clone()).or_else(|| derived.iter().find(|x| x.alias == a).map(|x| x.format.clone()))
        };
        for (j, name) in [&pair.0, &pair.1].iter().enumerate() {
            if fmt_of(name).is_none() {
                return err("UNKNOWN_FIELD", format!("{path}.{key}[{j}]"), format!("'{name}' is not a measure of this report."));
            }
        }
        let alias = s_of(o, "as").unwrap_or_else(|| format!("{}_{}", key, derived.len() + 1));
        take_alias(&alias, &format!("{path}.as"))?;
        let (fa, fb) = (fmt_of(&pair.0).unwrap_or_default(), fmt_of(&pair.1).unwrap_or_default());
        let format = match op {
            DerivedOp::Percent => "PERCENT".to_string(),
            DerivedOp::Difference => fa,
            DerivedOp::Ratio if fa == "MONEY" && fb != "MONEY" => "MONEY".into(),
            DerivedOp::Ratio => "NUMBER".into(),
        };
        derived.push(Derived { label: s_of(o, "label").unwrap_or_else(|| humanize(&alias)), alias, op: *op, a: pair.0, b: pair.1, format });
    }

    // Records (a list of rows) or an aggregate.
    let records = measures.is_empty() && group_by.is_empty() && derived.is_empty() && shape::is_table(&view_type) && view_type != "CROSSTAB";
    let mut list_fields = Vec::new();
    if records {
        let wanted: Vec<(String, String)> = match spec.get("fields") {
            Some(Value::Array(a)) => a
                .iter()
                .enumerate()
                .map(|(i, v)| (v.as_str().unwrap_or("").to_string(), format!("fields[{i}]")))
                .collect(),
            _ => source
                .fields
                .values()
                .filter(|f| !f.pii && caller.allowed(f.authority.as_deref()))
                .map(|f| (f.key.clone(), String::new()))
                .collect(),
        };
        if wanted.len() > MAX_LIST_FIELDS && spec.get("fields").is_some() {
            return err("TOO_MANY", "fields", format!("A list shows at most {MAX_LIST_FIELDS} fields."));
        }
        for (key, path) in wanted.into_iter().take(MAX_LIST_FIELDS) {
            let f = field(&key, &path)?;
            if f.pii {
                return err("PII_GROUP", path, format!("{} is personal data, so it cannot be grouped or listed.", f.label));
            }
            list_fields.push(f);
        }
    }

    let compare = compare_of(spec, &w, catalog, scope)?;
    if compare.is_some() && records {
        return err("BAD_KIND", "compare", "A comparison needs measures; a list of rows has none.");
    }
    let condition = and_all(w.conditions.clone(), scope);

    // Sort.
    let output_aliases: Vec<String> = if records {
        list_fields.iter().map(|f| f.key.clone()).collect()
    } else {
        group_by.iter().map(|g| g.alias.clone()).chain(measures.iter().map(|m| m.alias.clone())).chain(derived.iter().map(|d| d.alias.clone())).collect()
    };
    if compare.is_some() {
        let values: Vec<String> = measures.iter().map(|m| m.alias.clone()).chain(derived.iter().map(|d| d.alias.clone())).collect();
        if let Some(a) = output_aliases.iter().find(|a| values.iter().any(|v| **a == format!("{v}{CMP_SUFFIX}") || **a == format!("{v}{DELTA_SUFFIX}"))) {
            return err("BAD_KIND", "compare", format!("The name '{a}' is kept for the comparison's columns; rename it."));
        }
    }
    let mut sort = Vec::new();
    for (i, so) in sort_in.iter().enumerate() {
        let path = format!("sort[{i}]");
        let o = obj(so, &path)?;
        known_keys(o, &["by", "dir"], &path, "a sort")?;
        let by = s_of(o, "by").unwrap_or_default();
        if !output_aliases.contains(&by) {
            return err("UNKNOWN_FIELD", format!("{path}.by"), format!("'{by}' is not a column of this report."));
        }
        let desc = s_of(o, "dir").is_some_and(|d| d.eq_ignore_ascii_case("DESC"));
        sort.push((by, desc));
    }

    // Two money measures whose currencies come from different columns cannot be split together.
    let currency_fields: Vec<&str> = measures
        .iter()
        .filter(|m| m.format == "MONEY")
        .filter_map(|m| m.field.as_ref().and_then(|f| f.currency_field.as_deref()))
        .collect();
    if currency_fields.windows(2).any(|w| w[0] != w[1]) {
        return err("MIXED_CURRENCY", "measures", "These money measures take their currency from different fields, so they cannot be shown together.");
    }
    let fixed: Vec<String> = measures
        .iter()
        .filter(|m| m.format == "MONEY")
        .map(|m| m.field.as_ref().and_then(|f| f.currency.clone()).or_else(|| catalog.currency.clone()).unwrap_or_default())
        .collect();
    if fixed.windows(2).any(|w| w[0] != w[1] && !w[0].is_empty() && !w[1].is_empty()) {
        return err("MIXED_CURRENCY", "measures", "These money measures are in different currencies, so they cannot be shown together.");
    }

    let shape = Shape { group_by: group_by.len(), values: measures.len() + derived.len() };
    shape::check(&view_type, shape).map_err(|why| ReportError::new("BAD_VIEW", "view.type", why))?;
    check_view_refs(&view, &output_aliases)?;
    let links = links_of(source.link.as_ref(), &source, w.segment_count_link.as_ref());

    Ok(Plan {
        source,
        segment_label,
        measures,
        derived,
        group_by,
        condition,
        period: w.period,
        sort,
        limit,
        view_type,
        view,
        top_n,
        records,
        list_fields,
        params: Obj::new(),
        pinned_currency: w.pinned_currency,
        shape,
        compare,
        records_page: None,
        links,
        paging: None,
    })
}

/// View records (P1b): a page of the source's rows, segment AND filters AND scope, only the
/// source's `records.fields` (personal data only when listed there; a field whose authority the
/// caller lacks, or that the trimmed catalog no longer has, is left out), plus `_id` always, once,
/// as a hidden column (for the row link; the catalog need not list it).
fn validate_records(spec: &Obj, source: Source, catalog: &Catalog, scope: &Value, caller: &Caller) -> R<Plan> {
    let def = match (&source.records, source.kind) {
        (Some(d), SourceKind::Storage) => d.clone(),
        _ => return err("RECORDS_NOT_ALLOWED", "records", format!("{} has no records to show.", source.label)),
    };
    if !def.authority_any.is_empty() && !def.authority_any.iter().any(|a| caller.allowed(Some(a))) {
        return err("RECORDS_NOT_ALLOWED", "records", format!("You cannot view the records of {}.", source.label));
    }
    for k in ["measures", "groupBy", "derived", "limit", "compare", "fields", "params"] {
        if spec.get(k).is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())) {
            return err("BAD_KIND", k, format!("View records takes source, segment, filters, sort and records, not {k}."));
        }
    }
    let ro = obj(spec.get("records").unwrap_or(&Value::Null), "records")?;
    known_keys(ro, &["page", "size", "export"], "records", "records")?;
    let export = match ro.get("export") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return err("BAD_KIND", "records.export", "records.export must be true or false."),
    };
    let cap = if export { RECORDS_EXPORT } else { RECORDS_PAGE };
    let whole = |k: &str, default: usize, min: u64| -> R<usize> {
        match ro.get(k) {
            None | Some(Value::Null) => Ok(default),
            Some(Value::Number(n)) if n.as_u64().is_some_and(|n| n >= min && n <= 1_000_000) => Ok(n.as_u64().unwrap_or(0) as usize),
            Some(_) => err("BAD_KIND", format!("records.{k}"), format!("records.{k} must be a whole number of {min} or more.")),
        }
    };
    let page = whole("page", 0, 0)?;
    let size = whole("size", cap, 1)?;
    if size > cap {
        return err(
            "TOO_MANY",
            "records.size",
            if export {
                format!("An export takes at most {RECORDS_EXPORT} records.")
            } else {
                format!("View records shows at most {RECORDS_PAGE} records a page; use records.export for up to {RECORDS_EXPORT}.")
            },
        );
    }
    let list_fields: Vec<Field> = def
        .fields
        .iter()
        .filter_map(|k| source.fields.get(k))
        // `_id` is always returned once, as the hidden first column (for the row link).
        .filter(|f| f.key != "_id" && caller.allowed(f.authority.as_deref()))
        .cloned()
        .collect();
    if list_fields.is_empty() {
        return err("RECORDS_NOT_ALLOWED", "records", format!("None of the record fields of {} are yours to see.", source.label));
    }
    let sort = match spec.get("sort").filter(|s| s.as_array().is_some_and(|a| !a.is_empty())) {
        Some(s) => {
            let given = parse_sort_list(s, "sort", |p, m| ReportError::new("BAD_KIND", p, m))?;
            for (i, (by, _)) in given.iter().enumerate() {
                source_field(&source, caller, by, &format!("sort[{i}].by"))?;
            }
            given
        }
        None => def.sort.clone(),
    };
    let view = match spec.get("view") {
        None | Some(Value::Null) => json!({"type": "TABLE"}),
        Some(v) => Value::Object(obj(v, "view")?.clone()),
    };
    let w = where_of(spec, &source, catalog, caller)?;
    let condition = and_all(w.conditions.clone(), scope);
    let links = links_of(def.link.as_ref().or(source.link.as_ref()), &source, w.segment_count_link.as_ref());
    Ok(Plan {
        segment_label: w.segment_label,
        measures: Vec::new(),
        derived: Vec::new(),
        group_by: Vec::new(),
        condition,
        period: w.period,
        sort,
        limit: None,
        view_type: view.get("type").and_then(Value::as_str).unwrap_or("TABLE").to_string(),
        view,
        top_n: None,
        records: true,
        list_fields,
        params: Obj::new(),
        pinned_currency: w.pinned_currency,
        shape: Shape { group_by: 0, values: 0 },
        compare: None,
        records_page: Some(RecordsPage { page, size, export }),
        links,
        paging: None,
        source,
    })
}

/// view.x / view.y must name columns of the report (the rest of `view` is the UI's).
fn check_view_refs(view: &Value, aliases: &[String]) -> R<()> {
    if let Some(x) = view.get("x").and_then(Value::as_str) {
        if !aliases.iter().any(|a| a == x) {
            return err("BAD_VIEW", "view.x", format!("view.x '{x}' is not a column of this report."));
        }
    }
    if let Some(Value::Array(ys)) = view.get("y") {
        for (i, y) in ys.iter().enumerate() {
            let y = y.as_str().unwrap_or("");
            if !aliases.iter().any(|a| a == y) {
                return err("BAD_VIEW", format!("view.y[{i}]"), format!("view.y '{y}' is not a column of this report."));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_function_source(
    spec: &Obj,
    source: Source,
    _catalog: &Catalog,
    scope: &Value,
    caller: &Caller,
    view: Value,
    view_type: String,
    top_n: Option<usize>,
    limit: Option<usize>,
    derived_in: &[Value],
    sort_in: &[Value],
) -> R<Plan> {
    for k in ["measures", "groupBy", "filters", "segment", "fields"] {
        if spec.get(k).is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())) {
            return err("BAD_KIND", k, format!("{} is a function source: it takes params, not {k}.", source.label));
        }
    }
    let mut params = source.params.clone();
    if let Some(given) = spec.get("params") {
        let given = obj(given, "params")?;
        for (k, v) in given {
            if !source.allowed_params.iter().any(|a| a == k) {
                return err("UNKNOWN_FIELD", format!("params.{k}"), format!("{} takes no param '{k}'.", source.label));
            }
            params.insert(k.clone(), v.clone());
        }
    }
    if let Some(sp) = &source.scope_param {
        params.insert(sp.clone(), scope.clone());
    }
    for (k, c) in &source.columns {
        if !caller.allowed(c.authority.as_deref()) {
            return err("FORBIDDEN_FIELD", format!("columns.{k}"), format!("You cannot report on {}.", c.label));
        }
    }
    let measures: Vec<Measure> = source
        .columns
        .values()
        .filter(|c| c.kind == FieldKind::Measure)
        .map(|c| Measure {
            alias: c.key.clone(),
            func: "SUM".into(),
            field: Some(c.clone()),
            label: c.label.clone(),
            format: c.format.clone().unwrap_or_else(|| "NUMBER".into()),
            segment: None,
        })
        .collect();
    let groups: Vec<Group> = source
        .columns
        .values()
        .filter(|c| c.kind != FieldKind::Measure)
        .map(|c| Group { alias: c.key.clone(), field: c.clone(), bucket: None, fy: false })
        .collect();
    let mut derived = Vec::new();
    for (i, d) in derived_in.iter().enumerate() {
        let path = format!("derived[{i}]");
        let o = obj(d, &path)?;
        known_keys(o, &["as", "label", "ratio", "difference", "percent"], &path, "a derived measure")?;
        let (op, key) = if o.contains_key("ratio") {
            (DerivedOp::Ratio, "ratio")
        } else if o.contains_key("difference") {
            (DerivedOp::Difference, "difference")
        } else if o.contains_key("percent") {
            (DerivedOp::Percent, "percent")
        } else {
            return err("BAD_KIND", path, "A derived measure has exactly one of ratio, difference or percent.");
        };
        let Some(Value::Array(a)) = o.get(key).filter(|v| v.as_array().is_some_and(|a| a.len() == 2)) else {
            return err("BAD_KIND", format!("{path}.{key}"), format!("{key} takes two measure names."));
        };
        let (x, y) = (a[0].as_str().unwrap_or("").to_string(), a[1].as_str().unwrap_or("").to_string());
        for (j, n) in [&x, &y].iter().enumerate() {
            if !measures.iter().any(|m| &m.alias == *n) {
                return err("UNKNOWN_FIELD", format!("{path}.{key}[{j}]"), format!("'{n}' is not a measure of this report."));
            }
        }
        let alias = s_of(o, "as").unwrap_or_else(|| format!("{key}_{}", i + 1));
        if !is_alias(&alias) || source.columns.contains_key(&alias) {
            return err("BAD_KIND", format!("{path}.as"), format!("The name '{alias}' is not usable or is used twice."));
        }
        let format = if op == DerivedOp::Percent { "PERCENT".into() } else { "NUMBER".into() };
        derived.push(Derived { label: s_of(o, "label").unwrap_or_else(|| humanize(&alias)), alias, op, a: x, b: y, format });
    }
    let aliases: Vec<String> = source.columns.keys().cloned().chain(derived.iter().map(|d| d.alias.clone())).collect();
    let mut sort = Vec::new();
    for (i, so) in sort_in.iter().enumerate() {
        let o = obj(so, &format!("sort[{i}]"))?;
        known_keys(o, &["by", "dir"], &format!("sort[{i}]"), "a sort")?;
        let by = s_of(o, "by").unwrap_or_default();
        if !aliases.contains(&by) {
            return err("UNKNOWN_FIELD", format!("sort[{i}].by"), format!("'{by}' is not a column of this report."));
        }
        sort.push((by, s_of(o, "dir").is_some_and(|d| d.eq_ignore_ascii_case("DESC"))));
    }
    // Hidden columns (ids, a currency code) are not part of the shape (as shapeRules.ts counts).
    let shown_groups = groups.iter().filter(|g| !g.field.hidden && g.field.key != "currency").count();
    let shown_values = measures.iter().filter(|m| !m.field.as_ref().is_some_and(|f| f.hidden)).count() + derived.len();
    let shape = Shape { group_by: shown_groups, values: shown_values };
    shape::check(&view_type, shape).map_err(|why| ReportError::new("BAD_VIEW", "view.type", why))?;
    check_view_refs(&view, &aliases)?;
    let links = links_of(source.link.as_ref(), &source, None);
    let paging = source.paging.clone();
    Ok(Plan {
        source,
        segment_label: None,
        measures,
        derived,
        group_by: groups,
        condition: Value::Null,
        period: None,
        sort,
        limit,
        view_type,
        view,
        top_n,
        records: false,
        list_fields: Vec::new(),
        params,
        pinned_currency: IndexMap::new(),
        shape,
        compare: None,
        records_page: None,
        links,
        paging,
    })
}

/// The condition a period puts on a date field; none for ALL_TIME.
///
/// An ISO text column holds an instant in UTC (`2026-11-17T06:13:26Z`, compared as text with the
/// UTC bounds of the local days) or a bare local date (`2026-11-17`, compared with the local dates
/// themselves). `LIKE '____-__-__'` tells the two apart, so both work in any zone.
pub fn period_condition(f: &Field, p: &Period, zone: &Zone) -> Option<Value> {
    let (from, to) = p.range?;
    let start = zone.midnight_utc(from);
    let end = zone.midnight_utc(to + chrono::Duration::days(1));
    let c = &f.column;
    if f.string_date {
        return Some(json!({"operator": "OR", "conditions": [
            {"operator": "AND", "conditions": [
                {"field": c, "operator": "LIKE", "value": "____-__-__"},
                {"field": c, "operator": "GREATER_THAN_EQUAL", "value": period::iso_date(from)},
                {"field": c, "operator": "LESS_THAN_EQUAL", "value": period::iso_date(to)}]},
            {"operator": "AND", "conditions": [
                {"field": c, "operator": "LIKE", "value": "%T%"},
                {"field": c, "operator": "GREATER_THAN_EQUAL", "value": period::iso_bound(start)},
                {"field": c, "operator": "LESS_THAN", "value": period::iso_bound(end)}]}]}));
    }
    let (lo, hi) = match f.encoding.as_deref() {
        Some("EPOCH_MILLIS") => (json!(start.timestamp_millis()), json!(end.timestamp_millis())),
        Some("EPOCH_SECONDS") => (json!(start.timestamp()), json!(end.timestamp())),
        _ => (json!(period::datetime_bound(start)), json!(period::datetime_bound(end))),
    };
    Some(json!({"operator": "AND", "conditions": [
        {"field": c, "operator": "GREATER_THAN_EQUAL", "value": lo},
        {"field": c, "operator": "LESS_THAN", "value": hi}]}))
}
