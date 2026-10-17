//! The filter language of `AbstractJOOQDataController` (`GET` page filter and `POST /query`):
//! `AbstractCondition` as `AbstractConditionDeserializer` reads it, turned into SQL the way
//! `AbstractDAO.filter` does.
//!
//! Supported as in Java: `ComplexCondition` (AND / OR, `negate`), `FilterCondition` with every
//! operator `AbstractDAO.buildConditionForField` handles, `fieldExpr`. Group and having
//! conditions are accepted and ignored, as `AbstractDAO` ignores a having condition with no
//! group fields; no security table is queried with them.
//!
//! A DAO that overrides `filterConditionFilter` (`UserDAO`, `ClientDAO`) passes a hook that
//! answers the filters it handles itself; the rest go through the base rules. Columns are
//! qualified with the table name, as jOOQ renders them, because the context restrictions join
//! other tables that have the same column names.
//!
//! Adapted from `crates/files`' copy (a unit crate cannot depend on another).

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::mysql::MySql;
use sqlx::QueryBuilder;

/// How a column's values are converted (`AbstractDAO.fieldValue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColType {
    Str,
    Enum,
    Num,
    Ts,
}

/// The columns of a table, by their jOOQ names. An empty `name` leaves columns unqualified.
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [(&'static str, ColType)],
}

impl Table {
    /// `AbstractDAO.getField`: `fieldName` camel case to the column's upper snake case.
    pub fn column(&self, field: &str) -> Option<(&'static str, ColType)> {
        let mut name = String::with_capacity(field.len() + 4);
        for c in field.chars() {
            if c.is_ascii_uppercase() {
                name.push('_');
            }
            name.push(c);
        }
        let name = name.to_uppercase();
        self.columns.iter().find(|(c, _)| *c == name).copied()
    }

    /// The column as the SQL names it.
    pub fn qualified(&self, col: &str) -> String {
        if self.name.is_empty() {
            col.to_string()
        } else {
            format!("{}.{col}", self.name)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Equals,
    LessThan,
    GreaterThan,
    LessThanEqual,
    GreaterThanEqual,
    IsTrue,
    IsFalse,
    IsNull,
    Between,
    In,
    Like,
    StringLooseEqual,
    Match,
    MatchAll,
    TextSearch,
}

impl Op {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "EQUALS" => Self::Equals,
            "LESS_THAN" => Self::LessThan,
            "GREATER_THAN" => Self::GreaterThan,
            "LESS_THAN_EQUAL" => Self::LessThanEqual,
            "GREATER_THAN_EQUAL" => Self::GreaterThanEqual,
            "IS_TRUE" => Self::IsTrue,
            "IS_FALSE" => Self::IsFalse,
            "IS_NULL" => Self::IsNull,
            "BETWEEN" => Self::Between,
            "IN" => Self::In,
            "LIKE" => Self::Like,
            "STRING_LOOSE_EQUAL" => Self::StringLooseEqual,
            "MATCH" => Self::Match,
            "MATCH_ALL" => Self::MatchAll,
            "TEXT_SEARCH" => Self::TextSearch,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldExpr {
    pub function: String,
    pub fields: Vec<String>,
    pub separator: Option<String>,
}

impl FieldExpr {
    pub fn is_valid(&self) -> bool {
        match self.function.as_str() {
            "UPPER" | "LOWER" | "TRIM" => self.fields.len() == 1,
            "CONCAT" | "COALESCE" => self.fields.len() >= 2,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub field: Option<String>,
    pub field_expr: Option<FieldExpr>,
    pub op: Op,
    pub value: Option<Value>,
    pub to_value: Option<Value>,
    pub multi_value: Option<Vec<Value>>,
    pub value_field: bool,
    pub to_value_field: bool,
    pub negate: bool,
}

impl Filter {
    pub fn eq(field: &str, value: impl Into<Value>) -> Self {
        Self {
            field: Some(field.to_string()),
            field_expr: None,
            op: Op::Equals,
            value: Some(value.into()),
            to_value: None,
            multi_value: None,
            value_field: false,
            to_value_field: false,
            negate: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    Complex { and: bool, conditions: Vec<Cond>, negate: bool },
    Filter(Filter),
    /// A group or having condition: no `WHERE` part.
    Ignored,
}

impl Cond {
    pub fn and(conditions: Vec<Cond>) -> Self {
        Self::Complex { and: true, conditions, negate: false }
    }

    /// `findConditionWithField`: the filters on `field`, at any depth.
    pub fn filters_on(&self, field: &str) -> Vec<&Filter> {
        match self {
            Self::Filter(f) if f.field.as_deref() == Some(field) => vec![f],
            Self::Complex { conditions, .. } => conditions.iter().flat_map(|c| c.filters_on(field)).collect(),
            _ => vec![],
        }
    }
}

/// Why a condition could not be read or applied, in the words of the Java exception.
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

/// `AbstractConditionDeserializer`. `None` for a missing or empty condition.
pub fn parse(v: &Value) -> Result<Option<Cond>, Invalid> {
    let Value::Object(m) = v else {
        return if v.is_null() { Ok(None) } else { Err(Invalid("Invalid condition".into())) };
    };
    if m.is_empty() {
        return Ok(None);
    }
    let negate = m.get("negate").and_then(Value::as_bool).unwrap_or(false);
    if matches!(m.get("havingConditions"), Some(Value::Array(_))) {
        return Ok(Some(Cond::Ignored));
    }
    if let Some(Value::String(op)) = m.get("operator") {
        if op == "AND" || op == "OR" {
            let mut conditions = Vec::new();
            if let Some(Value::Array(items)) = m.get("conditions") {
                for item in items {
                    if let Some(c) = parse(item)? {
                        conditions.push(c);
                    }
                }
            }
            return Ok(Some(Cond::Complex { and: op == "AND", conditions, negate }));
        }
    }
    if matches!(m.get("aggregateFunction"), Some(Value::String(_))) {
        return Ok(Some(Cond::Ignored));
    }

    let field = match m.get("field") {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        _ => None,
    };
    let field_expr = match m.get("fieldExpr") {
        Some(Value::Object(fe)) if !fe.is_empty() => Some(FieldExpr {
            function: fe.get("function").and_then(Value::as_str).unwrap_or("").to_string(),
            fields: fe
                .get("fields")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|f| f.as_str().map(str::to_string)).collect())
                .unwrap_or_default(),
            separator: fe.get("separator").and_then(Value::as_str).map(str::to_string),
        }),
        _ => None,
    };
    if field.is_none() && field_expr.is_none() {
        return Err(Invalid("Invalid condition".into()));
    }
    let op = match m.get("operator") {
        None | Some(Value::Null) => Op::Equals,
        Some(Value::String(s)) => Op::parse(s).ok_or_else(|| Invalid(format!("Invalid operator '{s}'")))?,
        Some(other) => return Err(Invalid(format!("Invalid operator '{other}'"))),
    };
    let non_null = |k: &str| m.get(k).filter(|v| !v.is_null()).cloned();
    Ok(Some(Cond::Filter(Filter {
        field,
        field_expr,
        op,
        value: non_null("value"),
        to_value: non_null("toValue"),
        multi_value: m.get("multiValue").and_then(Value::as_array).cloned(),
        value_field: m.get("valueField").and_then(Value::as_bool).unwrap_or(false),
        to_value_field: m.get("toValueField").and_then(Value::as_bool).unwrap_or(false),
        negate,
    })))
}

/// `ConditionUtil.parameterMapToMap`: every query parameter an EQUALS (one value) or IN (several).
pub fn from_params(params: &[(String, String)]) -> Option<Cond> {
    let mut names: Vec<&str> = Vec::new();
    for (k, _) in params {
        if !names.contains(&k.as_str()) {
            names.push(k);
        }
    }
    let conditions: Vec<Cond> = names
        .into_iter()
        .map(|name| {
            let values: Vec<&str> = params.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect();
            if values.len() == 1 {
                Cond::Filter(Filter::eq(name, values[0]))
            } else {
                let joined = values.iter().map(|v| v.replace(',', "\\,")).collect::<Vec<_>>().join(",");
                let mut f = Filter::eq(name, joined);
                f.op = Op::In;
                Cond::Filter(f)
            }
        })
        .collect();
    match conditions.len() {
        0 => None,
        1 => conditions.into_iter().next(),
        _ => Some(Cond::and(conditions)),
    }
}

/// A value bound into the SQL.
#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Null,
    Str(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Ts(DateTime<Utc>),
}

/// SQL text and binds, in order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Sql {
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    Bind(Bind),
}

impl Sql {
    pub fn text(s: impl Into<String>) -> Self {
        Self { parts: vec![Part::Text(s.into())] }
    }

    pub fn push_text(&mut self, s: impl Into<String>) {
        self.parts.push(Part::Text(s.into()));
    }

    pub fn push_bind(&mut self, b: Bind) {
        self.parts.push(Part::Bind(b));
    }

    pub fn append(&mut self, other: Sql) {
        self.parts.extend(other.parts);
    }

    /// `DSL.and(a, b)` where either may be `noCondition()`.
    pub fn and(a: Option<Sql>, b: Option<Sql>) -> Option<Sql> {
        match (a, b) {
            (None, b) => b,
            (a, None) => a,
            (Some(a), Some(b)) => {
                let mut s = Sql::text("(");
                s.append(a);
                s.push_text(" AND ");
                s.append(b);
                s.push_text(")");
                Some(s)
            }
        }
    }

    /// Appends to a query being built.
    pub fn push_to(&self, qb: &mut QueryBuilder<'_, MySql>) {
        for p in &self.parts {
            match p {
                Part::Text(t) => {
                    qb.push(t.as_str());
                }
                Part::Bind(b) => match b {
                    Bind::Null => {
                        qb.push_bind(Option::<String>::None);
                    }
                    Bind::Str(s) => {
                        qb.push_bind(s.clone());
                    }
                    Bind::I64(n) => {
                        qb.push_bind(*n);
                    }
                    Bind::U64(n) => {
                        qb.push_bind(*n);
                    }
                    Bind::F64(n) => {
                        qb.push_bind(*n);
                    }
                    Bind::Ts(t) => {
                        qb.push_bind(*t);
                    }
                },
            }
        }
    }
}

/// `Object.toString()` of a value Jackson read into an `Object`.
pub fn java_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// `AbstractDAO.fieldValue`.
pub fn field_value(t: ColType, v: &Value) -> Result<Bind, Invalid> {
    Ok(match t {
        ColType::Str | ColType::Enum => Bind::Str(java_string(v)),
        ColType::Num => match v {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Bind::I64(i)
                } else if let Some(u) = n.as_u64() {
                    Bind::U64(u)
                } else {
                    Bind::F64(n.as_f64().unwrap_or(0.0))
                }
            }
            other => {
                let s = java_string(other);
                Bind::I64(s.parse::<i64>().map_err(|_| Invalid(format!("For input string: \"{s}\"")))?)
            }
        },
        ColType::Ts => {
            let s = java_string(v);
            if s == "now" {
                Bind::Ts(Utc::now())
            } else {
                // `Long.parseLong`'s message, then `LocalDateTime.ofEpochSecond`'s range check.
                let secs = s.parse::<i64>().map_err(|_| Invalid(format!("For input string: \"{s}\"")))?;
                Bind::Ts(DateTime::from_timestamp(secs, 0).ok_or_else(|| Invalid(format!("Invalid value for EpochDay: {s}")))?)
            }
        }
    })
}

/// jOOQ's `Convert.TRUE_VALUES` / `FALSE_VALUES`, for `isTrue()` / `isFalse()` on text.
const TRUE_VALUES: &[&str] = &["1", "1.0", "y", "Y", "yes", "YES", "true", "TRUE", "on", "ON", "enabled", "ENABLED"];
const FALSE_VALUES: &[&str] = &["0", "0.0", "n", "N", "no", "NO", "false", "FALSE", "off", "OFF", "disabled", "DISABLED"];

/// A DAO's own `filterConditionFilter`: `Some` for a filter it renders itself.
pub type Hook<'a> = &'a dyn Fn(&Filter, &Table) -> Option<Result<Option<Sql>, Invalid>>;

/// `AbstractDAO.filter`: `None` is jOOQ's `noCondition()`.
pub fn to_sql(c: &Cond, table: &Table) -> Result<Option<Sql>, Invalid> {
    to_sql_with(c, table, &|_, _| None)
}

/// [`to_sql`] with a DAO's overrides.
pub fn to_sql_with(c: &Cond, table: &Table, hook: Hook<'_>) -> Result<Option<Sql>, Invalid> {
    match c {
        Cond::Ignored => Ok(None),
        Cond::Complex { and, conditions, negate } => {
            let mut parts = Vec::new();
            for child in conditions {
                if let Some(s) = to_sql_with(child, table, hook)? {
                    parts.push(s);
                }
            }
            if parts.is_empty() {
                return Ok(None);
            }
            let mut sql = Sql::text("(");
            for (i, p) in parts.into_iter().enumerate() {
                if i > 0 {
                    sql.push_text(if *and { " AND " } else { " OR " });
                }
                sql.append(p);
            }
            sql.push_text(")");
            Ok(Some(negated(sql, *negate)))
        }
        Cond::Filter(f) => {
            let s = match hook(f, table) {
                Some(r) => r?,
                None => filter_sql(f, table)?,
            };
            Ok(s.map(|s| negated(s, f.negate)))
        }
    }
}

/// `condition.not()`.
pub fn negated(sql: Sql, negate: bool) -> Sql {
    if !negate {
        return sql;
    }
    let mut out = Sql::text("NOT (");
    out.append(sql);
    out.push_text(")");
    out
}

/// The column (or expression) a filter is on, with how its values convert.
fn target(f: &Filter, table: &Table) -> Option<(String, ColType)> {
    if let Some(fe) = f.field_expr.as_ref().filter(|fe| fe.is_valid()) {
        let mut cols = Vec::new();
        for name in &fe.fields {
            cols.push(format!("CAST({} AS CHAR)", table.qualified(table.column(name)?.0)));
        }
        let sql = match fe.function.as_str() {
            "CONCAT" => match fe.separator.as_deref().filter(|s| !s.is_empty()) {
                Some(sep) => format!("CONCAT({})", cols.join(&format!(", {}, ", sql_string(sep)))),
                None => format!("CONCAT({})", cols.join(", ")),
            },
            "UPPER" => format!("UPPER({})", cols[0]),
            "LOWER" => format!("LOWER({})", cols[0]),
            "TRIM" => format!("TRIM({})", cols[0]),
            _ => format!("COALESCE({})", cols.join(", ")),
        };
        return Some((sql, ColType::Str));
    }
    let (col, t) = table.column(f.field.as_deref()?)?;
    Some((table.qualified(col), t))
}

/// A string literal for SQL text; only used for a `fieldExpr` separator.
fn sql_string(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''"))
}

fn filter_sql(f: &Filter, table: &Table) -> Result<Option<Sql>, Invalid> {
    let Some((col, t)) = target(f, table) else { return Ok(None) };
    let bind_of = |v: &Option<Value>| -> Result<Bind, Invalid> {
        match v {
            None => Ok(Bind::Null),
            Some(v) => field_value(t, v),
        }
    };

    let mut sql = Sql::text(col.clone());
    match f.op {
        Op::Between => {
            sql.push_text(" BETWEEN ");
            if f.value_field {
                sql.push_text(col.clone());
            } else {
                sql.push_bind(bind_of(&f.value)?);
            }
            sql.push_text(" AND ");
            if f.to_value_field {
                sql.push_text(col.clone());
            } else {
                sql.push_bind(bind_of(&f.to_value)?);
            }
        }
        Op::Equals | Op::GreaterThan | Op::GreaterThanEqual | Op::LessThan | Op::LessThanEqual => {
            let sym = match f.op {
                Op::Equals => " = ",
                Op::GreaterThan => " > ",
                Op::GreaterThanEqual => " >= ",
                Op::LessThan => " < ",
                _ => " <= ",
            };
            sql.push_text(sym);
            // Java compares with the field named by `field` again: the same column.
            if f.value_field {
                sql.push_text(col.clone());
            } else {
                let Some(v) = &f.value else { return Ok(None) };
                sql.push_bind(field_value(t, v)?);
            }
        }
        Op::IsTrue | Op::IsFalse => {
            let truth = f.op == Op::IsTrue;
            if t == ColType::Num {
                sql.push_text(if truth { " = 1" } else { " = 0" });
            } else {
                let values = if truth { TRUE_VALUES } else { FALSE_VALUES };
                let mut s = Sql::text(format!("CAST({col} AS CHAR) IN ("));
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        s.push_text(", ");
                    }
                    s.push_bind(Bind::Str(v.to_string()));
                }
                s.push_text(")");
                return Ok(Some(s));
            }
        }
        Op::IsNull => sql.push_text(" IS NULL"),
        Op::In => {
            let values = multi_values(t, f)?;
            if values.is_empty() {
                return Ok(Some(Sql::text("1 = 0")));
            }
            sql.push_text(" IN (");
            for (i, b) in values.into_iter().enumerate() {
                if i > 0 {
                    sql.push_text(", ");
                }
                sql.push_bind(b);
            }
            sql.push_text(")");
        }
        Op::Like => {
            let Some(v) = &f.value else {
                return Err(Invalid("LIKE needs a value".into()));
            };
            sql.push_text(" LIKE ");
            sql.push_bind(Bind::Str(java_string(v)));
        }
        Op::StringLooseEqual => {
            let v = f.value.as_ref().map(java_string).unwrap_or_else(|| "null".into());
            sql.push_text(" LIKE ");
            sql.push_bind(Bind::Str(format!("%{v}%")));
        }
        Op::Match | Op::MatchAll | Op::TextSearch => return Ok(None),
    }
    Ok(Some(sql))
}

/// `AbstractDAO.multiFieldValue`: `multiValue` as given, else `value` split on unescaped commas
/// (the backslash stays in the value, as it does in Java).
pub fn multi_values(t: ColType, f: &Filter) -> Result<Vec<Bind>, Invalid> {
    if let Some(mv) = f.multi_value.as_ref().filter(|m| !m.is_empty()) {
        return Ok(mv
            .iter()
            .map(|v| match v {
                Value::Number(n) => n.as_i64().map(Bind::I64).unwrap_or_else(|| Bind::F64(n.as_f64().unwrap_or(0.0))),
                Value::Null => Bind::Null,
                other => Bind::Str(java_string(other)),
            })
            .collect());
    }
    let Some(v) = &f.value else { return Ok(vec![]) };
    let s = java_string(v);
    let s = s.trim();
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut from = 0;
    for i in 0..=chars.len() {
        if i < chars.len() && chars[i] != ',' {
            continue;
        }
        if i > 0 && chars[i - 1] == '\\' {
            continue;
        }
        let piece: String = chars[from..i].iter().collect();
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        out.push(field_value(t, &Value::String(piece.to_string()))?);
        from = i + 1;
    }
    Ok(out)
}

/// `ORDER BY` for a page's sort, columns the table does not have left out (`AbstractDAO.list`).
/// Columns are qualified so an enum sorts as the enum, not as the CHAR alias the select gives it.
pub fn order_by(sort: &[crate::spring::Order], table: &Table) -> String {
    let cols: Vec<String> = sort
        .iter()
        .filter_map(|o| {
            table
                .column(&o.property)
                .map(|(c, _)| format!("{} {}", table.qualified(c), if o.ascending { "ASC" } else { "DESC" }))
        })
        .collect();
    if cols.is_empty() {
        String::new()
    } else {
        format!(" ORDER BY {}", cols.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T: Table = Table {
        name: "",
        columns: &[
            ("ID", ColType::Num),
            ("CLIENT_CODE", ColType::Str),
            ("RESOURCE_TYPE", ColType::Enum),
            ("WRITE_ACCESS", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    };

    fn render(c: &Cond) -> String {
        render_with(c, &T)
    }

    fn render_with(c: &Cond, t: &Table) -> String {
        to_sql(c, t)
            .unwrap()
            .map(|s| {
                s.parts
                    .iter()
                    .map(|p| match p {
                        Part::Text(t) => t.clone(),
                        Part::Bind(b) => format!("{{{b:?}}}"),
                    })
                    .collect::<String>()
            })
            .unwrap_or_else(|| "<none>".into())
    }

    #[test]
    fn field_names_convert_like_abstract_dao() {
        assert_eq!(T.column("clientCode").map(|c| c.0), Some("CLIENT_CODE"));
        assert_eq!(T.column("id").map(|c| c.0), Some("ID"));
        assert_eq!(T.column("ID"), None);
        assert_eq!(T.column("page"), None);
    }

    #[test]
    fn filters_and_complex() {
        let c = parse(&json!({"operator": "OR", "negate": true, "conditions": [
            {"field": "clientCode", "value": "SYSTEM"},
            {"field": "id", "operator": "IN", "value": "1, 2, 3"},
            {"field": "nope", "value": 1},
            {"field": "writeAccess", "operator": "IS_TRUE"}
        ]}))
        .unwrap()
        .unwrap();
        assert_eq!(
            render(&c),
            "NOT ((CLIENT_CODE = {Str(\"SYSTEM\")} OR ID IN ({I64(1)}, {I64(2)}, {I64(3)}) OR WRITE_ACCESS = 1))"
        );
    }

    #[test]
    fn empty_in_pieces_fail_like_java() {
        // An empty piece does not move the start, so the next one reads ",3": not a number.
        let c = parse(&json!({"field": "id", "operator": "IN", "value": "1,,3"})).unwrap().unwrap();
        assert!(to_sql(&c, &T).is_err());
        let c = parse(&json!({"field": "clientCode", "operator": "IN", "value": "A,,B"})).unwrap().unwrap();
        assert_eq!(render(&c), "CLIENT_CODE IN ({Str(\"A\")}, {Str(\",B\")})");
    }

    #[test]
    fn no_condition_cases() {
        assert_eq!(parse(&json!({})).unwrap(), None);
        assert_eq!(render(&parse(&json!({"field": "clientCode"})).unwrap().unwrap()), "<none>");
        assert_eq!(render(&parse(&json!({"operator": "AND", "conditions": []})).unwrap().unwrap()), "<none>");
        assert!(parse(&json!({"value": 1})).is_err());
        assert!(parse(&json!({"field": "id", "operator": "NOPE"})).is_err());
    }

    #[test]
    fn values_convert_by_column_type() {
        let c = parse(&json!({"field": "id", "value": "abc"})).unwrap().unwrap();
        assert!(to_sql(&c, &T).is_err());
        let c = parse(&json!({"field": "updatedAt", "operator": "GREATER_THAN", "value": 0})).unwrap().unwrap();
        assert!(render(&c).starts_with("UPDATED_AT > {Ts("));
        let c = parse(&json!({"field": "clientCode", "operator": "STRING_LOOSE_EQUAL", "value": "YS"})).unwrap().unwrap();
        assert_eq!(render(&c), "CLIENT_CODE LIKE {Str(\"%YS%\")}");
    }

    #[test]
    fn params_become_equals_or_in() {
        let p = vec![
            ("resourceType".to_string(), "STATIC".to_string()),
            ("clientCode".into(), "A".into()),
            ("clientCode".into(), "B,C".into()),
        ];
        let c = from_params(&p).unwrap();
        assert_eq!(
            render(&c),
            "(RESOURCE_TYPE = {Str(\"STATIC\")} AND CLIENT_CODE IN ({Str(\"A\")}, {Str(\"B\\\\,C\")}))"
        );
        assert_eq!(c.filters_on("resourceType").len(), 1);
    }

    fn filter(v: serde_json::Value) -> String {
        render(&parse(&v).unwrap().unwrap())
    }

    #[test]
    fn field_expressions() {
        assert_eq!(
            filter(json!({"fieldExpr": {"function": "CONCAT", "fields": ["clientCode", "id"], "separator": "o'k"}, "value": "A"})),
            "CONCAT(CAST(CLIENT_CODE AS CHAR), 'o''k', CAST(ID AS CHAR)) = {Str(\"A\")}"
        );
        assert_eq!(
            filter(json!({"fieldExpr": {"function": "CONCAT", "fields": ["clientCode", "id"], "separator": ""}, "value": "A"})),
            "CONCAT(CAST(CLIENT_CODE AS CHAR), CAST(ID AS CHAR)) = {Str(\"A\")}"
        );
        assert_eq!(filter(json!({"fieldExpr": {"function": "UPPER", "fields": ["clientCode"]}, "value": "A"})), "UPPER(CAST(CLIENT_CODE AS CHAR)) = {Str(\"A\")}");
        assert_eq!(filter(json!({"fieldExpr": {"function": "LOWER", "fields": ["clientCode"]}, "value": 1})), "LOWER(CAST(CLIENT_CODE AS CHAR)) = {Str(\"1\")}");
        assert_eq!(filter(json!({"fieldExpr": {"function": "TRIM", "fields": ["id"]}, "value": "1"})), "TRIM(CAST(ID AS CHAR)) = {Str(\"1\")}");
        assert_eq!(
            filter(json!({"fieldExpr": {"function": "COALESCE", "fields": ["id", "clientCode"], "separator": "-"}, "value": "1"})),
            "COALESCE(CAST(ID AS CHAR), CAST(CLIENT_CODE AS CHAR)) = {Str(\"1\")}"
        );
        // An invalid expression falls back to `field`; with none, no condition.
        assert_eq!(filter(json!({"fieldExpr": {"function": "UPPER", "fields": ["id", "id"]}, "field": "id", "value": 2})), "ID = {I64(2)}");
        assert_eq!(filter(json!({"fieldExpr": {"function": "REVERSE", "fields": ["id"]}, "value": 2})), "<none>");
        assert_eq!(filter(json!({"fieldExpr": {"function": "UPPER", "fields": ["nope"]}, "value": 2})), "<none>");
        assert_eq!(filter(json!({"fieldExpr": {}, "field": "id", "value": 3})), "ID = {I64(3)}");
    }

    #[test]
    fn every_operator() {
        assert_eq!(filter(json!({"field": "id", "operator": "BETWEEN", "value": 1, "toValue": "9"})), "ID BETWEEN {I64(1)} AND {I64(9)}");
        assert_eq!(filter(json!({"field": "id", "operator": "BETWEEN", "valueField": true, "toValueField": true})), "ID BETWEEN ID AND ID");
        assert_eq!(filter(json!({"field": "id", "operator": "BETWEEN"})), "ID BETWEEN {Null} AND {Null}");
        assert_eq!(filter(json!({"field": "id", "operator": "GREATER_THAN_EQUAL", "value": 1})), "ID >= {I64(1)}");
        assert_eq!(filter(json!({"field": "id", "operator": "LESS_THAN", "value": 1})), "ID < {I64(1)}");
        assert_eq!(filter(json!({"field": "id", "operator": "LESS_THAN_EQUAL", "value": 1})), "ID <= {I64(1)}");
        assert_eq!(filter(json!({"field": "id", "operator": "EQUALS", "valueField": true, "value": "x"})), "ID = ID");
        assert_eq!(filter(json!({"field": "id", "operator": null, "value": 5})), "ID = {I64(5)}");
        assert_eq!(filter(json!({"field": "writeAccess", "operator": "IS_FALSE"})), "WRITE_ACCESS = 0");
        let truth = filter(json!({"field": "clientCode", "operator": "IS_TRUE"}));
        assert!(truth.starts_with("CAST(CLIENT_CODE AS CHAR) IN ({Str(\"1\")}, ") && truth.ends_with("{Str(\"ENABLED\")})"), "{truth}");
        let falsity = filter(json!({"field": "clientCode", "operator": "IS_FALSE"}));
        assert!(falsity.contains("{Str(\"off\")}"), "{falsity}");
        assert_eq!(filter(json!({"field": "clientCode", "operator": "IS_NULL"})), "CLIENT_CODE IS NULL");
        assert_eq!(filter(json!({"field": "id", "operator": "IN"})), "1 = 0");
        assert_eq!(filter(json!({"field": "id", "operator": "IN", "value": ""})), "1 = 0");
        assert_eq!(
            filter(json!({"field": "id", "operator": "IN", "multiValue": [1, 2.5, null, "x", true]})),
            "ID IN ({I64(1)}, {F64(2.5)}, {Null}, {Str(\"x\")}, {Str(\"true\")})"
        );
        assert_eq!(filter(json!({"field": "clientCode", "operator": "LIKE", "value": "A%"})), "CLIENT_CODE LIKE {Str(\"A%\")}");
        assert_eq!(filter(json!({"field": "clientCode", "operator": "STRING_LOOSE_EQUAL"})), "CLIENT_CODE LIKE {Str(\"%null%\")}");
        for op in ["MATCH", "MATCH_ALL", "TEXT_SEARCH"] {
            assert_eq!(filter(json!({"field": "clientCode", "operator": op, "value": "x"})), "<none>");
        }
        assert_eq!(filter(json!({"field": "id", "operator": "EQUALS"})), "<none>");
        assert_eq!(parse(&json!({"field": "id", "operator": 5})).unwrap_err(), Invalid("Invalid operator '5'".into()));
    }

    #[test]
    fn values_by_column_type() {
        assert_eq!(field_value(ColType::Str, &Value::Null).unwrap(), Bind::Str("null".into()));
        assert_eq!(field_value(ColType::Enum, &json!(true)).unwrap(), Bind::Str("true".into()));
        assert_eq!(field_value(ColType::Num, &json!(-3)).unwrap(), Bind::I64(-3));
        assert_eq!(field_value(ColType::Num, &json!(u64::MAX)).unwrap(), Bind::U64(u64::MAX));
        assert_eq!(field_value(ColType::Num, &json!(1.5)).unwrap(), Bind::F64(1.5));
        assert_eq!(field_value(ColType::Num, &json!("42")).unwrap(), Bind::I64(42));
        assert!(matches!(field_value(ColType::Ts, &json!("now")).unwrap(), Bind::Ts(_)));
        assert_eq!(field_value(ColType::Ts, &json!(1_700_000_000)).unwrap(), Bind::Ts(DateTime::from_timestamp(1_700_000_000, 0).unwrap()));
        assert!(field_value(ColType::Ts, &json!("yesterday")).is_err());
        assert!(field_value(ColType::Ts, &json!(i64::MAX)).is_err());
    }

    #[test]
    fn ignored_and_malformed_conditions() {
        assert_eq!(parse(&Value::Null).unwrap(), None);
        assert_eq!(parse(&json!("x")).unwrap_err(), Invalid("Invalid condition".into()));
        assert_eq!(parse(&json!({"havingConditions": []})).unwrap(), Some(Cond::Ignored));
        assert_eq!(parse(&json!({"aggregateFunction": "SUM", "field": "id"})).unwrap(), Some(Cond::Ignored));
        assert_eq!(to_sql(&Cond::Ignored, &T).unwrap(), None);
        let c = parse(&json!({"operator": "AND", "conditions": [{"havingConditions": []}, {}, {"field": "id", "value": 1, "negate": true}]})).unwrap().unwrap();
        assert_eq!(render(&c), "(NOT (ID = {I64(1)}))");
        assert!(Cond::Ignored.filters_on("id").is_empty());
    }

    #[test]
    fn sql_binds_and_order() {
        let sql = Sql {
            parts: vec![
                Part::Text("A = ".into()),
                Part::Bind(Bind::Null),
                Part::Text(" AND B = ".into()),
                Part::Bind(Bind::Str("s".into())),
                Part::Bind(Bind::I64(1)),
                Part::Bind(Bind::U64(2)),
                Part::Bind(Bind::F64(3.5)),
                Part::Bind(Bind::Ts(Utc::now())),
            ],
        };
        let mut qb = QueryBuilder::<MySql>::new("SELECT 1 WHERE ");
        sql.push_to(&mut qb);
        assert_eq!(qb.sql(), "SELECT 1 WHERE A = ? AND B = ?????");
        let sort = vec![crate::spring::Order::new("id", false), crate::spring::Order::new("nope", true), crate::spring::Order::new("clientCode", true)];
        assert_eq!(order_by(&sort, &T), " ORDER BY ID DESC, CLIENT_CODE ASC");
        let q = Table { name: "security_user", columns: &[("ID", ColType::Num)] };
        assert_eq!(order_by(&sort[..1], &q), " ORDER BY security_user.ID DESC");
        assert_eq!(render_with(&parse(&json!({"field": "id", "value": 1})).unwrap().unwrap(), &q), "security_user.ID = {I64(1)}");
        assert_eq!(order_by(&[], &T), "");
        assert_eq!(from_params(&[]), None);
        assert_eq!(render(&from_params(&[("id".into(), "7".into())]).unwrap()), "ID = {I64(7)}");
    }
}
