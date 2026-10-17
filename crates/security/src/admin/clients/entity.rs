//! The jOOQ DTO round trip the `AbstractDAO` / `AbstractUpdatableDAO` subclasses of this piece
//! share, described once per table instead of once per class:
//!
//! - a row is read into the DTO's properties (`record.into(Pojo.class)`), and written by Jackson in
//!   the DTO's property order (the base DTO's `id`, `createdAt`, `createdBy`, `updatedAt`,
//!   `updatedBy`, then the class's fields), `NON_EMPTY`, write-only properties left out;
//! - an insert or update is `record.from(pojo)`: every mapped column is written, except that a
//!   null on a `NOT NULL` column is left for the database's default (jOOQ's
//!   `resetChangedOnNotNull`), and an update leaves `CREATED_BY` / `CREATED_AT` alone;
//! - a `PATCH` sets only the properties the DTO class itself declares setters for
//!   (`getDeclaredMethods()`), each converted as Jackson's `convertValue` would.

use axum::http::StatusCode;
use serde_json::{Map, Value};
use sqlx::mysql::MySqlRow;
use sqlx::Row as _;

use super::common::{coerce, Kind, FIELD_NOT_AVAILABLE, OBJECT_NOT_FOUND};
use crate::condition::{Bind, ColType, Sql, Table};
use crate::data::crud::{self, ClientCheck};
use crate::data::Db;
use crate::errors::{AuthError, AuthResult};
use crate::jackson::{is_empty_value, Obj};
use crate::spring::Pageable;

/// One property of a DTO and the column it maps to.
#[derive(Debug, Clone, Copy)]
pub struct Col {
    pub prop: &'static str,
    /// The column; `""` for a property no column backs (filled by a join or never stored).
    pub col: &'static str,
    pub kind: Kind,
    pub not_null: bool,
    /// Written in responses (false for write-only and `@JsonIgnore` properties).
    pub out: bool,
    /// Read from request bodies (false for `@JsonIgnore` ones).
    pub input: bool,
    /// A Java primitive: a JSON null reads as false / 0.
    pub primitive: bool,
}

/// A column-backed property.
pub const fn col(prop: &'static str, col: &'static str, kind: Kind, not_null: bool) -> Col {
    Col { prop, col, kind, not_null, out: true, input: true, primitive: false }
}

/// A primitive property (`boolean`, `int`): never null in the DTO.
pub const fn prim(prop: &'static str, col: &'static str, kind: Kind) -> Col {
    Col { prop, col, kind, not_null: true, out: true, input: true, primitive: true }
}

/// A write-only primitive.
pub const fn prim_write_only(prop: &'static str, col: &'static str, kind: Kind) -> Col {
    Col { prop, col, kind, not_null: true, out: false, input: true, primitive: true }
}

/// A primitive Jackson cannot see by its own name (a Lombok `isX` field: the property is `x`).
pub const fn prim_hidden(prop: &'static str, col: &'static str, kind: Kind) -> Col {
    Col { prop, col, kind, not_null: true, out: false, input: false, primitive: true }
}

/// A write-only property (`@JsonProperty(access = WRITE_ONLY)`).
pub const fn write_only(prop: &'static str, col: &'static str, kind: Kind, not_null: bool) -> Col {
    Col { prop, col, kind, not_null, out: false, input: true, primitive: false }
}

/// A `@JsonIgnore` property: neither read nor written by Jackson, still a column.
pub const fn ignored(prop: &'static str, col: &'static str, kind: Kind, not_null: bool) -> Col {
    Col { prop, col, kind, not_null, out: false, input: false, primitive: false }
}

/// A property without a column.
pub const fn extra(prop: &'static str, kind: Kind) -> Col {
    Col { prop, col: "", kind, not_null: false, out: true, input: true, primitive: false }
}

/// `AbstractDTO`'s properties.
pub const ID: Col = col("id", "ID", Kind::U64, true);
pub const CREATED_AT: Col = col("createdAt", "CREATED_AT", Kind::Ts, true);
pub const CREATED_BY: Col = col("createdBy", "CREATED_BY", Kind::U64, false);
/// `AbstractUpdatableDTO`'s.
pub const UPDATED_AT: Col = col("updatedAt", "UPDATED_AT", Kind::Ts, true);
pub const UPDATED_BY: Col = col("updatedBy", "UPDATED_BY", Kind::U64, false);

/// A DTO class over one table.
pub struct Entity {
    /// `Class.getSimpleName()`, as `OBJECT_NOT_FOUND` names it.
    pub pojo: &'static str,
    pub table: &'static str,
    /// Every property in Jackson's order.
    pub cols: &'static [Col],
    /// `(PATCH key, property)` for each setter the class itself declares.
    pub setters: &'static [(&'static str, &'static str)],
    /// `(JSON key, property)` for the properties Jackson reads under another name (a Lombok
    /// `isX` boolean is set through `setX`, so the key is `x`).
    pub aliases: &'static [(&'static str, &'static str)],
    /// The filter language's view of the table: every stored column, as the shared generic
    /// DAO selects them.
    pub filter: Table,
    /// The client id column of a client-check DAO (`AbstractUpdatableClientCheckDAO`).
    pub client_column: Option<&'static str>,
}

/// A DTO's values, by property.
pub type Row = Map<String, Value>;

impl Entity {
    pub fn col(&self, prop: &str) -> Option<&Col> {
        self.cols.iter().find(|c| c.prop == prop)
    }

    fn stored(&self) -> impl Iterator<Item = &Col> {
        self.cols.iter().filter(|c| !c.col.is_empty())
    }

    /// The columns of a `SELECT`, qualified.
    pub fn select_list(&self) -> String {
        self.stored().map(|c| format!("{}.{}", self.table, c.col)).collect::<Vec<_>>().join(", ")
    }

    /// `record.into(Pojo.class)`.
    pub fn read_row(&self, row: &MySqlRow) -> AuthResult<Row> {
        let mut out = Row::new();
        for c in self.stored() {
            out.insert(c.prop.to_string(), read_value(row, c.col, c.kind)?);
        }
        Ok(out)
    }

    /// The DTO through Jackson, then the getter-only properties.
    pub fn to_json(&self, row: &Row, getters: Vec<(&str, Value)>) -> Value {
        let mut o = Obj::new();
        for c in self.cols.iter().filter(|c| c.out) {
            o = o.put(c.prop, row.get(c.prop).cloned().unwrap_or(Value::Null));
        }
        for (k, v) in getters {
            o = o.put(k, v);
        }
        o.build()
    }

    /// A request body read into the DTO (Jackson, unknown properties ignored), over the values
    /// the DTO's field initializers give it.
    pub fn from_body(&self, body: &Value, defaults: Row) -> AuthResult<Row> {
        let mut out = defaults;
        let keys = self.cols.iter().filter(|c| c.input).map(|c| (c.prop, c.prop)).chain(self.aliases.iter().copied());
        for (key, prop) in keys {
            let (Some(v), Some(c)) = (body.get(key), self.col(prop)) else { continue };
            let mut v = coerce(c.kind, v).map_err(|_| crate::web::unreadable())?;
            if v.is_null() && c.primitive {
                v = if c.kind == Kind::Bool { Value::Bool(false) } else { Value::from(0) };
            }
            out.insert(c.prop.to_string(), v);
        }
        Ok(out)
    }

    /// `AbstractJOOQUpdatableDataService.update(key, fields)`'s setter loop over `row`.
    pub fn patch(&self, row: &mut Row, fields: &Map<String, Value>) -> AuthResult<()> {
        for (key, value) in fields {
            let Some((_, prop)) = self.setters.iter().find(|(k, _)| k == key) else { continue };
            let Some(c) = self.col(prop) else { continue };
            let refused = || AuthError::literal(StatusCode::BAD_REQUEST, "SEC.FIELD_NOT_UPDATABLE", format!("{key}{FIELD_NOT_AVAILABLE}")).with_param("field", key);
            let mut v = coerce(c.kind, value).map_err(|_| refused())?;
            // `convertValue(null, int.class)` is the primitive's default.
            if v.is_null() && c.primitive {
                v = if c.kind == Kind::Bool { Value::Bool(false) } else { Value::from(0) };
            }
            row.insert(c.prop.to_string(), v);
        }
        Ok(())
    }

    /// The 404 `AbstractDAO.getRecordById` raises.
    pub fn not_found(&self, id: impl std::fmt::Display) -> AuthError {
        super::common::err(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &[self.pojo, &id.to_string()])
    }
}

/// A column read as the property's type.
pub fn read_value(row: &MySqlRow, col: &str, kind: Kind) -> AuthResult<Value> {
    Ok(match kind {
        Kind::U64 => int(row, col)?.map(|n| Value::from(n as u64)).unwrap_or(Value::Null),
        Kind::I64 => int(row, col)?.map(|n| Value::from(n as i64)).unwrap_or(Value::Null),
        Kind::Bool => int(row, col)?.map(|n| Value::Bool(n != 0)).unwrap_or(Value::Null),
        Kind::Str | Kind::Enum(_) => row.try_get::<Option<String>, _>(col)?.map(Value::String).unwrap_or(Value::Null),
        Kind::Ts => crate::mysql::ts(row, col)?.map(|t| Value::from(t.and_utc().timestamp())).unwrap_or(Value::Null),
        // A JSON column is its text (sqlx has no JSON type here without the `json` feature).
        Kind::Json => match row.try_get_unchecked::<Option<String>, _>(col)? {
            Some(s) => serde_json::from_str(&s).unwrap_or(Value::Null),
            None => Value::Null,
        },
    })
}

/// Any integer column (signed or not, `TINYINT(1)` included).
fn int(row: &MySqlRow, col: &str) -> AuthResult<Option<i128>> {
    if let Ok(v) = row.try_get::<Option<i64>, _>(col) {
        return Ok(v.map(i128::from));
    }
    if let Ok(v) = row.try_get::<Option<u64>, _>(col) {
        return Ok(v.map(i128::from));
    }
    Ok(row.try_get::<Option<bool>, _>(col)?.map(i128::from))
}

/// A property's value as the column binds it.
pub fn bind_of(kind: Kind, v: &Value) -> Bind {
    match (kind, v) {
        (_, Value::Null) => Bind::Null,
        (Kind::U64, Value::Number(n)) => Bind::U64(n.as_u64().unwrap_or(0)),
        (Kind::I64, Value::Number(n)) => Bind::I64(n.as_i64().unwrap_or(0)),
        (Kind::Bool, Value::Bool(b)) => Bind::I64(i64::from(*b)),
        (Kind::Ts, Value::Number(n)) => chrono::DateTime::from_timestamp(n.as_i64().unwrap_or(0), 0).map(Bind::Ts).unwrap_or(Bind::Null),
        (Kind::Json, v) => Bind::Str(v.to_string()),
        (_, Value::String(s)) => Bind::Str(s.clone()),
        (_, other) => Bind::Str(other.to_string()),
    }
}

/// The columns `record.from(pojo)` marks changed: a null on a `NOT NULL` column is not.
fn written(e: &Entity, row: &Row) -> Vec<(&'static str, Bind)> {
    e.stored()
        .filter_map(|c| {
            let v = row.get(c.prop).cloned().unwrap_or(Value::Null);
            (!(v.is_null() && c.not_null)).then(|| (c.col, bind_of(c.kind, &v)))
        })
        .collect()
}

impl Entity {
    /// The shared generic DAO's view of the table ([`crate::data::crud`]).
    pub fn crud(&self) -> crud::Entity {
        crud::Entity { table: Table { name: self.filter.name, columns: self.filter.columns }, client_column: self.client_column, not_null: &[] }
    }
}

/// `AbstractDAO.create`: the id is cleared, the row inserted, the new id returned.
pub async fn insert(db: &Db, e: &Entity, row: &Row) -> AuthResult<u64> {
    let mut r = row.clone();
    r.remove("id");
    db.entity_insert(&e.crud(), &written(e, &r)).await
}

/// `AbstractUpdatableDAO.update(entity)`: every mapped column but the creation ones, by id
/// (`updatedAt` is cleared first, so the column's `ON UPDATE` sets it).
pub async fn update(db: &Db, e: &Entity, row: &Row) -> AuthResult<()> {
    let Some(id) = row.get("id").and_then(Value::as_u64) else {
        // `idField.eq(null)` matches nothing.
        return Ok(());
    };
    let mut r = row.clone();
    r.insert("updatedAt".into(), Value::Null);
    db.entity_update(&e.crud(), id, &written(e, &r)).await?;
    Ok(())
}

/// `AbstractDAO.delete(id)`: the rows deleted.
pub async fn delete(db: &Db, e: &Entity, id: u64) -> AuthResult<u64> {
    db.entity_delete(&e.crud(), id).await
}

/// `getRecordById`: the row (with the caller's client-check joins, without their filter).
pub async fn by_id_as(db: &Db, e: &Entity, scope: ClientCheck, id: u64) -> AuthResult<Option<Row>> {
    db.entity_by_id(&e.crud(), scope, id).await?.as_ref().map(|r| e.read_row(r)).transpose()
}

/// A row by id, no joins.
pub async fn by_id(db: &Db, e: &Entity, id: u64) -> AuthResult<Option<Row>> {
    by_id_as(db, e, ClientCheck::All, id).await
}

/// `AbstractDAO.readById`: the row, or the DAO's 404.
pub async fn read_by_id(db: &Db, e: &Entity, id: u64) -> AuthResult<Row> {
    by_id(db, e, id).await?.ok_or_else(|| e.not_found(id))
}


/// `AbstractDAO.readPageFilter`: the page's rows and the count, under the caller's client check.
pub async fn page(db: &Db, e: &Entity, scope: ClientCheck, cond: Option<Sql>, pageable: &Pageable) -> AuthResult<(Vec<Row>, i64)> {
    let (rows, total) = db.entity_page(&e.crud(), scope, cond, pageable).await?;
    Ok((rows.iter().map(|r| e.read_row(r)).collect::<AuthResult<_>>()?, total))
}

/// The filter-language types of an entity's columns.
pub const fn col_type(kind: Kind) -> ColType {
    match kind {
        Kind::U64 | Kind::I64 | Kind::Bool => ColType::Num,
        Kind::Ts => ColType::Ts,
        Kind::Enum(_) => ColType::Enum,
        Kind::Str | Kind::Json => ColType::Str,
    }
}

/// Whether Jackson would leave a value out (`NON_EMPTY`).
pub fn omitted(v: &Value) -> bool {
    is_empty_value(v)
}

/// `ULong` of a row's property.
pub fn u64_of(row: &Row, prop: &str) -> Option<u64> {
    row.get(prop).and_then(Value::as_u64)
}

/// Text of a row's property.
pub fn str_of<'a>(row: &'a Row, prop: &str) -> Option<&'a str> {
    row.get(prop).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const E: &[&str] = &["LIVE", "DRAFT"];
    static COLS: [Col; 9] = [
        ID,
        CREATED_AT,
        CREATED_BY,
        UPDATED_AT,
        UPDATED_BY,
        col("name", "NAME", Kind::Str, true),
        write_only("secret", "SECRET", Kind::Str, false),
        extra("label", Kind::Enum(E)),
        prim("flag", "", Kind::Bool),
    ];
    const T: Entity = Entity {
        pojo: "Thing",
        table: "t",
        cols: &COLS,
        setters: &[("name", "name"), ("label", "label"), ("flag", "flag")],
        aliases: &[("theName", "name")],
        filter: Table { name: "t", columns: &[("ID", ColType::Num), ("NAME", ColType::Str)] },
        client_column: None,
    };

    #[test]
    fn json_and_bodies() {
        let row = T.from_body(&json!({"id": "4", "name": 5, "secret": "s", "label": "LIVE", "other": 1}), Row::new()).unwrap();
        assert_eq!(row["id"], 4);
        assert_eq!(row["name"], "5");
        let v = T.to_json(&row, vec![("extraGetter", json!(true))]);
        assert_eq!(v, json!({"id": 4, "name": "5", "label": "LIVE", "extraGetter": true}));
        assert!(T.from_body(&json!({"label": "X"}), Row::new()).is_err());
        assert_eq!(T.from_body(&json!({"theName": "n"}), Row::new()).unwrap()["name"], "n");
        assert_eq!(T.select_list(), "t.ID, t.CREATED_AT, t.CREATED_BY, t.UPDATED_AT, t.UPDATED_BY, t.NAME, t.SECRET");
        assert_eq!(T.not_found(9).message(), "Thing with id 9 not found");
        assert!(T.col("nope").is_none());
    }

    #[test]
    fn patch_uses_declared_setters_only() {
        let mut row = T.from_body(&json!({"id": 1, "name": "a"}), Row::new()).unwrap();
        T.patch(&mut row, json!({"name": "b", "id": 7, "secret": "x"}).as_object().unwrap()).unwrap();
        assert_eq!((row["id"].clone(), row["name"].clone()), (json!(1), json!("b")));
        assert!(row.get("secret").is_none());
        let e = T.patch(&mut row, json!({"label": "BAD"}).as_object().unwrap()).unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(e.message(), "label field cannot be updated, it might not be available or unmodifiable");
        T.patch(&mut row, json!({"flag": null}).as_object().unwrap()).unwrap();
        assert_eq!(row["flag"], false);
    }

    #[test]
    fn jooq_written_columns() {
        let row = T.from_body(&json!({"id": 1, "createdBy": 3}), Row::new()).unwrap();
        let cols: Vec<&str> = written(&T, &row).into_iter().map(|(c, _)| c).collect();
        // NAME is NOT NULL and null: left to the default; SECRET is nullable: written as NULL.
        assert_eq!(cols, vec!["ID", "CREATED_BY", "UPDATED_BY", "SECRET"]);
        assert_eq!(T.crud().table.name, "t");
        assert_eq!(col_type(Kind::Bool), ColType::Num);
        assert_eq!(col_type(Kind::Ts), ColType::Ts);
        assert_eq!(col_type(Kind::Enum(E)), ColType::Enum);
        assert_eq!(col_type(Kind::Json), ColType::Str);
        assert!(omitted(&Value::Null) && !omitted(&json!(0)));
        assert_eq!(u64_of(&row, "id"), Some(1));
        assert_eq!(str_of(&row, "id"), None);
    }

    #[test]
    fn binds() {
        assert_eq!(bind_of(Kind::U64, &json!(1)), Bind::U64(1));
        assert_eq!(bind_of(Kind::I64, &json!(-1)), Bind::I64(-1));
        assert_eq!(bind_of(Kind::Bool, &json!(true)), Bind::I64(1));
        assert!(matches!(bind_of(Kind::Ts, &json!(0)), Bind::Ts(_)));
        assert_eq!(bind_of(Kind::Json, &json!({"a": 1})), Bind::Str("{\"a\":1}".into()));
        assert_eq!(bind_of(Kind::Str, &json!("s")), Bind::Str("s".into()));
        assert_eq!(bind_of(Kind::Str, &json!(3)), Bind::Str("3".into()));
        assert_eq!(bind_of(Kind::Str, &Value::Null), Bind::Null);
    }

    #[test]
    fn column_kinds_at_run_time() {
        let all = [
            col("a", "A", Kind::Str, true),
            prim("b", "B", Kind::Bool),
            prim_write_only("c", "C", Kind::I64),
            prim_hidden("d", "D", Kind::Bool),
            write_only("e", "E", Kind::Str, false),
            ignored("f", "F", Kind::Str, true),
            extra("g", Kind::Json),
        ];
        let flags: Vec<(bool, bool, bool)> = all.iter().map(|c| (c.out, c.input, c.primitive)).collect();
        assert_eq!(
            flags,
            vec![(true, true, false), (true, true, true), (false, true, true), (false, false, true), (false, true, false), (false, false, false), (true, true, false)]
        );
        // A null for a primitive boolean is false.
        let r = T.from_body(&json!({"flag": null}), Row::new()).unwrap();
        assert_eq!(r["flag"], json!(false));
    }

    #[tokio::test]
    async fn an_update_without_an_id_matches_nothing() {
        let s = crate::admin::users::testkit::offline();
        assert!(update(&s.db, &T, &Row::new()).await.is_ok());
    }
}
