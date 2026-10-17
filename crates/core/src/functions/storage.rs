//! `CoreServices.Storage`: the KIRun functions over the storage policy layer, with the Java
//! signatures (`functions/storage/*`). Rows go in as `StorageJson.toMap` reads them (longs
//! kept apart from doubles) and come out as `gson.toJsonTree` writes them; a missing object
//! (`StorageObjectNotFoundException`) is the only error a function answers itself.

use std::sync::Arc;

use appdata::model::{AggregateQuery, DataObject, DraftCopyFilter, Follow, Page, Query, Sort};
use appdata::value::{Document, Value as DataValue};
use async_trait::async_trait;
use indexmap::IndexMap;
use kirun::json::schema::array::ArraySchemaType;
use kirun::json::schema::r#type::SchemaType;
use kirun::json::schema::r#type::TypeUtil;
use kirun::json::schema::Schema;
use kirun::model::{Event, EventResult, FunctionOutput, FunctionSignature, Parameter};
use kirun::{Map, Value};

use super::{arg, arg_string, output, CoreFunction};
use crate::error::CoreError;
use crate::storage::service::AppDataService;
use crate::storage::values::{gson_object, gson_tree, storage_document, storage_value};

pub const NAMESPACE: &str = "CoreServices.Storage";

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

fn result_events(output_schema: Schema) -> Map<Event> {
    Map::from([
        Event::output_event_map_entry(Map::from([("result".to_string(), output_schema)])),
        Event::event_map_entry(Event::ERROR, Map::from([("result".to_string(), Schema::of_any("result"))])),
    ])
}

fn p(name: &str, schema: Schema) -> (String, Parameter) {
    Parameter::of_entry(name, schema, false)
}

fn code(name: &str) -> (String, Parameter) {
    p(name, Schema::of_string(name).set_default_value(s("")))
}

fn flag(name: &str, default: bool) -> (String, Parameter) {
    p(name, Schema::of_boolean(name).set_default_value(Value::Bool(default)))
}

fn int(name: &str, default: i64) -> (String, Parameter) {
    p(name, Schema::of_integer(name).set_default_value(Value::from(default)))
}

fn object(name: &str) -> (String, Parameter) {
    p(name, Schema::of_object(name).set_default_value(Value::Object(Default::default())))
}

fn list_of(name: &str, item: Schema) -> (String, Parameter) {
    p(name, Schema::of_array(name, vec![item]).set_default_value(Value::Array(Vec::new())))
}

fn strings(name: &str) -> (String, Parameter) {
    Parameter::of_entry(name, Schema::of_string(name), true)
}

fn signature(name: &str, params: Vec<(String, Parameter)>, output_schema: Schema) -> FunctionSignature {
    FunctionSignature::new(name)
        .set_namespace(NAMESPACE)
        .set_parameters(params.into_iter().collect())
        .set_events(result_events(output_schema))
}

fn enums(values: &[&str]) -> Vec<Value> {
    values.iter().map(|v| s(v)).collect()
}

fn object_schema(name: &str, props: Vec<(&str, Schema)>) -> Schema {
    Schema::new()
        .set_name(name)
        .set_type(TypeUtil::of(&[SchemaType::Object]))
        .set_properties(props.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// `appCode` / `clientCode`: null or blank is none (`StringUtil.isNullOrBlank`).
fn opt_code(args: &Map<Value>, name: &str) -> Result<Option<String>, CoreError> {
    match arg(args, name) {
        Value::Null => Ok(None),
        _ => Ok(Some(arg_string(args, name)?).filter(|c| !c.trim().is_empty())),
    }
}

fn bool_arg(args: &Map<Value>, name: &str) -> bool {
    match arg(args, name) {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// `getAsInt()` of a number argument.
fn int_arg(args: &Map<Value>, name: &str) -> Result<i32, CoreError> {
    match arg(args, name) {
        Value::Number(n) => Ok(n.as_i64().map(|i| i as i32).unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i32)),
        Value::String(t) => t.trim().parse().map_err(|_| CoreError::unknown(format!("For input string: \"{t}\""))),
        _ => Err(CoreError::unknown(format!("{name} is not a number"))),
    }
}

/// `eagerFields`: every element's `getAsString()`.
fn eager_fields(args: &Map<Value>) -> Result<Vec<String>, CoreError> {
    match arg(args, "eagerFields") {
        Value::Array(a) => a.iter().map(element_string).collect(),
        _ => Ok(Vec::new()),
    }
}

fn element_string(v: &Value) -> Result<String, CoreError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(crate::gson::number_to_java_string(n)),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Err(CoreError::unknown("JsonNull")),
        _ => Err(CoreError::unknown("Not a JSON Primitive")),
    }
}

/// `stringList`: nulls and blanks left out.
fn string_list(args: &Map<Value>, name: &str) -> Result<Vec<String>, CoreError> {
    match arg(args, name) {
        Value::Null => Ok(Vec::new()),
        Value::Array(a) => {
            let mut out = Vec::new();
            for e in a.iter().filter(|e| !e.is_null()) {
                let s = element_string(e)?;
                if !s.trim().is_empty() {
                    out.push(s);
                }
            }
            Ok(out)
        }
        _ => Err(CoreError::unknown("Not a JSON Array")),
    }
}

/// `mapper.convertValue(StorageJson.toMap(filter), AbstractCondition.class)`, none when the
/// filter is empty.
fn condition_of(filter: &Value) -> Result<DataValue, CoreError> {
    match filter {
        Value::Object(o) if !o.is_empty() => Ok(DataValue::Object(storage_document(o))),
        _ => Ok(DataValue::Null),
    }
}

fn rows_of(v: &Value) -> Result<Vec<DataValue>, CoreError> {
    match v {
        Value::Array(a) if !a.is_empty() => Ok(a.iter().map(storage_value).collect()),
        _ => Ok(Vec::new()),
    }
}

fn error_event(message: &str) -> FunctionOutput {
    let mut m = Map::new();
    m.insert(Event::ERROR.to_string(), s(message));
    FunctionOutput::new(vec![EventResult::of(Event::ERROR, m)])
}

fn row_output(row: &Document) -> Result<FunctionOutput, CoreError> {
    Ok(output("result", Value::Object(gson_object(row)?.into_iter().collect())))
}

fn rows_output(rows: &[Document]) -> Result<FunctionOutput, CoreError> {
    let list = rows.iter().map(|r| gson_object(r).map(Value::Object)).collect::<Result<Vec<_>, _>>()?;
    Ok(output("result", Value::Array(list)))
}

/// The page map the read functions answer with (`Map.of`, written by Gson).
fn page_output(page: &Page<Document>, with_sort: bool) -> Result<FunctionOutput, CoreError> {
    let content = page.content.iter().map(|r| gson_object(r).map(Value::Object)).collect::<Result<Vec<_>, _>>()?;
    let mut info = serde_json::Map::new();
    info.insert("first".into(), Value::Bool(page.is_first()));
    info.insert("last".into(), Value::Bool(page.is_last()));
    info.insert("size".into(), Value::from(page.pageable.size));
    info.insert("page".into(), Value::from(page.number()));
    info.insert("totalElements".into(), Value::from(page.total));
    info.insert("totalPages".into(), Value::from(page.total_pages()));
    if with_sort {
        info.insert("sort".into(), gson_sort(&page.pageable.sort));
    }
    info.insert("numberOfElements".into(), Value::from(page.content.len() as i64));
    let mut pg = serde_json::Map::new();
    pg.insert("content".into(), Value::Array(content));
    pg.insert("page".into(), Value::Object(info));
    pg.insert("total".into(), Value::from(page.total));
    Ok(output("result", Value::Object(pg)))
}

/// Gson's reflective write of Spring's `Sort`: its `orders` and each order's fields.
fn gson_sort(sort: &Sort) -> Value {
    let orders: Vec<Value> = sort
        .orders
        .iter()
        .map(|o| {
            serde_json::json!({
                "direction": o.direction.name(),
                "property": o.property,
                "ignoreCase": o.ignore_case,
                "nullHandling": o.null_handling.name(),
            })
        })
        .collect();
    serde_json::json!({ "orders": orders })
}

fn data_object(v: &DataValue) -> DataObject {
    match v {
        DataValue::Object(o) => DataObject::of(o.clone()),
        _ => DataObject::default(),
    }
}

/// `StorageJson.toMapList`: each element a map.
fn data_objects(v: &Value) -> Result<Vec<DataObject>, CoreError> {
    let Value::Array(a) = v else { return Ok(Vec::new()) };
    let mut out = Vec::with_capacity(a.len());
    for (i, e) in a.iter().enumerate() {
        match e {
            Value::Object(o) => out.push(DataObject::of(storage_document(o))),
            Value::Null => out.push(DataObject::default()),
            _ => {
                return Err(CoreError::unknown(format!(
                    "java.lang.IllegalStateException: Expected BEGIN_OBJECT but was {} at line 1 column 2 path $[{i}]",
                    match e {
                        Value::Array(_) => "BEGIN_ARRAY",
                        Value::String(_) => "STRING",
                        Value::Bool(_) => "BOOLEAN",
                        _ => "NUMBER",
                    }
                )))
            }
        }
    }
    Ok(out)
}

macro_rules! storage_function {
    ($name:ident) => {
        pub struct $name {
            signature: FunctionSignature,
            service: Arc<AppDataService>,
        }

        impl $name {
            pub fn new(service: Arc<AppDataService>) -> Self {
                Self { signature: Self::make_signature(), service }
            }
        }
    };
}

storage_function!(Create);
storage_function!(CreateMany);
storage_function!(Read);
storage_function!(ReadPage);
storage_function!(Update);
storage_function!(UpdateMany);
storage_function!(Delete);
storage_function!(DeleteByFilter);
storage_function!(Aggregate);
storage_function!(GetVersionDetails);
storage_function!(ClearDraft);
storage_function!(CopyToDraft);

fn sort_order(with_case: bool) -> Schema {
    let mut props = vec![
        ("direction", Schema::of_string("direction").set_enums(enums(&["ASC", "DESC"])).set_default_value(s("ASC"))),
        ("property", Schema::of_string("property")),
    ];
    if with_case {
        props.push(("ignoreCase", Schema::of_boolean("ignoreCase").set_default_value(Value::Bool(true))));
        props.push((
            "nullHandling",
            Schema::of_string("nullHandling")
                .set_enums(enums(&["NATIVE", "NULLS_FIRST", "NULLS_LAST"]))
                .set_default_value(s("NATIVE")),
        ));
    }
    object_schema("SortOrder", props)
}

impl Create {
    fn make_signature() -> FunctionSignature {
        signature(
            "Create",
            vec![
                p("storageName", Schema::of_string("storageName")),
                p("dataObject", Schema::of_object("dataObject")),
                code("appCode"),
                code("clientCode"),
                flag("eager", false),
                strings("eagerFields"),
            ],
            Schema::of_any("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for Create {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let data = storage_value(arg(args, "dataObject"));
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let eager = bool_arg(args, "eager");
        let fields = eager_fields(args)?;
        let created = self
            .service
            .create(app.as_deref(), client.as_deref(), &storage, data_object(&data), Some(eager), Some(fields))
            .await?;
        row_output(&created)
    }
}

impl CreateMany {
    fn make_signature() -> FunctionSignature {
        signature(
            "CreateMany",
            vec![
                p(
                    "storageName",
                    Schema::of_string("storageName"),
                ),
                p(
                    "dataArray",
                    Schema::of_array("dataArray", Vec::new()).set_items(ArraySchemaType::of(vec![Schema::of_any("dataArray")])),
                ),
                code("appCode"),
                code("clientCode"),
                flag("eager", false),
                strings("eagerFields"),
            ],
            Schema::of_any("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for CreateMany {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let eager = bool_arg(args, "eager");
        let fields = eager_fields(args)?;
        let rows = data_objects(arg(args, "dataArray"))?;
        let created = self
            .service
            .create_many(app.as_deref(), client.as_deref(), &storage, rows, Some(eager), Some(fields))
            .await?;
        rows_output(&created)
    }
}

impl Read {
    fn make_signature() -> FunctionSignature {
        signature(
            "Read",
            vec![
                p("storageName", Schema::of_string("storageName")),
                p("dataObjectId", Schema::of_string("dataObjectId")),
                code("appCode"),
                code("clientCode"),
                flag("eager", false),
                strings("eagerFields"),
            ],
            Schema::of_any("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for Read {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let id = arg_string(args, "dataObjectId")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let eager = bool_arg(args, "eager");
        let fields = eager_fields(args)?;
        match self.service.read(app.as_deref(), client.as_deref(), &storage, &id, Some(eager), Some(fields)).await {
            Ok(row) => row_output(&row),
            Err(e) if e.is_object_not_found() => Ok(output("result", Value::Object(Default::default()))),
            Err(e) => Err(e),
        }
    }
}

impl ReadPage {
    fn make_signature() -> FunctionSignature {
        signature(
            "ReadPage",
            vec![
                p("storageName", Schema::of_string("storageName")),
                object("filter"),
                int("page", 0),
                int("size", 20),
                flag("count", true),
                list_of("sort", sort_order(true)),
                code("appCode"),
                code("clientCode"),
                flag("eager", false),
                strings("eagerFields"),
                strings("ignoreFields"),
                list_of("joins", Schema::of_object("join")),
                list_of("subQueries", Schema::of_object("subQuery")),
            ],
            Schema::of_any("result"),
        )
    }
}

/// `getSortObj`: each order's direction and property, with its case and nulls handling.
fn read_page_sort(sort: &Value) -> Result<DataValue, CoreError> {
    let mut orders = Vec::new();
    for o in sort.as_array().map(Vec::as_slice).unwrap_or_default() {
        let Value::Object(o) = o else { return Err(CoreError::unknown("Not a JSON Object")) };
        let get = |k: &str| o.get(k).map(element_string).transpose();
        let direction = get("direction")?.ok_or_else(|| CoreError::unknown("direction is null"))?;
        let property = get("property")?.ok_or_else(|| {
            CoreError::unknown("Cannot invoke \"com.google.gson.JsonElement.getAsString()\" because the return value of \"com.google.gson.JsonObject.get(String)\" is null")
        })?;
        if property.trim().is_empty() {
            return Err(CoreError::unknown("Property must not be null or empty"));
        }
        let mut order = Document::new();
        order.insert("direction".into(), DataValue::from(if direction.eq_ignore_ascii_case("desc") { "DESC" } else { "ASC" }));
        order.insert("property".into(), DataValue::String(property));
        if matches!(o.get("ignoreCase"), Some(Value::Bool(true))) {
            order.insert("ignoreCase".into(), DataValue::from("true"));
        }
        if let Some(n) = o.get("nullHandling") {
            let n = element_string(n)?;
            let h = match n.as_str() {
                "NULLS_FIRST" | "NULLS_LAST" => n,
                _ => "NATIVE".into(),
            };
            order.insert("nullHandling".into(), DataValue::String(h));
        }
        orders.push(DataValue::Object(order));
    }
    Ok(DataValue::Array(orders))
}

/// The parts of a query a function takes from objects: the condition, joins and
/// sub-queries, read the way Jackson reads a `Query`.
fn query_with(condition: DataValue, joins: Vec<DataValue>, sub_queries: Vec<DataValue>) -> Result<Query, CoreError> {
    let mut d = Document::new();
    d.insert("condition".into(), condition);
    if !joins.is_empty() {
        d.insert("joins".into(), DataValue::Array(joins));
    }
    if !sub_queries.is_empty() {
        d.insert("subQueries".into(), DataValue::Array(sub_queries));
    }
    let condition = d.get("condition").cloned().unwrap_or(DataValue::Null);
    Query::from_value(&DataValue::Object(d)).map_err(|e| unreadable_condition(&condition, e))
}

/// A query Jackson could not read: `AbstractConditionDeserializer` refusing the condition
/// itself is its `GenericException` (400 "Invalid condition"), which Java lets through; any
/// other problem (a condition nested deeper, which Jackson wraps) is an unknown error.
fn unreadable_condition(condition: &DataValue, e: String) -> CoreError {
    if e == "Invalid condition" && appdata::model::Condition::refused_at_top(condition) {
        return CoreError::coded(axum::http::StatusCode::BAD_REQUEST, "CORE.CONDITION_INVALID", e);
    }
    CoreError::unknown(e)
}

#[async_trait]
impl CoreFunction for ReadPage {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let page = int_arg(args, "page")?;
        let size = int_arg(args, "size")?;
        let eager = bool_arg(args, "eager");
        let fields = eager_fields(args)?;
        let ignore = string_list(args, "ignoreFields")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let mut q = query_with(condition_of(arg(args, "filter"))?, rows_of(arg(args, "joins"))?, rows_of(arg(args, "subQueries"))?)?;
        q.exclude_fields = Some(!ignore.is_empty());
        q.fields = Some(ignore);
        q.page = page;
        q.size = size;
        q.count = Some(true);
        q.eager = Some(eager);
        q.sort = Sort::from_value(&read_page_sort(arg(args, "sort"))?).map_err(CoreError::unknown)?;
        q.eager_fields = Some(fields);
        let pg = self.service.read_page(app.as_deref(), client.as_deref(), &storage, &q).await?;
        page_output(&pg, true)
    }
}

impl Update {
    fn make_signature() -> FunctionSignature {
        signature(
            "Update",
            vec![
                p("storageName", Schema::of_string("storageName")),
                flag("isPartial", false),
                p("dataObjectId", Schema::of_string("dataObjectId")),
                p("dataObject", Schema::of_object("dataObject")),
                code("appCode"),
                code("clientCode"),
                flag("eager", false),
                strings("eagerFields"),
            ],
            Schema::of_any("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for Update {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let partial = bool_arg(args, "isPartial");
        let id = arg_string(args, "dataObjectId")?;
        let eager = bool_arg(args, "eager");
        let fields = eager_fields(args)?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let mut row = match storage_value(arg(args, "dataObject")) {
            DataValue::Object(o) => o,
            _ => Document::new(),
        };
        row.insert("_id".into(), DataValue::String(id));
        match self
            .service
            .update(app.as_deref(), client.as_deref(), &storage, DataObject::of(row), !partial, Some(eager), Some(fields))
            .await
        {
            Ok(row) => row_output(&row),
            Err(e) if e.is_object_not_found() => Ok(output("result", Value::Object(Default::default()))),
            Err(e) => Err(e),
        }
    }
}

impl UpdateMany {
    fn make_signature() -> FunctionSignature {
        signature(
            "UpdateMany",
            vec![
                p("storageName", Schema::of_string("storageName")),
                p(
                    "dataArray",
                    Schema::of_array("dataArray", Vec::new()).set_items(ArraySchemaType::of(vec![Schema::of_any("dataArray")])),
                ),
                code("appCode"),
                code("clientCode"),
                flag("eager", false),
                strings("eagerFields"),
                flag("isPartial", false),
            ],
            Schema::of_any("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for UpdateMany {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let eager = bool_arg(args, "eager");
        let partial = bool_arg(args, "isPartial");
        let fields = eager_fields(args)?;
        let rows = data_objects(arg(args, "dataArray"))?;
        let updated = self
            .service
            .update_many(app.as_deref(), client.as_deref(), &storage, rows, !partial, Some(eager), Some(fields))
            .await?;
        rows_output(&updated)
    }
}

impl Delete {
    fn make_signature() -> FunctionSignature {
        signature(
            "Delete",
            vec![
                p("storageName", Schema::of_string("storageName")),
                p("dataObjectId", Schema::of_string("dataObjectId")),
                code("appCode"),
                code("clientCode"),
                flag("deleteVersion", false),
            ],
            Schema::of_boolean("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for Delete {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let id = arg_string(args, "dataObjectId")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let delete_version = bool_arg(args, "deleteVersion");
        match self.service.delete(app.as_deref(), client.as_deref(), &storage, &id, Some(delete_version)).await {
            Ok(b) => Ok(output("result", Value::Bool(b))),
            Err(e) if e.is_object_not_found() => Ok(output("result", Value::Bool(false))),
            Err(e) => Err(e),
        }
    }
}

impl DeleteByFilter {
    fn make_signature() -> FunctionSignature {
        signature(
            "DeleteByFilter",
            vec![
                p("storageName", Schema::of_string("storageName")),
                object("filter"),
                flag("devMode", false),
                flag("deleteVersion", false),
                code("appCode"),
                code("clientCode"),
            ],
            Schema::of_long("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for DeleteByFilter {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let dev_mode = bool_arg(args, "devMode");
        let delete_version = bool_arg(args, "deleteVersion");
        let mut q = query_with(condition_of(arg(args, "filter"))?, Vec::new(), Vec::new())?;
        q.exclude_fields = Some(false);
        q.fields = Some(Vec::new());
        let n = match self
            .service
            .delete_by_filter(app.as_deref(), client.as_deref(), &storage, &q, Some(dev_mode), Some(delete_version))
            .await
        {
            Ok(n) => n,
            Err(e) if e.is_object_not_found() => 0,
            Err(e) => return Err(e),
        };
        Ok(output("result", serde_json::json!({ "deletedCount": n })))
    }
}

impl Aggregate {
    fn make_signature() -> FunctionSignature {
        let group_by = object_schema(
            "GroupByField",
            vec![
                ("field", Schema::of_string("field")),
                ("alias", Schema::of_string("alias")),
                (
                    "bucket",
                    Schema::of_string("bucket").set_enums(enums(&["YEAR", "QUARTER", "MONTH", "WEEK", "ISO_WEEK", "DAY", "HOUR"])),
                ),
                ("encoding", Schema::of_string("encoding").set_enums(enums(&["EPOCH_SECONDS", "EPOCH_MILLIS"]))),
                ("timezone", Schema::of_string("timezone").set_default_value(s("UTC"))),
            ],
        );
        let aggregation = object_schema(
            "Aggregation",
            vec![
                (
                    "function",
                    Schema::of_string("function").set_enums(enums(&["MAX", "MIN", "SUM", "AVG", "COUNT", "COUNT_DISTINCT"])),
                ),
                ("field", Schema::of_string("field")),
                ("alias", Schema::of_string("alias")),
            ],
        );
        signature(
            "Aggregate",
            vec![
                p("storageName", Schema::of_string("storageName")),
                object("filter"),
                object("having"),
                list_of("groupBy", group_by),
                list_of("aggregations", aggregation),
                list_of("sort", sort_order(false)),
                int("page", 0),
                int("size", 100),
                flag("count", false),
                code("appCode"),
                code("clientCode"),
                list_of("joins", Schema::of_object("join")),
                list_of("subQueries", Schema::of_object("subQuery")),
            ],
            Schema::of_any("result"),
        )
    }
}

/// `str(o, key)`: absent, null or blank is none.
fn str_of(o: &serde_json::Map<String, Value>, key: &str) -> Result<Option<String>, CoreError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(element_string(v)?).filter(|s| !s.trim().is_empty())),
    }
}

/// `AggregateStorageObject.toQuery`.
pub fn aggregate_query(args: &Map<Value>) -> Result<AggregateQuery, CoreError> {
    let mut d = Document::new();
    d.insert("condition".into(), condition_of(arg(args, "filter"))?);
    d.insert("having".into(), condition_of(arg(args, "having"))?);
    let objects = |name: &str| -> Result<Vec<serde_json::Map<String, Value>>, CoreError> {
        let mut out = Vec::new();
        for e in arg(args, name).as_array().map(Vec::as_slice).unwrap_or_default() {
            match e {
                Value::Null => {}
                Value::Object(o) => out.push(o.clone()),
                _ => return Err(CoreError::unknown("Not a JSON Object")),
            }
        }
        Ok(out)
    };
    let mut groups = Vec::new();
    for o in objects("groupBy")? {
        let mut g = Document::new();
        let put = |g: &mut Document, k: &str, v: Option<String>| {
            if let Some(v) = v {
                g.insert(k.into(), DataValue::String(v));
            }
        };
        put(&mut g, "field", str_of(&o, "field")?);
        put(&mut g, "alias", str_of(&o, "alias")?);
        put(&mut g, "bucket", str_of(&o, "bucket")?.map(|b| b.to_uppercase()));
        put(&mut g, "encoding", str_of(&o, "encoding")?.map(|b| b.to_uppercase()));
        put(&mut g, "timezone", str_of(&o, "timezone")?);
        groups.push(DataValue::Object(g));
    }
    d.insert("groupBy".into(), DataValue::Array(groups));
    let mut aggs = Vec::new();
    for o in objects("aggregations")? {
        let mut a = Document::new();
        if let Some(f) = str_of(&o, "field")? {
            a.insert("field".into(), DataValue::String(f));
        }
        if let Some(f) = str_of(&o, "alias")? {
            a.insert("alias".into(), DataValue::String(f));
        }
        if let Some(f) = str_of(&o, "function")? {
            a.insert("function".into(), DataValue::String(f.to_uppercase()));
        }
        aggs.push(DataValue::Object(a));
    }
    d.insert("aggregations".into(), DataValue::Array(aggs));
    let mut orders = Vec::new();
    for o in objects("sort")? {
        let Some(property) = str_of(&o, "property")? else { continue };
        let desc = str_of(&o, "direction")?.is_some_and(|d| d.eq_ignore_ascii_case("desc"));
        let mut order = Document::new();
        order.insert("direction".into(), DataValue::from(if desc { "DESC" } else { "ASC" }));
        order.insert("property".into(), DataValue::String(property));
        orders.push(DataValue::Object(order));
    }
    if !orders.is_empty() {
        d.insert("sort".into(), DataValue::Array(orders));
    }
    d.insert("page".into(), DataValue::Int(int_arg(args, "page")? as i64));
    d.insert("size".into(), DataValue::Int(int_arg(args, "size")? as i64));
    d.insert("count".into(), DataValue::Bool(bool_arg(args, "count")));
    let joins = rows_of(arg(args, "joins"))?;
    if !joins.is_empty() {
        d.insert("joins".into(), DataValue::Array(joins));
    }
    let subs = rows_of(arg(args, "subQueries"))?;
    if !subs.is_empty() {
        d.insert("subQueries".into(), DataValue::Array(subs));
    }
    AggregateQuery::from_value(&DataValue::Object(d)).map_err(CoreError::unknown)
}

#[async_trait]
impl CoreFunction for Aggregate {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let q = aggregate_query(args)?;
        let pg = self.service.aggregate(app.as_deref(), client.as_deref(), &storage, &q).await?;
        page_output(&pg, false)
    }
}

impl GetVersionDetails {
    fn make_signature() -> FunctionSignature {
        signature(
            "GetVersionDetails",
            vec![
                p("storageName", Schema::of_string("storageName")),
                p("objectId", Schema::of_string("objectId")),
                flag("includeObject", true),
                object("filter"),
                int("page", 0),
                int("size", 20),
                flag("count", true),
                code("appCode"),
                code("clientCode"),
            ],
            Schema::of_any("result"),
        )
    }
}

#[async_trait]
impl CoreFunction for GetVersionDetails {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let storage = arg_string(args, "storageName")?;
        let object_id = match arg(args, "objectId") {
            Value::Null => None,
            _ => Some(arg_string(args, "objectId")?),
        };
        let Some(object_id) = object_id.filter(|o| !o.trim().is_empty()) else {
            return Ok(error_event("objectId is required to read a row's version history."));
        };
        let include = bool_arg(args, "includeObject");
        let mut q = query_with(condition_of(arg(args, "filter"))?, Vec::new(), Vec::new())?;
        q.page = int_arg(args, "page")?;
        q.size = int_arg(args, "size")?;
        q.count = Some(bool_arg(args, "count"));
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let pg = self
            .service
            .read_page_version(app.as_deref(), client.as_deref(), &storage, &object_id, &q, Some(include))
            .await?;
        page_output(&pg, false)
    }
}

impl ClearDraft {
    fn make_signature() -> FunctionSignature {
        signature("ClearDraft", vec![code("appCode"), code("clientCode")], Schema::of_object("result"))
    }
}

fn counts_output(m: &IndexMap<String, i64>) -> FunctionOutput {
    output("result", Value::Object(m.iter().map(|(k, v)| (k.clone(), Value::from(*v))).collect()))
}

#[async_trait]
impl CoreFunction for ClearDraft {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let cleared = self.service.clear_draft_data(app.as_deref(), client.as_deref()).await?;
        Ok(counts_output(&cleared))
    }
}

impl CopyToDraft {
    fn make_signature() -> FunctionSignature {
        signature("CopyToDraft", vec![object("filters"), code("appCode"), code("clientCode")], Schema::of_object("result"))
    }
}

/// `mapper.convertValue(filters, Map<String, DraftCopyFilter>)`.
pub fn draft_copy_filters(v: &Value) -> Result<IndexMap<String, DraftCopyFilter>, CoreError> {
    let mut out = IndexMap::new();
    let Value::Object(o) = v else { return Ok(out) };
    for (name, f) in o {
        let filter = match f {
            Value::Null => DraftCopyFilter::default(),
            Value::Object(f) => {
                let condition = match f.get("condition") {
                    None | Some(Value::Null) => None,
                    Some(c) => appdata::model::Condition::from_value(&storage_value(c)).map_err(CoreError::unknown)?,
                };
                let follow = match f.get("follow") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(a)) => {
                        let mut list = Vec::new();
                        for x in a {
                            let Value::Object(x) = x else { return Err(CoreError::unknown("Cannot deserialize Follow")) };
                            let get = |k: &str| x.get(k).and_then(Value::as_str).map(str::to_string);
                            list.push(Follow {
                                field: get("field").unwrap_or_default(),
                                storage: get("storage").unwrap_or_default(),
                                ref_field: get("refField"),
                            });
                        }
                        Some(list)
                    }
                    Some(_) => return Err(CoreError::unknown("Cannot deserialize value of type `java.util.ArrayList`")),
                };
                DraftCopyFilter { condition, follow }
            }
            _ => return Err(CoreError::unknown("Cannot construct instance of `DraftCopyFilter`")),
        };
        out.insert(name.clone(), filter);
    }
    Ok(out)
}

#[async_trait]
impl CoreFunction for CopyToDraft {
    fn signature(&self) -> &FunctionSignature {
        &self.signature
    }

    async fn internal_execute(&self, args: &Map<Value>) -> Result<FunctionOutput, CoreError> {
        let filters = draft_copy_filters(arg(args, "filters"))?;
        let (app, client) = (opt_code(args, "appCode")?, opt_code(args, "clientCode")?);
        let copied = self.service.copy_app_to_draft(app.as_deref(), client.as_deref(), filters).await?;
        Ok(counts_output(&copied))
    }
}

/// Every storage function, in the order `makeStorageFunctions` registers them.
pub fn all(service: &Arc<AppDataService>) -> Vec<Arc<dyn kirun::function::Function>> {
    use super::Core;
    vec![
        Arc::new(Core(ClearDraft::new(service.clone()))),
        Arc::new(Core(CopyToDraft::new(service.clone()))),
        Arc::new(Core(Create::new(service.clone()))),
        Arc::new(Core(CreateMany::new(service.clone()))),
        Arc::new(Core(Delete::new(service.clone()))),
        Arc::new(Core(Update::new(service.clone()))),
        Arc::new(Core(Read::new(service.clone()))),
        Arc::new(Core(ReadPage::new(service.clone()))),
        Arc::new(Core(DeleteByFilter::new(service.clone()))),
        Arc::new(Core(Aggregate::new(service.clone()))),
        Arc::new(Core(UpdateMany::new(service.clone()))),
        Arc::new(Core(GetVersionDetails::new(service.clone()))),
    ]
}

/// The JSON a stored value is written as for a function's caller (`gson.toJsonTree`).
pub fn gson(v: &DataValue) -> Result<Value, CoreError> {
    gson_tree(v)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use appdata::model::{AggregateFunction, DateBucketUnit, JoinType};
    use appdata::value::Value as DV;
    use kirun::function::Function;
    use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
    use kirun::runtime::FunctionExecutionParameters;
    use serde_json::json;

    use super::*;
    use crate::context;
    use crate::testing::{auth, policy, request, security_stub, MemoryCatalog, MemoryEngine, RecordingEvents};

    // Port of commons-core `AggregateStorageObjectTest`.

    fn args(over: serde_json::Value) -> Map<Value> {
        let mut m: Map<Value> = json!({"filter": {}, "having": {}, "groupBy": [], "aggregations": [], "sort": [], "page": 0,
                                       "size": 100, "count": false, "joins": [], "subQueries": []})
        .as_object()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
        for (k, v) in over.as_object().unwrap() {
            m.insert(k.clone(), v.clone());
        }
        m
    }

    #[test]
    fn no_joins_builds_the_same_query_as_before() {
        let q = aggregate_query(&args(json!({"aggregations": [{"function": "COUNT", "alias": "n"}]}))).unwrap();
        assert!(q.joins.is_none());
        assert!(q.sub_queries.is_none());
        assert_eq!(q.aggregations.unwrap()[0].function, Some(AggregateFunction::Count));
    }

    #[test]
    fn joins_and_sub_queries_reach_the_query() {
        let q = aggregate_query(&args(json!({
            "joins": [{"relation": "ticketId", "alias": "t", "type": "INNER"}, {"relation": "stageId"}],
            "subQueries": [{"storage": "task", "relation": "ticketId", "alias": "tk",
                            "condition": {"field": "completed", "operator": "IS_FALSE"},
                            "aggregations": [{"function": "MIN", "field": "dueDate", "alias": "mn"}]}],
            "filter": {"field": "t.isActive", "operator": "IS_TRUE"},
            "groupBy": [{"field": "t.assignedUserId", "alias": "u"}],
            "aggregations": [{"function": "COUNT_DISTINCT", "field": "ticketId", "alias": "deals"}]})))
        .unwrap();
        let joins = q.joins.unwrap();
        assert_eq!(joins.len(), 2);
        assert_eq!(joins[0].relation.as_deref(), Some("ticketId"));
        assert_eq!(joins[0].alias.as_deref(), Some("t"));
        assert_eq!(joins[0].join_type, Some(JoinType::Inner));
        assert_eq!(joins[1].join_type, Some(JoinType::Left));
        assert_eq!(joins[1].resolved_alias().as_deref(), Some("stageId"));
        let subs = q.sub_queries.unwrap();
        assert_eq!(subs[0].storage.as_deref(), Some("task"));
        assert_eq!(subs[0].alias.as_deref(), Some("tk"));
        assert!(subs[0].condition.is_some());
        assert_eq!(subs[0].aggregations.as_ref().unwrap()[0].function, Some(AggregateFunction::Min));
        assert!(q.condition.is_some());
        assert_eq!(q.group_by.unwrap()[0].field.as_deref(), Some("t.assignedUserId"));
        let a = q.aggregations.unwrap();
        assert_eq!(a[0].function, Some(AggregateFunction::CountDistinct));
        assert_eq!(a[0].field.as_deref(), Some("ticketId"));
    }

    #[test]
    fn iso_week_bucket_is_understood() {
        let q = aggregate_query(&args(json!({
            "groupBy": [{"field": "createdAt", "alias": "wk", "bucket": "iso_week", "timezone": "Asia/Kolkata"}],
            "aggregations": [{"function": "count_distinct", "field": "clientId", "alias": "c"}]})))
        .unwrap();
        let g = &q.group_by.as_ref().unwrap()[0];
        assert_eq!(g.bucket, Some(DateBucketUnit::IsoWeek));
        assert_eq!(g.timezone.as_deref(), Some("Asia/Kolkata"));
        assert_eq!(q.aggregations.as_ref().unwrap()[0].function, Some(AggregateFunction::CountDistinct));
        assert_eq!(q.pageable().unwrap().size, 100);
    }

    // The functions over the policy layer, in memory.

    fn st(v: serde_json::Value) -> appdata::model::Storage {
        appdata::model::Storage::from_value(&DV::from_json(&v)).unwrap()
    }

    async fn functions() -> (Arc<AppDataService>, Arc<MemoryEngine>) {
        let base = security_stub(&[], &["app"]).await;
        let catalog = MemoryCatalog::with(vec![
            st(json!({"name": "s", "appCode": "app", "clientCode": "SYSTEM"})),
            st(json!({"name": "e", "appCode": "app", "clientCode": "SYSTEM"})),
        ]);
        let engine = Arc::new(MemoryEngine::default());
        let svc = Arc::new(policy(catalog, engine.clone(), &base, Arc::new(RecordingEvents::default())));
        (svc, engine)
    }

    async fn run(f: &dyn Function, a: serde_json::Value) -> Result<(String, Value), String> {
        let mut fep =
            FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
                .set_arguments(a.as_object().cloned().unwrap_or_default().into_iter().collect());
        let mut out = f.execute(&mut fep).await.map_err(|e| e.to_string())?;
        let er = out.next().unwrap();
        let v = er.get_result().values().next().cloned().unwrap_or(Value::Null);
        Ok((er.get_name().to_string(), v))
    }

    #[tokio::test]
    async fn every_function_over_the_policy_layer() {
        let (svc, engine) = functions().await;
        let ctx = request(
            auth(json!({"user": {"id": 1, "stringAuthorities": ["Authorities.Logged_IN"]}, "authenticated": true,
                        "clientCode": "SYSTEM"}), Some("SYSTEM"), Some("app")),
            false,
            None,
        );
        context::with_request(ctx, async {
            let all = all(&svc);
            let f = |n: &str| all.iter().find(|f| f.get_signature().get_name() == n).unwrap().clone();

            let (name, row) = run(f("Create").as_ref(), json!({"storageName": "s", "dataObject": {"a": 1, "b": null}})).await.unwrap();
            assert_eq!(name, "output");
            assert_eq!(row["a"], json!(1));
            assert!(row.get("b").is_none());
            let id = row["_id"].as_str().unwrap().to_string();

            let (_, rows) = run(f("CreateMany").as_ref(), json!({"storageName": "s", "dataArray": [{"a": 2}, {"a": 5}]})).await.unwrap();
            assert_eq!(rows.as_array().unwrap().len(), 2);
            // A null row reaches the engine as no data, which fails as Java's does.
            assert!(run(f("CreateMany").as_ref(), json!({"storageName": "s", "dataArray": [null]})).await.is_err());
            assert!(run(f("CreateMany").as_ref(), json!({"storageName": "s", "dataArray": [5]})).await.is_err());

            let (_, read) = run(f("Read").as_ref(), json!({"storageName": "s", "dataObjectId": id, "eagerFields": ["x"]})).await.unwrap();
            assert_eq!(read["a"], json!(1));
            let (_, missing) = run(f("Read").as_ref(), json!({"storageName": "s", "dataObjectId": "nope"})).await.unwrap();
            assert_eq!(missing, json!({}));

            let (_, page) = run(
                f("ReadPage").as_ref(),
                json!({"storageName": "s", "filter": {"field": "a", "operator": "EQUALS", "value": 1}, "size": 5,
                       "sort": [{"property": "a", "direction": "DESC", "ignoreCase": true, "nullHandling": "NULLS_LAST"}],
                       "ignoreFields": ["x", ""], "joins": [{"relation": "r"}], "subQueries": [{"storage": "e"}]}),
            )
            .await
            .unwrap();
            assert_eq!(page["total"], json!(1));
            assert_eq!(page["page"]["size"], json!(5));
            assert_eq!(page["page"]["sort"]["orders"][0], json!({"direction": "DESC", "property": "a", "ignoreCase": true, "nullHandling": "NULLS_LAST"}));
            assert!(run(f("ReadPage").as_ref(), json!({"storageName": "s", "sort": [{"direction": "ASC", "property": ""}]})).await.is_err());

            let (_, upd) = run(f("Update").as_ref(), json!({"storageName": "s", "dataObjectId": id, "dataObject": {"c": 3}, "isPartial": true}))
                .await
                .unwrap();
            assert_eq!(upd["a"], json!(1));
            assert_eq!(upd["c"], json!(3));
            let (_, gone) = run(f("Update").as_ref(), json!({"storageName": "s", "dataObjectId": "nope", "dataObject": {}})).await.unwrap();
            assert_eq!(gone, json!({}));
            let (_, many) = run(f("UpdateMany").as_ref(), json!({"storageName": "s", "dataArray": [{"_id": id, "d": 4}], "isPartial": true}))
                .await
                .unwrap();
            assert_eq!(many[0]["d"], json!(4));

            let (_, agg) = run(f("Aggregate").as_ref(), json!({"storageName": "s", "aggregations": [{"function": "COUNT", "alias": "n"}],
                                                              "sort": [{"property": "n", "direction": "DESC"}, {"direction": "ASC"}],
                                                              "groupBy": [{"field": "a", "bucket": "DAY", "encoding": "EPOCH_SECONDS"}]}))
                .await
                .unwrap();
            assert_eq!(agg["content"][0]["n"], json!(3));
            assert!(agg["page"].get("sort").is_none());

            let (_, versions) = run(f("GetVersionDetails").as_ref(), json!({"storageName": "s", "objectId": id, "filter": {"field": "x", "value": 1}}))
                .await
                .unwrap();
            assert_eq!(versions["total"], json!(0));
            let (name, err) = run(f("GetVersionDetails").as_ref(), json!({"storageName": "s", "objectId": " "})).await.unwrap();
            assert_eq!((name.as_str(), err), ("error", json!("objectId is required to read a row's version history.")));

            let (_, n) = run(f("DeleteByFilter").as_ref(), json!({"storageName": "s", "devMode": true})).await.unwrap();
            assert_eq!(n, json!({"deletedCount": 3}));
            let (_, d) = run(f("Delete").as_ref(), json!({"storageName": "s", "dataObjectId": id})).await.unwrap();
            assert_eq!(d, json!(true));
            let (_, d) = run(f("Delete").as_ref(), json!({"storageName": "s", "dataObjectId": id})).await.unwrap();
            assert_eq!(d, json!(false));

            let (_, copied) = run(f("CopyToDraft").as_ref(), json!({"filters": {"s": {"condition": {"field": "a", "value": 1},
                                                                                       "follow": [{"field": "f", "storage": "e"}]}}}))
                .await
                .unwrap();
            assert_eq!(copied, json!({"e": 0, "s": 2}));
            let (_, cleared) = run(f("ClearDraft").as_ref(), json!({})).await.unwrap();
            assert_eq!(cleared, json!({"s": 2}));
            assert!(run(f("CopyToDraft").as_ref(), json!({"filters": {"s": 1}})).await.is_err());
            assert!(run(f("Read").as_ref(), json!({"storageName": "missing", "dataObjectId": "1"})).await.is_err());
            assert_eq!(engine.count("s"), 2);
        })
        .await;
    }

    #[test]
    fn filters_and_arguments() {
        let f = draft_copy_filters(&json!({"a": null, "b": {"follow": null}, "c": {"follow": [{"field": "x", "storage": "y", "refField": "z"}]}})).unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f["c"].follow.as_ref().unwrap()[0].ref_field.as_deref(), Some("z"));
        assert!(draft_copy_filters(&json!({"a": {"follow": [1]}})).is_err());
        assert!(draft_copy_filters(&json!({"a": {"follow": 1}})).is_err());
        assert!(draft_copy_filters(&json!({"a": {"condition": 5}})).is_err() || draft_copy_filters(&json!({"a": {"condition": 5}})).is_ok());
        assert!(draft_copy_filters(&json!(1)).unwrap().is_empty());
        let a: Map<Value> = json!({"s": "x", "n": 2.5, "b": "true", "z": null, "l": [1, true, "s"], "o": {}, "bad": [null], "nested": [[1]]})
            .as_object().unwrap().clone().into_iter().collect();
        assert_eq!(opt_code(&a, "z").unwrap(), None);
        assert_eq!(opt_code(&a, "s").unwrap(), Some("x".into()));
        assert!(bool_arg(&a, "b"));
        assert!(!bool_arg(&a, "n"));
        assert_eq!(int_arg(&a, "n").unwrap(), 2);
        assert!(int_arg(&a, "z").is_err());
        assert!(int_arg(&a, "s").is_err());
        assert_eq!(string_list(&a, "l").unwrap(), ["1", "true", "s"]);
        assert!(string_list(&a, "o").is_err());
        assert!(string_list(&a, "nested").is_err());
        assert!(string_list(&a, "missing").unwrap().is_empty());
        assert!(element_string(&Value::Null).is_err());
        assert!(rows_of(&json!(5)).unwrap().is_empty());
        assert_eq!(condition_of(&json!([])).unwrap(), DV::Null);
        let mut ea: Map<Value> = Map::new();
        ea.insert("eagerFields".into(), json!([1, "x"]));
        assert_eq!(eager_fields(&ea).unwrap(), ["1", "x"]);
        assert_eq!(error_event("m").next().unwrap().get_result()["error"], json!("m"));
        assert_eq!(gson(&DV::Int(1)).unwrap(), json!(1));
        let sorts = read_page_sort(&json!([{"direction": "desc", "property": "p", "nullHandling": "WHATEVER"}])).unwrap();
        assert_eq!(sorts.as_array().unwrap()[0].as_object().unwrap()["nullHandling"], DV::from("NATIVE"));
        assert!(read_page_sort(&json!([1])).is_err());
        assert!(read_page_sort(&json!([{"property": "p"}])).is_err());
        assert!(read_page_sort(&json!([{"direction": "ASC"}])).is_err());
        assert!(aggregate_query(&args(json!({"groupBy": [1]}))).is_err());
    }

    #[test]
    fn signatures_are_the_java_ones() {
        let names: Vec<(String, usize)> = [
            Create::make_signature(),
            CreateMany::make_signature(),
            Read::make_signature(),
            ReadPage::make_signature(),
            Update::make_signature(),
            UpdateMany::make_signature(),
            Delete::make_signature(),
            DeleteByFilter::make_signature(),
            Aggregate::make_signature(),
            GetVersionDetails::make_signature(),
            ClearDraft::make_signature(),
            CopyToDraft::make_signature(),
        ]
        .iter()
        .map(|s| (s.get_full_name(), s.get_parameters().len()))
        .collect();
        assert_eq!(
            names,
            [
                ("CoreServices.Storage.Create".to_string(), 6),
                ("CoreServices.Storage.CreateMany".into(), 6),
                ("CoreServices.Storage.Read".into(), 6),
                ("CoreServices.Storage.ReadPage".into(), 13),
                ("CoreServices.Storage.Update".into(), 8),
                ("CoreServices.Storage.UpdateMany".into(), 7),
                ("CoreServices.Storage.Delete".into(), 5),
                ("CoreServices.Storage.DeleteByFilter".into(), 6),
                ("CoreServices.Storage.Aggregate".into(), 13),
                ("CoreServices.Storage.GetVersionDetails".into(), 9),
                ("CoreServices.Storage.ClearDraft".into(), 2),
                ("CoreServices.Storage.CopyToDraft".into(), 3),
            ]
        );
    }

    /// Java lets `AbstractConditionDeserializer`'s refusal of the condition itself through as a
    /// 400; a refusal deeper down is Jackson's wrapping, an unknown error.
    #[test]
    fn unreadable_conditions() {
        let top = query_with(DV::from_json(&json!({"value": 1})), Vec::new(), Vec::new()).unwrap_err();
        assert_eq!((top.status(), top.text()), (axum::http::StatusCode::BAD_REQUEST, "Invalid condition".to_string()));
        assert_eq!(top.code().unwrap().code, "CORE.CONDITION_INVALID");
        let nested = query_with(DV::from_json(&json!({"operator": "OR", "conditions": [{"value": 1}]})), Vec::new(), Vec::new()).unwrap_err();
        assert_eq!(nested.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(nested.code().is_none());
    }
}
