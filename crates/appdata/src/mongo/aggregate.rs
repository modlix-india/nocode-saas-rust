//! The aggregation pipeline stages of `MongoAppDataService.aggregate`: group, flatten the
//! group keys back to the top level, measure.

use mongodb::bson::{doc, Bson, Document as BsonDocument};

use crate::model::{AggregateFunction, AggregateQuery, Aggregation, DateBucketUnit, GroupByField, Schema, SchemaType, Sort};

/// Epoch seconds sit near 1e9 and milliseconds near 1e12; a "seconds" value past this is a
/// units mistake.
pub const EPOCH_SECONDS_SANITY_CEILING: i64 = 100_000_000_000;

pub fn group_stage(query: &AggregateQuery) -> BsonDocument {
    let mut group = BsonDocument::new();
    match query.group_by.as_ref().filter(|g| !g.is_empty()) {
        None => {
            group.insert("_id", Bson::Null);
        }
        Some(groups) => {
            let mut keys = BsonDocument::new();
            for g in groups {
                keys.insert(g.resolved_alias().unwrap_or_default(), group_key(g));
            }
            group.insert("_id", keys);
        }
    }
    for a in query.aggregations.iter().flatten() {
        group.insert(a.resolved_alias().unwrap_or_default(), accumulator(a));
    }
    doc! { "$group": group }
}

/// The group key: the raw value, or an epoch number lifted to a date and truncated in the
/// caller's zone.
fn group_key(g: &GroupByField) -> Bson {
    let path = format!("${}", g.field.clone().unwrap_or_default());
    let Some(bucket) = g.bucket else { return Bson::String(path) };
    let to_millis = g.encoding.map(|e| e.to_millis()).unwrap_or(1);
    let millis = if to_millis == 1 {
        Bson::String(path)
    } else {
        Bson::Document(doc! { "$multiply": [path, Bson::Int64(to_millis)] })
    };
    let mut trunc = doc! {
        "date": { "$toDate": millis },
        "unit": bucket.mongo_unit(),
        "timezone": g.resolved_timezone(),
    };
    if bucket == DateBucketUnit::IsoWeek {
        trunc.insert("startOfWeek", "monday");
    }
    Bson::Document(doc! { "$dateTrunc": trunc })
}

fn accumulator(a: &Aggregation) -> Bson {
    let field = a.field.clone().filter(|f| !f.trim().is_empty());
    let f = a.function.unwrap_or(AggregateFunction::Count);
    if f == AggregateFunction::Count {
        let Some(field) = field else { return Bson::Document(doc! { "$sum": 1 }) };
        return Bson::Document(doc! {
            "$sum": { "$cond": [ { "$in": [ { "$type": format!("${field}") }, ["missing", "null"] ] }, 0, 1 ] }
        });
    }
    let path = format!("${}", field.unwrap_or_default());
    Bson::Document(match f {
        AggregateFunction::CountDistinct => doc! { "$addToSet": path },
        AggregateFunction::Sum => doc! { "$sum": path },
        AggregateFunction::Avg => doc! { "$avg": path },
        AggregateFunction::Min => doc! { "$min": path },
        AggregateFunction::Max => doc! { "$max": path },
        AggregateFunction::Count => doc! { "$sum": 1 },
    })
}

/// Flatten `_id` back to the top level, and turn a distinct set into its size.
pub fn project_stage(query: &AggregateQuery) -> BsonDocument {
    let mut project = doc! { "_id": 0 };
    for g in query.group_by.iter().flatten() {
        let alias = g.resolved_alias().unwrap_or_default();
        project.insert(alias.clone(), projected_key(g, &alias));
    }
    for a in query.aggregations.iter().flatten() {
        let alias = a.resolved_alias().unwrap_or_default();
        let v = if a.function == Some(AggregateFunction::CountDistinct) {
            Bson::Document(doc! {
                "$size": { "$filter": { "input": format!("${alias}"), "cond": { "$ne": ["$$this", Bson::Null] } } }
            })
        } else {
            Bson::Int32(1)
        };
        project.insert(alias, v);
    }
    doc! { "$project": project }
}

fn projected_key(g: &GroupByField, alias: &str) -> Bson {
    let r = format!("$_id.{alias}");
    if g.bucket.is_none() {
        return Bson::String(r);
    }
    let as_long = doc! { "$toLong": r };
    let to_millis = g.encoding.map(|e| e.to_millis()).unwrap_or(1);
    if to_millis == 1 {
        Bson::Document(as_long)
    } else {
        Bson::Document(doc! { "$toLong": { "$divide": [as_long, Bson::Int64(to_millis)] } })
    }
}

/// `sort(Sort)`: none for an unsorted sort or the query default.
pub fn sort_doc(sort: &Sort) -> Option<BsonDocument> {
    if !sort.is_sorted() || *sort == Sort::default_query_sort() {
        return None;
    }
    let mut d = BsonDocument::new();
    for o in &sort.orders {
        d.insert(o.property.clone(), if o.is_ascending() { 1 } else { -1 });
    }
    Some(d)
}

/// The Mongo-only rule: a bucketed field needs an encoding, because dates here are numbers.
pub fn bucket_encoding_problem(query: &AggregateQuery) -> Option<String> {
    for g in query.group_by.iter().flatten() {
        if let (Some(bucket), None) = (g.bucket, g.encoding) {
            return Some(format!(
                "field '{}' is bucketed by {} so it needs an encoding (EPOCH_SECONDS or EPOCH_MILLIS); dates are stored as numbers and seconds cannot be told from milliseconds",
                g.field.clone().unwrap_or_default(),
                bucket.name()
            ));
        }
    }
    None
}

/// Every referenced field has to be one the storage declares; a bucketed one a number.
pub fn schema_problem(storage_name: &str, schema: Option<&Schema>, query: &AggregateQuery) -> Option<String> {
    let props = schema.and_then(|s| s.properties.as_ref()).filter(|p| !p.is_empty())?;
    let declared = |field: &str| -> Option<&Schema> {
        if field == "_id" {
            return props.get("_id");
        }
        props.get(field.split('.').next().unwrap_or(field))
    };
    for g in query.group_by.iter().flatten() {
        let field = g.field.clone().unwrap_or_default();
        let Some(fs) = declared(&field) else {
            return Some(format!("storage {storage_name} declares no field '{field}'"));
        };
        if g.bucket.is_some() && !is_numeric(fs) {
            return Some(format!(
                "field '{field}' is bucketed as a date but is not a number in the storage schema; only epoch-number dates can be bucketed"
            ));
        }
    }
    for a in query.aggregations.iter().flatten() {
        let Some(field) = a.field.as_ref().filter(|f| !f.trim().is_empty()) else { continue };
        if declared(field).is_none() {
            return Some(format!("storage {storage_name} declares no field '{field}'"));
        }
    }
    None
}

fn is_numeric(s: &Schema) -> bool {
    [SchemaType::Integer, SchemaType::Long, SchemaType::Float, SchemaType::Double].iter().any(|t| s.has_type(*t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DateEncoding;

    #[test]
    fn stages() {
        let mut g = GroupByField::new("createdAt");
        g.bucket = Some(DateBucketUnit::IsoWeek);
        g.encoding = Some(DateEncoding::EpochSeconds);
        g.alias = Some("wk".into());
        let q = AggregateQuery {
            group_by: Some(vec![g, GroupByField::new("region")]),
            aggregations: Some(vec![
                Aggregation::new(AggregateFunction::Count, None),
                Aggregation::new(AggregateFunction::CountDistinct, Some("owner")),
            ]),
            ..Default::default()
        };
        let group = Bson::Document(group_stage(&q)).into_relaxed_extjson().to_string();
        assert!(group.contains(r#""$multiply":["$createdAt",1000]"#), "{group}");
        assert!(group.contains(r#""startOfWeek":"monday""#), "{group}");
        assert!(group.contains(r#""count":{"$sum":1}"#), "{group}");
        let project = Bson::Document(project_stage(&q)).into_relaxed_extjson().to_string();
        assert!(project.contains(r#""region":"$_id.region""#), "{project}");
        assert!(project.contains(r#""$divide":[{"$toLong":"$_id.wk"},1000]"#), "{project}");
        assert!(project.contains(r#""$size""#), "{project}");
    }
}
