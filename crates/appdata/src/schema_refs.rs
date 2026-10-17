//! What the engines need from a storage's schema: the definition as written
//! (`StorageService.getSchema`) and, for MySQL DDL, the definition with its references
//! followed (`getResolvedSchema`: `SchemaRefResolver` plus the relation columns).
//!
//! References are looked up through a [`SchemaRepository`], which the caller supplies:
//! KIRun's built-in System schemas are answered here, an app's own schemas by whatever
//! resolves them for the tenant (the override chain is the caller's business).

use std::sync::Arc;

use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};

use crate::model::{Items, RelationType, Schema, SchemaType, Storage, StringFormat};
use crate::value::Value;

/// Follow a chain of references at most this deep.
pub const MAX_DEPTH: usize = 10;

#[async_trait]
pub trait SchemaRepository: Send + Sync {
    /// The schema called `namespace.name`, or None.
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>>;
}

/// KIRun's own schemas (`KIRunReactiveSchemaRepository`), as far as a column type reads
/// them.
pub struct KirunSystemSchemas;

#[async_trait]
impl SchemaRepository for KirunSystemSchemas {
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>> {
        let of = |types: Vec<SchemaType>| Schema {
            namespace: Some(namespace.to_string()),
            name: Some(name.to_string()),
            types: Some(types),
            ..Default::default()
        };
        use SchemaType::*;
        Ok(match (namespace, name) {
            ("System", "any") => Some(of(vec![Integer, Long, Float, Double, String, Boolean, Array, Null, Object])),
            ("System", "boolean") => Some(of(vec![Boolean])),
            ("System", "double") => Some(of(vec![Double])),
            ("System", "float") => Some(of(vec![Float])),
            ("System", "integer") => Some(of(vec![Integer])),
            ("System", "long") => Some(of(vec![Long])),
            ("System", "number") => Some(of(vec![Integer, Long, Float, Double])),
            ("System", "string") => Some(of(vec![String])),
            ("System", "Null") => Some(of(vec![Null])),
            ("Date", "Timestamp") => Some(of(vec![String])),
            _ => None,
        })
    }
}

/// Several repositories asked in turn, as `ReactiveHybridRepository`.
pub struct HybridRepository(pub Vec<Arc<dyn SchemaRepository>>);

#[async_trait]
impl SchemaRepository for HybridRepository {
    async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>> {
        for r in &self.0 {
            if let Some(s) = r.find(namespace, name).await? {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }
}

/// `StorageService.getSchema`: the definition as written.
pub fn storage_schema(storage: &Storage) -> Option<Schema> {
    storage.schema.as_ref().and_then(Schema::from_value)
}

/// `StorageService.getResolvedSchema`: references followed two levels, relation columns
/// added.
pub async fn resolved_schema(storage: &Storage, repo: Option<&dyn SchemaRepository>) -> Option<Schema> {
    let schema = storage_schema(storage)?;
    let resolved = resolve(&schema, repo).await;
    Some(with_relations(storage, resolved))
}

/// `SchemaRefResolver.resolve`.
pub async fn resolve(storage_schema: &Schema, repo: Option<&dyn SchemaRepository>) -> Schema {
    let Some(repo) = repo else { return storage_schema.clone() };
    let followed = follow(storage_schema, repo).await;
    let resolved = if followed == *storage_schema { followed } else { merge_properties(storage_schema, followed) };
    properties(resolved, repo).await
}

async fn properties(schema: Schema, repo: &dyn SchemaRepository) -> Schema {
    let Some(props) = schema.properties.as_ref().filter(|p| !p.is_empty()) else { return schema };
    let mut out = IndexMap::new();
    for (k, v) in props {
        if v.reference.as_ref().is_none_or(|r| r.trim().is_empty()) {
            out.insert(k.clone(), v.clone());
            continue;
        }
        let r = follow(v, repo).await;
        out.insert(k.clone(), if r == *v { r } else { overlay(v, r) });
    }
    Schema { properties: Some(out), ..schema }
}

/// Follow one chain of references to its end; a chain that cannot be followed leaves the
/// schema as written (the type mapper makes it JSON with a note).
async fn follow(schema: &Schema, repo: &dyn SchemaRepository) -> Schema {
    let mut current = schema.clone();
    let mut seen = IndexSet::new();
    let mut depth = 0;
    loop {
        let Some(r) = current.reference.clone().filter(|r| !r.trim().is_empty()) else { return current };
        if depth >= MAX_DEPTH || !seen.insert(r.clone()) {
            return current;
        }
        match schema_from_ref(&current, repo, &r).await {
            Some(resolved) => {
                let again = resolved.reference.as_ref().is_some_and(|x| !x.trim().is_empty()) && resolved != current;
                current = resolved;
                if !again {
                    return current;
                }
                depth += 1;
            }
            None => return if depth == 0 { schema.clone() } else { current },
        }
    }
}

/// `ReactiveSchemaUtil.getSchemaFromRef`, for the external and `#/` forms.
async fn schema_from_ref(schema: &Schema, repo: &dyn SchemaRepository, reference: &str) -> Option<Schema> {
    if reference.trim().is_empty() {
        return None;
    }
    let parts: Vec<&str> = reference.split('/').collect();
    let base = if reference.starts_with('#') {
        schema.clone()
    } else {
        let full = parts.first()?;
        let dot = full.rfind('.')?;
        let (ns, name) = (&full[..dot], &full[dot + 1..]);
        if ns.is_empty() || name.is_empty() {
            return None;
        }
        repo.find(ns, name).await.ok().flatten()?
    };
    if parts.len() <= 1 {
        return Some(base);
    }
    walk(base, &parts[1..])
}

fn walk(mut schema: Schema, parts: &[&str]) -> Option<Schema> {
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == "$defs" {
            i += 1;
            schema = schema.defs.as_ref()?.get(*parts.get(i)?)?.clone();
        } else {
            if !schema.has_type(SchemaType::Object) {
                return None;
            }
            schema = schema.properties.as_ref()?.get(parts[i])?.clone();
        }
        i += 1;
    }
    Some(schema)
}

/// What the author wrote beside the ref wins over what it resolved to: type, format,
/// maxLength, and the field's own name.
pub fn overlay(local: &Schema, resolved: Schema) -> Schema {
    let mut out = resolved;
    if local.types.is_some() {
        out.types = local.types.clone();
    }
    if local.format.is_some() {
        out.format = local.format;
    }
    if local.max_length.is_some() {
        out.max_length = local.max_length;
    }
    out.name = local.name.clone();
    out
}

/// Locally declared properties merged over a resolved set.
pub fn merge_properties(local: &Schema, resolved: Schema) -> Schema {
    let Some(local_props) = local.properties.as_ref().filter(|p| !p.is_empty()) else { return resolved };
    let mut merged = resolved.properties.clone().unwrap_or_default();
    for (k, v) in local_props {
        merged.insert(k.clone(), v.clone());
    }
    let mut required: IndexSet<String> = resolved.required.clone().unwrap_or_default().into_iter().collect();
    for r in local.required.iter().flatten() {
        required.insert(r.clone());
    }
    Schema { properties: Some(merged), required: Some(required.into_iter().collect()), ..resolved }
}

/// Relation fields as columns: a TO_MANY is a list of ids, a TO_ONE one fixed-width id.
pub fn with_relations(storage: &Storage, resolved: Schema) -> Schema {
    let Some(relations) = storage.relations.as_ref().filter(|r| !r.is_empty()) else { return resolved };
    let mut props = resolved.properties.clone().unwrap_or_default();
    for (field, relation) in relations {
        if props.contains_key(field) {
            continue;
        }
        let s = if relation.relation_type == Some(RelationType::ToMany) {
            Schema::of_array(field, Schema::of_string(field).with_format(StringFormat::Id))
        } else {
            Schema::of_string(field).with_format(StringFormat::Id)
        };
        props.insert(field.clone(), s);
    }
    Schema { properties: Some(props), ..resolved }
}

/// An item schema, for callers walking arrays.
pub fn single_item(s: &Schema) -> Option<&Schema> {
    match &s.items {
        Some(Items::Single(i)) => Some(i),
        _ => None,
    }
}

/// A schema JSON straight from a stored document's `definition`.
pub fn schema_from_definition(definition: &Value) -> Option<Schema> {
    Schema::from_value(definition)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(IndexMap<String, Schema>);

    #[async_trait]
    impl SchemaRepository for Fixed {
        async fn find(&self, namespace: &str, name: &str) -> anyhow::Result<Option<Schema>> {
            Ok(self.0.get(&format!("{namespace}.{name}")).cloned())
        }
    }

    fn parse(s: &str) -> Schema {
        Schema::from_value(&Value::parse_json(s).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn follows_the_storage_ref_and_property_refs() {
        let mut repo = IndexMap::new();
        repo.insert(
            "App.Customer".to_string(),
            parse(r#"{"type":"OBJECT","properties":{"name":{"type":"STRING","maxLength":40},"code":{"ref":"App.Code","maxLength":12}},"required":["name"]}"#),
        );
        repo.insert("App.Code".to_string(), parse(r#"{"type":"STRING","maxLength":64}"#));
        let repo = Fixed(repo);
        let storage = parse(r#"{"ref":"App.Customer","properties":{"extra":{"type":"INTEGER"}}}"#);
        let r = resolve(&storage, Some(&repo)).await;
        let props = r.properties.unwrap();
        assert_eq!(props.keys().collect::<Vec<_>>(), vec!["name", "code", "extra"]);
        assert_eq!(props["code"].max_length, Some(12));
        assert!(props["code"].has_type(SchemaType::String));
        assert_eq!(r.required, Some(vec!["name".to_string()]));
    }

    #[tokio::test]
    async fn an_unresolvable_ref_is_left_as_written() {
        let repo = Fixed(IndexMap::new());
        let storage = parse(r#"{"type":"OBJECT","properties":{"x":{"ref":"Gone.Thing"}}}"#);
        let r = resolve(&storage, Some(&repo)).await;
        assert_eq!(r.properties.unwrap()["x"].reference.as_deref(), Some("Gone.Thing"));
        let sys = parse(r#"{"type":"OBJECT","properties":{"x":{"ref":"System.any"}}}"#);
        let r = resolve(&sys, Some(&KirunSystemSchemas)).await;
        assert_eq!(r.properties.unwrap()["x"].allowed_types().len(), 9);
    }
}
