//! core's overridable documents (`com.fincity.saas.commons.core.document`) as
//! [`overridable::DocType`]s, read from the `core` Mongo database through
//! [`overridable::Store`]. Every core object is draftable.
//!
//! `getObjectName()` gives the cache names (`FunctionCache_<app>_<name>`, ...), which are the
//! ones the Java core evicts on save.

use overridable::difference::apply_map;
use overridable::pojo::{map_field, set_opt_map, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use overridable::{DocType, JMap, JValue};

/// `CoreFunction` (`AbstractFunction`).
pub const FUNCTION: Pojo = Pojo {
    name: "CoreFunction",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("definition", K::MapObject, C::MapObject),
            Field::new("executeAuth", K::Str, C::Copy),
        ],
    ],
};

/// `CoreSchema` (`AbstractSchema`).
pub const SCHEMA: Pojo = Pojo {
    name: "CoreSchema",
    parts: &[OVERRIDABLE_BASE, &[Field::new("definition", K::MapObject, C::MapObject)]],
};

/// `Storage`. The nested classes (`StorageRelation`, `StorageIndex`, ...) are kept as plain
/// maps; the storage policy layer reads them.
pub const STORAGE: Pojo = Pojo {
    name: "Storage",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("schema", K::MapObject, C::MapObject),
            Field::new("uniqueName", K::Str, C::Copy),
            Field::new("isAudited", K::BoxBool, C::Copy),
            Field::new("isVersioned", K::BoxBool, C::Copy),
            Field::new("isAppLevel", K::BoxBool, C::Copy),
            Field::new("onlyThruKIRun", K::BoxBool, C::Copy),
            Field::new("createAuth", K::Str, C::Copy),
            Field::new("readAuth", K::Str, C::Copy),
            Field::new("updateAuth", K::Str, C::Copy),
            Field::new("deleteAuth", K::Str, C::Copy),
            Field::new("relations", K::MapObject, C::MapObject),
            Field::new("generateEvents", K::BoxBool, C::Copy),
            Field::new("triggers", K::MapObject, C::MapObject),
            Field::new("fieldDefinitionMap", K::MapObject, C::MapObject),
            // Not copied by the copy constructor.
            Field::new("versionRetentionDays", K::BoxInt, C::Skip),
            Field::new("versionRetentionCount", K::BoxInt, C::Skip),
            Field::new("columnDefinitions", K::MapObject, C::MapObject),
            Field::new("indexes", K::MapObject, C::MapObject),
            Field::new("textIndexFields", K::Object, C::Copy),
        ],
    ],
};

/// `Connection`.
pub const CONNECTION: Pojo = Pojo {
    name: "Connection",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("connectionType", K::Str, C::Copy),
            Field::new("connectionSubType", K::Str, C::Copy),
            Field::new("connectionDetails", K::MapObject, C::MapObject),
            Field::new("isAppLevel", K::BoxBool, C::Copy),
            Field::new("onlyThruKIRun", K::BoxBool, C::Copy),
        ],
    ],
};

/// `EventDefinition`. The policy layer only asks whether one exists and whether it carries
/// the caller's authentication; the schedule is kept as a plain map.
pub const EVENT_DEFINITION: Pojo = Pojo {
    name: "EventDefinition",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("schema", K::MapObject, C::MapObject),
            Field::new("includeContextAuthentication", K::BoxBool, C::Copy),
            Field::new("schedule", K::MapObject, C::Copy),
        ],
    ],
};

/// `EventAction`.
pub const EVENT_ACTION: Pojo = Pojo {
    name: "EventAction",
    parts: &[OVERRIDABLE_BASE, &[Field::new("tasks", K::MapObject, C::MapObject)]],
};

/// `Template`.
pub const TEMPLATE: Pojo = Pojo {
    name: "Template",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("templateParts", K::MapObject, C::MapObject),
            Field::new("resources", K::MapObject, C::MapObject),
            Field::new("defaultLanguage", K::Str, C::Copy),
            Field::new("templateType", K::Str, C::Copy),
            Field::new("toExpression", K::Str, C::Copy),
            Field::new("fromExpression", K::Str, C::Copy),
            Field::new("languageExpression", K::Str, C::Copy),
            Field::new("variableSchema", K::MapObject, C::MapObject),
            Field::new("sampleData", K::MapObject, C::MapObject),
            Field::new("design", K::MapObject, C::MapObject),
        ],
    ],
};

fn fallback(this: &mut JMap, base: &JMap, field: &str) {
    if this.get(field).is_none_or(JValue::is_null) {
        this.insert(field.to_string(), base.get(field).cloned().unwrap_or(JValue::Null));
    }
}

/// `AbstractFunction` / `AbstractSchema.applyOverride`: `apply(...).map(...)`, so a merge with
/// nothing on either side empties the whole override.
fn apply_definition(mut this: JMap, base: &JMap) -> Option<JMap> {
    let d = apply_map(map_field(&this, "definition"), map_field(base, "definition"))?;
    this.insert("definition".into(), JValue::Object(d));
    Some(this)
}

pub struct FunctionDoc;
pub struct SchemaDoc;
pub struct StorageDoc;
pub struct ConnectionDoc;
pub struct EventDefinitionDoc;
pub struct EventActionDoc;

/// `EventDefinition`'s collection.
pub const EVENT_DEFINITION_COLLECTION: &str = "eventDefinition";
pub struct TemplateDoc;

impl DocType for TemplateDoc {
    fn object_name(&self) -> &'static str {
        "Template"
    }
    fn collection(&self) -> &'static str {
        "template"
    }
    fn pojo(&self) -> &'static Pojo {
        &TEMPLATE
    }
    /// `Template.applyOverride`: the maps merged onto the base's (an empty merge stored as
    /// null, `flatMapMonoWithNull`), the unset strings inherited.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        for f in ["templateParts", "resources", "variableSchema", "sampleData", "design"] {
            let v = apply_map(map_field(&this, f), map_field(base, f));
            set_opt_map(&mut this, f, v);
        }
        for f in ["templateType", "defaultLanguage", "toExpression", "fromExpression", "languageExpression"] {
            fallback(&mut this, base, f);
        }
        Some(this)
    }
}

impl DocType for EventDefinitionDoc {
    fn object_name(&self) -> &'static str {
        "EventDefinition"
    }
    fn collection(&self) -> &'static str {
        "eventDefinition"
    }
    fn pojo(&self) -> &'static Pojo {
        &EVENT_DEFINITION
    }
    /// `EventDefinition.applyOverride`: the schema merged (empty when nothing is left),
    /// `includeContextAuthentication` inherited, the schedule merged field by field
    /// (`EventSchedule.merge`).
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let schema = apply_map(map_field(&this, "schema"), map_field(base, "schema")).unwrap_or_default();
        this.insert("schema".into(), JValue::Object(schema));
        fallback(&mut this, base, "includeContextAuthentication");
        let schedule = crate::scheduler::EventSchedule::merge_j(this.get("schedule"), base.get("schedule"));
        this.insert("schedule".into(), schedule);
        Some(this)
    }
}

impl DocType for EventActionDoc {
    fn object_name(&self) -> &'static str {
        "EventAction"
    }
    fn collection(&self) -> &'static str {
        "eventAction"
    }
    fn pojo(&self) -> &'static Pojo {
        &EVENT_ACTION
    }
    /// `EventAction.applyOverride`: the tasks merged onto the base's (`defaultIfEmpty(Map.of())`,
    /// so an empty merge is an empty map, never a missing one).
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let tasks = apply_map(map_field(&this, "tasks"), map_field(base, "tasks")).unwrap_or_default();
        this.insert("tasks".into(), JValue::Object(tasks));
        Some(this)
    }
}

impl DocType for FunctionDoc {
    fn object_name(&self) -> &'static str {
        "Function"
    }
    fn collection(&self) -> &'static str {
        "function"
    }
    fn pojo(&self) -> &'static Pojo {
        &FUNCTION
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        let mut this = apply_definition(this, base)?;
        fallback(&mut this, base, "executeAuth");
        Some(this)
    }
}

impl DocType for SchemaDoc {
    fn object_name(&self) -> &'static str {
        "Schema"
    }
    fn collection(&self) -> &'static str {
        "schema"
    }
    fn pojo(&self) -> &'static Pojo {
        &SCHEMA
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        apply_definition(this, base)
    }
}

impl DocType for StorageDoc {
    fn object_name(&self) -> &'static str {
        "Storage"
    }
    fn collection(&self) -> &'static str {
        "storage"
    }
    fn pojo(&self) -> &'static Pojo {
        &STORAGE
    }
    /// `Storage.applyOverride`: the maps merged onto the base's, `textIndexFields` taken whole
    /// (the base's when this one has none), unset scalars inherited, and `columnDefinitions`
    /// merged with an empty result stored as null. The storage unit (step 2) re-checks this
    /// against the Java tests before it relies on it.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        for f in ["schema", "relations", "triggers", "fieldDefinitionMap", "indexes"] {
            let v = apply_map(map_field(&this, f), map_field(base, f));
            set_opt_map(&mut this, f, v);
        }
        fallback(&mut this, base, "textIndexFields");
        for f in [
            "isAudited",
            "isVersioned",
            "createAuth",
            "readAuth",
            "updateAuth",
            "deleteAuth",
            "uniqueName",
            "isAppLevel",
            "onlyThruKIRun",
            "generateEvents",
            "versionRetentionDays",
            "versionRetentionCount",
        ] {
            fallback(&mut this, base, f);
        }
        let cd = apply_map(map_field(&this, "columnDefinitions"), map_field(base, "columnDefinitions"))
            .filter(|m| !m.is_empty());
        set_opt_map(&mut this, "columnDefinitions", cd);
        Some(this)
    }
}

impl DocType for ConnectionDoc {
    fn object_name(&self) -> &'static str {
        "Connection"
    }
    fn collection(&self) -> &'static str {
        "connection"
    }
    fn pojo(&self) -> &'static Pojo {
        &CONNECTION
    }
    /// `Connection.applyOverride` returns itself: connections are never merged.
    fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;
    use overridable::store::apply_actual_override;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    #[test]
    fn function_override_merges_definition_and_inherits_execute_auth() {
        let base = obj(r#"{"name":"A.b","definition":{"name":"b","namespace":"A","steps":{"s1":{"name":"Add"}}},"executeAuth":"Authorities.ROLE_X"}"#);
        let this = obj(r#"{"name":"A.b","definition":{"steps":{"s2":{"name":"Sub"}}},"executeAuth":null}"#);
        let got = apply_actual_override(&FunctionDoc, this, Some(&base)).unwrap();
        assert_eq!(got["executeAuth"], JValue::Str("Authorities.ROLE_X".into()));
        let steps = got["definition"].as_object().unwrap()["steps"].as_object().unwrap();
        assert!(steps.contains_key("s1") && steps.contains_key("s2"));
        assert_eq!(got["definition"].as_object().unwrap()["namespace"], JValue::Str("A".into()));
    }

    #[test]
    fn template_override_merges_parts_and_inherits_strings() {
        let base = obj(r#"{"name":"t","templateParts":{"en":{"subject":"S","body":"B"}},"defaultLanguage":"en","toExpression":"x"}"#);
        let this = obj(r#"{"name":"t","templateParts":{"en":{"body":"B2"}},"toExpression":null}"#);
        let got = TemplateDoc.apply_override(this, &base).unwrap();
        let en = got["templateParts"].as_object().unwrap()["en"].as_object().unwrap().clone();
        assert_eq!(en["subject"], JValue::Str("S".into()));
        assert_eq!(en["body"], JValue::Str("B2".into()));
        assert_eq!(got["defaultLanguage"], JValue::Str("en".into()));
        assert_eq!(got["toExpression"], JValue::Str("x".into()));
        assert_eq!(TemplateDoc.cache_name("a", "t"), "TemplateCache_a_t");
        assert_eq!(TemplateDoc.collection(), "template");
        assert_eq!(TemplateDoc.pojo().name, "Template");
    }

    #[test]
    fn cache_names_are_the_java_ones() {
        assert_eq!(FunctionDoc.cache_name("appbuilder", "Test.fibonacci"), "FunctionCache_appbuilder_Test.fibonacci");
        assert_eq!(SchemaDoc.cache_name("a", "B.c"), "SchemaCache_a_B.c");
    }

    #[test]
    fn storage_inherits_unset_scalars() {
        let base = obj(r#"{"name":"s","isAudited":true,"readAuth":"Authorities.X","schema":{"type":"OBJECT"},"textIndexFields":["a"]}"#);
        let this = obj(r#"{"name":"s","isAudited":null,"schema":{"properties":{"x":{"type":"STRING"}}}}"#);
        let got = StorageDoc.apply_override(this, &base).unwrap();
        assert_eq!(got["isAudited"], JValue::Bool(true));
        assert_eq!(got["readAuth"], JValue::Str("Authorities.X".into()));
        assert_eq!(got["textIndexFields"], JValue::Array(vec![JValue::Str("a".into())]));
        assert!(got["schema"].as_object().unwrap().contains_key("properties"));
    }

    #[test]
    fn the_four_classes() {
        for (dt, name, coll, pojo) in [
            (&FunctionDoc as &dyn DocType, "Function", "function", "CoreFunction"),
            (&SchemaDoc, "Schema", "schema", "CoreSchema"),
            (&StorageDoc, "Storage", "storage", "Storage"),
            (&ConnectionDoc, "Connection", "connection", "Connection"),
        ] {
            assert_eq!(dt.object_name(), name);
            assert_eq!(dt.collection(), coll);
            assert_eq!(dt.pojo().name, pojo);
            assert!(dt.draftable());
        }
        let base = obj(r#"{"definition":{"type":"OBJECT","properties":{"a":{"type":"STRING"}}}}"#);
        let this = obj(r#"{"definition":{"properties":{"b":{"type":"STRING"}}}}"#);
        let merged = SchemaDoc.apply_override(this, &base).unwrap();
        assert_eq!(merged["definition"].as_object().unwrap()["properties"].as_object().unwrap().len(), 2);
        // Nothing on either side: Java's empty Mono.
        assert!(SchemaDoc.apply_override(obj(r#"{"definition":null}"#), &obj(r#"{"definition":null}"#)).is_none());
        let c = ConnectionDoc.apply_override(obj(r#"{"connectionType":"REST_API"}"#), &obj(r#"{"connectionType":"MAIL"}"#)).unwrap();
        assert_eq!(c["connectionType"], JValue::Str("REST_API".into()));
        // An empty merged columnDefinitions is stored as null.
        let s = StorageDoc.apply_override(obj(r#"{"columnDefinitions":{}}"#), &obj(r#"{"columnDefinitions":{}}"#)).unwrap();
        assert_eq!(s["columnDefinitions"], JValue::Null);
    }


    // Port of commons-core `StorageFlagsOverrideTest` (the read half; `makeActualOverride` is
    // the editor's save path).

    fn base_flags() -> JMap {
        obj(r#"{"name":"deal","appCode":"app","clientCode":"SYSTEM","isAudited":true,"isVersioned":false,"isAppLevel":true,"onlyThruKIRun":true}"#)
    }

    #[test]
    fn unset_is_null() {
        let s = appdata::model::Storage::from_value(&appdata::Value::from_json(&serde_json::json!({}))).unwrap();
        assert_eq!((s.is_audited, s.is_versioned, s.is_app_level, s.only_thru_kirun), (None, None, None, None));
        assert!(!s.audited(), "null still reads as false for a base storage");
    }

    #[test]
    fn fork_inherits() {
        let fork = obj(r#"{"name":"deal","appCode":"app","clientCode":"FIN2","baseClientCode":"SYSTEM"}"#);
        let m = apply_actual_override(&StorageDoc, fork, Some(&base_flags())).unwrap();
        assert_eq!(m["isAudited"], JValue::Bool(true));
        assert_eq!(m["isVersioned"], JValue::Bool(false));
        assert_eq!(m["isAppLevel"], JValue::Bool(true));
        assert_eq!(m["onlyThruKIRun"], JValue::Bool(true));
    }

    #[test]
    fn fork_overrides_one() {
        let fork = obj(r#"{"name":"deal","appCode":"app","clientCode":"FIN2","baseClientCode":"SYSTEM","isAudited":false}"#);
        let m = apply_actual_override(&StorageDoc, fork, Some(&base_flags())).unwrap();
        assert_eq!(m["isAudited"], JValue::Bool(false));
        assert_eq!(m["onlyThruKIRun"], JValue::Bool(true));
    }

    // Port of core `StorageOverrideChainIntegrationTest`, the read half (`storageService.read`
    // folds the chain root first); the save half is the editor's.

    fn fold(chain: &[&str]) -> JMap {
        let mut merged: Option<JMap> = None;
        for doc in chain {
            let this = obj(doc);
            merged = apply_actual_override(&StorageDoc, this, merged.as_ref());
        }
        merged.unwrap()
    }

    fn decimal(field: &str, precision: i32, scale: i32) -> String {
        format!(r#"{{"{field}":{{"mysql":{{"type":"DECIMAL","precision":{precision},"scale":{scale}}}}}}}"#)
    }

    fn mysql(m: &JMap, field: &str, what: &str) -> JValue {
        m["columnDefinitions"].as_object().unwrap()[field].as_object().unwrap()["mysql"].as_object().unwrap()[what].clone()
    }

    #[test]
    fn column_definition_inherited() {
        let root = format!(r#"{{"name":"t","clientCode":"SYSTEM","schema":{{"price":"p"}},"columnDefinitions":{}}}"#, decimal("price", 19, 4));
        let m = fold(&[&root, r#"{"name":"t","clientCode":"LZCLA"}"#, r#"{"name":"t","clientCode":"LZACP1"}"#]);
        assert_eq!(mysql(&m, "price", "precision"), JValue::Int(19));
    }

    #[test]
    fn leaf_pin_wins() {
        let root = format!(r#"{{"name":"t","schema":{{"price":"p"}},"columnDefinitions":{}}}"#, decimal("price", 19, 4));
        let leaf = format!(r#"{{"name":"t","columnDefinitions":{}}}"#, decimal("price", 10, 2));
        let m = fold(&[&root, r#"{"name":"t"}"#, &leaf]);
        assert_eq!(mysql(&m, "price", "precision"), JValue::Int(10));
        assert_eq!(mysql(&m, "price", "scale"), JValue::Int(2));
    }

    #[test]
    fn mid_and_leaf_merge() {
        let mid = format!(r#"{{"name":"t","columnDefinitions":{}}}"#, decimal("price", 12, 3));
        let leaf = format!(r#"{{"name":"t","columnDefinitions":{}}}"#, decimal("cost", 8, 2));
        let m = fold(&[r#"{"name":"t","schema":{"price":"p","cost":"c"}}"#, &mid, &leaf]);
        assert_eq!(mysql(&m, "price", "precision"), JValue::Int(12));
        assert_eq!(mysql(&m, "cost", "precision"), JValue::Int(8));
    }

    #[test]
    fn indexes_inherited() {
        let m = fold(&[
            r#"{"name":"t","schema":{"title":"t"},"indexes":{"byTitle":{"fields":[{"fieldName":"title"}]}},"textIndexFields":["title"]}"#,
            r#"{"name":"t"}"#,
            r#"{"name":"t","indexes":{"byLeaf":{"fields":[{"fieldName":"title"}]}}}"#,
        ]);
        let ix = m["indexes"].as_object().unwrap();
        assert!(ix.contains_key("byTitle") && ix.contains_key("byLeaf"));
        assert_eq!(m["textIndexFields"], JValue::Array(vec![JValue::Str("title".into())]));
    }

    #[test]
    fn absent_stays_absent() {
        let m = fold(&[r#"{"name":"t","schema":{"a":"1"}}"#, r#"{"name":"t"}"#]);
        assert!(m.get("columnDefinitions").is_none_or(JValue::is_null));
    }

    #[test]
    fn read_merges_child_over_base() {
        let m = fold(&[r#"{"name":"t","schema":{"fromRoot":"r","shared":"root"}}"#, r#"{"name":"t","schema":{"fromMid":"m","shared":"mid"}}"#]);
        let s = m["schema"].as_object().unwrap();
        assert_eq!(s["fromRoot"], JValue::Str("r".into()));
        assert_eq!(s["fromMid"], JValue::Str("m".into()));
        assert_eq!(s["shared"], JValue::Str("mid".into()));
    }

    #[test]
    fn read_merges_all_three_levels() {
        let m = fold(&[
            r#"{"name":"t","schema":{"fromRoot":"r","sharedRootMid":"root","sharedAll":"root"}}"#,
            r#"{"name":"t","schema":{"fromMid":"m","sharedRootMid":"mid","sharedAll":"mid"}}"#,
            r#"{"name":"t","schema":{"fromLeaf":"l","sharedAll":"leaf"}}"#,
        ]);
        let s = m["schema"].as_object().unwrap();
        assert_eq!(s["fromRoot"], JValue::Str("r".into()));
        assert_eq!(s["fromMid"], JValue::Str("m".into()));
        assert_eq!(s["fromLeaf"], JValue::Str("l".into()));
        assert_eq!(s["sharedRootMid"], JValue::Str("mid".into()));
        assert_eq!(s["sharedAll"], JValue::Str("leaf".into()));
    }

    #[test]
    fn read_does_not_collapse_stored_delta() {
        let leaf = obj(r#"{"name":"t","schema":{"fromLeaf":"l"}}"#);
        let stored = leaf.clone();
        let base = fold(&[r#"{"name":"t","schema":{"fromRoot":"r"}}"#, r#"{"name":"t","schema":{"fromMid":"m"}}"#]);
        assert!(apply_actual_override(&StorageDoc, leaf, Some(&base)).is_some());
        assert_eq!(stored["schema"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn unique_name_is_not_inherited() {
        let m = fold(&[
            r#"{"name":"t","uniqueName":"testapp_system_teststorage","schema":{"fromRoot":"r"}}"#,
            r#"{"name":"t","uniqueName":"testapp_lzcla_teststorage","schema":{"fromMid":"m"}}"#,
            r#"{"name":"t","uniqueName":"testapp_lzacp1_teststorage","schema":{"fromLeaf":"l"}}"#,
        ]);
        assert_eq!(m["uniqueName"], JValue::Str("testapp_lzacp1_teststorage".into()));
    }

    #[test]
    fn event_definitions_merge_their_schema_and_inherit_the_flag() {
        let base = obj(r#"{"name":"Storage.x.Create","schema":{"a":1},"includeContextAuthentication":true,"schedule":{"cron":"* * *"}}"#);
        let this = obj(r#"{"name":"Storage.x.Create","schema":{"b":2}}"#);
        let m = apply_actual_override(&EventDefinitionDoc, this, Some(&base)).unwrap();
        assert_eq!(m["includeContextAuthentication"], JValue::Bool(true));
        assert!(m["schema"].as_object().unwrap().contains_key("a"));
        assert!(m["schedule"].as_object().is_some());
        assert_eq!(EventDefinitionDoc.collection(), "eventDefinition");
        assert_eq!(EventDefinitionDoc.object_name(), "EventDefinition");
        assert_eq!(EventDefinitionDoc.pojo().name, "EventDefinition");
    }
}