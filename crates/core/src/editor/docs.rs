//! The write half of core's documents: `extractDifference` of every class (what a derived
//! client's document stores), and the three documents only the editor touches
//! (`Notification`, `Workflow`, `Action`).
//!
//! The read half (`applyOverride`, the cache names) is in [`crate::docs`].

use overridable::difference::{apply_map, apply_map_with, extract_map, extract_map_boolean, extract_map_with, extract_value};
use overridable::pojo::{map_field, set_opt_map, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use overridable::{java_map, DocType, JMap, JValue};

use crate::editor::beans::{self, T};

/// `Notification`. `notificationType` starts as `INFO`.
pub const NOTIFICATION: Pojo = Pojo {
    name: "Notification",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("notificationType", K::Str, C::Copy),
            Field::new("defaultLanguage", K::Str, C::Copy),
            Field::new("languageExpression", K::Str, C::Copy),
            Field::new("variableSchema", K::MapObject, C::MapObject),
            Field::new("channelTemplates", K::MapObject, C::MapObject),
            Field::new("channelConnections", K::MapString, C::MapObject),
            Field::new("channelEnabled", K::MapBool, C::MapObject),
        ],
    ],
};

/// `Connection` as the editor writes it: `isAppLevel` and `onlyThruKIRun` start as false.
pub const CONNECTION: Pojo = Pojo {
    name: "Connection",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("connectionType", K::Str, C::Copy),
            Field::new("connectionSubType", K::Str, C::Copy),
            Field::new("connectionDetails", K::MapObject, C::MapObject),
            Field::new("isAppLevel", K::PrimBool, C::Copy),
            Field::new("onlyThruKIRun", K::PrimBool, C::Copy),
            // Rust only: the OAuth consent gate, kept as given (absent stays absent).
            Field::new("consentAuth", K::Str, C::Copy),
        ],
    ],
};

/// `Workflow`.
pub const WORKFLOW: Pojo = Pojo {
    name: "Workflow",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("isTemplate", K::BoxBool, C::Copy),
            Field::new("startAuth", K::Str, C::Copy),
            Field::new("steps", K::MapObject, C::MapObject),
            Field::new("trigger", K::Object, C::Copy),
        ],
    ],
};

/// `Action`.
pub const ACTION: Pojo = Pojo {
    name: "Action",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("functionNamespace", K::Str, C::Copy),
            Field::new("functionName", K::Str, C::Copy),
            Field::new("properties", K::MapString, C::MapObject),
        ],
    ],
};

fn fallback(this: &mut JMap, base: &JMap, field: &str) {
    if this.get(field).is_none_or(JValue::is_null) {
        this.insert(field.to_string(), base.get(field).cloned().unwrap_or(JValue::Null));
    }
}

/// `if (CommonsUtil.safeEquals(this.f, base.f)) this.f = null`.
fn null_if_same(this: &mut JMap, base: &JMap, field: &str) {
    let a = this.get(field).filter(|v| !v.is_null());
    let b = base.get(field).filter(|v| !v.is_null());
    if a == b {
        this.insert(field.to_string(), JValue::Null);
    }
}

/// `if (this.f != null && this.f.equals(base.f)) this.f = null` (the same, for a field the
/// class only clears when it is set).
fn null_if_set_and_same(this: &mut JMap, base: &JMap, field: &str) {
    if this.get(field).is_some_and(|v| !v.is_null()) && this.get(field) == base.get(field) {
        this.insert(field.to_string(), JValue::Null);
    }
}

fn extract_into(this: &mut JMap, base: &JMap, field: &str) {
    let d = extract_map(map_field(this, field), map_field(base, field));
    this.insert(field.to_string(), JValue::Object(d));
}

fn extract_typed(this: &mut JMap, base: &JMap, field: &str, element: &dyn Fn(&JValue, &JValue) -> Option<JValue>) {
    let d = extract_map_with(map_field(this, field), map_field(base, field), element);
    this.insert(field.to_string(), JValue::Object(d));
}

/// A field of a class's difference: `safeEquals(existing, incoming) ? null : incoming`.
fn field_diff(existing: &JMap, incoming: &JMap, field: &str) -> JValue {
    let e = existing.get(field).filter(|v| !v.is_null());
    let i = incoming.get(field).filter(|v| !v.is_null());
    if e == i {
        JValue::Null
    } else {
        i.cloned().unwrap_or_default()
    }
}

/// A difference object as Spring Data stores it (its null fields left out).
fn bean_diff(existing: &JMap, incoming: &JMap, fields: &[&str]) -> JMap {
    let mut out = JMap::new();
    for f in fields {
        let v = field_diff(existing, incoming, f);
        if !v.is_null() {
            out.insert(f.to_string(), v);
        }
    }
    out
}

/// `StorageRelation.extractDifference` (on the existing relation, given the incoming one).
pub fn relation_diff(incoming: &JValue, existing: &JValue) -> Option<JValue> {
    let (Some(i), Some(e)) = (incoming.as_object(), existing.as_object()) else { return extract_value(Some(incoming), Some(existing)) };
    let fields: Vec<&str> = beans::STORAGE_RELATION.fields.iter().map(|f| f.name).collect();
    Some(JValue::Object(bean_diff(e, i, &fields)))
}

fn mysql_or_mongo_diff(existing: Option<&JMap>, incoming: Option<&JMap>, fields: &[&str]) -> Option<JMap> {
    let incoming = incoming?;
    Some(match existing {
        None => incoming.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect(),
        Some(e) => bean_diff(e, incoming, fields),
    })
}

/// `StorageColumnDefinition.extractDifference`.
pub fn column_definition_diff(incoming: &JValue, existing: &JValue) -> Option<JValue> {
    let (Some(i), Some(e)) = (incoming.as_object(), existing.as_object()) else { return extract_value(Some(incoming), Some(existing)) };
    let mysql_fields: Vec<&str> = beans::MYSQL_COLUMN.fields.iter().map(|f| f.name).collect();
    let mut out = JMap::new();
    if let Some(m) = mysql_or_mongo_diff(map_field(e, "mysql"), map_field(i, "mysql"), &mysql_fields) {
        out.insert("mysql".into(), JValue::Object(m));
    }
    if let Some(m) = mysql_or_mongo_diff(map_field(e, "mongo"), map_field(i, "mongo"), &["bsonType"]) {
        out.insert("mongo".into(), JValue::Object(m));
    }
    Some(JValue::Object(out))
}

/// `EventActionTask.extractDifference`: the order and the type when they changed, the
/// parameters' difference (empty when none); the key is left out.
pub fn task_diff(incoming: &JValue, existing: &JValue) -> Option<JValue> {
    let (Some(i), Some(e)) = (incoming.as_object(), existing.as_object()) else { return extract_value(Some(incoming), Some(existing)) };
    let mut out = JMap::new();
    for f in ["order", "type"] {
        let v = field_diff(e, i, f);
        if !v.is_null() {
            out.insert(f.into(), v);
        }
    }
    let params = extract_map(map_field(i, "parameters"), map_field(e, "parameters"));
    out.insert("parameters".into(), JValue::Object(params));
    // `new EventActionTask()` is written key, order, type, parameters.
    let mut ordered = JMap::new();
    for f in ["key", "order", "type", "parameters"] {
        if let Some(v) = out.shift_remove(f) {
            ordered.insert(f.into(), v);
        }
    }
    Some(JValue::Object(ordered))
}

/// `NotificationTemplate.extractDifference`.
pub fn notification_template_diff(incoming: &JValue, existing: &JValue) -> Option<JValue> {
    let (Some(i), Some(e)) = (incoming.as_object(), existing.as_object()) else { return extract_value(Some(incoming), Some(existing)) };
    let mut out = JMap::new();
    out.insert("templateParts".into(), JValue::Object(extract_map(map_field(i, "templateParts"), map_field(e, "templateParts"))));
    out.insert("resources".into(), JValue::Object(extract_map(map_field(i, "resources"), map_field(e, "resources"))));
    Some(JValue::Object(out))
}

/// `AbstractFunction.extractDifference`.
pub fn function(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_into(&mut this, base, "definition");
    null_if_set_and_same(&mut this, base, "executeAuth");
    Some(this)
}

/// `AbstractSchema.extractDifference`.
pub fn schema(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_into(&mut this, base, "definition");
    Some(this)
}

/// `Storage.extractDifference` (`subMakeOverride` clears every flag the base already has).
pub fn storage(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_into(&mut this, base, "schema");
    extract_typed(&mut this, base, "relations", &relation_diff);
    extract_into(&mut this, base, "triggers");
    extract_into(&mut this, base, "fieldDefinitionMap");
    extract_into(&mut this, base, "indexes");
    // `extract(Object, Object)` on the lists: the same list is no difference.
    let tif = extract_value(this.get("textIndexFields"), base.get("textIndexFields")).unwrap_or_default();
    this.insert("textIndexFields".into(), tif);
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
        null_if_same(&mut this, base, f);
    }
    let cd = extract_map_with(map_field(&this, "columnDefinitions"), map_field(base, "columnDefinitions"), &column_definition_diff);
    set_opt_map(&mut this, "columnDefinitions", Some(cd).filter(|m| !m.is_empty()));
    Some(this)
}

/// `Connection.extractDifference` returns itself.
pub fn connection(this: JMap, _base: &JMap) -> Option<JMap> {
    Some(this)
}

/// `EventDefinition.extractDifference`.
pub fn event_definition(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_into(&mut this, base, "schema");
    null_if_same(&mut this, base, "includeContextAuthentication");
    let derived = this.get("schedule").and_then(crate::scheduler::EventSchedule::from_j);
    let base_schedule = base.get("schedule").and_then(crate::scheduler::EventSchedule::from_j);
    let diff = crate::scheduler::EventSchedule::difference(derived.as_ref(), base_schedule.as_ref());
    this.insert("schedule".into(), diff.map(|d| beans::stored(T::Bean(&beans::EVENT_SCHEDULE), &d.to_j())).unwrap_or_default());
    Some(this)
}

/// `EventAction.extractDifference`.
pub fn event_action(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_typed(&mut this, base, "tasks", &task_diff);
    Some(this)
}

/// `Template.extractDifference`.
pub fn template(mut this: JMap, base: &JMap) -> Option<JMap> {
    for f in ["templateParts", "resources", "variableSchema", "sampleData", "design"] {
        extract_into(&mut this, base, f);
    }
    for f in ["templateType", "defaultLanguage", "toExpression", "fromExpression", "languageExpression"] {
        null_if_same(&mut this, base, f);
    }
    Some(this)
}

/// `Notification.extractDifference`. The scalars are filled from the base when unset (the
/// class does that rather than clearing what equals the base).
pub fn notification(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_typed(&mut this, base, "channelTemplates", &notification_template_diff);
    extract_into(&mut this, base, "channelConnections");
    extract_into(&mut this, base, "variableSchema");
    let ce = extract_map_boolean(map_field(&this, "channelEnabled"), map_field(base, "channelEnabled"));
    this.insert("channelEnabled".into(), JValue::Object(ce));
    for f in ["notificationType", "defaultLanguage", "languageExpression"] {
        fallback(&mut this, base, f);
    }
    Some(this)
}

/// `Action.extractDifference`.
pub fn action(mut this: JMap, base: &JMap) -> Option<JMap> {
    extract_into(&mut this, base, "properties");
    null_if_set_and_same(&mut this, base, "functionNamespace");
    null_if_set_and_same(&mut this, base, "functionName");
    Some(this)
}

pub struct NotificationDoc;
pub struct WorkflowDoc;
pub struct ActionDoc;

impl DocType for NotificationDoc {
    fn object_name(&self) -> &'static str {
        "Notification"
    }
    fn collection(&self) -> &'static str {
        "notification"
    }
    fn pojo(&self) -> &'static Pojo {
        &NOTIFICATION
    }
    /// `Notification.applyOverride`: the four maps merged, the unset scalars inherited.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let typed = |o: &JValue, b: Option<&JValue>| -> Option<JValue> {
            let (Some(om), Some(bm)) = (o.as_object(), b.and_then(JValue::as_object)) else { return Some(o.clone()) };
            let mut out = JMap::new();
            out.insert("templateParts".into(), apply_map(map_field(om, "templateParts"), map_field(bm, "templateParts")).map(JValue::Object).unwrap_or_default());
            out.insert("resources".into(), apply_map(map_field(om, "resources"), map_field(bm, "resources")).map(JValue::Object).unwrap_or_default());
            Some(JValue::Object(out))
        };
        let ch = apply_map_with(map_field(&this, "channelTemplates"), map_field(base, "channelTemplates"), &typed);
        set_opt_map(&mut this, "channelTemplates", ch);
        for f in ["channelConnections", "variableSchema"] {
            let v = apply_map(map_field(&this, f), map_field(base, f));
            set_opt_map(&mut this, f, v);
        }
        let ce = apply_map(map_field(&this, "channelEnabled"), map_field(base, "channelEnabled"));
        set_opt_map(&mut this, "channelEnabled", ce);
        for f in ["notificationType", "defaultLanguage", "languageExpression"] {
            fallback(&mut this, base, f);
        }
        Some(this)
    }
    fn extract_difference(&self, this: JMap, base: &JMap) -> Option<JMap> {
        notification(this, base)
    }
}

impl DocType for WorkflowDoc {
    fn object_name(&self) -> &'static str {
        "Workflow"
    }
    fn collection(&self) -> &'static str {
        "workflow"
    }
    fn pojo(&self) -> &'static Pojo {
        &WORKFLOW
    }
    /// `Workflow` neither merges nor extracts: each document is whole.
    fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
    fn extract_difference(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
}

impl DocType for ActionDoc {
    fn object_name(&self) -> &'static str {
        "Action"
    }
    fn collection(&self) -> &'static str {
        "action"
    }
    fn pojo(&self) -> &'static Pojo {
        &ACTION
    }
    /// `Action.applyOverride`: the properties merged (empty when nothing is left), the function
    /// inherited when unset.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let p = apply_map(map_field(&this, "properties"), map_field(base, "properties")).unwrap_or_default();
        this.insert("properties".into(), JValue::Object(p));
        fallback(&mut this, base, "functionNamespace");
        fallback(&mut this, base, "functionName");
        Some(this)
    }
    fn extract_difference(&self, this: JMap, base: &JMap) -> Option<JMap> {
        action(this, base)
    }
}

/// A map as a Java `HashMap` filled from it.
pub fn hash_map(m: JMap) -> JMap {
    java_map::by_puts(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    // ── StorageFlagsOverrideTest.equalFlagsAreNotStored ──

    #[test]
    fn equal_flags_are_not_stored() {
        let base = obj(r#"{"name":"deal","isAudited":true,"isVersioned":false,"isAppLevel":true,"onlyThruKIRun":true,"uniqueName":"u1"}"#);
        let fork = obj(r#"{"name":"deal","isAudited":true,"isVersioned":true,"isAppLevel":true,"onlyThruKIRun":true,"uniqueName":"u1"}"#);
        let d = storage(fork, &base).unwrap();
        assert_eq!(d["isAudited"], JValue::Null, "the same as the base: not stored");
        assert_eq!(d["isAppLevel"], JValue::Null);
        assert_eq!(d["onlyThruKIRun"], JValue::Null);
        assert_eq!(d["uniqueName"], JValue::Null, "a shared table name is the base's");
        assert_eq!(d["isVersioned"], JValue::Bool(true), "a change is stored");
    }

    // ── StorageRelationDiffTest ──

    #[test]
    fn relation_differences() {
        let base = obj(r#"{"relations":{"owner":{"storageName":"users","relationType":"TO_ONE","deleteConstraint":"NOTHING","updateConstraint":"NOTHING"}}}"#);
        let same = obj(r#"{"relations":{"owner":{"storageName":"users","relationType":"TO_ONE","deleteConstraint":"NOTHING","updateConstraint":"NOTHING"}}}"#);
        let d = storage(same, &base).unwrap();
        assert_eq!(d["relations"], JValue::Object(JMap::new()), "an unchanged relation is no difference");
        let changed = obj(r#"{"relations":{"owner":{"storageName":"users","relationType":"TO_MANY","deleteConstraint":"CASCADE","updateConstraint":"NOTHING"}}}"#);
        let d = storage(changed, &base).unwrap();
        assert_eq!(d["relations"], JValue::Object(obj(r#"{"owner":{"relationType":"TO_MANY","deleteConstraint":"CASCADE"}}"#)));
        let added = obj(r#"{"relations":{"owner":{"storageName":"users","relationType":"TO_ONE","deleteConstraint":"NOTHING","updateConstraint":"NOTHING"},"tags":{"storageName":"tags"}}}"#);
        let d = storage(added, &base).unwrap();
        assert_eq!(d["relations"], JValue::Object(obj(r#"{"tags":{"storageName":"tags"}}"#)));
        let removed = obj(r#"{"relations":{}}"#);
        let d = storage(removed, &base).unwrap();
        assert_eq!(d["relations"], JValue::Object(obj(r#"{"owner":null}"#)), "a relation the fork drops is a deletion");
    }

    // ── StorageColumnDefinitionDiffTest ──

    #[test]
    fn column_definition_differences() {
        let base = obj(r#"{"columnDefinitions":{"price":{"mysql":{"type":"DECIMAL","precision":19,"scale":4}}}}"#);
        let d = storage(obj(r#"{"columnDefinitions":{"price":{"mysql":{"type":"DECIMAL","precision":19,"scale":4}}}}"#), &base).unwrap();
        assert_eq!(d["columnDefinitions"], JValue::Null, "an empty difference is stored as null");
        let d = storage(obj(r#"{"columnDefinitions":{"price":{"mysql":{"type":"DECIMAL","precision":10,"scale":4}}}}"#), &base).unwrap();
        assert_eq!(d["columnDefinitions"], JValue::Object(obj(r#"{"price":{"mysql":{"precision":10}}}"#)));
        let d = storage(obj(r#"{"columnDefinitions":{"price":{"mysql":{"type":"DECIMAL","precision":19,"scale":4},"mongo":{"bsonType":"DECIMAL128"}}}}"#), &base).unwrap();
        assert_eq!(d["columnDefinitions"], JValue::Object(obj(r#"{"price":{"mysql":{},"mongo":{"bsonType":"DECIMAL128"}}}"#)));
        assert_eq!(column_definition_diff(&JValue::Str("x".into()), &JValue::Str("y".into())), Some(JValue::Str("x".into())));
    }

    // ── EventActionTaskDiffTest ──

    #[test]
    fn task_differences() {
        let base = obj(r#"{"tasks":{"t1":{"key":"t1","order":1,"type":"SEND_EMAIL","parameters":{"to":"a","cc":"b"}}}}"#);
        let d = event_action(obj(r#"{"tasks":{"t1":{"key":"t1","order":1,"type":"SEND_EMAIL","parameters":{"to":"a","cc":"c"}}}}"#), &base).unwrap();
        assert_eq!(d["tasks"], JValue::Object(obj(r#"{"t1":{"parameters":{"cc":"c"}}}"#)));
        let d = event_action(obj(r#"{"tasks":{"t1":{"key":"t1","order":2,"type":"CALL_CORE_FUNCTION","parameters":{"to":"a","cc":"b"}}}}"#), &base).unwrap();
        assert_eq!(d["tasks"], JValue::Object(obj(r#"{"t1":{"order":2,"type":"CALL_CORE_FUNCTION","parameters":{}}}"#)));
        assert_eq!(task_diff(&JValue::Int(1), &JValue::Int(2)), Some(JValue::Int(1)));
    }

    #[test]
    fn the_other_classes() {
        let f = function(obj(r#"{"definition":{"name":"f","namespace":"A","steps":{}},"executeAuth":"X"}"#), &obj(r#"{"definition":{"name":"f","namespace":"A"},"executeAuth":"X"}"#)).unwrap();
        assert_eq!(f["executeAuth"], JValue::Null);
        assert_eq!(f["definition"], JValue::Object(obj(r#"{"steps":{}}"#)));
        let s = schema(obj(r#"{"definition":{"name":"s","type":"OBJECT"}}"#), &obj(r#"{"definition":{"name":"s"}}"#)).unwrap();
        assert_eq!(s["definition"], JValue::Object(obj(r#"{"type":"OBJECT"}"#)));
        assert_eq!(connection(obj(r#"{"a":1}"#), &obj("{}")).unwrap(), obj(r#"{"a":1}"#));
        let e = event_definition(
            obj(r#"{"schema":{"a":1},"includeContextAuthentication":true,"schedule":{"cron":"0 * * * *","enabled":false}}"#),
            &obj(r#"{"schema":{"a":1},"includeContextAuthentication":true,"schedule":{"cron":"0 * * * *"}}"#),
        )
        .unwrap();
        assert_eq!(e["includeContextAuthentication"], JValue::Null);
        assert_eq!(e["schedule"], JValue::Object(obj(r#"{"enabled":false}"#)));
        let e = event_definition(obj(r#"{"schedule":{"cron":"0 * * * *"}}"#), &obj(r#"{"schedule":{"cron":"0 * * * *"}}"#)).unwrap();
        assert_eq!(e["schedule"], JValue::Null);
        let t = template(obj(r#"{"templateParts":{"en":{"body":"B"}},"toExpression":"x","templateType":"MAIL"}"#), &obj(r#"{"templateParts":{"en":{"body":"A"}},"toExpression":"x"}"#)).unwrap();
        assert_eq!(t["toExpression"], JValue::Null);
        assert_eq!(t["templateType"], JValue::Str("MAIL".into()));
        let n = notification(
            obj(r#"{"channelTemplates":{"email":{"templateParts":{"en":{"s":"x"}},"resources":{}}},"channelEnabled":{"email":true,"sms":false},"notificationType":null}"#),
            &obj(r#"{"channelTemplates":{"email":{"templateParts":{"en":{"s":"y"}}}},"channelEnabled":{"email":true},"notificationType":"ALERT"}"#),
        )
        .unwrap();
        assert_eq!(n["notificationType"], JValue::Str("ALERT".into()), "filled from the base, as the class does");
        assert_eq!(n["channelEnabled"], JValue::Object(obj(r#"{"sms":false}"#)));
        assert_eq!(n["channelTemplates"], JValue::Object(obj(r#"{"email":{"templateParts":{"en":{"s":"x"}},"resources":{}}}"#)));
        let a = action(obj(r#"{"functionName":"f","functionNamespace":"N","properties":{"a":"1"}}"#), &obj(r#"{"functionName":"f","functionNamespace":"M","properties":{"a":"1"}}"#)).unwrap();
        assert_eq!((a["functionName"].clone(), a["functionNamespace"].clone()), (JValue::Null, JValue::Str("N".into())));
        assert_eq!(a["properties"], JValue::Object(JMap::new()));
    }

    #[test]
    fn the_editor_only_classes_merge_as_java_does() {
        let n = NotificationDoc
            .apply_override(
                obj(r#"{"channelTemplates":{"email":{"templateParts":{"en":{"s":"x"}}}},"notificationType":null,"channelEnabled":{"sms":true}}"#),
                &obj(r#"{"channelTemplates":{"email":{"templateParts":{"en":{"b":"y"}},"resources":{"r":"1"}}},"notificationType":"ALERT","channelEnabled":{"email":true},"channelConnections":{"email":"c"}}"#),
            )
            .unwrap();
        assert_eq!(n["notificationType"], JValue::Str("ALERT".into()));
        let email = n["channelTemplates"].as_object().unwrap()["email"].as_object().unwrap();
        assert_eq!(email["templateParts"].as_object().unwrap()["en"].as_object().unwrap().len(), 2);
        assert_eq!(n["channelEnabled"].as_object().unwrap().len(), 2);
        assert_eq!(n["channelConnections"], JValue::Object(obj(r#"{"email":"c"}"#)));
        assert_eq!(NotificationDoc.collection(), "notification");
        assert_eq!(NotificationDoc.pojo().name, "Notification");
        let w = WorkflowDoc.apply_override(obj(r#"{"steps":{}}"#), &obj(r#"{"startAuth":"x"}"#)).unwrap();
        assert!(w.get("startAuth").is_none());
        assert_eq!(WorkflowDoc.extract_difference(obj(r#"{"a":1}"#), &obj("{}")).unwrap(), obj(r#"{"a":1}"#));
        assert_eq!((WorkflowDoc.collection(), WorkflowDoc.object_name(), WorkflowDoc.pojo().name), ("workflow", "Workflow", "Workflow"));
        let a = ActionDoc.apply_override(obj(r#"{"properties":null}"#), &obj(r#"{"functionName":"f","properties":{"a":"1"}}"#)).unwrap();
        assert_eq!(a["functionName"], JValue::Str("f".into()));
        assert_eq!(a["properties"], JValue::Object(obj(r#"{"a":"1"}"#)));
        assert_eq!((ActionDoc.collection(), ActionDoc.object_name()), ("action", "Action"));
        assert!(ActionDoc.extract_difference(obj(r#"{"properties":{}}"#), &obj("{}")).is_some());
        assert!(NotificationDoc.extract_difference(obj("{}"), &obj("{}")).is_some());
        assert_eq!(hash_map(obj(r#"{"b":1,"a":2}"#)).len(), 2);
    }
}
