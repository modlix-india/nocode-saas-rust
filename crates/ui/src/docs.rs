//! The ui service's overridable documents (`com.fincity.saas.ui.document`): their fields, and
//! each class's `applyOverride`.

use overridable::difference::{
    apply_map, apply_map_boolean, apply_map_with_deferral, extract_map, extract_map_boolean, extract_map_with,
    maps_deferred,
};
use overridable::pojo::{map_field, set_opt_map, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use overridable::{DocType, JMap, JValue};

/// `com.fincity.saas.ui.model.ComponentDefinition`.
pub const COMPONENT_DEFINITION: Pojo = Pojo {
    name: "ComponentDefinition",
    parts: &[&[
        Field::new("key", K::Str, C::Copy),
        Field::new("name", K::Str, C::Copy),
        Field::new("type", K::Str, C::Copy),
        Field::new("properties", K::MapObject, C::MapObject),
        Field::new("styleProperties", K::MapObject, C::MapObject),
        Field::new("override", K::PrimBool, C::Copy),
        Field::new("children", K::MapBool, C::MapObject),
        Field::new("displayOrder", K::BoxInt, C::Copy),
        Field::new("bindingPath", K::MapString, C::MapObject),
        Field::new("bindingPath2", K::MapString, C::MapObject),
        Field::new("bindingPath3", K::MapString, C::MapObject),
        Field::new("bindingPath4", K::MapString, C::MapObject),
        Field::new("bindingPath5", K::MapString, C::MapObject),
        Field::new("bindingPath6", K::MapString, C::MapObject),
    ]],
};

pub const PAGE: Pojo = Pojo {
    name: "Page",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("device", K::Str, C::Copy),
            Field::new("translations", K::MapMapString, C::MapStringMap),
            Field::new("properties", K::MapObject, C::MapObject),
            Field::new("eventFunctions", K::MapObject, C::MapObject),
            Field::new("rootComponent", K::Str, C::Copy),
            Field::new("componentDefinition", K::MapPojo(&COMPONENT_DEFINITION), C::MapObject),
            Field::new("componentVersions", K::MapInt, C::NewHashMap),
            Field::new("eventFunctionVersions", K::MapInt, C::NewHashMap),
        ],
    ],
};

pub const APPLICATION: Pojo = Pojo {
    name: "Application",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("translations", K::MapMapString, C::MapStringMap),
            Field::new("languages", K::MapMapString, C::MapStringMap),
            Field::new("properties", K::MapObject, C::MapObject),
            Field::new("defaultLanguage", K::Str, C::Copy),
            // Not copied by the copy constructor; set by the engine after.
            Field::new("urlClientCode", K::Str, C::Skip),
        ],
    ],
};

pub const STYLE: Pojo = Pojo {
    name: "Style",
    parts: &[OVERRIDABLE_BASE, &[Field::new("styleString", K::Str, C::Copy)]],
};

pub const THEME: Pojo = Pojo {
    name: "StyleTheme",
    parts: &[OVERRIDABLE_BASE, &[Field::new("variables", K::MapMapString, C::MapStringMap)]],
};

pub const FUNCTION: Pojo = Pojo {
    name: "UIFunction",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("definition", K::MapObject, C::MapObject),
            Field::new("executeAuth", K::Str, C::Copy),
        ],
    ],
};

pub const SCHEMA: Pojo = Pojo {
    name: "UISchema",
    parts: &[OVERRIDABLE_BASE, &[Field::new("definition", K::MapObject, C::MapObject)]],
};

pub const FILLER: Pojo = Pojo {
    name: "UIFiller",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("definition", K::MapObject, C::MapObject),
            Field::new("values", K::MapObject, C::MapObject),
        ],
    ],
};

pub const PERSONALIZATION: Pojo = Pojo {
    name: "Personalization",
    parts: &[OVERRIDABLE_BASE, &[Field::new("personalization", K::MapObject, C::MapObject)]],
};

fn merge_into(this: &mut JMap, base: &JMap, field: &str) {
    let v = apply_map(map_field(this, field), map_field(base, field));
    set_opt_map(this, field, v);
}

fn fallback(this: &mut JMap, base: &JMap, field: &str) {
    if this.get(field).is_none_or(JValue::is_null) {
        this.insert(field.to_string(), base.get(field).cloned().unwrap_or(JValue::Null));
    }
}

const COMPONENT_MAPS: [&str; 9] = [
    "properties", "children", "styleProperties", "bindingPath", "bindingPath2", "bindingPath3", "bindingPath4",
    "bindingPath5", "bindingPath6",
];

/// Whether Java's `ComponentDefinition.applyOverride` finishes on its scheduler: when any of
/// its map merges has entries on both sides.
pub fn component_deferred(o: &JValue, b: &JValue) -> bool {
    let (JValue::Object(o), JValue::Object(b)) = (o, b) else {
        return false;
    };
    COMPONENT_MAPS.iter().any(|f| match (o.get(*f), b.get(*f)) {
        (Some(x), Some(y)) => maps_deferred(x, y),
        _ => false,
    })
}

/// `ComponentDefinition.applyOverride(base)`.
pub fn component_apply(override_: &JValue, base: Option<&JValue>) -> Option<JValue> {
    let JValue::Object(o) = override_ else {
        return Some(override_.clone());
    };
    let Some(JValue::Object(b)) = base else {
        // No base: an override-only entry disappears, a full one stays.
        let is_override = o.get("override").and_then(JValue::as_bool).unwrap_or(false);
        return (!is_override).then(|| override_.clone());
    };
    let mut this = o.clone();
    let props = apply_map(map_field(&this, "properties"), map_field(b, "properties"));
    let children = apply_map_boolean(map_field(&this, "children"), map_field(b, "children"));
    let style = apply_map(map_field(&this, "styleProperties"), map_field(b, "styleProperties"));
    let paths: Vec<Option<JMap>> = ["bindingPath", "bindingPath2", "bindingPath3", "bindingPath4", "bindingPath5", "bindingPath6"]
        .iter()
        .map(|f| apply_map(map_field(&this, f), map_field(b, f)))
        .collect();

    set_opt_map(&mut this, "children", children);
    set_opt_map(&mut this, "properties", props);
    set_opt_map(&mut this, "styleProperties", style);
    this.insert("key".into(), b.get("key").cloned().unwrap_or(JValue::Null));
    this.insert("override".into(), JValue::Bool(true));
    fallback(&mut this, b, "type");
    fallback(&mut this, b, "name");
    fallback(&mut this, b, "displayOrder");
    for (f, v) in ["bindingPath", "bindingPath2", "bindingPath3", "bindingPath4", "bindingPath5", "bindingPath6"]
        .iter()
        .zip(paths)
    {
        if let Some(m) = v.filter(|m| !m.is_empty()) {
            this.insert(f.to_string(), JValue::Object(m));
        }
    }
    Some(JValue::Object(this))
}

/// `ComponentDefinition.extractDifference(incoming)` with `existing` as `this`, kept as Java
/// has it: a changed name or type records the EXISTING value, and every non-empty binding path
/// difference is written to `bindingPath` (the later ones overwriting the earlier).
pub fn component_extract(incoming: &JValue, existing: &JValue) -> Option<JValue> {
    let (JValue::Object(inc), JValue::Object(this)) = (incoming, existing) else {
        return Some(incoming.clone());
    };
    let diff = |f: &str| extract_map(map_field(inc, f), map_field(this, f));
    let mut cd = JMap::new();
    for f in COMPONENT_DEFINITION.fields() {
        cd.insert(f.name.to_string(), JValue::Null);
    }
    let same = |f: &str| inc.get(f).unwrap_or(&JValue::Null) == this.get(f).unwrap_or(&JValue::Null);
    for f in ["name", "type"] {
        let v = if same(f) { JValue::Null } else { this.get(f).cloned().unwrap_or_default() };
        cd.insert(f.into(), v);
    }
    cd.insert("override".into(), JValue::Bool(true));
    cd.insert("properties".into(), JValue::Object(diff("properties")));
    cd.insert(
        "children".into(),
        JValue::Object(extract_map_boolean(map_field(inc, "children"), map_field(this, "children"))),
    );
    cd.insert("styleProperties".into(), JValue::Object(diff("styleProperties")));
    let order = if same("displayOrder") { JValue::Null } else { inc.get("displayOrder").cloned().unwrap_or_default() };
    cd.insert("displayOrder".into(), order);
    for f in ["bindingPath", "bindingPath2", "bindingPath3", "bindingPath4", "bindingPath5", "bindingPath6"] {
        let d = diff(f);
        if !d.is_empty() {
            cd.insert("bindingPath".into(), JValue::Object(d));
        }
    }
    Some(JValue::Object(cd))
}

fn extract_into(this: &mut JMap, base: &JMap, field: &str) {
    let d = extract_map(map_field(this, field), map_field(base, field));
    this.insert(field.to_string(), JValue::Object(d));
}

pub struct PageDoc;
pub struct ApplicationDoc;
pub struct StyleDoc;
pub struct ThemeDoc;
pub struct FunctionDoc;
pub struct SchemaDoc;
pub struct FillerDoc;

impl DocType for PageDoc {
    fn object_name(&self) -> &'static str {
        "Page"
    }
    fn collection(&self) -> &'static str {
        "page"
    }
    fn pojo(&self) -> &'static Pojo {
        &PAGE
    }
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        merge_into(&mut this, base, "translations");
        merge_into(&mut this, base, "properties");
        merge_into(&mut this, base, "eventFunctions");
        let cd = apply_map_with_deferral(
            map_field(&this, "componentDefinition"),
            map_field(base, "componentDefinition"),
            &component_apply,
            &component_deferred,
        );
        set_opt_map(&mut this, "componentDefinition", cd);
        // Unconditional in Page.applyOverride.
        this.insert("device".into(), base.get("device").cloned().unwrap_or(JValue::Null));
        fallback(&mut this, base, "rootComponent");
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        extract_into(&mut this, base, "properties");
        extract_into(&mut this, base, "translations");
        let cd = extract_map_with(
            map_field(&this, "componentDefinition"),
            map_field(base, "componentDefinition"),
            &component_extract,
        );
        this.insert("componentDefinition".into(), JValue::Object(cd));
        extract_into(&mut this, base, "eventFunctions");
        if this.get("rootComponent").is_some_and(|r| !r.is_null()) && this.get("rootComponent") == base.get("rootComponent") {
            this.insert("rootComponent".into(), JValue::Null);
        }
        Some(this)
    }
}

impl DocType for ApplicationDoc {
    fn object_name(&self) -> &'static str {
        "Application"
    }
    fn collection(&self) -> &'static str {
        "application"
    }
    fn pojo(&self) -> &'static Pojo {
        &APPLICATION
    }
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        merge_into(&mut this, base, "translations");
        merge_into(&mut this, base, "languages");
        merge_into(&mut this, base, "properties");
        fallback(&mut this, base, "defaultLanguage");
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        extract_into(&mut this, base, "translations");
        extract_into(&mut this, base, "languages");
        extract_into(&mut this, base, "properties");
        if this.get("defaultLanguage").is_some_and(|r| !r.is_null()) && this.get("defaultLanguage") == base.get("defaultLanguage") {
            this.insert("defaultLanguage".into(), JValue::Null);
        }
        Some(this)
    }
}

impl DocType for StyleDoc {
    fn object_name(&self) -> &'static str {
        "Style"
    }
    fn collection(&self) -> &'static str {
        "style"
    }
    fn pojo(&self) -> &'static Pojo {
        &STYLE
    }
    fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
}

impl DocType for ThemeDoc {
    fn object_name(&self) -> &'static str {
        "Theme"
    }
    fn collection(&self) -> &'static str {
        "theme"
    }
    fn pojo(&self) -> &'static Pojo {
        &THEME
    }
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        merge_into(&mut this, base, "variables");
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        extract_into(&mut this, base, "variables");
        Some(this)
    }
}

/// `AbstractFunction` / `AbstractSchema.applyOverride`: `apply(...).map(...)`, so a merge with
/// nothing on either side makes the whole override empty.
fn apply_definition(mut this: JMap, base: &JMap) -> Option<JMap> {
    let d = apply_map(map_field(&this, "definition"), map_field(base, "definition"))?;
    this.insert("definition".into(), JValue::Object(d));
    Some(this)
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
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        format!("UIFunctionCache_{app_code}_{name}")
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        let mut this = apply_definition(this, base)?;
        fallback(&mut this, base, "executeAuth");
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        extract_into(&mut this, base, "definition");
        if this.get("executeAuth").is_some_and(|r| !r.is_null()) && this.get("executeAuth") == base.get("executeAuth") {
            this.insert("executeAuth".into(), JValue::Null);
        }
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
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        format!("UISchemaCache_{app_code}_{name}")
    }
    fn apply_override(&self, this: JMap, base: &JMap) -> Option<JMap> {
        apply_definition(this, base)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        extract_into(&mut this, base, "definition");
        Some(this)
    }
}

impl DocType for FillerDoc {
    fn object_name(&self) -> &'static str {
        "Filler"
    }
    fn collection(&self) -> &'static str {
        "filler"
    }
    fn pojo(&self) -> &'static Pojo {
        &FILLER
    }
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        format!("UIFillerCache_{app_code}_{name}")
    }
    /// `flatMapMono` over two merges: either one coming back empty empties the whole override.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let d = apply_map(map_field(&this, "definition"), map_field(base, "definition"))?;
        let v = apply_map(map_field(&this, "values"), map_field(base, "values"))?;
        this.insert("definition".into(), JValue::Object(d));
        this.insert("values".into(), JValue::Object(v));
        Some(this)
    }
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        extract_into(&mut this, base, "definition");
        extract_into(&mut this, base, "values");
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
    fn page_override_merges_components_and_takes_the_base_device() {
        let base = obj(
            r#"{"name":"home","device":"desktop","rootComponent":"root","description":"base d",
            "properties":{"title":"Base","wrapShell":true},
            "componentDefinition":{
              "root":{"key":"root","name":"Root","type":"Grid","children":{"a":true,"b":true},"displayOrder":0,"override":false,
                      "properties":{"x":1},"bindingPath":{"type":"VALUE","value":"Page.x"}},
              "a":{"key":"a","name":"A","type":"Text","override":false},
              "b":{"key":"b","name":"B","type":"Text","override":false}}}"#,
        );
        let ovr = obj(
            r#"{"name":"home","device":null,"properties":{"title":"Mine","wrapShell":null},
            "componentDefinition":{
              "root":{"override":true,"children":{"b":null,"c":true},"properties":{"y":2}},
              "c":{"key":"c","name":"C","type":"Button","override":false},
              "ghost":{"key":"ghost","override":true}}}"#,
        );
        let got = apply_actual_override(&PageDoc, ovr, Some(&base)).unwrap();
        assert_eq!(got["device"], JValue::Str("desktop".into()));
        assert_eq!(got["rootComponent"], JValue::Str("root".into()));
        assert_eq!(got["description"], JValue::Str("base d".into()));
        assert_eq!(got["properties"], JValue::Object(obj(r#"{"title":"Mine"}"#)));
        let cd = got["componentDefinition"].as_object().unwrap();
        let root = cd["root"].as_object().unwrap();
        assert_eq!(root["key"], JValue::Str("root".into()));
        assert_eq!(root["type"], JValue::Str("Grid".into()));
        assert_eq!(root["override"], JValue::Bool(true));
        assert_eq!(root["displayOrder"], JValue::Int(0));
        // A child the override removed (null) leaves the merged children.
        assert_eq!(root["children"], JValue::Object(obj(r#"{"a":true,"c":true}"#)));
        assert_eq!(root["properties"], JValue::Object(obj(r#"{"x":1,"y":2}"#)));
        assert_eq!(root["bindingPath"], JValue::Object(obj(r#"{"type":"VALUE","value":"Page.x"}"#)));
        // Only in the override: taken whole, override flag or not.
        assert!(cd.contains_key("c"));
        assert!(cd.contains_key("ghost"));
        assert!(cd.contains_key("a"));
    }

    #[test]
    fn override_only_component_vanishes_without_a_base_value() {
        let v = parse(br#"{"key":"x","override":true}"#).unwrap();
        assert_eq!(component_apply(&v, None), None);
        let v = parse(br#"{"key":"x","override":false}"#).unwrap();
        assert!(component_apply(&v, None).is_some());
    }

    #[test]
    fn function_with_no_definition_on_either_side_merges_to_nothing() {
        let this = obj(r#"{"name":"a","definition":null}"#);
        let base = obj(r#"{"name":"a","definition":null}"#);
        assert!(FunctionDoc.apply_override(this, &base).is_none());
    }

    // The Java ui `DifferenceApplicatorTest` (commons.mongo.util).
    #[test]
    fn test_component_definition() {
        let base = parse(
            br##"{"key":"7hwvfLdbWu30fEKpWYTI5","name":"Home","type":"Link","override":true,"displayOrder":1,
            "properties":{"linkPath":{"value":"/#wMvpDZzOZNVcEcc0d62yn"},"label":{"value":"Home"}}}"##,
        )
        .unwrap();
        let ovr = parse(br#"{"properties":{"label":{"value":"Test"}},"displayOrder":4,"override":false}"#).unwrap();
        let got = component_apply(&ovr, Some(&base)).unwrap();
        let got = got.as_object().unwrap();
        assert_eq!(
            got["properties"],
            parse(br##"{"linkPath":{"value":"/#wMvpDZzOZNVcEcc0d62yn"},"label":{"value":"Test"}}"##).unwrap()
        );
        assert_eq!(got["displayOrder"], JValue::Int(4));
    }

    // The Java ui `DifferenceExtractorTest` (commons.mongo.util).
    #[test]
    fn test_difference_extractor() {
        let base = parse(
            br##"{"key":"7hwvfLdbWu30fEKpWYTI5","name":"Home","type":"Link","override":true,"displayOrder":1,
            "properties":{"linkPath":{"value":"/#wMvpDZzOZNVcEcc0d62yn"},"label":{"value":"Home"}}}"##,
        )
        .unwrap();
        let ovr = parse(
            br##"{"key":"7hwvfLdbWu30fEKpWYTI5","name":"Home","type":"Link","override":true,"displayOrder":4,
            "properties":{"linkPath":{"value":"/#wMvpDZzOZNVcEcc0d62yn"},"label":{"value":"Test"}}}"##,
        )
        .unwrap();
        // DifferenceExtractor.extract(ovr, base) asks the existing value: base.extractDifference(ovr).
        let diff = component_extract(&ovr, &base).unwrap();
        let diff = diff.as_object().unwrap();
        assert_eq!(diff["properties"], parse(br#"{"label":{"value":"Test"}}"#).unwrap());
        assert_eq!(diff["displayOrder"], JValue::Int(4));
        assert!(diff["name"].is_null());
    }

    #[test]
    fn component_extract_keeps_the_java_quirks() {
        let base = parse(br#"{"name":"Old","type":"A","bindingPath2":{"value":"x"},"children":{"a":true}}"#).unwrap();
        let inc = parse(br#"{"name":"New","type":"B","bindingPath2":{"value":"y"},"children":{"a":false}}"#).unwrap();
        let d = component_extract(&inc, &base).unwrap();
        let d = d.as_object().unwrap();
        assert_eq!(d["name"], JValue::Str("Old".into()), "Java records the existing name");
        assert_eq!(d["type"], JValue::Str("A".into()));
        assert_eq!(d["bindingPath"], parse(br#"{"value":"y"}"#).unwrap(), "every path lands in bindingPath");
        assert!(d["bindingPath2"].is_null());
        assert_eq!(d["children"], parse(br#"{"a":false}"#).unwrap());
        assert_eq!(component_extract(&JValue::Int(1), &base), Some(JValue::Int(1)));
        assert_eq!(component_apply(&JValue::Int(1), None), Some(JValue::Int(1)));
    }

    #[test]
    fn component_deferral() {
        let a = parse(br#"{"properties":{"x":1}}"#).unwrap();
        let b = parse(br#"{"properties":{"y":1}}"#).unwrap();
        let e = parse(br#"{"properties":{}}"#).unwrap();
        assert!(component_deferred(&a, &b));
        assert!(!component_deferred(&a, &e));
        assert!(!component_deferred(&JValue::Int(1), &b));
    }

    #[test]
    fn every_class_names_itself_like_java() {
        let docs: Vec<(&dyn DocType, &str, &str, &str)> = vec![
            (&PageDoc, "Page", "page", "PageCache_a_n"),
            (&ApplicationDoc, "Application", "application", "ApplicationCache_a_n"),
            (&StyleDoc, "Style", "style", "StyleCache_a_n"),
            (&ThemeDoc, "Theme", "theme", "ThemeCache_a_n"),
            (&FunctionDoc, "Function", "function", "UIFunctionCache_a_n"),
            (&SchemaDoc, "Schema", "schema", "UISchemaCache_a_n"),
            (&FillerDoc, "Filler", "filler", "UIFillerCache_a_n"),
        ];
        for (d, name, coll, cache) in docs {
            assert_eq!(d.object_name(), name);
            assert_eq!(d.collection(), coll);
            assert_eq!(d.cache_name("a", "n"), cache);
            assert!(d.pojo().fields().count() > 17);
        }
        assert_eq!(PERSONALIZATION.fields().count(), 18);
    }

    #[test]
    fn each_class_merges_and_extracts_its_own_fields() {
        let base = obj(r#"{"translations":{"en":{"a":"A"}},"languages":{"en":{"n":"English"}},"properties":{"p":1},
            "defaultLanguage":"en","variables":{"ALL":{"c":"red"}},"definition":{"d":1},"values":{"v":1},
            "executeAuth":"X","eventFunctions":{"f":{"x":1}},"rootComponent":"r","styleString":"s"}"#);
        let mine = obj(r#"{"translations":{"en":{"b":"B"}},"properties":{"q":2},"variables":{"ALL":{"d":"blue"}},
            "definition":{"e":2},"values":{"w":2},"eventFunctions":{"g":{"y":1}}}"#);
        let app = ApplicationDoc.apply_override(mine.clone(), &base).unwrap();
        assert_eq!(app["defaultLanguage"], JValue::Str("en".into()));
        assert_eq!(app["properties"].as_object().unwrap().len(), 2);
        let back = ApplicationDoc.extract_difference(app, &base).unwrap();
        assert_eq!(back["properties"], parse(br#"{"q":2}"#).unwrap());
        assert!(back["defaultLanguage"].is_null());
        let th = ThemeDoc.apply_override(mine.clone(), &base).unwrap();
        assert_eq!(th["variables"].as_object().unwrap()["ALL"].as_object().unwrap().len(), 2);
        assert!(ThemeDoc.extract_difference(th, &base).is_some());
        let st = StyleDoc.apply_override(mine.clone(), &base).unwrap();
        assert!(st.get("styleString").is_none());
        let f = FunctionDoc.apply_override(mine.clone(), &base).unwrap();
        assert_eq!(f["executeAuth"], JValue::Str("X".into()));
        let f = FunctionDoc.extract_difference(f, &base).unwrap();
        assert!(f["executeAuth"].is_null());
        assert_eq!(f["definition"], parse(br#"{"e":2}"#).unwrap());
        let s = SchemaDoc.apply_override(mine.clone(), &base).unwrap();
        assert_eq!(s["definition"].as_object().unwrap().len(), 2);
        assert!(SchemaDoc.extract_difference(s, &base).is_some());
        let fi = FillerDoc.apply_override(mine.clone(), &base).unwrap();
        assert_eq!(fi["values"].as_object().unwrap().len(), 2);
        assert!(FillerDoc.extract_difference(fi, &base).is_some());
        assert!(FillerDoc.apply_override(obj("{}"), &obj("{}")).is_none());
        assert!(SchemaDoc.apply_override(obj("{}"), &obj("{}")).is_none());
        let p = PageDoc.apply_override(mine, &base).unwrap();
        assert_eq!(p["rootComponent"], JValue::Str("r".into()));
        let pd = PageDoc.extract_difference(p, &base).unwrap();
        assert!(pd["rootComponent"].is_null());
        assert_eq!(pd["eventFunctions"], parse(br#"{"g":{"y":1}}"#).unwrap());
    }

}
