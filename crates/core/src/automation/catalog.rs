//! What an automation can start on and what it can do, in an app: the catalog the editor and
//! the AI agent draw from.
//!
//! An app declares, and writes no engine code:
//!
//! - a **trigger** with an `automation` block on an EventDefinition. The trigger's key is the
//!   event's name. A storage event (`Storage.<name>.Create`, ...) needs an EventDefinition of
//!   that name to be raised at all, so a storage trigger is declared the same way.
//! - an **action** with an `automation` block on a server function. The action's key is the
//!   function's `namespace.name`. Any server function can be one.
//!
//! The block (every part optional):
//!
//! ```text
//! title, sentence, description, category
//! trigger only: subject ("deal"), subjectPath ("dealId"), fields [ { name, label, type, options } ]
//! action only:  params [ { name, label, type, required, options, variables } ], outputs [ { name, label, type } ],
//!               idempotent
//! ```
//!
//! An action without `params` takes its function's parameters, labelled by name. `options`
//! names a server function (`{namespace, name}`) the editor calls itself for a picker's choices.
//!
//! Built-in actions ([`built_in`]) are the engine's own, so a site app with no functions of its
//! own can still send an email or a notification, or call a webhook. Their keys start with
//! `core:`. A built-in param may carry `choices` (`[{label, value}]`), a fixed list the editor
//! offers as it is (the app's notifications, say).

use overridable::pojo::{map_field, str_field};
use overridable::{JMap, JValue};

/// The prefix of a built-in action's key; a function's `namespace.name` never has a colon.
pub const BUILT_IN_PREFIX: &str = "core:";
pub const SEND_EMAIL: &str = "core:sendEmail";
pub const POST_WEBHOOK: &str = "core:postWebhook";
pub const RAISE_EVENT: &str = "core:raiseEvent";
pub const SEND_NOTIFICATION: &str = "core:sendNotification";

/// The block's field on an EventDefinition and on a function.
pub const BLOCK: &str = "automation";

fn s(v: &str) -> JValue {
    JValue::Str(v.to_string())
}

fn obj(pairs: &[(&str, JValue)]) -> JValue {
    JValue::Object(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
}

fn param(name: &str, label: &str, ty: &str, required: bool) -> JValue {
    obj(&[("name", s(name)), ("label", s(label)), ("type", s(ty)), ("required", JValue::Bool(required)), ("variables", JValue::Bool(true))])
}

/// `param` with a fixed list to pick from, and no variables.
fn choice_param(name: &str, label: &str, ty: &str, required: bool, choices: Vec<JValue>) -> JValue {
    let mut p = param(name, label, ty, required);
    if let JValue::Object(m) = &mut p {
        m.insert("variables".into(), JValue::Bool(false));
        m.insert("choices".into(), JValue::Array(choices));
    }
    p
}

/// The app's notifications as choices: `{label, value}`, the value being the name.
pub fn notification_choices(notifications: &[JMap]) -> Vec<JValue> {
    let mut out: Vec<(String, JValue)> = notifications
        .iter()
        .filter_map(|n| {
            let name = text(n, "name")?;
            let label = text(n, "title").or_else(|| text(n, "description")).unwrap_or(name);
            Some((label.to_lowercase(), obj(&[("label", s(label)), ("value", s(name))])))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.1 == b.1);
    out.into_iter().map(|(_, v)| v).collect()
}

/// The engine's own actions. `notifications` are the app's, offered by "Send a notification".
pub fn built_in(notifications: &[JMap]) -> Vec<JValue> {
    let action = |key: &str, title: &str, sentence: &str, params: Vec<JValue>, outputs: Vec<JValue>| {
        obj(&[
            ("key", s(key)),
            ("title", s(title)),
            ("sentence", s(sentence)),
            ("builtIn", JValue::Bool(true)),
            ("category", s("General")),
            ("params", JValue::Array(params)),
            ("outputs", JValue::Array(outputs)),
            ("idempotent", JValue::Bool(false)),
        ])
    };
    vec![
        action(
            SEND_EMAIL,
            "Send an email",
            "send the email {template} to {to}",
            vec![
                param("to", "To", "STRING", true),
                param("template", "Email template", "TEMPLATE", true),
                param("connectionName", "Send with", "CONNECTION", false),
                param("data", "Values for the template", "OBJECT", false),
            ],
            vec![obj(&[("name", s("sent")), ("label", s("Sent")), ("type", s("BOOLEAN"))])],
        ),
        action(
            POST_WEBHOOK,
            "Post to a webhook",
            "post the details to {url}",
            vec![param("url", "Address", "URL", true), param("body", "What to send", "OBJECT", false)],
            vec![
                obj(&[("name", s("status")), ("label", s("Answer code")), ("type", s("INTEGER"))]),
                obj(&[("name", s("body")), ("label", s("Answer")), ("type", s("OBJECT"))]),
            ],
        ),
        action(
            RAISE_EVENT,
            "Raise an event",
            "raise the event {eventName}",
            vec![param("eventName", "Event", "EVENT", true), param("data", "Details", "OBJECT", false)],
            vec![],
        ),
        action(
            SEND_NOTIFICATION,
            "Send a notification",
            "send the notification {notification}",
            vec![
                choice_param("notification", "Notification", "NOTIFICATION", true, notification_choices(notifications)),
                param("to", "To these people (user ids)", "USER", false),
                param("everyone", "Or everyone in the business", "BOOLEAN", false),
                param("onlyWith", "Only those who hold (authority)", "AUTHORITY", false),
                param("data", "Values for the message", "OBJECT", false),
            ],
            vec![
                obj(&[("name", s("sent")), ("label", s("Sent")), ("type", s("BOOLEAN"))]),
                obj(&[("name", s("count")), ("label", s("Sent to")), ("type", s("INTEGER"))]),
            ],
        ),
    ]
}

/// The block, when the document has one that is an object.
pub fn block(doc: &JMap) -> Option<&JMap> {
    map_field(doc, BLOCK)
}

fn text<'a>(m: &'a JMap, field: &str) -> Option<&'a str> {
    str_field(m, field).map(str::trim).filter(|t| !t.is_empty())
}

fn copy(out: &mut JMap, from: &JMap, fields: &[&str]) {
    for f in fields {
        if let Some(v) = from.get(*f).filter(|v| !v.is_null()) {
            out.insert(f.to_string(), v.clone());
        }
    }
}

fn heading(out: &mut JMap, doc: &JMap, b: &JMap, key: &str) {
    let title = text(b, "title").or_else(|| text(doc, "title")).unwrap_or(key).to_string();
    let sentence = text(b, "sentence").map(str::to_string).unwrap_or_else(|| title.to_lowercase());
    out.insert("title".into(), JValue::Str(title));
    out.insert("sentence".into(), JValue::Str(sentence));
    if let Some(d) = text(b, "description").or_else(|| text(doc, "description")) {
        out.insert("description".into(), s(d));
    }
}

/// An EventDefinition as a trigger, when it carries the block.
pub fn trigger(def: &JMap) -> Option<JValue> {
    let b = block(def)?;
    let key = text(def, "name")?;
    let mut out = JMap::new();
    out.insert("key".into(), s(key));
    heading(&mut out, def, b, key);
    copy(&mut out, b, &["category", "subject", "subjectPath"]);
    out.insert("fields".into(), b.get("fields").filter(|v| matches!(v, JValue::Array(_))).cloned().unwrap_or(JValue::Array(vec![])));
    Some(JValue::Object(out))
}

/// The parameters a function's definition declares, as action params.
fn params_of_definition(func: &JMap) -> Vec<JValue> {
    let Some(params) = map_field(func, "definition").and_then(|d| map_field(d, "parameters")) else { return vec![] };
    params
        .iter()
        .map(|(name, p)| {
            let ty = p
                .as_object()
                .and_then(|p| map_field(p, "schema"))
                .and_then(|sc| sc.get("type"))
                .map(|t| match t {
                    JValue::Array(a) => a.first().map(JValue::java_to_string).unwrap_or_default(),
                    other => other.java_to_string(),
                })
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| "ANY".into());
            param(name, name, &ty, false)
        })
        .collect()
}

/// A server function as an action, when it carries the block.
pub fn action(func: &JMap) -> Option<JValue> {
    let b = block(func)?;
    let key = text(func, "name")?;
    let mut out = JMap::new();
    out.insert("key".into(), s(key));
    heading(&mut out, func, b, key);
    out.insert("builtIn".into(), JValue::Bool(false));
    copy(&mut out, b, &["category"]);
    let params = match b.get("params") {
        Some(JValue::Array(p)) => JValue::Array(p.clone()),
        _ => JValue::Array(params_of_definition(func)),
    };
    out.insert("params".into(), params);
    out.insert("outputs".into(), b.get("outputs").filter(|v| matches!(v, JValue::Array(_))).cloned().unwrap_or(JValue::Array(vec![])));
    out.insert("idempotent".into(), JValue::Bool(b.get("idempotent").and_then(JValue::as_bool).unwrap_or(false)));
    Some(JValue::Object(out))
}

/// Any server function as a step, for a builder (who can write functions anyway): the
/// declared action when the function carries the block, else the function itself with its
/// own parameters, `"offered": false` (tenants' editors never list it, and only a builder may
/// save a step that runs it, see [`crate::automation::guard`]).
pub fn function_step(func: &JMap) -> Option<JValue> {
    if let Some(JValue::Object(mut a)) = action(func) {
        a.insert("offered".into(), JValue::Bool(true));
        return Some(JValue::Object(a));
    }
    let key = text(func, "name")?;
    let short = key.rsplit_once('.').map(|(_, n)| n).unwrap_or(key);
    let mut out = JMap::new();
    out.insert("key".into(), s(key));
    out.insert("title".into(), s(key));
    out.insert("sentence".into(), JValue::Str(format!("run the function {short}")));
    if let Some(d) = map_field(func, "definition").and_then(|d| text(d, "description")).or_else(|| text(func, "description")) {
        out.insert("description".into(), s(d));
    }
    out.insert("builtIn".into(), JValue::Bool(false));
    out.insert("offered".into(), JValue::Bool(false));
    out.insert("category".into(), s("App functions (builders only)"));
    out.insert("params".into(), JValue::Array(params_of_definition(func)));
    out.insert("outputs".into(), JValue::Array(vec![]));
    out.insert("idempotent".into(), JValue::Bool(false));
    Some(JValue::Object(out))
}

/// Adds every function of `functions` the catalog does not list yet ([`function_step`]),
/// after the declared actions, by key.
pub fn add_function_steps(catalog: &mut JValue, functions: &[JMap]) {
    let Some(JValue::Array(actions)) = catalog.as_object_mut().and_then(|c| c.get_mut("actions")) else { return };
    let listed: std::collections::BTreeSet<String> =
        actions.iter().filter_map(|a| a.as_object().and_then(|m| str_field(m, "key")).map(str::to_string)).collect();
    let mut more: Vec<(String, JValue)> = functions
        .iter()
        .filter_map(function_step)
        .filter_map(|a| a.as_object().and_then(|m| str_field(m, "key")).map(|k| (k.to_string(), a.clone())))
        .filter(|(k, _)| !listed.contains(k))
        .collect();
    more.sort_by(|a, b| a.0.cmp(&b.0));
    more.dedup_by(|a, b| a.0 == b.0);
    actions.extend(more.into_iter().map(|(_, a)| a));
}

/// A storage as the trigger "a new entry is added": key `Storage.<name>.Create`, the entry's
/// fields under `dataObject`, as core raises the storage event. Saving an automation on it
/// switches the storage's events on ([`crate::automation::storage_trigger`]).
pub fn storage_trigger(storage: &JMap) -> Option<JValue> {
    let name = text(storage, "name")?;
    let b = block(storage);
    let label = b.and_then(|b| text(b, "title")).or_else(|| text(storage, "title")).unwrap_or(name).to_string();
    let empty = JMap::new();
    let props = map_field(storage, "schema").and_then(|sc| map_field(sc, "properties")).unwrap_or(&empty);
    let fields: Vec<JValue> = props
        .iter()
        .map(|(f, p)| {
            let ty = p.as_object().and_then(|p| p.get("type")).map(JValue::java_to_string).unwrap_or_else(|| "STRING".into());
            obj(&[("name", JValue::Str(format!("dataObject.{f}"))), ("label", s(f)), ("type", JValue::Str(ty.trim_matches(['[', ']', '"']).to_string()))])
        })
        .collect();
    let mut out = JMap::new();
    out.insert("key".into(), JValue::Str(format!("Storage.{name}.Create")));
    out.insert("title".into(), JValue::Str(format!("New entry in {label}")));
    out.insert("sentence".into(), JValue::Str(format!("a new entry is added to {label}")));
    out.insert("category".into(), s("Forms and data"));
    out.insert("subject".into(), s("entry"));
    out.insert("subjectPath".into(), s("dataObject._id"));
    out.insert("storage".into(), s(name));
    out.insert("fields".into(), JValue::Array(fields));
    Some(JValue::Object(out))
}

/// `{ appCode, triggers, actions }`, each list sorted by title. The built-in actions come first.
/// A storage trigger an event definition already declares is not listed twice.
pub fn catalog(app: &str, event_definitions: &[JMap], functions: &[JMap], storages: &[JMap], notifications: &[JMap]) -> JValue {
    let by_title = |mut l: Vec<JValue>| {
        l.sort_by_key(|v| v.as_object().and_then(|m| str_field(m, "title")).unwrap_or("").to_lowercase());
        l
    };
    let mut declared: Vec<JValue> = event_definitions.iter().filter_map(trigger).collect();
    let keys: Vec<String> = declared.iter().filter_map(|t| t.as_object().and_then(|m| str_field(m, "key")).map(str::to_string)).collect();
    declared.extend(
        storages
            .iter()
            .filter_map(storage_trigger)
            .filter(|t| t.as_object().and_then(|m| str_field(m, "key")).is_some_and(|k| !keys.iter().any(|d| d == k))),
    );
    let triggers = by_title(declared);
    let mut actions = built_in(notifications);
    actions.extend(by_title(functions.iter().filter_map(action).collect()));
    obj(&[("appCode", s(app)), ("triggers", JValue::Array(triggers)), ("actions", JValue::Array(actions))])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> JMap {
        match overridable::json::parse(text.as_bytes()).expect("json") {
            JValue::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    fn get<'a>(v: &'a JValue, k: &str) -> &'a JValue {
        &v.as_object().expect("object")[k]
    }

    #[test]
    fn a_trigger_from_an_event_definition() {
        let t = trigger(&doc(
            r#"{"name":"LZ_DEAL_CREATED","title":"Deal created","automation":{"sentence":"a deal is created","subject":"deal","subjectPath":"dealId",
                "fields":[{"name":"productId","label":"Product","type":"STRING","options":{"namespace":"LeadZumpV2","name":"productOptions"}}]}}"#,
        ))
        .unwrap();
        assert_eq!(get(&t, "key").as_str(), Some("LZ_DEAL_CREATED"));
        assert_eq!(get(&t, "title").as_str(), Some("Deal created"));
        assert_eq!(get(&t, "sentence").as_str(), Some("a deal is created"));
        assert_eq!(get(&t, "subjectPath").as_str(), Some("dealId"));
        assert!(matches!(get(&t, "fields"), JValue::Array(f) if f.len() == 1));

        // No block, no trigger; a bare block takes its words from the definition.
        assert!(trigger(&doc(r#"{"name":"X"}"#)).is_none());
        assert!(trigger(&doc(r#"{"name":"X","automation":null}"#)).is_none());
        let bare = trigger(&doc(r#"{"name":"Storage.contactForm.Create","automation":{}}"#)).unwrap();
        assert_eq!(get(&bare, "title").as_str(), Some("Storage.contactForm.Create"));
        assert!(matches!(get(&bare, "fields"), JValue::Array(f) if f.is_empty()));
    }

    #[test]
    fn an_action_from_a_function() {
        let declared = action(&doc(
            r#"{"name":"LeadZumpV2.whatsappTemplateSend","automation":{"title":"Send WhatsApp template","sentence":"send the WhatsApp template {template}",
                "params":[{"name":"template","label":"Template","required":true}],"outputs":[{"name":"messageId"}],"idempotent":true}}"#,
        ))
        .unwrap();
        assert_eq!(get(&declared, "key").as_str(), Some("LeadZumpV2.whatsappTemplateSend"));
        assert_eq!(get(&declared, "builtIn").as_bool(), Some(false));
        assert_eq!(get(&declared, "idempotent").as_bool(), Some(true));
        assert!(matches!(get(&declared, "params"), JValue::Array(p) if p.len() == 1));

        // No params listed: the function's own parameters, by name.
        let derived = action(&doc(
            r#"{"name":"Ns.notify","title":"Notify","definition":{"parameters":{"userId":{"schema":{"type":["STRING"]}},"text":{"schema":{"type":"STRING"}},"any":{}}},"automation":{}}"#,
        ))
        .unwrap();
        assert_eq!(get(&derived, "sentence").as_str(), Some("notify"));
        let names: Vec<String> = match get(&derived, "params") {
            JValue::Array(p) => p.iter().map(|x| format!("{}:{}", get(x, "name").as_str().unwrap(), get(x, "type").as_str().unwrap())).collect(),
            _ => panic!(),
        };
        assert_eq!(names, vec!["userId:STRING", "text:STRING", "any:ANY"]);
        assert!(action(&doc(r#"{"name":"Ns.plain","definition":{}}"#)).is_none());
    }

    #[test]
    fn a_storage_as_a_trigger() {
        let t = storage_trigger(&doc(
            r#"{"name":"contactForm","title":"Contact form","schema":{"type":"OBJECT","properties":{"email":{"type":"STRING"},"age":{"type":["INTEGER"]}}}}"#,
        ))
        .unwrap();
        assert_eq!(get(&t, "key").as_str(), Some("Storage.contactForm.Create"));
        assert_eq!(get(&t, "sentence").as_str(), Some("a new entry is added to Contact form"));
        let fields: Vec<String> = match get(&t, "fields") {
            JValue::Array(f) => f.iter().map(|x| format!("{}:{}", get(x, "name").as_str().unwrap(), get(x, "type").as_str().unwrap())).collect(),
            _ => panic!(),
        };
        assert_eq!(fields, vec!["dataObject.email:STRING", "dataObject.age:INTEGER"]);
        // An event definition that declares the same storage event wins.
        let c = catalog("site", &[doc(r#"{"name":"Storage.contactForm.Create","automation":{"title":"Contact form sent"}}"#)], &[], &[doc(r#"{"name":"contactForm"}"#)], &[]);
        match get(&c, "triggers") {
            JValue::Array(l) => assert_eq!(l.len(), 1),
            _ => panic!(),
        }
    }

    #[test]
    fn the_catalog_lists_built_ins_first() {
        let c = catalog(
            "leadzumptwo",
            &[doc(r#"{"name":"B","automation":{"title":"b event"}}"#), doc(r#"{"name":"A","automation":{"title":"A event"}}"#), doc(r#"{"name":"C"}"#)],
            &[doc(r#"{"name":"Ns.z","automation":{"title":"Zed"}}"#), doc(r#"{"name":"Ns.a","automation":{"title":"Ay"}}"#)],
            &[],
            &[doc(r#"{"name":"dealAssigned","description":"Deal assigned to you"}"#), doc(r#"{"name":"aRaw"}"#)],
        );
        let keys = |k: &str| match get(&c, k) {
            JValue::Array(l) => l.iter().map(|x| get(x, "key").as_str().unwrap().to_string()).collect::<Vec<_>>(),
            _ => panic!(),
        };
        assert_eq!(keys("triggers"), vec!["A", "B"]);
        assert_eq!(keys("actions"), vec![SEND_EMAIL, POST_WEBHOOK, RAISE_EVENT, SEND_NOTIFICATION, "Ns.a", "Ns.z"]);
        assert!(keys("actions").iter().all(|k| !k.starts_with(BUILT_IN_PREFIX) || built_in(&[]).iter().any(|b| get(b, "key").as_str() == Some(k))));
        // The notification picker offers the app's notifications, by their words, sorted.
        let JValue::Array(actions) = get(&c, "actions") else { panic!() };
        let notify = actions.iter().find(|a| get(a, "key").as_str() == Some(SEND_NOTIFICATION)).unwrap();
        let JValue::Array(params) = get(notify, "params") else { panic!() };
        let JValue::Array(choices) = get(&params[0], "choices") else { panic!() };
        let picked: Vec<(String, String)> = choices.iter().map(|c| (get(c, "label").as_str().unwrap().into(), get(c, "value").as_str().unwrap().into())).collect();
        assert_eq!(picked, vec![("aRaw".into(), "aRaw".into()), ("Deal assigned to you".into(), "dealAssigned".into())]);
        assert_eq!(get(&params[0], "variables").as_bool(), Some(false));

        // A builder's catalog adds every other function, with its own parameters.
        let mut c = c;
        add_function_steps(&mut c, &[
            doc(r#"{"name":"Ns.a","automation":{"title":"Ay"}}"#),
            doc(r#"{"name":"Mine.notifyTeam","definition":{"description":"Tells the team","parameters":{"dealId":{"schema":{"type":"STRING"}}}}}"#),
        ]);
        let JValue::Array(actions) = get(&c, "actions") else { panic!() };
        let keys: Vec<&str> = actions.iter().map(|a| get(a, "key").as_str().unwrap()).collect();
        assert_eq!(keys.iter().filter(|k| **k == "Ns.a").count(), 1, "a declared action is not listed twice");
        let mine = actions.iter().find(|a| get(a, "key").as_str() == Some("Mine.notifyTeam")).unwrap();
        assert_eq!(get(mine, "offered").as_bool(), Some(false));
        assert_eq!(get(mine, "sentence").as_str(), Some("run the function notifyTeam"));
        assert_eq!(get(mine, "description").as_str(), Some("Tells the team"));
        let JValue::Array(p) = get(mine, "params") else { panic!() };
        assert_eq!(get(&p[0], "name").as_str(), Some("dealId"));
    }
}
