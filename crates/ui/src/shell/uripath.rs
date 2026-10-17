//! `URIPathService` at request time: the URI path document and its nested models, finding the
//! route for a request, and running its KIRun function through the core service.
//!
//! A route is a `uri_path` document whose `name` is an Ant pattern (`/api/open/x/**`) and whose
//! `pathDefinitions` say, per HTTP method, which function to run and how to build its
//! arguments (path variables of `pathString`, query parameters, headers, the JSON body) and
//! how to answer (an output event's result, or an error event's status and body).

use std::collections::HashMap;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use mongodb::bson::doc;
use overridable::difference::{apply_map, apply_map_with, apply_value, extract_map, extract_map_with, extract_value};
use overridable::pojo::{map_field, str_field, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use overridable::{java_map, DocType, JMap, JValue};
use platform::error::AppError;

use crate::authority::has_authority;
use crate::shell::gson::{self, G};
use crate::shell::paths::{ant_match, PathPattern};

/// `com.fincity.saas.ui.model.PathDefinition`: the nested definitions are kept as the stored
/// maps (its copy constructor copies them by reference).
pub const PATH_DEFINITION: Pojo = Pojo {
    name: "PathDefinition",
    parts: &[&[
        Field::new("uriType", K::Str, C::Copy),
        Field::new("headers", K::Object, C::Copy),
        Field::new("whitelist", K::Object, C::Copy),
        Field::new("blacklist", K::Object, C::Copy),
        Field::new("referrer", K::Object, C::Copy),
        Field::new("kiRunFxDefinition", K::Object, C::Copy),
        Field::new("redirectionDefinition", K::Object, C::Copy),
    ]],
};

/// `com.fincity.saas.ui.document.URIPath`.
pub const URI_PATH: Pojo = Pojo {
    name: "URIPath",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("pathString", K::Str, C::Copy),
            Field::new("shortCode", K::Str, C::Copy),
            Field::new("pathDefinitions", K::MapPojo(&PATH_DEFINITION), C::MapObject),
        ],
    ],
};

pub struct UriPathDoc;

impl DocType for UriPathDoc {
    fn object_name(&self) -> &'static str {
        "URIPath"
    }
    fn collection(&self) -> &'static str {
        "uri_path"
    }
    fn pojo(&self) -> &'static Pojo {
        &URI_PATH
    }
    /// `URIPathService.getCacheName`: `URIPathCache_<app>_URICache_<app><name>`.
    fn cache_name(&self, app_code: &str, name: &str) -> String {
        format!("URIPathCache_{app_code}_URICache_{app_code}{name}")
    }
    /// `URIPath.applyOverride(base)`.
    fn apply_override(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let pd = apply_map_with(map_field(&this, "pathDefinitions"), map_field(base, "pathDefinitions"), &|o, b| {
            path_definition_apply(o, b)
        });
        this.insert("pathDefinitions".into(), pd.map(JValue::Object).unwrap_or(JValue::Null));
        for f in ["pathString", "shortCode"] {
            if this.get(f).is_none_or(JValue::is_null) {
                this.insert(f.into(), base.get(f).cloned().unwrap_or(JValue::Null));
            }
        }
        Some(this)
    }
    /// `URIPath.extractDifference(base)`.
    fn extract_difference(&self, mut this: JMap, base: &JMap) -> Option<JMap> {
        let pd = extract_map_with(map_field(&this, "pathDefinitions"), map_field(base, "pathDefinitions"), &|inc, existing| {
            path_definition_extract(existing, inc)
        });
        this.insert("pathDefinitions".into(), JValue::Object(pd));
        for f in ["pathString", "shortCode"] {
            if this.get(f).is_some_and(|v| !v.is_null()) && this.get(f) == base.get(f) {
                this.insert(f.into(), JValue::Null);
            }
        }
        Some(this)
    }
}

fn obj(v: Option<&JValue>) -> Option<&JMap> {
    v.and_then(JValue::as_object)
}

fn nn(v: Option<&JValue>) -> Option<&JValue> {
    v.filter(|x| !x.is_null())
}

/// Fills the delta's null fields from the base (`applyOverride` of the nested models).
fn fill_from(this: &mut JMap, base: &JMap, fields: &[&str]) {
    for f in fields {
        if this.get(*f).is_none_or(JValue::is_null) {
            this.insert(f.to_string(), base.get(*f).cloned().unwrap_or(JValue::Null));
        }
    }
}

/// Records the incoming value of each field that differs from the base.
fn changed_scalars(diff: &mut JMap, base: &JMap, inc: &JMap, fields: &[&str]) {
    for f in fields {
        let (b, i) = (base.get(*f).unwrap_or(&JValue::Null), inc.get(*f).unwrap_or(&JValue::Null));
        diff.insert(f.to_string(), if b == i { JValue::Null } else { i.clone() });
    }
}

const KIRUN_MAPS: [&str; 3] = ["headersMapping", "pathParamMapping", "queryParamMapping"];
const KIRUN_SCALARS: [&str; 6] =
    ["name", "namespace", "functionAppCode", "outputEventName", "outputEventParamName", "errorEventName"];
const REDIRECTION_SCALARS: [&str; 5] = ["redirectionType", "targetHttpMethod", "targetUrl", "validFrom", "validUntil"];
const PATH_LISTS: [&str; 4] = ["headers", "whitelist", "blacklist", "referrer"];

/// `KIRunFxDefinition.applyOverride(base)`, `this` being the delta.
pub fn kirun_apply(this: &JValue, base: Option<&JValue>) -> Option<JValue> {
    let (Some(t), Some(b)) = (this.as_object(), obj(base)) else { return Some(this.clone()) };
    let mut out = t.clone();
    for f in KIRUN_MAPS {
        let m = apply_map(map_field(t, f), map_field(b, f));
        out.insert(f.into(), m.map(JValue::Object).unwrap_or(JValue::Null));
    }
    fill_from(&mut out, b, &KIRUN_SCALARS);
    Some(JValue::Object(out))
}

/// `KIRunFxDefinition.extractDifference(inc)`, `base` being the receiver.
pub fn kirun_extract(base: &JValue, inc: &JValue) -> Option<JValue> {
    let (Some(b), Some(i)) = (base.as_object(), inc.as_object()) else { return Some(inc.clone()) };
    let mut diff = JMap::new();
    for f in KIRUN_MAPS {
        diff.insert(f.into(), JValue::Object(extract_map(map_field(i, f), map_field(b, f))));
    }
    changed_scalars(&mut diff, b, i, &KIRUN_SCALARS);
    Some(JValue::Object(diff))
}

/// `RedirectionDefinition.applyOverride(base)`.
pub fn redirection_apply(this: &JValue, base: Option<&JValue>) -> Option<JValue> {
    let (Some(t), Some(b)) = (this.as_object(), obj(base)) else { return Some(this.clone()) };
    let mut out = t.clone();
    fill_from(&mut out, b, &REDIRECTION_SCALARS);
    Some(JValue::Object(out))
}

/// `RedirectionDefinition.extractDifference(inc)`.
pub fn redirection_extract(base: &JValue, inc: &JValue) -> Option<JValue> {
    let (Some(b), Some(i)) = (base.as_object(), inc.as_object()) else { return Some(inc.clone()) };
    let mut diff = JMap::new();
    changed_scalars(&mut diff, b, i, &REDIRECTION_SCALARS);
    Some(JValue::Object(diff))
}

/// `DifferenceApplicator.apply(override, base)` reaching a nested model: a null override is
/// nothing (the base is not kept), otherwise the model's own `applyOverride`.
fn typed_apply(o: Option<&JValue>, b: Option<&JValue>, f: fn(&JValue, Option<&JValue>) -> Option<JValue>) -> JValue {
    match nn(o) {
        None => JValue::Null,
        Some(o) => f(o, nn(b)).unwrap_or(JValue::Null),
    }
}

/// `DifferenceExtractor.extract(incoming, existing)` reaching a nested model.
fn typed_extract(inc: Option<&JValue>, existing: Option<&JValue>, f: fn(&JValue, &JValue) -> Option<JValue>) -> JValue {
    match (nn(inc), nn(existing)) {
        (None, None) => JValue::Null,
        (Some(i), None) => i.clone(),
        // JsonNull in Java, which the model's setter cannot take; null is what it means.
        (None, Some(_)) => JValue::Null,
        (Some(i), Some(e)) if i == e => JValue::Null,
        (Some(i), Some(e)) => f(e, i).unwrap_or(JValue::Null),
    }
}

/// `PathDefinition.applyOverride(base)`, `this` being the delta.
pub fn path_definition_apply(this: &JValue, base: Option<&JValue>) -> Option<JValue> {
    let (Some(t), Some(b)) = (this.as_object(), obj(base)) else { return Some(this.clone()) };
    let mut out = t.clone();
    for f in PATH_LISTS {
        out.insert(f.into(), apply_value(nn(t.get(f)), b.get(f)).unwrap_or(JValue::Null));
    }
    out.insert("kiRunFxDefinition".into(), typed_apply(t.get("kiRunFxDefinition"), b.get("kiRunFxDefinition"), kirun_apply));
    out.insert(
        "redirectionDefinition".into(),
        typed_apply(t.get("redirectionDefinition"), b.get("redirectionDefinition"), redirection_apply),
    );
    fill_from(&mut out, b, &["uriType"]);
    Some(JValue::Object(out))
}

/// `PathDefinition.extractDifference(inc)`, `base` being the receiver.
pub fn path_definition_extract(base: &JValue, inc: &JValue) -> Option<JValue> {
    let (Some(b), Some(i)) = (base.as_object(), inc.as_object()) else { return Some(inc.clone()) };
    let mut diff = JMap::new();
    diff.insert("uriType".into(), JValue::Null);
    for f in PATH_LISTS {
        let d = extract_value(i.get(f), b.get(f)).filter(|v| !v.is_null()).unwrap_or(JValue::Null);
        diff.insert(f.into(), d);
    }
    diff.insert("kiRunFxDefinition".into(), typed_extract(i.get("kiRunFxDefinition"), b.get("kiRunFxDefinition"), kirun_extract));
    diff.insert(
        "redirectionDefinition".into(),
        typed_extract(i.get("redirectionDefinition"), b.get("redirectionDefinition"), redirection_extract),
    );
    if b.get("uriType") != i.get("uriType") {
        diff.insert("uriType".into(), i.get("uriType").cloned().unwrap_or(JValue::Null));
    }
    Some(JValue::Object(diff))
}

/// The parts of the request a route reads.
#[derive(Debug, Clone, Default)]
pub struct RouteRequest {
    /// `GET`, `POST`, ...
    pub method: String,
    /// `request.getURI().getPath()`: the path, percent-decoded.
    pub path: String,
    /// `request.getQueryParams()`, in order (a parameter with no `=` has no value).
    pub query: Vec<(String, Option<String>)>,
    /// The request headers in order, names as the Java ui would see them.
    pub headers: Vec<(String, String)>,
}

impl RouteRequest {
    fn query_first(&self, key: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == key).and_then(|(_, v)| v.as_deref())
    }

    fn header_first(&self, key: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }
}

/// Spring's `LinkedMultiValueMap<String, String>`: keys in first-added order.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MultiValue(pub Vec<(String, Vec<Option<String>>)>);

impl MultiValue {
    pub fn add(&mut self, key: &str, value: Option<String>) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, vs)) => vs.push(value),
            None => self.0.push((key.to_string(), vec![value])),
        }
    }

    pub fn set(&mut self, key: &str, value: Option<String>) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, vs)) => *vs = vec![value],
            None => self.0.push((key.to_string(), vec![value])),
        }
    }
}

fn string_map(def: &JMap, field: &str) -> Vec<(String, String)> {
    map_field(def, field)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.java_to_string())).collect())
        .unwrap_or_default()
}

/// The `pathString` variables of the request path, in `HashMap` order.
fn path_variables(path_string: &str, path: &str) -> Option<JMap> {
    let pattern = PathPattern::parse(path_string).ok()?;
    let vars: HashMap<String, String> = pattern.match_and_extract(path)?;
    let m: JMap = vars.into_iter().map(|(k, v)| (k, JValue::Str(v))).collect();
    Some(java_map::by_puts(m))
}

/// `getParamsFromHeadersPathRequest`: the GET arguments. Without a mapping every query
/// parameter (and every header) is passed under its own name.
pub fn get_params(req: &RouteRequest, path_string: Option<&str>, def: &JMap) -> MultiValue {
    let mut params = MultiValue::default();
    let qm = string_map(def, "queryParamMapping");
    if qm.is_empty() {
        for (k, v) in &req.query {
            params.add(k, v.clone());
        }
    } else {
        for (k, v) in &qm {
            params.add(v, req.query_first(k).map(str::to_string));
        }
    }
    if let Some(ps) = path_string.filter(|s| !s.trim().is_empty()) {
        if let Some(vars) = path_variables(ps, &req.path) {
            let pm = string_map(def, "pathParamMapping");
            if pm.is_empty() {
                for (k, v) in &vars {
                    params.set(k, Some(v.java_to_string()));
                }
            } else {
                for (k, v) in &pm {
                    params.add(v, vars.get(k).map(JValue::java_to_string));
                }
            }
        }
    }
    let hm = string_map(def, "headersMapping");
    if hm.is_empty() {
        for (k, v) in &req.headers {
            params.add(k, Some(v.clone()));
        }
    } else {
        for (k, v) in &hm {
            params.add(v, req.header_first(k).map(str::to_string));
        }
    }
    params
}

/// `URIPathService.withMappedParams`: the body plus the path variables, query parameters and
/// headers the definition maps (and only those), a mapped value replacing a body key.
pub fn with_mapped_params(body: Option<&G>, req: &RouteRequest, path_string: Option<&str>, def: &JMap) -> G {
    let mut args = match body {
        Some(b @ G::Obj(_)) => b.clone(),
        _ => G::Obj(Vec::new()),
    };
    let pm = string_map(def, "pathParamMapping");
    if let (false, Some(ps)) = (pm.is_empty(), path_string.filter(|s| !s.trim().is_empty())) {
        if let Some(vars) = path_variables(ps, &req.path) {
            for (k, v) in &pm {
                if let Some(x) = vars.get(k) {
                    args.set(v, G::Str(x.java_to_string()));
                }
            }
        }
    }
    for (k, v) in string_map(def, "queryParamMapping") {
        if let Some(x) = req.query_first(&k) {
            args.set(&v, G::Str(x.to_string()));
        }
    }
    for (k, v) in string_map(def, "headersMapping") {
        if let Some(x) = req.header_first(&k) {
            args.set(&v, G::Str(x.to_string()));
        }
    }
    args
}

/// `HttpStatus.resolve(code).getReasonPhrase()` (Spring 6.2), for the 4xx and 5xx codes.
pub fn reason_phrase(code: u16) -> Option<&'static str> {
    Some(match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested range not satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        419 => "Insufficient Space On Resource",
        420 => "Method Failure",
        421 => "Destination Locked",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version not supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        509 => "Bandwidth Limit Exceeded",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => return None,
    })
}

/// What a route answers when the function ran.
#[derive(Debug, PartialEq)]
pub enum RouteAnswer {
    /// `ResponseEntity.status(s).body(text)`.
    Body(StatusCode, String),
    /// `GenericException(status, message)`.
    Error(StatusCode, String),
    /// A `NullPointerException` and the like: the generic 500 with this debug text.
    Fault(String),
}

fn named_event<'a>(response: &'a G, name: &str) -> Option<&'a G> {
    match response {
        G::Arr(a) => a.iter().find(|e| {
            matches!(e, G::Obj(_)) && e.get("name").is_some_and(|n| n.is_primitive() && n.as_string().as_deref() == Some(name))
        }),
        _ => None,
    }
}

/// `URIPathService.errorEventResponse`: `None` is the empty Mono.
pub fn error_event_response(response: &G, def: &JMap) -> Option<RouteAnswer> {
    let name = str_field(def, "errorEventName").filter(|s| !s.trim().is_empty())?;
    let event = named_event(response, name)?;
    let empty = G::Obj(Vec::new());
    let result = match event.get("result") {
        Some(r @ G::Obj(_)) => r,
        _ => &empty,
    };
    let mut status: i64 = 400;
    if let Some(s) = result.get("status").filter(|s| s.is_primitive()) {
        status = match s.as_double() {
            // `(int) d`: saturating, NaN to 0.
            Some(d) => {
                if d.is_nan() {
                    0
                } else {
                    d.clamp(i32::MIN as f64, i32::MAX as f64) as i64
                }
            }
            None => 400,
        };
    }
    let code = u16::try_from(status)
        .ok()
        .filter(|c| *c >= 400 && reason_phrase(*c).is_some())
        .unwrap_or(400);
    let http = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
    if let Some(body) = result.get("body").filter(|b| !matches!(b, G::Null)) {
        let text = match body {
            G::Str(s) => s.clone(),
            other => gson::to_string(other),
        };
        return Some(RouteAnswer::Body(http, text));
    }
    let message = match result.get("message").filter(|m| m.is_primitive()) {
        Some(m) => m.as_string().unwrap_or_default(),
        None => reason_phrase(code).unwrap_or("Bad Request").to_string(),
    };
    Some(RouteAnswer::Error(http, message))
}

/// `TokenValueExtractor.splitPath`: dots outside brackets, not `..`.
fn split_path(token: &str) -> Vec<String> {
    let b = token.as_bytes();
    let mut parts = Vec::new();
    let (mut start, mut in_bracket) = (0, false);
    for i in 0..b.len() {
        match b[i] {
            b'[' => in_bracket = true,
            b']' => in_bracket = false,
            b'.' if !in_bracket => {
                let double = (i > 0 && b[i - 1] == b'.') || (i + 1 < b.len() && b[i + 1] == b'.');
                if !double {
                    if i > start {
                        parts.push(token[start..i].to_string());
                    }
                    start = i + 1;
                }
            }
            _ => {}
        }
    }
    if start < token.len() {
        parts.push(token[start..].to_string());
    }
    parts
}

fn length_of(e: &G) -> Option<G> {
    match e {
        G::Arr(a) => Some(G::Num(a.len().to_string())),
        G::Obj(m) => match e.get("length") {
            Some(l @ (G::Bool(_) | G::Num(_) | G::Str(_) | G::Null)) => Some(l.clone()),
            _ => Some(G::Num(m.len().to_string())),
        },
        G::Str(s) => Some(G::Num(s.encode_utf16().count().to_string())),
        _ => None,
    }
}

/// An index segment (`-1` counts from the end); `Err` when it is not an integer.
fn index_of(seg: &str, len: usize, token: &str) -> Result<Option<usize>, String> {
    let neg = seg.starts_with('-');
    let digits = seg.strip_prefix('-').unwrap_or(seg);
    let n: i64 = match digits.parse() {
        Ok(n) if !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) => n,
        _ => return Err(format!("{token} : {seg} couldn't be parsed into integer in {token}")),
    };
    let idx = if neg { len as i64 - n } else { n };
    Ok((idx >= 0 && (idx as usize) < len).then_some(idx as usize))
}

/// One segment of a token path (`resolveSegmentFast` and the bracket handling, ranges aside).
/// `Err` is the `ExpressionEvaluationException` message.
fn resolve_segment(e: &G, seg: &str, part: &str, token: &str) -> Result<Option<G>, String> {
    let quoted = seg.len() >= 2 && (seg.starts_with('"') && seg.ends_with('"') || seg.starts_with('\'') && seg.ends_with('\''));
    if seg == "length" || seg == "\"length\"" || seg == "'length'" {
        return match length_of(e) {
            Some(l) => Ok(Some(l)),
            None => Err(format!("{token} : Length can't be found in token {token}")),
        };
    }
    match e {
        G::Obj(_) => Ok(e.get(if quoted { &seg[1..seg.len() - 1] } else { seg }).cloned()),
        G::Arr(a) => Ok(index_of(seg, a.len(), token)?.map(|i| a[i].clone())),
        G::Str(s) => {
            let units: Vec<u16> = s.encode_utf16().collect();
            Ok(index_of(seg, units.len(), token)?.map(|i| G::Str(String::from_utf16_lossy(&units[i..i + 1]))))
        }
        other => Err(format!(
            "{token} : Unable to retrive {part} from {} in the path {token}",
            gson::to_string(other)
        )),
    }
}

/// `new ArgumentsTokenValueExtractor(Map.of("result", result)).getValue("Arguments." + param)`.
pub fn arguments_value(result: &G, param: &str) -> Result<Option<G>, String> {
    let token = format!("Arguments.{param}");
    let mut parts = split_path(&token);
    if parts.len() < 2 {
        return Ok(None);
    }
    let mut key = parts[1].clone();
    let from = match key.find('[') {
        Some(b) => {
            parts[1] = key[b..].to_string();
            key.truncate(b);
            1
        }
        None => 2,
    };
    let mut current = if key == "result" { Some(result.clone()) } else { None };
    for part in &parts[from..] {
        let Some(mut cur) = current.take().filter(|e| !matches!(e, G::Null)) else { return Ok(None) };
        for seg in part.split(['[', ']']).map(str::trim).filter(|s| !s.is_empty()) {
            if seg.contains("..") {
                return Err(format!("{token} : ranges are not supported here"));
            }
            match resolve_segment(&cur, seg, part, &token)? {
                Some(next) => cur = next,
                None => return Ok(None),
            }
        }
        current = Some(cur);
    }
    Ok(current)
}

const NPE_RESULT: &str = "Cannot invoke \"com.google.gson.JsonElement.toString()\" because the return value of \"com.google.gson.JsonObject.get(String)\" is null";
const NPE_ARGUMENT: &str = "Cannot invoke \"com.google.gson.JsonElement.toString()\" because the return value of \"com.fincity.nocode.kirun.engine.runtime.tokenextractors.ArgumentsTokenValueExtractor.getValue(String)\" is null";

/// `URIPathService.extractOutputEvent`: `Ok(None)` is the empty Mono.
pub fn extract_output_event(response: &G, name: &str, param: Option<&str>) -> Result<Option<String>, String> {
    let Some(event) = named_event(response, name) else { return Ok(None) };
    match param.filter(|p| !p.trim().is_empty()) {
        None => match event.get("result") {
            Some(r) => Ok(Some(gson::to_string(r))),
            None => Err(NPE_RESULT.into()),
        },
        Some(p) => match event.get("result") {
            Some(r @ G::Obj(_)) => match arguments_value(r, p)? {
                Some(v) => Ok(Some(gson::to_string(&v))),
                None => Err(NPE_ARGUMENT.into()),
            },
            _ => Ok(None),
        },
    }
}

/// The function's answer turned into the route's: `Ok(None)` is the empty Mono (a GET then
/// serves the page, a body method a bare 400).
pub fn answer(response: Option<&str>, def: &JMap) -> Result<Option<RouteAnswer>, RouteAnswer> {
    let Some(text) = response else { return Ok(None) };
    if text.trim().is_empty() {
        return Ok(Some(RouteAnswer::Body(StatusCode::OK, String::new())));
    }
    let Some(output) = str_field(def, "outputEventName").filter(|s| !s.trim().is_empty()) else {
        return Ok(Some(RouteAnswer::Body(StatusCode::OK, text.to_string())));
    };
    let events = gson::parse_array(text).map_err(RouteAnswer::Fault)?;
    match extract_output_event(&events, output, str_field(def, "outputEventParamName")) {
        Err(npe) => Err(RouteAnswer::Fault(npe)),
        Ok(Some(s)) => Ok(Some(RouteAnswer::Body(StatusCode::OK, s))),
        Ok(None) => Ok(error_event_response(&events, def)),
    }
}

/// `FORBIDDEN_EXECUTION` when the route's permission is not held.
pub fn access_check(uri_path: &JMap, authorities: &[String], authenticated: bool) -> Result<(), AppError> {
    let Some(p) = str_field(uri_path, "permission").filter(|p| !p.trim().is_empty()) else { return Ok(()) };
    if has_authority(Some(p), authorities) {
        return Ok(());
    }
    Err(crate::catalogue::execution_forbidden(authenticated, p))
}

/// The first pattern (in the order given) that matches the path.
pub fn first_match<'a>(patterns: impl IntoIterator<Item = &'a String>, path: &str) -> Option<&'a String> {
    patterns.into_iter().find(|p| ant_match(p, path))
}

/// `findAllNamesByAppCodeAndClientCode`: the never-published routes left out.
pub fn names_filter(app: &str, cc: &str) -> mongodb::bson::Document {
    doc! { "appCode": app, "clientCode": cc, "published": { "$ne": false } }
}

/// A route's text answer with the content type the controller method produces.
pub fn text_response(status: StatusCode, body: String, content_type: &'static str) -> Response {
    let mut r = (status, body).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    r
}

/// Query string for the core call, the way Feign expands a `MultiValueMap` query map. A null
/// value is a `NullPointerException` there.
pub fn query_string(params: &MultiValue) -> Result<String, String> {
    let mut out = String::new();
    for (k, vs) in &params.0 {
        for v in vs {
            let Some(v) = v else {
                return Err("Cannot invoke \"Object.toString()\" because \"element\" is null".into());
            };
            if !out.is_empty() {
                out.push('&');
            }
            out.push_str(&encode(k));
            out.push('=');
            out.push_str(&encode(v));
        }
    }
    Ok(out)
}

fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    //! The Java `UriPathModelDiffTest` and `URIPathKIRunRouteTest`, and the rest of the route
    //! helpers.
    use super::*;

    /// JSON as the Java side reads it (keys in `serde_json`'s sorted order).
    fn j(v: serde_json::Value) -> JValue {
        overridable::json::parse(v.to_string().as_bytes()).unwrap()
    }

    fn m(v: serde_json::Value) -> JMap {
        match j(v) {
            JValue::Object(o) => o,
            _ => panic!("not an object"),
        }
    }

    fn fx(name: &str, ns: &str, headers: Option<serde_json::Value>) -> JValue {
        let mut o = m(serde_json::json!({"name": name, "namespace": ns}));
        if let Some(h) = headers {
            o.insert("headersMapping".into(), j(h));
        }
        JValue::Object(o)
    }

    fn get<'a>(v: &'a JValue, f: &str) -> &'a JValue {
        v.as_object().and_then(|o| o.get(f)).unwrap_or(&JValue::Null)
    }

    // UriPathModelDiffTest

    #[test]
    fn keeps_derived_scalar() {
        let base = fx("baseFn", "ns", None);
        let derived = fx("derivedFn", "ns", None);
        let delta = kirun_extract(&base, &derived).unwrap();
        assert_eq!(get(&delta, "name"), &JValue::from("derivedFn"), "the delta must carry the DERIVED name");
        assert!(get(&delta, "namespace").is_null(), "an unchanged namespace is not an override");
        let rebuilt = kirun_apply(&delta, Some(&base)).unwrap();
        assert_eq!(get(&rebuilt, "name"), &JValue::from("derivedFn"));
        assert_eq!(get(&rebuilt, "namespace"), &JValue::from("ns"));
    }

    #[test]
    fn keeps_derived_map_entry() {
        let base = fx("fn", "ns", Some(serde_json::json!({"a": "1"})));
        let derived = fx("fn", "ns", Some(serde_json::json!({"a": "2"})));
        let delta = kirun_extract(&base, &derived).unwrap();
        let rebuilt = kirun_apply(&delta, Some(&base)).unwrap();
        assert_eq!(get(get(&rebuilt, "headersMapping"), "a"), &JValue::from("2"), "the derived mapping must win");
    }

    #[test]
    fn keeps_derived_list() {
        let base = j(serde_json::json!({"whitelist": ["10.0.0.1"]}));
        let derived = j(serde_json::json!({"whitelist": ["10.0.0.2", "10.0.0.3"]}));
        let delta = path_definition_extract(&base, &derived).unwrap();
        let rebuilt = path_definition_apply(&delta, Some(&base)).unwrap();
        assert_eq!(
            get(&rebuilt, "whitelist"),
            &j(serde_json::json!(["10.0.0.2", "10.0.0.3"])),
            "a derived client's whitelist must not come back as the base's"
        );
    }

    #[test]
    fn keeps_derived_nested_model() {
        let base = JValue::Object(JMap::from_iter([("kiRunFxDefinition".to_string(), fx("baseFn", "ns", None))]));
        let derived = JValue::Object(JMap::from_iter([("kiRunFxDefinition".to_string(), fx("derivedFn", "ns", None))]));
        let delta = path_definition_extract(&base, &derived).unwrap();
        let rebuilt = path_definition_apply(&delta, Some(&base)).unwrap();
        assert_eq!(get(get(&rebuilt, "kiRunFxDefinition"), "name"), &JValue::from("derivedFn"));
    }

    #[test]
    fn keeps_derived_redirection_target() {
        let base = j(serde_json::json!({"targetUrl": "https://base.example/"}));
        let derived = j(serde_json::json!({"targetUrl": "https://derived.example/"}));
        let delta = redirection_extract(&base, &derived).unwrap();
        assert_eq!(get(&delta, "targetUrl"), &JValue::from("https://derived.example/"));
        let rebuilt = redirection_apply(&delta, Some(&base)).unwrap();
        assert_eq!(
            get(&rebuilt, "targetUrl"),
            &JValue::from("https://derived.example/"),
            "the base must not overwrite a value the derived client set"
        );
    }

    // URIPathKIRunRouteTest

    fn req(method: &str, path_and_query: &str, headers: &[(&str, &str)]) -> RouteRequest {
        let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
        RouteRequest {
            method: method.into(),
            path: path.into(),
            query: query
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|kv| match kv.split_once('=') {
                    Some((k, v)) => (k.to_string(), Some(v.to_string())),
                    None => (kv.to_string(), None),
                })
                .collect(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn no_mapping_keeps_body() {
        let r = req("POST", "/api/open/x/abc?q=1", &[("X-Forwarded-Host", "h")]);
        let body = gson::parse_object(r#"{"a":1}"#).unwrap();
        let args = with_mapped_params(Some(&body), &r, Some("/api/open/x/{code}"), &JMap::new());
        assert_eq!(args, body);
    }

    #[test]
    fn mapped_params_merged() {
        let r = req("POST", "/api/open/tickets/req/website/P123?src=fb", &[("X-Forwarded-Host", "site.example.com")]);
        let def = m(serde_json::json!({
            "pathParamMapping": {"code": "code"},
            "queryParamMapping": {"src": "source", "missing": "never"},
            "headersMapping": {"X-Forwarded-Host": "requestHost"},
        }));
        let input = gson::parse_object(r#"{"code":"fromBody","leadDetails":{"fullName":"A"}}"#).unwrap();
        let args = with_mapped_params(Some(&input), &r, Some("/api/open/tickets/req/website/{code}"), &def);
        assert_eq!(args.get("code"), Some(&G::Str("P123".into())));
        assert_eq!(args.get("source"), Some(&G::Str("fb".into())));
        assert_eq!(args.get("requestHost"), Some(&G::Str("site.example.com".into())));
        assert!(!args.has("never"), "an absent query parameter adds nothing");
        assert_eq!(args.get("leadDetails").and_then(|l| l.get("fullName")), Some(&G::Str("A".into())));
        assert_eq!(input.get("code"), Some(&G::Str("fromBody".into())), "the request body itself is not modified");
        assert_eq!(
            gson::to_string(&args),
            r#"{"code":"P123","leadDetails":{"fullName":"A"},"source":"fb","requestHost":"site.example.com"}"#
        );
    }

    #[test]
    fn no_error_event_name() {
        let resp = gson::parse_array(r#"[{"name":"error","result":{"status":404}}]"#).unwrap();
        assert_eq!(error_event_response(&resp, &JMap::new()), None);
    }

    fn error_def() -> JMap {
        m(serde_json::json!({"errorEventName": "error"}))
    }

    #[test]
    fn error_event_with_body() {
        let resp = gson::parse_array(r#"[{"name":"error","result":{"status":403.0,"body":"Verification token mismatch"}}]"#).unwrap();
        assert_eq!(
            error_event_response(&resp, &error_def()),
            Some(RouteAnswer::Body(StatusCode::FORBIDDEN, "Verification token mismatch".into()))
        );
        let obj_body = gson::parse_array(r#"[{"name":"error","result":{"status":409,"body":{"d":true}}}]"#).unwrap();
        assert_eq!(
            error_event_response(&obj_body, &error_def()),
            Some(RouteAnswer::Body(StatusCode::CONFLICT, r#"{"d":true}"#.into()))
        );
    }

    #[test]
    fn error_event_without_body() {
        let resp = gson::parse_array(r#"[{"name":"error","result":{"status":404,"message":"Unknown with identity x not found."}}]"#).unwrap();
        assert_eq!(
            error_event_response(&resp, &error_def()),
            Some(RouteAnswer::Error(StatusCode::NOT_FOUND, "Unknown with identity x not found.".into()))
        );
        let bad = gson::parse_array(r#"[{"name":"error","result":{"status":200}}]"#).unwrap();
        assert_eq!(
            error_event_response(&bad, &error_def()),
            Some(RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into()))
        );
    }

    #[test]
    fn error_event_name_round_trip() {
        let base = j(serde_json::json!({"name": "fn"}));
        let derived = j(serde_json::json!({"name": "fn", "errorEventName": "error"}));
        let delta = kirun_extract(&base, &derived).unwrap();
        assert_eq!(get(&delta, "errorEventName"), &JValue::from("error"));
        assert!(get(&kirun_extract(&base, &base).unwrap(), "errorEventName").is_null());
        // The copy constructor keeps it: the definition is stored and copied as it is.
        let copy = overridable::pojo::clone_pojo(&PATH_DEFINITION, &m(serde_json::json!({"kiRunFxDefinition": derived.clone()})));
        assert_eq!(get(copy.get("kiRunFxDefinition").unwrap(), "errorEventName"), &JValue::from("error"));
    }

    // The rest of the route.

    #[test]
    fn error_event_statuses_and_messages() {
        let ev = |result: &str| gson::parse_array(&format!(r#"[{{"name":"x"}},{{"name":"error","result":{result}}}]"#)).unwrap();
        let cases = [
            (r#"{"status":"404"}"#, RouteAnswer::Error(StatusCode::NOT_FOUND, "Not Found".into())),
            (r#"{"status":true}"#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into())),
            (r#"{"status":499}"#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into())),
            (r#"{"status":"abc","message":12}"#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "12".into())),
            (r#"{"status":503.9,"message":{"x":1}}"#, RouteAnswer::Error(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable".into())),
            (r#"{"status":1e10}"#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into())),
            (r#"{"status":[1]}"#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into())),
            (r#"{"body":null,"message":"m"}"#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "m".into())),
            (r#"{"body":[1,"<a>"]}"#, RouteAnswer::Body(StatusCode::BAD_REQUEST, r#"[1,"<a>"]"#.into())),
            (r#""not an object""#, RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into())),
        ];
        for (result, expected) in cases {
            assert_eq!(error_event_response(&ev(result), &error_def()), Some(expected), "{result}");
        }
        let nan = gson::parse_array(r#"[{"name":"error","result":{"status":"NaN"}}]"#).unwrap();
        assert_eq!(error_event_response(&nan, &error_def()), Some(RouteAnswer::Error(StatusCode::BAD_REQUEST, "Bad Request".into())));
        assert_eq!(error_event_response(&ev("{}"), &m(serde_json::json!({"errorEventName": "other"}))), None);
        assert_eq!(error_event_response(&G::Obj(vec![]), &error_def()), None);
        assert_eq!(reason_phrase(499), None);
    }

    #[test]
    fn output_events_and_their_parameters() {
        let resp = gson::parse_array(
            r#"[1,{"name":2},{"name":"output","result":{"result":{"challenge":"12345","n":1.50},"list":[{"a":"x"},{"a":"y"}],"s":"héllo","length":4}}]"#,
        )
        .unwrap();
        let out = |p: Option<&str>| extract_output_event(&resp, "output", p);
        assert_eq!(out(None).unwrap().unwrap(), r#"{"result":{"challenge":"12345","n":1.50},"list":[{"a":"x"},{"a":"y"}],"s":"héllo","length":4}"#);
        assert_eq!(out(Some("result.result.challenge")).unwrap().unwrap(), r#""12345""#);
        assert_eq!(out(Some("result.result.n")).unwrap().unwrap(), "1.50");
        assert_eq!(out(Some("result")).unwrap(), out(None).unwrap(), "the whole result");
        assert_eq!(out(Some("result.list[1].a")).unwrap().unwrap(), r#""y""#);
        assert_eq!(out(Some("result.list[-1].a")).unwrap().unwrap(), r#""y""#);
        assert_eq!(out(Some("result.list.length")).unwrap().unwrap(), "2");
        assert_eq!(out(Some("result.length")).unwrap().unwrap(), "4");
        assert_eq!(out(Some("result.result.length")).unwrap().unwrap(), "2");
        assert_eq!(out(Some("result.s.length")).unwrap().unwrap(), "5");
        assert_eq!(out(Some("result.s[1]")).unwrap().unwrap(), r#""é""#);
        assert_eq!(out(Some("result[\"list\"][0].a")).unwrap().unwrap(), r#""x""#);
        assert_eq!(out(Some("result.list[5]")).unwrap_err(), NPE_ARGUMENT);
        assert_eq!(out(Some("response")).unwrap_err(), NPE_ARGUMENT);
        assert_eq!(out(Some("result.missing.deeper")).unwrap_err(), NPE_ARGUMENT);
        assert_eq!(
            out(Some("result.result.n.x")).unwrap_err(),
            "Arguments.result.result.n.x : Unable to retrive x from 1.50 in the path Arguments.result.result.n.x"
        );
        assert_eq!(
            out(Some("result.result.n[0]")).unwrap_err(),
            "Arguments.result.result.n[0] : Unable to retrive n[0] from 1.50 in the path Arguments.result.result.n[0]"
        );
        assert_eq!(
            out(Some("result.s.x")).unwrap_err(),
            "Arguments.result.s.x : x couldn't be parsed into integer in Arguments.result.s.x"
        );
        assert_eq!(
            out(Some("result.s[\"x\"]")).unwrap_err(),
            "Arguments.result.s[\"x\"] : \"x\" couldn't be parsed into integer in Arguments.result.s[\"x\"]"
        );
        assert_eq!(out(Some("result.list[a]")).unwrap_err(), "Arguments.result.list[a] : a couldn't be parsed into integer in Arguments.result.list[a]");
        assert_eq!(out(Some("result.s[9]")).unwrap_err(), NPE_ARGUMENT);
        assert_eq!(out(Some("result.result[\"challenge\"]")).unwrap().unwrap(), r#""12345""#);
        assert_eq!(out(Some("result.list[0][\"a\"]")).unwrap().unwrap(), r#""x""#);
        assert!(out(Some("result.list[1..2]")).is_err());
        assert_eq!(extract_output_event(&resp, "nothing", None), Ok(None));
        let no_result = gson::parse_array(r#"[{"name":"output"}]"#).unwrap();
        assert_eq!(extract_output_event(&no_result, "output", None).unwrap_err(), NPE_RESULT);
        assert_eq!(extract_output_event(&no_result, "output", Some("result.x")), Ok(None));
        let prim = gson::parse_array(r#"[{"name":"output","result":"text"}]"#).unwrap();
        assert_eq!(extract_output_event(&prim, "output", None), Ok(Some(r#""text""#.into())));
        assert_eq!(extract_output_event(&prim, "output", Some("result")), Ok(None));
        assert_eq!(split_path("Arguments.a..b.c[x.y]"), vec!["Arguments", "a..b", "c[x.y]"]);
        assert_eq!(arguments_value(&G::Null, "result"), Ok(Some(G::Null)));
        assert_eq!(arguments_value(&G::Null, "result.x"), Ok(None));
        assert_eq!(
            arguments_value(&G::Num("1".into()), "result.length"),
            Err("Arguments.result.length : Length can't be found in token Arguments.result.length".into())
        );
        assert!(arguments_value(&G::Num("1".into()), "result.x").is_err());
        assert!(arguments_value(&G::Arr(vec![]), "result.x").is_err());
        assert_eq!(arguments_value(&G::Arr(vec![]), "result.0"), Ok(None));
        assert_eq!(arguments_value(&G::Obj(vec![]), ""), Ok(None));
        assert_eq!(
            arguments_value(&G::Obj(vec![("length".into(), G::Arr(vec![]))]), "result.length"),
            Ok(Some(G::Num("1".into())))
        );
        assert_eq!(arguments_value(&G::Obj(vec![("a".into(), G::Num("1".into()))]), "result[\"a\"]"), Ok(Some(G::Num("1".into()))));
    }

    #[test]
    fn answers_from_the_function_output() {
        let def = m(serde_json::json!({"outputEventName": "output", "outputEventParamName": "result.result", "errorEventName": "error"}));
        assert_eq!(answer(None, &def), Ok(None));
        assert_eq!(answer(Some("  "), &def), Ok(Some(RouteAnswer::Body(StatusCode::OK, String::new()))));
        assert_eq!(
            answer(Some(r#"[{"name":"output","result":{"result":"ok"}}]"#), &def),
            Ok(Some(RouteAnswer::Body(StatusCode::OK, r#""ok""#.into())))
        );
        assert_eq!(
            answer(Some(r#"[{"name":"error","result":{"status":403,"body":"no"}}]"#), &def),
            Ok(Some(RouteAnswer::Body(StatusCode::FORBIDDEN, "no".into())))
        );
        assert_eq!(answer(Some(r#"[{"name":"other"}]"#), &def), Ok(None));
        assert!(matches!(answer(Some(r#"{"name":"output"}"#), &def), Err(RouteAnswer::Fault(_))));
        assert_eq!(
            answer(Some(r#"[{"name":"output","result":{}}]"#), &def),
            Err(RouteAnswer::Fault(NPE_ARGUMENT.into()))
        );
        assert_eq!(answer(Some("[1, 2]"), &JMap::new()), Ok(Some(RouteAnswer::Body(StatusCode::OK, "[1, 2]".into()))));
    }

    #[test]
    fn get_arguments_from_query_path_and_headers() {
        let r = req(
            "GET",
            "/hello/x%20y/b2/C/B?q=1&q=2&flag&e=",
            &[("appCode", "appbuilder"), ("X-Forwarded-Host", "h")],
        );
        let path = RouteRequest { path: "/hello/x y/b2/C/B".into(), ..r.clone() };
        let none = get_params(&path, Some("/hello/{a}/{b}/C/B"), &JMap::new());
        assert_eq!(
            none.0,
            vec![
                ("q".to_string(), vec![Some("1".to_string()), Some("2".to_string())]),
                ("flag".to_string(), vec![None]),
                ("e".to_string(), vec![Some(String::new())]),
                ("a".to_string(), vec![Some("x y".to_string())]),
                ("b".to_string(), vec![Some("b2".to_string())]),
                ("appCode".to_string(), vec![Some("appbuilder".to_string())]),
                ("X-Forwarded-Host".to_string(), vec![Some("h".to_string())]),
            ]
        );
        assert!(query_string(&none).is_err(), "a parameter without a value cannot be sent");
        let def = m(serde_json::json!({
            "pathParamMapping": {"a": "aParam", "zz": "missing"},
            "queryParamMapping": {"q": "query"},
            "headersMapping": {"appcode": "app"},
        }));
        let mapped = get_params(&path, Some("/hello/{a}/{b}/C/B"), &def);
        assert_eq!(
            mapped.0,
            vec![
                ("query".to_string(), vec![Some("1".to_string())]),
                ("aParam".to_string(), vec![Some("x y".to_string())]),
                ("missing".to_string(), vec![None]),
                ("app".to_string(), vec![Some("appbuilder".to_string())]),
            ]
        );
        let ok = get_params(&path, Some("/no/match"), &m(serde_json::json!({"queryParamMapping": {"q": "query"}, "headersMapping": {"appCode": "a b&c"}})));
        assert_eq!(query_string(&ok).unwrap(), "query=1&a%20b%26c=appbuilder");
        let mut mv = MultiValue::default();
        mv.set("k", Some("1".into()));
        mv.add("k", Some("2".into()));
        mv.set("k", Some("3".into()));
        assert_eq!(query_string(&mv).unwrap(), "k=3");
        assert_eq!(get_params(&path, Some(" "), &def).0.len(), 2);
    }

    #[test]
    fn route_access_and_matching() {
        let auth = vec!["Authorities.Application_READ".to_string()];
        assert!(access_check(&JMap::new(), &[], false).is_ok());
        assert!(access_check(&m(serde_json::json!({"permission": "Authorities.Application_READ"})), &auth, true).is_ok());
        let e = access_check(&m(serde_json::json!({"permission": "Authorities.Logged_IN"})), &auth, true).unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert_eq!(overridable::write::messages::error_message(&e), "Authorization Authorities.Logged_IN is required");
        assert!(matches!(&e, AppError::Coded(c) if c.code == "UI.FORBIDDEN_EXECUTION"));
        let e = access_check(&m(serde_json::json!({"permission": "Authorities.Logged_IN"})), &[], false).unwrap_err();
        assert!(matches!(&e, AppError::Coded(c) if c.code == "UI.SIGN_IN_REQUIRED"));
        let patterns = vec!["/a/b".to_string(), "/hello/*/*/C/B".to_string(), "/hello/**".to_string()];
        assert_eq!(first_match(&patterns, "/hello/x/y/C/B"), Some(&patterns[1]));
        assert_eq!(first_match(&patterns, "/nothing"), None);
        assert_eq!(names_filter("a", "B").get_str("clientCode").unwrap(), "B");
        let r = text_response(StatusCode::OK, "x".into(), "text/plain;charset=UTF-8");
        assert_eq!(r.headers()["content-type"], "text/plain;charset=UTF-8");
    }

    #[test]
    fn uri_path_document_merges_and_differs() {
        let dt = UriPathDoc;
        assert_eq!(dt.object_name(), "URIPath");
        assert_eq!(dt.collection(), "uri_path");
        assert_eq!(dt.cache_name("leadzump", "/api/x/**"), "URIPathCache_leadzump_URICache_leadzump/api/x/**");
        assert!(dt.draftable());
        let base = m(serde_json::json!({
            "pathString": "/a/{x}", "shortCode": "s1",
            "pathDefinitions": {
                "GET": {"uriType": "KIRUN_FUNCTION", "headers": ["h"], "kiRunFxDefinition": {"name": "f", "namespace": "n", "queryParamMapping": {"a": "b"}}},
                "POST": {"uriType": "KIRUN_FUNCTION", "kiRunFxDefinition": {"name": "p"}},
            }
        }));
        let derived = m(serde_json::json!({
            "pathString": null,
            "pathDefinitions": {
                "GET": {"kiRunFxDefinition": {"name": "g", "queryParamMapping": {"c": "d"}}},
                "DELETE": {"uriType": "REDIRECTION", "redirectionDefinition": {"targetUrl": "https://x/"}},
            }
        }));
        let merged = dt.apply_override(derived, &base).unwrap();
        assert_eq!(merged["pathString"], JValue::from("/a/{x}"));
        assert_eq!(merged["shortCode"], JValue::from("s1"));
        let pd = merged["pathDefinitions"].as_object().unwrap();
        let get_def = &pd["GET"];
        assert_eq!(get(get_def, "uriType"), &JValue::from("KIRUN_FUNCTION"));
        assert!(get(get_def, "headers").is_null(), "a list the delta does not carry is not kept from the base");
        let fxd = get(get_def, "kiRunFxDefinition");
        assert_eq!(get(fxd, "name"), &JValue::from("g"));
        assert_eq!(get(fxd, "namespace"), &JValue::from("n"));
        assert_eq!(get(get(fxd, "queryParamMapping"), "a"), &JValue::from("b"));
        assert_eq!(get(get(fxd, "queryParamMapping"), "c"), &JValue::from("d"));
        assert_eq!(get(&pd["POST"], "kiRunFxDefinition"), &j(serde_json::json!({"name": "p"})));
        assert_eq!(get(get(&pd["DELETE"], "redirectionDefinition"), "targetUrl"), &JValue::from("https://x/"));

        let incoming = m(serde_json::json!({
            "pathString": "/a/{x}", "shortCode": "s2",
            "pathDefinitions": {
                "GET": {"uriType": "KIRUN_FUNCTION", "headers": ["h"], "kiRunFxDefinition": {"name": "f2", "namespace": "n", "queryParamMapping": {"a": "b"}}},
                "PUT": {"uriType": "KIRUN_FUNCTION"},
            }
        }));
        let diff = dt.extract_difference(incoming, &base).unwrap();
        assert!(diff["pathString"].is_null());
        assert_eq!(diff["shortCode"], JValue::from("s2"));
        let dpd = diff["pathDefinitions"].as_object().unwrap();
        assert!(dpd["POST"].is_null(), "a definition the derived drops is a deletion");
        assert_eq!(dpd["PUT"], j(serde_json::json!({"uriType": "KIRUN_FUNCTION"})));
        let dget = &dpd["GET"];
        assert!(get(dget, "uriType").is_null());
        assert!(get(dget, "headers").is_null());
        assert_eq!(get(get(dget, "kiRunFxDefinition"), "name"), &JValue::from("f2"));
        assert!(get(get(dget, "kiRunFxDefinition"), "namespace").is_null());
        assert_eq!(get(get(dget, "kiRunFxDefinition"), "queryParamMapping"), &JValue::Object(JMap::new()));

        // The typed helpers at their edges.
        assert_eq!(kirun_apply(&JValue::from("x"), None), Some(JValue::from("x")));
        assert_eq!(kirun_extract(&JValue::Null, &JValue::from("x")), Some(JValue::from("x")));
        assert_eq!(redirection_apply(&JValue::from("x"), None), Some(JValue::from("x")));
        assert_eq!(redirection_extract(&JValue::Null, &JValue::from("x")), Some(JValue::from("x")));
        assert_eq!(path_definition_apply(&JValue::from("x"), None), Some(JValue::from("x")));
        assert_eq!(path_definition_extract(&JValue::Null, &JValue::from("x")), Some(JValue::from("x")));
        assert!(typed_extract(None, Some(&JValue::from("e")), redirection_extract).is_null());
        assert!(typed_extract(None, None, redirection_extract).is_null());
        assert_eq!(typed_extract(Some(&JValue::from("i")), None, redirection_extract), JValue::from("i"));
        assert!(typed_extract(Some(&JValue::from("i")), Some(&JValue::from("i")), redirection_extract).is_null());
        let changed = path_definition_extract(&j(serde_json::json!({"uriType": "A"})), &j(serde_json::json!({"uriType": "B"}))).unwrap();
        assert_eq!(get(&changed, "uriType"), &JValue::from("B"));
    }
}
