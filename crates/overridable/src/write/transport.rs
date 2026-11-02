//! `AbstractTransportService` and the `Transport` document: moving an app's objects between
//! environments. Export reads every object of the client in the app (merged) through each
//! service and writes them as JSON or as a zip (`<ObjectName>/<name>.json`); import saves each
//! object through its own service's `create` or `update`, types in the service order and each
//! type in dependency waves, so the per-kind validation and evictions all run.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use mongodb::bson::{doc, Bson, DateTime};
use platform::error::{AppError, AppResult};
use platform::security::{ContextAuthentication, OnBehalfOf};

use crate::backend::Find;
use crate::json::{parse, to_jackson_pretty, JMap, JValue};
use crate::pojo::{convert_json, decode_bson, str_field, to_jackson, CloneRule as C, Field, Kind as K, Pojo, OVERRIDABLE_BASE};
use crate::store::DocType;
use crate::write::condition::{Condition, FilterCondition, Operator};
use crate::write::kind::{Kind, Method};
use crate::write::messages as msg;
use crate::write::persist::Clock;
use crate::write::service::{Commons, OverridableService};
use crate::write::{topo, AnyService};

/// The `Transport` document.
pub const TRANSPORT: Pojo = Pojo {
    name: "Transport",
    parts: &[
        OVERRIDABLE_BASE,
        &[
            Field::new("uniqueTransportCode", K::Str, C::Copy),
            Field::new("objects", K::Object, C::Copy),
            Field::new("type", K::Str, C::Copy),
            Field::new("encodedModl", K::Str, C::Copy),
        ],
    ],
};

/// The youngest a transport may be and still be swept, and the most one sweep removes.
const MIN_RETENTION_DAYS: i64 = 7;
const MAX_CLEANUP_LIMIT: i64 = 500;
const SLASH_ESCAPE: &str = "__slash__";

/// The transport document kind: never drafted, never updated.
pub struct TransportKind;

impl DocType for TransportKind {
    fn object_name(&self) -> &'static str {
        "Transport"
    }

    fn collection(&self) -> &'static str {
        "transport"
    }

    fn pojo(&self) -> &'static Pojo {
        &TRANSPORT
    }

    fn draftable(&self) -> bool {
        false
    }

    fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> {
        Some(this)
    }
}

#[async_trait]
impl Kind for TransportKind {
    /// `update` is refused outright, before any access check.
    async fn before_update(&self, cx: &Commons, _ca: &ContextAuthentication, _entity: &mut JMap) -> AppResult<()> {
        Err(msg::with_param(cx.error(StatusCode::NOT_MODIFIED, msg::CANNOT_BE_UPDATED, &[]), "what", "Transport"))
    }
}

/// `TransportRequest`.
#[derive(Debug, Clone, Default)]
pub struct TransportRequest {
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub name: Option<String>,
    pub object_list: Option<HashMap<String, Vec<String>>>,
    /// `ZIP` unless the request says `JSON`.
    pub json: bool,
}

impl TransportRequest {
    pub fn from_json(v: &JValue) -> Result<Self, AppError> {
        let m = v.as_object().cloned().unwrap_or_default();
        let s = |k: &str| m.get(k).and_then(JValue::as_str).map(str::to_string);
        let object_list = m.get("objectList").and_then(JValue::as_object).map(|o| {
            o.iter()
                .map(|(k, v)| {
                    let names = match v {
                        JValue::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
                        _ => Vec::new(),
                    };
                    (k.clone(), names)
                })
                .collect()
        });
        let json = match m.get("fileType") {
            None | Some(JValue::Null) => false,
            Some(JValue::Str(t)) if t == "ZIP" => false,
            Some(JValue::Str(t)) if t == "JSON" => true,
            Some(other) => {
                let t = other.java_to_string();
                let text = format!("Unknown file type {t}");
                return Err(msg::literal("DEF.TRANSPORT_FILE_TYPE_UNKNOWN", StatusCode::BAD_REQUEST, text).param("type", t).into());
            }
        };
        Ok(Self { client_code: s("clientCode"), app_code: s("appCode"), name: s("name"), object_list, json })
    }

    /// The names asked for of one type: `Err(())` when the type is left out entirely.
    fn names_for(&self, object_name: &str) -> Result<Option<&[String]>, ()> {
        match &self.object_list {
            Some(list) if !list.is_empty() => list.get(object_name).map(|n| Some(n.as_slice())).ok_or(()),
            _ => Ok(None),
        }
    }
}

/// A made transport, ready to send.
#[derive(Debug, Clone)]
pub struct TransportFile {
    pub content_type: &'static str,
    pub content_disposition: Option<String>,
    pub bytes: Vec<u8>,
}

/// `UniqueUtil.shortUUID`: 128 random bits in base 62.
pub fn short_uuid() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut n: u128 = rand::random();
    let mut out = Vec::new();
    while n > 0 {
        out.push(ALPHABET[(n % 62) as usize]);
        n /= 62;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `Base64.getEncoder().encodeToString`.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `Base64.getDecoder().decode`: the basic alphabet, padding optional, nothing else allowed.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, AppError> {
    let bad = || AppError::Internal(anyhow::anyhow!("Illegal base64 character"));
    let body = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        let v = B64.iter().position(|x| *x == c).ok_or_else(bad)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn transport_error(cx: &Commons, action: &str, detail: &str) -> AppError {
    cx.error(StatusCode::FORBIDDEN, msg::TRANSPORT_ERROR, &[action, detail])
}

/// The transport service of one process (`ui` or `core`).
pub struct TransportService {
    svc: OverridableService<TransportKind>,
    services: Vec<Arc<dyn AnyService>>,
    transport_type: &'static str,
    extension: &'static str,
}

impl TransportService {
    /// `services` in `getServieMap()` order; `transport_type` is `ui` or `core`, `extension`
    /// `umodl` or `cmodl`.
    pub fn new(cx: Commons, services: Vec<Arc<dyn AnyService>>, transport_type: &'static str, extension: &'static str) -> Self {
        Self { svc: OverridableService::new(TransportKind, cx), services, transport_type, extension }
    }

    /// The transport documents' own service (read, list, delete, ...).
    pub fn documents(&self) -> &OverridableService<TransportKind> {
        &self.svc
    }

    fn cx(&self) -> &Commons {
        self.svc.commons()
    }

    /// `transportTypes`: the object names, in service order.
    pub fn transport_types(&self) -> Vec<&'static str> {
        self.services.iter().map(|s| s.object_name()).collect()
    }

    async fn find_by_code(&self, code: Option<&str>) -> AppResult<Option<JMap>> {
        let value = code.map(|c| JValue::Str(c.to_string()));
        let fc = FilterCondition { value, ..FilterCondition::new("uniqueTransportCode", Operator::Equals, JValue::Null) };
        let filter = Condition::to_mongo(Some(&Condition::Complex { and: false, conditions: vec![Some(Condition::Filter(fc))], negate: false }))?;
        let found = self.cx().backend().find_one(self.svc.collection(), filter, None).await?;
        Ok(found.map(|d| decode_bson(&TRANSPORT, &d)))
    }

    /// `create`: named `<name><uniqueTransportCode>`; a code already stored answers that row.
    pub async fn create(&self, ca: &ContextAuthentication, mut entity: JMap) -> AppResult<JMap> {
        let code = str_field(&entity, "uniqueTransportCode").map(str::to_string);
        let name = format!("{}{}", str_field(&entity, "name").unwrap_or(""), code.as_deref().unwrap_or("null"));
        entity.insert("name".into(), JValue::Str(name));
        match self.find_by_code(code.as_deref()).await? {
            Some(existing) => Ok(existing),
            None => self.svc.create(ca, entity).await,
        }
    }

    /// `applyTransportWithTransportCode`.
    pub async fn apply_transport_with_code(&self, ca: &ContextAuthentication, on_behalf: &OnBehalfOf, code: &str) -> AppResult<bool> {
        let Some(t) = self.find_by_code(Some(code)).await? else {
            return Err(self.cx().error(StatusCode::NOT_FOUND, msg::OBJECT_NOT_FOUND, &["Transport", code]));
        };
        self.apply_transport(ca, on_behalf, str_field(&t, "id").unwrap_or_default(), None, false).await
    }

    /// `applyTransport`: saves everything the transport carries. With `for_app`, the objects
    /// go into that app, under the client security names for it.
    pub async fn apply_transport(&self, ca: &ContextAuthentication, on_behalf: &OnBehalfOf, id: &str, for_app: Option<&str>, is_base_app: bool) -> AppResult<bool> {
        let transport = self.svc.read(ca, id).await?;
        let for_app = for_app.filter(|a| !a.trim().is_empty());
        let base = match for_app {
            Some(app) => {
                let caller = OnBehalfOf {
                    access_token: ca.access_token.clone(),
                    client_code: ca.url_client_code.clone().unwrap_or_default(),
                    app_code: ca.url_app_code.clone().unwrap_or_default(),
                    ..on_behalf.clone()
                };
                self.cx().directory().find_base_client_code_for_override(&caller, app).await?
            }
            None => None,
        };
        let objects = match transport.get("objects") {
            Some(JValue::Array(a)) => a.clone(),
            _ => Vec::new(),
        };
        let modl = str_field(&transport, "encodedModl").filter(|m| !m.trim().is_empty());
        let by_type = match modl {
            None if objects.is_empty() => return Ok(true),
            None => group_objects(&objects),
            Some(m) => self.read_zip_objects(&base64_decode(m)?)?,
        };
        let _ = is_base_app;
        let name = transport.get("name").cloned().unwrap_or_default().java_to_string();
        let ctx = Apply { ca, for_app, base: base.as_ref(), transport_name: &name };
        for service in &self.services {
            let Some(list) = by_type.get(service.object_name()) else { continue };
            let entities: Vec<JMap> = list.iter().filter_map(|d| service.make_entity(service.object_name(), d)).collect();
            let ordered = topo::sort(&entities, |e| str_field(e, "name").map(str::to_string), |e| service.transport_dependencies(e));
            for wave in &ordered.waves {
                for e in wave {
                    ctx.add(service.as_ref(), e.clone()).await?;
                }
            }
            if !ordered.cyclic.is_empty() {
                tracing::warn!(object = service.object_name(), count = ordered.cyclic.len(), "objects depend on each other in a cycle, saving them in two passes");
                for e in &ordered.cyclic {
                    if let Some(stripped) = service.strip_transport_dependencies(e) {
                        ctx.add(service.as_ref(), stripped).await?;
                    }
                }
                for e in &ordered.cyclic {
                    ctx.add(service.as_ref(), e.clone()).await?;
                }
            }
        }
        Ok(true)
    }

    /// The `<ObjectName>/*.json` entries of a transport zip, grouped by type.
    fn read_zip_objects(&self, bytes: &[u8]) -> AppResult<HashMap<String, Vec<JMap>>> {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| AppError::Internal(e.into()))?;
        let mut out: HashMap<String, Vec<JMap>> = HashMap::new();
        for service in &self.services {
            let prefix = format!("{}/", service.object_name());
            for i in 0..zip.len() {
                let mut f = zip.by_index(i).map_err(|e| AppError::Internal(e.into()))?;
                let name = f.name().to_string();
                let Some(rest) = name.strip_prefix(&prefix) else { continue };
                if rest.contains('/') || !name.to_lowercase().trim().ends_with(".json") {
                    continue;
                }
                let mut text = Vec::new();
                f.read_to_end(&mut text).map_err(|e| AppError::Internal(e.into()))?;
                if let JValue::Object(m) = parse(&text)? {
                    out.entry(service.object_name().to_string()).or_default().push(m);
                }
            }
        }
        Ok(out)
    }

    /// `makeTransport`: the client's objects in the app, as a zip (default) or one JSON.
    pub async fn make_transport(&self, ca: &ContextAuthentication, internal: bool, req: &TransportRequest) -> AppResult<TransportFile> {
        let allowed = match (internal, req.json) {
            (true, true) => ca.is_system_client(),
            (true, false) => true,
            (false, _) => self.svc.access_check(ca, Method::Create, req.app_code.as_deref(), req.client_code.as_deref(), false).await?,
        };
        if !allowed {
            return Err(self.cx().messages.refusal(ca, StatusCode::FORBIDDEN, msg::FORBIDDEN_CREATE, &["Transport"]));
        }
        let mut to = JMap::new();
        to.insert("appCode".into(), req.app_code.clone().map(JValue::Str).unwrap_or_default());
        to.insert("clientCode".into(), req.client_code.clone().map(JValue::Str).unwrap_or_default());
        to.insert("name".into(), req.name.clone().map(JValue::Str).unwrap_or_default());
        // `new Transport()`: the DTO's `int version = 1`.
        to.insert("version".into(), JValue::Int(1));
        to.insert("uniqueTransportCode".into(), JValue::Str(short_uuid()));
        to.insert("type".into(), JValue::Str(self.transport_type.to_string()));
        let (app, client) = (req.app_code.as_deref().unwrap_or(""), req.client_code.as_deref().unwrap_or(""));
        let mut per_type = Vec::new();
        for service in &self.services {
            let Ok(names) = req.names_for(service.object_name()) else { continue };
            per_type.push((service.clone(), service.read_for_transport(ca, app, client, names).await?));
        }
        if req.json {
            let objects: Vec<JValue> = per_type
                .iter()
                .flat_map(|(s, list)| {
                    list.iter().map(move |e| {
                        let mut o = JMap::new();
                        o.insert("objectType".into(), JValue::Str(s.object_name().to_string()));
                        let data = s.to_data(e);
                        if !data.is_empty() {
                            o.insert("data".into(), JValue::Object(data));
                        }
                        JValue::Object(o)
                    })
                })
                .collect();
            to.insert("objects".into(), JValue::Array(objects));
            let body = to_jackson_pretty(&JValue::Object(to_jackson(&TRANSPORT, &to)));
            return Ok(TransportFile { content_type: "application/json", content_disposition: None, bytes: body.into_bytes() });
        }
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        let zerr = |e: zip::result::ZipError| AppError::Internal(e.into());
        let ioerr = |e: std::io::Error| AppError::Internal(e.into());
        zip.start_file("transport.json", opts).map_err(zerr)?;
        zip.write_all(to_jackson_pretty(&JValue::Object(to_jackson(&TRANSPORT, &to))).as_bytes()).map_err(ioerr)?;
        for (service, list) in &per_type {
            zip.add_directory(format!("{}/", service.object_name()), opts).map_err(zerr)?;
            for e in list {
                let file = format!("{}/{}.json", service.object_name(), str_field(e, "name").unwrap_or("").replace('/', SLASH_ESCAPE));
                zip.start_file(file, opts).map_err(zerr)?;
                zip.write_all(to_jackson_pretty(&JValue::Object(service.to_data(e))).as_bytes()).map_err(ioerr)?;
            }
        }
        let bytes = zip.finish().map_err(zerr)?.into_inner();
        Ok(TransportFile {
            content_type: "application/zip",
            content_disposition: Some(format!("attachment; filename={app}_{client}.{}", self.extension)),
            bytes,
        })
    }

    /// `createAndApply`: stores an uploaded transport (a zip carrying `transport.json`, or the
    /// JSON itself) and applies it. Answers the stored transport.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_and_apply(
        &self,
        ca: &ContextAuthentication,
        on_behalf: &OnBehalfOf,
        file_name: &str,
        bytes: &[u8],
        is_json: bool,
        application_code: Option<&str>,
        is_for_base_app: bool,
    ) -> AppResult<JMap> {
        let creating = |e: String| transport_error(self.cx(), "Creating", &e);
        let entity = if is_json || file_name.ends_with(".json") {
            match parse(bytes).map_err(|e| creating(e.to_string()))? {
                JValue::Object(m) => convert_json(&TRANSPORT, &m),
                _ => return Err(creating("not a transport".into())),
            }
        } else {
            let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| creating(e.to_string()))?;
            let mut f = zip.by_name("transport.json").map_err(|e| creating(e.to_string()))?;
            let mut text = Vec::new();
            f.read_to_end(&mut text).map_err(|e| creating(e.to_string()))?;
            let mut m = match parse(&text).map_err(|e| creating(e.to_string()))? {
                JValue::Object(m) => convert_json(&TRANSPORT, &m),
                _ => return Err(creating("not a transport".into())),
            };
            m.insert("encodedModl".into(), JValue::Str(base64_encode(bytes)));
            m
        };
        let transport = self.create(ca, entity).await?;
        self.apply_transport(ca, on_behalf, str_field(&transport, "id").unwrap_or_default(), application_code, is_for_base_app)
            .await?;
        Ok(transport)
    }

    /// `cleanupOlderThan`: drops import receipts older than the retention window (at least 7
    /// days), at most `limit` (1 to 500) per run, their version rows first.
    pub async fn cleanup_older_than(&self, retention_days: i64, limit: i64) -> AppResult<JMap> {
        let days = retention_days.max(MIN_RETENTION_DAYS);
        let cap = limit.clamp(1, MAX_CLEANUP_LIMIT);
        let cutoff = Clock { ms: Clock::now().ms - days * 86_400_000 }.stored();
        let backend = self.cx().backend();
        let find = Find::new(doc! {"createdAt": {"$lt": cutoff}})
            .limit(cap)
            .projection(doc! {"_id": 1, "name": 1, "appCode": 1, "clientCode": 1});
        let candidates = backend.find(self.svc.collection(), find).await?;
        let mut owners: Vec<((Bson, Bson), Vec<Bson>)> = Vec::new();
        for c in &candidates {
            let get = |k: &str| c.get(k).cloned().unwrap_or(Bson::Null);
            let owner = (get("appCode"), get("clientCode"));
            match owners.iter_mut().find(|(o, _)| *o == owner) {
                Some((_, names)) => names.push(get("name")),
                None => owners.push((owner, vec![get("name")])),
            }
        }
        let mut versions = 0;
        for ((app, client), names) in owners {
            let filter = doc! {"$and": [{"objectAppCode": app}, {"clientCode": client}, {"objectType": "TRANSPORT"}, {"objectName": {"$in": names}}]};
            versions += backend.delete_many("version", filter).await?;
        }
        let ids: Vec<Bson> = candidates.iter().filter_map(|c| c.get("_id").cloned()).collect();
        let transports = if ids.is_empty() { 0 } else { backend.delete_many(self.svc.collection(), doc! {"_id": {"$in": ids}}).await? };
        if transports > 0 {
            tracing::info!(transports, versions, kind = self.transport_type, days, "removed old transports");
        }
        let mut out = JMap::new();
        out.insert("transportsRemoved".into(), JValue::Int(transports as i64));
        out.insert("versionsRemoved".into(), JValue::Int(versions as i64));
        Ok(out)
    }
}

/// The JSON transport's objects grouped by type (`objectType` null ones left out).
fn group_objects(objects: &[JValue]) -> HashMap<String, Vec<JMap>> {
    let mut out: HashMap<String, Vec<JMap>> = HashMap::new();
    for o in objects {
        let Some(m) = o.as_object() else { continue };
        let Some(t) = str_field(m, "objectType") else { continue };
        let data = m.get("data").and_then(JValue::as_object).cloned().unwrap_or_default();
        out.entry(t.to_string()).or_default().push(data);
    }
    out
}

/// What `addObjectToService` needs from the transport being applied.
struct Apply<'a> {
    ca: &'a ContextAuthentication,
    for_app: Option<&'a str>,
    base: Option<&'a (String, bool)>,
    transport_name: &'a str,
}

impl Apply<'_> {
    /// `addObjectToService`: re-homed on the caller (or the owner security names), then
    /// created, or updated over the client's row of the same name.
    async fn add(&self, service: &dyn AnyService, mut e: JMap) -> AppResult<()> {
        if let Some(app) = self.for_app {
            e.insert("appCode".into(), JValue::Str(app.to_string()));
        }
        let mine = JValue::Str(self.ca.client_code().to_string());
        let (client, base) = match self.base {
            Some((code, true)) => (JValue::Str(code.clone()), JValue::Null),
            Some((code, false)) => (mine, JValue::Str(code.clone())),
            None => (mine, JValue::Null),
        };
        e.insert("clientCode".into(), client);
        e.insert("baseClientCode".into(), base);
        e.insert("id".into(), JValue::Null);
        e.insert("message".into(), JValue::Str(format!("From transport : {}", self.transport_name)));
        e.insert("version".into(), JValue::Int(1));
        let s = |k: &str| str_field(&e, k).unwrap_or("").to_string();
        let name = str_field(&e, "name").map(str::to_string);
        match service.read_to_transport(self.ca, name.as_deref(), &s("appCode"), &s("clientCode")).await? {
            Some((version, id)) => {
                e.insert("version".into(), JValue::Int(version));
                e.insert("id".into(), JValue::Str(id));
                service.update(self.ca, e).await?;
            }
            None => {
                service.create(self.ca, e).await?;
            }
        }
        Ok(())
    }
}

/// The transport document's `_id` for an inserted row, as a string.
pub fn id_string(b: &Bson) -> String {
    crate::bson_conv::to_java_string(b).java_to_string()
}

/// Days ago as a stored date (for tests of the sweep).
pub fn days_ago(days: i64) -> Bson {
    Bson::DateTime(DateTime::from_millis(Clock::now().ms - days * 86_400_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_like_java() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let e = base64_encode(s.as_bytes());
            assert_eq!(base64_decode(&e).unwrap(), s.as_bytes());
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("Zm8").unwrap(), b"fo", "padding is optional");
        assert!(base64_decode("Zm 8").is_err());
    }

    #[test]
    fn short_uuids_are_base62() {
        let a = short_uuid();
        assert!(!a.is_empty() && a.len() <= 22 && a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, short_uuid());
    }

    #[test]
    fn requests_parse_like_jackson() {
        let r = TransportRequest::from_json(&parse(br#"{"appCode":"a","objectList":{"Page":["x"],"Style":1},"fileType":"JSON"}"#).unwrap()).unwrap();
        assert!(r.json);
        assert_eq!(r.names_for("Page"), Ok(Some(&["x".to_string()][..])));
        assert_eq!(r.names_for("Style"), Ok(Some(&[][..])));
        assert_eq!(r.names_for("Theme"), Err(()));
        let r = TransportRequest::from_json(&parse(br#"{"fileType":"ZIP","objectList":{}}"#).unwrap()).unwrap();
        assert!(!r.json);
        assert_eq!(r.names_for("Page"), Ok(None));
        assert!(TransportRequest::from_json(&parse(br#"{"fileType":"TAR"}"#).unwrap()).is_err());
        assert!(!TransportRequest::from_json(&JValue::Null).unwrap().json);
    }

    #[test]
    fn json_objects_group_by_type() {
        let objects = match parse(br#"[{"objectType":"Page","data":{"name":"a"}},{"objectType":null},{"data":{}},1,{"objectType":"Page"}]"#).unwrap() {
            JValue::Array(a) => a,
            _ => panic!(),
        };
        let g = group_objects(&objects);
        assert_eq!(g.len(), 1);
        assert_eq!(g["Page"].len(), 2);
        assert_eq!(id_string(&Bson::String("x".into())), "x");
        assert!(matches!(days_ago(1), Bson::DateTime(_)));
    }
}
