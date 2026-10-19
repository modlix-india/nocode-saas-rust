//! Eureka's JSON, as the Java server writes it (Jackson, `EurekaJacksonCodec`) and as the
//! clients in use send it.
//!
//! Written exactly in Jackson's shape and field order: `"port":{"$":8104,"@enabled":"true"}`,
//! `dataCenterInfo` with `@class`, `lastUpdatedTimestamp` and `lastDirtyTimestamp` as strings,
//! the lease timestamps as numbers, `isCoordinatingDiscoveryServer` as a string, and an empty
//! metadata map as `{"@class":"java.util.Collections$EmptyMap"}`.
//!
//! Read leniently, because every client spells something differently: numbers may come as
//! strings and the other way round, `overriddenstatus` (py_eureka_client) or `overriddenStatus`
//! (Jackson), a lone `instance` or `application` as an object instead of an array, and missing
//! fields take Eureka's defaults.

use std::collections::BTreeMap;
use std::fmt;

use indexmap::IndexMap;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

pub const DEFAULT_DATA_CENTER_CLASS: &str = "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo";
/// What Jackson writes for an empty metadata map.
pub const EMPTY_MAP_CLASS: &str = "java.util.Collections$EmptyMap";
/// Eureka's default lease when a client sends none.
pub const DEFAULT_RENEWAL_SECS: u32 = 30;
pub const DEFAULT_DURATION_SECS: u32 = 90;

/// `InstanceStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Status {
    Up,
    Down,
    Starting,
    OutOfService,
    #[default]
    Unknown,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Up => "UP",
            Status::Down => "DOWN",
            Status::Starting => "STARTING",
            Status::OutOfService => "OUT_OF_SERVICE",
            Status::Unknown => "UNKNOWN",
        }
    }

    /// Eureka's `InstanceStatus.toEnum`: any case, and anything unrecognised is `UNKNOWN`.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "UP" => Status::Up,
            "DOWN" => Status::Down,
            "STARTING" => Status::Starting,
            "OUT_OF_SERVICE" => Status::OutOfService,
            _ => Status::Unknown,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Status {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Status::parse(&String::deserialize(d)?))
    }
}

/// What happened to an instance, in a delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ActionType {
    Added,
    Modified,
    Deleted,
}

impl ActionType {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionType::Added => "ADDED",
            ActionType::Modified => "MODIFIED",
            ActionType::Deleted => "DELETED",
        }
    }
}

/// `{"$": 8104, "@enabled": "true"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortInfo {
    pub port: u16,
    pub enabled: bool,
}

impl Serialize for PortInfo {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("$", &self.port)?;
        m.serialize_entry("@enabled", if self.enabled { "true" } else { "false" })?;
        m.end()
    }
}

impl<'de> Deserialize<'de> for PortInfo {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PortInfo;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a port number or {\"$\": port, \"@enabled\": flag}")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<PortInfo, E> {
                Ok(PortInfo { port: port_of(v as i64)?, enabled: true })
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<PortInfo, E> {
                Ok(PortInfo { port: port_of(v)?, enabled: true })
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<PortInfo, E> {
                Ok(PortInfo { port: port_of(int_of_str(v)?)?, enabled: true })
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<PortInfo, A::Error> {
                let mut port = 0;
                let mut enabled = true;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "$" => port = port_of(map.next_value::<Lenient>()?.0)?,
                        "@enabled" => enabled = map.next_value::<LenientBool>()?.0,
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(PortInfo { port, enabled })
            }
        }
        d.deserialize_any(V)
    }
}

fn port_of<E: de::Error>(v: i64) -> Result<u16, E> {
    u16::try_from(v).map_err(|_| E::custom(format!("port {v} is out of range")))
}

fn int_of_str<E: de::Error>(v: &str) -> Result<i64, E> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(0);
    }
    v.parse::<i64>().map_err(|_| E::custom(format!("{v:?} is not a number")))
}

/// A number that may arrive as a string (`"1792395662982"`); an empty string is 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Lenient(pub i64);

impl<'de> Deserialize<'de> for Lenient {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Lenient;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a number or a numeric string")
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Lenient, E> {
                Ok(Lenient(v))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Lenient, E> {
                i64::try_from(v).map(Lenient).map_err(|_| E::custom("number too large"))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Lenient, E> {
                Ok(Lenient(v as i64))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Lenient, E> {
                int_of_str(v).map(Lenient)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Lenient, E> {
                Ok(Lenient(0))
            }
        }
        d.deserialize_any(V)
    }
}

/// A flag that may arrive as `"true"` or `true`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LenientBool(pub bool);

impl<'de> Deserialize<'de> for LenientBool {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = LenientBool;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a boolean or \"true\"/\"false\"")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<LenientBool, E> {
                Ok(LenientBool(v))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<LenientBool, E> {
                Ok(LenientBool(v.trim().eq_ignore_ascii_case("true")))
            }
            fn visit_unit<E: de::Error>(self) -> Result<LenientBool, E> {
                Ok(LenientBool(false))
            }
        }
        d.deserialize_any(V)
    }
}

/// Metadata in the order it was sent. Values are strings on the wire; a client sending a number
/// gets it back as a string, as Jackson does. Jackson's `@class` marker is dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata(pub IndexMap<String, String>);

impl Serialize for Metadata {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len().max(1)))?;
        if self.0.is_empty() {
            m.serialize_entry("@class", EMPTY_MAP_CLASS)?;
        }
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Metadata;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a metadata object")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Metadata, E> {
                Ok(Metadata::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Metadata, A::Error> {
                let mut out = IndexMap::new();
                while let Some(k) = map.next_key::<String>()? {
                    let v: serde_json::Value = map.next_value()?;
                    if k == "@class" {
                        continue;
                    }
                    let v = match v {
                        serde_json::Value::Null => continue,
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    out.insert(k, v);
                }
                Ok(Metadata(out))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataCenterInfo {
    #[serde(rename = "@class", default = "default_dc_class")]
    pub class: String,
    #[serde(default = "default_dc_name")]
    pub name: String,
    /// Only Amazon's data centre info has metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

fn default_dc_class() -> String {
    DEFAULT_DATA_CENTER_CLASS.to_string()
}

fn default_dc_name() -> String {
    "MyOwn".to_string()
}

impl Default for DataCenterInfo {
    fn default() -> Self {
        Self { class: default_dc_class(), name: default_dc_name(), metadata: None }
    }
}

/// The lease: the client sends the two durations, the server fills in the timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseInfo {
    pub renewal_interval_in_secs: u32,
    pub duration_in_secs: u32,
    pub registration_timestamp: i64,
    pub last_renewal_timestamp: i64,
    pub eviction_timestamp: i64,
    pub service_up_timestamp: i64,
}

impl Default for LeaseInfo {
    fn default() -> Self {
        Self {
            renewal_interval_in_secs: DEFAULT_RENEWAL_SECS,
            duration_in_secs: DEFAULT_DURATION_SECS,
            registration_timestamp: 0,
            last_renewal_timestamp: 0,
            eviction_timestamp: 0,
            service_up_timestamp: 0,
        }
    }
}

impl<'de> Deserialize<'de> for LeaseInfo {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase", default)]
        struct Wire {
            renewal_interval_in_secs: Option<Lenient>,
            duration_in_secs: Option<Lenient>,
            registration_timestamp: Lenient,
            last_renewal_timestamp: Lenient,
            eviction_timestamp: Lenient,
            service_up_timestamp: Lenient,
        }
        let w = Wire::deserialize(d)?;
        // A zero or negative duration means "the default", as in Eureka.
        let secs = |v: Option<Lenient>, default: u32| match v {
            Some(Lenient(n)) if n > 0 => u32::try_from(n).unwrap_or(u32::MAX),
            _ => default,
        };
        Ok(LeaseInfo {
            renewal_interval_in_secs: secs(w.renewal_interval_in_secs, DEFAULT_RENEWAL_SECS),
            duration_in_secs: secs(w.duration_in_secs, DEFAULT_DURATION_SECS),
            registration_timestamp: w.registration_timestamp.0,
            last_renewal_timestamp: w.last_renewal_timestamp.0,
            eviction_timestamp: w.eviction_timestamp.0,
            service_up_timestamp: w.service_up_timestamp.0,
        })
    }
}

/// One registered instance. Fields are in the order Jackson writes them.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceInfo {
    pub instance_id: String,
    pub host_name: String,
    pub app: String,
    pub ip_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub status: Status,
    pub overridden_status: Status,
    pub port: PortInfo,
    pub secure_port: PortInfo,
    pub country_id: i64,
    pub data_center_info: DataCenterInfo,
    pub lease_info: LeaseInfo,
    pub metadata: Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_group_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_page_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_page_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_health_check_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_vip_address: Option<String>,
    #[serde(serialize_with = "bool_as_string")]
    pub is_coordinating_discovery_server: bool,
    #[serde(serialize_with = "i64_as_string")]
    pub last_updated_timestamp: i64,
    #[serde(serialize_with = "i64_as_string")]
    pub last_dirty_timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<ActionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asg_name: Option<String>,
}

fn bool_as_string<S: Serializer>(v: &bool, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(if *v { "true" } else { "false" })
}

fn i64_as_string<S: Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(v)
}

impl Default for InstanceInfo {
    fn default() -> Self {
        Self {
            instance_id: String::new(),
            host_name: String::new(),
            app: String::new(),
            ip_addr: String::new(),
            sid: None,
            status: Status::Up,
            overridden_status: Status::Unknown,
            port: PortInfo { port: 7001, enabled: true },
            secure_port: PortInfo { port: 7002, enabled: false },
            country_id: 1,
            data_center_info: DataCenterInfo::default(),
            lease_info: LeaseInfo::default(),
            metadata: Metadata::default(),
            app_group_name: None,
            home_page_url: None,
            status_page_url: None,
            health_check_url: None,
            secure_health_check_url: None,
            vip_address: None,
            secure_vip_address: None,
            is_coordinating_discovery_server: false,
            last_updated_timestamp: 0,
            last_dirty_timestamp: 0,
            action_type: None,
            asg_name: None,
        }
    }
}

impl<'de> Deserialize<'de> for InstanceInfo {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase", default)]
        struct Wire {
            instance_id: Option<String>,
            host_name: Option<String>,
            app: Option<String>,
            ip_addr: Option<String>,
            sid: Option<String>,
            status: Option<Status>,
            overridden_status: Option<Status>,
            /// py_eureka_client's spelling (and Eureka's XML element name).
            overriddenstatus: Option<Status>,
            port: Option<PortInfo>,
            secure_port: Option<PortInfo>,
            country_id: Option<Lenient>,
            data_center_info: Option<DataCenterInfo>,
            lease_info: Option<LeaseInfo>,
            metadata: Option<Metadata>,
            app_group_name: Option<String>,
            home_page_url: Option<String>,
            status_page_url: Option<String>,
            health_check_url: Option<String>,
            secure_health_check_url: Option<String>,
            vip_address: Option<String>,
            secure_vip_address: Option<String>,
            is_coordinating_discovery_server: Option<LenientBool>,
            last_updated_timestamp: Option<Lenient>,
            last_dirty_timestamp: Option<Lenient>,
            action_type: Option<ActionType>,
            asg_name: Option<String>,
        }
        let w = Wire::deserialize(d)?;
        let def = InstanceInfo::default();
        let host_name = w.host_name.unwrap_or_default();
        // Eureka's `InstanceInfo.getId()`: the instance id, else the host name.
        let instance_id = w.instance_id.filter(|s| !s.is_empty()).unwrap_or_else(|| host_name.clone());
        Ok(InstanceInfo {
            instance_id,
            host_name,
            app: w.app.unwrap_or_default().to_ascii_uppercase(),
            ip_addr: w.ip_addr.unwrap_or_default(),
            sid: w.sid,
            status: w.status.unwrap_or(Status::Up),
            overridden_status: w.overridden_status.or(w.overriddenstatus).unwrap_or(Status::Unknown),
            port: w.port.unwrap_or(def.port),
            secure_port: w.secure_port.unwrap_or(def.secure_port),
            country_id: w.country_id.map_or(1, |c| c.0),
            data_center_info: w.data_center_info.unwrap_or_default(),
            lease_info: w.lease_info.unwrap_or_default(),
            metadata: w.metadata.unwrap_or_default(),
            app_group_name: w.app_group_name,
            home_page_url: w.home_page_url,
            status_page_url: w.status_page_url,
            health_check_url: w.health_check_url,
            secure_health_check_url: w.secure_health_check_url,
            vip_address: w.vip_address,
            secure_vip_address: w.secure_vip_address,
            is_coordinating_discovery_server: w.is_coordinating_discovery_server.is_some_and(|b| b.0),
            last_updated_timestamp: w.last_updated_timestamp.map_or(0, |t| t.0),
            last_dirty_timestamp: w.last_dirty_timestamp.map_or(0, |t| t.0),
            action_type: w.action_type,
            asg_name: w.asg_name,
        })
    }
}

impl InstanceInfo {
    /// `http://<ipAddr>:<port>`, where a caller sends traffic.
    pub fn base_url(&self) -> String {
        format!("http://{}:{}", self.ip_addr, self.port.port)
    }
}

/// `{"instance": {...}}`, the body of a registration and of a single-instance GET.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceEnvelope {
    pub instance: InstanceInfo,
}

/// The instances of one app.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Application {
    pub name: String,
    pub instances: Vec<InstanceInfo>,
}

impl Serialize for Application {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Application", 2)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("instance", &self.instances)?;
        st.end()
    }
}

/// One element or a list: older Eureka servers send a lone instance (or app) as an object.
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    Many(Vec<T>),
    One(T),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::Many(v) => v,
            OneOrMany::One(t) => vec![t],
        }
    }
}

impl<'de> Deserialize<'de> for Application {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Wire {
            name: String,
            instance: Option<OneOrMany<InstanceInfo>>,
        }
        let w = Wire::deserialize(d)?;
        Ok(Application { name: w.name.to_ascii_uppercase(), instances: w.instance.map(OneOrMany::into_vec).unwrap_or_default() })
    }
}

/// `{"application": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationEnvelope {
    pub application: Application,
}

/// The registry (or a delta of it).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Applications {
    /// `versions__delta`: "1" for the full registry, the change version for a delta.
    pub versions_delta: String,
    /// `apps__hashcode`, see [`reconcile_hashcode`].
    pub apps_hashcode: String,
    pub applications: Vec<Application>,
}

impl Serialize for Applications {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Applications", 3)?;
        st.serialize_field("versions__delta", &self.versions_delta)?;
        st.serialize_field("apps__hashcode", &self.apps_hashcode)?;
        st.serialize_field("application", &self.applications)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for Applications {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Wire {
            #[serde(rename = "versions__delta")]
            versions_delta: Option<serde_json::Value>,
            #[serde(rename = "apps__hashcode")]
            apps_hashcode: Option<String>,
            application: Option<OneOrMany<Application>>,
        }
        let w = Wire::deserialize(d)?;
        let versions_delta = match w.versions_delta {
            Some(serde_json::Value::String(s)) => s,
            Some(serde_json::Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        Ok(Applications {
            versions_delta,
            apps_hashcode: w.apps_hashcode.unwrap_or_default(),
            applications: w.application.map(OneOrMany::into_vec).unwrap_or_default(),
        })
    }
}

/// `{"applications": {...}}`, the body of `GET /eureka/apps` and `/apps/delta`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationsEnvelope {
    pub applications: Applications,
}

impl Applications {
    /// Every instance of every app.
    pub fn instances(&self) -> impl Iterator<Item = &InstanceInfo> {
        self.applications.iter().flat_map(|a| a.instances.iter())
    }

    pub fn is_empty(&self) -> bool {
        self.instances().next().is_none()
    }

    /// The app named `name` (any case).
    pub fn application(&self, name: &str) -> Option<&Application> {
        self.applications.iter().find(|a| a.name.eq_ignore_ascii_case(name))
    }

    /// Base URLs of `app`'s UP instances, in registry order.
    pub fn up_urls(&self, app: &str) -> Vec<String> {
        self.application(app)
            .map(|a| a.instances.iter().filter(|i| i.status == Status::Up).map(InstanceInfo::base_url).collect())
            .unwrap_or_default()
    }

    /// Eureka's reconcile hash code of these instances.
    pub fn hashcode(&self) -> String {
        reconcile_hashcode(self.instances().map(|i| i.status))
    }

    /// What a router cares about: each instance's app, id, status, address and metadata. Two
    /// registries with the same membership differ only in lease timestamps.
    pub fn membership(&self) -> Vec<(String, String, Status, String, Metadata)> {
        let mut m: Vec<_> = self
            .instances()
            .map(|i| (i.app.clone(), i.instance_id.clone(), i.status, i.base_url(), i.metadata.clone()))
            .collect();
        m.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        m
    }
}

/// Eureka's `apps__hashcode`: each status with its count, sorted by status name, as
/// `STATUS_count_` (`OUT_OF_SERVICE_1_UP_2_`). Empty for an empty registry. Clients compare it
/// with their own copy after applying a delta and fetch everything again when it differs.
pub fn reconcile_hashcode(statuses: impl Iterator<Item = Status>) -> String {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in statuses {
        *counts.entry(s.as_str()).or_default() += 1;
    }
    counts.iter().map(|(s, n)| format!("{s}_{n}_")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn statuses() {
        for s in [Status::Up, Status::Down, Status::Starting, Status::OutOfService, Status::Unknown] {
            assert_eq!(Status::parse(s.as_str()), s);
            assert_eq!(s.to_string(), s.as_str());
        }
        assert_eq!(Status::parse(" out_of_service "), Status::OutOfService);
        assert_eq!(Status::parse("nonsense"), Status::Unknown);
        assert_eq!(serde_json::from_value::<Status>(json!("up")).unwrap(), Status::Up);
        for a in [ActionType::Added, ActionType::Modified, ActionType::Deleted] {
            assert_eq!(serde_json::to_value(a).unwrap(), json!(a.as_str()));
        }
    }

    #[test]
    fn hashcode_is_sorted_status_counts() {
        use Status::*;
        assert_eq!(reconcile_hashcode([].into_iter()), "");
        assert_eq!(reconcile_hashcode([Up, OutOfService, Up].into_iter()), "OUT_OF_SERVICE_1_UP_2_");
        assert_eq!(reconcile_hashcode([Up, Unknown].into_iter()), "UNKNOWN_1_UP_1_");
        assert_eq!(reconcile_hashcode([Up, Down, Starting].into_iter()), "DOWN_1_STARTING_1_UP_1_");
    }

    #[test]
    fn reads_every_client_spelling() {
        // py_eureka_client: overriddenstatus, all lease fields, empty metadata, string timestamps.
        let py: InstanceEnvelope = serde_json::from_value(json!({"instance": {
            "instanceId": "", "hostName": "h2", "app": "ai", "ipAddr": "10.1.1.2",
            "status": "UP", "overriddenstatus": "out_of_service",
            "port": {"$": "8000", "@enabled": "true"}, "securePort": {"$": 9443, "@enabled": false},
            "countryId": "1", "dataCenterInfo": {"@class": "x.Y", "name": "MyOwn"},
            "leaseInfo": {"renewalIntervalInSecs": 30, "durationInSecs": "0", "registrationTimestamp": 0},
            "metadata": {"a": "b", "n": 5, "z": null, "@class": "java.util.Collections$EmptyMap"},
            "isCoordinatingDiscoveryServer": "false",
            "lastUpdatedTimestamp": "1792395662982", "lastDirtyTimestamp": 1792395662983u64
        }}))
        .unwrap();
        let i = py.instance;
        assert_eq!(i.instance_id, "h2", "an empty instance id falls back to the host name");
        assert_eq!(i.app, "AI");
        assert_eq!(i.overridden_status, Status::OutOfService);
        assert_eq!(i.port, PortInfo { port: 8000, enabled: true });
        assert_eq!(i.secure_port, PortInfo { port: 9443, enabled: false });
        assert_eq!(i.lease_info.duration_in_secs, DEFAULT_DURATION_SECS);
        assert_eq!(i.metadata.0.get("n").map(String::as_str), Some("5"));
        assert_eq!(i.metadata.0.len(), 2);
        assert_eq!((i.last_updated_timestamp, i.last_dirty_timestamp), (1792395662982, 1792395662983));
        assert_eq!(i.data_center_info.class, "x.Y");
        assert_eq!(i.base_url(), "http://10.1.1.2:8000");

        // A bare minimum: Eureka's defaults.
        let bare: InstanceInfo = serde_json::from_value(json!({"hostName": "h", "port": 81, "metadata": null,
            "isCoordinatingDiscoveryServer": true, "lastDirtyTimestamp": "", "dataCenterInfo": {}})).unwrap();
        assert_eq!((bare.status, bare.overridden_status, bare.port.port), (Status::Up, Status::Unknown, 81));
        assert_eq!(bare.lease_info, LeaseInfo::default());
        assert_eq!(bare.data_center_info, DataCenterInfo::default());
        assert!(bare.is_coordinating_discovery_server);
        assert_eq!(bare.last_dirty_timestamp, 0);
        let p: InstanceInfo = serde_json::from_value(json!({"port": "82", "countryId": 2.0})).unwrap();
        assert_eq!((p.port.port, p.country_id), (82, 2));
        let p: InstanceInfo = serde_json::from_value(json!({"port": {"$": 83, "other": 1}, "lastDirtyTimestamp": null})).unwrap();
        assert_eq!(p.port, PortInfo { port: 83, enabled: true });
        let odd: InstanceInfo = serde_json::from_value(json!({
            "leaseInfo": {"registrationTimestamp": null, "lastRenewalTimestamp": -5},
            "port": {"$": 84, "@enabled": null}
        }))
        .unwrap();
        assert_eq!((odd.lease_info.registration_timestamp, odd.lease_info.last_renewal_timestamp), (0, -5));
        assert!(!odd.port.enabled);

        for bad in [
            json!({"port": 70000}),
            json!({"port": -1}),
            json!({"port": "x"}),
            json!({"port": true}),
            json!({"lastDirtyTimestamp": "soon"}),
            json!({"lastDirtyTimestamp": 18446744073709551615u64}),
            json!({"isCoordinatingDiscoveryServer": 3}),
            json!({"metadata": 3}),
            json!({"lastDirtyTimestamp": []}),
        ] {
            assert!(serde_json::from_value::<InstanceInfo>(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn writes_jacksons_shape() {
        let mut i = InstanceInfo {
            instance_id: "h1:files:8104".into(),
            host_name: "10.1.1.1".into(),
            app: "FILES".into(),
            ip_addr: "10.1.1.1".into(),
            last_dirty_timestamp: 5,
            last_updated_timestamp: 6,
            ..Default::default()
        };
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["port"], json!({"$": 7001, "@enabled": "true"}));
        assert_eq!(v["metadata"], json!({"@class": EMPTY_MAP_CLASS}));
        assert_eq!(v["lastDirtyTimestamp"], "5");
        assert_eq!(v["isCoordinatingDiscoveryServer"], "false");
        assert!(v.get("actionType").is_none() && v.get("homePageUrl").is_none());
        i.metadata.0.insert("k".into(), "v".into());
        i.is_coordinating_discovery_server = true;
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["metadata"], json!({"k": "v"}));
        assert_eq!(v["isCoordinatingDiscoveryServer"], "true");
        let back: InstanceInfo = serde_json::from_value(v).unwrap();
        assert_eq!(back, i);
    }

    /// The Java server's JSON, read and written again, is byte for byte what it wrote.
    #[test]
    fn json_round_trips_the_java_goldens() {
        for golden in [
            include_str!("../tests/goldens/apps.json"),
            include_str!("../tests/goldens/apps_oos.json"),
            include_str!("../tests/goldens/delta.json"),
            include_str!("../tests/goldens/empty.json"),
        ] {
            let parsed: ApplicationsEnvelope = serde_json::from_str(golden).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), golden);
        }
        let app = include_str!("../tests/goldens/app.json");
        assert_eq!(serde_json::to_string(&serde_json::from_str::<ApplicationEnvelope>(app).unwrap()).unwrap(), app);
        for one in [include_str!("../tests/goldens/instance.json"), include_str!("../tests/goldens/conflict.json")] {
            assert_eq!(serde_json::to_string(&serde_json::from_str::<InstanceEnvelope>(one).unwrap()).unwrap(), one);
        }
        let oos = serde_json::from_str::<ApplicationsEnvelope>(include_str!("../tests/goldens/apps_oos.json")).unwrap();
        assert_eq!(oos.applications.hashcode(), oos.applications.apps_hashcode, "our hash code is the Java one");
        // What the Rust and py clients send register as the Java server read them.
        for body in [include_str!("../tests/goldens/register_rust.json"), include_str!("../tests/goldens/register_py.json")] {
            let i = serde_json::from_str::<InstanceEnvelope>(body).unwrap().instance;
            assert!(i.port.enabled && !i.secure_port.enabled && i.status == Status::Up);
        }
    }

    #[test]
    fn applications_helpers_and_shapes() {
        let one = json!({"applications": {"versions__delta": 3, "apps__hashcode": "UP_1_",
            "application": {"name": "files", "instance": {"hostName": "a", "ipAddr": "1.1.1.1", "port": 1}}}});
        let apps = serde_json::from_value::<ApplicationsEnvelope>(one).unwrap().applications;
        assert_eq!(apps.versions_delta, "3");
        assert_eq!(apps.application("Files").unwrap().name, "FILES");
        assert_eq!(apps.up_urls("files"), vec!["http://1.1.1.1:1"]);
        assert_eq!(apps.up_urls("none"), Vec::<String>::new());
        assert_eq!(apps.hashcode(), "UP_1_");
        assert!(!apps.is_empty());
        assert_eq!(apps.membership().len(), 1);

        let empty: ApplicationsEnvelope =
            serde_json::from_value(json!({"applications": {"versions__delta": null, "application": []}})).unwrap();
        assert!(empty.applications.is_empty());
        assert_eq!(empty.applications.versions_delta, "");
        let none: Application = serde_json::from_value(json!({"name": "x"})).unwrap();
        assert!(none.instances.is_empty());

        let out = serde_json::to_string(&ApplicationsEnvelope { applications: Applications::default() }).unwrap();
        assert_eq!(out, r#"{"applications":{"versions__delta":"","apps__hashcode":"","application":[]}}"#);
        let env = ApplicationEnvelope { application: Application { name: "X".into(), instances: vec![] } };
        assert_eq!(serde_json::to_string(&env).unwrap(), r#"{"application":{"name":"X","instance":[]}}"#);
    }
}
