//! The registry protocol's XML, as the Java server writes it (XStream, pretty printed with two spaces, no
//! declaration).
//!
//! py_eureka_client 0.11.10 reads only XML, with ElementTree, and throws when `<port>` has no
//! `enabled` attribute, when `<dataCenterInfo>` has no `class`, or when a numeric element is
//! present but empty. So every one of those is always written, from typed fields that cannot be
//! empty. Element names and order follow the Java output exactly (see the goldens in
//! `tests/goldens`, captured from the Java registry server).

use std::fmt::Write;

use crate::wire::{Application, Applications, InstanceInfo, Metadata, EMPTY_MAP_CLASS};

/// `<applications>`, the body of `GET /eureka/apps` and `/apps/delta`.
pub fn applications(apps: &Applications) -> String {
    let mut w = Xml::default();
    w.open("applications", 0);
    w.leaf("versions__delta", &apps.versions_delta, 1);
    w.leaf("apps__hashcode", &apps.apps_hashcode, 1);
    for app in &apps.applications {
        application_at(&mut w, app, 1);
    }
    w.close("applications", 0);
    w.finish()
}

/// `<application>`, the body of `GET /eureka/apps/{APP}`.
pub fn application(app: &Application) -> String {
    let mut w = Xml::default();
    application_at(&mut w, app, 0);
    w.finish()
}

/// `<instance>`, the body of `GET /eureka/apps/{APP}/{ID}`.
pub fn instance(i: &InstanceInfo) -> String {
    let mut w = Xml::default();
    instance_at(&mut w, i, 0);
    w.finish()
}

fn application_at(w: &mut Xml, app: &Application, depth: usize) {
    w.open("application", depth);
    w.leaf("name", &app.name, depth + 1);
    for i in &app.instances {
        instance_at(w, i, depth + 1);
    }
    w.close("application", depth);
}

fn instance_at(w: &mut Xml, i: &InstanceInfo, d: usize) {
    let c = d + 1;
    w.open("instance", d);
    w.leaf("instanceId", &i.instance_id, c);
    w.leaf("hostName", &i.host_name, c);
    w.leaf("app", &i.app, c);
    w.leaf("ipAddr", &i.ip_addr, c);
    if let Some(sid) = &i.sid {
        w.leaf("sid", sid, c);
    }
    w.leaf("status", i.status.as_str(), c);
    w.leaf("overriddenstatus", i.overridden_status.as_str(), c);
    w.port("port", i.port.port, i.port.enabled, c);
    w.port("securePort", i.secure_port.port, i.secure_port.enabled, c);
    w.leaf("countryId", &i.country_id.to_string(), c);
    w.line(c, &format!("<dataCenterInfo class=\"{}\">", escape(&i.data_center_info.class)));
    w.leaf("name", &i.data_center_info.name, c + 1);
    if let Some(m) = &i.data_center_info.metadata {
        metadata_at(w, m, c + 1);
    }
    w.close("dataCenterInfo", c);
    let l = &i.lease_info;
    w.open("leaseInfo", c);
    w.leaf("renewalIntervalInSecs", &l.renewal_interval_in_secs.to_string(), c + 1);
    w.leaf("durationInSecs", &l.duration_in_secs.to_string(), c + 1);
    w.leaf("registrationTimestamp", &l.registration_timestamp.to_string(), c + 1);
    w.leaf("lastRenewalTimestamp", &l.last_renewal_timestamp.to_string(), c + 1);
    w.leaf("evictionTimestamp", &l.eviction_timestamp.to_string(), c + 1);
    w.leaf("serviceUpTimestamp", &l.service_up_timestamp.to_string(), c + 1);
    w.close("leaseInfo", c);
    metadata_at(w, &i.metadata, c);
    let optional = [
        ("appGroupName", &i.app_group_name),
        ("homePageUrl", &i.home_page_url),
        ("statusPageUrl", &i.status_page_url),
        ("healthCheckUrl", &i.health_check_url),
        ("secureHealthCheckUrl", &i.secure_health_check_url),
        ("vipAddress", &i.vip_address),
        ("secureVipAddress", &i.secure_vip_address),
    ];
    for (name, value) in optional {
        if let Some(v) = value {
            w.leaf(name, v, c);
        }
    }
    w.leaf("isCoordinatingDiscoveryServer", if i.is_coordinating_discovery_server { "true" } else { "false" }, c);
    w.leaf("lastUpdatedTimestamp", &i.last_updated_timestamp.to_string(), c);
    w.leaf("lastDirtyTimestamp", &i.last_dirty_timestamp.to_string(), c);
    if let Some(a) = i.action_type {
        w.leaf("actionType", a.as_str(), c);
    }
    if let Some(asg) = &i.asg_name {
        w.leaf("asgName", asg, c);
    }
    w.close("instance", d);
}

/// Metadata keys become element names. XStream encodes `_` as `__` and `$` as `_-`, so a Java
/// client reads the key back unchanged; a key that still is not a valid XML name is left out,
/// because one bad element would make every py client fail to read the whole registry.
fn metadata_at(w: &mut Xml, m: &Metadata, d: usize) {
    let entries: Vec<(String, &String)> = m.0.iter().filter_map(|(k, v)| element_name(k).map(|n| (n, v))).collect();
    if entries.is_empty() {
        w.line(d, &format!("<metadata class=\"{EMPTY_MAP_CLASS}\"/>"));
        return;
    }
    w.open("metadata", d);
    for (name, v) in entries {
        w.leaf(&name, v, d + 1);
    }
    w.close("metadata", d);
}

fn element_name(key: &str) -> Option<String> {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        match ch {
            '_' => out.push_str("__"),
            '$' => out.push_str("_-"),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => out.push(c),
            _ => return None,
        }
    }
    let first = out.chars().next()?;
    (first.is_ascii_alphabetic() || first == '_').then_some(out)
}

/// Text and attribute escaping as XStream does it. Characters XML 1.0 cannot carry at all are
/// dropped.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#xd;"),
            '\t' | '\n' => out.push(ch),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Default)]
struct Xml {
    out: String,
}

impl Xml {
    fn line(&mut self, depth: usize, s: &str) {
        if !self.out.is_empty() {
            self.out.push('\n');
        }
        for _ in 0..depth {
            self.out.push_str("  ");
        }
        self.out.push_str(s);
    }

    fn open(&mut self, name: &str, depth: usize) {
        self.line(depth, &format!("<{name}>"));
    }

    fn close(&mut self, name: &str, depth: usize) {
        self.line(depth, &format!("</{name}>"));
    }

    fn leaf(&mut self, name: &str, text: &str, depth: usize) {
        let mut s = String::new();
        let _ = write!(s, "<{name}>{}</{name}>", escape(text));
        self.line(depth, &s);
    }

    fn port(&mut self, name: &str, port: u16, enabled: bool, depth: usize) {
        self.line(depth, &format!("<{name} enabled=\"{enabled}\">{port}</{name}>"));
    }

    fn finish(self) -> String {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ApplicationEnvelope, ApplicationsEnvelope, InstanceEnvelope, DataCenterInfo};

    fn apps(json: &str) -> Applications {
        serde_json::from_str::<ApplicationsEnvelope>(json).unwrap().applications
    }

    /// Every XML golden from the Java server, rendered from the JSON the same server answered
    /// for the same registry state.
    #[test]
    fn matches_the_java_server() {
        let full = apps(include_str!("../tests/goldens/apps.json"));
        assert_eq!(applications(&full), include_str!("../tests/goldens/apps.xml"));
        assert_eq!(applications(&apps(include_str!("../tests/goldens/empty.json"))), include_str!("../tests/goldens/empty.xml"));

        let app: ApplicationEnvelope = serde_json::from_str(include_str!("../tests/goldens/app.json")).unwrap();
        assert_eq!(application(&app.application), include_str!("../tests/goldens/app.xml"));

        // The AI instance at registration, as GET /eureka/apps/AI/{id} wrote it.
        let ai = &full.application("AI").unwrap().instances[0];
        assert_eq!(instance(ai), include_str!("../tests/goldens/instance.xml"));

        // The delta after a cancel: DELETED with an eviction timestamp. The two captures were
        // separate requests, so only the delta version differs.
        let mut delta = apps(include_str!("../tests/goldens/delta.json"));
        let xml = include_str!("../tests/goldens/delta.xml");
        let version = xml.split("<versions__delta>").nth(1).unwrap().split('<').next().unwrap();
        delta.versions_delta = version.to_string();
        assert_eq!(applications(&delta), xml);
    }

    #[test]
    fn writes_what_py_eureka_client_needs() {
        let mut i: InstanceInfo = serde_json::from_str::<InstanceEnvelope>(include_str!("../tests/goldens/register_py.json"))
            .unwrap()
            .instance;
        i.metadata.0.insert("with_under$core".into(), "a<b & \"c\" 'd'\r\u{1}".into());
        i.metadata.0.insert("bad key".into(), "x".into());
        i.metadata.0.insert("9lives".into(), "x".into());
        i.metadata.0.insert(String::new(), "x".into());
        i.sid = Some("s".into());
        i.app_group_name = Some("g".into());
        i.asg_name = Some("asg".into());
        i.is_coordinating_discovery_server = true;
        i.data_center_info = DataCenterInfo { metadata: Some(Default::default()), ..Default::default() };
        let x = instance(&i);
        assert!(x.contains("<port enabled=\"true\">8000</port>"));
        assert!(x.contains("<securePort enabled=\"false\">9443</securePort>"));
        assert!(x.contains("<dataCenterInfo class=\"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo\">"));
        assert!(x.contains("<with__under_-core>a&lt;b &amp; &quot;c&quot; &apos;d&apos;&#xd;</with__under_-core>"), "{x}");
        assert!(!x.contains("bad key") && !x.contains("9lives") && !x.contains("<>"));
        assert!(x.contains("<sid>s</sid>") && x.contains("<appGroupName>g</appGroupName>") && x.contains("<asgName>asg</asgName>"));
        assert!(x.contains("<isCoordinatingDiscoveryServer>true</isCoordinatingDiscoveryServer>"));
        assert!(x.contains("    <metadata class=\"java.util.Collections$EmptyMap\"/>"), "empty data centre metadata");
        for numeric in ["countryId", "renewalIntervalInSecs", "durationInSecs", "registrationTimestamp", "lastRenewalTimestamp",
            "evictionTimestamp", "serviceUpTimestamp", "lastUpdatedTimestamp", "lastDirtyTimestamp"]
        {
            assert!(!x.contains(&format!("<{numeric}></{numeric}>")), "{numeric} is never empty");
        }
        assert_eq!(escape("tab\tnl\n\u{fffe}>"), "tab\tnl\n&gt;");
    }
}
