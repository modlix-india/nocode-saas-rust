//! oci-config's `rust/units.toml`: what `tools/render_config.py` hard-coded (the units, the
//! settings read from Java, the database prefixes, the secrets and the ai and ssr variables),
//! plus each secret's place in the units' documents, the live keys and the discovery mode per
//! environment.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Where the manifest sits in oci-config.
pub const PATH: &str = "rust/units.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Keys every unit applies in place (prefixes of a unit's document).
    #[serde(default)]
    pub live: Vec<String>,
    pub gateway_url: String,
    #[serde(default)]
    pub gateway_pair: Vec<String>,
    pub env: BTreeMap<String, EnvSpec>,
    pub units: Vec<UnitSpec>,
    pub db_prefix: BTreeMap<String, String>,
    pub settings: Vec<SettingSpec>,
    pub secrets: Vec<SecretSpec>,
    pub ai: AppEnvSpec,
    pub ssr: AppEnvSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Discovery {
    /// `http://<unit>:<port>`: the network alias of the unit's containers.
    Alias,
    /// The registry: `eureka:<NAME>` in the gateway, the gateway pair elsewhere.
    Lighthouse,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSpec {
    pub discovery: Discovery,
    #[serde(default)]
    pub doubled: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSpec {
    pub name: String,
    pub port: u16,
    /// The Java service whose settings the unit reads.
    pub service: String,
    /// Its name in the registry; default the unit's name in capitals.
    pub registry: Option<String>,
    #[serde(default)]
    pub live: Vec<String>,
}

impl UnitSpec {
    pub fn registry_name(&self) -> String {
        self.registry.clone().unwrap_or_else(|| self.name.to_ascii_uppercase())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Str,
    Int,
    Bool,
}

impl Kind {
    /// Python's `kind.__name__`, as the script's messages print it.
    pub fn py_name(self) -> &'static str {
        match self {
            Kind::Str => "str",
            Kind::Int => "int",
            Kind::Bool => "bool",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingSpec {
    pub name: String,
    /// The Java key; default the name.
    pub key: Option<String>,
    pub kind: Kind,
    /// Java's `@Value` default, used when the key is unset.
    pub default: Option<toml::Value>,
    #[serde(default)]
    pub required: bool,
}

impl SettingSpec {
    pub fn java_key(&self) -> &str {
        self.key.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpec {
    pub name: String,
    pub service: String,
    /// The Java key, or `mq` for the AMQP URI.
    pub key: String,
    pub required: bool,
    /// Where it sits in a unit's document (`database.password`).
    pub path: String,
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VarKind {
    Gateway,
    Str,
    Set,
    Bool,
    Or,
    Nullish,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppVar {
    pub name: String,
    pub keys: Vec<String>,
    pub kind: VarKind,
    #[serde(default)]
    pub required: bool,
    pub only_with: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Then {
    pub name: String,
    pub value: String,
    pub when: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppEnvSpec {
    pub env: Vec<AppVar>,
    #[serde(default)]
    pub then: Vec<Then>,
    #[serde(default)]
    pub unmapped: Vec<String>,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self> {
        let m: Manifest = toml::from_str(text).with_context(|| format!("{PATH} is not a valid manifest"))?;
        m.check()?;
        Ok(m)
    }

    fn check(&self) -> Result<()> {
        let mut names = BTreeSet::new();
        for u in &self.units {
            if !names.insert(u.name.as_str()) {
                bail!("{PATH}: unit {} is listed twice", u.name);
            }
        }
        for s in &self.settings {
            if s.required == s.default.is_some() {
                bail!("{PATH}: setting {} needs either required = true or a default", s.name);
            }
        }
        for s in &self.secrets {
            if let Some(u) = s.units.iter().find(|u| !names.contains(u.as_str())) {
                bail!("{PATH}: secret {} names an unknown unit {u}", s.name);
            }
        }
        for (env, spec) in &self.env {
            if let Some(u) = spec.doubled.iter().find(|u| !names.contains(u.as_str())) {
                bail!("{PATH}: [env.{env}] doubled names an unknown unit {u}");
            }
        }
        Ok(())
    }

    pub fn unit(&self, name: &str) -> Option<&UnitSpec> {
        self.units.iter().find(|u| u.name == name)
    }

    pub fn setting(&self, name: &str) -> Option<&SettingSpec> {
        self.settings.iter().find(|s| s.name == name)
    }

    /// The secrets a unit gets.
    pub fn secrets_of<'a>(&'a self, unit: &'a str) -> impl Iterator<Item = &'a SecretSpec> + 'a {
        self.secrets.iter().filter(move |s| s.units.iter().any(|u| u == unit))
    }

    /// The keys a unit applies live: the shared ones, then its own.
    pub fn live_of(&self, unit: &str) -> Vec<String> {
        let mut out = self.live.clone();
        if let Some(u) = self.unit(unit) {
            out.extend(u.live.iter().cloned());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/oci-config/rust/units.toml");

    #[test]
    fn the_fixture_manifest_holds_what_the_script_hard_coded() {
        let m = Manifest::parse(FIXTURE).unwrap();
        assert_eq!(m.units.len(), 15);
        assert_eq!(m.unit("gateway-rust").unwrap().registry_name(), "GATEWAY");
        assert_eq!(m.unit("core-exec").unwrap().registry_name(), "CORE-EXEC");
        assert_eq!(m.env["prod"].doubled.len(), 8);
        assert_eq!(m.env["dev"].discovery, Discovery::Alias);
        assert_eq!(m.settings.len(), 17);
        assert_eq!(m.setting("jwt.token.default.refresh").unwrap().default, Some(toml::Value::Integer(10)));
        assert_eq!(m.setting("ui.jsURL").unwrap().java_key(), "ui.jsURL");
        assert_eq!(m.secrets.len(), 16);
        assert_eq!(m.secrets_of("multi").count(), 0);
        assert_eq!(m.secrets_of("security-auth").map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["MODLIX__REDIS__URL", "MODLIX__JWT__KEY", "MODLIX__MQ__URI", "MODLIX__SMS__TWO_FACTOR_API_KEY", "SECURITY_DB_PASSWORD"]);
        assert_eq!(m.live_of("gateway-rust"), ["telemetry.log_level", "features", "routes", "pools"]);
        assert_eq!(m.live_of("nope"), ["telemetry.log_level", "features"]);
        assert_eq!(m.ai.env.len(), 26);
        assert_eq!(m.ssr.env.len(), 10);
        assert_eq!(Kind::Int.py_name(), "int");
        assert_eq!((Kind::Str.py_name(), Kind::Bool.py_name()), ("str", "bool"));
    }

    #[test]
    fn mistakes_are_refused() {
        let twice = FIXTURE.replace("name = \"security-internal\"", "name = \"security-auth\"");
        assert!(Manifest::parse(&twice).unwrap_err().to_string().contains("listed twice"));
        let both = FIXTURE.replace("kind = \"str\"\nrequired = true", "kind = \"str\"\nrequired = true\ndefault = \"x\"");
        assert!(Manifest::parse(&both).unwrap_err().to_string().contains("either required"));
        let unknown = FIXTURE.replace("units = [\"ui-shell\"]", "units = [\"ui-nope\"]");
        assert!(Manifest::parse(&unknown).unwrap_err().to_string().contains("unknown unit ui-nope"));
        let doubled = FIXTURE.replace("doubled = [\"core-exec\",", "doubled = [\"core-nope\",");
        assert!(Manifest::parse(&doubled).unwrap_err().to_string().contains("unknown unit core-nope"));
        assert!(Manifest::parse("nonsense = 1").is_err());
    }
}
