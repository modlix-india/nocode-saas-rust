//! ui-engine configuration: `config/ui-engine.toml`, secrets (`MODLIX__MONGO__URI`,
//! `MODLIX__REDIS__URL`) from the environment.

use platform::config::{EurekaConfig, MongoConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    pub mongo: MongoConfig,
    pub ui: UiSection,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8102, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig { cache_prefix: "cmn".into(), ..Default::default() },
            security: SecurityConfig::default(),
            mongo: MongoConfig::default(),
            ui: UiSection::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSection {
    /// `ui.resourceCacheAge`: the `max-age` of style, theme and function responses.
    pub resource_cache_age: u32,
    /// The offset of the zone the Java ui's JVM runs in (`+05:30` on a developer machine in
    /// India, `+00:00` in the containers). Java writes stored dates shifted by it, so the Rust
    /// unit must use the same value for its timestamps to match.
    pub java_zone_offset: String,
}

impl Default for UiSection {
    fn default() -> Self {
        Self { resource_cache_age: 604_800, java_zone_offset: "+00:00".into() }
    }
}

impl UiSection {
    /// `+05:30` as seconds east of UTC.
    pub fn zone_offset_seconds(&self) -> anyhow::Result<i32> {
        let s = self.java_zone_offset.trim();
        if s.eq_ignore_ascii_case("z") || s.is_empty() {
            return Ok(0);
        }
        let (sign, rest) = match s.as_bytes()[0] {
            b'+' => (1, &s[1..]),
            b'-' => (-1, &s[1..]),
            _ => (1, s),
        };
        let (h, m) = rest.split_once(':').unwrap_or((rest, "0"));
        let h: i32 = h.parse()?;
        let m: i32 = m.parse()?;
        Ok(sign * (h * 3600 + m * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_offsets_parse() {
        let mut s = UiSection::default();
        assert_eq!(s.zone_offset_seconds().unwrap(), 0);
        for (text, secs) in [("+05:30", 19_800), ("-03:00", -10_800), ("Z", 0), ("", 0), ("05:30", 19_800), ("+05", 18_000)] {
            s.java_zone_offset = text.into();
            assert_eq!(s.zone_offset_seconds().unwrap(), secs, "{text}");
        }
        s.java_zone_offset = "+x".into();
        assert!(s.zone_offset_seconds().is_err());
        s.java_zone_offset = "+05:y".into();
        assert!(s.zone_offset_seconds().is_err());
        let c = UiConfig::default();
        assert_eq!(c.server.port, 8102);
        assert_eq!(c.redis.cache_prefix, "cmn");
        assert_eq!(c.ui.resource_cache_age, 604_800);
    }
}
