//! Talking to Lighthouse, the registry that replaces Eureka.
//!
//! - [`wire`]: Eureka's `InstanceInfo` and `Applications` in the JSON shape the Java server
//!   (Jackson) writes, read leniently (ports and timestamps as numbers or strings,
//!   `overriddenstatus` in either spelling), and [`xml`] for the clients that only read XML
//!   (py_eureka_client).
//! - [`replication`]: the peer batch (`ReplicationList`) and the anti-entropy digest.
//! - [`registration()`]: a unit's registration, made only once it is ready and withdrawn in an
//!   orderly way on shutdown.
//! - [`watch()`]: the registry as a stream, for the gateway.
//! - [`config`]: a unit's configuration document and its version, and the version watch.

pub mod config;
pub mod registration;
pub mod replication;
pub mod watch;
pub mod wire;
pub mod xml;

pub use registration::{registration, Registration};
pub use watch::{watch, WatchConfig, Watcher};
pub use wire::{ActionType, Application, Applications, InstanceInfo, Status};

/// The default Lighthouse when none is configured: the local one.
pub const DEFAULT_SERVER: &str = "http://localhost:8761/eureka";

/// `http://host:8761`, `http://host:8761/` and `http://host:8761/eureka/` all name the same
/// server. Returns its Eureka API base without a trailing slash (`http://host:8761/eureka`).
pub fn eureka_base(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    if u.ends_with("/eureka") {
        u.to_string()
    } else {
        format!("{u}/eureka")
    }
}

/// The server's origin (`http://host:8761`), for its routes outside `/eureka`.
pub fn origin(url: &str) -> String {
    eureka_base(url).trim_end_matches("/eureka").to_string()
}

/// The servers named by `LIGHTHOUSE_URLS` (comma separated), else the local one.
pub fn servers_from_env() -> Vec<String> {
    servers_from(std::env::var("LIGHTHOUSE_URLS").ok().as_deref())
}

fn servers_from(value: Option<&str>) -> Vec<String> {
    let list: Vec<String> = value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(eureka_base)
        .collect();
    if list.is_empty() {
        vec![DEFAULT_SERVER.to_string()]
    } else {
        list
    }
}

/// `LIGHTHOUSE_TOKEN`, when set and not empty.
pub fn token_from_env() -> Option<String> {
    std::env::var("LIGHTHOUSE_TOKEN").ok().filter(|t| !t.is_empty())
}

/// Wall-clock milliseconds, the unit of every Eureka timestamp.
pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(eureka_base("http://h:8761"), "http://h:8761/eureka");
        assert_eq!(eureka_base(" http://h:8761/ "), "http://h:8761/eureka");
        assert_eq!(eureka_base("http://h:8761/eureka/"), "http://h:8761/eureka");
        assert_eq!(origin("http://h:8761/eureka/"), "http://h:8761");
        assert_eq!(origin("http://h:8761"), "http://h:8761");
        assert_eq!(servers_from(None), vec![DEFAULT_SERVER]);
        assert_eq!(servers_from(Some(" , ")), vec![DEFAULT_SERVER]);
        assert_eq!(
            servers_from(Some("http://a:1, http://b:2/eureka/")),
            vec!["http://a:1/eureka", "http://b:2/eureka"]
        );
        assert!(!servers_from_env().is_empty());
        let _ = token_from_env();
        assert!(now_millis() > 1_700_000_000_000);
    }
}
