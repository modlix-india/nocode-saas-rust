//! The messages the engines raise are core's (`crates/core/messages/en.toml`, codes `CORE.*`):
//! the file is registered under the same name by whichever of core, appdata and connections
//! raises first, so the codes render with their values named in every unit and test.

use std::sync::Once;

/// core's English texts, compiled in.
pub const CORE_EN: &str = include_str!("../../core/messages/en.toml");

/// Adds core's catalogue to the process (once).
pub fn register() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| platform::messages::register("core", "en", CORE_EN));
}
