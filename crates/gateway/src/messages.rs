//! The gateway's message catalogue (`messages/en.toml`, codes `GW.*`).

/// The English texts, compiled in.
pub const EN: &str = include_str!("../messages/en.toml");

/// Adds the gateway's codes to the process catalogue (once).
pub fn register() {
    platform::messages::register("gateway", "en", EN);
}

#[cfg(test)]
mod tests {
    #[test]
    fn catalogue_is_complete() {
        let mut c = platform::messages::Catalogue::default();
        c.add_builtin("gateway", "en", super::EN).unwrap();
        platform::messages::check_catalogue(&c, "GW");
        assert_eq!(c.codes().len(), 6);
    }
}
