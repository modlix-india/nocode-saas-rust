//! A person's notification choices, applied when sending (Rust only: Java stored preferences
//! and never read them).
//!
//! The preference map a person saves per app (`/api/notification/preference`) may hold
//!
//! ```json
//! {"channels": {"email": true, "inapp": true},
//!  "categories": {"assigned": {"email": true}, "comment": {"inapp": false}}}
//! ```
//!
//! For a channel and a notification's category, the category's choice wins, then the channel's,
//! then the definition's default (`channelEnabled`, [`CoreNotification::on_by_default`]). So an
//! app can make email opt in (`channelEnabled: {email: false}`) or opt out (absent), and each
//! person can change either. Any other keys in the map are the app's own and are ignored here.

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::dao::Dao;
use crate::model::CoreNotification;

/// Whether a person with preference map `pref` gets `channel` for `category`.
pub fn wants(pref: Option<&Map<String, Value>>, channel: &str, category: Option<&str>, notification: &CoreNotification) -> bool {
    let choice = |section: Option<&Value>| section.and_then(|s| s.get(channel)).and_then(Value::as_bool);
    let pref = pref.filter(|p| !p.is_empty());
    let by_category = category.and_then(|c| choice(pref.and_then(|p| p.get("categories")).and_then(|cs| cs.get(c))));
    let by_channel = choice(pref.and_then(|p| p.get("channels")));
    by_category.or(by_channel).unwrap_or_else(|| notification.on_by_default(channel))
}

/// Where the sender finds the recipients' preference maps.
#[async_trait]
pub trait PreferenceSource: Send + Sync {
    /// The stored maps of these users in this app; a user with none is absent.
    async fn preferences(&self, app_code: &str, user_ids: &[u64]) -> Result<HashMap<u64, Map<String, Value>>>;
}

#[async_trait]
impl PreferenceSource for Dao {
    async fn preferences(&self, app_code: &str, user_ids: &[u64]) -> Result<HashMap<u64, Map<String, Value>>> {
        self.preferences_of(app_code, user_ids).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn def(v: Value) -> CoreNotification {
        CoreNotification::from_json(&v).unwrap()
    }

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn no_choice_follows_the_definition() {
        let opt_out = def(json!({"channelTemplates": {"email": {}}}));
        let opt_in = def(json!({"channelTemplates": {"email": {}}, "channelEnabled": {"email": false}}));
        assert!(wants(None, "email", Some("assigned"), &opt_out), "absent channelEnabled: on until turned off");
        assert!(!wants(None, "email", Some("assigned"), &opt_in), "channelEnabled false: off until turned on");
        assert!(wants(None, "inapp", None, &opt_in), "other channels keep their own default");
        assert!(!wants(Some(&Map::new()), "email", None, &opt_in));
    }

    #[test]
    fn the_category_choice_wins_then_the_channel_choice() {
        let opt_in = def(json!({"channelEnabled": {"email": false}}));
        let p = map(json!({"channels": {"email": true}, "categories": {"comment": {"email": false}}}));
        assert!(wants(Some(&p), "email", Some("assigned"), &opt_in), "the channel choice turns email on");
        assert!(!wants(Some(&p), "email", Some("comment"), &opt_in), "the category choice turns it off again");
        assert!(wants(Some(&p), "email", None, &opt_in), "no category: the channel choice");
        let p = map(json!({"categories": {"assigned": {"email": true}}}));
        assert!(wants(Some(&p), "email", Some("assigned"), &opt_in));
        assert!(!wants(Some(&p), "email", Some("comment"), &opt_in));
    }

    #[test]
    fn values_that_are_not_true_or_false_are_no_choice() {
        let d = def(json!({}));
        let p = map(json!({"channels": {"inapp": "no"}, "categories": {"x": "off"}, "theme": "dark"}));
        assert!(wants(Some(&p), "inapp", Some("x"), &d));
    }
}
