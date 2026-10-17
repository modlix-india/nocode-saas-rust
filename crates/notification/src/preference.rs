//! `NotificationPreferenceService`: a user's preference map per app.
//!
//! A caller reads and writes its own preference, or, naming `userId`, another user's after
//! security's `isUserClientManageClient` check (made with Java's argument order: the target
//! user's id and client, then the caller's client). A write evicts `notificationPreference`
//! everywhere, as Java's does; nothing reads that cache today.

use anyhow::{anyhow, Result};
use platform::cache::CacheService;
use platform::error::{AppError, Coded};
use platform::security::ContextAuthentication;
use serde_json::{Map, Value};

use crate::calls::DirectoryClient;
use crate::dao::{preference_map, Dao};

pub const CACHE_NAME_NOTIFICATION_PREFERENCE: &str = "notificationPreference";

pub struct PreferenceService {
    pub dao: Dao,
    pub directory: DirectoryClient,
    pub cache: Option<CacheService>,
}

/// A JSON number or numeric string as a `BigInteger`'s text.
fn big_integer_text(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

impl PreferenceService {
    /// `getValidatedUserId`: the caller when no user is named; otherwise the named user after
    /// the management check.
    pub async fn validated_user_id(&self, ca: &ContextAuthentication, user_id: Option<i128>, debug: Option<&str>) -> Result<u64> {
        let Some(uid) = user_id else { return Ok(ca.user.id) };
        let uid_text = uid.to_string();

        let client = self
            .directory
            .client_by_code(ca.client_code.as_deref(), debug)
            .await?
            .ok_or_else(|| anyhow!("Cannot invoke \"Client.getId()\" because the client is null"))?;
        let client_id = big_integer_text(client.get("id"));

        let user = self
            .directory
            .user_internal(&uid_text, debug)
            .await?
            .ok_or_else(|| anyhow!("Cannot invoke \"com.modlix.saas.commons2.security.model.User.getClientId()\" because \"user\" is null"))?;
        let user_client_id = big_integer_text(user.get("clientId"));

        let managed = self
            .directory
            .is_user_client_manage_client(ca.url_app_code.as_deref(), &uid_text, user_client_id, client_id, debug)
            .await?
            .and_then(|v| v.as_bool())
            .ok_or_else(|| anyhow!("Cannot invoke \"java.lang.Boolean.booleanValue()\" because \"isManaged\" is null"))?;
        if !managed {
            let coded = Coded::new("NOTIF.USER_PREFERENCE_FORBIDDEN").param("id", uid).debug(format!("User don't have access to this user Id : {uid}"));
            crate::catalogue::register();
            return Err(AppError::from(coded).into());
        }
        // ULong.valueOf(BigInteger).
        u64::try_from(uid).map_err(|_| anyhow!("Value is out of range : {uid}"))
    }

    /// `getNotificationPreference`: the stored map, `{}` when there is none.
    pub async fn get(&self, ca: &ContextAuthentication, app_code: &str, user_id: Option<i128>, debug: Option<&str>) -> Result<Map<String, Value>> {
        let uid = self.validated_user_id(ca, user_id, debug).await?;
        Ok(self.dao.preference(app_code, uid).await?.map(|r| preference_map(r.preference.as_deref())).unwrap_or_default())
    }

    /// `setNotificationPreference`: creates the row (even for no preference), replaces it, or
    /// deletes it when an existing row is given an empty or absent preference. The answer is
    /// what was given (`None` when nothing was given for a new row), `{}` after a delete.
    pub async fn set(
        &self,
        ca: &ContextAuthentication,
        app_code: &str,
        user_id: Option<i128>,
        preference: Option<Map<String, Value>>,
        debug: Option<&str>,
    ) -> Result<Option<Map<String, Value>>> {
        let uid = self.validated_user_id(ca, user_id, debug).await?;
        if let Some(cache) = &self.cache {
            // cacheService.evict(name, appCode, userId): the key is the two joined.
            cache.evict_everywhere(CACHE_NAME_NOTIFICATION_PREFERENCE, &format!("{app_code}{uid}")).await;
        }
        let by = ca.user.id;
        let stored = preference.as_ref().map(|p| Value::Object(p.clone()).to_string());
        match self.dao.preference(app_code, uid).await? {
            None => {
                self.dao.insert_preference(app_code, uid, stored.as_deref(), by).await?;
                Ok(preference)
            }
            Some(row) => match stored.filter(|_| preference.as_ref().is_some_and(|p| !p.is_empty())) {
                None => {
                    self.dao.delete_preference(row.id).await?;
                    Ok(Some(Map::new()))
                }
                Some(json) => {
                    self.dao.update_preference(row.id, &json, by).await?;
                    Ok(preference)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ids_from_security_answers() {
        assert_eq!(big_integer_text(Some(&json!(1))).as_deref(), Some("1"));
        assert_eq!(big_integer_text(Some(&json!(" 7 "))).as_deref(), Some("7"));
        assert_eq!(big_integer_text(Some(&json!(""))), None);
        assert_eq!(big_integer_text(Some(&json!(null))), None);
        assert_eq!(big_integer_text(None), None);
    }
}
