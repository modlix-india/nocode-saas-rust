//! An automation that starts when a storage row is written (`Storage.<name>.Create`,
//! `.Update`, `.Delete`), as SiteZump's form automations do.
//!
//! Core raises a storage event only when the storage has `generateEvents` on and an
//! EventDefinition of that exact name exists ([`crate::storage::service`]). People who draw a
//! "when the contact form is submitted" automation should not have to know that, so saving
//! the automation sets both up, through the same services and checks as a person doing it by
//! hand: the saver needs `Storage_UPDATE` (only when the switch is off) and
//! `EventDefinition_CREATE` (only when the definition is missing).
//!
//! Only the client's own storage is switched on. A storage that belongs to the app's owner
//! (leadzumptwo's `deal`, say) is the owner's to change; the save is refused with a reason
//! unless events are already on.

use axum::http::StatusCode;
use overridable::pojo::{map_field, str_field};
use overridable::write::OverridableService;
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::editor::kinds::CoreKind;

/// The storage and the operation of a storage event's name.
pub fn storage_event(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("Storage.")?;
    let (name, op) = rest.rsplit_once('.')?;
    (!name.is_empty() && matches!(op, "Create" | "Update" | "Delete")).then_some((name, op))
}

fn refuse(message: String) -> AppError {
    AppError::new(StatusCode::BAD_REQUEST, message)
}

/// Makes the storage event of the automation's trigger one that core raises.
pub async fn ensure(
    storages: Option<&OverridableService<CoreKind>>,
    event_definitions: Option<&OverridableService<CoreKind>>,
    ca: &ContextAuthentication,
    doc: &JMap,
) -> AppResult<()> {
    let Some(key) = map_field(doc, "trigger").and_then(|t| str_field(t, "key")) else { return Ok(()) };
    let Some((name, _)) = storage_event(key) else { return Ok(()) };
    let (Some(storages), Some(defs)) = (storages, event_definitions) else { return Ok(()) };
    let Some(app) = str_field(doc, "appCode").filter(|a| !a.trim().is_empty()) else { return Ok(()) };
    let client = str_field(doc, "clientCode").filter(|c| !c.trim().is_empty()).unwrap_or(ca.client_code()).to_string();

    // The storage as the client sees it, live.
    let Some(seen) = storages.read_resolved(ca, name, app, &client, false).await? else {
        return Err(refuse(format!("There is no storage \"{name}\" in this app for the automation to start on.")));
    };
    let on = seen.entity.get("generateEvents").and_then(JValue::as_bool).unwrap_or(false);
    if !on {
        let Some(own) = storages.find_one(name, app, &client).await? else {
            return Err(refuse(format!(
                "\"{name}\" belongs to the app, and it does not report new entries. Ask the app's owner to switch its events on."
            )));
        };
        let id = str_field(&own, "id").or_else(|| str_field(&own, "_id")).unwrap_or_default().to_string();
        let mut entity = storages.read(ca, &id).await?;
        entity.insert("generateEvents".into(), JValue::Bool(true));
        storages.update(ca, entity).await?;
    }
    if defs.read_resolved(ca, key, app, &client, false).await?.is_none() {
        let mut def = JMap::new();
        def.insert("name".into(), JValue::Str(key.to_string()));
        def.insert("appCode".into(), JValue::Str(app.to_string()));
        def.insert("clientCode".into(), JValue::Str(client.clone()));
        def.insert("schema".into(), JValue::Object(JMap::new()));
        def.insert("message".into(), JValue::Str("Made by an automation that starts on this storage".into()));
        defs.create(ca, def).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::storage_event;

    #[test]
    fn storage_event_names() {
        assert_eq!(storage_event("Storage.contactForm.Create"), Some(("contactForm", "Create")));
        assert_eq!(storage_event("Storage.a.b.Update"), Some(("a.b", "Update")));
        assert_eq!(storage_event("Storage.x.Read"), None);
        assert_eq!(storage_event("Storage..Create"), None);
        assert_eq!(storage_event("LZ_DEAL_CREATED"), None);
    }
}
