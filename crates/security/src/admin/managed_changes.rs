//! Events that tell a managing company that a company it manages changed.
//!
//! A managing company (a builder's tenant such as FIN) keeps facts about the companies it manages
//! (its business partners) next to its own data: the partner's name and status, its active users,
//! their names and phones, and who manages it. Those facts live here, in security. Until these
//! events existed the only way to keep them fresh was to recompute them every few minutes for every
//! company. Now every change raises one event, and the app recomputes only the company that changed.
//!
//! - `CLIENT_UPDATED`: the company's details or status changed, it was deleted, or its client
//!   managers changed (`what` is `client`, `status`, `deleted` or `managers`).
//! - `USER_UPDATED`: one of its users was created, changed, activated, deactivated, unblocked or
//!   deleted (`what` names which; `userId` is the user).
//!
//! Who gets it: the event is raised for the company's NEAREST managing company
//! (`security_client_hierarchy.MANAGE_CLIENT_LEVEL_0`), as that company's client code, so the app's
//! EventAction runs with the managing company's data. A company managed only by SYSTEM (a company
//! that signed up on its own) has no managing company to tell, and nothing is raised.
//!
//! Which app: the app of the request that made the change (`urlAppCode`). A change made outside any
//! app (no app code on the request) raises nothing; the app's own periodic safety run catches it.
//!
//! Data (ids as text, as `APP_ACCESS_CHANGED` sends them): `clientId`, `clientCode` (the company
//! that changed), `managingClientId`, `managingClientCode`, `what`, `changedBy`, and `userId` for
//! `USER_UPDATED`. The event carries no authentication: core runs it as the managing company's event
//! runner.
//!
//! Raising never fails or slows the change that caused it beyond the lookup: a failure is logged.

use serde_json::Value;

use crate::admin::Admin;
use crate::events::EventMessage;
use crate::model::ContextAuth;

pub const CLIENT_UPDATED: &str = "CLIENT_UPDATED";
pub const USER_UPDATED: &str = "USER_UPDATED";

/// The client code of the root company; a company managed only by it gets no event.
const SYSTEM: &str = "SYSTEM";

/// What changed, as the event's `what`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Name or other details of the company.
    Client,
    /// The company was activated or deactivated.
    Status,
    /// The company was deleted.
    Deleted,
    /// A client manager was added to or removed from the company.
    Managers,
    /// One of the company's users was created.
    UserCreated,
    /// One of the company's users was changed (name, phone, email...).
    UserChanged,
    /// One of the company's users was activated, deactivated or unblocked.
    UserStatus,
    /// One of the company's users was deleted.
    UserDeleted,
}

impl Change {
    pub fn event_name(self) -> &'static str {
        match self {
            Change::Client | Change::Status | Change::Deleted | Change::Managers => CLIENT_UPDATED,
            _ => USER_UPDATED,
        }
    }

    pub fn what(self) -> &'static str {
        match self {
            Change::Client => "client",
            Change::Status => "status",
            Change::Deleted => "deleted",
            Change::Managers => "managers",
            Change::UserCreated => "created",
            Change::UserChanged => "changed",
            Change::UserStatus => "status",
            Change::UserDeleted => "deleted",
        }
    }
}

/// The event for a change, or `None` when nobody is to be told (no app on the request, or the
/// company has no managing company other than SYSTEM).
pub fn event_for(
    change: Change,
    app_code: Option<&str>,
    client: (u64, &str),
    manager: Option<(u64, &str)>,
    user_id: Option<u64>,
    changed_by: u64,
) -> Option<EventMessage> {
    let app_code = app_code.map(str::trim).filter(|a| !a.is_empty())?;
    let (manager_id, manager_code) = manager.filter(|(_, code)| !code.is_empty() && *code != SYSTEM)?;
    let mut data = vec![
        ("clientId".to_string(), Value::from(client.0.to_string())),
        ("clientCode".to_string(), Value::from(client.1)),
        ("managingClientId".to_string(), Value::from(manager_id.to_string())),
        ("managingClientCode".to_string(), Value::from(manager_code)),
        ("what".to_string(), Value::from(change.what())),
        ("changedBy".to_string(), Value::from(changed_by.to_string())),
    ];
    if let Some(u) = user_id {
        data.push(("userId".to_string(), Value::from(u.to_string())));
    }
    Some(EventMessage {
        event_name: change.event_name().into(),
        client_code: Some(manager_code.to_string()),
        app_code: Some(app_code.to_string()),
        data,
        ..Default::default()
    })
}

impl Admin {
    /// Raises `CLIENT_UPDATED` or `USER_UPDATED` to the company's nearest managing company (see the
    /// module notes). Call it after the change is stored, and for a delete with what was read
    /// before the delete (the hierarchy row may be gone after it).
    pub async fn notify_managed_change(&self, ca: &ContextAuth, client_id: u64, change: Change, user_id: Option<u64>) {
        if let Err(e) = self.try_notify_managed_change(ca, client_id, change, user_id).await {
            tracing::warn!(client_id, event = change.event_name(), what = change.what(), "could not raise the managed company change: {e}");
        }
    }

    async fn try_notify_managed_change(
        &self,
        ca: &ContextAuth,
        client_id: u64,
        change: Change,
        user_id: Option<u64>,
    ) -> crate::errors::AuthResult<()> {
        let Some(app_code) = ca.url_app_code.as_deref().filter(|a| !a.trim().is_empty()) else { return Ok(()) };
        let Some(manager_id) = self.dir().hierarchy(client_id).await?.level0 else { return Ok(()) };
        let Some(client) = self.dir().client(client_id).await? else { return Ok(()) };
        let Some(manager) = self.dir().client(manager_id).await? else { return Ok(()) };
        let event = event_for(
            change,
            Some(app_code),
            (client_id, client.code.as_deref().unwrap_or_default()),
            Some((manager_id, manager.code.as_deref().unwrap_or_default())),
            user_id,
            ca.user.id(),
        );
        if let Some(event) = event {
            self.events.publish(&event).await?;
            tracing::info!(
                event = event.event_name,
                app = app_code,
                client = client.code.as_deref().unwrap_or_default(),
                manager = manager.code.as_deref().unwrap_or_default(),
                what = change.what(),
                "managed company change raised"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(e: &EventMessage) -> serde_json::Map<String, Value> {
        e.data.iter().cloned().collect()
    }

    #[test]
    fn a_change_goes_to_the_nearest_managing_company_in_the_requests_app() {
        let e = event_for(Change::Client, Some("leadzumptwo"), (4410, "PART1"), Some((7, "FIN")), None, 142).unwrap();
        assert_eq!(e.event_name, CLIENT_UPDATED);
        assert_eq!(e.client_code.as_deref(), Some("FIN"));
        assert_eq!(e.app_code.as_deref(), Some("leadzumptwo"));
        let d = data(&e);
        assert_eq!(d["clientId"], Value::from("4410"));
        assert_eq!(d["clientCode"], Value::from("PART1"));
        assert_eq!(d["managingClientId"], Value::from("7"));
        assert_eq!(d["managingClientCode"], Value::from("FIN"));
        assert_eq!(d["what"], Value::from("client"));
        assert_eq!(d["changedBy"], Value::from("142"));
        assert!(!d.contains_key("userId"));
    }

    #[test]
    fn a_user_change_names_the_user() {
        let e = event_for(Change::UserStatus, Some("leadzumptwo"), (4410, "PART1"), Some((7, "FIN")), Some(9001), 142).unwrap();
        assert_eq!(e.event_name, USER_UPDATED);
        let d = data(&e);
        assert_eq!((d["what"].clone(), d["userId"].clone()), (Value::from("status"), Value::from("9001")));
    }

    #[test]
    fn nothing_is_raised_without_an_app_or_a_managing_company_other_than_system() {
        assert!(event_for(Change::Client, None, (1, "A"), Some((7, "FIN")), None, 1).is_none());
        assert!(event_for(Change::Client, Some("  "), (1, "A"), Some((7, "FIN")), None, 1).is_none());
        assert!(event_for(Change::Client, Some("leadzumptwo"), (1, "A"), Some((1, "SYSTEM")), None, 1).is_none());
        assert!(event_for(Change::Client, Some("leadzumptwo"), (1, "A"), None, None, 1).is_none());
    }

    #[test]
    fn every_change_has_its_event_and_word() {
        let all = [
            (Change::Client, CLIENT_UPDATED, "client"),
            (Change::Status, CLIENT_UPDATED, "status"),
            (Change::Deleted, CLIENT_UPDATED, "deleted"),
            (Change::Managers, CLIENT_UPDATED, "managers"),
            (Change::UserCreated, USER_UPDATED, "created"),
            (Change::UserChanged, USER_UPDATED, "changed"),
            (Change::UserStatus, USER_UPDATED, "status"),
            (Change::UserDeleted, USER_UPDATED, "deleted"),
        ];
        for (c, name, what) in all {
            assert_eq!((c.event_name(), c.what()), (name, what));
        }
    }
}
