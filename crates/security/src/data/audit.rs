//! The two audit trails the admin services write: `security_sox_log` (`SoxLogService`) and
//! `security_client_activity` (`ClientActivityService.createLog`). Java writes both with
//! `.subscribe()` and never waits for them or reports their failures; so do these.

use super::Db;
use crate::errors::AuthResult;

/// `SecuritySoxLogObjectName`.
pub mod object {
    pub const USER: &str = "USER";
    pub const ROLE: &str = "ROLE";
    pub const PERMISSION: &str = "PERMISSION";
    pub const PACKAGE: &str = "PACKAGE";
    pub const CLIENT: &str = "CLIENT";
    pub const CLIENT_TYPE: &str = "CLIENT_TYPE";
    pub const APP: &str = "APP";
    pub const PROFILE: &str = "PROFILE";
    pub const INVOICE: &str = "INVOICE";
}

/// `SecuritySoxLogActionName`.
pub mod action {
    pub const CREATE: &str = "CREATE";
    pub const UPDATE: &str = "UPDATE";
    pub const DELETE: &str = "DELETE";
    pub const READ: &str = "READ";
    pub const ASSIGN: &str = "ASSIGN";
    pub const UNASSIGN: &str = "UNASSIGN";
    pub const OTHER: &str = "OTHER";
    pub const LOGIN: &str = "LOGIN";
}

impl Db {
    /// `SoxLogService.create`: `created_by` is the signed-in user.
    pub async fn sox_log(&self, object_id: Option<u64>, object_name: &str, action_name: &str, description: &str, created_by: Option<u64>) -> AuthResult<()> {
        sqlx::query("INSERT INTO security_sox_log (OBJECT_ID, OBJECT_NAME, ACTION_NAME, DESCRIPTION, CREATED_BY) VALUES (?, ?, ?, ?, ?)")
            .bind(object_id)
            .bind(object_name)
            .bind(action_name)
            .bind(description)
            .bind(created_by)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `ClientActivityService.createLog` (through `AbstractJOOQDataService.create`).
    pub async fn client_activity(&self, client_id: Option<u64>, name: &str, description: &str, created_by: Option<u64>) -> AuthResult<()> {
        sqlx::query("INSERT INTO security_client_activity (CLIENT_ID, ACTIVITY_NAME, DESCRIPTION, CREATED_BY) VALUES (?, ?, ?, ?)")
            .bind(client_id)
            .bind(name)
            .bind(description)
            .bind(created_by)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// `SoxLogService.create(...).subscribe()`.
pub fn sox(db: &Db, object_id: Option<u64>, object_name: &'static str, action_name: &'static str, description: String, by: Option<u64>) {
    let db = db.clone();
    tokio::spawn(async move {
        if let Err(e) = db.sox_log(object_id, object_name, action_name, &description, by).await {
            tracing::warn!(error = %e, "sox log not written");
        }
    });
}

/// `ClientActivityService.createLog(...)`: fire and forget.
pub fn activity(db: &Db, client_id: Option<u64>, name: String, description: String, by: Option<u64>) {
    let db = db.clone();
    tokio::spawn(async move {
        if let Err(e) = db.client_activity(client_id, &name, &description, by).await {
            tracing::warn!(error = %e, "client activity not written");
        }
    });
}

/// What `AbstractSecurityUpdatableDataService` logs after a create, update or delete: a sox row
/// (`<Class> created[: identifier]`) and a client activity (`<Class> Create`) with the same text.
#[allow(clippy::too_many_arguments)]
pub fn entity_changed(
    db: &Db,
    by: Option<u64>,
    object_name: &'static str,
    action_name: &'static str,
    object_id: u64,
    client_id: Option<u64>,
    class_name: &str,
    identifier: Option<&str>,
) {
    let (verb, activity_verb) = match action_name {
        action::CREATE => ("created", "Create"),
        action::DELETE => ("deleted", "Delete"),
        _ => ("updated", "Update"),
    };
    let base = format!("{class_name} {verb}");
    let description = match identifier.filter(|i| !i.trim().is_empty()) {
        Some(i) => format!("{base}: {i}"),
        None => base,
    };
    sox(db, Some(object_id), object_name, action_name, description.clone(), by);
    activity(db, client_id, format!("{class_name} {activity_verb}"), description, by);
}

/// `assignLog` / `unAssignLog`: the sox row, then an activity named after the object
/// (`User Assign`, `Profile Unassign`).
pub fn assignment(db: &Db, by: Option<u64>, object_name: &'static str, assign: bool, object_id: u64, client_id: Option<u64>, description: String) {
    let action_name = if assign { action::ASSIGN } else { action::UNASSIGN };
    sox(db, Some(object_id), object_name, action_name, description.clone(), by);
    let title = format!("{}{}", &object_name[..1], object_name[1..].to_lowercase());
    activity(db, client_id, format!("{title} {}", if assign { "Assign" } else { "Unassign" }), description, by);
}

#[cfg(test)]
mod offline_tests {
    use super::*;

    /// The fire-and-forget logs only warn when their row cannot be written.
    #[tokio::test]
    async fn logs_that_cannot_be_written() {
        let s = crate::admin::users::testkit::offline();
        sox(&s.db, Some(1), object::USER, action::OTHER, "x".into(), None);
        activity(&s.db, Some(1), "x".into(), "y".into(), None);
        entity_changed(&s.db, None, object::ROLE, action::UPDATE, 1, Some(1), "RoleV2", None);
        // The pool gives up within its 200 ms acquire timeout; the warnings follow.
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    }
}
