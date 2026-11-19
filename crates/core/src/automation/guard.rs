//! Which functions an automation's steps may run, checked when it is saved.
//!
//! The engine runs any server function a step names, as the client's event runner. So what a
//! saved automation may name is decided here:
//!
//! - a **builder** (the SYSTEM client, or anyone holding `Authorities.Function_UPDATE`, who
//!   can write a function anyway) may run any function of the app: write one that calls
//!   `SendNotification`, say, and use it in a step;
//! - **everyone else** (a tenant's admin) may run the built-in actions and the functions the
//!   app offers to automations (those carrying the `automation` block), nothing else. Without
//!   this, a hand-made document could run an app's internal event-runner functions.

use axum::http::StatusCode;
use overridable::pojo::{map_field, str_field};
use overridable::write::OverridableService;
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use overridable::backend::Find;

use super::catalog::{BLOCK, BUILT_IN_PREFIX};
use crate::editor::kinds::CoreKind;

pub const FUNCTION_UPDATE: &str = "Authorities.Function_UPDATE";

/// Whether `ca` may make a step run any function of the app.
pub fn builder(ca: &ContextAuthentication) -> bool {
    ca.is_system_client() || ca.has_authority(FUNCTION_UPDATE)
}

/// The function keys the steps of `doc` run (built-ins left out), with each step's words.
pub fn function_steps(doc: &JMap) -> Vec<(String, String)> {
    let Some(nodes) = map_field(doc, "nodes") else { return vec![] };
    nodes
        .iter()
        .filter_map(|(key, n)| {
            let n = n.as_object()?;
            (str_field(n, "type") == Some(super::ACTION)).then_some(())?;
            let action = str_field(n, "action").map(str::trim).filter(|a| !a.is_empty() && !a.starts_with(BUILT_IN_PREFIX))?;
            let title = str_field(n, "title").map(str::trim).filter(|t| !t.is_empty()).unwrap_or(key);
            Some((action.to_string(), title.to_string()))
        })
        .collect()
}

/// Refuses a save whose steps run a function the saver may not use.
pub async fn check_steps(functions: Option<&OverridableService<CoreKind>>, ca: &ContextAuthentication, doc: &JMap) -> AppResult<()> {
    if builder(ca) {
        return Ok(());
    }
    let Some(functions) = functions else { return Ok(()) };
    let steps = function_steps(doc);
    if steps.is_empty() {
        return Ok(());
    }
    let Some(app) = str_field(doc, "appCode").filter(|a| !a.trim().is_empty()) else { return Ok(()) };
    let client = str_field(doc, "clientCode").filter(|c| !c.trim().is_empty()).unwrap_or(ca.client_code()).to_string();
    for (action, title) in steps {
        // Offered = a stored copy carries the block (as the catalog lists them; a read
        // fills a missing block with an empty one, so the read alone cannot tell), and the
        // client can see the function.
        let filter = mongodb::bson::doc! { "appCode": app, "name": &action, BLOCK: { "$exists": true, "$ne": null } };
        let rows = functions.commons().backend().find(functions.collection(), Find::new(filter)).await.map_err(AppError::Internal)?;
        let mut offered = false;
        if !rows.is_empty() {
            for draft in [false, true] {
                if functions.read_resolved(ca, &action, app, &client, draft).await?.is_some() {
                    offered = true;
                    break;
                }
            }
        }
        if !offered {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                format!("The step \"{title}\" runs {action}, which this app does not offer to automations. Choose another action, or ask the app's builder to offer it."),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_function_steps_of_a_document() {
        let doc = match overridable::json::parse(
            br#"{"nodes":{"a":{"type":"ACTION","action":"Ns.send","title":"Send it"},"b":{"type":"ACTION","action":"core:sendEmail"},
                "c":{"type":"WAIT","for":"P1D"},"d":{"type":"ACTION","action":"Ns.other"},"e":{"type":"ACTION","action":" "}}}"#,
        )
        .unwrap()
        {
            JValue::Object(m) => m,
            _ => panic!(),
        };
        let mut steps = function_steps(&doc);
        steps.sort();
        assert_eq!(steps, vec![("Ns.other".to_string(), "d".to_string()), ("Ns.send".to_string(), "Send it".to_string())]);
    }
}
