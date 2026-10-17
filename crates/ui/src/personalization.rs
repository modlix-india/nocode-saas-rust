//! `PersonalizationController` / `PersonalizationService`: one document per user, app and
//! setting name (`name` + user id), in the caller's own client.

use axum::http::StatusCode;
use axum::response::Response;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime, Document};
use overridable::bson_conv::{doc_to_j, from_j};
use overridable::pojo::stored_millis_for_utc_now;
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};

fn db_err(e: mongodb::error::Error) -> AppError {
    AppError::Internal(e.into())
}

use crate::catalogue;
use crate::respond::json_ok;
use crate::state::{AppState, Caller};

const COLLECTION: &str = "personalization";
const ALREADY_EXISTS: &str = "already_exists";
const CANNOT_CHANGE_PREF: &str = "cannot_change_pref";
const VERSION_MISMATCH: &str = "version_mismatch";
const UNABLE_TO_DELETE: &str = "unable_to_delete";

fn user_id(caller: &Caller) -> String {
    caller.ca.user.id.to_string()
}

fn filter(caller: &Caller, app: &str, name: &str) -> Document {
    doc! {"name": format!("{name}{}", user_id(caller)), "appCode": app, "clientCode": caller.ca.client_code()}
}

/// The stored `personalization` map as Spring reads it back: stored order, no copy.
fn stored_map(d: &Document) -> AppResult<JValue> {
    match d.get("personalization") {
        Some(Bson::Document(p)) => Ok(JValue::Object(doc_to_j(p))),
        // `.map(Personalization::getPersonalization)` returning null.
        _ => Err(AppError::Internal(anyhow::anyhow!("The mapper returned a null value."))),
    }
}

/// `GET /api/ui/personalization/{appName}/{name}`.
pub async fn get(st: &AppState, caller: &Caller, app: &str, name: &str) -> AppResult<Response> {
    if !caller.authenticated() {
        return Ok(json_ok(&JValue::Object(JMap::new())));
    }
    match st.store().find_doc(COLLECTION, filter(caller, app, name)).await? {
        Some(d) => Ok(json_ok(&stored_map(&d)?)),
        None => Ok(json_ok(&JValue::Object(JMap::new()))),
    }
}

async fn evict(st: &AppState, app: &str, full_name: &str) {
    let cache = &st.inner().cache;
    cache.evict_all_everywhere(&format!("PersonalizationCache_{app}_{full_name}")).await;
    cache.evict_all_everywhere(&format!("PersonalizationCache_{app}_{full_name}_DRAFT")).await;
    cache.evict_all_everywhere(&format!("PersonalizationCache_{app}_Personalization_READ_PAGE")).await;
}

/// `POST /api/ui/personalization/{appName}/{name}`: create or replace, answering with what
/// was stored. An anonymous caller gets its own body back and nothing is stored.
pub async fn post(st: &AppState, caller: &Caller, app: &str, name: &str, body: JValue) -> AppResult<Response> {
    if !caller.authenticated() {
        return Ok(json_ok(&body));
    }
    let personalization = match &body {
        JValue::Object(_) => from_j(&body),
        _ => return Err(catalogue::literal("UI.PERSONALIZATION_NOT_OBJECT", StatusCode::BAD_REQUEST, "Personalization must be an object").into()),
    };
    let coll = st.store().db().collection::<Document>(COLLECTION);
    let full_name = format!("{name}{}", user_id(caller));
    let now = DateTime::from_millis(stored_millis_for_utc_now(chrono::Utc::now().timestamp_millis()));
    let id = match st.store().find_doc(COLLECTION, filter(caller, app, name)).await? {
        None => {
            let id = ObjectId::new();
            let d = doc! {
                "_id": id,
                "personalization": personalization,
                "name": &full_name,
                "clientCode": caller.ca.client_code(),
                "appCode": app,
                "version": 1_i32,
                "updatedAt": now,
                "createdAt": now,
                "createdBy": user_id(caller),
            };
            if coll.count_documents(filter(caller, app, name)).await.map_err(db_err)? > 0 {
                return Err(catalogue::error_as("UI.PERSONALIZATION_EXISTS", StatusCode::CONFLICT, ALREADY_EXISTS, &["Personalization", &full_name]));
            }
            coll.insert_one(d).await.map_err(db_err)?;
            id
        }
        Some(existing) => {
            let id = existing.get_object_id("_id").map_err(|e| AppError::Internal(e.into()))?;
            let created_by = existing.get("createdBy").map(|b| overridable::bson_conv::to_java_string(b).java_to_string());
            if created_by.as_deref() != Some(user_id(caller).as_str()) {
                return Err(catalogue::error(StatusCode::FORBIDDEN, CANNOT_CHANGE_PREF, &[]));
            }
            let version = existing.get("version").and_then(|v| match v {
                Bson::Int32(i) => Some(*i as i64),
                Bson::Int64(i) => Some(*i),
                _ => None,
            });
            let version_filter = match version {
                Some(v) => doc! {"_id": id, "version": v},
                None => doc! {"_id": id},
            };
            let next = version.unwrap_or(1) + 1;
            let r = coll
                .update_one(
                    version_filter,
                    doc! {"$set": {
                        "personalization": personalization,
                        "version": i32::try_from(next).unwrap_or(i32::MAX),
                        "updatedAt": now,
                        "updatedBy": user_id(caller),
                    }},
                )
                .await
                .map_err(db_err)?;
            if r.matched_count == 0 {
                return Err(catalogue::error(StatusCode::PRECONDITION_FAILED, VERSION_MISMATCH, &[]));
            }
            id
        }
    };
    evict(st, app, &full_name).await;
    let stored = st
        .store()
        .find_doc(COLLECTION, doc! {"_id": id})
        .await?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("personalization {id} vanished after the write")))?;
    Ok(json_ok(&stored_map(&stored)?))
}

/// `DELETE /api/ui/personalization/{appName}/{name}`.
///
/// Java dereferences the document it did not find, so deleting anonymously or deleting
/// nothing is a 500 there; that is kept.
pub async fn delete(st: &AppState, caller: &Caller, app: &str, name: &str) -> AppResult<Response> {
    let found = if caller.authenticated() {
        st.store().find_doc(COLLECTION, filter(caller, app, name)).await?
    } else {
        None
    };
    let Some(d) = found else {
        return Err(AppError::Internal(anyhow::anyhow!("NullPointerException: personalization not found")));
    };
    let id = d.get_object_id("_id").map_err(|e| AppError::Internal(e.into()))?;
    let created_by = d.get("createdBy").map(|b| overridable::bson_conv::to_java_string(b).java_to_string());
    if created_by.as_deref() != Some(user_id(caller).as_str()) {
        return Err(catalogue::error(StatusCode::FORBIDDEN, CANNOT_CHANGE_PREF, &[]));
    }
    let full_name = format!("{name}{}", user_id(caller));
    let coll = st.store().db().collection::<Document>(COLLECTION);
    let derived = coll
        .count_documents(doc! {"name": &full_name, "appCode": app, "baseClientCode": caller.ca.client_code()})
        .await
        .map_err(db_err)?;
    if derived > 0 {
        return Err(catalogue::error(StatusCode::FORBIDDEN, UNABLE_TO_DELETE, &["Personalization", &id.to_hex()]));
    }
    coll.delete_one(doc! {"_id": id}).await.map_err(db_err)?;
    evict(st, app, &full_name).await;
    Ok(json_ok(&JValue::Bool(true)))
}
