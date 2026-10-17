//! The routes, as `EngineController`, `PersonalizationController`, and the `repositoryFind` /
//! `repositoryFilter` routes of `FunctionController` and `SchemaController` map them.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use overridable::{JMap, JValue};
use platform::error::{input, AppError};
use platform::http::with_route;

use crate::engine::Engine;
use crate::respond::{error_response, json_ok, options_too, unknown_error, with_ui_layers};
use crate::state::AppState;
use crate::{personalization, repository};

pub fn router(state: AppState) -> Router {
    let r = Router::new()
        .route("/api/ui/application", options_too(get(application)))
        .route("/api/ui/page/{page_name}", options_too(get(page)))
        .route("/api/ui/style", options_too(get(style)))
        .route("/api/ui/theme", options_too(get(theme)))
        .route("/api/ui/function/{namespace}/{name}", options_too(get(function)))
        .route("/api/ui/urlDetails", options_too(get(url_details)))
        .route(
            "/api/ui/personalization/{app_name}/{name}",
            options_too(get(personalization_get).post(personalization_post).delete(personalization_delete)),
        )
        .route("/api/ui/functions/repositoryFind", options_too(get(functions_find)))
        .route("/api/ui/functions/repositoryFilter", options_too(get(functions_filter)))
        .route("/api/ui/schemas/repositoryFind", options_too(get(schemas_find)))
        .route("/api/ui/schemas/repositoryFilter", options_too(get(schemas_filter)))
        .fallback(universal);
    with_ui_layers(r).with_state(state)
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `@RequestHeader("appCode")` and `("clientCode")`: required, in that order.
fn codes(h: &HeaderMap) -> Result<(String, String), Response> {
    for name in ["appCode", "clientCode"] {
        if header(h, name).is_none() {
            return Err(unknown_error(
                StatusCode::BAD_REQUEST,
                &format!("400 BAD_REQUEST \"Required header '{name}' is not present.\""),
            ));
        }
    }
    Ok((
        header(h, "appCode").unwrap_or_default().to_string(),
        header(h, "clientCode").unwrap_or_default().to_string(),
    ))
}

fn finish(r: Result<Response, AppError>, route: &'static str) -> Response {
    with_route(r.unwrap_or_else(error_response), route)
}

async fn application(State(st): State<AppState>, h: HeaderMap) -> Response {
    const ROUTE: &str = "/api/ui/application";
    let r = async {
        // The security filter runs before the controller reads its headers.
        let caller = st.caller(&h).await?;
        let (app, cc) = match codes(&h) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        Engine::new(&st, &caller).application(&app, &cc, header(&h, "if-none-match")).await
    }
    .await;
    finish(r, ROUTE)
}

async fn page(State(st): State<AppState>, Path(page_name): Path<String>, h: HeaderMap) -> Response {
    const ROUTE: &str = "/api/ui/page/{pageName}";
    let r = async {
        // The security filter runs before the controller reads its headers.
        let caller = st.caller(&h).await?;
        let (app, cc) = match codes(&h) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        Engine::new(&st, &caller)
            .page(&page_name, &app, &cc, header(&h, "if-none-match"))
            .await
    }
    .await;
    finish(r, ROUTE)
}

async fn style(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    const ROUTE: &str = "/api/ui/style";
    let r = async {
        // The security filter runs before the controller reads its headers.
        let caller = st.caller(&h).await?;
        let (app, cc) = match codes(&h) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        Engine::new(&st, &caller)
            .style(&app, &cc, q.get("theme").map(String::as_str), header(&h, "if-none-match"))
            .await
    }
    .await;
    finish(r, ROUTE)
}

async fn theme(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    const ROUTE: &str = "/api/ui/theme";
    let r = async {
        // The security filter runs before the controller reads its headers.
        let caller = st.caller(&h).await?;
        let (app, cc) = match codes(&h) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        Engine::new(&st, &caller)
            .theme(&app, &cc, q.get("theme").map(String::as_str), header(&h, "if-none-match"))
            .await
    }
    .await;
    finish(r, ROUTE)
}

async fn function(State(st): State<AppState>, Path((namespace, name)): Path<(String, String)>, h: HeaderMap) -> Response {
    const ROUTE: &str = "/api/ui/function/{namespace}/{name}";
    let r = async {
        // The security filter runs before the controller reads its headers.
        let caller = st.caller(&h).await?;
        let (app, cc) = match codes(&h) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        Engine::new(&st, &caller)
            .function(&namespace, &name, &app, &cc, header(&h, "if-none-match"))
            .await
    }
    .await;
    finish(r, ROUTE)
}

async fn url_details(State(st): State<AppState>, h: HeaderMap) -> Response {
    const ROUTE: &str = "/api/ui/urlDetails";
    let r = async {
        // The filter asks security for every request, so a refused token refuses this too.
        st.caller(&h).await?;
        let (app, cc) = match codes(&h) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        let mut m = JMap::new();
        m.insert("appCode".into(), JValue::Str(app));
        m.insert("clientCode".into(), JValue::Str(cc));
        Ok(json_ok(&JValue::Object(m)))
    }
    .await;
    finish(r, ROUTE)
}

/// Every other path falls to the Java ui's `UniversalController` (the index page), which
/// refuses a request without `X-Forwarded-Host` before anything else. That much is answered
/// the same; the index page itself is not served here.
pub async fn universal(h: HeaderMap) -> Response {
    let r = if header(&h, "x-forwarded-host").is_none() {
        unknown_error(
            StatusCode::BAD_REQUEST,
            "400 BAD_REQUEST \"Required header 'X-Forwarded-Host' is not present.\"",
        )
    } else {
        StatusCode::NOT_FOUND.into_response()
    };
    with_route(r, "unmatched")
}

const PERSONALIZATION_ROUTE: &str = "/api/ui/personalization/{appName}/{name}";

async fn personalization_get(State(st): State<AppState>, Path((app, name)): Path<(String, String)>, h: HeaderMap) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        personalization::get(&st, &caller, &app, &name).await
    }
    .await;
    finish(r, PERSONALIZATION_ROUTE)
}

async fn personalization_post(
    State(st): State<AppState>,
    Path((app, name)): Path<(String, String)>,
    h: HeaderMap,
    body: Bytes,
) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        let body = overridable::json::parse(&body)
            .map_err(|e| AppError::from(input::body_unreadable(None).status(StatusCode::BAD_REQUEST).debug(format!("Failed to read HTTP message: {e}"))))?;
        personalization::post(&st, &caller, &app, &name, body).await
    }
    .await;
    finish(r, PERSONALIZATION_ROUTE)
}

async fn personalization_delete(
    State(st): State<AppState>,
    Path((app, name)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        personalization::delete(&st, &caller, &app, &name).await
    }
    .await;
    finish(r, PERSONALIZATION_ROUTE)
}

async fn functions_find(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        repository::find(&st, &caller, repository::Kind::Function, &q).await
    }
    .await;
    finish(r, "/api/ui/functions/repositoryFind")
}

async fn functions_filter(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        repository::filter(&st, &caller, repository::Kind::Function, &q).await
    }
    .await;
    finish(r, "/api/ui/functions/repositoryFilter")
}

async fn schemas_find(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        repository::find(&st, &caller, repository::Kind::Schema, &q).await
    }
    .await;
    finish(r, "/api/ui/schemas/repositoryFind")
}

async fn schemas_filter(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> Response {
    let r = async {
        let caller = st.caller(&h).await?;
        repository::filter(&st, &caller, repository::Kind::Schema, &q).await
    }
    .await;
    finish(r, "/api/ui/schemas/repositoryFilter")
}
