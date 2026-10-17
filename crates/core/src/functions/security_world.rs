//! A stand-in security service for the security function tests (`SecurityFunctionTestSupport`
//! and the `CallerSecurityFunctionsTest` world): SYSTEM(1, SYS) manages FIN(7) and OTHER(55);
//! FIN manages BP1(90). FIN has write access to leadzumptwo; SYSTEM to every app. Users: 110
//! and 111 in FIN, 500 in BP1, 600 in OTHER, 700 in SYSTEM.
//!
//! Every call is recorded; routes the world does not model answer what a test put in
//! `answers` (`"METHOD /path"` to status and body), or a loud 599.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use kirun::function::Function;
use kirun::model::FunctionOutput;
use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
use kirun::runtime::FunctionExecutionParameters;
use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::auth::Authentication;
use crate::context::{self, RequestContext};
use crate::error::CoreError;

pub type Manages = Box<dyn Fn(u64, u64) -> Option<bool> + Send + Sync>;
pub type ManagesCode = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub raw_query: String,
    pub body: String,
    pub headers: HeaderMap,
}

pub struct World {
    pub calls: Mutex<Vec<Call>>,
    pub answers: Mutex<HashMap<String, (u16, String)>>,
    /// `doesClientManageClient`; `None` fails the call.
    pub manages: Mutex<Manages>,
    pub manages_code: Mutex<ManagesCode>,
    pub user_client: HashMap<u64, u64>,
}

pub fn clients() -> HashMap<u64, Value> {
    HashMap::from([
        (1, json!({"id": 1, "code": "SYSTEM", "typeCode": "SYS"})),
        (7, json!({"id": 7, "code": "FIN", "typeCode": "BUS"})),
        (90, json!({"id": 90, "code": "BP1", "typeCode": "BUS"})),
        (55, json!({"id": 55, "code": "OTHER", "typeCode": "BUS"})),
    ])
}

fn chain(id: u64) -> Option<Value> {
    match id {
        1 => Some(json!([1])),
        7 => Some(json!([7, 1])),
        90 => Some(json!([90, 7, 1])),
        55 => Some(json!([55, 1])),
        _ => None,
    }
}

impl World {
    /// The world of `CallerSecurityFunctionsTest.security()`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            answers: Mutex::new(HashMap::new()),
            manages: Mutex::new(Box::new(|m, c| Some((m == 1 && c != 1) || (m == 7 && c == 90)))),
            manages_code: Mutex::new(Box::new(|_, _| false)),
            user_client: HashMap::from([(110, 7), (111, 7), (500, 90), (600, 55), (700, 1)]),
        })
    }

    pub fn answer(&self, method: &str, path: &str, status: u16, body: &str) {
        self.answers.lock().insert(format!("{method} {path}"), (status, body.to_string()));
    }

    pub fn set_manages(&self, f: impl Fn(u64, u64) -> Option<bool> + Send + Sync + 'static) {
        *self.manages.lock() = Box::new(f);
    }

    pub fn set_manages_code(&self, f: impl Fn(&str, &str) -> bool + Send + Sync + 'static) {
        *self.manages_code.lock() = Box::new(f);
    }

    /// Calls whose path starts with `prefix`.
    pub fn count(&self, prefix: &str) -> usize {
        self.calls.lock().iter().filter(|c| c.path.starts_with(prefix)).count()
    }

    pub fn last(&self, prefix: &str) -> Call {
        self.calls.lock().iter().rev().find(|c| c.path.starts_with(prefix)).cloned().unwrap_or_else(|| panic!("no call to {prefix}"))
    }

    /// The as-caller calls (to security's public routes).
    pub fn as_caller_calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .iter()
            .filter(|c| !c.path.contains("/internal"))
            .map(|c| format!("{} {}", c.method, c.path))
            .collect()
    }

    pub async fn serve(self: &Arc<Self>) -> String {
        crate::testing::serve(Router::new().fallback(handle).with_state(self.clone())).await
    }
}

fn ok(body: impl Into<String>) -> Response {
    (StatusCode::OK, body.into()).into_response()
}

async fn handle(State(w): State<Arc<World>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let raw_query = uri.query().unwrap_or("").to_string();
    let query: HashMap<String, String> = crate::exec::parse_query(uri.query()).into_iter().collect();
    let path = uri.path().to_string();
    if path == "/api/security/internal/securityContextAuthentication" && !headers.contains_key("authorization") {
        return ok(json!({"user": {"id": 0, "clientId": 7, "stringAuthorities": ["Authorities._Anonymous"]},
                         "authenticated": false, "clientCode": "FIN"})
        .to_string());
    }
    w.calls.lock().push(Call {
        method: method.to_string(),
        path: path.clone(),
        query: query.clone(),
        raw_query,
        body: String::from_utf8_lossy(&body).into_owned(),
        headers,
    });
    if let Some((s, b)) = w.answers.lock().get(&format!("{method} {path}")).cloned() {
        return (StatusCode::from_u16(s).unwrap_or(StatusCode::OK), b).into_response();
    }
    let num = |k: &str| query.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    match path.as_str() {
        "/api/security/clients/internal/doesClientManageClient" => match (w.manages.lock())(num("managingClientId"), num("clientId")) {
            Some(b) => ok(b.to_string()),
            None => (StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"No client hierarchy found"}"#).into_response(),
        },
        "/api/security/clients/internal/doesClientManageClientCode" => {
            let m = query.get("managingClientCode").cloned().unwrap_or_default();
            let c = query.get("clientCode").cloned().unwrap_or_default();
            ok((w.manages_code.lock())(&m, &c).to_string())
        }
        "/api/security/clients/internal/clientHierarchy" => chain(num("clientId")).map(|c| ok(c.to_string())).unwrap_or_else(|| ok("")),
        "/api/security/clients/internal/getClientById" => clients().get(&num("clientId")).map(|c| ok(c.to_string())).unwrap_or_else(|| ok("")),
        "/api/security/clients/internal/getClientByCode" => {
            let code = query.get("clientCode").cloned().unwrap_or_default();
            clients().values().find(|c| c["code"] == code.as_str()).map(|c| ok(c.to_string())).unwrap_or_else(|| ok(""))
        }
        "/api/security/applications/internal/hasWriteAccess" => {
            let app = query.get("appCode").cloned().unwrap_or_default();
            let client = query.get("clientCode").cloned().unwrap_or_default();
            ok((client == "SYSTEM" || (app == "leadzumptwo" && client == "FIN")).to_string())
        }
        p if p.starts_with("/api/security/users/internal/") && p[29..].bytes().all(|b| b.is_ascii_digit()) => {
            let id: u64 = p[29..].parse().unwrap_or(0);
            match w.user_client.get(&id) {
                Some(c) => ok(json!({"id": id, "clientId": c}).to_string()),
                None => ok(""),
            }
        }
        _ => (StatusCode::from_u16(599).unwrap(), format!("unexpected call {method} {path}")).into_response(),
    }
}

/// `SecurityFunctionTestSupport.user`: signed in, URL app leadzumptwo, URL client SYSTEM.
pub fn user(user_id: u64, client_id: u64, client_code: &str, authorities: &[&str]) -> Authentication {
    crate::testing::auth(
        json!({
            "user": {"id": user_id, "clientId": client_id, "stringAuthorities": authorities},
            "authenticated": true, "clientCode": client_code, "clientTypeCode": if client_id == 1 { "SYS" } else { "BUS" },
            "accessToken": "tok-110"
        }),
        Some("SYSTEM"),
        Some("leadzumptwo"),
    )
}

pub fn without_token(mut a: Authentication) -> Authentication {
    a.raw.remove("accessToken");
    a.ca.access_token = None;
    a
}

pub fn anonymous(client_id: u64, client_code: &str) -> Authentication {
    let mut a = user(0, client_id, client_code, &[]);
    a.ca.authenticated = false;
    a.raw.insert("authenticated".into(), Value::Bool(false));
    a
}

pub fn with_app(mut a: Authentication, app: &str) -> Authentication {
    a.ca.url_app_code = Some(app.to_string());
    a
}

/// Runs `f` with `args` as the caller `auth`; inside a definition when `in_definition`; with a
/// forwarded host when `with_request`.
pub async fn run(
    f: &dyn Function,
    args: Value,
    auth: Authentication,
    in_definition: bool,
    with_request: bool,
) -> Result<serde_json::Map<String, Value>, CoreError> {
    let ctx = Arc::new(RequestContext {
        auth: Arc::new(auth),
        app_code: Some("leadzumptwo".into()),
        client_code: Some("SYSTEM".into()),
        forwarded_host: if with_request { "leadzumptwo.local.modlix.com".into() } else { String::new() },
        forwarded_port: if with_request { "443".into() } else { String::new() },
        draft: false,
        debug: None,
        raised: Default::default(),
    });
    let c2 = ctx.clone();
    let fut = async move {
        let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
            .set_arguments(args.as_object().cloned().unwrap_or_default().into_iter().collect());
        f.execute(&mut fep).await
    };
    let r: kirun::Result<FunctionOutput> = if in_definition {
        context::with_request(ctx, context::with_run(context::RunScope::default(), fut)).await
    } else {
        context::with_request(ctx, fut).await
    };
    match r {
        Ok(mut o) => Ok(o.next().map(|e| e.get_result().iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()),
        Err(e) => Err(c2.raised.lock().take().unwrap_or_else(|| CoreError::unknown(e.to_string()))),
    }
}

/// The function named `name` among `functions`.
pub fn find(functions: &[Arc<dyn Function>], name: &str) -> Arc<dyn Function> {
    functions.iter().find(|f| f.get_signature().get_name() == name).cloned().unwrap_or_else(|| panic!("no {name}"))
}
