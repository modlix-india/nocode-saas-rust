//! `CoreServices.Platform.*`: the guard on every path a call can come from (with the fake
//! services checked untouched each time), every job against the fakes, the listing, and the
//! platform app's seed (`tools/platform_seed/definitions.json`) run as core-events runs it.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use kirun::function::Function;
use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
use kirun::runtime::FunctionExecutionParameters;
use overridable::backend::{FakeDirectory, MemBackend};
use overridable::Store;
use platform::cache::{CacheService, LocalCaches};
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};

use super::platform::{all, guard, is_platform_function, listed, refused_because, Job, MAX_PATHS_PER_EVENT};
use super::security_world::{anonymous, find, user, World};
use crate::context::{self, EventActionRun, RequestContext, RunScope};
use crate::error::CoreError;
use crate::exec::{self, Arguments};
use crate::platform_calls::tests::Targets;
use crate::platform_calls::PlatformCalls;
use crate::repos::FunctionSource;
use crate::state::AppState;

const SEED: &str = include_str!("../../../../tools/platform_seed/definitions.json");

fn seed() -> Value {
    serde_json::from_str(SEED).expect("definitions.json")
}

/// Java's text of the refusal (what travels inside core and stays in `debugMessage`).
fn message(name: &str) -> String {
    format!("CoreServices.Platform.{name} runs only as a task of the platform app's events")
}

/// The refusal as the caller reads it (`CORE.PLATFORM_FUNCTION_REFUSED`).
fn shown(name: &str) -> String {
    format!("{}.", message(name))
}

fn obj(v: Value) -> kirun::Map<Value> {
    v.as_object().cloned().unwrap_or_default().into_iter().collect()
}

/// The anonymous event-runner context core-events runs a scheduled tick under (Java's
/// `EventsQueListener.makeAnonymousContextAuth`: `_Anonymous` and `_Event_Runner`).
fn event_runner(app: &str, client: &str) -> Arc<RequestContext> {
    let auth = crate::testing::auth(
        json!({"user": {"id": 0, "clientId": 1, "userName": "_Anonymous",
                        "stringAuthorities": ["Authorities._Anonymous", "Authorities._Event_Runner"]},
               "authenticated": false, "clientCode": client, "loggedInFromClientCode": client}),
        Some(client),
        Some(app),
    );
    Arc::new(RequestContext { auth: Arc::new(auth), app_code: Some(app.into()), client_code: Some(client.into()), ..Default::default() })
}

fn action(app: &str, client: &str, event: &str) -> EventActionRun {
    EventActionRun { app_code: app.into(), client_code: client.into(), event_name: event.into() }
}

/// Where a direct call runs.
#[derive(Debug, Clone, Copy)]
enum Place {
    /// A request of a signed-in SYSTEM user, no event action.
    Request,
    /// An anonymous request, no event action.
    Anonymous,
    /// The platform app's action (SYSTEM), optionally inside a definition owned by `owner`.
    Platform(Option<&'static str>),
    /// An action of another app or client.
    Action(&'static str, &'static str),
    /// The platform app's action for an event a signed-in caller raised (CreateEvent).
    RaisedByCaller,
}

/// Runs `f` with `args` at `place`; the output event's result, or the error raised.
async fn call_at(place: Place, f: &dyn Function, args: Value) -> Result<Map<String, Value>, CoreError> {
    let ctx = match place {
        Place::Request => crate::testing::request(user(142, 1, "SYSTEM", &["Authorities.ROLE_Owner"]), false, None),
        Place::Anonymous => crate::testing::request(anonymous(1, "SYSTEM"), false, None),
        Place::Platform(_) => event_runner("platform", "SYSTEM"),
        Place::Action(app, client) => event_runner(app, client),
        Place::RaisedByCaller => crate::testing::request(user(142, 1, "SYSTEM", &["Authorities.ROLE_Owner"]), false, None),
    };
    let c2 = ctx.clone();
    let run = async move {
        let mut fep = FunctionExecutionParameters::new(Arc::new(KIRunFunctionRepository::new()), Arc::new(KIRunSchemaRepository::new()))
            .set_arguments(obj(args));
        f.execute(&mut fep).await
    };
    let r = context::with_request(ctx, async move {
        match place {
            Place::Request | Place::Anonymous => run.await,
            Place::Platform(None) => context::with_event_action(action("platform", "SYSTEM", "JOB"), run).await,
            Place::Platform(Some(owner)) => {
                let scope = RunScope { owner_app_code: Some(owner.into()) };
                context::with_event_action(action("platform", "SYSTEM", "JOB"), context::with_run(scope, run)).await
            }
            Place::Action(app, client) => context::with_event_action(action(app, client, "JOB"), run).await,
            Place::RaisedByCaller => context::with_event_action(action("platform", "SYSTEM", "JOB"), run).await,
        }
    })
    .await;
    match r {
        Ok(mut o) => Ok(o.next().map(|e| e.get_result().iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()),
        Err(e) => Err(c2.raised.lock().take().unwrap_or_else(|| CoreError::unknown(e.to_string()))),
    }
}

async fn functions() -> (Arc<Targets>, Vec<Arc<dyn Function>>) {
    let t = Arc::new(Targets::default());
    let (_, calls) = t.serve().await;
    (t, all(&Arc::new(calls)))
}

/// Arguments a healthy call of each function takes.
fn valid_args(job: Job) -> Value {
    match job {
        Job::Meter => json!({"service": "core"}),
        Job::CleanupTransports => json!({"service": "ui"}),
        _ => json!({}),
    }
}

// ------------------------------------------------------------------ the guard

async fn reason_in(app: &str, client: &str, owner: Option<&str>) -> Option<String> {
    let inside = context::with_event_action(action(app, client, "E"), async {
        match owner {
            Some(o) => context::with_run(RunScope { owner_app_code: Some(o.into()) }, async { refused_because() }).await,
            None => refused_because(),
        }
    });
    context::with_request(event_runner(app, client), inside).await
}

#[tokio::test]
async fn the_guard_admits_only_the_platform_apps_actions() {
    assert_eq!(refused_because().as_deref(), Some("not running as an event action's task"));
    assert_eq!(reason_in("platform", "SYSTEM", None).await, None);
    assert_eq!(reason_in("platform", "SYSTEM", Some("platform")).await, None);
    assert_eq!(reason_in("leadzumptwo", "SYSTEM", None).await.unwrap(), "an event action of app leadzumptwo");
    assert_eq!(reason_in("platform", "FIN", None).await.unwrap(), "an event action of client FIN");
    // Codes are compared exactly.
    assert!(reason_in("Platform", "SYSTEM", None).await.is_some());
    assert!(reason_in("platform", "system", None).await.is_some());
    assert!(reason_in("platform ", "SYSTEM", None).await.is_some());
    assert_eq!(reason_in("platform", "SYSTEM", Some("leadzumptwo")).await.unwrap(), "inside a definition owned by app leadzumptwo");
    // The platform app's action for an event a caller raised (CreateEvent carries the raiser's
    // authentication), or with no context at all, is not the scheduler's.
    let raised = context::with_request(
        crate::testing::request(user(142, 1, "SYSTEM", &["Authorities.ROLE_Owner"]), false, None),
        context::with_event_action(action("platform", "SYSTEM", "E"), async { refused_because() }),
    )
    .await;
    assert_eq!(raised.as_deref(), Some("the event was raised by a caller, not by the scheduler"));
    let bare = context::with_event_action(action("platform", "SYSTEM", "E"), async { refused_because() }).await;
    assert_eq!(bare.as_deref(), Some("the event was raised by a caller, not by the scheduler"));
    // A platform definition running outside any action is still refused.
    let outside = context::with_run(RunScope { owner_app_code: Some("platform".into()) }, async { refused_because() }).await;
    assert_eq!(outside.as_deref(), Some("not running as an event action's task"));
    let e = guard("CoreServices.Platform.Meter").unwrap_err();
    assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, message("Meter")));
    // A spawned task does not carry the action (core-events must not spawn inside an action).
    let spawned = context::with_event_action(action("platform", "SYSTEM", "E"), async {
        tokio::spawn(async { refused_because() }).await.unwrap()
    })
    .await;
    assert!(spawned.is_some());
}

#[tokio::test]
async fn every_function_refuses_outside_a_platform_action_and_calls_nothing() {
    let (t, fs) = functions().await;
    let places = [
        Place::Request,
        Place::Anonymous,
        Place::Action("leadzumptwo", "SYSTEM"),
        Place::Action("platform", "FIN"),
        Place::Action("leadzumptwo", "FIN"),
        Place::Platform(Some("leadzumptwo")),
        Place::RaisedByCaller,
    ];
    for job in Job::ALL {
        let f = find(&fs, job.name());
        for place in places {
            for args in [valid_args(job), json!({"service": 7, "limit": "many"})] {
                let e = call_at(place, f.as_ref(), args.clone()).await.unwrap_err();
                assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, message(job.name())), "{job:?} at {place:?} with {args}");
            }
        }
    }
    assert!(t.calls().is_empty(), "{:?}", t.lines());
}

// ------------------------------------------------------------------ the state over the routes

const SIGNED_IN: &str = "Basic dXNlcjpwYXNz";

struct Setup {
    world: Arc<World>,
    targets: Arc<Targets>,
    backend: Arc<MemBackend>,
    state: AppState,
}

/// The execution state core-exec and core-events run on, offline: security is `world`, the
/// definitions are in memory, the platform targets are fakes; no app has remote repositories.
async fn setup(dependencies: &str) -> Setup {
    let world = World::new();
    world.answer("GET", "/api/security/applications/internal/dependencies", 200, dependencies);
    world.answer(
        "GET",
        "/api/security/internal/securityContextAuthentication",
        200,
        &json!({"user": {"id": 142, "clientId": 1, "userName": "u", "stringAuthorities": ["Authorities.Logged_IN", "Authorities.ROLE_Owner"]},
                "authenticated": true, "clientCode": "SYSTEM", "clientTypeCode": "SYS", "verifiedAppCode": "platform"})
        .to_string(),
    );
    let security_base = world.serve().await;
    let targets = Arc::new(Targets::default());
    let (_, calls) = targets.serve().await;
    let backend = Arc::new(MemBackend::new());
    let state = state(&security_base, calls, backend.clone()).await;
    Setup { world, targets, backend, state }
}

async fn state(security_base: &str, calls: PlatformCalls, backend: Arc<MemBackend>) -> AppState {
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let store = Store::with_parts(backend, Arc::new(FakeDirectory::new()), &cache).unwrap();
    let security = platform::security::SecurityClient::new(Upstream::fixed(&[security_base]), 0).unwrap();
    let definitions = Arc::new(crate::repos::app::Definitions::new(store, security, cache.family(), Duration::from_secs(5)));
    // No app has a row in core_remote_repositories (the MySQL table is not reachable here).
    let names: Arc<LocalCaches<String, Arc<Vec<String>>>> = cache.family();
    for app in ["platform", "leadzumptwo", "appbuilder"] {
        names.insert(crate::repos::remote::CACHE_REMOTE_REPOSITORIES, app.to_string(), Arc::new(Vec::new())).await;
    }
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy("mysql://root@127.0.0.1:1/core")
        .unwrap();
    let ep = Arc::new(crate::clients::EntityProcessor::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap());
    let appdata = crate::testing::offline_storage_service().await;
    let mut deps = crate::testing::offline_deps(security_base, appdata.clone()).await;
    deps.platform = Arc::new(calls);
    let builtins = crate::state::Builtins::new(crate::repos::core_functions::CoreFunctions::new(&deps));
    let state = AppState::new(crate::state::Inner {
        config: crate::config::CoreConfig::default(),
        auth: crate::auth::AuthClient::new(Upstream::fixed(&[security_base])).unwrap(),
        definitions,
        remote: crate::repos::remote::RemoteRepositories::new(pool, names, ep),
        kirun_functions: builtins.kirun_functions,
        kirun_schemas: builtins.kirun_schemas,
        core_functions: builtins.core_functions,
        core_schemas: builtins.core_schemas,
        appdata,
        integrations: deps.integrations.clone(),
        event_runs: Arc::new(crate::event_runs::EventRunService::new(
            Arc::new(crate::event_runs::MemoryEventRunDao::default()),
            Arc::new(crate::scheduler::EventDefinitionService::new(deps.defs.definitions().store().clone(), deps.cache.clone())),
            deps.security.clone(),
            true,
        )),
    });
    deps.integrations.attach(&state);
    state
}

/// Stores a function document as the seed (or a test) has it.
fn put_function(backend: &MemBackend, doc: &Value) {
    backend.put_raw("function", mongodb::bson::to_document(doc).unwrap());
}

/// A stored function of `app` (no `executeAuth`) whose one step calls
/// `CoreServices.Platform.Meter(service=core)`.
fn meter_caller(app: &str, namespace: &str) -> Value {
    json!({
        "name": format!("{namespace}.meter"), "appCode": app, "clientCode": "SYSTEM",
        "definition": {
            "name": "meter", "namespace": namespace, "parameters": {},
            "events": {"output": {"name": "output", "parameters": {"result": {"name": "result", "type": ["BOOLEAN"]}}}},
            "steps": {
                "run": {"statementName": "run", "namespace": "CoreServices.Platform", "name": "Meter",
                        "parameterMap": {"service": {"one": {"key": "one", "type": "VALUE", "value": "core", "order": 1}}}},
                "output": {"statementName": "output", "namespace": "System", "name": "GenerateEvent", "parameterMap": {
                    "eventName": {"one": {"key": "one", "type": "VALUE", "value": "output", "order": 1}},
                    "results": {"one": {"key": "one", "type": "VALUE", "order": 1,
                        "value": {"name": "result", "value": {"isExpression": true, "value": "Steps.run.output.result"}}}}}}
            }
        }
    })
}

struct Http {
    base: String,
    http: reqwest::Client,
}

impl Http {
    async fn new(st: &AppState) -> Self {
        Self { base: crate::testing::serve(crate::handlers::router(st.clone())).await, http: reqwest::Client::new() }
    }

    async fn send(&self, method: &str, path: &str, app: &str, signed_in: bool, body: Option<&str>) -> (u16, Value) {
        let mut rb = self
            .http
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{}{path}", self.base))
            .header("appCode", app)
            .header("clientCode", "SYSTEM")
            .header("X-Forwarded-Host", "platform.local.modlix.com")
            .header("X-Forwarded-Port", "443");
        if signed_in {
            rb = rb.header("Authorization", SIGNED_IN);
        }
        if let Some(b) = body {
            rb = rb.header("content-type", "application/json").body(b.to_string());
        }
        let r = rb.send().await.unwrap();
        let status = r.status().as_u16();
        let text = r.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }
}

/// `exec::run` (what core-events' CALL_CORE_FUNCTION task does) of `ns.name` for `app` and
/// `client`, as `ctx`, inside `action`.
async fn run_task(st: &AppState, ctx: Arc<RequestContext>, run: EventActionRun, ns: &str, name: &str, args: Value) -> Result<Map<String, Value>, CoreError> {
    let (app, client) = (run.app_code.clone(), run.client_code.clone());
    let out = context::with_request(ctx, context::with_event_action(run, async {
        exec::run(st, Some(ns), name, &app, &client, Arguments::Body(obj(args))).await
    }))
    .await?;
    let mut out = out.expect("function found");
    Ok(out.next().map(|e| e.get_result().iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default())
}

// ------------------------------------------------------------------ refusals over the routes

#[tokio::test]
async fn the_execute_route_refuses_signed_in_and_anonymous_callers() {
    let s = setup("[]").await;
    let c = Http::new(&s.state).await;
    for signed_in in [true, false] {
        let (st, body) = c.send("POST", "/api/core/function/execute/CoreServices.Platform/Meter", "platform", signed_in, Some(r#"{"service":"core"}"#)).await;
        assert_eq!((st, body["message"].clone()), (403, json!(shown("Meter"))), "signed in: {signed_in}");
        assert_eq!((body["code"].clone(), body["debugMessage"].clone()), (json!("CORE.PLATFORM_FUNCTION_REFUSED"), json!(message("Meter"))));
        let (st, body) = c.send("GET", "/api/core/function/execute/CoreServices.Platform.CleanupTokens?unusedDays=1", "platform", signed_in, None).await;
        assert_eq!((st, body["message"].clone()), (403, json!(shown("CleanupTokens"))));
        // Resolvable from any app, so refused rather than missing.
        let (st, body) = c.send("POST", "/api/core/function/execute/CoreServices.Platform/ReconcileBilling", "leadzumptwo", signed_in, Some("{}")).await;
        assert_eq!((st, body["message"].clone()), (403, json!(shown("ReconcileBilling"))));
    }
    // Bad arguments are not even read before the refusal.
    let (st, _) = c.send("POST", "/api/core/function/execute/CoreServices.Platform/CleanupTransports", "platform", true, Some(r#"{"limit":"x"}"#)).await;
    assert_eq!(st, 403);
    // A name the family does not have is missing as any other.
    let (st, _) = c.send("POST", "/api/core/function/execute/CoreServices.Platform/Nope", "leadzumptwo", true, Some("{}")).await;
    assert_eq!(st, 404);
    assert!(s.targets.calls().is_empty(), "{:?}", s.targets.lines());
    // The anonymous caller was asked of security like any other (no Authorization sent).
    assert!(s.world.calls.lock().iter().all(|c| !c.path.contains("billing") && !c.path.contains("tokens")));
}

#[tokio::test]
async fn a_stored_function_run_from_a_request_is_refused() {
    let s = setup("[]").await;
    put_function(&s.backend, &meter_caller("platform", "Probe.Fns"));
    for f in seed()["functions"].as_array().unwrap() {
        put_function(&s.backend, f);
    }
    let c = Http::new(&s.state).await;
    for signed_in in [true, false] {
        // Even the platform app's own function, run from a request, reaches the guard and stops.
        let (st, body) = c.send("POST", "/api/core/function/execute/Probe.Fns/meter", "platform", signed_in, Some("{}")).await;
        assert_eq!(st, 403, "{body}");
        assert_eq!(body["message"], json!(shown("Meter")));
        // The seed's job functions are for the event runner only (executeAuth).
        let (st, body) = c.send("POST", "/api/core/function/execute/Platform.Jobs/CORE_METERING", "platform", signed_in, Some("{}")).await;
        assert_eq!(st, 403, "{body}");
    }
    // Directly, inside a request's definition run, as a page's server function would.
    let def = crate::repos::definition::DefinitionFunction::new(
        meter_caller("platform", "Probe.Fns")["definition"].clone(),
        None,
        Some("platform".into()),
        Duration::from_secs(5),
    )
    .unwrap();
    let repo = Arc::new(crate::repos::FunctionRepo(Arc::new(crate::repos::Hybrid::<dyn FunctionSource>::new(vec![
        s.state.inner().kirun_functions.clone(),
        s.state.inner().core_functions.clone(),
    ]))));
    let ctx = crate::testing::request(user(142, 1, "SYSTEM", &[]), false, None);
    let c2 = ctx.clone();
    let r = context::with_request(ctx, async {
        let mut fep = FunctionExecutionParameters::new(repo, Arc::new(KIRunSchemaRepository::new()));
        def.execute(&mut fep).await
    })
    .await;
    assert!(r.is_err());
    let raised = c2.raised.lock().take().unwrap();
    assert_eq!((raised.status(), raised.text()), (StatusCode::FORBIDDEN, message("Meter")));
    assert!(s.targets.calls().is_empty(), "{:?}", s.targets.lines());
}

#[tokio::test]
async fn an_event_action_of_another_app_or_client_or_raised_by_a_caller_is_refused() {
    let s = setup("[]").await;
    for (app, client) in [("leadzumptwo", "SYSTEM"), ("platform", "FIN"), ("appbuilder", "SYSTEM")] {
        let e = run_task(&s.state, event_runner(app, client), action(app, client, "SECURITY_METERING"), "CoreServices.Platform", "Meter", json!({"service": "security"}))
            .await
            .unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, message("Meter")), "{app}/{client}");
    }
    // The platform app's own action, for an event a caller raised with CreateEvent (which names
    // any app and client, and carries the raiser's authentication), is not the scheduler's.
    let raiser = crate::testing::request(user(142, 1, "SYSTEM", &["Authorities.ROLE_Owner"]), false, None);
    let e = run_task(&s.state, raiser, action("platform", "SYSTEM", "CORE_METERING"), "CoreServices.Platform", "Meter", json!({"service": "core"}))
        .await
        .unwrap_err();
    assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, message("Meter")));
    assert!(s.targets.calls().is_empty(), "{:?}", s.targets.lines());
}

#[tokio::test]
async fn a_definition_owned_by_another_app_is_refused_during_a_platform_action() {
    // platform depends on leadzumptwo, so leadzumptwo's function resolves for platform's task
    // and runs with leadzumptwo as its owner.
    let s = setup(r#"["leadzumptwo"]"#).await;
    put_function(&s.backend, &meter_caller("leadzumptwo", "Other.Fns"));
    put_function(&s.backend, &meter_caller("platform", "Probe.Fns"));
    let refused = run_task(&s.state, event_runner("platform", "SYSTEM"), action("platform", "SYSTEM", "CORE_METERING"), "Other.Fns", "meter", json!({})).await;
    let e = refused.unwrap_err();
    assert_eq!(e.status(), StatusCode::FORBIDDEN, "{e:?}");
    assert_eq!(e.text(), message("Meter"));
    assert!(s.targets.calls().is_empty(), "{:?}", s.targets.lines());
    // The same step in the platform app's own function runs.
    let ok = run_task(&s.state, event_runner("platform", "SYSTEM"), action("platform", "SYSTEM", "CORE_METERING"), "Probe.Fns", "meter", json!({})).await.unwrap();
    assert_eq!(ok["result"], json!(true));
    assert_eq!(s.targets.lines(), ["core /api/core/internal/billing/meter"]);
}

// ------------------------------------------------------------------ the jobs, as core-events runs them

/// The worker's requests for each job of the seed, in order (its execution services with the
/// job data of V3, V9, V10, V11 and V13), less entity-processor's metering and reconcile: that
/// service retired with the switch (2026-10-18).
fn worker_calls(job: &str) -> Vec<&'static str> {
    match job {
        "SSL_RENEWAL" => vec!["security /api/security/ssl/internal/renew-certificates?daysBeforeExpiry=3"],
        "TOKEN_CLEANUP" => vec!["security /api/security/internal/tokens/cleanup?unusedDays=90"],
        "SECURITY_METERING" => vec!["security /api/security/internal/billing/meter/security"],
        "CORE_METERING" => vec!["core /api/core/internal/billing/meter"],
        "FILES_METERING" => vec!["files /api/files/internal/billing/meter"],
        "BILLING_RECONCILE" => vec![
            "security /api/security/internal/billing/reconcile",
            "core /api/core/internal/billing/reconcile",
            "files /api/files/internal/billing/reconcile",
        ],
        "FILES_TTL_CLEANUP" => vec![
            "files /api/files/internal/secured/cleanupExpired?limit=500",
            "files /api/files/internal/static/cleanupExpired?limit=500",
            "files /api/files/internal/secured/applyRetention?limit=500",
            "files /api/files/internal/static/applyRetention?limit=500",
            "entity-processor /api/entity/processor/whatsapp/internal/media/stampExpired?retentionDays=30&limit=1000",
        ],
        "TRANSPORT_CLEANUP_UI" => vec!["ui /api/ui/transports/internal/cleanupOlderThan?retentionDays=90&limit=200"],
        "TRANSPORT_CLEANUP_CORE" => vec!["core /api/core/transports/internal/cleanupOlderThan?retentionDays=90&limit=200"],
        "EVENT_RUN_CLEANUP" => vec![
            "core /api/core/eventRuns/internal/cleanupOlderThan?retentionDays=90&successRetentionDays=7&staleAfterHours=6&limit=50000",
        ],
        other => panic!("no worker job {other}"),
    }
}

#[tokio::test]
async fn every_seeded_job_makes_the_workers_requests() {
    let seed = seed();
    let jobs = seed["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 10);
    for job in jobs {
        let name = job["name"].as_str().unwrap();
        let s = setup("[]").await;
        for f in seed["functions"].as_array().unwrap() {
            put_function(&s.backend, f);
        }
        // The task as the seed's EventAction has it: no arguments.
        let task = &seed["eventActions"].as_array().unwrap().iter().find(|a| a["name"] == name).unwrap()["tasks"]["key1"]["parameters"];
        let (ns, fname) = (task["namespace"].as_str().unwrap(), task["name"].as_str().unwrap());
        let out = run_task(&s.state, event_runner("platform", "SYSTEM"), action("platform", "SYSTEM", name), ns, fname, json!({}))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(s.targets.lines(), worker_calls(name), "{name}");
        let expected = match name {
            "SSL_RENEWAL" => json!({"renewedCount": 2, "failedCount": 1, "errors": ["x.example: dns"]}),
            "TOKEN_CLEANUP" => json!({"expiredTokensRemoved": 4, "unusedTokensRemoved": 5, "expiredDraftTokensRemoved": 6}),
            "BILLING_RECONCILE" => json!({"security": true, "core": true, "files": true}),
            "FILES_TTL_CLEANUP" => json!({
                "secured": {"expiredRemoved": 3, "retentionRemoved": 0, "eventsRaised": 0, "eventsFailed": 0},
                "static": {"expiredRemoved": 1, "retentionRemoved": 0, "eventsRaised": 0, "eventsFailed": 0},
                "messagesMarkedExpired": 7, "errors": []}),
            "TRANSPORT_CLEANUP_UI" => json!({"transportsRemoved": 8, "versionsRemoved": 8}),
            "TRANSPORT_CLEANUP_CORE" => json!({"transportsRemoved": 2, "versionsRemoved": 1}),
            "EVENT_RUN_CLEANUP" => json!({"runsRemoved": 50000, "successesRemoved": 49000, "staleClosed": 3}),
            _ => json!(true),
        };
        assert_eq!(out["result"], expected, "{name}");

        // Without the event runner's authority (a request's caller) the job function refuses
        // before its step runs; without the action its step refuses.
        let before = s.targets.calls().len();
        let no_runner = crate::testing::request(user(142, 1, "SYSTEM", &["Authorities.ROLE_Owner"]), false, None);
        let e = run_task(&s.state, no_runner, action("platform", "SYSTEM", name), ns, fname, json!({})).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::FORBIDDEN, "{name}");
        let ctx = event_runner("platform", "SYSTEM");
        let e = context::with_request(ctx, exec::run(&s.state, Some(ns), fname, "platform", "SYSTEM", Arguments::Body(kirun::Map::new())))
            .await
            .err()
            .unwrap();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, message(job["function"].as_str().unwrap().rsplit('.').next().unwrap())));
        assert_eq!(s.targets.calls().len(), before, "{name}");
    }
}

// ------------------------------------------------------------------ each function's own behaviour

async fn platform_call(fs: &[Arc<dyn Function>], name: &str, args: Value) -> Result<Map<String, Value>, CoreError> {
    call_at(Place::Platform(None), find(fs, name).as_ref(), args).await
}

#[tokio::test]
async fn defaults_are_the_workers_and_arguments_reach_the_calls() {
    let (t, fs) = functions().await;
    platform_call(&fs, "RenewCertificates", json!({})).await.unwrap();
    platform_call(&fs, "RenewCertificates", json!({"daysBeforeExpiry": 3})).await.unwrap();
    platform_call(&fs, "CleanupTokens", json!({})).await.unwrap();
    platform_call(&fs, "CleanupTokens", json!({"unusedDays": null})).await.unwrap();
    platform_call(&fs, "CleanupTransports", json!({"service": " UI "})).await.unwrap();
    platform_call(&fs, "CleanupTransports", json!({"service": "core", "retentionDays": 30, "limit": 5})).await.unwrap();
    platform_call(&fs, "CleanupEventRuns", json!({})).await.unwrap();
    platform_call(&fs, "CleanupEventRuns", json!({"limit": 10, "staleAfterHours": 2})).await.unwrap();
    platform_call(&fs, "Meter", json!({"service": "Entity-Processor"})).await.unwrap();
    // Inside the platform app's own definition the functions run too.
    let r = call_at(Place::Platform(Some("platform")), find(&fs, "Meter").as_ref(), json!({"service": "files"})).await.unwrap();
    assert_eq!(r["result"], json!(true));
    assert_eq!(
        t.lines(),
        [
            "security /api/security/ssl/internal/renew-certificates?daysBeforeExpiry=30",
            "security /api/security/ssl/internal/renew-certificates?daysBeforeExpiry=3",
            "security /api/security/internal/tokens/cleanup?unusedDays=90",
            "security /api/security/internal/tokens/cleanup?unusedDays=90",
            "ui /api/ui/transports/internal/cleanupOlderThan?retentionDays=90&limit=200",
            "core /api/core/transports/internal/cleanupOlderThan?retentionDays=30&limit=5",
            "core /api/core/eventRuns/internal/cleanupOlderThan?retentionDays=90&successRetentionDays=7&staleAfterHours=6&limit=50000",
            "core /api/core/eventRuns/internal/cleanupOlderThan?retentionDays=90&successRetentionDays=7&staleAfterHours=2&limit=10",
            "entity-processor /api/entity/processor/internal/billing/meter",
            "files /api/files/internal/billing/meter",
        ]
    );
}

#[tokio::test]
async fn a_service_is_never_guessed() {
    let (t, fs) = functions().await;
    for (name, args, text) in [
        ("Meter", json!({"service": "ui"}), "CoreServices.Platform.Meter has no service 'ui'. Expected security, core, entity-processor or files."),
        ("Meter", json!({"service": " "}), "CoreServices.Platform.Meter has no service ''. Expected security, core, entity-processor or files."),
        ("CleanupTransports", json!({"service": "files"}), "Unknown service in transport cleanup: 'files'. Expected 'ui' or 'core'."),
        ("CleanupTransports", json!({"service": ""}), "CoreServices.Platform.CleanupTransports has no 'service'. Expected 'ui' or 'core'."),
    ] {
        let e = platform_call(&fs, name, args).await.unwrap_err();
        assert_eq!((e.status(), e.text().as_str()), (StatusCode::BAD_REQUEST, text));
    }
    // No service at all fails the signature (required, no default).
    for name in ["Meter", "CleanupTransports"] {
        let e = platform_call(&fs, name, json!({})).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR, "{name}");
        assert!(e.text().contains("service"), "{}", e.text());
    }
    // A wrong type fails the signature too.
    assert!(platform_call(&fs, "CleanupTokens", json!({"unusedDays": "ninety"})).await.is_err());
    assert!(t.calls().is_empty(), "{:?}", t.lines());
}

#[tokio::test]
async fn a_one_call_job_fails_with_the_services_answer() {
    let (t, fs) = functions().await;
    t.answer("/api/core/eventRuns/internal/cleanupOlderThan", 500, r#"{"message":"core is down"}"#);
    let e = platform_call(&fs, "CleanupEventRuns", json!({})).await.unwrap_err();
    assert_eq!((e.status(), e.text()), (StatusCode::INTERNAL_SERVER_ERROR, "core is down".to_string()));
    t.answer("/api/security/ssl/internal/renew-certificates", 500, r#"{"message":"Only system users can renew certificates"}"#);
    assert_eq!(platform_call(&fs, "RenewCertificates", json!({})).await.unwrap_err().text(), "Only system users can renew certificates");
    // An empty answer is null, as Feign reads it.
    t.answer("/api/files/internal/billing/meter", 200, "");
    assert_eq!(platform_call(&fs, "Meter", json!({"service": "files"})).await.unwrap()["result"], Value::Null);
    t.answer("/api/ui/transports/internal/cleanupOlderThan", 200, "");
    assert_eq!(platform_call(&fs, "CleanupTransports", json!({"service": "ui"})).await.unwrap()["result"], Value::Null);
    t.answer("/api/security/internal/tokens/cleanup", 200, "true");
    assert!(platform_call(&fs, "CleanupTokens", json!({})).await.unwrap_err().text().contains("JSON decoding error"));
}

#[tokio::test]
async fn reconcile_asks_every_service_and_then_names_the_failures() {
    let (t, fs) = functions().await;
    t.answer("/api/core/internal/billing/reconcile", 500, r#"{"message":"db down"}"#);
    t.answer("/api/files/internal/billing/reconcile", 200, "false");
    let e = platform_call(&fs, "ReconcileBilling", json!({})).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        e.text(),
        r#"CoreServices.Platform.ReconcileBilling: core: 500 db down (result: {"security":true,"core":null,"files":false})"#
    );
    assert_eq!(t.lines(), worker_calls("BILLING_RECONCILE"));
}

#[tokio::test]
async fn reconcile_takes_the_services_it_is_given() {
    let (t, fs) = functions().await;
    // In the order given, each once, names read as the meter reads them.
    let r = platform_call(&fs, "ReconcileBilling", json!({"services": ["files", " Entity-Processor ", "files"]})).await.unwrap();
    assert_eq!(r["result"], json!({"files": true, "entity-processor": true}));
    assert_eq!(
        t.lines(),
        ["files /api/files/internal/billing/reconcile", "entity-processor /api/entity/processor/internal/billing/reconcile"]
    );
    // null is the default; an empty list reconciles nothing.
    platform_call(&fs, "ReconcileBilling", json!({"services": null})).await.unwrap();
    assert_eq!(t.lines().len(), 2 + 3);
    let r = platform_call(&fs, "ReconcileBilling", json!({"services": []})).await.unwrap();
    assert_eq!((r["result"].clone(), t.lines().len()), (json!({}), 5));
    // A service it does not know, or ui (which has no billing), is refused before any call.
    for bad in ["ui", "nope"] {
        let e = platform_call(&fs, "ReconcileBilling", json!({"services": ["core", bad]})).await.unwrap_err();
        assert_eq!((e.status(), e.code().map(|c| c.code.to_string())), (StatusCode::BAD_REQUEST, Some("CORE.PLATFORM_ARGUMENT_INVALID".into())), "{bad}");
        assert!(e.text().contains(&format!("has no service '{bad}'")), "{}", e.text());
    }
    assert_eq!(t.lines().len(), 5);
}

fn paths(app: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("/{app}/whatsapp/incoming/{i}.jpg")).collect()
}

#[tokio::test]
async fn files_cleanup_raises_per_group_in_chunks_and_carries_on() {
    let (t, fs) = functions().await;
    let big = paths("leadzumptwo", 2 * MAX_PATHS_PER_EVENT + 201);
    t.answer(
        "/api/files/internal/secured/applyRetention",
        200,
        &json!([
            null,
            {"clientCode": "FIN", "appCode": "leadzumptwo", "paths": big},
            {"clientCode": "C2", "appCode": "a2", "resourceType": "SECURED", "paths": []},
            {"clientCode": "C3", "appCode": "a3", "paths": null},
            {"clientCode": "C4", "appCode": "a4", "resourceType": "Secured", "paths": ["/a4/x"]},
            {"clientCode": "C5", "appCode": "refused", "paths": ["/refused/x"]},
            {"clientCode": "C6", "appCode": "broken", "paths": ["/broken/x", "/broken/y"]}
        ])
        .to_string(),
    );
    t.answer("/api/files/internal/static/applyRetention", 200, &json!([{"clientCode": "C7", "paths": ["/z"]}]).to_string());
    let out = platform_call(&fs, "CleanupExpiredFiles", json!({"limit": 50})).await.unwrap();
    let r = &out["result"];
    assert_eq!(r["secured"], json!({"expiredRemoved": 3, "retentionRemoved": 1205, "eventsRaised": 4, "eventsFailed": 2}));
    assert_eq!(r["static"], json!({"expiredRemoved": 1, "retentionRemoved": 1, "eventsRaised": 0, "eventsFailed": 1}));
    assert_eq!(r["messagesMarkedExpired"], json!(7));
    let errors: Vec<&str> = r["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect();
    assert_eq!(errors.len(), 3, "{errors:?}");
    assert_eq!(errors[0], r#"secured FILES_EXPIRED for app "refused" client "C5" (1 paths): refused"#);
    assert!(errors[1].starts_with(r#"secured FILES_EXPIRED for app "broken" client "C6" (2 paths): "#), "{}", errors[1]);
    assert!(errors[2].starts_with(r#"static FILES_EXPIRED for app null client "C7" (1 paths): "#), "{}", errors[2]);

    let raises: Vec<Value> = t.calls().iter().filter(|c| c.path.ends_with("/raise")).map(|c| serde_json::from_str(&c.body).unwrap()).collect();
    assert_eq!(raises.len(), 7);
    let sizes: Vec<usize> = raises.iter().map(|r| r["data"]["paths"].as_array().unwrap().len()).collect();
    assert_eq!(sizes, [500, 500, 201, 1, 1, 2, 1]);
    assert_eq!(raises[0]["eventName"], json!("FILES_EXPIRED"));
    assert_eq!((raises[0]["appCode"].clone(), raises[0]["clientCode"].clone()), (json!("leadzumptwo"), json!("FIN")));
    // The group's type when it names one, the bucket's in capitals when not.
    assert_eq!(raises[0]["data"]["resourceType"], json!("SECURED"));
    assert_eq!(raises[3]["data"]["resourceType"], json!("Secured"));
    assert_eq!(raises[6]["data"]["resourceType"], json!("STATIC"));
    assert_eq!(raises[6]["appCode"], Value::Null);
    let all_paths: Vec<Value> = raises[..3].iter().flat_map(|r| r["data"]["paths"].as_array().unwrap().clone()).collect();
    assert_eq!(all_paths, big.iter().map(|p| json!(p)).collect::<Vec<_>>());
    // In the worker's order: lifetimes, retention (raising as it goes), then the stamping.
    let order: Vec<String> = t.lines().into_iter().filter(|l| !l.ends_with("/raise")).collect();
    assert_eq!(
        order,
        [
            "files /api/files/internal/secured/cleanupExpired?limit=50",
            "files /api/files/internal/static/cleanupExpired?limit=50",
            "files /api/files/internal/secured/applyRetention?limit=50",
            "files /api/files/internal/static/applyRetention?limit=50",
            "entity-processor /api/entity/processor/whatsapp/internal/media/stampExpired?retentionDays=30&limit=1000",
        ]
    );
    // Six raises for the secured groups (3 chunks, then 3 one-chunk groups), one for static.
    let lines = t.lines();
    assert!(lines[3..9].iter().all(|l| l == "core /api/core/events/internal/raise"), "{lines:?}");
    assert_eq!(lines[10], "core /api/core/events/internal/raise");
}

#[tokio::test]
async fn files_cleanup_runs_every_step_and_then_fails_on_a_files_error() {
    let (t, fs) = functions().await;
    t.answer("/api/files/internal/secured/cleanupExpired", 503, r#"{"message":"files is restarting"}"#);
    t.answer("/api/files/internal/static/applyRetention", 200, r#"["not a group"]"#);
    t.answer("/api/entity/processor/whatsapp/internal/media/stampExpired", 500, r#"{"message":"ep down"}"#);
    t.answer("/api/files/internal/secured/applyRetention", 200, &json!([{"clientCode": "FIN", "appCode": "leadzumptwo", "paths": ["/a"]}]).to_string());
    let e = platform_call(&fs, "CleanupExpiredFiles", json!({})).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BAD_GATEWAY);
    let text = e.text();
    assert!(text.starts_with("CoreServices.Platform.CleanupExpiredFiles: secured cleanupExpired: 503 files is restarting; static applyRetention: 500 "), "{text}");
    assert!(text.contains(r#""secured":{"expiredRemoved":null,"retentionRemoved":1,"eventsRaised":1,"eventsFailed":0}"#), "{text}");
    assert!(text.contains(r#""static":{"expiredRemoved":1,"retentionRemoved":null,"eventsRaised":0,"eventsFailed":0}"#), "{text}");
    assert!(text.contains("stampExpired: 500 ep down"), "{text}");
    // Every step was still taken.
    assert_eq!(
        t.lines(),
        [
            "files /api/files/internal/secured/cleanupExpired?limit=500",
            "files /api/files/internal/static/cleanupExpired?limit=500",
            "files /api/files/internal/secured/applyRetention?limit=500",
            "core /api/core/events/internal/raise",
            "files /api/files/internal/static/applyRetention?limit=500",
            "entity-processor /api/entity/processor/whatsapp/internal/media/stampExpired?retentionDays=30&limit=1000",
        ]
    );
    // A stamping failure alone is listed, not a failure.
    let (t2, fs2) = functions().await;
    t2.answer("/api/entity/processor/whatsapp/internal/media/stampExpired", 500, r#"{"message":"ep down"}"#);
    let out = platform_call(&fs2, "CleanupExpiredFiles", json!({})).await.unwrap();
    assert_eq!(out["result"]["messagesMarkedExpired"], Value::Null);
    assert_eq!(out["result"]["errors"], json!(["stampExpired: 500 ep down"]));
    // Without an entity-processor upstream (retired 2026-10-18) the stamping is skipped quietly.
    let t3 = Arc::new(Targets::default());
    let (mut ups, _) = t3.serve().await;
    ups.entity_processor = Err("not configured".into());
    let fs3 = all(&Arc::new(crate::platform_calls::PlatformCalls::new(ups).unwrap()));
    let out = platform_call(&fs3, "CleanupExpiredFiles", json!({})).await.unwrap();
    assert_eq!((out["result"]["messagesMarkedExpired"].clone(), out["result"]["errors"].clone()), (json!(0), json!([])));
    assert!(!t3.lines().iter().any(|l| l.starts_with("entity-processor")), "{:?}", t3.lines());
}

// ------------------------------------------------------------------ signatures and listing

#[tokio::test]
async fn signatures() {
    let (_, fs) = functions().await;
    assert_eq!(fs.len(), 7);
    let names: Vec<String> = fs.iter().map(|f| f.get_signature().get_full_name()).collect();
    assert_eq!(names, Job::ALL.iter().map(|j| j.full_name()).collect::<Vec<_>>());
    let param = |f: &str, p: &str| -> Value {
        let s = find(&fs, f).get_signature().clone();
        let p = s.get_parameters().get(p).unwrap_or_else(|| panic!("{f}.{p}")).clone();
        p.get_schema().get_default_value().cloned().unwrap_or(Value::Null)
    };
    assert_eq!(param("RenewCertificates", "daysBeforeExpiry"), json!(30));
    assert_eq!(param("CleanupTokens", "unusedDays"), json!(90));
    assert_eq!(param("CleanupExpiredFiles", "limit"), json!(500));
    assert_eq!((param("CleanupTransports", "retentionDays"), param("CleanupTransports", "limit")), (json!(90), json!(200)));
    assert_eq!(
        ["retentionDays", "successRetentionDays", "staleAfterHours", "limit"].map(|p| param("CleanupEventRuns", p)),
        [json!(90), json!(7), json!(6), json!(50000)]
    );
    assert_eq!(param("Meter", "service"), Value::Null);
    assert_eq!(param("CleanupTransports", "service"), Value::Null);
    assert_eq!(param("ReconcileBilling", "services"), json!(["security", "core", "files"]));
    for f in &fs {
        let sig = f.get_signature();
        assert!(sig.get_events().get("output").unwrap().get_parameters().contains_key("result"));
        assert!(sig.get_description().unwrap().ends_with("Runs only as a task of the platform app's events."));
        // As repositoryFind writes it for the platform app.
        let j = crate::repos::signature_json(f.as_ref());
        assert_eq!(j["namespace"], json!("CoreServices.Platform"));
    }
}

#[tokio::test]
async fn listed_only_for_the_platform_app_but_resolvable_everywhere() {
    let s = setup("[]").await;
    let core = s.state.inner().core_functions.clone();
    assert!(is_platform_function("CoreServices.Platform.Meter"));
    assert!(!is_platform_function("CoreServices.PlatformX.Meter"));
    assert!(!is_platform_function("CoreServices.Platform"));
    let other = listed(core.clone(), "leadzumptwo");
    assert!(other.find(Some("CoreServices.Platform"), "Meter").await.unwrap().is_none());
    assert!(other.find(Some("CoreServices"), "Platform.Meter").await.unwrap().is_none());
    assert!(other.find(Some("CoreServices.Hash"), "HashData").await.unwrap().is_some());
    // The 72 Java has, SendDataNotification, Storage.GetFields, Storage.Batch / UpdateIf /
    // NextSequence, Event.GetScheduleState and Security.SendContactCode / VerifyContactCode.
    assert_eq!(other.filter("").await.unwrap().len(), 80);
    assert_eq!(other.filter("senddatanotification").await.unwrap(), ["CoreServices.Notification.SendDataNotification"]);
    assert!(other.filter("platform").await.unwrap().is_empty());
    let mine = listed(core.clone(), "platform");
    assert!(mine.find(Some("CoreServices.Platform"), "Meter").await.unwrap().is_some());
    assert_eq!(mine.filter("coreservices.platform").await.unwrap().len(), 7);
    // Execution reads the repository itself.
    assert!(core.find(Some("CoreServices.Platform"), "CleanupEventRuns").await.unwrap().is_some());

    let c = Http::new(&s.state).await;
    let find_q = "namespace=CoreServices.Platform&name=Meter";
    let (st, body) = c.send("GET", &format!("/api/core/functions/repositoryFind?appCode=leadzumptwo&clientCode=SYSTEM&{find_q}"), "leadzumptwo", true, None).await;
    assert_eq!((st, body), (200, Value::String(String::new())));
    let data_q = "namespace=CoreServices.Notification&name=SendDataNotification";
    let (st, body) = c.send("GET", &format!("/api/core/functions/repositoryFind?appCode=leadzumptwo&clientCode=SYSTEM&{data_q}"), "leadzumptwo", true, None).await;
    assert_eq!(st, 200);
    assert_eq!(body["definition"]["name"], json!("SendDataNotification"));
    assert_eq!(body["definition"]["parameters"]["ttlSeconds"]["schema"]["defaultValue"], json!(60));
    let (st, body) = c.send("GET", &format!("/api/core/functions/repositoryFind?appCode=platform&clientCode=SYSTEM&{find_q}"), "platform", true, None).await;
    assert_eq!(st, 200);
    assert_eq!((body["definition"]["namespace"].clone(), body["definition"]["name"].clone()), (json!("CoreServices.Platform"), json!("Meter")));
    // The app comes from the caller when the query names none.
    let (_, body) = c.send("GET", &format!("/api/core/functions/repositoryFind?{find_q}"), "appbuilder", true, None).await;
    assert_eq!(body, Value::String(String::new()));
    let (st, body) = c.send("GET", "/api/core/functions/repositoryFilter?appCode=leadzumptwo&clientCode=SYSTEM&filter=platform", "leadzumptwo", true, None).await;
    assert_eq!((st, body), (200, json!([])));
    let (_, body) = c.send("GET", "/api/core/functions/repositoryFilter?appCode=leadzumptwo&clientCode=SYSTEM&filter=CoreServices.Hash", "leadzumptwo", true, None).await;
    assert_eq!(body, json!(["CoreServices.Hash.HashData"]));
    let (_, body) = c.send("GET", "/api/core/functions/repositoryFilter?appCode=platform&clientCode=SYSTEM&filter=Platform.", "platform", true, None).await;
    let listed_names: BTreeSet<String> = body.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(listed_names, Job::ALL.iter().map(|j| j.full_name()).collect::<BTreeSet<_>>());
    // Executing from another app is the guard's 403, not a 404.
    let (st, _) = c.send("POST", "/api/core/function/execute/CoreServices.Platform/Meter", "leadzumptwo", true, Some(r#"{"service":"core"}"#)).await;
    assert_eq!(st, 403);
    assert!(s.targets.calls().is_empty());
}

// ------------------------------------------------------------------ the seed

/// The worker's rows (V3, V9, V10, V11, V13; V14 removed only entity-processor jobs), less
/// entity-processor-metering (that service retired with the switch, 2026-10-18):
/// task name, job type, Quartz schedule, job data.
const WORKER_TASKS: &[(&str, &str, &str, &str)] = &[
    ("ssl-certificate-renewal", "SSL_RENEWAL", "0 0 2 * * ?", r#"{"daysBeforeExpiry": 3}"#),
    ("expired-token-cleanup", "TOKEN_CLEANUP", "0 0 3 * * ?", r#"{"unusedDays": 90}"#),
    ("security-metering", "SECURITY_METERING", "0 0/15 * * * ?", "{}"),
    ("core-metering", "CORE_METERING", "0 0/15 * * * ?", "{}"),
    ("files-metering", "FILES_METERING", "0 0/15 * * * ?", "{}"),
    ("billing-reconcile", "BILLING_RECONCILE", "0 45 0 * * ?", "{}"),
    ("files-ttl-cleanup", "FILES_TTL_CLEANUP", "0 20 * * * ?", r#"{"limit": 500}"#),
    ("transport-cleanup-ui", "TRANSPORT_CLEANUP", "0 40 3 * * ?", r#"{"service": "ui", "retentionDays": 90, "limit": 200}"#),
    ("transport-cleanup-core", "TRANSPORT_CLEANUP", "0 50 3 * * ?", r#"{"service": "core", "retentionDays": 90, "limit": 200}"#),
    (
        "event-run-cleanup",
        "EVENT_RUN_CLEANUP",
        "0 25 * * * ?",
        r#"{"retentionDays": 90, "successRetentionDays": 7, "staleAfterHours": 6, "limit": 50000}"#,
    ),
];

/// The values a cron field takes: `*`, `?`, `n`, `a-b`, `*/s`, `a/s`, `a-b/s`, lists.
fn expand(field: &str, lo: u32, hi: u32) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for part in field.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().unwrap()),
            None => (part, 1),
        };
        let (a, b) = match range {
            "*" | "?" => (lo, hi),
            r => match r.split_once('-') {
                Some((a, b)) => (a.parse().unwrap(), b.parse().unwrap()),
                None => {
                    let a: u32 = r.parse().unwrap();
                    (a, if part.contains('/') { hi } else { a })
                }
            },
        };
        out.extend((a..=b).step_by(step as usize));
    }
    out
}

#[test]
fn the_seed_carries_the_workers_jobs_with_the_same_instants() {
    let seed = seed();
    let app = &seed["app"];
    assert_eq!((app["appCode"].as_str(), app["clientCode"].as_str()), (Some("platform"), Some("SYSTEM")));
    let jobs = seed["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), WORKER_TASKS.len());
    let by = |list: &str, name: &str| -> Value {
        let found: Vec<&Value> = seed[list].as_array().unwrap().iter().filter(|d| d["name"] == name).collect();
        assert_eq!(found.len(), 1, "{list} {name}");
        found[0].clone()
    };
    for (job, (task, jtype, quartz, data)) in jobs.iter().zip(WORKER_TASKS) {
        let name = job["name"].as_str().unwrap();
        assert_eq!((job["workerTask"].as_str(), job["workerJobType"].as_str(), job["workerSchedule"].as_str()), (Some(*task), Some(*jtype), Some(*quartz)), "{name}");
        let data: Value = serde_json::from_str(data).unwrap();
        assert_eq!(job["workerJobData"], data, "{name}");
        // A metering row's job type picked the service; the function takes it as an argument.
        // BILLING_RECONCILE names the services it reconciles (the worker's four less entity-processor).
        let data = match jtype.strip_suffix("_METERING") {
            Some(service) => json!({"service": service.to_lowercase().replace('_', "-")}),
            None if *jtype == "BILLING_RECONCILE" => json!({"services": ["security", "core", "files"]}),
            None => data,
        };
        assert_eq!(job["arguments"], data, "{name}");

        // The schedule: one run for SYSTEM, UTC, on, at the worker's instants.
        let def = by("eventDefinitions", name);
        assert_eq!((def["appCode"].as_str(), def["clientCode"].as_str()), (Some("platform"), Some("SYSTEM")));
        let cron = def["schedule"]["cron"].as_str().unwrap();
        assert_eq!(def["schedule"], json!({"cron": cron, "timezone": "UTC", "enabled": true, "perClient": false}), "{name}");
        assert_eq!(job["cron"].as_str(), Some(cron));
        let q: Vec<&str> = quartz.split(' ').collect();
        let u: Vec<&str> = cron.split(' ').collect();
        assert_eq!((q.len(), u.len()), (6, 5), "{name}");
        // CronGrid prepends "0 " (second 0) to five fields; the worker's crons fire at second 0.
        assert_eq!(expand(q[0], 0, 59), BTreeSet::from([0]), "{name}");
        assert_eq!(expand(q[1], 0, 59), expand(u[0], 0, 59), "{name} minutes");
        assert_eq!(expand(q[2], 0, 23), expand(u[1], 0, 23), "{name} hours");
        for (qf, uf) in [(q[3], u[2]), (q[4], u[3]), (q[5], u[4])] {
            assert!(matches!(qf, "*" | "?") && uf == "*", "{name}: every day");
        }

        // The action: one task calling the job's function, no arguments.
        let act = by("eventActions", name);
        let tasks = act["tasks"].as_object().unwrap();
        assert_eq!(tasks.len(), 1, "{name}");
        let t = &tasks["key1"];
        assert_eq!(t["type"], json!("CALL_CORE_FUNCTION"));
        assert_eq!(t["parameters"], json!({"namespace": "Platform.Jobs", "name": name}));

        // The job function: executeAuth for the event runner, one step calling the platform
        // function with exactly the job data.
        let f = by("functions", &format!("Platform.Jobs.{name}"));
        assert_eq!((f["appCode"].as_str(), f["clientCode"].as_str()), (Some("platform"), Some("SYSTEM")));
        assert_eq!(f["executeAuth"], json!("Authorities._Event_Runner"));
        let d = &f["definition"];
        assert_eq!((d["namespace"].as_str(), d["name"].as_str()), (Some("Platform.Jobs"), Some(name)));
        let step = &d["steps"]["run"];
        assert_eq!(format!("{}.{}", step["namespace"].as_str().unwrap(), step["name"].as_str().unwrap()), job["function"].as_str().unwrap());
        let args: Map<String, Value> =
            step["parameterMap"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v["one"]["value"].clone())).collect();
        assert_eq!(Value::Object(args), data, "{name}");
    }
    assert_eq!(seed["functions"].as_array().unwrap().len(), 10);
    assert_eq!(seed["eventDefinitions"].as_array().unwrap().len(), 10);
    assert_eq!(seed["eventActions"].as_array().unwrap().len(), 10);
    // The cron dialect: Quartz's 0/15 is every quarter hour, as */15.
    assert_eq!(expand("0/15", 0, 59), expand("*/15", 0, 59));
    assert_eq!(expand("0/15", 0, 59), BTreeSet::from([0, 15, 30, 45]));
    assert_eq!(expand("5-55/5", 0, 59).len(), 11);
    assert_eq!(expand("1,2", 0, 59), BTreeSet::from([1, 2]));
}

// ------------------------------------------------------------------ through core-events

struct SystemClient;

#[async_trait::async_trait]
impl crate::events::ClientLookup for SystemClient {
    async fn client_by_code(&self, code: &str) -> Result<Option<Value>, CoreError> {
        Ok(Some(json!({"id": 1, "code": code, "typeCode": "SYS", "levelType": "SYSTEM"})))
    }
}

/// The listener core-events runs, over `s`, its run log in memory.
fn listener(s: &Setup) -> (crate::events::EventsListener, Arc<crate::event_runs::MemoryEventRunDao>) {
    let dao = Arc::new(crate::event_runs::MemoryEventRunDao::default());
    let inner = s.state.inner();
    let runs = Arc::new(crate::event_runs::EventRunService::new(
        dao.clone(),
        Arc::new(crate::scheduler::EventDefinitionService::new(
            inner.definitions.store().clone(),
            CacheService::new("cmn", "evictionChannel", None).unwrap(),
        )),
        Arc::new(crate::clients::SecurityCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap()),
        true,
    ));
    let l = crate::events::EventsListener::new(Arc::new(crate::events::StoreActions(inner.definitions.store().clone())), Arc::new(SystemClient))
        .with_executor(crate::events::CALL_CORE_FUNCTION, Arc::new(crate::events::CallCoreFunction { state: s.state.clone() }))
        .with_run_log(runs);
    (l, dao)
}

fn tick(event: &str) -> connections::mq::EventMessage {
    connections::mq::EventMessage {
        event_name: Some(event.into()),
        app_code: Some("platform".into()),
        client_code: Some("SYSTEM".into()),
        data: Some(json!({"_schedule": {"kind": "cron", "runId": "r1", "tickAt": "2026-10-16T02:00:00Z"}}).as_object().unwrap().clone()),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_scheduled_tick_runs_its_job_through_the_events_listener() {
    let seed = seed();
    let s = setup("[]").await;
    for f in seed["functions"].as_array().unwrap() {
        put_function(&s.backend, f);
    }
    for a in seed["eventActions"].as_array().unwrap() {
        s.backend.put_raw("eventAction", mongodb::bson::to_document(a).unwrap());
    }
    let (l, dao) = listener(&s);
    // A tick: raised without a caller, so it runs as the client's anonymous event runner.
    assert_eq!(l.run(&tick("SSL_RENEWAL")).await.unwrap(), Some(true));
    assert_eq!(s.targets.lines(), worker_calls("SSL_RENEWAL"));
    let rows = dao.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, Some(crate::event_runs::RunStatus::Success));
    assert_eq!(rows[0].trigger_type, Some(crate::event_runs::TriggerType::Schedule));
    let task = &rows[0].tasks.as_ref().unwrap()[0];
    assert_eq!(task.target.as_deref(), Some("Platform.Jobs.SSL_RENEWAL"));

    // The same event raised by a caller (CreateEvent carries the raiser's authentication):
    // the job function's executeAuth (the event runner) refuses it before the platform
    // function's own guard is reached; nothing is called, and the run says why.
    let before = s.targets.calls().len();
    let mut raised = tick("TOKEN_CLEANUP");
    raised.data = None;
    raised.authentication = Some(json!({"user": {"id": 142, "clientId": 1, "stringAuthorities": ["Authorities.ROLE_Owner"]},
                                        "isAuthenticated": true, "clientCode": "SYSTEM", "urlClientCode": "SYSTEM", "urlAppCode": "platform"}));
    assert_eq!(l.run(&raised).await.unwrap(), Some(false));
    assert_eq!(s.targets.calls().len(), before);
    let rows = dao.rows();
    let refused = rows.last().unwrap();
    assert_eq!(refused.status, Some(crate::event_runs::RunStatus::Failed));
    let error = refused.tasks.as_ref().unwrap()[0].error.clone().unwrap();
    assert!(error.starts_with("Authorization"), "{error}");
}

#[tokio::test]
async fn a_failing_step_leaves_its_trace_in_the_run_log() {
    let s = setup("[]").await;
    // A platform job function whose step asks for a service the meter does not know.
    let mut f = meter_caller("platform", "Platform.Broken");
    f["definition"]["steps"]["run"]["parameterMap"]["service"]["one"]["value"] = json!("nope");
    put_function(&s.backend, &f);
    s.backend.put_raw(
        "eventAction",
        mongodb::bson::to_document(&json!({"name": "BROKEN", "appCode": "platform", "clientCode": "SYSTEM", "tasks": {
            "t1": {"key": "t1", "order": 0, "type": "CALL_CORE_FUNCTION", "parameters": {"namespace": "Platform.Broken", "name": "meter"}}}}))
        .unwrap(),
    );
    let (l, dao) = listener(&s);
    assert_eq!(l.run(&tick("BROKEN")).await.unwrap(), Some(false));
    assert!(s.targets.calls().is_empty());
    let task = dao.rows()[0].tasks.as_ref().unwrap()[0].clone();
    let error = task.error.unwrap();
    assert!(error.contains("at step run (CoreServices.Platform.Meter) of Platform.Broken.meter"), "{error}");
    let detail = task.detail.unwrap();
    assert!(detail.starts_with("KIRun steps, innermost first:"), "{detail}");
    assert!(detail.contains("\"service\": \"nope\""), "{detail}");
}

// ------------------------------------------------------------------ failures name their step

/// A stored function whose step `add` gives `System.Math.Add` a value that is not a number.
fn broken_adder() -> Value {
    json!({
        "name": "Probe.Fns.broken", "appCode": "platform", "clientCode": "SYSTEM",
        "definition": {
            "name": "broken", "namespace": "Probe.Fns", "parameters": {},
            "events": {"output": {"name": "output", "parameters": {}}},
            "steps": {
                "add": {"statementName": "add", "namespace": "System.Math", "name": "Add",
                        "parameterMap": {"value": {"one": {"key": "one", "type": "VALUE", "value": "abc", "order": 1}}}}
            }
        }
    })
}

/// Java answers "Please try again" with KIRun's chain in `debugMessage`; core-exec keeps the
/// chain there and says which step failed, in which function, and why.
#[tokio::test]
async fn a_failing_step_is_named() {
    let s = setup("[]").await;
    put_function(&s.backend, &broken_adder());
    let c = Http::new(&s.state).await;
    let (st, body) = c.send("POST", "/api/core/function/execute/Probe.Fns/broken", "platform", true, Some("{}")).await;
    assert_eq!(st, 500, "{body}");
    assert_eq!(body["code"], json!("CORE.FUNCTION_STEP_FAILED"), "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(message.starts_with("Step add (System.Math.Add) in Probe.Fns.broken failed: the value of value is not valid ("), "{message}");
    assert_eq!(body["params"]["step"], json!("add"));
    let debug = body["debugMessage"].as_str().unwrap();
    assert!(debug.starts_with("Error while executing the function System.Math.Add's parameter value in statement 'add'"), "{debug}");
    assert!(debug.ends_with("\nat step add (System.Math.Add) of Probe.Fns.broken"), "{debug}");
    assert!(!debug.contains("arguments"), "no step arguments go to the caller: {debug}");

    // A system function run directly has no step to name: the function, and why.
    let (st, body) = c.send("POST", "/api/core/function/execute/System.Math/Add", "platform", true, Some(r#"{"value": "abc"}"#)).await;
    assert_eq!((st, body["code"].clone()), (500, json!("CORE.FUNCTION_FAILED")), "{body}");
    assert!(body["message"].as_str().unwrap().starts_with("The function System.Math.Add failed: the value of value is not valid ("), "{body}");
    // A refusal a function raises comes up as it is.
    put_function(&s.backend, &meter_caller("platform", "Probe.Fns"));
    let (st, body) = c.send("POST", "/api/core/function/execute/Probe.Fns/meter", "platform", true, Some("{}")).await;
    assert_eq!((st, body["code"].clone()), (403, json!("CORE.PLATFORM_FUNCTION_REFUSED")));
}
