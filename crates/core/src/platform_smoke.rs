//! The one deliberate local smoke run of a platform job: `CoreServices.Platform.CleanupTransports`
//! for core, with a cut-off a hundred years back (`retentionDays = 36500`, `limit = 1`), so the
//! real call to the Java core's `/api/core/transports/internal/cleanupOlderThan` can remove
//! nothing. Run on purpose only: `RS_PLATFORM_SMOKE=1`, CORE_LOCAL_STACK=1, config/local.toml and
//! `CONFIG_FILE=<repo>/config/core-exec.toml` (tests run in the crate directory).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "one deliberate local smoke run: RS_PLATFORM_SMOKE=1 CORE_LOCAL_STACK=1 and config/local.toml"]
async fn cleanup_transports_on_the_local_stack_removes_nothing() {
    use std::sync::Arc;

    use serde_json::json;

    use crate::context::{self, EventActionRun, RequestContext};
    use crate::exec::{self, Arguments};

    if std::env::var("RS_PLATFORM_SMOKE").as_deref() != Ok("1") || !crate::testing::local_stack() {
        return;
    }
    let cfg: crate::config::CoreConfig = platform::config::load("core-exec").unwrap();
    let exec = crate::connect(&cfg).await.unwrap();
    let client = exec.security_calls.client_by_code("SYSTEM").await.unwrap().unwrap();
    let auth = crate::events::anonymous_authentication(Some("platform"), Some("SYSTEM"), &client).unwrap();
    let ctx = Arc::new(RequestContext { auth: Arc::new(auth), app_code: Some("platform".into()), client_code: Some("SYSTEM".into()), ..Default::default() });
    let run = EventActionRun { app_code: "platform".into(), client_code: "SYSTEM".into(), event_name: "TRANSPORT_CLEANUP_CORE".into() };
    let args: kirun::Map<serde_json::Value> =
        json!({"service": "core", "retentionDays": 36500, "limit": 1}).as_object().unwrap().clone().into_iter().collect();
    let out = context::with_request(
        ctx,
        context::with_event_action(run, async {
            exec::run(&exec.state, Some("CoreServices.Platform"), "CleanupTransports", "platform", "SYSTEM", Arguments::Body(args)).await
        }),
    )
    .await
    .unwrap()
    .expect("found");
    let mut out = out;
    let result = out.next().unwrap().get_result().get("result").cloned().unwrap();
    println!("CleanupTransports(core, 36500 days, limit 1) answered {result}");
    assert_eq!(result, json!({"transportsRemoved": 0, "versionsRemoved": 0}));
}
