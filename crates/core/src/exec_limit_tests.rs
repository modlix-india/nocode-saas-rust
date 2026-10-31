use super::*;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;

use futures::FutureExt;
use kirun::repository::{KIRunFunctionRepository, KIRunSchemaRepository};
use serde_json::{json, Value};

use crate::exec::{self, Arguments, Repositories};
use crate::repos::definition::DefinitionFunction;
use crate::repos::{FunctionSource, Hybrid, KirunFunctions, KirunSchemas};

fn settings(max_execution_seconds: u64, max_steps: u64) -> KirunSection {
    KirunSection { max_execution_seconds: Some(max_execution_seconds), max_steps }
}

/// The quadratic build that took the dev unit down (AdZumpV2.cmpTree, 2026-10-30): a range loop
/// that appends to an array in the context, each step copying the whole array, and, past the
/// loop, the array as the output. `to` is far beyond any limit.
fn runaway(name: &str) -> Value {
    json!({
        "name": name, "namespace": "Test",
        "events": {"output": {"name": "output", "parameters": {"value": {"type": "ARRAY", "items": {"type": "INTEGER"}}}}},
        "steps": {
            "create": {"statementName": "create", "namespace": "System.Context", "name": "Create",
                "parameterMap": {
                    "name": {"one": {"key": "one", "type": "VALUE", "value": "array"}},
                    "schema": {"one": {"key": "one", "type": "VALUE", "value": {"type": "ARRAY", "items": {"type": "INTEGER"}}}}}},
            "init": {"statementName": "init", "namespace": "System.Context", "name": "Set",
                "parameterMap": {
                    "name": {"one": {"key": "one", "type": "VALUE", "value": "Context.array"}},
                    "value": {"one": {"key": "one", "type": "VALUE", "value": []}}},
                "dependentStatements": {"Steps.create.output": true}},
            "loop": {"statementName": "loop", "namespace": "System.Loop", "name": "RangeLoop",
                "parameterMap": {
                    "from": {"one": {"key": "one", "type": "VALUE", "value": 0}},
                    "to": {"one": {"key": "one", "type": "VALUE", "value": 1_000_000_000_i64}}},
                "dependentStatements": {"Steps.init.output": true}},
            "insert": {"statementName": "insert", "namespace": "System.Array", "name": "InsertLast",
                "parameterMap": {
                    "source": {"one": {"key": "one", "type": "EXPRESSION", "expression": "Context.array"}},
                    "element": {"one": {"key": "one", "type": "EXPRESSION", "expression": "Steps.loop.iteration.index"}}}},
            "set": {"statementName": "set", "namespace": "System.Context", "name": "Set",
                "parameterMap": {
                    "name": {"one": {"key": "one", "type": "VALUE", "value": "Context.array"}},
                    "value": {"one": {"key": "one", "type": "EXPRESSION", "expression": "Steps.insert.output.result"}}}},
            "out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                "parameterMap": {
                    "eventName": {"one": {"key": "one", "type": "VALUE", "value": "output"}},
                    "results": {"one": {"key": "one", "type": "VALUE",
                        "value": {"name": "value", "value": {"isExpression": true, "value": "Context.array"}}}}},
                "dependentStatements": {"Steps.loop.output": true}}
        }
    })
}

/// `Test.addOne`: n + 1.
fn add_one() -> Value {
    json!({
        "name": "addOne", "namespace": "Test",
        "parameters": {"n": {"parameterName": "n", "schema": {"type": "INTEGER"}}},
        "events": {"output": {"name": "output", "parameters": {"result": {"type": "INTEGER"}}}},
        "steps": {
            "add": {"statementName": "add", "namespace": "System.Math", "name": "Add",
                    "parameterMap": {"value": {
                        "one": {"key": "one", "type": "EXPRESSION", "expression": "Arguments.n", "order": 1},
                        "two": {"key": "two", "type": "VALUE", "value": 1, "order": 2}}}},
            "out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                    "parameterMap": {
                        "eventName": {"e": {"key": "e", "type": "VALUE", "value": "output"}},
                        "results": {"r": {"key": "r", "type": "VALUE", "value": {"name": "result", "value": {"isExpression": true, "value": "Steps.add.output.value"}}}}}}
        }
    })
}

/// `Test.outer`: calls `Test.runaway` as a step, so the steps that run long are a nested
/// definition's.
fn outer() -> Value {
    json!({
        "name": "outer", "namespace": "Test",
        "events": {"output": {"name": "output", "parameters": {}}},
        "steps": {
            "call": {"statementName": "call", "namespace": "Test", "name": "runaway"},
            "out": {"statementName": "out", "namespace": "System", "name": "GenerateEvent",
                "parameterMap": {"eventName": {"e": {"key": "e", "type": "VALUE", "value": "output"}}},
                "dependentStatements": {"Steps.call.output": true}}
        }
    })
}

/// The stored definitions of a test app.
struct Definitions(HashMap<String, Arc<dyn Function>>);

#[async_trait]
impl FunctionSource for Definitions {
    async fn find(&self, namespace: Option<&str>, name: &str) -> Result<Option<Arc<dyn Function>>, CoreError> {
        Ok(self.0.get(&format!("{}.{name}", namespace.unwrap_or(""))).cloned())
    }

    async fn filter(&self, _: &str) -> Result<Vec<String>, CoreError> {
        Ok(Vec::new())
    }
}

/// What `exec::repositories` layers for an app: KIRun's functions, then the app's definitions.
fn repositories() -> Repositories {
    let mut defs: HashMap<String, Arc<dyn Function>> = HashMap::new();
    for d in [runaway("runaway"), add_one(), outer()] {
        let name = format!("Test.{}", d["name"].as_str().unwrap());
        defs.insert(name, Arc::new(DefinitionFunction::new(d, None, None, Duration::from_secs(300)).unwrap()));
    }
    let functions: Vec<Arc<dyn FunctionSource>> =
        vec![Arc::new(KirunFunctions(Arc::new(KIRunFunctionRepository::new()))), Arc::new(Definitions(defs))];
    Repositories {
        functions: Arc::new(Hybrid::new(functions)),
        schemas: Arc::new(Hybrid::<dyn crate::repos::SchemaSource>::new(vec![Arc::new(KirunSchemas(Arc::new(KIRunSchemaRepository::new())))])),
    }
}

/// `exec::run` for `Test.<name>` on [`repositories`], within `settings`.
async fn run(settings: &KirunSection, name: &str, args: Value) -> Result<Option<FunctionOutput>, CoreError> {
    let repos = repositories();
    let args = args.as_object().cloned().unwrap_or_default().into_iter().collect();
    guard(settings, &format!("Test.{name}"), "testapp", "TESTCLIENT", exec::run_in(&repos, Some("Test"), name, Arguments::Body(args)))
        .await
        .and_then(|r| r)
}

fn assert_time_limit(e: &CoreError, function: &str, seconds: u64) {
    assert_eq!(e.status(), StatusCode::UNPROCESSABLE_ENTITY, "{e:?}");
    let c = e.code().unwrap_or_else(|| panic!("a coded error: {e:?}"));
    assert_eq!(c.code, TIME_LIMIT_CODE);
    assert_eq!(
        c.english().message,
        format!("The function {function} ran longer than one call may ({seconds} seconds) and was stopped.")
    );
}

#[tokio::test]
async fn a_runaway_function_is_stopped_at_the_limit_and_the_next_call_runs() {
    let started = Instant::now();
    let e = run(&settings(1, 0), "runaway", json!({})).await.unwrap_err();
    let took = started.elapsed();
    assert_time_limit(&e, "Test.runaway", 1);
    // Stopped at a step, not by the backstop: within the second plus one step.
    assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(1) + BACKSTOP_GRACE, "{took:?}");

    // The same process, the next call: unaffected.
    let mut out = run(&settings(1, 0), "addOne", json!({"n": 41})).await.unwrap().unwrap();
    assert_eq!(out.next().unwrap().get_result()["result"], json!(42));
}

#[tokio::test]
async fn the_steps_of_a_nested_definition_are_held_to_the_same_limit() {
    let started = Instant::now();
    let e = run(&settings(1, 0), "outer", json!({})).await.unwrap_err();
    assert_time_limit(&e, "Test.outer", 1);
    assert!(started.elapsed() < Duration::from_secs(1) + BACKSTOP_GRACE);
}

/// `#[tokio::test]` is a single thread: without the yields, nothing else would run on it until
/// the function ended.
#[tokio::test]
async fn other_work_on_the_same_thread_goes_on_while_a_function_runs_long() {
    let ticks = Arc::new(AtomicU64::new(0));
    let t = ticks.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(5)).await;
            t.fetch_add(1, Ordering::Relaxed);
        }
    });
    let e = run(&settings(1, 0), "runaway", json!({})).await.unwrap_err();
    assert_time_limit(&e, "Test.runaway", 1);
    ticker.abort();
    // Without the yields it would not run at all until the function ended; with them it runs
    // every few tens of milliseconds (the timer is read between yields, not at each one).
    let n = ticks.load(Ordering::Relaxed);
    assert!(n >= 20, "the other task ran {n} times in a second");
}

#[tokio::test]
async fn the_step_limit_is_a_second_guard() {
    let e = run(&settings(0, 200), "runaway", json!({})).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let c = e.code().unwrap();
    assert_eq!(c.code, STEP_LIMIT_CODE);
    assert_eq!(c.english().message, "The function Test.runaway ran more steps than one call may (200) and was stopped.");
    // Within its steps a function runs as before.
    let mut out = run(&settings(0, 200), "addOne", json!({"n": 1})).await.unwrap().unwrap();
    assert_eq!(out.next().unwrap().get_result()["result"], json!(2));
}

#[tokio::test]
async fn a_run_inside_another_shares_its_budget() {
    let started = Instant::now();
    // The inner run's own (longer) setting is not used: the outer budget is.
    let r = guard(&settings(1, 0), "Test.caller", "testapp", "TESTCLIENT", async {
        let inner = run(&settings(600, 0), "runaway", json!({})).await;
        assert!(stopped());
        inner
    })
    .await;
    let e = r.unwrap_err();
    assert_time_limit(&e, "Test.caller", 1);
    assert!(started.elapsed() < Duration::from_secs(1) + BACKSTOP_GRACE);
    assert!(!active(), "the budget ends with the outer run");
}

/// A run stuck in an await (a slow query, an outbound call) is dropped a little after the
/// limit; what it held is released as the future is dropped.
#[tokio::test]
async fn a_run_stuck_in_an_await_is_dropped_after_the_limit() {
    struct Held(Arc<AtomicBool>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let released = Arc::new(AtomicBool::new(false));
    let held = Held(released.clone());
    let started = Instant::now();
    let r = guard(&settings(1, 0), "Test.waits", "testapp", "TESTCLIENT", async move {
        let _held = held;
        tokio::time::sleep(Duration::from_secs(60)).await;
    })
    .await;
    assert_time_limit(&r.unwrap_err(), "Test.waits", 1);
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(1) + BACKSTOP_GRACE && took < Duration::from_secs(5), "{took:?}");
    assert!(released.load(Ordering::SeqCst));
}

/// A loop function called directly hands back its iterations as events; reading them counts
/// against the same budget (`exec::execute`).
#[tokio::test]
async fn the_events_of_a_loop_called_directly_are_read_within_the_limit() {
    let repos = repositories();
    let args: kirun::Map<Value> = [("to".to_string(), json!(1_000_000_000_000_i64))].into_iter().collect();
    let r = guard(&settings(1, 0), "System.Loop.RangeLoop", "testapp", "TESTCLIENT", async {
        let out = exec::run_in(&repos, Some("System.Loop"), "RangeLoop", Arguments::Body(args)).await?;
        Ok::<_, CoreError>(exec::events_text(out.unwrap()).await)
    })
    .await;
    assert_time_limit(&r.unwrap_err(), "System.Loop.RangeLoop", 1);
}

#[tokio::test]
async fn no_limit_is_no_limit_and_outside_a_run_the_gate_is_open() {
    assert!(step().await.is_ok());
    assert!(!stopped());
    let mut out = run(&settings(0, 0), "addOne", json!({"n": 1})).await.unwrap().unwrap();
    assert_eq!(out.next().unwrap().get_result()["result"], json!(2));
    let b = Budget::new(&settings(0, 0), "f", "a", "c");
    for _ in 0..10_000 {
        assert_ne!(b.step(), Gate::Stop);
    }
}

#[test]
fn the_section_binds_from_toml_with_a_default_per_unit() {
    let c: crate::config::CoreConfig = toml::from_str("[kirun]\nmax_execution_seconds = 600\nmax_steps = 5000000").unwrap();
    assert_eq!(c.kirun, settings(600, 5_000_000));
    assert_eq!(c.kirun.clone().for_events().seconds(), 600, "a configured limit is kept by core-events");
    let d: crate::config::CoreConfig = toml::from_str("").unwrap();
    assert_eq!((d.kirun.seconds(), d.kirun.max_steps), (DEFAULT_MAX_EXECUTION_SECONDS, 0));
    assert_eq!(d.kirun.clone().for_events().seconds(), EVENTS_MAX_EXECUTION_SECONDS);
    let off: crate::config::CoreConfig = toml::from_str("[kirun]\nmax_execution_seconds = 0").unwrap();
    assert_eq!(off.kirun.for_events().seconds(), 0, "0 is no limit, in every unit");
}

// ------------------------------------------------------------------ against the local MySQL

/// A pool on the local MySQL (`eval "$(tools/local-env.py)"` for the password) with a scratch
/// database `RUSTTEST_execlimit`, created here and dropped by the caller.
async fn scratch_pool() -> sqlx::MySqlPool {
    let password = std::env::var("MODLIX__DATABASE__PASSWORD").expect("MODLIX__DATABASE__PASSWORD (eval \"$(tools/local-env.py)\")");
    let opts = sqlx::mysql::MySqlConnectOptions::new().host("127.0.0.1").port(3306).username("root").password(&password);
    let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(4).connect_with(opts).await.unwrap();
    sqlx::query("DROP DATABASE IF EXISTS RUSTTEST_execlimit").execute(&pool).await.unwrap();
    sqlx::query("CREATE DATABASE RUSTTEST_execlimit").execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE RUSTTEST_execlimit.t (ID INT PRIMARY KEY, NOTE VARCHAR(20))").execute(&pool).await.unwrap();
    pool
}

async fn rows(pool: &sqlx::MySqlPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM RUSTTEST_execlimit.t").fetch_one(pool).await.unwrap()
}

/// Whether row 1 can be written by another session within a second (no lock left behind).
async fn row_is_free(pool: &sqlx::MySqlPool) -> bool {
    let mut c = pool.acquire().await.unwrap();
    sqlx::query("SET SESSION innodb_lock_wait_timeout = 1").execute(&mut *c).await.unwrap();
    let ok = sqlx::query("INSERT INTO RUSTTEST_execlimit.t (ID, NOTE) VALUES (1, 'after')").execute(&mut *c).await.is_ok();
    let _ = sqlx::query("DELETE FROM RUSTTEST_execlimit.t WHERE ID = 1").execute(&mut *c).await;
    ok
}

/// A write scope (`Storage.Batch`, `UpdateIf`) whose run is stopped: at a step (the trigger
/// that runs long fails, the scope rolls back), and stuck in an await (the scope is dropped,
/// sqlx rolls the transaction back). Either way nothing is written and no lock stays.
#[tokio::test]
#[ignore = "needs the local MySQL"]
async fn a_write_scope_of_a_stopped_run_is_rolled_back() {
    use appdata::error::AppDataError;
    use appdata::mysql::sql::Sql;
    use appdata::mysql::tx;

    let pool = scratch_pool().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        // At a step.
        let r = guard(&settings(1, 0), "Test.batch", "testapp", "TESTCLIENT", async {
            tx::scope(async {
                tx::execute(&pool, &Sql::raw("INSERT INTO RUSTTEST_execlimit.t (ID, NOTE) VALUES (1, 'batch')")).await?;
                let trigger = run(&settings(600, 0), "runaway", json!({})).await;
                trigger.map_err(|e| AppDataError::internal(e.text()))?;
                Ok::<_, AppDataError>(())
            })
            .await
        })
        .await;
        assert_time_limit(&r.unwrap_err(), "Test.batch", 1);
        assert_eq!(rows(&pool).await, 0, "the write was rolled back");
        assert!(row_is_free(&pool).await, "no lock left on the row");

        // Stuck in an await, past the limit and the grace.
        let r = guard(&settings(1, 0), "Test.slow", "testapp", "TESTCLIENT", async {
            tx::scope(async {
                tx::execute(&pool, &Sql::raw("INSERT INTO RUSTTEST_execlimit.t (ID, NOTE) VALUES (1, 'slow')")).await?;
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok::<_, AppDataError>(())
            })
            .await
        })
        .await;
        assert_time_limit(&r.unwrap_err(), "Test.slow", 1);
        // The rollback goes out when the dropped connection is returned to the pool (a task).
        let mut free = false;
        for _ in 0..10 {
            if rows(&pool).await == 0 && row_is_free(&pool).await {
                free = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(free, "the dropped scope was rolled back and released its lock");
    })
    .catch_unwind()
    .await;
    let _ = sqlx::query("DROP DATABASE IF EXISTS RUSTTEST_execlimit").execute(&pool).await;
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}
