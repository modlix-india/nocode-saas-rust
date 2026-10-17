//! The Rust half of `tools/parity_core_scheduler.py`: core-scheduler and core-events, built as
//! their binaries build them, run for a few minutes on a scratch Mongo database, a scratch
//! exchange and scratch queues (the script sets all three, and this refuses anything else).

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by tools/parity_core_scheduler.py"]
async fn scheduler_parity_run() {
    use std::sync::Arc;

    use lapin::options::{ExchangeDeleteOptions, QueueDeleteOptions};
    use lapin::types::ShortString;

    use crate::config::CoreConfig;
    use crate::scheduler::{json_util_map, OneOffs, ScheduleRequest, ScheduleStore, ScheduledEventService};

    let Ok(minutes) = std::env::var("RS_PARITY_MINUTES") else { return };
    let minutes: u64 = minutes.parse().unwrap();
    let cfg: CoreConfig = platform::config::load("core-events").unwrap();
    assert!(cfg.mongo.database.starts_with("rs_scratch_"), "the parity run writes only to a scratch database");
    assert!(cfg.mq.events_exchange.starts_with("rs_scratch_"), "and publishes only to a scratch exchange");
    let queues = crate::events_queue::queue_names(&cfg.events);
    assert!(queues.iter().all(|q| q.starts_with("rs_scratch_")));
    let uri = cfg.mq.amqp_uri().expect("a broker");

    let exec = crate::connect(&cfg).await.unwrap();
    // RS_PARITY_NOOP: the real schedule load, decisions only. Every raised event is closed as
    // done without running anything (an action with no tasks), and nothing is logged.
    let noop = std::env::var("RS_PARITY_NOOP").as_deref() == Ok("1");
    if noop {
        assert!(!cfg.core.event_runs.enabled, "the real-load run must not write the run log");
    }
    let listener = Arc::new(if noop { noop_listener(&exec, &cfg) } else { crate::events_listener_of(&exec, &cfg) });
    let scheduler = Arc::new(crate::event_scheduler_of(
        cfg.clone(),
        exec.state.inner().definitions.store().clone(),
        exec.cache.clone(),
        exec.security_calls.clone(),
        exec.mongo.clone(),
        exec.pool.clone(),
    ));

    // The same one-off the Java side scheduled through CoreServices.Event.ScheduleEvent.
    let app = std::env::var("RS_PARITY_APP").unwrap_or_default();
    let key = std::env::var("RS_PARITY_ONE_OFF_KEY").unwrap_or_default();
    let event = std::env::var("RS_PARITY_ONE_OFF_EVENT").unwrap_or_default();
    let settings = cfg.core.scheduler.clone();
    let one_offs = ScheduledEventService::new(Arc::new(ScheduleStore::new(exec.mongo.clone(), settings.clone())), settings);
    if !noop {
    one_offs
        .schedule(ScheduleRequest {
            app_code: app,
            client_code: "SYSTEM".into(),
            draft: false,
            event_name: event,
            data: json_util_map(serde_json::json!({"n": 1, "who": "parity"}).as_object().unwrap()),
            run_at: None,
            key,
            scheduled_by: Some("142".into()),
        })
        .await
        .unwrap();
    }

    let consumer = tokio::spawn(crate::events_queue::consume_forever(listener, uri.clone(), cfg.mq.events_exchange.clone(), cfg.events.clone()));
    let passes = tokio::spawn(scheduler.run_forever());
    tokio::time::sleep(std::time::Duration::from_secs(minutes * 60)).await;
    passes.abort();
    // The runs raised by the last pass finishing.
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    consumer.abort();

    let conn = lapin::Connection::connect(&uri, lapin::ConnectionProperties::default()).await.unwrap();
    let ch = conn.create_channel().await.unwrap();
    for q in &queues {
        ch.queue_delete(ShortString::from(q.as_str()), QueueDeleteOptions::default()).await.unwrap();
    }
    ch.exchange_delete(ShortString::from(cfg.mq.events_exchange.as_str()), ExchangeDeleteOptions::default()).await.unwrap();
}

/// Every event's action is an action with no tasks: the run is closed as done, nothing runs.
#[cfg(test)]
fn noop_listener(exec: &crate::Exec, cfg: &crate::config::CoreConfig) -> crate::events::EventsListener {
    use std::sync::Arc;

    struct NoTasks;

    #[async_trait::async_trait]
    impl crate::events::EventActions for NoTasks {
        async fn read(&self, _: &str, _: &str, _: &str, _: bool) -> Result<Option<overridable::JMap>, crate::error::CoreError> {
            let mut a = overridable::JMap::new();
            a.insert("tasks".into(), overridable::JValue::Object(overridable::JMap::new()));
            Ok(Some(a))
        }
    }

    let settings = cfg.core.scheduler.clone();
    let store = Arc::new(crate::scheduler::ScheduleStore::new(exec.mongo.clone(), settings.clone()));
    let one_offs = Arc::new(crate::scheduler::ScheduledEventService::new(store.clone(), settings));
    crate::events::EventsListener::new(Arc::new(NoTasks), exec.security_calls.clone())
        .with_completion(Arc::new(crate::event_scheduler::RunCompletion::new(store, one_offs)))
}
