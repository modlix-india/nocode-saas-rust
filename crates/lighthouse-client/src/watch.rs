//! The registry as a stream, for the gateway.
//!
//! Polls `GET /eureka/apps` (JSON, with the last ETag) every 2 seconds and publishes the list
//! when its membership changes. The last list stays in force while every server fails or is
//! warming up (503), so a Lighthouse restart never empties the gateway's pools; and an empty
//! list replaces a non-empty one only after it has been seen 3 polls in a row.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::{ACCEPT, ETAG, IF_NONE_MATCH};
use reqwest::StatusCode;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::wire::{Applications, ApplicationsEnvelope};

#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Lighthouse servers, in any of the forms [`crate::eureka_base`] accepts.
    pub servers: Vec<String>,
    pub interval: Duration,
    /// Polls in a row that must see an empty registry before it is believed.
    pub empty_confirmations: u32,
    pub timeout: Duration,
    pub token: Option<String>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            servers: crate::servers_from_env(),
            interval: Duration::from_secs(2),
            empty_confirmations: 3,
            timeout: Duration::from_secs(5),
            token: crate::token_from_env(),
        }
    }
}

/// A running watch. Dropping it stops the polling.
pub struct Watcher {
    rx: watch::Receiver<Arc<Applications>>,
    task: JoinHandle<()>,
}

/// Watches the registry on `servers` with the default settings.
pub fn watch<I, S>(servers: I) -> Result<Watcher>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let servers: Vec<String> = servers.into_iter().map(|s| s.as_ref().to_string()).collect();
    Watcher::start(WatchConfig { servers, ..WatchConfig::default() })
}

impl Watcher {
    pub fn start(cfg: WatchConfig) -> Result<Self> {
        let mut poller = Poller::new(cfg)?;
        let (tx, rx) = watch::channel(Arc::new(Applications::default()));
        let interval = poller.cfg.interval;
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let current = tx.borrow().clone();
                if let Some(next) = poller.poll(&current).await {
                    tx.send_replace(Arc::new(next));
                }
            }
        });
        Ok(Self { rx, task })
    }

    /// A receiver that wakes on every published change.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Applications>> {
        self.rx.clone()
    }

    /// The registry as last published (empty until the first successful poll).
    pub fn current(&self) -> Arc<Applications> {
        self.rx.borrow().clone()
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One server's answer to a poll.
enum Answer {
    Fresh(Applications, Option<String>),
    Unchanged,
}

struct Poller {
    cfg: WatchConfig,
    servers: Vec<String>,
    http: reqwest::Client,
    current: usize,
    etag: Option<String>,
    empties: u32,
}

impl Poller {
    fn new(cfg: WatchConfig) -> Result<Self> {
        let servers: Vec<String> = cfg.servers.iter().map(|s| crate::eureka_base(s)).collect();
        if servers.is_empty() {
            return Err(anyhow!("no Lighthouse servers to watch"));
        }
        let http = reqwest::Client::builder().timeout(cfg.timeout).build()?;
        Ok(Self { cfg, servers, http, current: 0, etag: None, empties: 0 })
    }

    /// Polls once. `Some(list)` when the membership changed and should be published.
    async fn poll(&mut self, published: &Applications) -> Option<Applications> {
        let answer = match self.fetch().await {
            Ok(a) => a,
            Err(e) => {
                metrics::counter!("lighthouse_client_watch_polls_total", "result" => "kept").increment(1);
                tracing::debug!(error = %e, "registry poll failed, keeping the last list");
                return None;
            }
        };
        let Answer::Fresh(apps, etag) = answer else {
            metrics::counter!("lighthouse_client_watch_polls_total", "result" => "unchanged").increment(1);
            return None;
        };
        if apps.is_empty() && !published.is_empty() {
            self.empties += 1;
            if self.empties < self.cfg.empty_confirmations {
                // Not believed yet: ask again in full next time.
                self.etag = None;
                metrics::counter!("lighthouse_client_watch_polls_total", "result" => "empty_unconfirmed").increment(1);
                return None;
            }
            tracing::warn!(polls = self.empties, "the registry is empty, confirmed");
        }
        self.empties = 0;
        self.etag = etag;
        metrics::counter!("lighthouse_client_watch_polls_total", "result" => "fresh").increment(1);
        (apps.membership() != published.membership()).then_some(apps)
    }

    /// Asks the current server, then the others, until one answers 200 or 304.
    async fn fetch(&mut self) -> Result<Answer> {
        let n = self.servers.len();
        let mut last = anyhow!("no server answered");
        for k in 0..n {
            let i = (self.current + k) % n;
            // An ETag means something only to the server that issued it.
            let etag = if i == self.current { self.etag.clone() } else { None };
            match self.fetch_from(i, etag).await {
                Ok(a) => {
                    self.current = i;
                    return Ok(a);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn fetch_from(&self, i: usize, etag: Option<String>) -> Result<Answer> {
        let url = format!("{}/apps", self.servers[i]);
        let mut req = self.http.get(&url).header(ACCEPT, "application/json");
        if let Some(t) = &etag {
            req = req.header(IF_NONE_MATCH, t);
        }
        if let Some(t) = &self.cfg.token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::NOT_MODIFIED if etag.is_some() => Ok(Answer::Unchanged),
            StatusCode::OK => {
                let tag = resp.headers().get(ETAG).and_then(|v| v.to_str().ok()).map(str::to_string);
                let body: ApplicationsEnvelope = resp.json().await?;
                Ok(Answer::Fresh(body.applications, tag))
            }
            s => Err(anyhow!("{url}: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Application, InstanceInfo, PortInfo, Status};
    use axum::http::{HeaderMap, StatusCode as Http};
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::Router;
    use std::sync::Mutex;

    /// What the fake server answers next.
    #[derive(Clone)]
    enum Next {
        Apps(Vec<&'static str>),
        Warming,
        Garbage,
    }

    struct Fake {
        next: Mutex<Next>,
        seen_etags: Mutex<Vec<Option<String>>>,
    }

    fn apps(names: &[&str]) -> Applications {
        Applications {
            versions_delta: "1".into(),
            apps_hashcode: String::new(),
            applications: names
                .iter()
                .map(|n| Application {
                    name: n.to_string(),
                    instances: vec![InstanceInfo {
                        instance_id: format!("{n}-1"),
                        app: n.to_string(),
                        ip_addr: "10.0.0.1".into(),
                        port: PortInfo { port: 80, enabled: true },
                        status: Status::Up,
                        ..Default::default()
                    }],
                })
                .collect(),
        }
    }

    async fn fake(next: Next) -> (String, Arc<Fake>) {
        let f = Arc::new(Fake { next: Mutex::new(next), seen_etags: Mutex::new(vec![]) });
        let f2 = f.clone();
        let app = Router::new().route(
            "/eureka/apps",
            get(move |h: HeaderMap| {
                let f = f2.clone();
                async move {
                    let tag = h.get("if-none-match").map(|v| v.to_str().unwrap().to_string());
                    f.seen_etags.lock().unwrap().push(tag.clone());
                    assert_eq!(h["accept"], "application/json");
                    assert_eq!(h["authorization"], "Bearer tok");
                    let next = f.next.lock().unwrap().clone();
                    let r: Response = match next {
                        Next::Warming => Http::SERVICE_UNAVAILABLE.into_response(),
                        Next::Garbage => "not json".into_response(),
                        Next::Apps(names) => {
                            let etag = format!("\"{}\"", names.join("-"));
                            if tag.as_deref() == Some(etag.as_str()) {
                                return Http::NOT_MODIFIED.into_response();
                            }
                            let body = serde_json::to_string(&ApplicationsEnvelope { applications: apps(&names) }).unwrap();
                            ([("etag", etag)], body).into_response()
                        }
                    };
                    r
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, f)
    }

    fn cfg(servers: Vec<String>) -> WatchConfig {
        WatchConfig { servers, interval: Duration::from_millis(20), token: Some("tok".into()), ..Default::default() }
    }

    #[tokio::test]
    async fn polls_with_etags_keeps_the_list_and_confirms_empties() {
        let (base, f) = fake(Next::Apps(vec!["A"])).await;
        let mut p = Poller::new(cfg(vec!["http://127.0.0.1:1".into(), base.clone()])).unwrap();
        let empty = Applications::default();
        let first = p.poll(&empty).await.expect("the first list is published");
        assert_eq!(first.up_urls("A"), vec!["http://10.0.0.1:80"]);
        assert_eq!(p.current, 1, "fell over to the server that answered");
        assert!(p.poll(&first).await.is_none(), "304: nothing new");
        assert_eq!(f.seen_etags.lock().unwrap().last().unwrap().as_deref(), Some("\"A\""));

        // Warming or broken: the last list stays.
        *f.next.lock().unwrap() = Next::Warming;
        assert!(p.poll(&first).await.is_none());
        *f.next.lock().unwrap() = Next::Garbage;
        assert!(p.poll(&first).await.is_none());

        // An empty registry is believed on the third poll in a row.
        *f.next.lock().unwrap() = Next::Apps(vec![]);
        assert!(p.poll(&first).await.is_none());
        assert!(p.poll(&first).await.is_none());
        assert_eq!(f.seen_etags.lock().unwrap().last().unwrap(), &None, "an unbelieved empty list keeps no etag");
        let emptied = p.poll(&first).await.expect("confirmed");
        assert!(emptied.is_empty());

        // Same membership with fresh lease timestamps is not a change.
        *f.next.lock().unwrap() = Next::Apps(vec!["A", "B"]);
        let two = p.poll(&emptied).await.unwrap();
        p.etag = None;
        assert!(p.poll(&two).await.is_none());
    }

    #[tokio::test]
    async fn the_watcher_publishes_changes() {
        let (base, f) = fake(Next::Apps(vec!["A"])).await;
        let w = Watcher::start(cfg(vec![base.clone()])).unwrap();
        let mut rx = w.subscribe();
        tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|a| !a.is_empty())).await.unwrap().unwrap();
        assert_eq!(w.current().applications[0].name, "A");
        *f.next.lock().unwrap() = Next::Apps(vec!["A", "B"]);
        tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|a| a.applications.len() == 2)).await.unwrap().unwrap();
        drop(w);

        assert!(Watcher::start(WatchConfig { servers: vec![], ..Default::default() }).is_err());
        let w = watch([base.as_str()]).unwrap();
        assert!(w.current().is_empty());
    }
}
