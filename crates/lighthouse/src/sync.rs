//! Catching up with the peers.
//!
//! - **At startup** the registry is filled from the peers' `GET /eureka/apps` before it serves
//!   discovery: until one peer has answered (or `startup_wait_seconds` passed), discovery GETs
//!   answer 503 so clients keep their caches, while registrations and heartbeats are accepted.
//! - **Every `digest_interval_seconds`** each peer's digest is compared with ours, and what it
//!   has that we miss (or have older) is fetched and adopted. That repairs whatever a dropped
//!   batch or a full queue lost. Each instance pulls; between them the peers converge.

use std::time::Duration;

use anyhow::{bail, Result};
use lighthouse_client::replication::{Digest, REPLICATION_HEADER};
use lighthouse_client::wire::{Applications, ApplicationsEnvelope, InstanceEnvelope};
use reqwest::header::ACCEPT;

use crate::registry::Registry;

/// How Lighthouse instances call each other.
#[derive(Clone)]
pub struct PeerClient {
    pub http: reqwest::Client,
    pub token: Option<String>,
}

impl PeerClient {
    fn get(&self, url: reqwest::Url) -> reqwest::RequestBuilder {
        let req = self.http.get(url).header(ACCEPT, "application/json").header(REPLICATION_HEADER, "true");
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn json<T: serde::de::DeserializeOwned>(&self, url: reqwest::Url) -> Result<T> {
        let resp = self.get(url.clone()).send().await?;
        if !resp.status().is_success() {
            bail!("{url}: {}", resp.status());
        }
        Ok(resp.json().await?)
    }

    pub async fn applications(&self, peer: &str) -> Result<Applications> {
        let url = reqwest::Url::parse(&format!("{peer}/eureka/apps"))?;
        Ok(self.json::<ApplicationsEnvelope>(url).await?.applications)
    }

    pub async fn digest(&self, peer: &str) -> Result<Digest> {
        self.json(reqwest::Url::parse(&format!("{peer}/v1/peer/digest"))?).await
    }

    pub async fn instance(&self, peer: &str, app: &str, id: &str) -> Result<InstanceEnvelope> {
        let mut url = reqwest::Url::parse(peer)?;
        url.path_segments_mut().map_err(|_| anyhow::anyhow!("{peer} cannot be a base"))?.extend(["eureka", "apps", app, id]);
        self.json(url).await
    }
}

/// Fills the registry from the peers, then marks it ready.
pub async fn startup(registry: &Registry, peers: &[String], client: &PeerClient, wait: Duration, retry: Duration) {
    if peers.is_empty() {
        registry.set_ready();
        return;
    }
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let mut answered = false;
        for peer in peers {
            match client.applications(peer).await {
                Ok(apps) => {
                    let adopted = apps.instances().filter(|i| registry.adopt((*i).clone())).count();
                    tracing::info!(peer, adopted, "synced the registry from a peer");
                    answered = true;
                }
                Err(e) => tracing::debug!(peer, error = %e, "peer did not answer the startup sync"),
            }
        }
        let now = tokio::time::Instant::now();
        if answered || now >= deadline {
            if !answered {
                tracing::warn!(?wait, "no peer answered the startup sync: serving what this instance has");
            }
            registry.set_ready();
            return;
        }
        tokio::time::sleep(retry.min(deadline - now)).await;
    }
}

/// Compares one peer's digest with ours and adopts what we miss. Returns how many were taken.
pub async fn reconcile(registry: &Registry, peer: &str, client: &PeerClient) -> Result<usize> {
    let digest = client.digest(peer).await?;
    let mut taken = 0;
    for e in digest.instances.iter().filter(|e| registry.wants(e)) {
        match client.instance(peer, &e.app, &e.id).await {
            Ok(env) => taken += usize::from(registry.adopt(env.instance)),
            Err(err) => tracing::debug!(peer, app = e.app, id = e.id, error = %err, "could not fetch an instance for repair"),
        }
    }
    if taken > 0 {
        tracing::info!(peer, taken, "repaired the registry from a peer's digest");
        metrics::counter!("lighthouse_digest_repairs_total").increment(taken as u64);
    }
    Ok(taken)
}

/// Reconciles with every peer every `every`, once the registry is ready.
pub async fn digest_loop(registry: &Registry, peers: &[String], client: &PeerClient, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        if !registry.is_ready() {
            continue;
        }
        for peer in peers {
            if let Err(e) = reconcile(registry, peer, client).await {
                tracing::debug!(peer, error = %e, "digest comparison failed");
            }
        }
    }
}
