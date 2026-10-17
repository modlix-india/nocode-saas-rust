//! Logs, metrics and traces, the way Rust services usually ship them.
//!
//! - **Logs**: `tracing`, one JSON object per line on stdout (or pretty text for a terminal).
//!   The container runtime keeps stdout; the collector (Alloy) ships it to Loki. No log files.
//! - **Metrics**: the `metrics` facade with a Prometheus recorder, served on `/metrics`.
//!   Every series carries `service`, `instance` and `environment`.
//! - **Traces**: OpenTelemetry, exported over OTLP/HTTP when an endpoint is configured. Incoming
//!   `traceparent` headers continue the caller's trace; [`inject_trace_headers`] passes it on.
//!   Each request's log lines carry its `trace_id`, which is how Grafana jumps from a log line to
//!   its trace.

use anyhow::Result;
use http::HeaderMap;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::propagation::TextMapCompositePropagator;
use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

use crate::config::TelemetryConfig;

/// The request duration histogram every service records (OpenTelemetry's
/// `http.server.request.duration`, in Prometheus naming).
pub const HTTP_DURATION: &str = "http_server_request_duration_seconds";

/// Bucket bounds in seconds, from the platform's existing SLO set.
pub const HTTP_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0];

pub struct Telemetry {
    pub metrics: PrometheusHandle,
    tracer: Option<SdkTracerProvider>,
}

impl Telemetry {
    /// Flushes pending spans. Call once on shutdown.
    pub fn shutdown(&self) {
        if let Some(t) = &self.tracer {
            let _ = t.shutdown();
        }
    }
}

fn instance_name(cfg: &TelemetryConfig) -> String {
    if !cfg.instance.is_empty() {
        return cfg.instance.clone();
    }
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "local".into())
}

/// The OTLP/HTTP traces URL for a collector endpoint.
fn traces_url(endpoint: &str) -> String {
    if endpoint.ends_with("/v1/traces") {
        endpoint.to_string()
    } else {
        format!("{}/v1/traces", endpoint.trim_end_matches('/'))
    }
}

/// Sets up logging, metrics and (optionally) trace export for `service`.
pub fn init(service: &str, cfg: &TelemetryConfig) -> Result<Telemetry> {
    let instance = instance_name(cfg);

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| cfg.otlp_endpoint.clone());

    let tracer_provider = if endpoint.is_empty() {
        None
    } else {
        let url = traces_url(&endpoint);
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(url)
            .build()?;
        let resource = Resource::builder()
            .with_service_name(service.to_string())
            .with_attributes([
                KeyValue::new("service.instance.id", instance.clone()),
                KeyValue::new("deployment.environment", cfg.environment.clone()),
            ])
            .build();
        Some(
            SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    cfg.trace_sample_ratio.clamp(0.0, 1.0),
                ))))
                .with_resource(resource)
                .build(),
        )
    };

    opentelemetry::global::set_text_map_propagator(TextMapCompositePropagator::new(vec![Box::new(
        TraceContextPropagator::new(),
    )]));

    let otel_layer = tracer_provider.as_ref().map(|p| {
        opentelemetry::global::set_tracer_provider(p.clone());
        tracing_opentelemetry::layer().with_tracer(p.tracer(service.to_string()))
    });

    let fmt_layer = if cfg.log_format == "pretty" {
        fmt::layer().boxed()
    } else {
        fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .flatten_event(true)
            .boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .ok();

    let metrics = PrometheusBuilder::new()
        .add_global_label("service", service)
        .add_global_label("instance", instance)
        .add_global_label("environment", cfg.environment.clone())
        .set_buckets_for_metric(Matcher::Full(HTTP_DURATION.to_string()), HTTP_BUCKETS)?
        .install_recorder()?;

    Ok(Telemetry { metrics, tracer: tracer_provider })
}

/// Makes `span` a child of the trace named in `headers` (`traceparent`), if any, and returns the
/// trace id to log.
pub fn continue_trace(span: &tracing::Span, headers: &HeaderMap) -> String {
    let parent = opentelemetry::global::get_text_map_propagator(|p| {
        p.extract(&opentelemetry_http::HeaderExtractor(headers))
    });
    let _ = span.set_parent(parent);
    let id = span.context().span().span_context().trace_id();
    if id == opentelemetry::trace::TraceId::INVALID {
        String::new()
    } else {
        id.to_string()
    }
}

/// Adds `traceparent` for the current span to an outgoing request's headers.
pub fn inject_trace_headers(headers: &mut HeaderMap) {
    let cx = tracing::Span::current().context();
    opentelemetry::global::get_text_map_propagator(|p| {
        p.inject_context(&cx, &mut opentelemetry_http::HeaderInjector(headers))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_urls() {
        assert_eq!(traces_url("http://alloy:4318"), "http://alloy:4318/v1/traces");
        assert_eq!(traces_url("http://alloy:4318/"), "http://alloy:4318/v1/traces");
        assert_eq!(traces_url("http://a/v1/traces"), "http://a/v1/traces");
        let named = TelemetryConfig { instance: "blue".into(), ..Default::default() };
        assert_eq!(instance_name(&named), "blue");
        assert!(!instance_name(&TelemetryConfig::default()).is_empty());
    }

    #[test]
    fn no_traceparent_no_trace_id() {
        let span = tracing::info_span!("t");
        assert_eq!(continue_trace(&span, &HeaderMap::new()), "");
    }
}
