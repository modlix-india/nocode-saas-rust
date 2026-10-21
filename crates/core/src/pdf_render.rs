//! Where HTML becomes a PDF for `CoreServices.File.TemplateToPdf` and the template PDF preview.
//!
//! With `[pdf] upstream` set (the pdf-render sidecar, `deploy/pdf-render`: WeasyPrint, CSS with
//! `<style>` blocks and `@page`, tables, borders, colours, fonts, images from the files
//! service), the HTML is posted to `<base>/render` and its PDF returned. Without it, or when the
//! sidecar fails and `[pdf] fallback_on_error` is on (the default), [`crate::pdf`]'s text
//! renderer makes the PDF, as before (DIFFERENCES D31).

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use platform::config::UpstreamConfig;
use platform::registry::Registry;
use platform::upstream::Upstream;
use serde::{Deserialize, Serialize};

/// `[pdf]` of the core units.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PdfConfig {
    /// The pdf-render sidecar (`http://pdf-render:8120`). Empty: the text renderer.
    pub upstream: UpstreamConfig,
    /// How long one render may take.
    pub timeout_seconds: u64,
    /// When the sidecar fails, make the text renderer's PDF (logged) instead of failing the call.
    pub fallback_on_error: bool,
}

impl Default for PdfConfig {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::default(), timeout_seconds: 60, fallback_on_error: true }
    }
}

pub struct PdfRenderer {
    sidecar: Option<(Upstream, reqwest::Client)>,
    fallback_on_error: bool,
}

static RENDERER: OnceLock<PdfRenderer> = OnceLock::new();

/// Sets the process's renderer from `[pdf]` (once, at startup; later calls keep the first).
pub fn install(cfg: &PdfConfig, registry: Option<&Registry>) -> Result<()> {
    let r = PdfRenderer::from_config(cfg, registry)?;
    match &r.sidecar {
        Some(_) => tracing::info!(upstream = ?cfg.upstream.entries(), "pdf: the pdf-render sidecar"),
        None => tracing::info!("pdf: the text renderer ([pdf] upstream is not set)"),
    }
    let _ = RENDERER.set(r);
    Ok(())
}

/// `html` as a PDF with the installed renderer (the text renderer when none was installed).
pub async fn render(html: String) -> Result<Vec<u8>, String> {
    match RENDERER.get() {
        Some(r) => r.render(html).await,
        None => text(html).await,
    }
}

async fn text(html: String) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || crate::pdf::html_to_pdf(&html)).await.map_err(|e| e.to_string())
}

impl PdfRenderer {
    pub fn from_config(cfg: &PdfConfig, registry: Option<&Registry>) -> Result<Self> {
        let sidecar = if cfg.upstream.entries().is_empty() {
            None
        } else {
            let http = reqwest::Client::builder().timeout(Duration::from_secs(cfg.timeout_seconds.max(1))).build()?;
            Some((Upstream::from_config(&cfg.upstream, registry)?, http))
        };
        Ok(Self { sidecar, fallback_on_error: cfg.fallback_on_error })
    }

    pub async fn render(&self, html: String) -> Result<Vec<u8>, String> {
        // A blank body has nothing to lay out (the sidecar refuses it): the text renderer's
        // empty page, as before.
        let Some((upstream, http)) = self.sidecar.as_ref().filter(|_| !html.trim().is_empty()) else {
            return text(html).await;
        };
        let sent = upstream
            .send("/render", |base| {
                http.post(format!("{base}/render"))
                    .header(reqwest::header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(html.clone())
            })
            .await;
        let failure = match sent {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(b) if b.starts_with(b"%PDF") => return Ok(b.to_vec()),
                Ok(_) => "the answer is not a PDF".to_string(),
                Err(e) => e.to_string(),
            },
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                format!("{status}: {}", body.chars().take(200).collect::<String>())
            }
            Err(e) => e.to_string(),
        };
        if self.fallback_on_error {
            tracing::warn!(error = %failure, "pdf-render failed, using the text renderer");
            text(html).await
        } else {
            Err(format!("pdf-render failed: {failure}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::Router;

    use super::*;

    const SIDECAR_PDF: &[u8] = b"%PDF-1.7 from the sidecar";

    /// A fake sidecar answering `status` with `body`, recording what it was sent.
    async fn sidecar(status: StatusCode, body: &'static [u8]) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let s2 = seen.clone();
        let app = Router::new().route(
            "/render",
            post(move |h: HeaderMap, b: String| {
                let s = s2.clone();
                async move {
                    s.lock().unwrap().push((h["content-type"].to_str().unwrap().to_string(), b));
                    (status, body)
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, seen)
    }

    fn renderer(upstream: &str, fallback_on_error: bool) -> PdfRenderer {
        let cfg = PdfConfig { upstream: UpstreamConfig::One(upstream.into()), timeout_seconds: 5, fallback_on_error };
        PdfRenderer::from_config(&cfg, None).unwrap()
    }

    fn is_text_renderer_pdf(pdf: &[u8]) -> bool {
        pdf.starts_with(b"%PDF-1.4") && pdf != SIDECAR_PDF
    }

    #[tokio::test]
    async fn the_sidecar_renders_when_configured() {
        let (base, seen) = sidecar(StatusCode::OK, SIDECAR_PDF).await;
        let html = "<style>td { border: 1px solid }</style><table><tr><td>\u{20B9} 10</td></tr></table>";
        assert_eq!(renderer(&base, true).render(html.into()).await.unwrap(), SIDECAR_PDF);
        assert_eq!(seen.lock().unwrap()[0], ("text/html; charset=utf-8".to_string(), html.to_string()), "the HTML as is");
        // A blank body never reaches it.
        assert!(is_text_renderer_pdf(&renderer(&base, true).render("  ".into()).await.unwrap()));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_upstream_is_the_text_renderer() {
        let r = PdfRenderer::from_config(&PdfConfig::default(), None).unwrap();
        assert!(r.sidecar.is_none());
        assert!(is_text_renderer_pdf(&r.render("<p>Hello</p>".into()).await.unwrap()));
        // Nothing installed in this process: the same.
        assert!(is_text_renderer_pdf(&render("<p>Hello</p>".into()).await.unwrap()));
    }

    #[tokio::test]
    async fn a_failing_sidecar_falls_back_or_fails_as_configured() {
        let (refusing, _) = sidecar(StatusCode::INTERNAL_SERVER_ERROR, b"render failed: ValueError").await;
        let (not_pdf, _) = sidecar(StatusCode::OK, b"<html>oops</html>").await;
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        for base in [&refusing, &not_pdf, &closed] {
            assert!(is_text_renderer_pdf(&renderer(base, true).render("<p>x</p>".into()).await.unwrap()), "{base}");
            let e = renderer(base, false).render("<p>x</p>".into()).await.unwrap_err();
            assert!(e.starts_with("pdf-render failed: "), "{e}");
        }
        let e = renderer(&refusing, false).render("<p>x</p>".into()).await.unwrap_err();
        assert!(e.contains("500") && e.contains("ValueError"), "{e}");
    }

    /// One local run against a real sidecar (`docker run -p 127.0.0.1:8120:8120 pdf-render`).
    #[tokio::test]
    #[ignore = "needs a running pdf-render: PDF_RENDER_URL, PDF_RENDER_HTML (a file), PDF_RENDER_OUT"]
    async fn renders_through_a_running_sidecar() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
        let html = std::fs::read_to_string(var("PDF_RENDER_HTML")).unwrap();
        let pdf = renderer(&var("PDF_RENDER_URL"), false).render(html).await.unwrap();
        assert!(pdf.starts_with(b"%PDF") && !pdf.starts_with(b"%PDF-1.4"), "made by the sidecar, not the text renderer");
        std::fs::write(var("PDF_RENDER_OUT"), pdf).unwrap();
    }

    #[test]
    fn config_defaults_and_shape() {
        let c: PdfConfig = serde_json::from_value(serde_json::json!({"upstream": "http://pdf-render:8120"})).unwrap();
        assert_eq!(c.upstream.entries(), ["http://pdf-render:8120"]);
        assert_eq!((c.timeout_seconds, c.fallback_on_error), (60, true));
        assert!(PdfConfig::default().upstream.entries().is_empty());
    }
}
