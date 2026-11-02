//! `IFeignFilesService` (Feign name `files`): the files service's internal routes core calls,
//! `create` (a file written from the request's bytes) and `readFileAsBase64`.
//!
//! As Java's reactive Feign sends them: `@RequestParam`s in declaration order (a null one left
//! out), the resource type escaped as a path segment, and `create`'s `ByteBuffer` body as the
//! raw bytes with no `Content-Type` (WebClient's `ByteBufferEncoder` sets none) and their
//! `Content-Length`, which is what files reads (`request.getInputStream()`).

use anyhow::anyhow;
use platform::upstream::Upstream;
use serde_json::{Map, Value};

use crate::clients::{client, text, PATH_SEGMENT};
use crate::error::CoreError;

/// A `Mono<Map<String, Object>>` answer: an empty body (or JSON null) is no value; anything but
/// an object is Jackson's decoding error.
pub(crate) fn as_map(body: Option<String>) -> Result<Option<Map<String, Value>>, CoreError> {
    let Some(text) = body else { return Ok(None) };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Null) => Ok(None),
        Ok(Value::Object(m)) => Ok(Some(m)),
        Ok(other) => Err(CoreError::from(anyhow!(
            "JSON decoding error: Cannot deserialize value of type `java.util.LinkedHashMap<java.lang.String,java.lang.Object>`: {other}"
        ))),
        Err(e) => Err(CoreError::from(anyhow!("JSON decoding error: {e}"))),
    }
}

pub struct FilesCalls {
    upstream: Upstream,
    http: reqwest::Client,
}

fn segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

impl FilesCalls {
    pub fn new(upstream: Upstream) -> anyhow::Result<Self> {
        Ok(Self { upstream, http: client()? })
    }

    async fn url(&self, resource_type: &str, rest: &str) -> Result<String, CoreError> {
        let base = self.upstream.base().await.map_err(CoreError::from)?;
        Ok(format!("{base}/api/files/internal/{}{rest}", segment(resource_type)))
    }

    /// `create(resourceType, clientCode, override, filePath, fileName, ByteBuffer)`: the
    /// files service's `FileDetail` of the file written.
    pub async fn create(
        &self,
        file_type: &str,
        client_code: &str,
        overwrite: bool,
        path: &str,
        name: &str,
        bytes: impl Into<bytes::Bytes>,
    ) -> Result<Option<Map<String, Value>>, CoreError> {
        let flag = if overwrite { "true" } else { "false" };
        let rb = self
            .http
            .post(self.url(file_type, "").await?)
            .query(&[("clientCode", client_code), ("override", flag), ("filePath", path), ("fileName", name)])
            .body(bytes.into());
        as_map(text(rb).await?)
    }

    /// `readFileAsBase64(resourceType, clientCode, url, metadataRequired)`: plain text, a data
    /// URL when the metadata is asked for.
    pub async fn read_file_as_base64(
        &self,
        resource_type: &str,
        client_code: Option<&str>,
        url: &str,
        metadata_required: Option<bool>,
    ) -> Result<Option<String>, CoreError> {
        let mut q: Vec<(&str, &str)> = Vec::with_capacity(3);
        if let Some(c) = client_code {
            q.push(("clientCode", c));
        }
        q.push(("url", url));
        if let Some(m) = metadata_required {
            q.push(("metadataRequired", if m { "true" } else { "false" }));
        }
        text(self.http.get(self.url(resource_type, "/convertToBase64").await?).query(&q)).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    #[test]
    fn map_answers_as_jackson_reads_them() {
        assert_eq!(super::as_map(None).unwrap(), None);
        assert_eq!(super::as_map(Some("null".into())).unwrap(), None);
        assert_eq!(super::as_map(Some(r#"{"a":1}"#.into())).unwrap().unwrap()["a"], 1);
        assert!(super::as_map(Some("[1]".into())).unwrap_err().text().contains("LinkedHashMap"));
        assert!(super::as_map(Some("{".into())).unwrap_err().text().starts_with("JSON decoding error"));
    }

    use axum::body::Bytes;
    use axum::extract::RawQuery;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use parking_lot::Mutex;
    use serde_json::json;

    use super::*;
    use crate::testing::serve;

    /// What the fake files service received on `create`: path, query, content type, length
    /// header and the bytes.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct Upload {
        pub path: String,
        pub query: String,
        pub content_type: Option<String>,
        pub content_length: Option<String>,
        pub bytes: Vec<u8>,
    }

    pub(crate) type Uploads = Arc<Mutex<Vec<Upload>>>;

    /// A files service: `create` answers a `FileDetail` naming the file (or what `fileName`
    /// asks for: `empty` an empty body, `refused` a 403); `convertToBase64` answers
    /// `data:<url>` (`missing` empty, `broken` a 500).
    pub(crate) async fn fake() -> (String, Uploads) {
        let uploads: Uploads = Default::default();
        let u = uploads.clone();
        let router = Router::new()
            .route(
                "/api/files/internal/{resourceType}",
                post(move |uri: Uri, RawQuery(q): RawQuery, h: HeaderMap, body: Bytes| {
                    let u = u.clone();
                    async move {
                        let q = q.unwrap_or_default();
                        let header = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
                        u.lock().push(Upload {
                            path: uri.path().to_string(),
                            query: q.clone(),
                            content_type: header("content-type"),
                            content_length: header("content-length"),
                            bytes: body.to_vec(),
                        });
                        let p: std::collections::HashMap<String, String> = crate::exec::parse_query(Some(&q)).into_iter().collect();
                        match p.get("fileName").map(String::as_str) {
                            Some("empty") => StatusCode::OK.into_response(),
                            Some("refused") => (StatusCode::FORBIDDEN, r#"{"message":"no write"}"#).into_response(),
                            Some(name) => {
                                let path = format!("{}/{name}", p.get("filePath").cloned().unwrap_or_default().trim_end_matches('/'));
                                json!({"name": name, "filePath": path, "size": body.len(), "directory": false, "lastModified": null})
                                    .to_string()
                                    .into_response()
                            }
                            None => (StatusCode::BAD_REQUEST, r#"{"message":"fileName missing"}"#).into_response(),
                        }
                    }
                }),
            )
            .route(
                "/api/files/internal/{resourceType}/convertToBase64",
                get(|RawQuery(q): RawQuery| async move {
                    let p: std::collections::HashMap<String, String> = crate::exec::parse_query(q.as_deref()).into_iter().collect();
                    match p.get("url").map(String::as_str) {
                        Some("missing") => StatusCode::OK.into_response(),
                        Some("broken") => (StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"cannot convert"}"#).into_response(),
                        Some(url) => format!(
                            "data:{url};client={};meta={}",
                            p.get("clientCode").map(String::as_str).unwrap_or("-"),
                            p.get("metadataRequired").map(String::as_str).unwrap_or("-")
                        )
                        .into_response(),
                        None => StatusCode::BAD_REQUEST.into_response(),
                    }
                }),
            );
        (serve(router).await, uploads)
    }

    #[tokio::test]
    async fn create_sends_the_raw_bytes() {
        let (base, uploads) = fake().await;
        let f = FilesCalls::new(Upstream::fixed(&[&base])).unwrap();
        let detail = f.create("secured", "C1", true, "/docs a", "x.pdf", b"%PDF-1.4".to_vec()).await.unwrap().unwrap();
        assert_eq!(detail["filePath"], json!("/docs a/x.pdf"));
        assert_eq!(detail["size"], json!(8));
        let up = uploads.lock()[0].clone();
        assert_eq!(up.path, "/api/files/internal/secured");
        assert_eq!(up.query, "clientCode=C1&override=true&filePath=%2Fdocs+a&fileName=x.pdf");
        assert_eq!(up.content_type, None);
        assert_eq!(up.content_length.as_deref(), Some("8"));
        assert_eq!(up.bytes, b"%PDF-1.4");

        assert!(f.create("static", "C1", false, "/", "empty", Vec::new()).await.unwrap().is_none());
        assert!(uploads.lock()[1].query.contains("override=false"));
        let e = f.create("static", "C1", false, "/", "refused", Bytes::from_static(b"x")).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::FORBIDDEN, "no write".to_string()));
    }

    #[tokio::test]
    async fn base64_is_plain_text() {
        let (base, _) = fake().await;
        let f = FilesCalls::new(Upstream::fixed(&[&base])).unwrap();
        assert_eq!(f.read_file_as_base64("static", Some("C1"), "a/b.png", Some(true)).await.unwrap().unwrap(), "data:a/b.png;client=C1;meta=true");
        assert_eq!(f.read_file_as_base64("static", None, "a", None).await.unwrap().unwrap(), "data:a;client=-;meta=-");
        assert_eq!(f.read_file_as_base64("static", Some("C1"), "a", Some(false)).await.unwrap().unwrap(), "data:a;client=C1;meta=false");
        assert_eq!(f.read_file_as_base64("secured", Some("C1"), "missing", Some(false)).await.unwrap(), None);
        assert_eq!(f.read_file_as_base64("secured", Some("C1"), "broken", Some(false)).await.unwrap_err().text(), "cannot convert");
        let dead = FilesCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap();
        assert!(dead.create("static", "C", false, "/", "x", Vec::new()).await.is_err());
    }
}
