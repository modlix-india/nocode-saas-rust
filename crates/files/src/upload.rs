//! Request bodies: `multipart/form-data` (file parts streamed to the work directory, text parts
//! kept) and raw bodies streamed to a file.

use std::collections::HashMap;
use std::path::Path;

use axum::body::Body;
use axum::extract::{FromRequest, Multipart, Request};
use futures::StreamExt;
use platform::error::AppResult;
use tokio::io::AsyncWriteExt;

use crate::fs::TempFile;

/// One uploaded file: `MultipartFile`.
pub struct Part {
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub size: u64,
    pub file: TempFile,
}

#[derive(Default)]
pub struct Form {
    /// Text parts, in order (a part sent twice keeps both).
    pub texts: Vec<(String, String)>,
    pub files: HashMap<String, Vec<Part>>,
}

impl Form {
    /// `@RequestPart String`: the first text part of that name.
    pub fn text(&self, name: &str) -> Option<&str> {
        self.texts.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The first file of that name.
    pub fn file(&self, name: &str) -> Option<&Part> {
        self.files.get(name).and_then(|v| v.first())
    }

    pub fn take_file(&mut self, name: &str) -> Option<Part> {
        let v = self.files.get_mut(name)?;
        (!v.is_empty()).then(|| v.remove(0))
    }
}

fn is_multipart(req: &Request) -> bool {
    req.headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/form-data"))
}

/// Reads a multipart body; a request that is not multipart reads as an empty form.
pub async fn read_form(req: Request, dir: &Path) -> AppResult<Form> {
    let mut form = Form::default();
    if !is_multipart(&req) {
        return Ok(form);
    }
    let mut mp = Multipart::from_request(req, &())
        .await
        .map_err(|e| crate::errors::body_unreadable(e.body_text()))?;
    let bad = |e: axum::extract::multipart::MultipartError| crate::errors::body_unreadable(e.body_text());
    while let Some(mut field) = mp.next_field().await.map_err(bad)? {
        let name = field.name().unwrap_or("").to_string();
        let file_name = field.file_name().map(str::to_string);
        if file_name.is_none() {
            let text = field.text().await.map_err(bad)?;
            form.texts.push((name, text));
            continue;
        }
        let suffix: u64 = rand::random();
        let path = dir.join(format!("upload-{suffix:x}"));
        let temp = TempFile { path: path.clone() };
        let mut out = tokio::fs::File::create(&path).await.map_err(anyhow::Error::from)?;
        let mut size = 0u64;
        while let Some(chunk) = field.chunk().await.map_err(bad)? {
            size += chunk.len() as u64;
            out.write_all(&chunk).await.map_err(anyhow::Error::from)?;
        }
        out.flush().await.map_err(anyhow::Error::from)?;
        let part = Part {
            file_name,
            content_type: field.content_type().map(str::to_string),
            size,
            file: temp,
        };
        form.files.entry(name).or_default().push(part);
    }
    Ok(form)
}

/// The whole body in a file: the internal raw upload.
pub async fn body_to_file(body: Body, dir: &Path) -> AppResult<(TempFile, u64)> {
    let suffix: u64 = rand::random();
    let path = dir.join(format!("body-{suffix:x}"));
    let temp = TempFile { path: path.clone() };
    let mut out = tokio::fs::File::create(&path).await.map_err(anyhow::Error::from)?;
    let mut stream = body.into_data_stream();
    let mut size = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| crate::errors::body_unreadable(e.to_string()))?;
        size += chunk.len() as u64;
        out.write_all(&chunk).await.map_err(anyhow::Error::from)?;
    }
    out.flush().await.map_err(anyhow::Error::from)?;
    Ok((temp, size))
}

/// A JSON body, `null` when empty.
pub async fn read_json(body: Body) -> AppResult<serde_json::Value> {
    let bytes = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .map_err(|e| crate::errors::body_unreadable(e.to_string()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|e| crate::errors::body_unreadable(format!("Invalid JSON: {e}")))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_file_and_text_of_a_name() {
        let mut form = Form { texts: vec![("a".into(), "1".into()), ("a".into(), "2".into())], ..Default::default() };
        let part = |n: &str| Part {
            file_name: Some(n.into()),
            content_type: None,
            size: 0,
            file: TempFile { path: std::env::temp_dir().join(format!("files-upload-test-{n}-{:x}", rand::random::<u64>())) },
        };
        form.files.insert("file".into(), vec![part("one"), part("two")]);
        assert_eq!(form.text("a"), Some("1"));
        assert_eq!(form.file("file").and_then(|p| p.file_name.as_deref()), Some("one"));
        assert!(form.file("other").is_none());
        assert_eq!(form.take_file("file").and_then(|p| p.file_name), Some("one".into()));
        assert_eq!(form.take_file("file").and_then(|p| p.file_name), Some("two".into()));
        assert!(form.take_file("file").is_none());
        assert!(form.take_file("nothing").is_none());
    }
}
