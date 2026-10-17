//! `FilesInternalController` and `FilesInternalBillingController`: service-to-service calls,
//! with no caller checks (nginx keeps `/internal` off the internet).

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine;
use platform::error::{AppError, AppResult};
use serde_json::Value;

use super::{opt_i64, required, Ctx};
use crate::access::is_client_being_managed;
use crate::errors::{forbidden_path, missing, status, OrApp, FILE_CANNOT_BE_CONVERTED, UNABLE_TO_CONVERT};
use crate::fs::{mime_of, Fs, TempDir};
use crate::jackson::{self, json};
use crate::keys::create_access_key;
use crate::model::DetailOut;
use crate::paths::{download_name, resolve_with_client_code, Kind};
use crate::upload::{body_to_file, read_form};

/// Spring's `boolean` binding (`StringToBooleanConverter`).
fn spring_bool(p: &crate::spring::Params, name: &str, default: bool) -> AppResult<bool> {
    match p.get(name).map(|s| s.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if v.is_empty() => Ok(default),
        Some(v) => match v.as_str() {
            "true" | "on" | "yes" | "1" => Ok(true),
            "false" | "off" | "no" | "0" => Ok(false),
            _ => Err(crate::errors::param_invalid(name, format!("Invalid value '{v}' for parameter '{name}'"))),
        },
    }
}

fn limit(cx: &Ctx) -> AppResult<i64> {
    Ok(opt_i64(&cx.params, "limit")?.unwrap_or(500))
}

/// `GET /internal/secured/createKey?filePath=`: a key for any path, unchecked.
pub async fn create_key(cx: &Ctx) -> AppResult<Response> {
    let path = required(&cx.params, "filePath")?;
    let key = create_access_key(&cx.st, None, None, None, path).await?;
    Ok(jackson::text(format!("{}{key}", cx.st.config().secured_keys.key_uri)))
}

/// `POST /internal/{resourceType}`: the raw body stored at `<filePath>/<fileName>`.
pub async fn upload(cx: &Ctx, kind: Kind, req: Request) -> AppResult<Response> {
    let cc = required(&cx.params, "clientCode")?.to_string();
    let file_name = required(&cx.params, "fileName")?.to_string();
    let overwrite = spring_bool(&cx.params, "override", false)?;
    let file_path = cx.params.get("filePath").filter(|p| !p.is_empty()).unwrap_or("/").to_string();
    let expires = match opt_i64(&cx.params, "expiresAfterMinutes")? {
        None => None,
        Some(m) => Some(u32::try_from(m).map_err(|_| {
            crate::errors::param_invalid("expiresAfterMinutes", format!("Invalid value '{m}' for parameter 'expiresAfterMinutes'"))
        })?),
    };
    let (body, len) = body_to_file(req.into_body(), cx.st.work_dir()).await?;
    let fd = Fs::new(&cx.st, kind)
        .create_from_file(&cc, &file_path, Some(&file_name), &body.path, len, overwrite, "inline", expires)
        .await
        .app()?;
    Ok(match fd {
        Some(d) => json(&DetailOut::of(&d).with_creation_paths(kind, &file_path, &cc).json()),
        None => jackson::text(""),
    })
}

/// `POST /internal/{resourceType}/cleanupExpired`.
pub async fn cleanup(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    let n = Fs::new(&cx.st, kind).delete_expired(limit(cx)?).await.app()?;
    Ok(json(&Value::from(n)))
}

/// `POST /internal/{resourceType}/applyRetention`.
pub async fn retention(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    Ok(json(&crate::retention::apply(&cx.st, kind, limit(cx)?).await.app()?))
}

/// `GET /internal/{resourceType}/convertToBase64`: a file of a client `clientCode` manages, as
/// base64 (optionally a `data:` URL).
pub async fn base64(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    let cc = required(&cx.params, "clientCode")?.to_string();
    let url = required(&cx.params, "url")?.to_string();
    // Java requires the flag (an absent one fails unboxing with a 500); absent is false here.
    let metadata = spring_bool(&cx.params, "metadataRequired", false)?;
    let cannot = || status(StatusCode::INTERNAL_SERVER_ERROR, FILE_CANNOT_BE_CONVERTED, &[]);

    let (rp, _) = resolve_with_client_code(&url, kind).ok_or_else(cannot)?;
    if rp.is_empty() {
        return Err(cannot());
    }
    let start = usize::from(rp.starts_with('/'));
    let from_url = match rp[start..].find('/') {
        Some(i) => &rp[start..start + i],
        None => &rp[start..],
    };
    if from_url.trim().is_empty() {
        return Err(cannot());
    }
    if !is_client_being_managed(&cx.st, &cc, from_url).await.app()? {
        return Err(forbidden_path(kind, &rp));
    }
    let detail = cx.st.file_detail(kind, &rp).await.app()?.ok_or(AppError::Empty(StatusCode::NOT_FOUND))?;
    if detail.is_directory {
        return Err(crate::errors::err_as("FILES.FOLDER_NOT_CONVERTIBLE", StatusCode::BAD_REQUEST, UNABLE_TO_CONVERT, &[]));
    }
    let dir = TempDir::new(&cx.st, "b64").map_err(AppError::Internal)?;
    let local = Fs::new(&cx.st, kind).fetch(&rp, &dir).await.map_err(AppError::Internal)?;
    let bytes = tokio::fs::read(&local).await.map_err(anyhow::Error::from)?;
    let mut out = String::new();
    if metadata {
        let name = download_name(&rp);
        out.push_str(&format!("data:{};name:{name};base64,", mime_of(&name)));
    }
    out.push_str(&base64::engine::general_purpose::STANDARD.encode(bytes));
    Ok(jackson::text(out))
}

/// `POST /internal/aiUploader`: an AI generated file at `SYSTEM/aiGen/<clientCode>/`, never
/// replacing one already there.
pub async fn ai_uploader(cx: &mut Ctx, req: Request) -> AppResult<Response> {
    let dir = TempDir::new(&cx.st, "ai").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    cx.params.extend(form.texts.clone());
    let cc = required(&cx.params, "clientCode")?.to_string();
    let part = form.take_file("file").ok_or_else(|| missing("file"))?;
    let path = format!("aiGen/{cc}");
    let name = part.file_name.clone().unwrap_or_default();
    let fd = Fs::new(&cx.st, Kind::Static)
        .create_from_file("SYSTEM", &path, Some(&name), &part.file.path, part.size, false, "inline", None)
        .await
        .app()?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("no row for the uploaded file")))?;
    Ok(jackson::text(format!("/api/files/static/file/SYSTEM/{path}/{}", fd.name)))
}

/// `POST /internal/billing/reconcile?date=yyyy-MM-dd`.
pub async fn reconcile(cx: &Ctx) -> AppResult<Response> {
    let date = match cx.params.get("date") {
        None => None,
        Some(d) => Some(
            chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
                .map_err(|_| crate::errors::param_invalid("date", format!("Invalid date '{d}'")))?,
        ),
    };
    let ok = crate::billing::reconcile(&cx.st, date).await.map_err(AppError::Internal)?;
    Ok(json(&Value::Bool(ok)))
}
