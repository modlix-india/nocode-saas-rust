//! `AbstractResourceFileController` and its two subclasses: listing, delete, folders, uploads,
//! zip import and export, the job listings, `copyToClientPage` and `createKey`.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use platform::error::{AppError, AppResult};
use serde_json::Value;

use super::{opt_i64, required, Ctx};
use crate::access::{can_read_secured, has_read_access, has_write_access, sub_client_list_access};
use crate::errors::{forbidden_path, missing, status, OrApp, UNABLE_TO_READ_UP_FILE};
use crate::fs::{Fs, TempDir};
use crate::fsdao::FileType;
use crate::jackson::{self, json};
use crate::keys::{create_access_key, short_uuid, ChronoUnit};
use crate::model::DetailOut;
use crate::paths::{java_url_decode, resolve_with_client_code, resolve_without, uri_part, Kind};
use crate::spring::{known_total, page_json, safe_bool, Pageable};
use crate::upload::{read_form, read_json};

fn resolved(cx: &Ctx, part: &str) -> (String, String) {
    resolve_without(&cx.uri, part).unwrap_or_default()
}

fn ok_or_empty(d: Option<Value>) -> Response {
    match d {
        Some(v) => json(&v),
        // `ResponseEntity.ok(null)`: a 200 with no body.
        None => {
            let mut r = jackson::text("");
            r.headers_mut().remove(axum::http::header::CONTENT_TYPE);
            r
        }
    }
}

async fn require_write(cx: &Ctx, kind: Kind, rp: &str, cc: &str) -> AppResult<()> {
    if has_write_access(&cx.st, cx.ca(), rp, cc, kind).await.app()? {
        Ok(())
    } else {
        Err(forbidden_path(kind, rp))
    }
}

/// `GET /**`: a page of a folder's entries.
pub async fn list(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    let (rp, _) = resolved(cx, uri_part(kind));
    let cc = cx.client_code();
    let mut types = Vec::new();
    for v in cx.params.all("fileType") {
        for t in v.split(',').filter(|t| !t.trim().is_empty()) {
            types.push(FileType::parse(t).ok_or_else(|| {
                crate::errors::param_invalid("fileType", format!("Invalid value '{t}' for parameter 'fileType'"))
            })?);
        }
    }
    let page = Pageable::from_params(&cx.params);

    let allowed = has_read_access(&cx.st, cx.ca(), &rp, &cc, kind).await.app()?
        || (kind == Kind::Static && sub_client_list_access(&cx.st, cx.ca(), &rp, &cc).await.app()?);
    if !allowed {
        return Err(forbidden_path(kind, &rp));
    }

    let data = Fs::new(&cx.st, kind).list(&cc, &rp, &types, cx.params.get("filter"), &page).await.app()?;
    let content: Vec<Value> = data
        .content
        .iter()
        .map(|d| DetailOut::listed(d).with_list_paths(kind, &rp, &cc).json())
        .collect();
    let total = known_total(content.len(), &page).unwrap_or(data.total);
    Ok(json(&page_json(content, &page, total)))
}

/// `DELETE /**`: the file or folder (with everything under it, in the tree).
pub async fn delete(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    let (rp, _) = resolved(cx, uri_part(kind));
    let cc = cx.client_code();
    require_write(cx, kind, &rp, &cc).await?;
    let fs = Fs::new(&cx.st, kind);
    let deleted = fs.delete(&format!("{cc}/{rp}")).await.app()?;
    fs.evict(&cc).await;
    Ok(json(&Value::Bool(deleted)))
}

/// `POST /directory/**`. Checks write access, which Java does not.
pub async fn directory(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    let (rp, _) = resolved(cx, "directory");
    let cc = cx.client_code();
    require_write(cx, kind, &rp, &cc).await?;
    let fs = Fs::new(&cx.st, kind);
    let fd = fs.create_folder(&cc, &rp).await.app()?;
    fs.evict(&cc).await;
    Ok(ok_or_empty(fd.map(|d| DetailOut::of(&d).json())))
}

/// `FileExtensionUtil.getFileNameWithExtension`: the requested name keeps the uploaded file's
/// extension.
pub fn name_with_extension(actual: &str, name: &str) -> String {
    if name.trim().is_empty() {
        return String::new();
    }
    let ext = |n: &str| match n.rfind('.') {
        Some(i) if i + 1 < n.len() => n[i + 1..].to_string(),
        _ => String::new(),
    };
    let (actual_ext, given_ext) = (ext(actual), ext(name));
    if given_ext.trim().is_empty() || given_ext != actual_ext {
        format!("{name}.{actual_ext}")
    } else {
        name.to_string()
    }
}

/// `POST /**`: the first `file` part (only the first, as in Java) under the path.
pub async fn upload(cx: &mut Ctx, kind: Kind, req: Request) -> AppResult<Response> {
    let mut form = read_form(req, cx.st.work_dir()).await?;
    cx.params.extend(form.texts.clone());
    let cc = cx.client_code();
    let given = form.text("override").map(|o| safe_bool(Some(o)));
    // Static overwrites unless told not to; secured does not unless told to.
    let overwrite = match kind {
        Kind::Static => given.unwrap_or(true),
        Kind::Secured => given.unwrap_or(false),
    };
    let name = form.text("name").map(str::to_string);
    let (rp, raw) = resolved(cx, uri_part(kind));
    require_write(cx, kind, &rp, &cc).await?;

    let part = form.take_file("file").ok_or_else(|| missing("file"))?;
    let original = part.file_name.clone().unwrap_or_default();
    let file_name = match name {
        None => original.clone(),
        Some(n) => name_with_extension(&original, &n),
    };
    let fd = Fs::new(&cx.st, kind)
        .create_from_file(&cc, &rp, Some(&file_name), &part.file.path, part.size, overwrite, "inline", None)
        .await
        .app()?;
    Ok(ok_or_empty(fd.map(|d| DetailOut::of(&d).with_creation_paths(kind, &raw, &cc).json())))
}

/// `POST /import/**`: the zip's folders and files under the path, in the background; the
/// response is the job id. Checks write access, which Java does not.
pub async fn import(cx: &mut Ctx, kind: Kind, req: Request) -> AppResult<Response> {
    let dir = TempDir::new(&cx.st, "import").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    cx.params.extend(form.texts.clone());
    let overwrite = form.text("override").is_none_or(|o| safe_bool(Some(o)));
    let cc = cx.client_code();
    let (rp, _) = resolved(cx, &format!("{}/import", uri_part(kind)));

    let part = form.take_file("file").ok_or_else(|| status(StatusCode::BAD_REQUEST, UNABLE_TO_READ_UP_FILE, &[]))?;
    if !part.file_name.as_deref().unwrap_or("").to_lowercase().ends_with(".zip") {
        return Err(status(StatusCode::BAD_REQUEST, UNABLE_TO_READ_UP_FILE, &[]));
    }
    require_write(cx, kind, &rp, &cc).await?;

    let zip = dir.path.join("upload.zip");
    tokio::fs::rename(&part.file.path, &zip).await.map_err(anyhow::Error::from)?;
    let id = crate::jobs::create_row(&cx.st, true, kind, &cc, &rp, None, cx.user_id()).await.app()?;
    crate::jobs::start_import(cx.st.clone(), id, kind, cc, rp, zip, dir, overwrite);
    Ok(json(&Value::from(id)))
}

/// `GET /export/**`: the folder as a zip at `_downloads/<id>.zip`, made in the background.
pub async fn export(cx: &Ctx, kind: Kind) -> AppResult<Response> {
    let (rp, _) = resolved(cx, "export");
    let ca = cx.ca();
    let cc = cx.params.get("clientCode").map(str::to_string).unwrap_or_else(|| ca.client_code().to_string());
    if !has_read_access(&cx.st, ca, &rp, &cc, kind).await.app()? {
        return Err(forbidden_path(kind, &rp));
    }
    let cdn = format!("_downloads/{}.zip", short_uuid());
    let id = crate::jobs::create_row(&cx.st, false, kind, &cc, &rp, Some(&cdn), cx.user_id()).await.app()?;
    crate::jobs::start_export(cx.st.clone(), id, kind, cc, rp, cdn);
    Ok(json(&Value::from(id)))
}

/// `GET /exports`, `GET /imports`: the caller's own jobs.
pub async fn jobs(cx: &Ctx, kind: Kind, imports: bool) -> AppResult<Response> {
    let ca = cx.ca();
    let cc = cx.params.get("clientCode").map(str::to_string).unwrap_or_else(|| ca.client_code().to_string());
    let page = Pageable::from_params(&cx.params);
    Ok(json(&crate::jobs::list(&cx.st, imports, kind, &cc, ca.user.id, &page).await.app()?))
}

/// `POST /static/copyToClientPage`: AI generated images (`SYSTEM/aiGen/<x>/<name>`) copied into
/// the client's `sitezump/<pageName>`. Checks write access there, which Java does not.
pub async fn copy_to_client_page(cx: &Ctx, req: Request) -> AppResult<Response> {
    let page_name = required(&cx.params, "pageName")?.to_string();
    let body = read_json(req.into_body()).await?;
    let Value::Array(items) = body else {
        return Err(crate::errors::literal("FILES.FILE_URLS_REQUIRED", StatusCode::BAD_REQUEST, "A list of file URLs is required").into());
    };
    let cc = cx.client_code();
    let dest = format!("sitezump/{page_name}");
    require_write(cx, Kind::Static, &dest, &cc).await?;

    let fs = Fs::new(&cx.st, Kind::Static);
    let mut out = Vec::new();
    for item in items {
        let url = match &item {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let url_path = url.replace("/api/files/static/file/SYSTEM/aiGen/", "");
        let Some(last) = url_path.rfind('/') else { continue };
        let (url_cc, name) = (&url_path[..last], &url_path[last + 1..]);
        let name = java_url_decode(name);
        let copied = fs.copy_file("SYSTEM", &format!("aiGen/{url_cc}"), &cc, &dest, &name).await.app()?;
        if let Some(d) = copied {
            out.push(DetailOut::of(&d).with_creation_paths(Kind::Static, &dest, &cc).json());
        }
    }
    fs.evict(&cc).await;
    Ok(json(&Value::Array(out)))
}

/// `GET /secured/createKey/**`: a download key for a secured file the caller may read.
pub async fn create_key(cx: &Ctx) -> AppResult<Response> {
    let path = cx.uri.replace("/createKey", "");
    let raw = resolve_with_client_code(&path, Kind::Secured).map(|(_, raw)| raw).unwrap_or_default();
    if raw.is_empty() || !can_read_secured(&cx.st, cx.ca(), &raw).await.app()? {
        return Err(forbidden_path(Kind::Secured, &raw));
    }
    let time = opt_i64(&cx.params, "timeSpan")?;
    let unit = match cx.params.get("timeUnit").filter(|s| !s.trim().is_empty()) {
        None => None,
        Some(u) => Some(ChronoUnit::parse(u).ok_or_else(|| {
            crate::errors::param_invalid("timeUnit", format!("Invalid value '{u}' for parameter 'timeUnit'"))
        })?),
    };
    let limit = match opt_i64(&cx.params, "accessLimit")? {
        None => None,
        Some(l) if l >= 0 => Some(l as u64),
        Some(l) => return Err(crate::errors::param_invalid("accessLimit", format!("Invalid value '{l}' for parameter 'accessLimit'"))),
    };
    let key = create_access_key(&cx.st, time, unit, limit, &raw).await?;
    Ok(jackson::text(format!("{}{key}", cx.st.config().secured_keys.key_uri)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_keep_the_uploaded_extension() {
        assert_eq!(name_with_extension("a.png", "logo"), "logo.png");
        assert_eq!(name_with_extension("a.png", "logo.png"), "logo.png");
        assert_eq!(name_with_extension("a.png", "logo.jpg"), "logo.jpg.png");
        assert_eq!(name_with_extension("noext", "x"), "x.");
        assert_eq!(name_with_extension("a.png", " "), "");
    }
}
