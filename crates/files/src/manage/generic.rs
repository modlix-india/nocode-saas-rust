//! `TransformStaticImageController` and `GenericResourceFileController`: edited image uploads,
//! client and user pictures, a stateless resize, base64 conversions and the file system
//! reconcile.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use base64::Engine;
use platform::error::{AppError, AppResult};
use platform::http::spring_security_headers;
use serde_json::Value;

use super::Ctx;
use crate::access::has_write_access;
use crate::errors::{forbidden_path, missing, OrApp, FORBIDDEN_PERMISSION};
use crate::fs::{Fs, TempDir};
use crate::image_transform::{decode, details_from, encode, transform as transform_image, wants_alpha, ImageDetails};
use crate::jackson::{self, json, Obj};
use crate::model::DetailOut;
use crate::paths::{resolve_with_client_code, resolve_without, uri_part, Kind};
use crate::spring::safe_bool;
use crate::upload::{read_form, Form};

fn details(form: &Form) -> AppResult<ImageDetails> {
    details_from(|k| form.text(k).map(str::to_string))
}

async fn bytes_of(path: &std::path::Path) -> AppResult<Vec<u8>> {
    Ok(tokio::fs::read(path).await.map_err(anyhow::Error::from)?)
}

/// Writes `bytes` as `name` in `dir` and stores it at `<path>` with `name`, overwriting.
#[allow(clippy::too_many_arguments)]
async fn store_image(
    cx: &Ctx,
    kind: Kind,
    dir: &TempDir,
    cc: &str,
    path: &str,
    file_name: Option<&str>,
    local_name: &str,
    bytes: Vec<u8>,
    overwrite: bool,
) -> AppResult<Option<crate::dao::FileDetail>> {
    let local = crate::fs::safe_join(&dir.path, local_name).unwrap_or_else(|| dir.path.join("image"));
    let len = bytes.len() as u64;
    tokio::fs::write(&local, bytes).await.map_err(anyhow::Error::from)?;
    Fs::new(&cx.st, kind)
        .create_from_file(cc, path, file_name, &local, len, overwrite, "inline", None)
        .await
        .app()
}

/// `POST /api/files/transform/{resourceType}/**`: an uploaded image, or one already stored at
/// the `path` part, edited and written under the path.
pub async fn transform(cx: &mut Ctx, kind: Kind, req: Request) -> AppResult<Response> {
    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/form-data"));
    if !is_multipart {
        return Err(AppError::Empty(StatusCode::UNSUPPORTED_MEDIA_TYPE));
    }
    let dir = TempDir::new(&cx.st, "transform").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    cx.params.extend(form.texts.clone());
    let d = details(&form)?;
    let mut cc = cx.client_code();
    let overwrite = safe_bool(form.text("override"));
    let part = form.take_file("file");
    let file_name = match (form.text("fileName"), &part) {
        (Some(f), _) => f.to_string(),
        (None, Some(p)) => p.file_name.clone().unwrap_or_default(),
        (None, None) => return Err(missing("fileName")),
    };

    // The URI without `transform/`, then the path parts.
    let uri = match cx.uri.find("transform") {
        Some(i) => format!("{}{}", &cx.uri[..i], cx.uri.get(i + "transform".len() + 1..).unwrap_or("")),
        None => cx.uri.clone(),
    };
    let (mut rp, source_name) = match &part {
        Some(p) => (resolve_without(&uri, uri_part(kind)).unwrap_or_default().0, p.file_name.clone().unwrap_or_default()),
        None => {
            let file_path = form.text("path").ok_or_else(|| missing("path"))?;
            let (rp, _) = resolve_with_client_code(file_path, kind).ok_or_else(|| missing("path"))?;
            let segs: Vec<&str> = rp.split('/').filter(|s| !s.trim().is_empty()).collect();
            let (Some(first), Some(last)) = (segs.first(), segs.last()) else { return Err(missing("path")) };
            cc = first.to_string();
            let name = last.to_string();
            let after_cc = &rp[rp.find(cc.as_str()).map(|i| i + cc.len()).unwrap_or(0)..];
            let before_name = &after_cc[..after_cc.rfind(name.as_str()).unwrap_or(after_cc.len())];
            (before_name.to_string(), name)
        }
    };
    if let Some(s) = rp.strip_prefix('/') {
        rp = s.to_string();
    }
    if !has_write_access(&cx.st, cx.ca(), &rp, &cc, kind).await.app()? {
        return Err(forbidden_path(kind, &rp));
    }

    let source = match &part {
        Some(p) => bytes_of(&p.file.path).await?,
        None => {
            let key = format!("{cc}/{rp}/{source_name}").replace("//", "/");
            let local = Fs::new(&cx.st, kind).fetch(&key, &dir).await.map_err(AppError::Internal)?;
            bytes_of(&local).await?
        }
    };
    let mut alpha = wants_alpha(&source_name);
    if part.is_some() && !file_name.trim().is_empty() {
        alpha = wants_alpha(&file_name);
    }
    let img = transform_image(decode(&source)?, alpha, &d)?;
    let out = encode(&img, source_name.to_lowercase().ends_with("png"))?;
    let target = format!("{rp}/{file_name}").replace("//", "/");
    let fd = store_image(cx, kind, &dir, &cc, &target, None, &source_name, out, overwrite).await?;
    Ok(match fd {
        Some(d) => json(&DetailOut::of(&d).with_creation_paths(kind, &rp, &cc).json()),
        None => jackson::text(""),
    })
}

/// `POST /api/files/generic/client`: a client's logo at `SYSTEM/_clientImages/<clientId>.png`.
pub async fn client_image(cx: &mut Ctx, req: Request) -> AppResult<Response> {
    let ca = cx.ca().clone();
    if !ca.has_authority("Authorities.Client_UPDATE") {
        return Err(crate::errors::status(StatusCode::FORBIDDEN, FORBIDDEN_PERMISSION, &["Authorities.Client_UPDATE"]));
    }
    let dir = TempDir::new(&cx.st, "client").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    cx.params.extend(form.texts.clone());
    let d = details(&form)?;
    let client_id = super::opt_i64(&cx.params, "clientId")?.map(|v| v as u64);
    let part = form.take_file("file").ok_or_else(|| missing("file"))?;

    let effective = client_id.unwrap_or(ca.user.client_id);
    let cc = match client_id {
        None => ca.client_code.clone(),
        Some(id) => {
            let managed = cx
                .st
                .security()
                .is_user_client_manage_client(ca.url_app_code.as_deref(), ca.user.id, ca.user.client_id, Some(id))
                .await
                .app()?;
            if managed {
                cx.st
                    .security()
                    .client_by_id(id)
                    .await
                    .app()?
                    .and_then(|c| c["code"].as_str().map(str::to_string))
            } else {
                None
            }
        }
    };
    if cc.is_none_or(|c| c.trim().is_empty()) {
        return Err(forbidden_path(Kind::Static, "User Images"));
    }
    let img = transform_image(decode(&bytes_of(&part.file.path).await?)?, true, &d)?;
    let name = format!("{effective}.png");
    let fd = store_image(cx, Kind::Static, &dir, "SYSTEM", "_clientImages", Some(&name), &name, encode(&img, true)?, true).await?;
    Ok(match fd {
        Some(d) => json(&DetailOut::of(&d).with_creation_paths(Kind::Static, "/_clientImages", "SYSTEM").json()),
        None => jackson::text(""),
    })
}

/// `POST /api/files/generic/user`: a user's picture at `SYSTEM/_userImages/<userId>.png`
/// (secured). Your own needs nothing more; another's needs `User_UPDATE` and your client
/// managing theirs.
pub async fn user_image(cx: &mut Ctx, req: Request) -> AppResult<Response> {
    let ca = cx.ca().clone();
    let dir = TempDir::new(&cx.st, "user").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    cx.params.extend(form.texts.clone());
    let d = details(&form)?;
    let user_id = super::opt_i64(&cx.params, "userId")?.map(|v| v as u64);
    let part = form.take_file("file").ok_or_else(|| missing("file"))?;

    let uid = match user_id {
        None => Some(ca.user.id),
        Some(u) if u == ca.user.id => Some(u),
        Some(u) => {
            let target_client = cx
                .st
                .security()
                .user_internal(u)
                .await
                .ok()
                .flatten()
                .and_then(|v| v["clientId"].as_u64().or_else(|| v["clientId"].as_str().and_then(|s| s.parse().ok())));
            match target_client {
                Some(tc) if ca.has_authority("Authorities.User_UPDATE") => cx
                    .st
                    .security()
                    .is_user_client_manage_client(ca.url_app_code.as_deref(), ca.user.id, ca.user.client_id, Some(tc))
                    .await
                    .app()?
                    .then_some(u),
                _ => None,
            }
        }
    };
    let Some(uid) = uid else { return Err(forbidden_path(Kind::Secured, "User Images")) };
    let img = transform_image(decode(&bytes_of(&part.file.path).await?)?, true, &d)?;
    let name = format!("{uid}.png");
    let fd = store_image(cx, Kind::Secured, &dir, "SYSTEM", "_userImages", Some(&name), &name, encode(&img, true)?, true).await?;
    Ok(match fd {
        Some(d) => json(&DetailOut::of(&d).with_creation_paths(Kind::Secured, "/_userImages", "SYSTEM").json()),
        None => jackson::text(""),
    })
}

/// `POST /api/files/generic/resize`: the edited image straight back (jpg, jpeg and png only).
pub async fn resize(cx: &mut Ctx, req: Request) -> AppResult<Response> {
    let dir = TempDir::new(&cx.st, "resize").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    let d = details(&form)?;
    let part = form.take_file("file").ok_or_else(|| missing("file"))?;
    let original = part.file_name.clone().unwrap_or_default();
    let ext = original.rsplit('.').next().unwrap_or("").to_lowercase();
    let png = match ext.as_str() {
        "png" => true,
        "jpg" | "jpeg" => false,
        _ => {
            let text = format!("Unsupported image type '{ext}'");
            return Err(crate::errors::literal("FILES.IMAGE_TYPE_UNSUPPORTED", StatusCode::BAD_REQUEST, text).param("type", &ext).into());
        }
    };
    let img = transform_image(decode(&bytes_of(&part.file.path).await?)?, png, &d)?;
    let bytes = encode(&img, png)?;

    let mut h = HeaderMap::new();
    spring_security_headers(&mut h, true);
    h.insert(header::CONTENT_DISPOSITION, crate::download::content_disposition(false, &original));
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(if png { "image/png" } else { "image/jpeg" }));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut().extend(h);
    Ok(resp)
}

/// `GET /api/files/generic/internal/fs/populate`: rebuilds tree rows from the bucket in the
/// background. Public, like every `/internal/` route (nginx keeps them off the internet).
pub async fn populate(cx: &Ctx) -> AppResult<Response> {
    let cc = cx.params.get("clientCode").map(str::to_string);
    let folder = cx.params.get("folderPath").map(str::to_string);
    let rt = cx.params.get("resourceType").map(str::to_uppercase);
    for kind in [Kind::Static, Kind::Secured] {
        if rt.as_deref().is_some_and(|r| r != kind.db_name()) {
            continue;
        }
        let (st, cc, folder) = (cx.st.clone(), cc.clone(), folder.clone());
        tokio::spawn(async move {
            if let Err(e) = Fs::new(&st, kind).populate(cc.as_deref(), folder.as_deref()).await {
                tracing::error!(kind = kind.db_name(), error = %format!("{e:#}"), "file system populate failed");
            }
        });
    }
    Ok(jackson::text("FileSystem populated"))
}

/// `POST /api/files/generic/convertToBase64[WithDetails]`.
pub async fn base64(cx: &mut Ctx, req: Request, details: bool) -> AppResult<Response> {
    let dir = TempDir::new(&cx.st, "base64").map_err(AppError::Internal)?;
    let mut form = read_form(req, &dir.path).await?;
    let part = form.take_file("file").ok_or_else(|| missing("file"))?;
    if part.size == 0 {
        return Err(crate::errors::literal("FILES.FILE_EMPTY", StatusCode::BAD_REQUEST, "File is required and cannot be empty").into());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes_of(&part.file.path).await?);
    if !details {
        return Ok(jackson::text(encoded));
    }
    Ok(json(
        &Obj::new()
            .put("fileName", part.file_name.clone().map(Value::from).unwrap_or(Value::Null))
            .put("contentType", part.content_type.clone().map(Value::from).unwrap_or(Value::Null))
            .put("size", part.size)
            .put("base64Content", encoded)
            .build(),
    ))
}
