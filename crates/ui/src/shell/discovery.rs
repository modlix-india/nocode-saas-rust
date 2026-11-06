//! `/robots.txt`, `/sitemap.xml`, `/llms.txt` and `/indexnow.txt` (Rust only; see
//! `crate::aeo` for what they say). The app and client come from the request's host, as for
//! the index page (the gateway's `appCode` / `clientCode`, then the hosting gate), and every
//! absolute address uses the host the request came to. Each file is cached per app, client,
//! surface and host under `aeoFilesCache-<app>`, which every editor write of the app, its pages
//! and its URI paths clears.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use overridable::backend::Find;
use overridable::pojo::{decode_bson, map_field};
use overridable::JMap;

use crate::aeo::{self, AppInfo, PageInfo};
use crate::docs::{ApplicationDoc, PAGE};
use crate::engine::Engine;
use crate::respond::{build_text, Caching};
use crate::shell::javautil::{client_facing_host, md5_unique_id};
use crate::shell::server::{caller, finish, header as header_of, required, served_codes, unknown, Fail, ShellState};
use crate::shell::uripath::URI_PATH;
use crate::state::Caller;

/// One generated file: its text, or `None` for a 404.
#[derive(Debug, Clone)]
pub struct AeoFile {
    pub body: Option<String>,
    pub content_type: &'static str,
}

impl AeoFile {
    pub fn heap_bytes(&self) -> usize {
        self.body.as_ref().map_or(0, String::capacity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Robots,
    Sitemap,
    Llms,
    IndexNowKey,
}

impl Kind {
    fn route(self) -> &'static str {
        match self {
            Kind::Robots => "/robots.txt",
            Kind::Sitemap => "/sitemap.xml",
            Kind::Llms => "/llms.txt",
            Kind::IndexNowKey => aeo::INDEXNOW_KEY_PATH,
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Kind::Sitemap => "application/xml;charset=UTF-8",
            _ => "text/plain;charset=UTF-8",
        }
    }
}

pub async fn robots(st: State<ShellState>, h: HeaderMap) -> Response {
    serve(st, h, Kind::Robots).await
}

pub async fn sitemap(st: State<ShellState>, h: HeaderMap) -> Response {
    serve(st, h, Kind::Sitemap).await
}

pub async fn llms(st: State<ShellState>, h: HeaderMap) -> Response {
    serve(st, h, Kind::Llms).await
}

pub async fn indexnow_key(st: State<ShellState>, h: HeaderMap) -> Response {
    serve(st, h, Kind::IndexNowKey).await
}

/// `https://<host>` as the visitor typed it: the first forwarded host (port dropped) and the
/// first forwarded scheme; `https` unless a proxy says `http`.
pub fn request_base(h: &HeaderMap) -> String {
    let host = client_facing_host(header_of(h, "x-forwarded-host"), header_of(h, "host").map(|v| v.split(':').next().unwrap_or(v)).unwrap_or(""));
    let scheme = match header_of(h, "x-forwarded-proto").and_then(|p| p.split(',').next()).map(str::trim) {
        Some("http") => "http",
        _ => "https",
    };
    format!("{scheme}://{host}")
}

async fn serve(State(st): State<ShellState>, h: HeaderMap, kind: Kind) -> Response {
    let r = async {
        let caller = caller(&st, &h).await?;
        let (app, client) = served_codes(&st, required(&h, "appCode")?, required(&h, "clientCode")?).await;
        let base = request_base(&h);
        let key = format!("{client}|{}|{base}|{}", if caller.draft { "draft" } else { "live" }, kind.route());
        let file = st
            .inner()
            .aeo
            .get_or_load(&aeo::cache_name(&app), key, || async {
                Ok::<_, Fail>(Some(Arc::new(generate(&st, &caller, &app, &client, &base, kind).await?)))
            })
            .await?
            .ok_or_else(|| unknown(StatusCode::INTERNAL_SERVER_ERROR, "no file"))?;
        Ok(respond(&file, header_of(&h, "if-none-match")))
    }
    .await;
    finish(r, kind.route())
}

fn respond(file: &AeoFile, etag: Option<&str>) -> Response {
    match &file.body {
        Some(body) => build_text(&md5_unique_id(body), etag, Caching::Revalidate, Some(file.content_type), &[], || body.clone()),
        None => {
            let mut r = (StatusCode::NOT_FOUND, "Not Found").into_response();
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            r
        }
    }
}

fn internal(e: anyhow::Error) -> Fail {
    unknown(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:#}"))
}

async fn generate(st: &ShellState, caller: &Caller, app: &str, client: &str, base: &str, kind: Kind) -> Result<AeoFile, Fail> {
    let file = |body: Option<String>| AeoFile { body, content_type: kind.content_type() };
    let engine = Engine::new(&st.inner().ui, caller);
    let served = engine.served(app, client).await;
    let Some(app_doc) = engine.read_def(&ApplicationDoc, app, app, &served).await? else {
        return Ok(file(None));
    };
    let info = AppInfo::of(map_field(&app_doc.entity, "properties").unwrap_or(&JMap::new()));
    if caller.draft && kind != Kind::Robots {
        return Ok(file(None));
    }
    Ok(match kind {
        Kind::Robots => file(Some(aeo::robots_txt(base, &info, caller.draft))),
        Kind::IndexNowKey => file(Some(aeo::indexnow_key(&st.inner().cfg.aeo.indexnow_key_salt, app))),
        Kind::Sitemap => {
            let url_cc = caller.url_client_code(&served).to_string();
            let pages = pages(st, app, &url_cc, &served).await?;
            let aliases = aliases(st, app, &url_cc, &served).await?;
            file(Some(aeo::sitemap_xml(base, &aeo::entries(&info, &pages, &aliases))))
        }
        Kind::Llms => {
            if !info.visibility().llms_txt {
                return Ok(file(None));
            }
            let url_cc = caller.url_client_code(&served).to_string();
            let pages = pages(st, app, &url_cc, &served).await?;
            file(aeo::llms_txt(base, &info, &pages))
        }
    })
}

/// The live documents of `collection` in the app for every client the read looks through,
/// projected, one per name with each client's copy laid over the ones below it.
async fn merged(st: &ShellState, collection: &str, pojo: &'static overridable::pojo::Pojo, projection: mongodb::bson::Document, app: &str, url_cc: &str, cc: &str) -> Result<Vec<JMap>, Fail> {
    let store = st.inner().ui.store();
    let order = store.read_order(app, url_cc, cc).await.map_err(internal)?;
    let filter = mongodb::bson::doc! {"appCode": app, "clientCode": {"$in": order.to_vec()}, "published": {"$ne": false}};
    let docs = store.backend().find(collection, Find::new(filter).projection(projection)).await.map_err(internal)?;
    let rows = docs.iter().map(|d| decode_bson(pojo, d)).collect();
    Ok(aeo::merge_copies(rows, &order))
}

async fn pages(st: &ShellState, app: &str, url_cc: &str, cc: &str) -> Result<Vec<PageInfo>, Fail> {
    Ok(merged(st, "page", &PAGE, aeo::page_projection(), app, url_cc, cc).await?.iter().map(PageInfo::of).collect())
}

async fn aliases(st: &ShellState, app: &str, url_cc: &str, cc: &str) -> Result<Vec<(String, String)>, Fail> {
    Ok(merged(st, "uri_path", &URI_PATH, aeo::uri_path_projection(), app, url_cc, cc).await?.iter().filter_map(aeo::uri_path_alias).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn base_from_the_forwarded_headers() {
        assert_eq!(request_base(&h(&[("x-forwarded-host", "site.example,localhost:8080"), ("x-forwarded-proto", "https,http")])), "https://site.example");
        assert_eq!(request_base(&h(&[("x-forwarded-host", "site.example:443"), ("x-forwarded-proto", "http")])), "http://site.example");
        assert_eq!(request_base(&h(&[("host", "a.example:8080")])), "https://a.example");
    }

    #[test]
    fn missing_files_are_plain_404s() {
        let r = respond(&AeoFile { body: None, content_type: "text/plain;charset=UTF-8" }, None);
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = respond(&AeoFile { body: Some("x".into()), content_type: "application/xml;charset=UTF-8" }, None);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/xml;charset=UTF-8");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
    }
}
