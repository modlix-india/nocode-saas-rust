//! axum routers over [`crate::write::controller`], one per Java controller base class. Nothing
//! here is mounted: a unit builds the routers for its document kinds under the Java base paths
//! (`/api/ui/pages`, `/api/core/storages`, ...) and merges them into its own router.
//!
//! The caller comes from a [`CallerSource`]; [`SecurityCallers`] asks security the way
//! `JWTTokenFilter` does and fills in the request's `clientCode` / `appCode` headers as the
//! URL client and app, which the access checks read.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Multipart, Path, RawQuery};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::Router;
use futures::future::BoxFuture;
use platform::error::{AppError, AppResult, Coded};
use platform::http::with_route;
use platform::security::{CallerContext, ContextAuthentication, OnBehalfOf, SecurityClient};

use crate::write::controller::{self as c, Reply};
use crate::write::deletion::DeletionService;
use crate::write::kind::Kind;
use crate::write::publish::PublishService;
use crate::write::service::OverridableService;
use crate::write::spring::Params;
use crate::write::transport::TransportService;
use crate::write::version::VersionStore;

/// Who is calling.
#[async_trait]
pub trait CallerSource: Send + Sync + 'static {
    async fn caller(&self, headers: &HeaderMap) -> AppResult<ContextAuthentication>;
}

/// The caller as `JWTTokenFilter` establishes it: security's answer for the token, with the
/// `clientCode` / `appCode` headers as the URL client and app. Security's refusals are relayed
/// with their status and message, as Java relays them.
pub struct SecurityCallers {
    pub security: SecurityClient,
    pub server_port: u16,
}

#[async_trait]
impl CallerSource for SecurityCallers {
    async fn caller(&self, headers: &HeaderMap) -> AppResult<ContextAuthentication> {
        let ctx = CallerContext::from_headers(headers, self.server_port);
        let mut ca = match self.security.context_authentication(&ctx).await {
            Ok(ca) => ca,
            // Security's refusal as it came (its coded error, else its message); a credential
            // it turned down without a word is "signed out" (Java's body is empty).
            Err(e) => {
                return Err(match platform::security::refusal_error(&e) {
                    Some(AppError::Empty(status)) if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                        Coded::new("COMMON.SIGNED_OUT").status(status).debug(format!("security refused the caller ({})", status.as_u16())).into()
                    }
                    Some(refusal) => refusal,
                    None => AppError::Internal(e),
                })
            }
        };
        ca.url_client_code = ctx.client_code;
        ca.url_app_code = ctx.app_code;
        Ok(ca)
    }
}

/// The forwarded request a call on the caller's behalf repeats: `X-Forwarded-Host`,
/// `X-Forwarded-Port`, `clientCode` and `appCode` are all required, as the Java
/// `@RequestHeader`s are.
pub fn on_behalf(headers: &HeaderMap, ca: &ContextAuthentication) -> Option<OnBehalfOf> {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
    Some(OnBehalfOf {
        access_token: ca.access_token.clone(),
        forwarded_host: h("x-forwarded-host")?,
        forwarded_port: h("x-forwarded-port")?,
        client_code: h("clientcode")?,
        app_code: h("appcode")?,
    })
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn respond(route: &'static str, r: AppResult<Reply>) -> Response {
    let resp = match r {
        Ok(reply) => reply.into_response(),
        Err(e) => c::error_response(e),
    };
    with_route(resp, route)
}

fn params(q: Option<String>) -> Params {
    Params::from_query(q.as_deref())
}

fn missing_headers() -> AppError {
    c::spring_refusal(StatusCode::BAD_REQUEST, "Required header is not present")
}

type PostFn = Arc<dyn Fn(ContextAuthentication, Params, Bytes) -> BoxFuture<'static, AppResult<Reply>> + Send + Sync>;

/// The routes of `AbstractOverridableDataController` for one kind, under `base`.
pub fn overridable_router<K: Kind>(base: &str, svc: OverridableService<K>, callers: Arc<dyn CallerSource>) -> Router {
    let s = svc.clone();
    let post_fn: PostFn = Arc::new(move |ca, p, body| {
        let s = s.clone();
        Box::pin(async move { c::post(&s, &ca, &p, &body).await })
    });
    build(base, svc, callers, post_fn)
}

fn build<K: Kind>(base: &str, svc: OverridableService<K>, callers: Arc<dyn CallerSource>, post_fn: PostFn) -> Router {
    let root = leak(base.to_string());
    let nomap = leak(format!("{base}/nomap2"));
    let one = leak(format!("{base}/{{id}}"));
    let blueprint = leak(format!("{base}/{{id}}/blueprint"));
    let for_client = leak(format!("{base}/createForClient/{{id}}/{{clientCode}}"));
    let fork = leak(format!("{base}/{{id}}/fork"));
    let publish = leak(format!("{base}/{{id}}/publish"));
    let draft = leak(format!("{base}/{{id}}/draft"));

    macro_rules! with_caller {
        ($route:expr, $callers:expr, $h:expr, |$ca:ident| $body:expr) => {{
            match $callers.caller(&$h).await {
                Ok($ca) => respond($route, $body.await),
                Err(e) => respond($route, Err(e)),
            }
        }};
    }

    let (s1, c1) = (svc.clone(), callers.clone());
    let (c2, pf) = (callers.clone(), post_fn);
    let (s3, c3) = (svc.clone(), callers.clone());
    let (s4, c4) = (svc.clone(), callers.clone());
    let (s5, c5) = (svc.clone(), callers.clone());
    let (s6, c6) = (svc.clone(), callers.clone());
    let (s7, c7) = (svc.clone(), callers.clone());
    let (s8, c8) = (svc.clone(), callers.clone());
    let (s9, c9) = (svc, callers);
    Router::new()
        .route(
            root,
            get(move |h: HeaderMap, RawQuery(q): RawQuery| async move {
                with_caller!(root, c1, h, |ca| c::list(&s1, &ca, &params(q)))
            })
            .post(move |h: HeaderMap, RawQuery(q): RawQuery, body: Bytes| async move {
                with_caller!(root, c2, h, |ca| pf(ca, params(q), body))
            }),
        )
        .route(nomap, get(move || async move { respond(nomap, Ok(c::nomap2())) }).post(move || async move { respond(nomap, Ok(c::nomap2())) }))
        .route(
            one,
            get({
                let (s, cs) = (s3.clone(), c3.clone());
                move |h: HeaderMap, Path(id): Path<String>, RawQuery(q): RawQuery| async move {
                    with_caller!(one, cs, h, |ca| c::get_one(&s, &ca, &id, &params(q)))
                }
            })
            .put({
                let (s, cs) = (s3.clone(), c3.clone());
                move |h: HeaderMap, Path(id): Path<String>, RawQuery(q): RawQuery, body: Bytes| async move {
                    with_caller!(one, cs, h, |ca| c::put(&s, &ca, &id, &params(q), &body))
                }
            })
            .delete(move |h: HeaderMap, Path(id): Path<String>| async move { with_caller!(one, c4, h, |ca| c::delete(&s4, &ca, &id)) }),
        )
        .route(
            blueprint,
            patch(move |h: HeaderMap, Path(id): Path<String>, body: Bytes| async move {
                with_caller!(blueprint, c5, h, |ca| c::patch_blueprint(&s5, &ca, &id, &body))
            }),
        )
        .route(
            for_client,
            get(move |h: HeaderMap, Path((id, client)): Path<(String, String)>| async move {
                with_caller!(for_client, c6, h, |ca| c::create_for_client(&s6, &ca, &id, &client))
            }),
        )
        .route(fork, post(move |h: HeaderMap, Path(id): Path<String>| async move { with_caller!(fork, c7, h, |ca| c::fork(&s7, &ca, &id)) }))
        .route(
            publish,
            post(move |h: HeaderMap, Path(id): Path<String>, RawQuery(q): RawQuery| async move {
                with_caller!(publish, c8, h, |ca| c::publish(&s8, &ca, &id, &params(q)))
            }),
        )
        .route(
            draft,
            delete(move |h: HeaderMap, Path(id): Path<String>| async move { with_caller!(draft, c9, h, |ca| c::discard_draft(&s9, &ca, &id)) }),
        )
}

/// `AbstractVersionController` under `base`.
pub fn version_router(base: &str, versions: VersionStore, callers: Arc<dyn CallerSource>) -> Router {
    let one = leak(format!("{base}/{{id}}"));
    let query = leak(format!("{base}/{{id}}/query"));
    let (v2, c2) = (versions.clone(), callers.clone());
    Router::new()
        .route(
            one,
            get(move |h: HeaderMap, Path(id): Path<String>| async move {
                match callers.caller(&h).await {
                    Ok(ca) => respond(one, c::version_read(&versions, &ca, &id).await),
                    Err(e) => respond(one, Err(e)),
                }
            }),
        )
        .route(
            query,
            post(move |h: HeaderMap, Path(id): Path<String>, body: Bytes| async move {
                match c2.caller(&h).await {
                    Ok(ca) => respond(query, c::version_query(&v2, &ca, &id, &body).await),
                    Err(e) => respond(query, Err(e)),
                }
            }),
        )
}

/// `AbstractPublishController` under `base`.
pub fn publish_router(base: &str, p: Arc<PublishService>, callers: Arc<dyn CallerSource>) -> Router {
    let pending = leak(format!("{base}/app/{{appCode}}/pending"));
    let all = leak(format!("{base}/app/{{appCode}}"));
    let (p2, c2) = (p.clone(), callers.clone());
    Router::new()
        .route(
            pending,
            get(move |h: HeaderMap, Path(app): Path<String>, RawQuery(q): RawQuery| async move {
                match callers.caller(&h).await {
                    Ok(ca) => respond(pending, c::publish_pending(&p, &ca, &app, &params(q)).await),
                    Err(e) => respond(pending, Err(e)),
                }
            }),
        )
        .route(
            all,
            post(move |h: HeaderMap, Path(app): Path<String>, RawQuery(q): RawQuery| async move {
                match c2.caller(&h).await {
                    Ok(ca) => respond(all, c::publish_app(&p2, &ca, &app, &params(q)).await),
                    Err(e) => respond(all, Err(e)),
                }
            }),
        )
}

/// The `DeletionController` (`DELETE {base}?deleteAppCode=`).
pub fn deletion_router(base: &str, d: Arc<DeletionService>, callers: Arc<dyn CallerSource>) -> Router {
    let root = leak(base.to_string());
    Router::new().route(
        root,
        delete(move |h: HeaderMap, RawQuery(q): RawQuery| async move {
            match callers.caller(&h).await {
                Ok(ca) => respond(root, c::delete_app(&d, &ca, on_behalf(&h, &ca).as_ref(), &params(q)).await),
                Err(e) => respond(root, Err(e)),
            }
        }),
    )
}

/// `AbstractTransportController` under `base`: the overridable routes of the transport
/// documents (with `POST` refused) and the transport routes.
pub fn transport_router(base: &str, t: Arc<TransportService>, callers: Arc<dyn CallerSource>) -> Router {
    let t0 = t.clone();
    let post_fn: PostFn = Arc::new(move |ca, p, body| {
        let t = t0.clone();
        Box::pin(async move {
            if !p.contains("draft") {
                return Err(c::transport_post(&t));
            }
            let entity = c::read_entity(&crate::write::transport::TRANSPORT, &body)?;
            let created = if c::bool_param(&p, "draft", false)? {
                t.documents().create_unpublished(&ca, entity).await?
            } else {
                t.create(&ca, entity).await?
            };
            Ok(Reply::json(crate::json::JValue::Object(crate::pojo::to_jackson(&crate::write::transport::TRANSPORT, &created))))
        })
    });
    let docs = build(base, t.documents().clone(), callers.clone(), post_fn);

    let make = leak(format!("{base}/makeTransport"));
    let make_internal = leak(format!("{base}/internal/makeTransport"));
    let apply = leak(format!("{base}/applyTransport/{{id}}"));
    let apply_code = leak(format!("{base}/applyTransportCode/{{code}}"));
    let cleanup = leak(format!("{base}/internal/cleanupOlderThan"));
    let types = leak(format!("{base}/transportTypes"));
    let create_internal = leak(format!("{base}/internal/createAndApply"));
    let create = leak(format!("{base}/createAndApply"));

    let pair = || (t.clone(), callers.clone());
    let ((t1, c1), (t2, c2), (t3, c3), (t4, c4)) = (pair(), pair(), pair(), pair());
    let ((t7, c7), (t8, c8)) = (pair(), pair());
    let (t5, t6) = (t.clone(), t.clone());

    let routes = Router::new()
        .route(
            make,
            post(move |h: HeaderMap, body: Bytes| async move {
                match c1.caller(&h).await {
                    Ok(ca) => respond(make, c::make_transport(&t1, &ca, false, &body).await),
                    Err(e) => respond(make, Err(e)),
                }
            }),
        )
        .route(
            make_internal,
            post(move |h: HeaderMap, body: Bytes| async move {
                match c2.caller(&h).await {
                    Ok(ca) => respond(make_internal, c::make_transport(&t2, &ca, true, &body).await),
                    Err(e) => respond(make_internal, Err(e)),
                }
            }),
        )
        .route(
            apply,
            get(move |h: HeaderMap, Path(id): Path<String>| async move {
                let r = match c3.caller(&h).await {
                    Ok(ca) => match on_behalf(&h, &ca) {
                        Some(ob) => c::apply_transport(&t3, &ca, &ob, &id).await,
                        None => Err(missing_headers()),
                    },
                    Err(e) => Err(e),
                };
                respond(apply, r)
            }),
        )
        .route(
            apply_code,
            get(move |h: HeaderMap, Path(code): Path<String>| async move {
                let r = match c4.caller(&h).await {
                    Ok(ca) => match on_behalf(&h, &ca) {
                        Some(ob) => c::apply_transport_code(&t4, &ca, &ob, &code).await,
                        None => Err(missing_headers()),
                    },
                    Err(e) => Err(e),
                };
                respond(apply_code, r)
            }),
        )
        .route(cleanup, post(move |RawQuery(q): RawQuery| async move { respond(cleanup, c::cleanup_older_than(&t5, &params(q)).await) }))
        .route(types, get(move || async move { respond(types, Ok(c::transport_types(&t6))) }))
        .route(
            create_internal,
            post(move |h: HeaderMap, RawQuery(q): RawQuery, body: Bytes| async move {
                let p = params(q);
                let r = match c7.caller(&h).await {
                    Ok(ca) => match (on_behalf(&h, &ca), p.first("fileName").map(str::to_string)) {
                        (Some(ob), Some(name)) => c::create_and_apply(&t7, &ca, &ob, &p, &name, &body).await,
                        (None, _) => Err(missing_headers()),
                        (_, None) => Err(c::spring_refusal(StatusCode::BAD_REQUEST, "Required query parameter 'fileName' is not present.")),
                    },
                    Err(e) => Err(e),
                };
                respond(create_internal, r)
            }),
        )
        .route(
            create,
            post(move |h: HeaderMap, RawQuery(q): RawQuery, multipart: Multipart| async move {
                let p = params(q);
                let r = match c8.caller(&h).await {
                    Ok(ca) => match on_behalf(&h, &ca) {
                        Some(ob) => match file_part(multipart).await {
                            Ok((name, bytes)) => c::create_and_apply(&t8, &ca, &ob, &p, &name, &bytes).await,
                            Err(e) => Err(e),
                        },
                        None => Err(missing_headers()),
                    },
                    Err(e) => Err(e),
                };
                respond(create, r)
            }),
        );
    docs.merge(routes)
}

/// The `file` part of a multipart upload: its file name and bytes.
async fn file_part(mut multipart: Multipart) -> AppResult<(String, Bytes)> {
    let bad = |m: &str| c::spring_refusal(StatusCode::BAD_REQUEST, m.to_string());
    while let Some(field) = multipart.next_field().await.map_err(|e| bad(&e.to_string()))? {
        if field.name() == Some("file") {
            let name = field.file_name().unwrap_or("").to_string();
            let bytes = field.bytes().await.map_err(|e| bad(&e.to_string()))?;
            return Ok((name, bytes));
        }
    }
    Err(bad("Required part 'file' is not present."))
}
