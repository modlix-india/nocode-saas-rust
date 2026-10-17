//! Ported from security `AuthenticationControllerTest`: the routes, their status codes, bodies
//! and headers, through the router (the Java test drives `WebTestClient` with a mocked service;
//! here the in-memory store sits under the real service).

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use common::*;
use platform::http::RouteTemplate;
use serde_json::Value;
use tower::ServiceExt;

fn router(h: &Harness) -> axum::Router {
    security::handlers::router(h.auth.clone())
}

fn request(method: Method, uri: &str, headers: &[(&str, &str)], body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header("host", "apps.local:8080");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(Body::from(body.unwrap_or("").to_string())).unwrap()
}

async fn call(h: &Harness, req: Request<Body>) -> (StatusCode, Response, Value) {
    let resp = router(h).oneshot(req).await.unwrap();
    let status = resp.status();
    let (parts, body) = resp.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, Response::from_parts(parts, Body::from(bytes)), v)
}

const SYS: [(&str, &str); 4] = [("clientCode", "SYSTEM"), ("appCode", "appbuilder"), ("X-Forwarded-Host", "apps.local"), ("X-Forwarded-Port", "443")];

async fn token(h: &Harness) -> String {
    let (s, _, v) = call(h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userName":"kirangrandhi","password":"Pass@1234"}"#))).await;
    assert_eq!(s, StatusCode::OK);
    v["accessToken"].as_str().unwrap().to_string()
}

fn with(token: &str) -> Vec<(&'static str, String)> {
    SYS.iter().map(|(k, v)| (*k, v.to_string())).chain([("authorization", format!("Bearer {token}"))]).collect()
}

fn hdrs<'a>(v: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    v.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

fn route(r: &Response) -> &'static str {
    r.extensions().get::<RouteTemplate>().map(|t| t.0).unwrap_or("")
}

mod authenticate_tests {
    use super::*;

    #[tokio::test]
    async fn authenticate_valid_credentials_returns_200() {
        let h = harness();
        let (s, r, v) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userName":"kirangrandhi","password":"Pass@1234","rememberMe":"false","unknownField":1}"#))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(route(&r), "/api/security/authenticate");
        assert_eq!(v["verifiedAppCode"], "appbuilder");
        assert_eq!(v["client"]["code"], "SYSTEM");
        assert_eq!(v["user"]["userName"], "kirangrandhi");
        assert!(v["user"].get("lastName").is_none(), "NON_EMPTY drops the empty last name");
        for (k, want) in [("x-frame-options", "DENY"), ("referrer-policy", "no-referrer"), ("x-content-type-options", "nosniff"), ("cache-control", "no-cache, no-store, max-age=0, must-revalidate")] {
            assert_eq!(r.headers().get(k).unwrap(), want, "{k}");
        }
        assert!(r.headers().get("content-security-policy").is_none());
        assert_eq!(r.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
    }

    #[tokio::test]
    async fn authenticate_invalid_credentials_returns_403() {
        let h = harness();
        let (s, r, v) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userName":"nobody","password":"x"}"#))).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(coded(&v, "No registration available for the selected client on this application."), ("SEC.SIGN_IN_FAILED".into(), true));
        assert_eq!(v["message"], "We couldn't sign you in with these details.");
        assert_eq!(v["stackTrace"], "");
        assert!(v["exceptionId"].as_str().unwrap().starts_with("20"));
        assert_eq!(r.headers().get("x-frame-options").unwrap(), "DENY");
    }

    #[tokio::test]
    async fn authenticate_cookie_flag_sets_the_cookie() {
        let h = harness();
        let (s, r, _) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userId":"142","password":"Pass@1234","cookie":true}"#))).await;
        assert_eq!(s, StatusCode::OK);
        assert!(r.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().starts_with("Authorization=eyJ"));
    }

    #[tokio::test]
    async fn authenticate_bad_bodies_are_400() {
        let h = harness();
        for body in ["", "{", r#"{"userId":"abc"}"#, r#"{"userId":true}"#, r#"{"cookie":"maybe"}"#, r#"{"cookie":[1]}"#] {
            let (s, _, v) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(body))).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
            let code = v["code"].as_str().unwrap();
            assert!(["COMMON.BODY_MISSING", "COMMON.BODY_UNREADABLE", "COMMON.BODY_INVALID", "COMMON.FIELD_INVALID"].contains(&code), "{body}: {code}");
            assert!(v["debugMessage"].as_str().unwrap().starts_with("400 BAD_REQUEST"), "{body}");
        }
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userId":"","cookie":null,"rememberMe":1,"password":"Pass@1234","userName":"kirangrandhi"}"#))).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userId":null,"ssoToken":"FALSE","password":"Pass@1234","userName":"kirangrandhi"}"#))).await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn authenticate_with_unknown_client_code_fails_in_the_filter() {
        let h = harness();
        let (s, _, v) = call(&h, request(Method::POST, "/api/security/authenticate", &[("clientCode", "NOPE")], Some("{}"))).await;
        assert_eq!((s, coded(&v, "Unknown client information requested")), (StatusCode::UNAUTHORIZED, ("SEC.UNKNOWN_CLIENT".into(), true)));
    }

    #[tokio::test]
    async fn authenticate_store_failure_returns_500() {
        let h = harness();
        h.store.with(|d| d.fail.insert("users_by"));
        let (s, _, v) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(r#"{"userName":"x","password":"y"}"#))).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(v["debugMessage"], "users_by failed");
    }

    #[tokio::test]
    async fn wrong_method_is_405() {
        let h = harness();
        let (s, _, _) = call(&h, request(Method::GET, "/api/security/authenticate", &SYS, None)).await;
        assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    }
}

mod authenticate_social_tests {
    use super::*;

    #[tokio::test]
    async fn authenticate_w_social_missing_social_state_returns_400() {
        let h = harness();
        let (s, r, v) = call(&h, request(Method::POST, "/api/security/authenticate/social", &SYS, Some("{}"))).await;
        assert_eq!((s, coded(&v, "Internal Server Error (Unknown)")), (StatusCode::BAD_REQUEST, ("SEC.SOCIAL_LOGIN_FAILED".into(), true)));
        assert_eq!(route(&r), "/api/security/authenticate/social");
    }

    #[tokio::test]
    async fn authenticate_w_social_valid_request_returns_200() {
        let h = harness();
        h.store.with(|d| {
            d.states.push(security::store::StateRow {
                state: "st".into(),
                username: Some("kirangrandhi@example.com".into()),
                created_at: None,
                updated_at: Some(dt("2026-10-15 01:59:00")),
            })
        });
        let (s, _, v) = call(
            &h,
            request(Method::POST, "/api/security/authenticate/social", &SYS, Some(r#"{"userName":"kirangrandhi@example.com","socialRegisterState":"st"}"#)),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["user"]["id"], 142);
    }
}

mod generate_otp_tests {
    use super::*;

    #[tokio::test]
    async fn generate_otp_valid_request_returns_200_with_true() {
        let h = harness();
        let (s, r, v) = call(&h, request(Method::POST, "/api/security/authenticate/otp/generate", &SYS, Some(r#"{"userName":"kirangrandhi","generateOtp":true}"#))).await;
        assert_eq!((s, v), (StatusCode::OK, Value::Bool(true)));
        assert_eq!(route(&r), "/api/security/authenticate/otp/generate");
    }

    #[tokio::test]
    async fn generate_otp_flag_false_returns_200_with_false() {
        let h = harness();
        let (s, _, v) = call(&h, request(Method::POST, "/api/security/authenticate/otp/generate", &SYS, Some("{}"))).await;
        assert_eq!((s, v), (StatusCode::OK, Value::Bool(false)));
    }
}

mod revoke_tests {
    use super::*;

    #[tokio::test]
    async fn revoke_valid_request_returns_200() {
        let h = harness();
        let t = token(&h).await;
        let (s, r, _) = call(&h, request(Method::GET, "/api/security/revoke", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(r.headers().get(header::CONTENT_LENGTH).unwrap(), "0");
        assert!(h.store.with(|d| d.tokens.is_empty()));
        // The revoked token no longer signs anyone in: a bare 401, no Basic challenge.
        let (s, r, _) = call(&h, request(Method::GET, "/api/security/revoke", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(r.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn revoke_with_sso_logout_passes_true_to_service() {
        let h = harness();
        let t = token(&h).await;
        let _other = token(&h).await;
        let (s, _, _) = call(&h, request(Method::GET, "/api/security/revoke?ssoLogout=true", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::OK);
        assert!(h.store.with(|d| d.tokens.is_empty()));
    }

    #[tokio::test]
    async fn revoke_bad_parameter_is_400() {
        let h = harness();
        let t = token(&h).await;
        let (s, _, _) = call(&h, request(Method::GET, "/api/security/revoke?ssoLogout=perhaps", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        for p in ["ssoLogout=off", "ssoLogout=", "ssoLogout=%30", "other=1&x"] {
            let t = token(&h).await;
            let (s, _, _) = call(&h, request(Method::GET, &format!("/api/security/revoke?{p}"), &hdrs(&with(&t)), None)).await;
            assert_eq!(s, StatusCode::OK, "{p}");
        }
    }

    #[tokio::test]
    async fn revoke_service_throws_runtime_exception_returns_500() {
        let h = harness();
        let t = token(&h).await;
        let r = request(Method::GET, "/api/security/revoke", &hdrs(&with(&t)), None);
        // Signed in from the cache, then the delete fails.
        call(&h, request(Method::GET, "/api/security/internal/securityContextAuthentication", &hdrs(&with(&t)), None)).await;
        h.store.with(|d| d.fail.insert("delete_token"));
        let (s, _, _) = call(&h, r).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

mod refresh_token_tests {
    use super::*;

    #[tokio::test]
    async fn refresh_token_valid_token_returns_200() {
        let h = harness();
        let t = token(&h).await;
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/refreshToken", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["accessToken"], t);
    }

    #[tokio::test]
    async fn refresh_token_unauthorized_returns_401() {
        let h = harness();
        let (s, _, _) = call(&h, request(Method::GET, "/api/security/refreshToken", &SYS, None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_token_for_a_client_that_is_gone_is_an_empty_200() {
        let h = harness();
        let t = token(&h).await;
        call(&h, request(Method::GET, "/api/security/internal/securityContextAuthentication", &hdrs(&with(&t)), None)).await;
        h.cache.evict_all_everywhere("clientId").await;
        h.store.with(|d| d.clients.iter_mut().for_each(|c| if c.id == Some(1) { c.id = Some(100) }));
        let (s, r, _) = call(&h, request(Method::GET, "/api/security/refreshToken", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(r.headers().get(header::CONTENT_LENGTH).unwrap(), "0");
    }
}

mod make_one_time_token_tests {
    use super::*;

    #[tokio::test]
    async fn make_one_time_token_valid_request_returns_200() {
        let h = harness();
        let t = token(&h).await;
        let (s, _, v) = call(&h, request(Method::POST, "/api/security/makeOneTimeToken", &hdrs(&with(&t)), Some(r#"{"callbackUrl":"https://x/{token}"}"#))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["url"], format!("https://x/{}", v["token"].as_str().unwrap()));
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/internal/makeOneTimeToken", &hdrs(&with(&t)), Some(r#"{"rememberMe":true}"#))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h.store.with(|d| d.otts[1].row.remember_me), Some(true));
    }

    #[tokio::test]
    async fn make_one_time_token_unauthenticated_returns_401() {
        let h = harness();
        for path in ["/api/security/makeOneTimeToken", "/api/security/internal/makeOneTimeToken", "/api/security/user/access"] {
            let (s, r, _) = call(&h, request(Method::POST, path, &SYS, Some("{}"))).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
            assert!(r.headers().get(header::WWW_AUTHENTICATE).is_none());
        }
    }
}

mod authenticate_with_one_time_token_tests {
    use super::*;

    #[tokio::test]
    async fn authenticate_with_one_time_token_valid_path_token_returns_200() {
        let h = harness();
        let t = token(&h).await;
        let (_, _, v) = call(&h, request(Method::POST, "/api/security/makeOneTimeToken", &hdrs(&with(&t)), Some(r#"{"authMode":"COOKIE"}"#))).await;
        let ott = v["token"].as_str().unwrap().to_string();
        let (s, r, v) = call(&h, request(Method::GET, &format!("/api/security/authenticateWithOneTimeToken/{ott}"), &SYS, None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(route(&r), "/api/security/authenticateWithOneTimeToken/{pathToken}");
        assert_eq!(v["authenticated"], false);
        assert_eq!(v["verifiedAppCode"], "appbuilder");
        assert!(r.headers().get(header::SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn authenticate_with_one_time_token_invalid_token_returns_403() {
        let h = harness();
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/authenticateWithOneTimeToken/abc", &SYS, None)).await;
        assert_eq!((s, coded(&v, "User credentials mismatch")), (StatusCode::FORBIDDEN, ("SEC.USER_CREDENTIALS_MISMATCHED".into(), true)));
    }
}

mod user_access_tests {
    use super::*;

    #[tokio::test]
    async fn get_user_access_user_has_access_returns_200() {
        let h = harness();
        let t = token(&h).await;
        let (s, _, v) = call(&h, request(Method::POST, "/api/security/user/access", &hdrs(&with(&t)), Some(r#"{"appCode":"appbuilder"}"#))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["app"], true);
        assert!(v.get("appURL").is_none(), "no callback: the empty URL is left out");
    }
}

mod verify_token_tests {
    use super::*;

    #[tokio::test]
    async fn verify_token_no_security_context_returns_403_and_bad_token_401() {
        let h = harness();
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/verifyToken", &SYS, None)).await;
        assert_eq!((s, coded(&v, "Forbidden")), (StatusCode::FORBIDDEN, ("SEC.TOKEN_FORBIDDEN".into(), true)));
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/verifyToken", &[("clientCode", "SYSTEM"), ("authorization", "Bearer x")], None)).await;
        assert_eq!((s, coded(&v, "Unauthorized")), (StatusCode::UNAUTHORIZED, ("SEC.TOKEN_UNAUTHORIZED".into(), true)));
    }

    #[tokio::test]
    async fn verify_token_with_valid_token_returns_full_response() {
        let h = harness();
        let t = token(&h).await;
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/verifyToken", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!((v["client"]["code"].as_str(), v["accessToken"].as_str()), (Some("SYSTEM"), Some(t.as_str())));
        assert_eq!(v["user"]["timeZone"], "Asia/Kolkata");
    }

    #[tokio::test]
    async fn verify_token_for_a_client_that_is_gone_is_401() {
        let h = harness();
        let t = token(&h).await;
        call(&h, request(Method::GET, "/api/security/internal/securityContextAuthentication", &hdrs(&with(&t)), None)).await;
        h.cache.evict_all_everywhere("clientId").await;
        h.store.with(|d| d.clients.iter_mut().for_each(|c| if c.id == Some(1) { c.id = Some(100) }));
        let (s, _, _) = call(&h, request(Method::GET, "/api/security/verifyToken", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
}

mod context_authentication_tests {
    use super::*;

    #[tokio::test]
    async fn context_authentication_anonymous_and_signed_in() {
        let h = harness();
        let (s, r, v) = call(&h, request(Method::GET, "/api/security/internal/securityContextAuthentication", &SYS, None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(route(&r), "/api/security/internal/securityContextAuthentication");
        assert_eq!((v["authenticated"].as_bool(), v["name"].as_str()), (Some(false), Some("Anonymous")));
        let t = token(&h).await;
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/internal/securityContextAuthentication", &hdrs(&with(&t)), None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!((v["authenticated"].as_bool(), v["systemClient"].as_bool(), v["urlAppCode"].as_str()), (Some(true), Some(true), Some("appbuilder")));
        let (s, _, v) = call(&h, request(Method::GET, "/api/security/securityContextAuthentication", &hdrs(&with(&t)), None)).await;
        assert_eq!((s, v["authenticated"].as_bool()), (StatusCode::OK, Some(true)));
        let (s, _, _) = call(&h, request(Method::GET, "/api/security/securityContextAuthentication", &SYS, None)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn context_authentication_body_is_jackson_pretty() {
        let h = harness();
        let resp = router(&h)
            .oneshot(request(Method::GET, "/api/security/internal/securityContextAuthentication", &SYS, None))
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with("{\n  \"user\" : {\n    \"id\" : 0,"));
    }
}

mod cleanup_tokens_tests {
    use super::*;

    #[tokio::test]
    async fn cleanup_tokens_default_and_custom_days() {
        let h = harness();
        let (s, r, v) = call(&h, request(Method::POST, "/api/security/internal/tokens/cleanup", &[], None)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(route(&r), "/api/security/internal/tokens/cleanup");
        assert_eq!(v, serde_json::json!({"expiredTokensRemoved": 0, "unusedTokensRemoved": 0, "expiredDraftTokensRemoved": 0}));
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/internal/tokens/cleanup?unusedDays=30", &[], None)).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/internal/tokens/cleanup?unusedDays=", &[], None)).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/internal/tokens/cleanup?unusedDays=x", &[], None)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cleanup_tokens_service_error_returns_500() {
        let h = harness();
        h.store.with(|d| d.fail.insert("delete_expired_tokens"));
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/internal/tokens/cleanup", &[], None)).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

mod limits {
    use super::*;

    #[tokio::test]
    async fn oversized_body_is_refused() {
        let h = harness();
        let big = "x".repeat(2 * 1024 * 1024);
        let (s, _, _) = call(&h, request(Method::POST, "/api/security/authenticate", &SYS, Some(&big))).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
