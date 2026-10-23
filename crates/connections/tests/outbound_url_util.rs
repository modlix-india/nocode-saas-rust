//! `OutboundUrlUtilTest`, ported case for case, plus the checks Rust adds in `guard_target`.
//! Name resolution is pinned with `with_resolver`, so nothing here needs a network.

use std::net::IpAddr;
use std::sync::Arc;

use connections::error::ConnError;
use connections::outbound::{self, Resolver};
use serde_json::{json, Map, Value};

fn details(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

async fn refuses(key: &str, value: &str) {
    let r = outbound::validate_connection_details(Some(&details(json!({ key: value })))).await;
    assert!(matches!(r, Err(ConnError::Generic { .. })), "{key} = {value} should have been refused");
}

async fn allows(key: &str, value: &str) {
    let r = outbound::validate_connection_details(Some(&details(json!({ key: value })))).await;
    assert!(r.is_ok(), "{key} = {value} should have been allowed: {r:?}");
}

/// Names resolve as listed; anything else does not resolve.
fn dns(entries: &[(&str, &str)]) -> Resolver {
    let map: Vec<(String, IpAddr)> = entries.iter().map(|(n, ip)| (n.to_string(), ip.parse().unwrap())).collect();
    Arc::new(move |name: &str| {
        let hits: Vec<IpAddr> = map.iter().filter(|(n, _)| n == name).map(|(_, ip)| *ip).collect();
        if hits.is_empty() {
            None
        } else {
            Some(hits)
        }
    })
}

// --- PrivateTargets

#[tokio::test]
async fn loopback_and_any_local_by_name_and_by_number() {
    for url in [
        "http://localhost/api",
        "http://localhost:8080/api",
        "https://LOCALHOST/api",
        "http://localhost./api",
        "http://127.0.0.1/api",
        "http://127.99.1.2/api",
        "http://[::1]/api",
        "http://0.0.0.0/api",
    ] {
        refuses("baseUrl", url).await;
    }
}

#[tokio::test]
async fn rfc_1918_and_ipv6_unique_local() {
    for url in ["http://10.0.0.5/x", "http://172.16.4.1/x", "http://172.31.255.254/x", "http://192.168.1.1/x", "http://[fc00::1]/x", "http://[fd12:3456::1]/x"] {
        refuses("baseUrl", url).await;
    }
}

#[tokio::test]
async fn the_cloud_metadata_service_by_address_and_by_name() {
    refuses("baseUrl", "http://169.254.169.254/opc/v2/instance/").await;
    refuses("baseUrl", "http://metadata.google.internal/computeMetadata/v1/").await;
    refuses("baseUrl", "http://[fe80::1]/x").await;
}

#[tokio::test]
async fn carrier_grade_nat_and_protocol_assignment_ranges() {
    refuses("baseUrl", "http://100.64.0.1/x").await;
    refuses("baseUrl", "http://198.18.0.1/x").await;
    refuses("baseUrl", "http://192.0.0.1/x").await;
}

#[tokio::test]
async fn our_own_vcn_and_the_internal_by_convention_suffixes() {
    refuses("baseUrl", "http://dev-mysql.sub10150624021.modlixvcn.oraclevcn.com:3306/x").await;
    refuses("baseUrl", "http://core.internal/api").await;
    refuses("baseUrl", "http://printer.local/api").await;
    refuses("baseUrl", "http://box.home.arpa/api").await;
}

#[tokio::test]
async fn the_slash_12_boundary_is_not_off_by_one() {
    allows("baseUrl", "http://172.32.0.1/x").await;
    allows("baseUrl", "http://11.0.0.1/x").await;
}

// --- Schemes

#[tokio::test]
async fn http_and_https_are_the_only_ones_allowed_an_authority() {
    allows("baseUrl", "https://api.stripe.com/v1").await;
    allows("baseUrl", "http://api.example.com/v1").await;
    refuses("baseUrl", "ftp://files.example.com/x").await;
    refuses("baseUrl", "gopher://example.com/x").await;
}

#[tokio::test]
async fn a_local_read_dressed_up_as_a_url() {
    refuses("baseUrl", "file:///etc/passwd").await;
    refuses("baseUrl", "file:/etc/passwd").await;
    refuses("baseUrl", "jar:file:/app.jar!/x").await;
    refuses("baseUrl", "classpath:application.yml").await;
}

// --- Shape

#[tokio::test]
async fn the_oauth2_nested_url_objects_are_reached() {
    let d = details(json!({"baseUrl": "https://api.example.com", "tokenDetails": {"url": "http://127.0.0.1/token", "methodType": "POST"}}));
    let e = outbound::validate_connection_details(Some(&d)).await.unwrap_err();
    assert!(e.message().starts_with("'tokenDetails.url' cannot be saved"), "{}", e.message());
}

#[tokio::test]
async fn a_url_inside_a_list_is_reached() {
    let d = details(json!({"endpoints": ["https://ok.example.com", "http://192.168.0.9/x"]}));
    let e = outbound::validate_connection_details(Some(&d)).await.unwrap_err();
    assert!(e.message().starts_with("'endpoints[1]' cannot be saved"));
}

#[tokio::test]
async fn an_smtp_host_is_a_bare_host_and_is_still_checked() {
    assert!(outbound::validate_connection_details(Some(&details(json!({"mailProps": {"mail.smtp.host": "localhost"}})))).await.is_err());
    assert!(outbound::validate_connection_details(Some(&details(json!({"mailProps": {"mail.smtp.host": "10.0.0.4"}})))).await.is_err());
    assert!(outbound::validate_connection_details(Some(&details(json!({"mailProps": {"mail.smtp.host": "smtp.sendgrid.net"}})))).await.is_ok());
}

// --- `[connections] block_private_targets` at save time (Rust only)

async fn saved(v: Value, block_private_targets: bool) -> Result<(), ConnError> {
    outbound::validate_connection_details_with(Some(&details(v)), block_private_targets).await
}

#[tokio::test]
async fn with_the_guard_on_the_save_check_is_unchanged() {
    for v in [
        json!({"mailProps": {"mail.smtp.host": "localhost"}}),
        json!({"mailProps": {"mail.smtp.host": "127.0.0.1"}}),
        json!({"mailProps": {"mail.smtp.host": "mailpit.local"}}),
        json!({"baseUrl": "http://localhost:16040/api"}),
        json!({"baseUrl": "http://10.1.2.3/x"}),
        json!({"url": "mongodb://127.0.0.1:27017/db"}),
        json!({"tokenDetails": {"url": "http://[::1]/token"}}),
    ] {
        let strict = outbound::validate_connection_details(Some(&details(v.clone()))).await.unwrap_err();
        let on = saved(v.clone(), true).await.unwrap_err();
        assert_eq!((on.status(), on.message()), (strict.status(), strict.message()), "{v}");
        assert_eq!(on.code().map(|c| c.code.as_ref()), Some("CORE.CONNECTION_TARGET_REFUSED"));
    }
    assert!(saved(json!({"mailProps": {"mail.smtp.host": "smtp.sendgrid.net"}}), true).await.is_ok());
}

#[tokio::test]
async fn with_the_guard_off_private_and_loopback_hosts_can_be_saved() {
    for v in [
        json!({"mailProps": {"mail.smtp.host": "localhost", "mail.smtp.port": "16040"}}),
        json!({"mailProps": {"mail.smtp.host": "127.0.0.1"}}),
        json!({"mailProps": {"mail.smtp.host": "mailpit.local"}}),
        json!({"host": "192.168.1.20"}),
        json!({"baseUrl": "http://localhost:16040/api"}),
        json!({"baseUrl": "http://10.1.2.3/x"}),
        json!({"url": "mongodb://127.0.0.1:27017/db"}),
        json!({"tokenDetails": {"url": "http://[::1]/token"}}),
    ] {
        assert!(saved(v.clone(), false).await.is_ok(), "{v}");
    }
}

#[tokio::test]
async fn with_the_guard_off_the_other_save_rules_still_refuse() {
    for v in [
        json!({"baseUrl": "file:///etc/passwd"}),
        json!({"baseUrl": "gopher://localhost:70/x"}),
        json!({"baseUrl": "ftp://10.0.0.1/x"}),
        json!({"baseUrl": "jar:file:/app.jar!/x"}),
        json!({"baseUrl": "http:///nohost"}),
        json!({"url": "mongodb:///db"}),
        json!({"mailProps": {"mail.smtp.host": "   ."}}),
    ] {
        assert!(saved(v.clone(), false).await.is_err(), "{v}");
    }
}

#[tokio::test]
async fn ordinary_non_url_values_are_left_alone() {
    let d = details(json!({
        "userName": "svc-account", "password": "p@ss/word:1", "headerPrefix": "Bearer",
        "grantType": "client_credentials", "timeout": 30000, "isLifeTimeToken": false,
        "pagePath": "/settings/integrations", "mailProps": {"mail.smtp.starttls.enable": "true"}
    }));
    assert!(outbound::validate_connection_details(Some(&d)).await.is_ok());
}

#[tokio::test]
async fn null_and_empty_details_are_not_an_error() {
    assert!(outbound::validate_connection_details(None).await.is_ok());
    assert!(outbound::validate_connection_details(Some(&Map::new())).await.is_ok());
}

// --- Evasion

#[tokio::test]
async fn a_decimal_or_hex_spelling_of_loopback() {
    refuses("baseUrl", "http://2130706433/x").await;
    refuses("baseUrl", "http://0x7f000001/x").await;
    refuses("baseUrl", "http://127.1/x").await;
}

#[tokio::test]
async fn userinfo_that_makes_the_host_look_like_somewhere_else() {
    refuses("baseUrl", "http://api.example.com@127.0.0.1/x").await;
}

#[tokio::test]
async fn an_ipv4_mapped_ipv6_loopback() {
    refuses("baseUrl", "http://[::ffff:127.0.0.1]/x").await;
}

// --- Resolved

#[tokio::test]
async fn everything_the_save_time_check_refuses_the_call_time_check_refuses_too() {
    for url in [
        "http://localhost:9000/api",
        "http://127.0.0.1/x",
        "http://10.0.0.5/x",
        "http://169.254.169.254/opc/v2/instance/",
        "ftp://files.example.com/x",
        "file:///etc/passwd",
        "http://core.internal/api",
    ] {
        let e = outbound::validate_resolved(url).await.unwrap_err();
        assert!(e.message().starts_with(&format!("Refusing to call \"{url}\"")), "{}", e.message());
        assert!(!e.message().contains("cannot be saved"));
    }
}

#[tokio::test]
async fn a_name_that_resolves_to_loopback_is_refused_on_the_address() {
    let r = dns(&[("localhost.localdomain", "127.0.0.1")]);
    let e = outbound::with_resolver(r, outbound::validate_resolved("http://localhost.localdomain/x")).await.unwrap_err();
    assert!(e.message().contains("resolves to 127.0.0.1, which is a private or internal address"), "{}", e.message());
}

#[tokio::test]
async fn a_name_that_does_not_resolve_is_refused_rather_than_attempted() {
    let e = outbound::with_resolver(dns(&[]), outbound::validate_resolved("https://no-such-host.invalid/x")).await.unwrap_err();
    assert!(e.message().contains("does not resolve"), "{}", e.message());
}

#[tokio::test]
async fn an_address_literal_is_not_looked_up_twice() {
    // The resolver would refuse everything; a literal never reaches it.
    assert!(outbound::with_resolver(dns(&[]), outbound::validate_resolved("https://8.8.8.8/x")).await.is_ok());
}

#[tokio::test]
async fn every_answer_has_to_be_public() {
    let r = dns(&[("mixed.example.com", "93.184.216.34"), ("mixed.example.com", "10.0.0.7"), ("v6.example.com", "fd00::1")]);
    let e = outbound::with_resolver(r.clone(), outbound::validate_resolved("https://mixed.example.com/")).await.unwrap_err();
    assert!(e.message().contains("resolves to 10.0.0.7"));
    let e = outbound::with_resolver(r, outbound::validate_resolved("https://v6.example.com/")).await.unwrap_err();
    assert!(e.message().contains("resolves to fd00:0:0:0:0:0:0:1"), "{}", e.message());
}

#[tokio::test]
async fn the_refusal_names_the_field_and_the_value() {
    let e = outbound::validate_connection_details(Some(&details(json!({"baseUrl": "http://localhost:9000/api"})))).await.unwrap_err();
    assert!(e.message().contains("baseUrl") && e.message().contains("localhost"));
    assert_eq!(e.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn is_usable_answers_instead_of_throwing() {
    assert!(outbound::is_usable(Some(&details(json!({"baseUrl": "https://api.example.com"})))).await);
    assert!(!outbound::is_usable(Some(&details(json!({"baseUrl": "http://10.1.2.3"})))).await);
}

#[tokio::test]
async fn a_real_production_shape_passes_unchanged() {
    let d = details(json!({
        "baseUrl": "https://graph.facebook.com/v21.0", "userName": "modlix", "password": "secret", "timeout": 30000,
        "encodingMode": "URI_COMPONENT", "defaultHeaders": {"Content-Type": "application/json"}
    }));
    assert!(outbound::validate_connection_details(Some(&d)).await.is_ok());
}

// --- DatabaseSchemes

#[tokio::test]
async fn database_addresses() {
    allows("url", "mongodb://user:pw@cluster.example.com:27017/admin").await;
    allows("url", "mongodb+srv://user:pw@cluster.example.com/admin?retryWrites=true").await;
    allows("url", "mongodb://a.example.com:27017,b.example.com:27017/db").await;
    refuses("url", "mongodb://a.example.com:27017,10.0.0.5:27017/db").await;
    for url in [
        "mongodb://localhost:27017/admin",
        "mongodb://127.0.0.1:27017/admin",
        "mongodb://10.1.2.3:27017/admin",
        "mongodb://192.168.1.10:27017/admin",
        "mongodb://172.16.0.9:27017/admin",
        "mongodb://db.sub01.vcn01.oraclevcn.com:27017/admin",
        "mongodb://169.254.169.254:27017/admin",
        "mongodb+srv://mongo.internal/admin",
        "mongodb://user:p@ss@127.0.0.1:27017/admin",
        "mongodb:///admin",
        "mongodb://@/admin",
        "redis://cluster.example.com:6379",
        "ftp://files.example.com/x",
    ] {
        refuses("url", url).await;
    }
    allows("url", "mongodb://user:p@ss@cluster.example.com:27017/admin").await;
    // Bracketed members and their edge cases.
    refuses("url", "mongodb://[::1]:27017/db").await;
    refuses("url", "mongodb://[::1/db").await;
    refuses("url", "mongodb://a.example.com, /db").await;
    refuses("url", "mongodb://:27017/db").await;
}

// --- What Rust adds

#[tokio::test]
async fn guard_target_also_checks_the_clients_reading_of_the_url() {
    // A name whose only answer is an IPv4-mapped private address passes Java's check (an
    // Inet6Address there) but is refused here.
    let r = dns(&[("mapped.example.com", "::ffff:10.0.0.1"), ("public.example.com", "93.184.216.34")]);
    assert!(outbound::with_resolver(r.clone(), outbound::validate_resolved("https://mapped.example.com/")).await.is_ok());
    let e = outbound::with_resolver(r.clone(), outbound::guard_target("https://mapped.example.com/")).await.unwrap_err();
    assert!(e.message().contains("resolves to 10.0.0.1"), "{}", e.message());
    assert!(outbound::with_resolver(r.clone(), outbound::guard_target("https://public.example.com/x")).await.is_ok());
    assert!(outbound::with_resolver(r, outbound::guard_target("https://8.8.8.8/x")).await.is_ok());
    assert!(outbound::guard_target("http://127.0.0.1/").await.is_err());
}

#[test]
fn numeric_hosts_and_canonical_addresses() {
    assert!(outbound::numeric_host("[x]"));
    assert!(!outbound::numeric_host("[x\ny]"));
    assert!(outbound::numeric_host("0x7f.1"));
    assert!(outbound::numeric_host("::1"));
    assert!(!outbound::numeric_host("example.com"));
    use connections::java::inet::JavaInet;
    let mapped = JavaInet::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
    assert_eq!(outbound::canonical(mapped), JavaInet::V4([10, 0, 0, 1]));
    assert_eq!(outbound::canonical(JavaInet::V4([1, 2, 3, 4])), JavaInet::V4([1, 2, 3, 4]));
}
