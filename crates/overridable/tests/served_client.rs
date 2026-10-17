//! `servedClientCode` of `AbstractOverridableDataService` and the filler read keyed by it (Java
//! commit e2b7d48aa, `SharedHostServedClientIntegrationTest`'s service cases). Requests are shaped
//! the way the browser's are on a shared host: the client asked for is the host's, which is also
//! the URL's client, and the token is the tenant user's. SYSTEM hosts and owns the app, MID is
//! managed by SYSTEM, LEAF by MID.

mod common;

use common::*;
use overridable::pojo::map_field;
use overridable::write::filler::Filler;
use overridable::write::OverridableService;
use overridable::JValue;
use platform::security::ContextAuthentication;

const NAME: &str = "sharedHostPage";
const MID: &str = "LZMID";
const LEAF: &str = "LZLEAF";

/// The app inheritance as the platform builds it, `[owner, url client, client]` without
/// repeats, for the clients these tests read as.
fn shared_host() -> Env {
    let e = env();
    e.dir.hierarchy(SYSTEM, &[SYSTEM]);
    e.dir.hierarchy(MID, &[MID, SYSTEM]);
    e.dir.hierarchy(LEAF, &[LEAF, MID, SYSTEM]);
    e.dir.set(|a| {
        a.chains.insert(SYSTEM.into(), vec![SYSTEM.into()]);
        a.chains.insert(MID.into(), vec![SYSTEM.into(), MID.into()]);
        a.chains.insert(LEAF.into(), vec![SYSTEM.into(), LEAF.into()]);
    });
    e.page(&page_json(NAME, SYSTEM, "Submit", "r", ""));
    e.page(&format!(r#"{{"name":"{NAME}","appCode":"{APP}","clientCode":"{MID}","baseClientCode":"{SYSTEM}","version":1,"properties":{{"title":"MID label"}}}}"#));
    e
}

/// A user of `client` on the host `host`, the way `JWTTokenFilter` builds it.
fn user(client: &str, host: &str) -> ContextAuthentication {
    let mut ca = auth_for(client, &all_for("Page"));
    ca.url_client_code = Some(host.to_string());
    ca
}

fn anonymous_on(host: &str) -> ContextAuthentication {
    let mut ca = user(SYSTEM, host);
    ca.authenticated = false;
    ca
}

/// `pageService.read(name, appCode, clientCode)` as the given caller: the title served.
async fn read(e: &Env, ca: &ContextAuthentication, client: &str) -> Option<String> {
    let r = e.pages.read_resolved(ca, NAME, APP, client, false).await.unwrap()?;
    prop_str(&r.entity, "title").map(str::to_string)
}

async fn served(e: &Env, ca: Option<&ContextAuthentication>, client: &str) -> String {
    e.cx.store.served_client_code(ca, APP, client).await
}

#[tokio::test]
async fn a_tenants_user_on_the_shared_host_gets_the_tenants_own_page() {
    let e = shared_host();
    assert_eq!(served(&e, Some(&user(MID, SYSTEM)), SYSTEM).await, MID);
    assert_eq!(read(&e, &user(MID, SYSTEM), SYSTEM).await.as_deref(), Some("MID label"));
}

#[tokio::test]
async fn anonymous_visitors_and_the_hosts_own_users_still_get_the_hosts_page() {
    let e = shared_host();
    assert_eq!(read(&e, &anonymous_on(SYSTEM), SYSTEM).await.as_deref(), Some("Submit"));
    assert_eq!(read(&e, &user(SYSTEM, SYSTEM), SYSTEM).await.as_deref(), Some("Submit"));
    assert_eq!(served(&e, None, SYSTEM).await, SYSTEM, "no caller at all");
}

#[tokio::test]
async fn a_tenant_with_no_copy_of_its_own_gets_its_managing_clients() {
    let e = shared_host();
    assert_eq!(served(&e, Some(&user(LEAF, SYSTEM)), SYSTEM).await, LEAF);
    assert_eq!(read(&e, &user(LEAF, SYSTEM), SYSTEM).await.as_deref(), Some("MID label"));
}

#[tokio::test]
async fn a_tenant_without_read_access_to_the_app_is_served_the_hosts_page() {
    let e = shared_host();
    e.dir.set(|a| {
        a.read_by.insert((APP.into(), MID.into()), false);
    });
    assert_eq!(read(&e, &user(MID, SYSTEM), SYSTEM).await.as_deref(), Some("Submit"));
}

#[tokio::test]
async fn on_a_clients_own_site_a_user_of_a_client_above_it_still_sees_that_clients_site() {
    let e = shared_host();
    assert_eq!(served(&e, Some(&user(SYSTEM, MID)), MID).await, MID);
    assert_eq!(read(&e, &user(SYSTEM, MID), MID).await.as_deref(), Some("MID label"));
}

#[tokio::test]
async fn a_client_named_on_purpose_not_the_host_is_read_as_named() {
    let e = shared_host();
    assert_eq!(served(&e, Some(&user(SYSTEM, SYSTEM)), MID).await, MID);
    assert_eq!(read(&e, &user(SYSTEM, SYSTEM), MID).await.as_deref(), Some("MID label"));
    // A tenant naming another client that is not the host: as named too.
    assert_eq!(served(&e, Some(&user(LEAF, SYSTEM)), MID).await, MID);
}

#[tokio::test]
async fn a_host_that_does_not_manage_the_tenant_or_a_failed_lookup_reads_as_asked() {
    let e = shared_host();
    e.dir.hierarchy("OTHER", &["OTHER", "ELSEWHERE"]);
    assert_eq!(served(&e, Some(&user("OTHER", SYSTEM)), SYSTEM).await, SYSTEM);
    e.dir.hierarchy("LONER", &["LONER"]);
    assert_eq!(served(&e, Some(&user("LONER", SYSTEM)), SYSTEM).await, SYSTEM, "a hierarchy of the client alone");
    e.dir.set(|a| a.failing = true);
    assert_eq!(served(&e, Some(&user(MID, SYSTEM)), SYSTEM).await, SYSTEM);
}

#[tokio::test]
async fn blank_codes_and_a_caller_without_a_client_read_as_asked() {
    let e = shared_host();
    let mid = user(MID, SYSTEM);
    assert_eq!(e.cx.store.served_client_code(Some(&mid), " ", SYSTEM).await, SYSTEM);
    assert_eq!(e.cx.store.served_client_code(Some(&mid), APP, "").await, "");
    let mut nobody = user(MID, SYSTEM);
    nobody.client_code = None;
    assert_eq!(served(&e, Some(&nobody), SYSTEM).await, SYSTEM);
    let mut no_url = user(MID, SYSTEM);
    no_url.url_client_code = None;
    assert_eq!(served(&e, Some(&no_url), SYSTEM).await, SYSTEM, "no URL client: the host is not known");
}

#[tokio::test]
async fn the_filler_read_is_keyed_by_the_client_served() {
    let e = shared_host();
    let fillers = OverridableService::new(Filler::ui(&e.cache), e.cx.clone());
    let host = auth_for(SYSTEM, &all_for("Application"));
    fillers.create(&host, obj(r#"{"appCode":"testapp","definition":{"a":1},"values":{"v":"host"}}"#)).await.unwrap();
    let mut mid_writer = auth_for(MID, &all_for("Application"));
    mid_writer.url_client_code = Some(MID.into());
    fillers
        .create(&mid_writer, obj(r#"{"appCode":"testapp","baseClientCode":"SYSTEM","definition":{"a":1},"values":{"v":"MID"}}"#))
        .await
        .unwrap();
    let f = Filler::ui(&e.cache);
    let value = |r: Option<std::sync::Arc<overridable::Resolved>>| map_field(&r.unwrap().entity, "values").unwrap()["v"].clone();
    // The host's own read fills the host's entry first; it must not answer for the tenant.
    assert_eq!(value(f.read(&fillers, &host, APP, SYSTEM, false).await.unwrap()), JValue::from("host"));
    let tenant = {
        let mut ca = auth_for(MID, &all_for("Application"));
        ca.url_client_code = Some(SYSTEM.into());
        ca
    };
    assert_eq!(value(f.read(&fillers, &tenant, APP, SYSTEM, false).await.unwrap()), JValue::from("MID"));
}
