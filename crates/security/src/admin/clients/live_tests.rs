//! In-crate live tests of this piece's services, called directly (gated like the route tests:
//! `SECURITY_AUTH_LIVE=1` with `config/local.toml`). They reach what a SYSTEM caller through the
//! routes does not: an Owner of FIN acting on apps, access, properties and dependencies, explicit
//! apps, generated app codes, refused event publishes, the social sign-up round trip with a fake
//! provider. Every write is on scratch apps (`zzrust...`) made and removed here.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use super::apps::{self, Level};
use super::entity;
use super::testlive::{id_of, owner, remove_app, remove_leftovers, row, scratch_app, scratch_code, state, state_with, system, ctx, FailingEvents};
use crate::spring::{Order as SortOrder, Pageable};

fn status<T: std::fmt::Debug>(r: crate::errors::AuthResult<T>) -> StatusCode {
    r.unwrap_err().status()
}

#[tokio::test]
async fn apps_as_an_owner_and_explicit_apps() {
    let Some(s) = state().await else { return };
    for p in ["zzrustown", "zzrustexp", "zzrustgen"] {
        remove_leftovers(&s, p).await;
    }
    let sys = system(&s).await;
    let own = owner(&s).await;
    let fin = own.user.client_id();

    // The owner's own app, and one for a client it does not manage.
    let mine_code = scratch_code("zzrustown");
    let mine = scratch_app(&s, &own, json!({"appName": "ZZ Own", "appCode": mine_code, "appUsageType": "B2C"})).await;
    let mine_id = id_of(&mine);
    assert_eq!(entity::u64_of(&mine, "clientId"), Some(fin));
    assert_eq!(status(apps::create(&s, &own, row(json!({"appName": "x", "appCode": scratch_code("zzrustown"), "clientId": 1}))).await), StatusCode::FORBIDDEN);
    // Explicit apps belong to the client's manager (or SYSTEM), with edit access for the creator.
    let exp_code = scratch_code("zzrustexp");
    let exp = scratch_app(&s, &own, json!({"appName": "ZZ Exp", "appCode": exp_code, "appAccessType": "EXPLICIT", "appUsageType": "B2B"})).await;
    let exp_id = id_of(&exp);
    let manager = s.dir().managed_client(fin).await.unwrap().id.unwrap_or(1);
    assert_eq!(entity::u64_of(&exp, "clientId"), Some(manager));
    let exp2_code = scratch_code("zzrustexp");
    let exp2 = scratch_app(&s, &sys, json!({"appName": "ZZ Exp 2", "appCode": exp2_code, "appAccessType": "EXPLICIT"})).await;
    assert_eq!(entity::u64_of(&exp2, "clientId"), Some(1));
    // A generated code.
    let gen = scratch_app(&s, &sys, json!({"appName": "ZZ Rust Gen"})).await;
    let gen_code = entity::str_of(&gen, "appCode").unwrap().to_string();
    let gen_id = id_of(&gen);
    assert!(gen_code.starts_with("zzrustgen"), "{gen_code}");
    // A hostname someone already holds.
    let taken: Option<String> = sqlx::query_scalar(
        "SELECT LOWER(SUBSTRING_INDEX(URL_PATTERN, '.', 1)) FROM security_client_url WHERE URL_PATTERN LIKE '%.local.modlix.com' \
         AND SUBSTRING_INDEX(URL_PATTERN, '.', 1) REGEXP '^[a-z]+$' AND LOWER(SUBSTRING_INDEX(URL_PATTERN, '.', 1)) NOT IN (SELECT APP_CODE FROM security_app) LIMIT 1",
    )
    .fetch_optional(&s.db.pool)
    .await
    .unwrap();
    if let Some(label) = taken {
        match apps::create(&s, &sys, row(json!({"appName": "x", "appCode": label}))).await {
            Ok(made) => {
                remove_app(&s, &sys, id_of(&made)).await;
                panic!("{label} was taken");
            }
            Err(e) => assert_eq!(e.status(), StatusCode::CONFLICT),
        }
    }

    // Reads as the owner.
    let via_system = ctx(&s, Some(110), "SYSTEM", Some("appbuilder")).await;
    let any = apps::find_any_apps(&s, &via_system, &Pageable::of(0, 2, vec![]), None).await;
    let cond = crate::condition::from_params(&[("appCode".to_string(), "appbuilder".to_string())]);
    let any_cond = apps::find_any_apps(&s, &via_system, &Pageable::of(0, 2, vec![]), cond.as_ref()).await;
    if via_system.logged_in_from_client_id != Some(fin) {
        assert!(any.is_ok() && any_cond.is_ok());
    }
    assert_eq!(apps::by_code_check_access(&s, &own, &gen_code).await.unwrap(), None);
    let m = apps::read_access_map(&s, &own, &["appbuilder".to_string(), "appbuilder".to_string()]).await.unwrap();
    assert_eq!(m.as_object().unwrap().len(), 1);
    assert_eq!(apps::base_client_code(&s, &own, &exp_code).await.unwrap(), Some(json!(["SYSTEM", true])));
    assert!(!apps::has_delete_access(&s, &own, "appbuilder", "SYSTEM").await.unwrap());
    assert!(!apps::has_delete_access(&s, &own, "appbuilder", "NOPE").await.unwrap());
    let sorted = Pageable::of(0, 2, vec![SortOrder::new("name", false), SortOrder::new("nope", true)]);
    assert!(apps::app_clients(&s, &own, "appbuilder", Some(false), Some("fin"), &sorted).await.is_ok());

    // Updates: an explicit app with edit access, its own app, and one it cannot reach.
    let body = |id: u64, name: &str| row(json!({"id": id, "appName": name, "appUsageType": "B2B", "appAccessType": "EXPLICIT", "status": "ACTIVE"}));
    assert!(apps::update(&s, &own, &body(exp_id, "ZZ Exp up")).await.is_ok());
    assert!(apps::update(&s, &own, &row(json!({"id": mine_id, "appName": "ZZ Own up", "appUsageType": "B2C", "status": "ACTIVE"}))).await.is_ok());
    assert_eq!(status(apps::update(&s, &own, &body(gen_id, "no")).await), StatusCode::NOT_FOUND);

    // Access: not for a client it does not manage, not on someone else's explicit app.
    assert_eq!(status(apps::add_client_access(&s, &own, mine_id, Some(1), false).await), StatusCode::FORBIDDEN);
    assert_eq!(status(apps::add_client_access(&s, &own, exp_id, Some(fin), false).await), StatusCode::FORBIDDEN);
    assert!(apps::add_client_access(&s, &own, mine_id, Some(fin), true).await.unwrap());
    let own_access: u64 = sqlx::query_scalar(&format!("SELECT ID FROM security_app_access WHERE APP_ID = {mine_id} AND CLIENT_ID = {fin}")).fetch_one(&s.db.pool).await.unwrap();
    assert!(apps::remove_client_access(&s, &own, mine_id, own_access).await.unwrap());
    let exp_access: u64 = sqlx::query_scalar(&format!("SELECT ID FROM security_app_access WHERE APP_ID = {exp_id} AND CLIENT_ID = {fin}")).fetch_one(&s.db.pool).await.unwrap();
    assert_eq!(status(apps::remove_client_access(&s, &own, exp_id, exp_access).await), StatusCode::FORBIDDEN);
    assert_eq!(status(apps::update_client_access(&s, &own, Some(exp_access), true).await), StatusCode::FORBIDDEN);
    assert_eq!(status(apps::update_client_access(&s, &own, None, true).await), StatusCode::FORBIDDEN);

    // Properties.
    assert_eq!(apps::update_property(&s, &own, Some(mine_id), Some(fin), Some("ZZP"), Some("v")).await.unwrap(), Some(true));
    let pid: u64 = sqlx::query_scalar(&format!("SELECT ID FROM security_app_property WHERE APP_ID = {mine_id} AND NAME = 'ZZP'")).fetch_one(&s.db.pool).await.unwrap();
    assert_eq!(apps::delete_property_by_id(&s, &own, pid).await.unwrap(), Some(true));
    assert_eq!(apps::delete_property_by_id(&s, &own, 0).await.unwrap(), None);
    assert_eq!(apps::update_property(&s, &own, Some(mine_id), Some(1), Some("x"), Some("v")).await.unwrap(), None);
    assert_eq!(status(apps::update_property(&s, &own, Some(gen_id), Some(fin), Some("x"), Some("v")).await), StatusCode::FORBIDDEN);
    assert_eq!(status(apps::update_property(&s, &own, Some(mine_id), Some(fin), None, Some("v")).await), StatusCode::BAD_REQUEST);
    assert_eq!(apps::update_property(&s, &sys, Some(exp_id), Some(1), Some("ZZQ"), Some("v")).await.unwrap(), Some(true));
    let qid: u64 = sqlx::query_scalar(&format!("SELECT ID FROM security_app_property WHERE APP_ID = {exp_id} AND NAME = 'ZZQ'")).fetch_one(&s.db.pool).await.unwrap();
    assert_eq!(apps::delete_property_by_id(&s, &own, qid).await.unwrap(), None);
    assert_eq!(apps::delete_property_by_id(&s, &sys, qid).await.unwrap(), Some(true));
    assert_eq!(status(apps::delete_property(&s, &own, fin, mine_id, " ").await), StatusCode::BAD_REQUEST);
    assert_eq!(apps::delete_property(&s, &own, 1, mine_id, "x").await.unwrap(), None);
    assert_eq!(apps::delete_property(&s, &own, fin, gen_id, "x").await.unwrap(), Some(false));
    assert_eq!(apps::properties(&s, &own, Some(1), None, Some("appbuilder"), None).await.unwrap(), None);

    // Dependencies.
    assert!(apps::add_dependency(&s, &own, Some(&mine_code), Some("appbuilder")).await.is_ok());
    assert_eq!(status(apps::remove_dependency(&s, &own, &mine_code, "appbuilder").await), StatusCode::FORBIDDEN);
    assert_eq!(status(apps::add_dependency(&s, &own, Some(&gen_code), Some("appbuilder")).await), StatusCode::FORBIDDEN);
    assert_eq!(status(apps::add_dependency(&s, &own, None, Some("appbuilder")).await), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(status(apps::remove_dependency(&s, &own, &gen_code, &exp2_code).await), StatusCode::FORBIDDEN);

    // Events: an unknown client raises nothing; a broker that refuses is a false, not an error.
    assert!(!apps::raise(&s, &sys, &mine_code, mine_id, 0, Level::None, Level::Read).await);
    let failing = state_with(Some(Arc::new(FailingEvents))).await.unwrap();
    assert!(!apps::raise(&failing, &sys, &mine_code, mine_id, 1, Level::None, Level::Read).await);

    // Deletes.
    assert_eq!(status(apps::delete(&s, &own, gen_id).await), StatusCode::NOT_FOUND);
    assert!(apps::delete(&s, &own, exp_id).await.is_ok());
    assert_eq!(status(apps::delete_everything(&s, &own, gen_id, false).await), StatusCode::NOT_FOUND);
    assert!(apps::delete(&s, &own, mine_id).await.is_ok());
    assert!(apps::delete_everything(&s, &own, mine_id, false).await.unwrap());
    for id in [exp_id, id_of(&exp2), gen_id] {
        remove_app(&s, &sys, id).await;
    }
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_app WHERE APP_CODE LIKE 'zzrustown%' OR APP_CODE LIKE 'zzrustexp%' OR APP_CODE LIKE 'zzrustgen%'")
        .fetch_one(&s.db.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}


fn reg(part: &str) -> &'static super::app_reg::RegType {
    super::app_reg::reg_type(part).unwrap()
}

fn reg_body(extra: serde_json::Value) -> super::entity::Row {
    let mut b = row(json!({"clientType": "BUS", "level": "CLIENT", "businessType": "COMMON", "writeAccess": false, "register": false, "allowSubPathAccess": false}));
    b.extend(row(extra));
    b
}

fn reg_query(client_code: Option<&str>, client_id: Option<u64>, page: i64, size: i64) -> super::app_reg::RegQuery {
    super::app_reg::RegQuery {
        client_code: client_code.map(str::to_string),
        client_id,
        client_type: Some("BUS".into()),
        level: Some("CLIENT".into()),
        business_type: Some("COMMON".into()),
        page: Some(page),
        size: Some(size),
    }
}

#[tokio::test]
async fn registration_objects_as_system_and_owner() {
    use super::app_reg::{create, delete_object, page};
    let Some(s) = state().await else { return };
    remove_leftovers(&s, "zzrustrgo").await;
    let sys = system(&s).await;
    let own = owner(&s).await;
    let code = scratch_code("zzrustrgo");
    let app = scratch_app(&s, &sys, json!({"appName": "ZZ Reg Obj", "appCode": code, "appUsageType": "B2B"})).await;
    let app_id = id_of(&app);
    let mine_code = scratch_code("zzrustrgo");
    let mine = scratch_app(&s, &own, json!({"appName": "ZZ Reg Obj Own", "appCode": mine_code, "appUsageType": "B2B"})).await;
    let id = |v: &serde_json::Value| v["id"].as_u64().unwrap();

    // SYSTEM: every type, the referenced objects filled in.
    let role = create(&s, &sys, reg("userRole"), &code, reg_body(json!({"roleId": 1}))).await.unwrap();
    assert_eq!(role["role"]["id"], 1);
    let prof = create(&s, &sys, reg("userProfile"), &code, reg_body(json!({"profileId": 1}))).await.unwrap();
    assert_eq!(prof["profile"]["id"], 1);
    let restr = create(&s, &sys, reg("profileRestriction"), &code, reg_body(json!({"profileId": 1}))).await.unwrap();
    let dept = create(&s, &sys, reg("department"), &code, reg_body(json!({"name": "ZZ Dept"}))).await.unwrap();
    let sub = create(&s, &sys, reg("department"), &code, reg_body(json!({"name": "ZZ Sub", "parentDepartmentId": id(&dept)}))).await.unwrap();
    assert_eq!(sub["parentDepartment"]["id"], dept["id"]);
    let des = create(&s, &sys, reg("designation"), &code, reg_body(json!({"name": "ZZ Des"}))).await.unwrap();
    let des2 = create(&s, &sys, reg("designation"), &code, reg_body(json!({"name": "ZZ Des 2", "parentDesignationId": id(&des), "nextDesignationId": id(&des)}))).await.unwrap();
    // A user designation's designation is looked up as a user designation: refused (Java's too).
    assert_eq!(status(create(&s, &sys, reg("userDesignation"), &code, reg_body(json!({"designationId": id(&des)}))).await), StatusCode::FORBIDDEN);
    let acc = create(&s, &sys, reg("appAccess"), &code, reg_body(json!({"allowAppId": app_id, "writeAccess": true}))).await.unwrap();
    assert_eq!(acc["allowApp"]["appCode"], code.as_str());
    // Refused: an unknown role (the role read's 404), an unknown profile, an unknown app.
    assert_eq!(status(create(&s, &sys, reg("userRole"), &code, reg_body(json!({"roleId": 999_999_999}))).await), StatusCode::NOT_FOUND);
    assert_eq!(status(create(&s, &sys, reg("userProfile"), &code, reg_body(json!({"profileId": 999_999_999}))).await), StatusCode::FORBIDDEN);
    assert_eq!(status(create(&s, &sys, reg("fileAccess"), "zznoapphere", reg_body(json!({}))).await), StatusCode::FORBIDDEN);

    // Pages: by code or id, the filters, the bounds.
    let p = page(&s, &sys, reg("userRole"), &code, &reg_query(Some("SYSTEM"), None, 0, 5)).await.unwrap().unwrap();
    assert_eq!(p["totalElements"], 1);
    assert_eq!(page(&s, &sys, reg("designation"), &code, &reg_query(None, Some(1), 0, 5)).await.unwrap().unwrap()["totalElements"], 2);
    assert_eq!(page(&s, &sys, reg("userRole"), &code, &reg_query(Some("NOPE"), None, 0, 5)).await.unwrap(), None);
    assert_eq!(page(&s, &sys, reg("userRole"), "zznoapphere", &reg_query(None, None, 0, 5)).await.unwrap(), None);
    assert!(page(&s, &sys, reg("userRole"), &code, &reg_query(None, None, -1, 5)).await.is_err());
    assert!(page(&s, &sys, reg("userRole"), &code, &reg_query(None, None, 0, 0)).await.is_err());

    // An owner: nothing on SYSTEM's app; its own app's objects, for its own client only.
    assert_eq!(delete_object(&s, &own, reg("userRole"), id(&role)).await.unwrap(), None);
    assert_eq!(status(create(&s, &own, reg("fileAccess"), &code, reg_body(json!({"resourceType": "STATIC", "accessName": "zz", "path": "/zz"}))).await), StatusCode::FORBIDDEN);
    assert_eq!(
        status(create(&s, &own, reg("fileAccess"), &mine_code, reg_body(json!({"clientId": 1, "resourceType": "STATIC", "accessName": "zz", "path": "/zz"}))).await),
        StatusCode::FORBIDDEN
    );
    let fa = create(&s, &own, reg("fileAccess"), &mine_code, reg_body(json!({"resourceType": "STATIC", "accessName": "zz", "path": "/zz"}))).await.unwrap();
    let orole = create(&s, &own, reg("userRole"), &mine_code, reg_body(json!({"roleId": 1}))).await.unwrap();
    assert!(page(&s, &own, reg("fileAccess"), &mine_code, &reg_query(None, None, 0, 5)).await.unwrap().is_some());
    assert_eq!(delete_object(&s, &own, reg("fileAccess"), id(&fa)).await.unwrap(), Some(true));
    assert_eq!(delete_object(&s, &own, reg("userRole"), id(&orole)).await.unwrap(), Some(true));

    for (part, v) in [("userRole", &role), ("userProfile", &prof), ("profileRestriction", &restr), ("designation", &des2), ("designation", &des), ("department", &sub), ("department", &dept), ("appAccess", &acc)] {
        assert_eq!(delete_object(&s, &sys, reg(part), id(v)).await.unwrap(), Some(true), "{part}");
    }
    remove_app(&s, &sys, app_id).await;
    remove_app(&s, &sys, id_of(&mine)).await;
}

/// The provider's profile for a code, in process.
struct FakeProviders;

#[async_trait::async_trait]
impl super::registration::Providers for FakeProviders {
    async fn profile(&self, platform: &str, _: &str, _: &str, code: &str, _: &str) -> Result<super::registration::Profile, String> {
        if code == "fail" {
            return Err("provider down".into());
        }
        let email = format!("zz.soc.{code}@example.com");
        let v = if platform == "GOOGLE" {
            json!({"email": email, "given_name": "ZZ", "family_name": null, "id": 7})
        } else {
            json!({"email": email, "first_name": "ZZ", "last_name": "Meta"})
        };
        Ok(v.as_object().cloned().unwrap())
    }
}

/// The files service, recording what it is asked to make.
#[derive(Default)]
struct RecordingFiles(std::sync::Mutex<Vec<super::register::AccessPath>>);

#[async_trait::async_trait]
impl super::register::Files for RecordingFiles {
    async fn create_access_path(&self, path: &super::register::AccessPath) -> crate::errors::AuthResult<()> {
        self.0.lock().unwrap().push(path.clone());
        Ok(())
    }
}

fn location(r: &axum::response::Response) -> String {
    r.headers().get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
}

#[tokio::test]
async fn social_sign_up_and_more_registrations() {
    use super::register::{self, RegRequest};
    use super::registration::{callback, evoke};
    use crate::admin::users::passwords::SecretType;
    use crate::spring::Params;
    let Some(s) = state().await else { return };
    super::testlive::retire_scratch_users(&s, "zz.soc.%@example.com").await;
    remove_leftovers(&s, "zzrustsoc").await;
    let sys = system(&s).await;
    let code = scratch_code("zzrustsoc");
    let app = scratch_app(&s, &sys, json!({"appName": "ZZ Soc", "appCode": code, "appUsageType": "B2X2X"})).await;
    let app_id = id_of(&app);
    let other_code = scratch_code("zzrustsoc");
    let other = scratch_app(&s, &sys, json!({"appName": "ZZ Soc 2", "appCode": other_code, "appUsageType": "B2X"})).await;
    let host = format!("{code}.example.test");
    super::urls::create(&s, &sys, row(json!({"appCode": code, "urlPattern": host}))).await.unwrap().unwrap();
    let anon = ctx(&s, None, "SYSTEM", Some(&code)).await;
    let files = RecordingFiles::default();
    let good = "Zz!SocPass12345";

    // Not yet open for sign-ups.
    let r = RegRequest { pass_type: Some(SecretType::Otp), email_id: Some("zz.soc.none@example.com".into()), ..Default::default() };
    assert_eq!(status(register::pre_register_check_one(&s, &anon, r).await), StatusCode::BAD_REQUEST);
    assert!(apps::update_property(&s, &sys, Some(app_id), Some(1), Some("REGISTRATION_TYPE"), Some("REGISTRATION_TYPE_NO_VERIFICATION")).await.unwrap().is_some());
    // Registration objects: the other app granted too (and registered on), the Owner profile, a file path.
    let base = |extra: serde_json::Value| {
        let mut b = row(json!({"clientType": "INDV", "level": "CLIENT", "businessType": "COMMON", "writeAccess": false, "register": false, "allowSubPathAccess": false}));
        b.extend(row(extra));
        b
    };
    super::app_reg::create(&s, &sys, reg("appAccess"), &code, base(json!({"allowAppId": id_of(&other), "writeAccess": true, "register": true}))).await.unwrap();
    // Granted, but not registered on again: the registering app is put first all the same.
    super::app_reg::create(&s, &sys, reg("appAccess"), &code, base(json!({"allowAppId": app_id, "register": false}))).await.unwrap();
    super::app_reg::create(&s, &sys, reg("userProfile"), &code, base(json!({"profileId": 9}))).await.unwrap();
    super::app_reg::create(&s, &sys, reg("fileAccess"), &code, base(json!({"resourceType": "STATIC", "accessName": "zz", "path": "/zz", "writeAccess": true}))).await.unwrap();

    // Integrations, evoked with where to go back to.
    for p in ["GOOGLE", "META", "APPLE"] {
        super::integrations::create(&s, row(json!({"appId": app_id, "clientId": 1, "platform": p, "intgId": "cid", "intgSecret": "zz", "loginUri": "l", "signupUri": "u"}))).await.unwrap();
    }
    let state_for = |p: &str, redirect: Option<&str>| {
        let mut q = format!("platform={p}&appCode={code}&clientCode=SYSTEM");
        if let Some(r) = redirect {
            q.push_str(&format!("&redirectUrl={r}"));
        }
        Params::from_query(Some(&q))
    };
    assert_eq!(status(evoke(&s, &anon, "APPLE", &state_for("APPLE", None), "zz.example.test").await), StatusCode::BAD_REQUEST);
    let latest = |s: &crate::admin::AdminState| {
        let pool = s.db.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT STATE FROM security_app_reg_integration_tokens WHERE STATE IS NOT NULL ORDER BY ID DESC LIMIT 1").fetch_one(&pool).await.unwrap()
        }
    };
    let mut cases = vec![
        (None, format!("https://{host}/")),
        (Some("/welcome"), format!("https://{host}/welcome")),
        (Some("welcome"), format!("https://{host}/welcome")),
        (Some(&*Box::leak(format!("modlix.system.{code}://cb").into_boxed_str())), format!("modlix.system.{code}://cb")),
        (Some("other://cb"), format!("https://{host}/")),
        (Some(&*Box::leak(format!("https://{host}/in").into_boxed_str())), format!("https://{host}/in")),
        (Some("https://evil.example.test/x"), format!("https://{host}/")),
        (Some(&*Box::leak(format!("https://u@{host}/x").into_boxed_str())), format!("https://{host}/")),
        // The host decides, as the gateway resolves it; the port does not.
        (Some(&*Box::leak(format!("https://{host}:8443/x").into_boxed_str())), format!("https://{host}:8443/x")),
        (Some("https:///x"), format!("https://{host}/")),
    ];
    let mut first_state = None;
    for (i, (redirect, expected)) in cases.drain(..).enumerate() {
        let platform = if i % 2 == 0 { "GOOGLE" } else { "META" };
        evoke(&s, &anon, platform, &state_for(platform, redirect), "zz.example.test").await.unwrap().unwrap();
        let st = latest(&s).await;
        let resp = callback(&s, &anon, &Params::from_query(Some(&format!("code=c{i}&state={st}"))), &FakeProviders, "zz.example.test").await.unwrap().unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = location(&resp);
        assert!(loc.starts_with(&expected), "{redirect:?}: {loc}");
        assert!(loc.contains(&format!("emailId=zz.soc.c{i}@example.com")), "{loc}");
        if i == 0 {
            first_state = Some(st);
        }
    }
    // Cancelled on the consent screen, the provider down, no app on the URL, no app recorded.
    evoke(&s, &anon, "GOOGLE", &state_for("GOOGLE", None), "zz.example.test").await.unwrap().unwrap();
    let st = latest(&s).await;
    let cancelled = callback(&s, &anon, &Params::from_query(Some(&format!("state={st}"))), &FakeProviders, "h").await.unwrap().unwrap();
    assert!(location(&cancelled).contains("error=access_denied"));
    assert!(callback(&s, &anon, &Params::from_query(Some(&format!("code=fail&state={st}"))), &FakeProviders, "h").await.is_err());
    let no_app = ctx(&s, None, "SYSTEM", None).await;
    assert!(callback(&s, &no_app, &Params::from_query(Some(&format!("code=x&state={st}"))), &FakeProviders, "h").await.unwrap().is_none());
    evoke(&s, &anon, "GOOGLE", &Params::from_query(Some("platform=GOOGLE")), "zz.example.test").await.unwrap().unwrap();
    let bare = latest(&s).await;
    assert!(callback(&s, &anon, &Params::from_query(Some(&format!("code=x&state={bare}"))), &FakeProviders, "h").await.is_err());

    // The social sign-up: refused before the provider answered, with another identity; then made.
    let social = |state: &str, email: &str| RegRequest {
        social_register_state: Some(state.into()),
        email_id: Some(email.into()),
        first_name: Some("ZZ".into()),
        pass_type: Some(SecretType::Pin),
        pin: Some("4826".into()),
        ..Default::default()
    };
    let _ = good;
    let info = super::testlive::info(None, "SYSTEM", Some(&code), &[]);
    evoke(&s, &anon, "GOOGLE", &state_for("GOOGLE", None), "zz.example.test").await.unwrap().unwrap();
    let fresh = latest(&s).await;
    let r = register::register_social(&s, &files, &info, &anon, social(&fresh, "zz.soc.x@example.com")).await;
    assert_eq!(r.unwrap_err().message(), "Client Registration Error : Social login was not completed");
    let st0 = first_state.unwrap();
    let r = register::register_social(&s, &files, &info, &anon, social(&st0, "zz.soc.other@example.com")).await;
    assert_eq!(status(r), StatusCode::BAD_REQUEST);
    let done = register::register_social(&s, &files, &info, &anon, social(&st0, "zz.soc.c0@example.com")).await.unwrap().unwrap();
    let uid = done.body["userId"].as_u64().unwrap();
    assert!(done.cookie.is_some());
    let spent: Option<String> = sqlx::query_scalar("SELECT STATE FROM security_app_reg_integration_tokens WHERE STATE = ?").bind(&st0).fetch_optional(&s.db.pool).await.unwrap();
    assert_eq!(spent, None, "the state is spent");
    let cid: u64 = sqlx::query_scalar(&format!("SELECT CLIENT_ID FROM security_user WHERE ID = {uid}")).fetch_one(&s.db.pool).await.unwrap();
    // Both apps granted (the other with edit), the file path made for each app registered on.
    let granted: Vec<(u64, u8)> = sqlx::query_as(&format!("SELECT APP_ID, EDIT_ACCESS FROM security_app_access WHERE CLIENT_ID = {cid} ORDER BY APP_ID")).fetch_all(&s.db.pool).await.unwrap();
    assert_eq!(granted, vec![(app_id, 0), (id_of(&other), 1)]);
    assert!(!files.0.lock().unwrap().is_empty());
    // The Owner profile makes the user an owner: the client registered on the other app too.
    let client_row = s.dir().client(cid).await.unwrap().unwrap();
    assert!(register::register_app(&s, &files, &sys, &other_code, client_row.id(), uid).await.is_ok());
    assert_eq!(status(register::register_app(&s, &files, &sys, "zznoapphere", cid, uid).await), StatusCode::CONFLICT);
    assert_eq!(status(register::register_app(&s, &files, &sys, &other_code, 999_999_999, uid).await), StatusCode::CONFLICT);

    // Signed in as the scratch user just registered (never a real user): its client registers
    // one more under it, and the caller (no Owner role) becomes its manager.
    let ccode = s.dir().client(cid).await.unwrap().unwrap().code().to_string();
    let scratch_ca = crate::model::ContextAuth {
        authenticated: true,
        user: crate::model::ContextUser {
            id: Some(uid),
            client_id: Some(cid),
            string_authorities: Some(vec!["Authorities.Logged_IN".into()]),
            ..Default::default()
        },
        client_code: Some(ccode.clone()),
        client_type_code: Some("INDV".into()),
        logged_in_from_client_id: Some(cid),
        logged_in_from_client_code: Some(ccode.clone()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some(code.clone()),
        ..Default::default()
    };
    let mine = RegRequest {
        pass_type: Some(SecretType::Password),
        email_id: Some("zz.soc.signed@example.com".into()),
        client_name: Some("ZZ Soc Signed".into()),
        ..Default::default()
    };
    let info2 = super::testlive::info(None, "SYSTEM", Some(&code), &[]);
    let signed = register::register(&s, &files, &info2, &scratch_ca, mine).await.unwrap().unwrap();
    let suid = signed.body["userId"].as_u64().unwrap();
    let scid: u64 = sqlx::query_scalar(&format!("SELECT CLIENT_ID FROM security_user WHERE ID = {suid}")).fetch_one(&s.db.pool).await.unwrap();
    assert_eq!(s.dir().hierarchy(scid).await.unwrap().level0, Some(cid));
    let managed_by = |client: u64| {
        let pool = s.db.pool.clone();
        async move { sqlx::query_scalar::<_, u64>(&format!("SELECT MANAGER_ID FROM security_client_manager WHERE CLIENT_ID = {client}")).fetch_all(&pool).await.unwrap() }
    };
    assert_eq!(managed_by(scid).await, vec![uid]);
    // A client made directly by the same caller: under its client, managed by it.
    let cov_code = format!("ZZRC{}", super::apps::unique_letters("").chars().take(6).collect::<String>().to_uppercase());
    let cov = super::client_admin::create(&s, &scratch_ca, row(json!({"name": "ZZ Cov", "code": cov_code, "typeCode": "BUS", "timeZone": "Asia/Kolkata"})))
        .await
        .unwrap()
        .unwrap();
    let cov_id = id_of(&cov);
    assert_eq!(s.dir().hierarchy(cov_id).await.unwrap().level0, Some(cid));
    assert_eq!(managed_by(cov_id).await, vec![uid]);
    // A generated PIN, signed in with it; the events again need what is stored.
    let r = RegRequest { user_id: Some(suid), pass_type: Some(SecretType::Pin), ..Default::default() };
    assert!(register::evoke_registration_events(&s, &info, &anon, r).await.is_err());
    // Activities by the same caller: on its own client by default, and on one it manages.
    let act = super::activities::create(&s, &scratch_ca, row(json!({"activityName": "ZZ soc"}))).await.unwrap();
    assert_eq!((entity::u64_of(&act, "clientId"), entity::u64_of(&act, "createdBy")), (Some(cid), Some(uid)));
    let act2 = super::activities::create(&s, &scratch_ca, row(json!({"activityName": "ZZ cov", "clientId": cov_id}))).await.unwrap();
    assert_eq!(entity::u64_of(&act2, "clientId"), Some(cov_id));
    // A name whose prefix nobody uses keeps the bare prefix.
    let fresh_prefix = register::client_code_prefix(&format!("Zq{}", super::apps::unique_letters("").chars().take(3).collect::<String>()));
    let fresh_name = format!("{fresh_prefix} unused");
    let taken: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_client WHERE CODE LIKE CONCAT(?, '%')").bind(&fresh_prefix).fetch_one(&s.db.pool).await.unwrap();
    if taken == 0 {
        assert_eq!(register::valid_client_code(&s, &fresh_name).await.unwrap(), fresh_prefix);
    }
    // An unknown app: nothing to evoke, nothing to call back to; no client code: Java's NPE.
    let elsewhere = ctx(&s, None, "SYSTEM", Some("zznoapphere")).await;
    assert_eq!(evoke(&s, &elsewhere, "GOOGLE", &Params::from_query(Some("platform=GOOGLE")), "h").await.unwrap(), None);
    assert!(callback(&s, &elsewhere, &Params::from_query(Some("code=x&state=y")), &FakeProviders, "h").await.unwrap().is_none());
    let headless = crate::request::RequestInfo::new(axum::http::HeaderMap::new(), None);
    assert_eq!(status(super::registration::generate_otp(&s, &anon, &headless, &serde_json::Map::new()).await), StatusCode::INTERNAL_SERVER_ERROR);

    // Removed: the manager rows first, then the users and clients.
    super::testlive::retire_scratch_users(&s, "zz.soc.%@example.com").await;
    super::client_admin::delete(&s, &sys, cov_id).await.unwrap();
    for c in [scid, cov_id] {
        assert!(managed_by(c).await.is_empty(), "{c}");
    }
    for id in [app_id, id_of(&other)] {
        remove_app(&s, &sys, id).await;
    }
}

#[tokio::test]
async fn clients_urls_and_activities_beyond_system() {
    use super::{activities, client_admin, urls};
    let Some(s) = state().await else { return };
    remove_leftovers(&s, "zzrustcua").await;
    let sys = system(&s).await;
    let own = owner(&s).await;
    let plain = ctx(&s, Some(8), "FIN", Some("appbuilder")).await;
    let fin = own.user.client_id();

    // Hierarchies refused without a write.
    client_admin::evict_client(&s, None, None).await;
    assert_eq!(status(client_admin::create_hierarchy(&s, 7, 7).await), StatusCode::BAD_REQUEST);
    let deep: Option<u64> = sqlx::query_scalar("SELECT CLIENT_ID FROM security_client_hierarchy WHERE MANAGE_CLIENT_LEVEL_3 IS NOT NULL LIMIT 1").fetch_optional(&s.db.pool).await.unwrap();
    if let Some(d) = deep {
        assert_eq!(status(client_admin::create_hierarchy(&s, d, 999_999_999).await), StatusCode::BAD_REQUEST);
    }
    let consumer: Option<u64> = sqlx::query_scalar("SELECT ID FROM security_client WHERE LEVEL_TYPE = 'CONSUMER' LIMIT 1").fetch_optional(&s.db.pool).await.unwrap();
    if let Some(c) = consumer {
        let r = client_admin::create(&s, &sys, row(json!({"name": "ZZ no", "code": "ZZNOCREATE", "parentClientId": c}))).await;
        assert_eq!(status(r), StatusCode::BAD_REQUEST);
    }
    // Activities: refused on a client the caller does not manage; a member without the Owner
    // role sees only their own (read only: no real user writes here).
    assert_eq!(status(activities::create(&s, &own, row(json!({"activityName": "ZZ no", "clientId": 1}))).await), StatusCode::FORBIDDEN);
    assert!(activities::page(&s, &plain, fin, &Pageable::of(0, 2, vec![]), None).await.is_ok());

    // URLs: not for a client the caller does not manage; filtered listings; draft grants refused
    // without write access.
    let app = scratch_app(&s, &sys, json!({"appName": "ZZ CUA", "appCode": scratch_code("zzrustcua"), "appUsageType": "B2C"})).await;
    let app_code = entity::str_of(&app, "appCode").unwrap().to_string();
    assert_eq!(urls::create(&s, &own, row(json!({"appCode": app_code, "urlPattern": "zz-no.example.test", "clientId": 1}))).await.unwrap(), None);
    let p = Pageable::of(0, 2, vec![]);
    assert!(urls::client_urls(&s, &sys, "appbuilder", Some("SYSTEM"), Some("local"), Some("sys"), &p).await.is_ok());
    assert!(urls::client_urls(&s, &own, "appbuilder", Some("FIN"), None, None, &p).await.is_ok());
    assert_eq!(status(urls::client_urls(&s, &own, "appbuilder", Some("SYSTEM"), None, None, &p).await), StatusCode::FORBIDDEN);
    assert_eq!(status(urls::mint_draft_url(&s, &own, &app_code).await), StatusCode::FORBIDDEN);
    assert_eq!(status(urls::mint_draft_token(&s, &own, &app_code).await), StatusCode::FORBIDDEN);

    // A policy on the app goes with it.
    let pin = super::policies::create(&s, &sys, super::policies::PolicyType::Pin, row(json!({"appId": id_of(&app), "clientId": 1, "length": 6}))).await;
    assert!(pin.is_ok(), "{pin:?}");
    // A request through a proxy: where it says it came from.
    let proxied = super::testlive::info(None, "SYSTEM", Some("appbuilder"), &[("x-forwarded-host", "zz.example.test"), ("x-forwarded-proto", "https")]);
    assert_eq!(super::register::request_url_prefix(&proxied), "https://zz.example.test");

    remove_app(&s, &sys, id_of(&app)).await;
}
