//! The security DTOs as the service's `ObjectMapper` writes them: Jackson's property order
//! (the base DTO's `id`, `createdAt`, `createdBy`, `updatedAt`, `updatedBy`, then the class's
//! fields in declaration order, getter-only properties last), `NON_EMPTY`.
//!
//! Java fills the optional parts (`owners`, `managingClient`, ...) into the cached objects
//! themselves, so a later read of the same cached client or user can carry them. Rust keeps the
//! cached rows untouched and adds the parts per response.

use std::sync::Arc;

use chrono::NaiveDateTime;
use serde_json::Value;

use crate::jackson::{epoch, opt, Obj};
use crate::model::{App, Client, User};

/// `User.PLACEHOLDER`: an identifier the user does not have.
pub const PLACEHOLDER: &str = "NONE";

fn not_placeholder(v: &Option<String>) -> Value {
    match v.as_deref() {
        Some(PLACEHOLDER) | None => Value::Null,
        Some(s) => Value::from(s),
    }
}

/// The user counts `ClientDAO.fillUserCounts` sets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserCounts {
    pub active: i64,
    pub inactive: i64,
    pub deleted: i64,
    pub locked: i64,
    pub password_expired: i64,
}

/// What `ClientService.fillDetails` adds to a client.
#[derive(Debug, Clone, Default)]
pub struct ClientExtras {
    pub counts: UserCounts,
    pub owners: Option<Vec<Arc<User>>>,
    pub managing_client: Option<Arc<Client>>,
    pub apps: Option<Vec<Arc<App>>>,
    pub created_by_user: Option<Arc<User>>,
    pub client_managers: Option<Vec<Arc<User>>>,
}

fn users(list: &Option<Vec<Arc<User>>>) -> Value {
    list.as_ref().map(|l| Value::Array(l.iter().map(|u| user_json(u, &UserExtras::default())).collect())).unwrap_or(Value::Null)
}

/// The `Client` DTO. `totalUsers` is a getter, so it comes after every field.
pub fn client_json(c: &Client, x: &ClientExtras) -> Value {
    let n = x.counts;
    Obj::new()
        .put("id", opt(c.id))
        .put("createdAt", epoch(c.created_at))
        .put("createdBy", opt(c.created_by))
        .put("updatedAt", epoch(c.updated_at))
        .put("updatedBy", opt(c.updated_by))
        .put("code", opt(c.code.clone()))
        .put("name", opt(c.name.clone()))
        .put("typeCode", opt(c.type_code.clone()))
        .put("tokenValidityMinutes", c.token_validity_minutes)
        .put("localeCode", opt(c.locale_code.clone()))
        .put("timeZone", opt(c.time_zone.clone()))
        .put("statusCode", opt(c.status_code.clone()))
        .put("businessType", opt(c.business_type.clone()))
        .put("businessSize", opt(c.business_size.clone()))
        .put("industry", opt(c.industry.clone()))
        .put("levelType", opt(c.level_type.clone()))
        .put("website", opt(c.website.clone()))
        .put("emailId", opt(c.email_id.clone()))
        .put("phoneNumber", opt(c.phone_number.clone()))
        .put("alternatePhoneNumber", opt(c.alternate_phone_number.clone()))
        .put("linkedinUrl", opt(c.linkedin_url.clone()))
        .put("description", opt(c.description.clone()))
        .put("activeUsers", n.active)
        .put("inactiveUsers", n.inactive)
        .put("deletedUsers", n.deleted)
        .put("lockedUsers", n.locked)
        .put("passwordExpiredUsers", n.password_expired)
        .put("owners", users(&x.owners))
        .put("managagingClient", x.managing_client.as_ref().map(|m| client_json(m, &ClientExtras::default())).unwrap_or(Value::Null))
        .put("apps", x.apps.as_ref().map(|a| Value::Array(a.iter().map(|a| a.to_json()).collect())).unwrap_or(Value::Null))
        .put("createdByUser", x.created_by_user.as_ref().map(|u| user_json(u, &UserExtras::default())).unwrap_or(Value::Null))
        .put("clientManagers", users(&x.client_managers))
        .put("totalUsers", n.active + n.inactive + n.deleted + n.locked + n.password_expired)
        .build()
}

/// A `security_designation` row.
#[derive(Debug, Clone, Default)]
pub struct Designation {
    pub id: u64,
    pub client_id: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub parent_designation_id: Option<u64>,
    pub department_id: Option<u64>,
    pub next_designation_id: Option<u64>,
    pub profile_id: Option<u64>,
    pub created_by: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Designation {
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", epoch(self.created_at))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", epoch(self.updated_at))
            .put("updatedBy", opt(self.updated_by))
            .put("clientId", opt(self.client_id))
            .put("name", opt(self.name.clone()))
            .put("description", opt(self.description.clone()))
            .put("parentDesignationId", opt(self.parent_designation_id))
            .put("departmentId", opt(self.department_id))
            .put("nextDesignationId", opt(self.next_designation_id))
            .put("profileId", opt(self.profile_id))
            .build()
    }
}

/// The parts `DesignationService.fillDetails` adds.
#[derive(Debug, Clone, Default)]
pub struct DesignationExtras {
    pub parent: Option<Arc<Designation>>,
    pub next: Option<Arc<Designation>>,
    pub department: Option<Arc<Department>>,
}

/// The `Designation` DTO with its optional parts.
pub fn designation_json(d: &Designation, x: &DesignationExtras) -> Value {
    let mut v = d.to_json();
    if let Value::Object(m) = &mut v {
        if let Some(p) = &x.parent {
            m.insert("parentDesignation".into(), p.to_json());
        }
        if let Some(n) = &x.next {
            m.insert("nextDesignation".into(), n.to_json());
        }
        if let Some(dep) = &x.department {
            m.insert("department".into(), dep.to_json(None));
        }
    }
    v
}

/// A `security_department` row.
#[derive(Debug, Clone, Default)]
pub struct Department {
    pub id: u64,
    pub client_id: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub parent_department_id: Option<u64>,
    pub created_by: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<NaiveDateTime>,
}

impl Department {
    pub fn to_json(&self, parent: Option<&Department>) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", epoch(self.created_at))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", epoch(self.updated_at))
            .put("updatedBy", opt(self.updated_by))
            .put("clientId", opt(self.client_id))
            .put("name", opt(self.name.clone()))
            .put("description", opt(self.description.clone()))
            .put("parentDepartmentId", opt(self.parent_department_id))
            .put("parentDepartment", parent.map(|p| p.to_json(None)).unwrap_or(Value::Null))
            .build()
    }
}

/// A `security_v2_role` row (`RoleV2`); `appName` (the app's code) and `subRoles` are filled
/// by the services that list roles. `authority`, `parentRoleId` and `app` are never set.
#[derive(Debug, Clone, Default)]
pub struct Role {
    pub id: u64,
    pub client_id: Option<u64>,
    pub app_id: Option<u64>,
    pub app_name: Option<String>,
    pub name: Option<String>,
    pub short_name: Option<String>,
    pub description: Option<String>,
    pub created_by: Option<u64>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<NaiveDateTime>,
    pub sub_roles: Option<Vec<Role>>,
}

impl Role {
    pub fn to_json(&self) -> Value {
        Obj::new()
            .put("id", self.id)
            .put("createdAt", epoch(self.created_at))
            .put("createdBy", opt(self.created_by))
            .put("updatedAt", epoch(self.updated_at))
            .put("updatedBy", opt(self.updated_by))
            .put("clientId", opt(self.client_id))
            .put("appId", opt(self.app_id))
            .put("appName", opt(self.app_name.clone()))
            .put("name", opt(self.name.clone()))
            .put("shortName", opt(self.short_name.clone()))
            .put("description", opt(self.description.clone()))
            .put("subRoles", self.sub_roles.as_ref().map(|l| Value::Array(l.iter().map(Role::to_json).collect())).unwrap_or(Value::Null))
            .build()
    }
}

/// What `UserService.fillDetails` adds to a user.
#[derive(Debug, Clone, Default)]
pub struct UserExtras {
    /// `ProfileService.fillUser`, already in Jackson's shape.
    pub profiles: Option<Vec<Value>>,
    pub client: Option<Arc<Client>>,
    pub managing_client: Option<Arc<Client>>,
    pub created_by_user: Option<Arc<User>>,
    pub designation: Option<Arc<Designation>>,
    pub reporting_user: Option<Arc<User>>,
}

/// The `User` DTO. `password` and `pin` (and their `*Hashed` flags) are `@JsonIgnore`;
/// `userName`, `emailId` and `phoneNumber` read `NONE` as null; `noOtpResendAttempts` matches
/// no column, so jOOQ never fills it.
pub fn user_json(u: &User, x: &UserExtras) -> Value {
    let plain = |c: &Option<Arc<Client>>| c.as_ref().map(|c| client_json(c, &ClientExtras::default())).unwrap_or(Value::Null);
    let plain_user = |u: &Option<Arc<User>>| u.as_ref().map(|u| user_json(u, &UserExtras::default())).unwrap_or(Value::Null);
    Obj::new()
        .put("id", u.id)
        .put("createdAt", epoch(u.created_at))
        .put("createdBy", opt(u.created_by))
        .put("updatedAt", epoch(u.updated_at))
        .put("updatedBy", opt(u.updated_by))
        .put("clientId", u.client_id)
        .put("userName", not_placeholder(&u.user_name))
        .put("emailId", not_placeholder(&u.email_id))
        .put("phoneNumber", not_placeholder(&u.phone_number))
        .put("firstName", opt(u.first_name.clone()))
        .put("lastName", opt(u.last_name.clone()))
        .put("middleName", opt(u.middle_name.clone()))
        .put("localeCode", opt(u.locale_code.clone()))
        .put("timeZone", opt(u.time_zone.clone()))
        .put("accountNonExpired", u.account_non_expired)
        .put("accountNonLocked", u.account_non_locked)
        .put("credentialsNonExpired", u.credentials_non_expired)
        .put("noFailedAttempt", opt(u.no_failed_attempt))
        .put("noPinFailedAttempt", opt(u.no_pin_failed_attempt))
        .put("noOtpFailedAttempt", opt(u.no_otp_failed_attempt))
        .put("statusCode", if u.status_code.is_empty() { Value::Null } else { Value::from(u.status_code.as_str()) })
        .put("lockedUntil", epoch(u.locked_until))
        .put("lockedDueTo", opt(u.locked_due_to.clone()))
        .put("designationId", opt(u.designation_id))
        .put("reportingTo", opt(u.reporting_to))
        .put("profiles", x.profiles.clone().map(Value::Array).unwrap_or(Value::Null))
        .put("client", plain(&x.client))
        .put("managingClient", plain(&x.managing_client))
        .put("createdByUser", plain_user(&x.created_by_user))
        .put("designation", x.designation.as_ref().map(|d| d.to_json()).unwrap_or(Value::Null))
        .put("reportingUser", plain_user(&x.reporting_user))
        .build()
}

/// `com.fincity.saas.commons.security.dto.App`, as `getAppExplicitInfoByCode` fills it.
/// `isTemplate` is a primitive with a Lombok `isTemplate()` getter, so Jackson names it
/// `template` and, having no field of that name, writes it last.
#[derive(Debug, Clone, Default)]
pub struct ExplicitApp {
    pub app: App,
    pub client_code: Option<String>,
    pub explicit_client_id: Option<u64>,
    pub explicit_owner_client_code: Option<String>,
}

impl ExplicitApp {
    pub fn to_json(&self) -> Value {
        let a = &self.app;
        Obj::new()
            .put("id", a.id)
            .put("clientId", a.client_id)
            .put("appName", opt(a.app_name.clone()))
            .put("appCode", a.app_code.as_str())
            .put("appType", opt(a.app_type.clone()))
            .put("appAccessType", opt(a.app_access_type.clone()))
            .put("clientCode", opt(self.client_code.clone()))
            .put("explicitClientId", opt(self.explicit_client_id))
            .put("explicitOwnerClientCode", opt(self.explicit_owner_client_code.clone()))
            .put("status", opt(a.status.clone()))
            .put("template", false)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jackson::pretty;

    fn at(epoch: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(epoch, 0).unwrap().naive_utc()
    }

    #[test]
    fn user_as_the_java_service_writes_it() {
        // GET /api/security/users/internal/142 on 2026-10-16 (timestamps from the same row).
        let u = User {
            id: 142,
            client_id: 1,
            user_name: Some("kirangrandhi".into()),
            email_id: Some("kiran@modlix.com".into()),
            phone_number: Some("NONE".into()),
            first_name: Some("Kiran".into()),
            last_name: Some("Grandhi".into()),
            locale_code: Some("en_US".into()),
            password: Some("secret".into()),
            account_non_expired: true,
            account_non_locked: true,
            credentials_non_expired: true,
            no_failed_attempt: Some(0),
            no_pin_failed_attempt: Some(0),
            no_otp_failed_attempt: Some(0),
            status_code: "ACTIVE".into(),
            created_at: Some(at(1_699_347_862)),
            updated_at: Some(at(1_791_510_921)),
            updated_by: Some(142),
            ..Default::default()
        };
        let expected = "{\n  \"id\" : 142,\n  \"createdAt\" : 1699347862,\n  \"updatedAt\" : 1791510921,\n  \"updatedBy\" : 142,\n  \"clientId\" : 1,\n  \"userName\" : \"kirangrandhi\",\n  \"emailId\" : \"kiran@modlix.com\",\n  \"firstName\" : \"Kiran\",\n  \"lastName\" : \"Grandhi\",\n  \"localeCode\" : \"en_US\",\n  \"accountNonExpired\" : true,\n  \"accountNonLocked\" : true,\n  \"credentialsNonExpired\" : true,\n  \"noFailedAttempt\" : 0,\n  \"noPinFailedAttempt\" : 0,\n  \"noOtpFailedAttempt\" : 0,\n  \"statusCode\" : \"ACTIVE\"\n}";
        assert_eq!(pretty(&user_json(&u, &UserExtras::default())), expected);
    }

    #[test]
    fn client_with_its_extras_in_jackson_order() {
        let c = Client { id: Some(1), code: Some("SYSTEM".into()), token_validity_minutes: 60, ..Default::default() };
        let owner = Arc::new(User { id: 5, client_id: 1, status_code: "ACTIVE".into(), ..Default::default() });
        let x = ClientExtras {
            counts: UserCounts { active: 2, locked: 1, ..Default::default() },
            owners: Some(vec![owner.clone()]),
            managing_client: Some(Arc::new(Client { id: Some(9), ..Default::default() })),
            apps: Some(vec![Arc::new(App { id: 2, client_id: 1, app_code: "a".into(), ..Default::default() })]),
            created_by_user: Some(owner.clone()),
            client_managers: Some(vec![owner]),
        };
        let v = client_json(&c, &x);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "id", "code", "tokenValidityMinutes", "activeUsers", "inactiveUsers", "deletedUsers", "lockedUsers",
                "passwordExpiredUsers", "owners", "managagingClient", "apps", "createdByUser", "clientManagers", "totalUsers"
            ]
        );
        assert_eq!(v["totalUsers"], 3);
        assert_eq!(v["managagingClient"]["totalUsers"], 0);
    }

    #[test]
    fn user_extras_and_designation() {
        let u = User { id: 7, client_id: 2, designation_id: Some(3), reporting_to: Some(5), ..Default::default() };
        let d = Designation { id: 3, client_id: Some(2), name: Some("Lead".into()), ..Default::default() };
        let x = UserExtras {
            profiles: Some(vec![serde_json::json!({"id": 1})]),
            client: Some(Arc::new(Client { id: Some(2), ..Default::default() })),
            managing_client: Some(Arc::new(Client { id: Some(1), ..Default::default() })),
            created_by_user: Some(Arc::new(User { id: 1, ..Default::default() })),
            designation: Some(Arc::new(d)),
            reporting_user: Some(Arc::new(User { id: 5, ..Default::default() })),
        };
        let v = user_json(&u, &x);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "id", "clientId", "accountNonExpired", "accountNonLocked", "credentialsNonExpired", "designationId",
                "reportingTo", "profiles", "client", "managingClient", "createdByUser", "designation", "reportingUser"
            ]
        );
        assert_eq!(v["designation"]["name"], "Lead");
    }

    #[test]
    fn explicit_app_as_observed() {
        // GET /api/security/applications/internal/explicitInfo/appbuilder on 2026-10-16.
        let a = ExplicitApp {
            app: App {
                id: 2,
                client_id: 1,
                app_name: Some("App Builder".into()),
                app_code: "appbuilder".into(),
                app_type: Some("APP".into()),
                app_access_type: Some("OWN".into()),
                status: Some("ACTIVE".into()),
                ..Default::default()
            },
            client_code: Some("SYSTEM".into()),
            ..Default::default()
        };
        assert_eq!(
            pretty(&a.to_json()),
            "{\n  \"id\" : 2,\n  \"clientId\" : 1,\n  \"appName\" : \"App Builder\",\n  \"appCode\" : \"appbuilder\",\n  \"appType\" : \"APP\",\n  \"appAccessType\" : \"OWN\",\n  \"clientCode\" : \"SYSTEM\",\n  \"status\" : \"ACTIVE\",\n  \"template\" : false\n}"
        );
    }
}
