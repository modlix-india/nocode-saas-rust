//! The `UserDAO` (and policy DAO) SQL the admin user routes need beyond what the internal unit
//! reads: identity checks, writes of users, passwords, role and profile assignments, the
//! reporting tree checks, members, and the password / PIN policies with their history.

use sqlx::{MySql, QueryBuilder, Row};

use super::crud::Entity;
use super::{push_in_u64, Db};
use crate::condition::{Bind, ColType, Table};
use crate::errors::AuthResult;
use crate::model::{User, PLACEHOLDER};
use crate::mysql::{user, USER_COLUMNS};

use ColType::{Num, Str, Ts};

/// `security_user` as the generic DAO writes it.
pub const USER: Entity = Entity {
    table: Table {
        name: "security_user",
        columns: &[
            ("ID", Num),
            ("DESIGNATION_ID", Num),
            ("REPORTING_TO", Num),
            ("CLIENT_ID", Num),
            ("USER_NAME", Str),
            ("EMAIL_ID", Str),
            ("PHONE_NUMBER", Str),
            ("FIRST_NAME", Str),
            ("LAST_NAME", Str),
            ("MIDDLE_NAME", Str),
            ("LOCALE_CODE", Str),
            ("PASSWORD", Str),
            ("PASSWORD_HASHED", Num),
            ("PIN", Str),
            ("PIN_HASHED", Num),
            ("ACCOUNT_NON_EXPIRED", Num),
            ("ACCOUNT_NON_LOCKED", Num),
            ("CREDENTIALS_NON_EXPIRED", Num),
            ("NO_FAILED_ATTEMPT", Num),
            ("NO_PIN_FAILED_ATTEMPT", Num),
            ("NO_OTP_FAILED_ATTEMPT", Num),
            ("STATUS_CODE", Str),
            ("LOCKED_UNTIL", Ts),
            ("LOCKED_DUE_TO", Str),
            ("CREATED_BY", Num),
            ("CREATED_AT", Ts),
            ("UPDATED_BY", Num),
            ("UPDATED_AT", Ts),
            ("TIME_ZONE", Str),
        ],
    },
    client_column: Some("CLIENT_ID"),
    not_null: &[
        "ID",
        "CLIENT_ID",
        "USER_NAME",
        "EMAIL_ID",
        "PHONE_NUMBER",
        "ACCOUNT_NON_EXPIRED",
        "ACCOUNT_NON_LOCKED",
        "CREDENTIALS_NON_EXPIRED",
        "CREATED_AT",
        "UPDATED_AT",
    ],
};

fn n(v: Option<u64>) -> Bind {
    v.map(Bind::U64).unwrap_or(Bind::Null)
}

fn s(v: &Option<String>) -> Bind {
    v.clone().map(Bind::Str).unwrap_or(Bind::Null)
}

fn i(v: Option<i64>) -> Bind {
    v.map(Bind::I64).unwrap_or(Bind::Null)
}

fn b(v: bool) -> Bind {
    Bind::I64(i64::from(v))
}

fn t(v: Option<chrono::NaiveDateTime>) -> Bind {
    v.map(|t| Bind::Ts(t.and_utc())).unwrap_or(Bind::Null)
}

/// The record jOOQ makes from a `User` (`Record.from`): every mapped column. `noOtpResendAttempts`
/// has no column of its name, so `NO_OTP_RESEND_ATTEMPT` is never written this way.
pub fn user_values(u: &User) -> Vec<(&'static str, Bind)> {
    let status = (!u.status_code.is_empty()).then(|| u.status_code.clone());
    vec![
        ("DESIGNATION_ID", n(u.designation_id)),
        ("REPORTING_TO", n(u.reporting_to)),
        ("CLIENT_ID", Bind::U64(u.client_id)),
        ("USER_NAME", s(&u.user_name)),
        ("EMAIL_ID", s(&u.email_id)),
        ("PHONE_NUMBER", s(&u.phone_number)),
        ("FIRST_NAME", s(&u.first_name)),
        ("LAST_NAME", s(&u.last_name)),
        ("MIDDLE_NAME", s(&u.middle_name)),
        ("LOCALE_CODE", s(&u.locale_code)),
        ("PASSWORD", s(&u.password)),
        ("PASSWORD_HASHED", b(u.password_hashed)),
        ("PIN", s(&u.pin)),
        ("PIN_HASHED", b(u.pin_hashed)),
        ("ACCOUNT_NON_EXPIRED", b(u.account_non_expired)),
        ("ACCOUNT_NON_LOCKED", b(u.account_non_locked)),
        ("CREDENTIALS_NON_EXPIRED", b(u.credentials_non_expired)),
        ("NO_FAILED_ATTEMPT", i(u.no_failed_attempt)),
        ("NO_PIN_FAILED_ATTEMPT", i(u.no_pin_failed_attempt)),
        ("NO_OTP_FAILED_ATTEMPT", i(u.no_otp_failed_attempt)),
        ("STATUS_CODE", s(&status)),
        ("LOCKED_UNTIL", t(u.locked_until)),
        ("LOCKED_DUE_TO", s(&u.locked_due_to)),
        ("CREATED_BY", n(u.created_by)),
        ("CREATED_AT", t(u.created_at)),
        ("UPDATED_BY", n(u.updated_by)),
        ("UPDATED_AT", t(u.updated_at)),
        ("TIME_ZONE", s(&u.time_zone)),
    ]
}

/// `security_user_invite` (`UserInviteDAO`, a client-check table).
pub const INVITE: Entity = Entity {
    table: Table {
        name: "security_user_invite",
        columns: &[
            ("ID", Num),
            ("CLIENT_ID", Num),
            ("USER_NAME", Str),
            ("EMAIL_ID", Str),
            ("PHONE_NUMBER", Str),
            ("FIRST_NAME", Str),
            ("LAST_NAME", Str),
            ("INVITE_CODE", Str),
            ("PROFILE_ID", Num),
            ("DESIGNATION_ID", Num),
            ("REPORTING_TO", Num),
            ("CREATED_BY", Num),
            ("CREATED_AT", Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
    not_null: &["ID", "CLIENT_ID", "INVITE_CODE", "CREATED_AT"],
};

/// `security_user_request` (`UserRequestDAO`, a client-check table).
pub const REQUEST: Entity = Entity {
    table: Table {
        name: "security_user_request",
        columns: &[
            ("ID", Num),
            ("REQUEST_ID", Str),
            ("CLIENT_ID", Num),
            ("USER_ID", Num),
            ("APP_ID", Num),
            ("STATUS", Str),
            ("CREATED_BY", Num),
            ("CREATED_AT", Ts),
            ("UPDATED_BY", Num),
            ("UPDATED_AT", Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
    not_null: &["ID", "REQUEST_ID", "CLIENT_ID", "USER_ID", "APP_ID", "CREATED_AT", "UPDATED_AT"],
};

/// A `security_user_invite` row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Invite {
    pub id: u64,
    pub client_id: Option<u64>,
    pub user_name: Option<String>,
    pub email_id: Option<String>,
    pub phone_number: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub invite_code: Option<String>,
    pub profile_id: Option<u64>,
    pub designation_id: Option<u64>,
    pub reporting_to: Option<u64>,
    pub created_by: Option<u64>,
    pub created_at: Option<chrono::NaiveDateTime>,
}

pub fn invite(r: &sqlx::mysql::MySqlRow) -> AuthResult<Invite> {
    Ok(Invite {
        id: r.try_get("ID")?,
        client_id: r.try_get("CLIENT_ID")?,
        user_name: r.try_get("USER_NAME")?,
        email_id: r.try_get("EMAIL_ID")?,
        phone_number: r.try_get("PHONE_NUMBER")?,
        first_name: r.try_get("FIRST_NAME")?,
        last_name: r.try_get("LAST_NAME")?,
        invite_code: r.try_get("INVITE_CODE")?,
        profile_id: r.try_get("PROFILE_ID")?,
        designation_id: r.try_get("DESIGNATION_ID")?,
        reporting_to: r.try_get("REPORTING_TO")?,
        created_by: r.try_get("CREATED_BY")?,
        created_at: crate::mysql::ts(r, "CREATED_AT")?,
    })
}

pub fn invite_values(i: &Invite) -> Vec<(&'static str, Bind)> {
    vec![
        ("CLIENT_ID", n(i.client_id)),
        ("USER_NAME", s(&i.user_name)),
        ("EMAIL_ID", s(&i.email_id)),
        ("PHONE_NUMBER", s(&i.phone_number)),
        ("FIRST_NAME", s(&i.first_name)),
        ("LAST_NAME", s(&i.last_name)),
        ("INVITE_CODE", s(&i.invite_code)),
        ("PROFILE_ID", n(i.profile_id)),
        ("DESIGNATION_ID", n(i.designation_id)),
        ("REPORTING_TO", n(i.reporting_to)),
        ("CREATED_BY", n(i.created_by)),
        ("CREATED_AT", t(i.created_at)),
    ]
}

/// A `security_user_request` row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessRequest {
    pub id: u64,
    pub request_id: Option<String>,
    pub client_id: Option<u64>,
    pub user_id: Option<u64>,
    pub app_id: Option<u64>,
    pub status: Option<String>,
    pub created_by: Option<u64>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_by: Option<u64>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

pub fn access_request(r: &sqlx::mysql::MySqlRow) -> AuthResult<AccessRequest> {
    Ok(AccessRequest {
        id: r.try_get("ID")?,
        request_id: r.try_get("REQUEST_ID")?,
        client_id: r.try_get("CLIENT_ID")?,
        user_id: r.try_get("USER_ID")?,
        app_id: r.try_get("APP_ID")?,
        status: r.try_get("STATUS")?,
        created_by: r.try_get("CREATED_BY")?,
        created_at: crate::mysql::ts(r, "CREATED_AT")?,
        updated_by: r.try_get("UPDATED_BY")?,
        updated_at: crate::mysql::ts(r, "UPDATED_AT")?,
    })
}

pub fn access_request_values(a: &AccessRequest) -> Vec<(&'static str, Bind)> {
    vec![
        ("REQUEST_ID", s(&a.request_id)),
        ("CLIENT_ID", n(a.client_id)),
        ("USER_ID", n(a.user_id)),
        ("APP_ID", n(a.app_id)),
        ("STATUS", s(&a.status)),
        ("CREATED_BY", n(a.created_by)),
        ("CREATED_AT", t(a.created_at)),
        ("UPDATED_BY", n(a.updated_by)),
        ("UPDATED_AT", t(a.updated_at)),
    ]
}

/// `getUserAvailabilityConditions`: the given identifiers (blank and `NONE` left out).
fn availability(user_name: Option<&str>, email: Option<&str>, phone: Option<&str>) -> Vec<(&'static str, String)> {
    [("USER_NAME", user_name), ("EMAIL_ID", email), ("PHONE_NUMBER", phone)]
        .into_iter()
        .filter_map(|(c, v)| v.filter(|v| !v.trim().is_empty() && *v != PLACEHOLDER).map(|v| (c, v.to_string())))
        .collect()
}

fn push_identity(qb: &mut QueryBuilder<'_, MySql>, conds: &[(&'static str, String)], joiner: &str) {
    if conds.is_empty() {
        qb.push("1 = 1");
        return;
    }
    qb.push("(");
    for (k, (c, v)) in conds.iter().enumerate() {
        if k > 0 {
            qb.push(format!(" {joiner} "));
        }
        qb.push(format!("security_user.{c} = ")).push_bind(v.clone());
    }
    qb.push(")");
}

/// A password or PIN policy row (`ClientPasswordPolicy` / `ClientPinPolicy`) as the checks use it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecretPolicy {
    pub upper: bool,
    pub lower: bool,
    pub digit: bool,
    pub special: bool,
    pub spaces_allowed: bool,
    pub regex: Option<String>,
    pub min_length: Option<i64>,
    pub max_length: Option<i64>,
    pub history: Option<i64>,
    /// The PIN's exact length.
    pub length: Option<i64>,
}

impl SecretPolicy {
    /// `ClientPasswordPolicyService.getDefaultPolicy()`.
    pub fn default_password() -> Self {
        Self {
            upper: true,
            lower: true,
            digit: true,
            special: true,
            spaces_allowed: false,
            regex: None,
            min_length: Some(12),
            max_length: Some(20),
            history: Some(5),
            length: None,
        }
    }

    /// `ClientPinPolicyService.getDefaultPolicy()`.
    pub fn default_pin() -> Self {
        Self { length: Some(4), history: Some(3), ..Default::default() }
    }
}

impl Db {
    /// `getUserClientId`.
    pub async fn user_client_id(&self, user_id: u64) -> AuthResult<Option<u64>> {
        Ok(sqlx::query_scalar("SELECT CLIENT_ID FROM security_user WHERE ID = ?").bind(user_id).fetch_optional(&self.pool).await?)
    }

    /// `UserDAO.readInternal` (and the client-check `readById`, whose joins never drop a row).
    pub async fn user_row(&self, id: u64) -> AuthResult<Option<User>> {
        let sql = format!("SELECT {USER_COLUMNS} FROM security_user u WHERE u.ID = ? LIMIT 1");
        sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?.as_ref().map(user).transpose()
    }

    /// `checkUserExists` / `checkUserExistsExclude`: a non-deleted user holding all the given
    /// identifiers in a client the managing client manages directly.
    pub async fn user_exists_under(
        &self,
        managing_client_id: u64,
        user_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        type_code: Option<&str>,
        exclude: Option<u64>,
    ) -> AuthResult<bool> {
        let mut qb: QueryBuilder<MySql> =
            QueryBuilder::new("SELECT COUNT(*) FROM security_user LEFT JOIN security_client ON security_client.ID = security_user.CLIENT_ID WHERE ");
        if let Some(t) = type_code {
            qb.push("security_client.TYPE_CODE IN (").push_bind(t.to_string()).push(") AND ");
        }
        if let Some(x) = exclude {
            qb.push("security_user.ID <> ").push_bind(x).push(" AND ");
        }
        qb.push("security_user.CLIENT_ID IN (SELECT security_client_hierarchy.CLIENT_ID FROM security_client_hierarchy WHERE security_client_hierarchy.MANAGE_CLIENT_LEVEL_0 = ")
            .push_bind(managing_client_id)
            .push(") AND ");
        push_identity(&mut qb, &availability(user_name, email, phone), "AND");
        qb.push(" AND security_user.STATUS_CODE <> 'DELETED'");
        let n: i64 = qb.build().fetch_one(&self.pool).await?.try_get(0)?;
        Ok(n > 0)
    }

    /// `getUserIdsExisting`: the ids `checkUserExists` would count (at most 25).
    pub async fn user_ids_existing_under(
        &self,
        managing_client_id: u64,
        user_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        type_code: Option<&str>,
    ) -> AuthResult<Vec<u64>> {
        let conds = availability(user_name, email, phone);
        if conds.is_empty() {
            return Ok(vec![]);
        }
        let mut qb: QueryBuilder<MySql> =
            QueryBuilder::new("SELECT security_user.ID FROM security_user LEFT JOIN security_client ON security_client.ID = security_user.CLIENT_ID WHERE ");
        if let Some(t) = type_code {
            qb.push("security_client.TYPE_CODE IN (").push_bind(t.to_string()).push(") AND ");
        }
        qb.push("security_user.CLIENT_ID IN (SELECT security_client_hierarchy.CLIENT_ID FROM security_client_hierarchy WHERE security_client_hierarchy.MANAGE_CLIENT_LEVEL_0 = ")
            .push_bind(managing_client_id)
            .push(") AND ");
        push_identity(&mut qb, &conds, "AND");
        qb.push(" AND security_user.STATUS_CODE <> 'DELETED' LIMIT 25");
        let mut ids: Vec<u64> = qb.build().fetch_all(&self.pool).await?.iter().map(|r| r.try_get::<u64, _>(0)).collect::<Result<_, _>>()?;
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// `getUsersWithAnyIdentity`: the client's own non-deleted users holding any of them.
    pub async fn users_with_any_identity(
        &self,
        client_id: u64,
        user_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        exclude: Option<u64>,
    ) -> AuthResult<Vec<User>> {
        let conds = availability(user_name, email, phone);
        if conds.is_empty() {
            return Ok(vec![]);
        }
        let cols = USER_COLUMNS.replace("u.", "security_user.");
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(format!("SELECT {cols} FROM security_user WHERE security_user.CLIENT_ID = "));
        qb.push_bind(client_id).push(" AND ");
        push_identity(&mut qb, &conds, "OR");
        qb.push(" AND security_user.STATUS_CODE <> 'DELETED'");
        if let Some(x) = exclude {
            qb.push(" AND security_user.ID <> ").push_bind(x);
        }
        qb.push(" LIMIT 25");
        qb.build().fetch_all(&self.pool).await?.iter().map(user).collect()
    }

    /// `identityExistsInClientFamily` (QA-0445): a user that is not DELETED, in `root` or in any
    /// client it manages at any level, holding this email or this phone.
    pub async fn identity_exists_in_client_family(&self, root: Option<u64>, email: Option<&str>, phone: Option<&str>) -> AuthResult<bool> {
        let Some(root) = root else { return Ok(false) };
        let conds = availability(None, email, phone);
        if conds.is_empty() {
            return Ok(false);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT COUNT(*) FROM security_user WHERE (security_user.CLIENT_ID = ");
        qb.push_bind(root).push(" OR security_user.CLIENT_ID IN (SELECT CLIENT_ID FROM security_client_hierarchy WHERE ");
        for (k, level) in ["MANAGE_CLIENT_LEVEL_0", "MANAGE_CLIENT_LEVEL_1", "MANAGE_CLIENT_LEVEL_2", "MANAGE_CLIENT_LEVEL_3"].iter().enumerate() {
            if k > 0 {
                qb.push(" OR ");
            }
            qb.push(format!("{level} = ")).push_bind(root);
        }
        qb.push(")) AND ");
        push_identity(&mut qb, &conds, "OR");
        qb.push(" AND security_user.STATUS_CODE <> 'DELETED'");
        let n: i64 = qb.build_query_scalar().fetch_one(&self.pool).await?;
        Ok(n > 0)
    }

    /// `checkUserExistsUnderManagingClient`: any of the identifiers, in the clients below the
    /// parent (its children, and their children when asked).
    #[allow(clippy::too_many_arguments)]
    pub async fn user_exists_below(
        &self,
        parent: u64,
        direct: bool,
        grand: bool,
        user_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        exclude: Option<u64>,
    ) -> AuthResult<bool> {
        let conds = availability(user_name, email, phone);
        if conds.is_empty() || (!direct && !grand) {
            return Ok(false);
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT COUNT(*) FROM security_user WHERE security_user.CLIENT_ID IN (SELECT security_client_hierarchy.CLIENT_ID FROM security_client_hierarchy WHERE ",
        );
        let mut levels = Vec::new();
        if direct {
            levels.push("security_client_hierarchy.MANAGE_CLIENT_LEVEL_0");
        }
        if grand {
            levels.push("security_client_hierarchy.MANAGE_CLIENT_LEVEL_1");
        }
        for (k, l) in levels.iter().enumerate() {
            if k > 0 {
                qb.push(" OR ");
            }
            qb.push(format!("{l} = ")).push_bind(parent);
        }
        qb.push(") AND ");
        push_identity(&mut qb, &conds, "OR");
        qb.push(" AND security_user.STATUS_CODE <> 'DELETED'");
        if let Some(x) = exclude {
            qb.push(" AND security_user.ID <> ").push_bind(x);
        }
        let n: i64 = qb.build().fetch_one(&self.pool).await?.try_get(0)?;
        Ok(n > 0)
    }

    /// `UserDAO.setPassword` / `setPin`: the hash recorded in the history, then set on the user.
    pub async fn set_secret(&self, user_id: u64, current_user_id: u64, hash: &str, pin: bool) -> AuthResult<u64> {
        let (history, col, flag, value) = if pin {
            ("security_past_pins (USER_ID, PIN, PIN_HASHED, CREATED_BY)", "PIN", "PIN_HASHED", hash)
        } else {
            ("security_past_passwords (USER_ID, PASSWORD, PASSWORD_HASHED, CREATED_BY)", "PASSWORD", "PASSWORD_HASHED", hash)
        };
        sqlx::query(&format!("INSERT INTO {history} VALUES (?, ?, 1, ?)"))
            .bind(user_id)
            .bind(value)
            .bind(current_user_id)
            .execute(&self.pool)
            .await?;
        let r = sqlx::query(&format!("UPDATE security_user SET {col} = ?, {flag} = 1, UPDATED_BY = ? WHERE ID = ?"))
            .bind(value)
            .bind(current_user_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// The latest stored passwords (or PINs) of the user, newest first: (secret, hashed).
    pub async fn past_secrets(&self, user_id: u64, limit: Option<i64>, pin: bool) -> AuthResult<Vec<(String, bool)>> {
        let (table, col, flag) =
            if pin { ("security_past_pins", "PIN", "PIN_HASHED") } else { ("security_past_passwords", "PASSWORD", "PASSWORD_HASHED") };
        let mut sql = format!("SELECT {col}, {flag} FROM {table} WHERE USER_ID = ? ORDER BY CREATED_AT DESC");
        if let Some(l) = limit {
            sql.push_str(&format!(" LIMIT {}", l.max(0)));
        }
        let rows = sqlx::query(&sql).bind(user_id).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| Ok((r.try_get::<Option<String>, _>(0)?.unwrap_or_default(), r.try_get::<Option<i8>, _>(1)?.unwrap_or(0) != 0)))
            .collect()
    }

    /// The client's own password (or PIN) policy for the app.
    pub async fn secret_policy(&self, client_id: u64, app_id: u64, pin: bool) -> AuthResult<Option<SecretPolicy>> {
        if pin {
            let row = sqlx::query("SELECT LENGTH, PIN_HISTORY_COUNT FROM security_client_pin_policy WHERE CLIENT_ID = ? AND APP_ID = ? LIMIT 1")
                .bind(client_id)
                .bind(app_id)
                .fetch_optional(&self.pool)
                .await?;
            return row
                .map(|r| {
                    Ok(SecretPolicy {
                        length: Some(i64::from(r.try_get::<u16, _>(0)?)),
                        history: Some(i64::from(r.try_get::<u16, _>(1)?)),
                        ..Default::default()
                    })
                })
                .transpose();
        }
        let row = sqlx::query(
            "SELECT ATLEAST_ONE_UPPERCASE, ATLEAST_ONE_LOWERCASE, ATLEAST_ONE_DIGIT, ATLEAST_ONE_SPECIAL_CHAR, SPACES_ALLOWED, REGEX, \
             PASS_MIN_LENGTH, PASS_MAX_LENGTH, PASS_HISTORY_COUNT FROM security_client_password_policy WHERE CLIENT_ID = ? AND APP_ID = ? LIMIT 1",
        )
        .bind(client_id)
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            let flag = |k: usize| -> AuthResult<bool> { Ok(r.try_get::<i8, _>(k)? != 0) };
            let small = |k: usize| -> AuthResult<Option<i64>> { Ok(r.try_get::<Option<u16>, _>(k)?.map(i64::from)) };
            Ok(SecretPolicy {
                upper: flag(0)?,
                lower: flag(1)?,
                digit: flag(2)?,
                special: flag(3)?,
                spaces_allowed: flag(4)?,
                regex: r.try_get(5)?,
                min_length: small(6)?,
                max_length: small(7)?,
                history: small(8)?,
                length: None,
            })
        })
        .transpose()
    }

    pub async fn remove_role_for_user(&self, user_id: u64, role_id: u64) -> AuthResult<u64> {
        Ok(sqlx::query("DELETE FROM security_v2_user_role WHERE USER_ID = ? AND ROLE_ID = ?")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn role_assigned_for_user(&self, user_id: u64, role_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_v2_user_role WHERE ROLE_ID = ? AND USER_ID = ?")
            .bind(role_id)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n == 1)
    }

    pub async fn add_role_to_user(&self, user_id: u64, role_id: u64) -> AuthResult<bool> {
        let r = sqlx::query("INSERT INTO security_v2_user_role (USER_ID, ROLE_ID) VALUES (?, ?)").bind(user_id).bind(role_id).execute(&self.pool).await?;
        Ok(r.rows_affected() > 0)
    }

    /// `removeProfileForUser`. `add_profile_to_user` stores the profile's ROOT, but a client
    /// that overrides a profile reads it (assignedProfiles, app profiles) under the override's
    /// id, so the id a caller sends back can be the override: the row is deleted under the root
    /// as well as the given id (QA-0599: Java deleted only the given id, nothing matched).
    pub async fn remove_profile_for_user(&self, user_id: u64, profile_id: u64) -> AuthResult<u64> {
        let root: Option<u64> =
            sqlx::query_scalar("SELECT COALESCE(ROOT_PROFILE_ID, ID) FROM security_profile WHERE ID = ? LIMIT 1").bind(profile_id).fetch_optional(&self.pool).await?;
        Ok(sqlx::query("DELETE FROM security_profile_user WHERE USER_ID = ? AND PROFILE_ID IN (?, ?)")
            .bind(user_id)
            .bind(profile_id)
            .bind(root.unwrap_or(profile_id))
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    /// `addProfileToUser`: the profile's root is what the user holds; `None` when the profile is
    /// unknown (Java's empty).
    pub async fn add_profile_to_user(&self, user_id: u64, profile_id: u64) -> AuthResult<Option<u64>> {
        let root: Option<u64> =
            sqlx::query_scalar("SELECT COALESCE(ROOT_PROFILE_ID, ID) FROM security_profile WHERE ID = ? LIMIT 1").bind(profile_id).fetch_optional(&self.pool).await?;
        let Some(root) = root else { return Ok(None) };
        let r = sqlx::query("INSERT IGNORE INTO security_profile_user (USER_ID, PROFILE_ID) VALUES (?, ?)").bind(user_id).bind(root).execute(&self.pool).await?;
        Ok(Some(u64::from(r.rows_affected() > 0)))
    }

    /// `updateUserStatusToActive`: unlocked, counters reset (a deleted user is left alone).
    pub async fn user_status_to_active(&self, user_id: u64) -> AuthResult<bool> {
        let r = sqlx::query(
            "UPDATE security_user SET STATUS_CODE = 'ACTIVE', ACCOUNT_NON_EXPIRED = 1, ACCOUNT_NON_LOCKED = 1, CREDENTIALS_NON_EXPIRED = 1, \
             NO_FAILED_ATTEMPT = 0, NO_PIN_FAILED_ATTEMPT = 0, NO_OTP_RESEND_ATTEMPT = 0, NO_OTP_FAILED_ATTEMPT = 0, LOCKED_UNTIL = NULL, \
             LOCKED_DUE_TO = NULL WHERE ID = ? AND STATUS_CODE <> 'DELETED'",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// The ids reporting directly to any of these users (in the client, when given).
    async fn reports_of(&self, managers: &[u64], client_id: Option<u64>, skip_deleted: bool) -> AuthResult<Vec<u64>> {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT ID FROM security_user WHERE ");
        push_in_u64(&mut qb, "REPORTING_TO", managers);
        if let Some(c) = client_id {
            qb.push(" AND CLIENT_ID = ").push_bind(c);
        }
        if skip_deleted {
            qb.push(" AND STATUS_CODE <> 'DELETED'");
        }
        qb.build().fetch_all(&self.pool).await?.iter().map(|r| Ok(r.try_get::<u64, _>(0)?)).collect()
    }

    /// `UserDAO.canReportTo`: the manager is another user of the client and not below the user.
    pub async fn can_report_to(&self, client_id: u64, reporting_to: Option<u64>, user_id: Option<u64>) -> AuthResult<bool> {
        let Some(manager) = reporting_to else { return Ok(false) };
        if Some(manager) == user_id {
            return Ok(false);
        }
        let Some(user_id) = user_id else { return Ok(true) };
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_user WHERE ID = ? AND CLIENT_ID = ?")
            .bind(manager)
            .bind(client_id)
            .fetch_one(&self.pool)
            .await?;
        if n != 1 {
            return Ok(false);
        }
        // `expand` over the levels below the user (the user's own level included); a cycle in the
        // data would loop in Java as well, so the walk stops after a generous depth.
        let mut level = vec![user_id];
        for _ in 0..256 {
            if level.contains(&manager) {
                return Ok(false);
            }
            level = self.reports_of(&level, None, false).await?;
            if level.is_empty() {
                return Ok(true);
            }
        }
        Ok(true)
    }

    /// `isUserInSubOrg`: the target reports, at any depth, to the manager (within the client).
    pub async fn is_user_in_sub_org(&self, client_id: u64, manager: u64, target: u64) -> AuthResult<bool> {
        if manager == target {
            return Ok(true);
        }
        let mut level = vec![manager];
        for _ in 0..256 {
            if level.contains(&target) {
                return Ok(true);
            }
            level = self.reports_of(&level, Some(client_id), true).await?;
            if level.is_empty() {
                return Ok(false);
            }
        }
        Ok(false)
    }

    /// `getMembers`: (id, first name, last name, user name, status) of the client's members.
    #[allow(clippy::type_complexity)]
    pub async fn members(
        &self,
        client_id: u64,
        include_inactive: bool,
        search: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> AuthResult<Vec<(u64, Option<String>, Option<String>, Option<String>, Option<String>)>> {
        let mut qb: QueryBuilder<MySql> =
            QueryBuilder::new("SELECT ID, FIRST_NAME, LAST_NAME, USER_NAME, STATUS_CODE FROM security_user WHERE CLIENT_ID = ");
        qb.push_bind(client_id);
        qb.push(if include_inactive { " AND STATUS_CODE <> 'DELETED'" } else { " AND STATUS_CODE = 'ACTIVE'" });
        if let Some(s) = search.map(str::trim).filter(|s| !s.is_empty()) {
            // jOOQ's containsIgnoreCase: LOWER(col) LIKE LOWER('%s%') with the wildcards escaped.
            let pattern = format!("%{}%", s.replace('!', "!!").replace('%', "!%").replace('_', "!_"));
            qb.push(" AND (LOWER(FIRST_NAME) LIKE LOWER(").push_bind(pattern.clone()).push(") ESCAPE '!' OR LOWER(LAST_NAME) LIKE LOWER(");
            qb.push_bind(pattern.clone()).push(") ESCAPE '!' OR (LOWER(USER_NAME) LIKE LOWER(").push_bind(pattern);
            qb.push(") ESCAPE '!' AND USER_NAME <> 'NONE' AND USER_NAME NOT LIKE '%@%'))");
        }
        qb.push(" ORDER BY FIRST_NAME ASC, LAST_NAME ASC, ID ASC LIMIT ").push_bind(limit).push(" OFFSET ").push_bind(offset);
        let rows = qb.build().fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?, r.try_get(3)?, r.try_get::<Option<String>, _>(4)?)))
            .collect()
    }

    /// `ClientManagerDAO.bumpClientUpdatedAt`.
    async fn bump_clients(&self, client_ids: &[u64]) -> AuthResult<()> {
        if client_ids.is_empty() {
            return Ok(());
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("UPDATE security_client SET UPDATED_AT = CURRENT_TIMESTAMP WHERE ");
        push_in_u64(&mut qb, "ID", client_ids);
        qb.build().execute(&self.pool).await?;
        Ok(())
    }

    /// `createIfNotExists`.
    pub async fn add_client_manager(&self, client_id: u64, manager_id: u64, created_by: u64) -> AuthResult<u64> {
        let n = sqlx::query("INSERT IGNORE INTO security_client_manager (CLIENT_ID, MANAGER_ID, CREATED_BY) VALUES (?, ?, ?)")
            .bind(client_id)
            .bind(manager_id)
            .bind(created_by)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if n != 0 {
            self.bump_clients(&[client_id]).await?;
        }
        Ok(n)
    }

    /// `deleteByClientIdAndManagerId`.
    pub async fn remove_client_manager(&self, client_id: u64, manager_id: u64) -> AuthResult<u64> {
        let n = sqlx::query("DELETE FROM security_client_manager WHERE CLIENT_ID = ? AND MANAGER_ID = ?")
            .bind(client_id)
            .bind(manager_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if n != 0 {
            self.bump_clients(&[client_id]).await?;
        }
        Ok(n)
    }

    /// `getClientsOfManager`: a page of the manager's client ids and their count.
    pub async fn manager_client_page(&self, manager_id: u64, size: i64, offset: i64) -> AuthResult<(Vec<u64>, i64)> {
        let ids: Vec<u64> = sqlx::query_scalar("SELECT CLIENT_ID FROM security_client_manager WHERE MANAGER_ID = ? LIMIT ? OFFSET ?")
            .bind(manager_id)
            .bind(size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_client_manager WHERE MANAGER_ID = ?").bind(manager_id).fetch_one(&self.pool).await?;
        Ok((ids, total))
    }

    /// `migrateManagerAssignments`: the rows inserted (and deleted, when the old manager goes).
    pub async fn migrate_client_managers(&self, from: u64, to: u64, created_by: u64, remove: bool) -> AuthResult<u64> {
        let affected: Vec<u64> =
            sqlx::query_scalar("SELECT DISTINCT CLIENT_ID FROM security_client_manager WHERE MANAGER_ID = ?").bind(from).fetch_all(&self.pool).await?;
        let inserted = sqlx::query(
            "INSERT IGNORE INTO security_client_manager (CLIENT_ID, MANAGER_ID, CREATED_BY) \
             SELECT CLIENT_ID, ?, ? FROM security_client_manager WHERE MANAGER_ID = ?",
        )
        .bind(to)
        .bind(created_by)
        .bind(from)
        .execute(&self.pool)
        .await?
        .rows_affected();
        let deleted = if remove {
            sqlx::query("DELETE FROM security_client_manager WHERE MANAGER_ID = ?").bind(from).execute(&self.pool).await?.rows_affected()
        } else {
            0
        };
        self.bump_clients(&affected).await?;
        Ok(inserted + deleted)
    }

    /// `syncManagers`' writes: every manager of the client replaced.
    pub async fn replace_client_managers(&self, client_id: u64, managers: &[u64], created_by: u64) -> AuthResult<()> {
        let deleted = sqlx::query("DELETE FROM security_client_manager WHERE CLIENT_ID = ?").bind(client_id).execute(&self.pool).await?.rows_affected();
        if deleted != 0 {
            self.bump_clients(&[client_id]).await?;
        }
        if managers.is_empty() {
            return Ok(());
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("INSERT IGNORE INTO security_client_manager (CLIENT_ID, MANAGER_ID, CREATED_BY) ");
        qb.push_values(managers.iter(), |mut b, m| {
            b.push_bind(client_id).push_bind(*m).push_bind(created_by);
        });
        if qb.build().execute(&self.pool).await?.rows_affected() != 0 {
            self.bump_clients(&[client_id]).await?;
        }
        Ok(())
    }

    /// `getUserInvitation`.
    pub async fn invite_by_code(&self, code: &str) -> AuthResult<Option<Invite>> {
        let row = sqlx::query("SELECT * FROM security_user_invite WHERE INVITE_CODE = ? LIMIT 1").bind(code).fetch_optional(&self.pool).await?;
        row.as_ref().map(invite).transpose()
    }

    /// An invite by id, no joins.
    pub async fn invite_row(&self, id: u64) -> AuthResult<Option<Invite>> {
        let row = sqlx::query("SELECT * FROM security_user_invite WHERE ID = ? LIMIT 1").bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(invite).transpose()
    }

    /// `deleteUserInvitation`: true when exactly one row went.
    pub async fn delete_invite(&self, code: &str) -> AuthResult<bool> {
        Ok(sqlx::query("DELETE FROM security_user_invite WHERE INVITE_CODE = ?").bind(code).execute(&self.pool).await?.rows_affected() == 1)
    }

    /// `getInviteWithAnyIdentity`: a pending invite of the client for the e-mail or phone.
    pub async fn invite_with_identity(&self, client_id: Option<u64>, email: Option<&str>, phone: Option<&str>) -> AuthResult<Option<Invite>> {
        let conds: Vec<(&str, String)> = availability(None, email, phone);
        let Some(client_id) = client_id.filter(|_| !conds.is_empty()) else { return Ok(None) };
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT * FROM security_user_invite WHERE CLIENT_ID = ");
        qb.push_bind(client_id).push(" AND (");
        for (k, (c, v)) in conds.iter().enumerate() {
            if k > 0 {
                qb.push(" OR ");
            }
            qb.push(format!("{c} = ")).push_bind(v.clone());
        }
        qb.push(") LIMIT 1");
        qb.build().fetch_optional(&self.pool).await?.as_ref().map(invite).transpose()
    }

    /// `profileIdsOfApp`.
    pub async fn profile_ids_of_app(&self, app_id: u64) -> AuthResult<Vec<u64>> {
        Ok(sqlx::query_scalar("SELECT ID FROM security_profile WHERE APP_ID = ?").bind(app_id).fetch_all(&self.pool).await?)
    }

    /// `readByRequestId`.
    pub async fn request_by_request_id(&self, request_id: &str) -> AuthResult<Option<AccessRequest>> {
        let row = sqlx::query("SELECT * FROM security_user_request WHERE REQUEST_ID = ?").bind(request_id).fetch_optional(&self.pool).await?;
        row.as_ref().map(access_request).transpose()
    }

    pub async fn request_row(&self, id: u64) -> AuthResult<Option<AccessRequest>> {
        let row = sqlx::query("SELECT * FROM security_user_request WHERE ID = ? LIMIT 1").bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(access_request).transpose()
    }

    /// `checkPendingRequestExists`.
    pub async fn pending_request_exists(&self, user_id: u64, app_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_user_request WHERE USER_ID = ? AND APP_ID = ? AND STATUS = 'PENDING'")
            .bind(user_id)
            .bind(app_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n > 0)
    }

    /// `userIdsMatching`: users whose name, user name, e-mail or full name contains the text.
    pub async fn user_ids_matching(&self, text: &str) -> AuthResult<Vec<u64>> {
        let like = format!("%{text}%");
        Ok(sqlx::query_scalar(
            "SELECT ID FROM security_user WHERE FIRST_NAME LIKE ? OR LAST_NAME LIKE ? OR USER_NAME LIKE ? OR EMAIL_ID LIKE ? \
             OR CONCAT(COALESCE(FIRST_NAME, ''), ' ', COALESCE(LAST_NAME, '')) LIKE ? LIMIT 500",
        )
        .bind(&like)
        .bind(&like)
        .bind(&like)
        .bind(&like)
        .bind(&like)
        .fetch_all(&self.pool)
        .await?)
    }

    /// `ProfileDAO.getAssignedProfileIds(...).hasElements()` for an app.
    pub async fn has_assigned_profile_in_app(&self, user_id: u64, app_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_profile_user LEFT JOIN security_profile ON security_profile.ID = security_profile_user.PROFILE_ID \
             WHERE security_profile_user.USER_ID = ? AND security_profile.APP_ID = ?",
        )
        .bind(user_id)
        .bind(app_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n > 0)
    }

    /// `security_designation` rows of a client, by id (`canAssignDesignation`).
    pub async fn designation_in_client(&self, client_id: u64, designation_id: u64) -> AuthResult<bool> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_designation WHERE ID = ? AND CLIENT_ID = ?")
            .bind(designation_id)
            .bind(client_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_and_defaults() {
        let a = availability(Some(" "), Some("a@b"), Some(PLACEHOLDER));
        assert_eq!(a, vec![("EMAIL_ID", "a@b".to_string())]);
        assert!(availability(None, None, None).is_empty());
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("");
        push_identity(&mut qb, &[], "OR");
        assert_eq!(qb.sql(), "1 = 1");
        assert_eq!(SecretPolicy::default_password().min_length, Some(12));
        assert_eq!(SecretPolicy::default_pin().length, Some(4));
        let u = User { client_id: 3, status_code: String::new(), ..Default::default() };
        let v = user_values(&u);
        assert!(v.iter().any(|(c, b)| *c == "STATUS_CODE" && *b == Bind::Null));
    }
}
