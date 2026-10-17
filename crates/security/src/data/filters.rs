//! The filter language on the security tables: the columns `AbstractDAO.getField` finds, and
//! the filters `UserDAO` and `ClientDAO` render themselves (`filterConditionFilter`).

use serde_json::Value;

use crate::condition::{field_value, java_string, multi_values, Bind, ColType, Filter, Invalid, Op, Sql, Table};

use ColType::{Enum, Num, Str, Ts};

pub const USER: Table = Table {
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
        ("NO_OTP_RESEND_ATTEMPT", Num),
        ("NO_OTP_FAILED_ATTEMPT", Num),
        ("STATUS_CODE", Enum),
        ("LOCKED_UNTIL", Ts),
        ("LOCKED_DUE_TO", Str),
        ("CREATED_BY", Num),
        ("CREATED_AT", Ts),
        ("UPDATED_BY", Num),
        ("UPDATED_AT", Ts),
        ("TIME_ZONE", Str),
    ],
};

pub const CLIENT: Table = Table {
    name: "security_client",
    columns: &[
        ("ID", Num),
        ("CODE", Str),
        ("NAME", Str),
        ("TYPE_CODE", Str),
        ("LEVEL_TYPE", Enum),
        ("TOKEN_VALIDITY_MINUTES", Num),
        ("LOCALE_CODE", Str),
        ("STATUS_CODE", Enum),
        ("BUSINESS_TYPE", Str),
        ("CREATED_BY", Num),
        ("CREATED_AT", Ts),
        ("UPDATED_BY", Num),
        ("UPDATED_AT", Ts),
        ("BUSINESS_SIZE", Str),
        ("INDUSTRY", Str),
        ("BILLING_TIMEZONE", Str),
        ("TIME_ZONE", Str),
        ("WEBSITE", Str),
        ("EMAIL_ID", Str),
        ("PHONE_NUMBER", Str),
        ("ALTERNATE_PHONE_NUMBER", Str),
        ("LINKEDIN_URL", Str),
        ("DESCRIPTION", Str),
    ],
};

pub const PROFILE: Table = Table {
    name: "security_profile",
    columns: &[
        ("ID", Num),
        ("CLIENT_ID", Num),
        ("DEFAULT_PROFILE", Num),
        ("NAME", Str),
        ("TITLE", Str),
        ("APP_ID", Num),
        ("DESCRIPTION", Str),
        ("ROOT_PROFILE_ID", Num),
        ("ARRANGEMENT", Str),
        ("CREATED_BY", Num),
        ("CREATED_AT", Ts),
        ("UPDATED_BY", Num),
        ("UPDATED_AT", Ts),
    ],
};

/// `buildUserFieldCondition` / `buildProfileFieldCondition`: a filter on another table's
/// column, without `valueField` and `fieldExpr`. `None` is `noCondition()`.
fn other_table_condition(col: &str, t: ColType, f: &Filter) -> Result<Option<Sql>, Invalid> {
    let value = |v: &Option<Value>| -> Result<Bind, Invalid> {
        match v {
            None => Ok(Bind::Null),
            Some(v) => field_value(t, v),
        }
    };
    let compare = |sym: &str| -> Result<Option<Sql>, Invalid> {
        let mut s = Sql::text(format!("{col} {sym} "));
        s.push_bind(value(&f.value)?);
        Ok(Some(s))
    };
    let java_value = || f.value.as_ref().map(java_string).ok_or_else(|| Invalid("null value".into()));
    match f.op {
        Op::Equals => compare("="),
        Op::LessThan => compare("<"),
        Op::GreaterThan => compare(">"),
        Op::LessThanEqual => compare("<="),
        Op::GreaterThanEqual => compare(">="),
        Op::In => {
            let values = multi_values(t, f)?;
            if values.is_empty() {
                return Ok(Some(Sql::text("1 = 0")));
            }
            let mut s = Sql::text(format!("{col} IN ("));
            for (i, b) in values.into_iter().enumerate() {
                if i > 0 {
                    s.push_text(", ");
                }
                s.push_bind(b);
            }
            s.push_text(")");
            Ok(Some(s))
        }
        Op::Like => {
            let mut s = Sql::text(format!("{col} LIKE "));
            s.push_bind(Bind::Str(java_value()?));
            Ok(Some(s))
        }
        Op::StringLooseEqual => {
            let v = f.value.as_ref().map(java_string).unwrap_or_else(|| "null".into());
            let mut s = Sql::text(format!("{col} LIKE "));
            s.push_bind(Bind::Str(format!("%{v}%")));
            Ok(Some(s))
        }
        Op::IsTrue => Ok(Some(Sql::text(format!("{col} = 1")))),
        Op::IsFalse => Ok(Some(Sql::text(format!("{col} = 0")))),
        Op::IsNull => Ok(Some(Sql::text(format!("{col} IS NULL")))),
        Op::Between => {
            let mut s = Sql::text(format!("{col} BETWEEN "));
            s.push_bind(value(&f.value)?);
            s.push_text(" AND ");
            s.push_bind(value(&f.to_value)?);
            Ok(Some(s))
        }
        Op::Match | Op::MatchAll | Op::TextSearch => Ok(None),
    }
}

/// `EQUALS` on one value or `IN` on several, for the `appId` / `appCode` shortcuts.
fn id_or_code_condition(col: &str, t: ColType, f: &Filter) -> Result<Sql, Invalid> {
    if f.op == Op::Equals {
        let mut s = Sql::text(format!("{col} = "));
        match &f.value {
            None => return Ok(Sql::text(format!("{col} IS NULL"))),
            Some(v) if t == Str => s.push_bind(Bind::Str(java_string(v))),
            Some(v) => s.push_bind(field_value(t, v)?),
        }
        return Ok(s);
    }
    let values = multi_values(t, f)?;
    if values.is_empty() {
        return Ok(Sql::text("1 = 0"));
    }
    let mut s = Sql::text(format!("{col} IN ("));
    for (i, b) in values.into_iter().enumerate() {
        if i > 0 {
            s.push_text(", ");
        }
        s.push_bind(b);
    }
    s.push_text(")");
    Ok(s)
}

/// `Condition.not()` applied inside the shortcut, where Java negates it (the outer filter
/// negates the whole result again: kept).
fn maybe_not(s: Sql, negate: bool) -> Sql {
    crate::condition::negated(s, negate)
}

fn exists(from: &str, conditions: Vec<Sql>) -> Sql {
    let mut s = Sql::text(format!("EXISTS (SELECT 1 FROM {from} WHERE "));
    for (i, c) in conditions.into_iter().enumerate() {
        if i > 0 {
            s.push_text(" AND ");
        }
        s.append(c);
    }
    s.push_text(")");
    s
}

/// `UserDAO.filterConditionFilter`.
pub fn user_hook(f: &Filter, _: &Table) -> Option<Result<Option<Sql>, Invalid>> {
    if f.field_expr.as_ref().is_some_and(|e| e.is_valid()) {
        return None;
    }
    let field = f.field.as_deref()?;
    let profile_user = "security_profile_user JOIN security_profile ON security_profile_user.PROFILE_ID = security_profile.ID";
    let own = || Sql::text("security_profile_user.USER_ID = security_user.ID");
    if let Some(name) = field.strip_prefix("profile.") {
        let Some((col, t)) = PROFILE.column(name) else { return Some(Ok(None)) };
        return Some(other_table_condition(&PROFILE.qualified(col), t, f).map(|c| {
            let mut conds = vec![own()];
            conds.extend(c);
            Some(exists(profile_user, conds))
        }));
    }
    if field != "appId" && field != "appCode" {
        return None;
    }
    if f.op != Op::Equals && f.op != Op::In {
        return Some(Ok(Some(Sql::text("1 = 1"))));
    }
    let r = if field == "appId" {
        id_or_code_condition("security_profile.APP_ID", Num, f).map(|c| exists(profile_user, vec![own(), maybe_not(c, f.negate)]))
    } else {
        let from = format!("{profile_user} JOIN security_app ON security_app.ID = security_profile.APP_ID");
        id_or_code_condition("security_app.APP_CODE", Str, f).map(|c| exists(&from, vec![own(), maybe_not(c, f.negate)]))
    };
    Some(r.map(Some))
}

/// `ClientDAO.filterConditionFilter`.
pub fn client_hook(f: &Filter, _: &Table) -> Option<Result<Option<Sql>, Invalid>> {
    let field = f.field.as_deref()?;
    if let Some(name) = field.strip_prefix("user.") {
        let Some((col, t)) = USER.column(name) else { return Some(Ok(None)) };
        return Some(other_table_condition(&USER.qualified(col), t, f).map(|c| {
            let mut s = Sql::text("security_client.ID IN (SELECT security_user.CLIENT_ID FROM security_user");
            if let Some(c) = c {
                s.push_text(" WHERE ");
                s.append(c);
            }
            s.push_text(")");
            Some(s)
        }));
    }
    if field != "appId" && field != "appCode" {
        return None;
    }
    if f.op != Op::Equals && f.op != Op::In {
        return Some(Ok(Some(Sql::text("1 = 1"))));
    }
    let either = |owned: Sql, accessed: Sql, access_from: &str| {
        let mut s = Sql::text("(");
        s.append(exists("security_app", vec![Sql::text("security_app.CLIENT_ID = security_client.ID"), owned]));
        s.push_text(" OR ");
        s.append(exists(access_from, vec![Sql::text("security_app_access.CLIENT_ID = security_client.ID"), accessed]));
        s.push_text(")");
        s
    };
    let r = if field == "appId" {
        id_or_code_condition("security_app.ID", Num, f).and_then(|owned| {
            let accessed = id_or_code_condition("security_app_access.APP_ID", Num, f)?;
            Ok(either(maybe_not(owned, f.negate), maybe_not(accessed, f.negate), "security_app_access"))
        })
    } else {
        id_or_code_condition("security_app.APP_CODE", Str, f).map(|c| {
            let c = maybe_not(c, f.negate);
            either(
                c.clone(),
                c,
                "security_app_access LEFT JOIN security_app ON security_app.ID = security_app_access.APP_ID",
            )
        })
    };
    Some(r.map(Some))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::{parse, to_sql_with, Part};
    use serde_json::json;

    fn render(v: Value, table: &Table, hook: crate::condition::Hook<'_>) -> String {
        let c = parse(&v).unwrap().unwrap();
        match to_sql_with(&c, table, hook) {
            Err(e) => format!("ERR {}", e.0),
            Ok(None) => "<none>".into(),
            Ok(Some(s)) => s
                .parts
                .iter()
                .map(|p| match p {
                    Part::Text(t) => t.clone(),
                    Part::Bind(b) => format!("{{{b:?}}}"),
                })
                .collect(),
        }
    }

    fn user(v: Value) -> String {
        render(v, &USER, &user_hook)
    }

    fn client(v: Value) -> String {
        render(v, &CLIENT, &client_hook)
    }

    const PU: &str = "EXISTS (SELECT 1 FROM security_profile_user JOIN security_profile ON security_profile_user.PROFILE_ID = security_profile.ID WHERE security_profile_user.USER_ID = security_user.ID";

    #[test]
    fn user_filters() {
        assert_eq!(user(json!({"field": "clientId", "value": 1})), "security_user.CLIENT_ID = {I64(1)}");
        assert_eq!(user(json!({"field": "profile.name", "value": "Owner"})), format!("{PU} AND security_profile.NAME = {{Str(\"Owner\")}})"));
        assert_eq!(user(json!({"field": "profile.nope", "value": 1})), "<none>");
        assert_eq!(user(json!({"field": "profile.name", "operator": "MATCH", "value": 1})), format!("{PU})"));
        assert_eq!(user(json!({"field": "appId", "value": "5"})), format!("{PU} AND security_profile.APP_ID = {{I64(5)}})"));
        // Negated inside and again outside, as Java does.
        assert_eq!(
            user(json!({"field": "appId", "operator": "IN", "value": "5,6", "negate": true})),
            format!("NOT ({PU} AND NOT (security_profile.APP_ID IN ({{I64(5)}}, {{I64(6)}}))))")
        );
        assert!(user(json!({"field": "appCode", "value": "crm"})).contains("JOIN security_app ON security_app.ID = security_profile.APP_ID WHERE security_profile_user.USER_ID = security_user.ID AND security_app.APP_CODE = {Str(\"crm\")})"));
        assert_eq!(user(json!({"field": "appCode", "operator": "LIKE", "value": "c%"})), "1 = 1");
        assert_eq!(user(json!({"fieldExpr": {"function": "UPPER", "fields": ["userName"]}, "value": "A"})), "UPPER(CAST(security_user.USER_NAME AS CHAR)) = {Str(\"A\")}");
        assert_eq!(user(json!({"field": "appId", "value": null})), format!("{PU} AND security_profile.APP_ID IS NULL)"));
        assert_eq!(user(json!({"field": "appId", "operator": "IN"})), format!("{PU} AND 1 = 0)"));
    }

    #[test]
    fn every_operator_on_another_table() {
        let cases = [
            (json!({"operator": "LESS_THAN", "value": 3}), "security_profile.ID < {I64(3)}"),
            (json!({"operator": "GREATER_THAN", "value": 3}), "security_profile.ID > {I64(3)}"),
            (json!({"operator": "LESS_THAN_EQUAL", "value": 3}), "security_profile.ID <= {I64(3)}"),
            (json!({"operator": "GREATER_THAN_EQUAL", "value": 3}), "security_profile.ID >= {I64(3)}"),
            (json!({"operator": "IN", "value": "1,2"}), "security_profile.ID IN ({I64(1)}, {I64(2)})"),
            (json!({"operator": "IN"}), "1 = 0"),
            (json!({"operator": "LIKE", "value": 1}), "security_profile.ID LIKE {Str(\"1\")}"),
            (json!({"operator": "STRING_LOOSE_EQUAL", "value": 1}), "security_profile.ID LIKE {Str(\"%1%\")}"),
            (json!({"operator": "IS_TRUE"}), "security_profile.ID = 1"),
            (json!({"operator": "IS_FALSE"}), "security_profile.ID = 0"),
            (json!({"operator": "IS_NULL"}), "security_profile.ID IS NULL"),
            (json!({"operator": "BETWEEN", "value": 1, "toValue": 4}), "security_profile.ID BETWEEN {I64(1)} AND {I64(4)}"),
            (json!({"operator": "EQUALS"}), "security_profile.ID = {Null}"),
        ];
        for (mut v, expected) in cases {
            v["field"] = json!("profile.id");
            assert_eq!(user(v), format!("{PU} AND {expected})"));
        }
        assert_eq!(user(json!({"field": "profile.id", "operator": "LIKE"})), "ERR null value");
        assert_eq!(user(json!({"field": "profile.id", "value": "x"})), "ERR For input string: \"x\"");
    }

    #[test]
    fn client_filters() {
        assert_eq!(
            client(json!({"field": "user.emailId", "value": "a@b"})),
            "security_client.ID IN (SELECT security_user.CLIENT_ID FROM security_user WHERE security_user.EMAIL_ID = {Str(\"a@b\")})"
        );
        assert_eq!(client(json!({"field": "user.statusCode", "operator": "MATCH", "value": 1})), "security_client.ID IN (SELECT security_user.CLIENT_ID FROM security_user)");
        assert_eq!(client(json!({"field": "user.nope", "value": 1})), "<none>");
        let by_id = client(json!({"field": "appId", "value": 2}));
        assert_eq!(
            by_id,
            "(EXISTS (SELECT 1 FROM security_app WHERE security_app.CLIENT_ID = security_client.ID AND security_app.ID = {I64(2)}) OR EXISTS (SELECT 1 FROM security_app_access WHERE security_app_access.CLIENT_ID = security_client.ID AND security_app_access.APP_ID = {I64(2)}))"
        );
        let by_code = client(json!({"field": "appCode", "operator": "IN", "value": "a,b", "negate": true}));
        assert!(by_code.starts_with("NOT ((EXISTS (SELECT 1 FROM security_app WHERE security_app.CLIENT_ID = security_client.ID AND NOT (security_app.APP_CODE IN"), "{by_code}");
        assert!(by_code.contains("LEFT JOIN security_app ON security_app.ID = security_app_access.APP_ID"));
        assert_eq!(client(json!({"field": "appId", "operator": "IS_NULL"})), "1 = 1");
        assert_eq!(client(json!({"field": "code", "value": "SYSTEM"})), "security_client.CODE = {Str(\"SYSTEM\")}");
        assert_eq!(client(json!({"fieldExpr": {"function": "LOWER", "fields": ["code"]}, "value": "a"})), "LOWER(CAST(security_client.CODE AS CHAR)) = {Str(\"a\")}");
        assert_eq!(client(json!({"field": "appId", "value": "x"})), "ERR For input string: \"x\"");
    }
}
