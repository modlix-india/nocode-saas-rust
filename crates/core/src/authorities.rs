//! `AuthoritiesTokenExtractor` and `SecurityContextUtil.hasAuthority(expression, authorities)`.
//!
//! An execution authorization (a function's `executeAuth`) and `HasAuthority`'s argument are
//! KIRun expressions over `Authorities.`: `Authorities.ROLE_Owner`,
//! `Authorities.A or Authorities.B`. Each `Authorities.<x>` token is true exactly when the
//! caller holds the authority spelled by the whole token.

use std::sync::Arc;

use kirun::runtime::expression::tokenextractor::token_value_extractor::{TokenValueExtractor, ValuesMap};
use kirun::runtime::expression::ExpressionEvaluator;
use kirun::{KIRunError, Map, Value};

pub const PREFIX: &str = "Authorities.";

pub struct AuthoritiesTokenExtractor {
    authorities: Vec<String>,
}

impl AuthoritiesTokenExtractor {
    pub fn new(authorities: Vec<String>) -> Self {
        Self { authorities }
    }

    pub fn values_map(self) -> ValuesMap {
        let mut m: ValuesMap = Map::new();
        m.insert(PREFIX.to_string(), Arc::new(self) as Arc<dyn TokenValueExtractor>);
        m
    }
}

impl TokenValueExtractor for AuthoritiesTokenExtractor {
    fn get_prefix(&self) -> &str {
        PREFIX
    }

    fn get_store(&self) -> Value {
        Value::Array(self.authorities.iter().cloned().map(Value::String).collect())
    }

    fn get_value_internal(&self, token: &str, _values_map: Option<&ValuesMap>) -> kirun::Result<Value> {
        Ok(Value::Bool(self.authorities.iter().any(|a| a == token)))
    }
}

/// `SecurityContextUtil.hasAuthority(authority, authorities)`: a blank expression allows,
/// no authorities refuse, otherwise the expression must evaluate to `true`. A result that is
/// not a primitive fails as `getAsJsonPrimitive()` does.
/// The engines' readAuth check for a joined or sub-queried storage, with KIRun's evaluator.
/// An expression KIRun cannot evaluate refuses (Java fails the read with it).
pub struct KirunAuthorityCheck;

impl appdata::engine::AuthorityCheck for KirunAuthorityCheck {
    fn has_authority(&self, expression: Option<&str>, authorities: &[String]) -> bool {
        has_authority(expression, authorities).unwrap_or(false)
    }
}

pub fn has_authority(expression: Option<&str>, authorities: &[String]) -> Result<bool, KIRunError> {
    let Some(expression) = expression.filter(|e| !e.trim().is_empty()) else {
        return Ok(true);
    };
    if authorities.is_empty() {
        return Ok(false);
    }
    let values = AuthoritiesTokenExtractor::new(authorities.to_vec()).values_map();
    match ExpressionEvaluator::new(expression).evaluate(&values)? {
        Value::Bool(b) => Ok(b),
        Value::Number(_) | Value::String(_) => Ok(false),
        other => Err(KIRunError::runtime(format!("Not a JSON Primitive: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auths(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn single_and_compound_expressions() {
        let a = auths(&["Authorities.ROLE_Owner", "Authorities.LEADZUMPTWO.ROLE_Internal_Helper_Only"]);
        assert!(has_authority(Some("Authorities.ROLE_Owner"), &a).unwrap());
        assert!(!has_authority(Some("Authorities.ROLE_Nobody"), &a).unwrap());
        assert!(has_authority(Some("Authorities.LEADZUMPTWO.ROLE_Internal_Helper_Only"), &a).unwrap());
        assert!(has_authority(Some("Authorities.ROLE_Nobody or Authorities.ROLE_Owner"), &a).unwrap());
        assert!(!has_authority(Some("Authorities.ROLE_Nobody and Authorities.ROLE_Owner"), &a).unwrap());
        assert!(has_authority(Some("not Authorities.ROLE_Nobody"), &a).unwrap());
    }

    // Port of commons-security `SecurityContextUtilHasAuthorityTest`, one test per Java test.
    // Java has a `Collection<GrantedAuthority>` and a `List<String>` overload; here both are
    // the caller's authority names.

    const OWNER: &str = "Authorities.ROLE_Owner";

    #[test]
    fn has_authority_with_granted_authorities_owner_present_should_return_true() {
        assert!(has_authority(Some(OWNER), &auths(&["Authorities.ROLE_Client_Manager", OWNER, "Authorities.User_CREATE"])).unwrap());
    }

    #[test]
    fn has_authority_with_granted_authorities_owner_absent_should_return_false() {
        assert!(!has_authority(Some(OWNER), &auths(&["Authorities.ROLE_Client_Manager", "Authorities.User_CREATE"])).unwrap());
    }

    #[test]
    fn has_authority_with_granted_authorities_empty_collection_should_return_false() {
        assert!(!has_authority(Some(OWNER), &[]).unwrap());
    }

    #[test]
    fn has_authority_with_granted_authorities_null_authority_should_return_true() {
        assert!(has_authority(None, &auths(&[OWNER])).unwrap());
    }

    #[test]
    fn has_authority_with_granted_authorities_blank_authority_should_return_true() {
        assert!(has_authority(Some(""), &auths(&[OWNER])).unwrap());
    }

    #[test]
    fn has_authority_with_string_list_owner_present_should_return_true() {
        assert!(has_authority(Some(OWNER), &auths(&["Authorities.ROLE_Client_Manager", OWNER, "Authorities.User_CREATE"])).unwrap());
    }

    #[test]
    fn has_authority_with_string_list_owner_absent_should_return_false() {
        assert!(!has_authority(Some(OWNER), &auths(&["Authorities.ROLE_Client_Manager", "Authorities.User_CREATE"])).unwrap());
    }

    #[test]
    fn has_authority_with_string_list_empty_list_should_return_false() {
        assert!(!has_authority(Some(OWNER), &auths(&[])).unwrap());
    }

    #[test]
    fn has_authority_with_full_authority_list_should_return_true() {
        let full = auths(&[
            "Authorities.ROLE_Client_Manager", "Authorities.ROLE_User_Manager", "Authorities.ROLE_Application_Manager",
            "Authorities.ROLE_Files_Manager", "Authorities.ROLE_Data_Manager", "Authorities.ROLE_Data_Connection_Manager",
            "Authorities.ROLE_Profile_CREATE", "Authorities.ROLE_Profile_READ", "Authorities.ROLE_Client_CREATE",
            "Authorities.ROLE_Profile_UPDATE", "Authorities.ROLE_Client_READ", "Authorities.ROLE_Profile_DELETE",
            "Authorities.ROLE_Client_UPDATE", "Authorities.ROLE_Profile_Manager", "Authorities.ROLE_Client_DELETE", OWNER,
            "Authorities.ROLE_User_CREATE", "Authorities.ROLE_User_READ", "Authorities.ROLE_User_UPDATE",
            "Authorities.ROLE_User_DELETE", "Authorities.Client_CREATE", "Authorities.Client_READ", "Authorities.Client_UPDATE",
            "Authorities.Client_DELETE", "Authorities.User_CREATE", "Authorities.User_READ", "Authorities.User_UPDATE",
            "Authorities.User_DELETE", "Authorities.Logged_IN",
        ]);
        assert!(has_authority(Some(OWNER), &full).unwrap());
    }

    #[test]
    fn has_authority_user_create_should_work() {
        assert!(has_authority(Some("Authorities.User_CREATE"), &auths(&["Authorities.User_CREATE", OWNER, "Authorities.Logged_IN"])).unwrap());
    }

    #[test]
    fn has_authority_with_only_owner_should_return_true() {
        assert!(has_authority(Some(OWNER), &auths(&[OWNER])).unwrap());
    }

    #[test]
    fn a_result_that_is_not_a_primitive_fails() {
        assert!(!has_authority(Some("'text'"), &auths(&[OWNER])).unwrap());
        assert!(!has_authority(Some("2"), &auths(&[OWNER])).unwrap());
        assert!(has_authority(Some("null"), &auths(&[OWNER])).is_err());
        let x = AuthoritiesTokenExtractor::new(auths(&[OWNER]));
        assert_eq!(x.get_store(), serde_json::json!([OWNER]));
    }

    #[test]
    fn blank_allows_and_no_authorities_refuse() {
        assert!(has_authority(None, &[]).unwrap());
        assert!(has_authority(Some("  "), &[]).unwrap());
        assert!(!has_authority(Some("Authorities.ROLE_Owner"), &[]).unwrap());
    }
}
