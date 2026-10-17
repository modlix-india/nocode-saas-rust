//! `SecurityContextUtil.hasAuthority(expression, authorities)`.
//!
//! Java evaluates the permission string as a KIRun expression in which `Authorities.X` is
//! true when the caller holds the authority `Authorities.X`, and the permission passes only if
//! the result is the boolean `true`. Permissions in the definitions are `Authorities.*` paths
//! joined by `and`, `or`, `not` and parentheses, which is what this evaluates, with KIRun's
//! truthiness: null is false, numbers are false at zero, strings are true. A token that is
//! neither an `Authorities.` path nor a literal is a string, as KIRun's literal extractor makes
//! it, so a misspelt prefix (`Authorization.Logged_IN`, present in real definitions) denies
//! on its own and counts as true inside `and` / `or`.

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
}

impl Val {
    fn truthy(&self) -> bool {
        match self {
            Val::Null => false,
            Val::Bool(b) => *b,
            Val::Num(n) => *n != 0.0,
            Val::Str(_) => true,
        }
    }

    /// `LogicalNotOperator`.
    fn not(&self) -> Val {
        Val::Bool(match self {
            Val::Null => true,
            Val::Bool(b) => !b,
            Val::Str(_) => false,
            Val::Num(n) => *n == 0.0,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Open,
    Close,
    And,
    Or,
    Not,
    Word(String),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut Vec<Tok>| {
        if word.is_empty() {
            return;
        }
        out.push(match word.as_str() {
            "and" => Tok::And,
            "or" => Tok::Or,
            "not" => Tok::Not,
            _ => Tok::Word(word.clone()),
        });
        word.clear();
    };
    let mut in_quote = false;
    for c in s.chars() {
        if in_quote {
            word.push(c);
            if c == '"' {
                in_quote = false;
            }
            continue;
        }
        match c {
            '"' => {
                word.push(c);
                in_quote = true;
            }
            '(' => {
                flush(&mut word, &mut out);
                out.push(Tok::Open);
            }
            ')' => {
                flush(&mut word, &mut out);
                out.push(Tok::Close);
            }
            c if c.is_whitespace() => flush(&mut word, &mut out),
            c => word.push(c),
        }
    }
    flush(&mut word, &mut out);
    out
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    authorities: &'a [String],
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn or(&mut self) -> Val {
        let mut left = self.and();
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            let right = self.and();
            left = Val::Bool(left.truthy() || right.truthy());
        }
        left
    }

    fn and(&mut self) -> Val {
        let mut left = self.unary();
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            let right = self.unary();
            left = Val::Bool(left.truthy() && right.truthy());
        }
        left
    }

    fn unary(&mut self) -> Val {
        if self.peek() == Some(&Tok::Not) {
            self.pos += 1;
            return self.unary().not();
        }
        self.primary()
    }

    fn primary(&mut self) -> Val {
        match self.toks.get(self.pos).cloned() {
            Some(Tok::Open) => {
                self.pos += 1;
                let v = self.or();
                if self.peek() == Some(&Tok::Close) {
                    self.pos += 1;
                }
                v
            }
            Some(Tok::Word(w)) => {
                self.pos += 1;
                self.value(&w)
            }
            _ => {
                self.pos += 1;
                Val::Null
            }
        }
    }

    fn value(&self, token: &str) -> Val {
        if token.starts_with("Authorities.") {
            return Val::Bool(self.authorities.iter().any(|a| a == token));
        }
        literal(token)
    }
}

/// KIRun `LiteralTokenValueExtractor`.
fn literal(token: &str) -> Val {
    match token {
        "true" => return Val::Bool(true),
        "false" => return Val::Bool(false),
        "null" => return Val::Null,
        _ => {}
    }
    if token.len() >= 2 && token.starts_with('"') && token.ends_with('"') {
        return Val::Str(token[1..token.len() - 1].to_string());
    }
    let numeric = match token.split_once('.') {
        None => token.parse::<i64>().ok().map(|n| n as f64),
        Some((_, frac)) if frac.chars().all(|c| c.is_ascii_digit()) => token.parse::<f64>().ok(),
        Some(_) => None,
    };
    numeric.map(Val::Num).unwrap_or_else(|| Val::Str(token.to_string()))
}

/// `hasAuthority`: a blank permission passes; otherwise the expression must come out `true`.
pub fn has_authority(permission: Option<&str>, authorities: &[String]) -> bool {
    let Some(p) = permission.map(str::trim).filter(|p| !p.is_empty()) else {
        return true;
    };
    if authorities.is_empty() {
        return false;
    }
    let mut parser = Parser { toks: tokenize(p), pos: 0, authorities };
    let v = parser.or();
    v == Val::Bool(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn expressions_from_real_definitions() {
        let user = auth(&["Authorities.Logged_IN", "Authorities.ROLE_Owner", "Authorities.LEADZUMP.ROLE_Deal_READ"]);
        assert!(has_authority(None, &user));
        assert!(has_authority(Some("  "), &user));
        assert!(has_authority(Some("Authorities.Logged_IN"), &user));
        assert!(has_authority(Some("Authorities.Logged_IN  "), &user));
        assert!(has_authority(Some("Authorities.Logged_IN and Authorities.ROLE_Owner"), &user));
        assert!(!has_authority(Some("Authorities.Logged_IN and Authorities.ROLE_Partner_Manager"), &user));
        assert!(has_authority(
            Some("Authorities.Logged_IN and (Authorities.LEADZUMP.ROLE_Deal_READ_ASSIGNED or Authorities.LEADZUMP.ROLE_Deal_READ)  "),
            &user
        ));
        assert!(has_authority(Some("Authorities.ROLE_Owner or Authorities.User_READ"), &user));
        assert!(!has_authority(Some("not Authorities.ROLE_Owner"), &user));
        assert!(has_authority(Some("not Authorities.SITEZUMP.PROFILE_Access_Request_Profile"), &user));
        // A misspelt prefix is a string: never `true` alone, truthy in a conjunction.
        assert!(!has_authority(Some("Authorization.Logged_IN"), &user));
        assert!(has_authority(Some("Authoritites.Logged_IN and Authorities.Logged_IN"), &user));
        // The anonymous user holds only Authorities._Anonymous.
        let anon = auth(&["Authorities._Anonymous"]);
        assert!(!has_authority(Some("Authorities.Logged_IN"), &anon));
        assert!(!has_authority(Some("Authorities.ANYTIME"), &anon));
        assert!(!has_authority(Some("Authorities.Logged_IN"), &[]));
    }

    // The commons-security `SecurityContextUtilHasAuthorityTest`, one test per Java method
    // (the GrantedAuthority and List<String> overloads read the same strings here).
    const OWNER_ROLE: &str = "Authorities.ROLE_Owner";

    #[test]
    fn has_authority_with_granted_authorities_owner_present_should_return_true() {
        let a = auth(&["Authorities.ROLE_Client_Manager", "Authorities.ROLE_Owner", "Authorities.User_CREATE"]);
        assert!(has_authority(Some(OWNER_ROLE), &a));
    }

    #[test]
    fn has_authority_with_granted_authorities_owner_absent_should_return_false() {
        let a = auth(&["Authorities.ROLE_Client_Manager", "Authorities.User_CREATE"]);
        assert!(!has_authority(Some(OWNER_ROLE), &a));
    }

    #[test]
    fn has_authority_with_granted_authorities_empty_collection_should_return_false() {
        assert!(!has_authority(Some(OWNER_ROLE), &[]));
    }

    #[test]
    fn has_authority_with_granted_authorities_null_authority_should_return_true() {
        assert!(has_authority(None, &auth(&["Authorities.ROLE_Owner"])));
    }

    #[test]
    fn has_authority_with_granted_authorities_blank_authority_should_return_true() {
        assert!(has_authority(Some(""), &auth(&["Authorities.ROLE_Owner"])));
    }

    #[test]
    fn has_authority_with_string_list_owner_present_should_return_true() {
        let a = auth(&["Authorities.ROLE_Client_Manager", "Authorities.ROLE_Owner", "Authorities.User_CREATE"]);
        assert!(has_authority(Some(OWNER_ROLE), &a));
    }

    #[test]
    fn has_authority_with_string_list_owner_absent_should_return_false() {
        assert!(!has_authority(Some(OWNER_ROLE), &auth(&["Authorities.ROLE_Client_Manager", "Authorities.User_CREATE"])));
    }

    #[test]
    fn has_authority_with_string_list_empty_list_should_return_false() {
        assert!(!has_authority(Some(OWNER_ROLE), &auth(&[])));
    }

    #[test]
    fn has_authority_with_full_authority_list_should_return_true() {
        let a = auth(&[
            "Authorities.ROLE_Client_Manager", "Authorities.ROLE_User_Manager", "Authorities.ROLE_Application_Manager",
            "Authorities.ROLE_Files_Manager", "Authorities.ROLE_Data_Manager", "Authorities.ROLE_Data_Connection_Manager",
            "Authorities.ROLE_Profile_CREATE", "Authorities.ROLE_Profile_READ", "Authorities.ROLE_Client_CREATE",
            "Authorities.ROLE_Profile_UPDATE", "Authorities.ROLE_Client_READ", "Authorities.ROLE_Profile_DELETE",
            "Authorities.ROLE_Client_UPDATE", "Authorities.ROLE_Profile_Manager", "Authorities.ROLE_Client_DELETE",
            "Authorities.ROLE_Owner", "Authorities.ROLE_User_CREATE", "Authorities.ROLE_User_READ",
            "Authorities.ROLE_User_UPDATE", "Authorities.ROLE_User_DELETE", "Authorities.Client_CREATE",
            "Authorities.Client_READ", "Authorities.Client_UPDATE", "Authorities.Client_DELETE",
            "Authorities.User_CREATE", "Authorities.User_READ", "Authorities.User_UPDATE", "Authorities.User_DELETE",
            "Authorities.Logged_IN",
        ]);
        assert!(has_authority(Some(OWNER_ROLE), &a));
    }

    #[test]
    fn has_authority_user_create_should_work() {
        let a = auth(&["Authorities.User_CREATE", "Authorities.ROLE_Owner", "Authorities.Logged_IN"]);
        assert!(has_authority(Some("Authorities.User_CREATE"), &a));
    }

    #[test]
    fn has_authority_with_only_owner_should_return_true() {
        assert!(has_authority(Some(OWNER_ROLE), &auth(&["Authorities.ROLE_Owner"])));
    }

    // KIRun's literal rules, which only odd permission strings reach.
    #[test]
    fn literals_and_truthiness() {
        let a = auth(&["Authorities.X"]);
        assert!(has_authority(Some("true"), &a));
        assert!(!has_authority(Some("false"), &a));
        assert!(!has_authority(Some("null"), &a));
        assert!(!has_authority(Some("1"), &a), "a number is never the boolean true");
        assert!(has_authority(Some("1 and Authorities.X"), &a));
        assert!(!has_authority(Some("0 or Authorities.Y"), &a));
        assert!(has_authority(Some("2.5 and true"), &a));
        assert!(has_authority(Some("\"a b\" and Authorities.X"), &a));
        assert!(has_authority(Some("not null"), &a));
        assert!(!has_authority(Some("not \"s\""), &a));
        assert!(has_authority(Some("not 0"), &a));
        assert!(!has_authority(Some("not 1.5"), &a));
        assert!(has_authority(Some("not (Authorities.Y or false)"), &a));
        assert!(has_authority(Some("(Authorities.X"), &a), "an unclosed parenthesis still evaluates");
        assert!(!has_authority(Some("and"), &a), "an operator with nothing to apply to");
        assert!(!has_authority(Some("2.x"), &a));
        assert_eq!(literal("2.x"), Val::Str("2.x".into()));
        assert_eq!(literal("12"), Val::Num(12.0));
        assert_eq!(literal("1.25"), Val::Num(1.25));
    }

}
