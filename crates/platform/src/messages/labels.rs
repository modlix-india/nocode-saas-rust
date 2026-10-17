//! Plain labels for the technical names that end up in messages: authorities
//! (`Authorities.Page_UPDATE` reads "Edit pages") and Java class names (`ClientUrl` reads
//! "client URL").
//!
//! Labels are catalogue entries, so they translate and can be overridden like any text:
//! - `PERMISSION.<name>`: the label of one authority (`PERMISSION.Page_UPDATE`, or
//!   `PERMISSION.ROLE_Owner` for a role). An app-scoped authority (`Authorities.CRM.Lead_READ`)
//!   tries `PERMISSION.CRM.Lead_READ`, then `PERMISSION.Lead_READ`.
//! - `PERMISSION._READ`, `_CREATE`, `_UPDATE`, `_DELETE`: the label of a permission without one
//!   of its own, `{name}` being the rest of its name in words ("View {name}").
//! - `PERMISSION._ONE`, `_ROLE`, `_PROFILE`: how a label reads inside a sentence ("the {name}
//!   permission", "the {name} role", "the {name} profile").
//! - `ENTITY.<ClassName>`: a class name.
//! - `WORD.OR`: the word joining alternatives.

use super::catalogue::Catalogue;

/// Words kept in capitals when a name is turned into words.
const ACRONYMS: &[&str] = &["api", "crm", "csr", "id", "jwt", "otp", "sms", "ssl", "sso", "url"];

/// `Client_Password_Policy` and `ClientPasswordPolicy` read "client password policy" (with
/// `lower`); words already in capitals (`SSO`) and known acronyms (`Url`) stay in capitals.
pub fn humanize(name: &str, lower: bool) -> String {
    let mut words: Vec<String> = Vec::new();
    for chunk in name.split(['_', ' ', '-']).filter(|c| !c.is_empty()) {
        let chars: Vec<char> = chunk.chars().collect();
        let mut word = String::new();
        for (i, c) in chars.iter().enumerate() {
            let boundary = i > 0
                && c.is_uppercase()
                && (chars[i - 1].is_lowercase() || chars.get(i + 1).is_some_and(|n| n.is_lowercase()) && chars[i - 1].is_uppercase());
            if boundary && !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            word.push(*c);
        }
        if !word.is_empty() {
            words.push(word);
        }
    }
    words
        .into_iter()
        .map(|w| {
            let caps = w.len() > 1 && w.chars().all(|c| !c.is_lowercase());
            if ACRONYMS.contains(&w.to_lowercase().as_str()) {
                w.to_uppercase()
            } else if caps || !lower {
                w
            } else {
                w.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityKind {
    Permission,
    Role,
    Profile,
}

impl Catalogue {
    /// What an authority is, and its label.
    fn classify(&self, authority: &str, chain: &[String]) -> (AuthorityKind, String) {
        let trimmed = authority.trim();
        let name = trimmed.strip_prefix("Authorities.").unwrap_or(trimmed).replace(' ', "_");
        let rest = name.split_once('.').map(|(_, r)| r.to_string()).unwrap_or_else(|| name.clone());
        let (kind, bare) = if let Some(r) = rest.strip_prefix("ROLE_") {
            (AuthorityKind::Role, r)
        } else if let Some(p) = rest.strip_prefix("PROFILE_") {
            (AuthorityKind::Profile, p)
        } else {
            (AuthorityKind::Permission, rest.as_str())
        };
        let own = self
            .label(&format!("PERMISSION.{name}"), "", chain)
            .or_else(|| (rest != name).then(|| self.label(&format!("PERMISSION.{rest}"), "", chain)).flatten());
        if let Some(l) = own {
            return (kind, l);
        }
        if kind == AuthorityKind::Permission {
            for suffix in ["READ", "CREATE", "UPDATE", "DELETE"] {
                if let Some(thing) = bare.strip_suffix(&format!("_{suffix}")) {
                    let words = humanize(thing, true);
                    return (kind, self.label(&format!("PERMISSION._{suffix}"), &words, chain).unwrap_or(words));
                }
            }
            return (kind, humanize(bare, true));
        }
        (kind, humanize(bare, false))
    }

    /// The label of one authority, as the permission table shows it ("Edit pages", "Owner").
    pub fn authority_label(&self, authority: &str, chain: &[String]) -> String {
        self.classify(authority, chain).1
    }

    /// One authority as it reads in a sentence ("the Edit pages permission", "the Owner role").
    pub fn authority_phrase(&self, authority: &str, chain: &[String]) -> String {
        let (kind, label) = self.classify(authority, chain);
        let pattern = match kind {
            AuthorityKind::Permission => "PERMISSION._ONE",
            AuthorityKind::Role => "PERMISSION._ROLE",
            AuthorityKind::Profile => "PERMISSION._PROFILE",
        };
        self.label(pattern, &label, chain).unwrap_or(label)
    }

    /// One or several authorities (comma separated), any of which would do, as a sentence
    /// reads them: "the Edit pages permission or the Owner role".
    pub fn authority_labels(&self, value: &str, chain: &[String]) -> String {
        let phrases: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(|a| self.authority_phrase(a, chain))
            .collect();
        match phrases.as_slice() {
            [] => String::new(),
            [one] => one.clone(),
            [init @ .., last] => {
                let or = self.label("WORD.OR", "", chain).unwrap_or_else(|| "or".to_string());
                format!("{} {or} {last}", init.join(", "))
            }
        }
    }

    /// A Java class name in words.
    pub fn entity_label(&self, value: &str, chain: &[String]) -> String {
        let key = value.trim().replace(' ', "_");
        self.label(&format!("ENTITY.{key}"), "", chain).unwrap_or_else(|| humanize(value.trim(), true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_in_words() {
        assert_eq!(humanize("Client_Password_Policy", true), "client password policy");
        assert_eq!(humanize("ClientPasswordPolicy", true), "client password policy");
        assert_eq!(humanize("ClientUrl", true), "client URL");
        assert_eq!(humanize("SSO target app", true), "SSO target app");
        assert_eq!(humanize("Client_Manager", false), "Client Manager");
        assert_eq!(humanize("HTTPServer", true), "HTTP server");
        assert_eq!(humanize("", true), "");
    }

    fn cat() -> Catalogue {
        let mut c = Catalogue::default();
        c.add_builtin(
            "t",
            "en",
            r#"
            [WORD.OR]
            text = "or"
            [PERMISSION.Page_UPDATE]
            text = "Edit pages"
            [PERMISSION.Lead_READ]
            text = "View leads"
            [PERMISSION.ROLE_Owner]
            text = "Owner"
            [PERMISSION._ONE]
            text = "the {name} permission"
            [PERMISSION._ROLE]
            text = "the {name} role"
            [PERMISSION._PROFILE]
            text = "the {name} profile"
            [PERMISSION._READ]
            text = "View {name}"
            [PERMISSION._CREATE]
            text = "Create {name}"
            [ENTITY.ClientUrl]
            text = "client address"
            "#,
        )
        .unwrap();
        c
    }

    #[test]
    fn labels_and_phrases() {
        let c = cat();
        let en = vec!["en".to_string()];
        assert_eq!(c.authority_label("Authorities.Page_UPDATE", &en), "Edit pages");
        assert_eq!(c.authority_phrase("Authorities.Page_UPDATE", &en), "the Edit pages permission");
        assert_eq!(c.authority_label("Page UPDATE", &en), "Edit pages");
        assert_eq!(c.authority_label("Authorities.CRM.Lead_READ", &en), "View leads");
        assert_eq!(c.authority_label("Authorities.ROLE_Owner", &en), "Owner");
        assert_eq!(c.authority_phrase("Authorities.ROLE_Owner", &en), "the Owner role");
        assert_eq!(c.authority_phrase("Authorities.ROLE_Client_Manager", &en), "the Client Manager role");
        assert_eq!(c.authority_phrase("Authorities.CRM.PROFILE_Crm_Owner", &en), "the CRM Owner profile");
        assert_eq!(c.authority_label("Authorities.EventDefinition_READ", &en), "View event definition");
        assert_eq!(c.authority_label("Client Manager CREATE", &en), "Create client manager");
        assert_eq!(c.authority_label("Authorities.Thing_DELETE", &en), "thing", "no pattern: the words");
        assert_eq!(c.authority_phrase("SSO target app", &en), "the SSO target app permission");
        assert_eq!(c.authority_labels("Authorities.Page_UPDATE", &en), "the Edit pages permission");
        assert_eq!(
            c.authority_labels("Authorities.Page_UPDATE, Authorities.Lead_READ,Authorities.ROLE_Owner", &en),
            "the Edit pages permission, the View leads permission or the Owner role"
        );
        assert_eq!(c.authority_labels(" , ", &en), "");
        assert_eq!(Catalogue::default().authority_labels("A_READ,Bee_READ", &en), "a or bee");
    }

    #[test]
    fn entity_labels() {
        let c = cat();
        let en = vec!["en".to_string()];
        assert_eq!(c.entity_label("ClientUrl", &en), "client address");
        assert_eq!(c.entity_label("User Request", &en), "user request");
    }
}
