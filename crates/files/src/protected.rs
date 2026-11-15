//! Protected top-level folders of the SECURED tree (`[files] protected_prefixes`, default
//! `["hrms"]`).
//!
//! Many companies hold an open SECURED rule (PATH `''` or `/` with sub paths) that lets every
//! signed-in user read and write every secured folder. A protected folder is the exception: a
//! path whose FIRST segment names a protected prefix (case-insensitively, with or without a
//! leading `/`) is allowed only by a rule whose own PATH lies under that same prefix. A broader
//! rule (`''`, `/`, `/h`, `/hr%`, ...) no longer reaches it.
//!
//! The operations that work on the root as a whole leave a protected folder out for a caller
//! who has no rule under it: the root listing hides it, a root export does not zip it, a zip
//! imported into the root skips entries under it. A delete of the root never touched it (it
//! removes only the object at the exact key `<client>/` and no tree row).
//!
//! STATIC is not affected: static files are read without any access check, so a static
//! protected folder would protect nothing (the hrms app's static `hrms` folder is its public
//! site assets).

/// The first segment of `path`, without the leading slashes. `""` for the root.
pub fn first_segment(path: &str) -> &str {
    let p = path.trim_start_matches('/');
    p.split('/').next().unwrap_or("")
}

/// Whether `path` is the root (empty, or only slashes).
pub fn is_root(path: &str) -> bool {
    first_segment(path).is_empty()
}

fn normalized(prefix: &str) -> String {
    prefix.trim().trim_matches('/').to_lowercase()
}

/// The protected prefix (as configured) that the first segment of `path` names, if any.
/// `/hrms/a`, `hrms/a`, `/HRMS`, `hrms` are under `hrms`; `/hrmsx/a`, `/hr`, `/` are not.
pub fn prefix_of<'a>(prefixes: &'a [String], path: &str) -> Option<&'a str> {
    let seg = first_segment(path);
    if seg.is_empty() {
        return None;
    }
    let seg = seg.to_lowercase();
    prefixes
        .iter()
        .find(|p| {
            let n = normalized(p);
            !n.is_empty() && n == seg
        })
        .map(String::as_str)
}

/// Whether a rule whose PATH is `rule_path` may grant a path under `prefix`: its own first
/// segment must be exactly that prefix (`hrms`, `/hrms`, `/HRMS/payroll`). `''`, `/`, `/h`,
/// `hrm%` and `/hrmsx` are not.
pub fn rule_is_under(prefix: &str, rule_path: &str) -> bool {
    let n = normalized(prefix);
    !n.is_empty() && first_segment(rule_path.trim()).to_lowercase() == n
}

/// Whether one of the rules that LIKE-cover a protected path may grant it.
pub fn any_rule_under(prefix: &str, rule_paths: &[String]) -> bool {
    rule_paths.iter().any(|r| rule_is_under(prefix, r))
}

/// Whether the root entry `name` (a file or folder directly at the root) is a protected one.
pub fn name_is_protected<'a>(prefixes: &'a [String], name: &str) -> Option<&'a str> {
    if name.contains('/') {
        return None;
    }
    prefix_of(prefixes, name)
}

/// Whether a path relative to the root falls under one of `blocked` (prefixes the caller may
/// not reach): what a root export and a root zip import leave out.
pub fn is_blocked(blocked: &[String], rel: &str) -> bool {
    !blocked.is_empty() && prefix_of(blocked, rel).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hrms() -> Vec<String> {
        vec!["hrms".to_string()]
    }

    #[test]
    fn first_segments() {
        assert_eq!(first_segment("/hrms/a/b.pdf"), "hrms");
        assert_eq!(first_segment("hrms/a"), "hrms");
        assert_eq!(first_segment("//hrms/a"), "hrms");
        assert_eq!(first_segment("hrms"), "hrms");
        assert_eq!(first_segment(""), "");
        assert_eq!(first_segment("/"), "");
        assert!(is_root("") && is_root("/") && is_root("//") && !is_root("/a"));
    }

    #[test]
    fn protected_paths_read_and_upload_forms() {
        let p = hrms();
        // Reads come as `/hrms/...`, uploads as `hrms/...`.
        assert_eq!(prefix_of(&p, "/hrms/emp/1/pan.pdf"), Some("hrms"));
        assert_eq!(prefix_of(&p, "hrms/emp/1"), Some("hrms"));
        assert_eq!(prefix_of(&p, "hrms"), Some("hrms"));
        assert_eq!(prefix_of(&p, "/hrms"), Some("hrms"));
    }

    #[test]
    fn case_variants_are_protected() {
        let p = hrms();
        assert_eq!(prefix_of(&p, "/HRMS/a.pdf"), Some("hrms"));
        assert_eq!(prefix_of(&p, "Hrms/a.pdf"), Some("hrms"));
        // The configured value is normalized too.
        let odd = vec![" /HRMS/ ".to_string()];
        assert!(prefix_of(&odd, "/hrms/a").is_some());
    }

    #[test]
    fn look_alikes_are_not_protected() {
        let p = hrms();
        for path in ["/hrmsx/a", "hrmsx", "/hrm/a", "/h", "/", "", "/a/hrms/x", "_withInClient/hrms", "/hrms.pdf"] {
            assert_eq!(prefix_of(&p, path), None, "{path}");
        }
        // An empty list (or an empty entry) protects nothing.
        assert_eq!(prefix_of(&[], "/hrms/a"), None);
        assert_eq!(prefix_of(&["".to_string(), "/".to_string()], "/hrms/a"), None);
    }

    #[test]
    fn open_root_rule_does_not_reach_hrms_but_an_hrms_rule_does() {
        // The open rules every company has.
        for open in ["", "/", " ", "%", "/%", "/h", "/hr", "/hrm", "hrm%", "/h_ms", "/hrmsx", "/other"] {
            assert!(!rule_is_under("hrms", open), "{open:?}");
        }
        // The HRMS Files rules, in both forms, and narrower ones.
        for r in ["/hrms", "hrms", "/HRMS", "/hrms/", "hrms/payroll", "/hrms/emp/1"] {
            assert!(rule_is_under("hrms", r), "{r:?}");
        }
        assert!(!any_rule_under("hrms", &["".into(), "/".into()]));
        assert!(any_rule_under("hrms", &["".into(), "/hrms".into()]));
        assert!(!any_rule_under("hrms", &[]));
    }

    #[test]
    fn root_entries() {
        let p = hrms();
        assert_eq!(name_is_protected(&p, "hrms"), Some("hrms"));
        assert_eq!(name_is_protected(&p, "HRMS"), Some("hrms"));
        assert_eq!(name_is_protected(&p, "hrmsx"), None);
        assert_eq!(name_is_protected(&p, "kyc"), None);
    }

    #[test]
    fn export_and_import_skip_blocked_entries() {
        let b = hrms();
        assert!(is_blocked(&b, "hrms/emp/1/pan.pdf"));
        assert!(is_blocked(&b, "HRMS/x"));
        assert!(is_blocked(&b, "hrms"));
        assert!(!is_blocked(&b, "hrmsx/a"));
        assert!(!is_blocked(&b, "kyc/a.pdf"));
        assert!(!is_blocked(&[], "hrms/a"));
    }
}
