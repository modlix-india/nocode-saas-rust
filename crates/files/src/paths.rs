//! How the Java service turns a request URI into a storage path. Reproduced step by step,
//! because the stored keys, the cache keys and the access checks all depend on the exact result.

use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Static,
    Secured,
}

impl Kind {
    /// `FilesFileSystemType` / `FilesAccessPathResourceType` name.
    pub fn db_name(self) -> &'static str {
        match self {
            Self::Static => "STATIC",
            Self::Secured => "SECURED",
        }
    }

    /// `api/files/<type>/file`, the marker `resolvePathWithClientCode` cuts the URI at.
    fn file_marker(self) -> &'static str {
        match self {
            Self::Static => "api/files/static/file",
            Self::Secured => "api/files/secured/file",
        }
    }
}

/// `URLDecoder.decode(path.replace('+', ' '), UTF_8)`.
pub fn java_url_decode(s: &str) -> String {
    let spaced = s.replace('+', " ");
    percent_decode_str(&spaced).decode_utf8_lossy().into_owned()
}

/// `makeTuple`: `(decoded path, path as it came)`. Leading `/` dropped from both; the decoded
/// one also loses anything from a `?` and a trailing `/`.
///
/// The decoding is the inverse of what the service hands out (`url_encode`, `URLEncoder`): `+`
/// is a space and `%XX` a byte, so `a+b.pdf` is `a b.pdf` and `a%2Bb.pdf` is `a+b.pdf`.
///
/// Only a `?` that is in the path as it came starts a query. Java cut at the first `?` AFTER
/// decoding, so a name with an encoded `?` (`a%3Fb.pdf`, as the service's own `url` for
/// `a?b.pdf` spells it) lost everything from it and resolved to another path, `a`.
pub fn make_tuple(path: &str) -> (String, String) {
    let path = path.strip_prefix('/').unwrap_or(path);
    let orig = path.to_string();
    let before_query = path.split('?').next().unwrap_or(path);
    let mut decoded = java_url_decode(before_query);
    if decoded.ends_with('/') {
        decoded.pop();
    }
    (decoded, orig)
}

/// A `.` or `..` segment: a path that would step out of its folder. The tree walk never finds
/// one (no row has such a name), but a key or a check should not be made for it either.
pub fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|s| s == "." || s == "..")
}

/// The path a key minted before CXZ-1138 meant. Those keys hold the path as it came in the
/// `createKey` URL (`ANTER/_allSubClients/Money+Apartment_11.pdf`, at times with a leading `/`),
/// not the decoded one the direct route reads (`Money Apartment_11.pdf`). `None` when decoding
/// changes nothing, steps out of a folder, or changes the client code.
pub fn legacy_key_path(stored: &str) -> Option<String> {
    let (decoded, _) = make_tuple(stored);
    if decoded.is_empty() || decoded == stored || has_dot_segment(&decoded) {
        return None;
    }
    let stored = stored.strip_prefix('/').unwrap_or(stored);
    if split_client_code(&decoded).0 != split_client_code(stored).0 {
        return None;
    }
    Some(decoded)
}

/// `resolvePathWithClientCode`: everything after the first `api/files/<type>/file` in the raw
/// URI path. `None` when the marker is absent (Java would take a nonsense substring there).
pub fn resolve_with_client_code(uri_path: &str, kind: Kind) -> Option<(String, String)> {
    let marker = kind.file_marker();
    let at = uri_path.find(marker)?;
    Some(make_tuple(&uri_path[at + marker.len()..]))
}

/// `resolvePathWithoutClientCode(part, uri)`: everything after the first `part` in the raw
/// URI path, less one trailing `/`, through `makeTuple`. `None` when `part` is absent.
pub fn resolve_without(uri_path: &str, part: &str) -> Option<(String, String)> {
    let at = uri_path.find(part)? + part.len();
    let end = uri_path.len() - usize::from(uri_path.ends_with('/'));
    Some(make_tuple(uri_path.get(at..end.max(at)).unwrap_or("")))
}

/// `api/files/<type>`: the `uriPart` of a resource service.
pub fn uri_part(kind: Kind) -> &'static str {
    match kind {
        Kind::Static => "api/files/static",
        Kind::Secured => "api/files/secured",
    }
}

/// `FileSystemService.getFileDetail(path)` splits `<clientCode>/<rest>` at the first `/`.
pub fn split_client_code(path: &str) -> (&str, &str) {
    match path.find('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path, ""),
    }
}

/// `splitPathParts`: the non-blank segments.
pub fn path_parts(path: &str) -> Vec<&str> {
    let p = path.strip_prefix('/').unwrap_or(path);
    p.split('/').filter(|s| !s.trim().is_empty()).collect()
}

/// The last path segment as `sendFile` names the download: the last part, or the one before a
/// trailing `/`, or `file`.
pub fn download_name(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let mut name = parts.last().copied().unwrap_or("");
    if name.trim().is_empty() && parts.len() > 1 {
        name = parts[parts.len() - 2];
    }
    if name.trim().is_empty() {
        "file".into()
    } else {
        name.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_like_java() {
        let (rp, orig) = resolve_with_client_code(
            "/api/files/static/file/SYSTEM/loopzump/global/favicon/loopzump-32-v1.png",
            Kind::Static,
        )
        .unwrap();
        assert_eq!(rp, "SYSTEM/loopzump/global/favicon/loopzump-32-v1.png");
        assert_eq!(orig, rp);

        let (rp, orig) =
            resolve_with_client_code("/api/files/static/file/FIN/My%20Docs/a+b.png/", Kind::Static).unwrap();
        assert_eq!(rp, "FIN/My Docs/a b.png");
        assert_eq!(orig, "FIN/My%20Docs/a+b.png/");
    }

    #[test]
    fn tolerates_a_prefix_before_api() {
        let (rp, _) =
            resolve_with_client_code("/x/app/CC/api/files/secured/file/CC/a.pdf", Kind::Secured).unwrap();
        assert_eq!(rp, "CC/a.pdf");
    }

    #[test]
    fn without_client_code() {
        let (rp, raw) = resolve_without("/api/files/static/_rp/a%20b/", "api/files/static").unwrap();
        assert_eq!((rp.as_str(), raw.as_str()), ("_rp/a b", "_rp/a%20b"));
        assert_eq!(resolve_without("/api/files/static", "api/files/static").unwrap().0, "");
        assert_eq!(resolve_without("/api/files/static/", "api/files/static").unwrap().0, "");
        assert_eq!(resolve_without("/api/files/secured/directory/x/y", "directory").unwrap().0, "x/y");
        assert!(resolve_without("/api/files/static/x", "export").is_none());
    }

    #[test]
    fn splits_and_names() {
        assert_eq!(split_client_code("SYSTEM/a/b.png"), ("SYSTEM", "a/b.png"));
        assert_eq!(split_client_code("SYSTEM"), ("SYSTEM", ""));
        assert_eq!(path_parts("/a//b/ /c"), vec!["a", "b", "c"]);
        assert_eq!(download_name("SYSTEM/a/b.png"), "b.png");
        assert_eq!(download_name("SYSTEM/a/"), "a");
    }


    #[test]
    fn query_marks_and_empty_names() {
        // An encoded `?` is part of the name; a raw one starts a query.
        assert_eq!(make_tuple("/a%3Fb/c").0, "a?b/c");
        assert_eq!(make_tuple("/a/b.pdf?x=1").0, "a/b.pdf");
        assert_eq!(make_tuple("/a/b+c.pdf?x=%3F").0, "a/b c.pdf");
        assert_eq!(make_tuple("x"), ("x".to_string(), "x".to_string()));
        assert_eq!(download_name(""), "file");
        assert_eq!(download_name("/"), "file");
        assert_eq!(uri_part(Kind::Secured), "api/files/secured");
        assert_eq!(java_url_decode("a+b%2Fc%ZZ"), "a b/c%ZZ");
    }

    /// CXZ-1138: the decoding is the exact inverse of the `url` the service hands out
    /// (`URLEncoder`: space `+`, `+` `%2B`), and of `encodeURIComponent` (space `%20`).
    #[test]
    fn every_special_name_round_trips() {
        let names = [
            "a b.pdf", "a+b.pdf", "a b+c.pdf", "100%.pdf", "a%20b.pdf", "%", "%2", "%ZZ.pdf", "Q&A.pdf",
            "C#.pdf", "what?.pdf", "a=b;c.pdf", "Cost Sheet (1).pdf", "[x] {y}.pdf", "a, b.pdf",
            "Owner's.pdf", "नक्शा.pdf", "café.pdf", "🏠 plan.pdf", "a.b.c.tar.gz", " lead.pdf",
            "trail.pdf ", "Money%2BApartment%281%29.pdf", "~!*$@:.pdf", "a\tb.pdf",
        ];
        let component = |s: &str| {
            s.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect::<String>()
        };
        for name in names {
            let folder = "CC/My Docs (2)/x";
            for spelled in [crate::spring::url_encode(name), component(name)] {
                let uri = format!("/api/files/secured/file/{}/{spelled}", crate::spring::url_encode("My Docs (2)").replace("%2F", "/"));
                let uri = uri.replacen("/file/", "/file/CC/", 1).replacen("My+Docs+%282%29", "My+Docs+%282%29/x", 1);
                let (rp, _) = resolve_with_client_code(&uri, Kind::Secured).unwrap();
                assert_eq!(rp, format!("{folder}/{name}"), "{name:?} as {spelled}");
            }
        }
        // A bare `+` is a space; only `%2B` is a plus.
        assert_eq!(make_tuple("CC/a+b.pdf").0, "CC/a b.pdf");
        assert_eq!(make_tuple("CC/a%2Bb.pdf").0, "CC/a+b.pdf");
        assert_eq!(make_tuple("CC/a%2bb.pdf").0, "CC/a+b.pdf");
        // Decoded once only: `%2520` is the text `%20`.
        assert_eq!(make_tuple("CC/a%2520b.pdf").0, "CC/a%20b.pdf");
    }

    #[test]
    fn dot_segments() {
        assert!(has_dot_segment("CC/../x"));
        assert!(has_dot_segment("CC/a/."));
        assert!(has_dot_segment(".."));
        assert!(!has_dot_segment("CC/..a/b../.hidden/x..y"));
        assert!(!has_dot_segment("CC/a b/c"));
    }

    /// Keys made before CXZ-1138 hold the `createKey` URL's path, still encoded, at times with a
    /// leading `/`: the file they meant is the decoded one, unless decoding steps out of a
    /// folder or names another client.
    #[test]
    fn legacy_key_paths() {
        assert_eq!(
            legacy_key_path("ANTER/_allSubClients/Money+Apartment_11_A-142costsheet.pdf").as_deref(),
            Some("ANTER/_allSubClients/Money Apartment_11_A-142costsheet.pdf")
        );
        assert_eq!(legacy_key_path("/LALIT/Cost+Sheet+%281%29.pdf").as_deref(), Some("LALIT/Cost Sheet (1).pdf"));
        assert_eq!(legacy_key_path("CC/My+Docs/a%2Bb.pdf").as_deref(), Some("CC/My Docs/a+b.pdf"));
        // Nothing to decode: the stored path was the answer (or there is none).
        assert_eq!(legacy_key_path("CC/plain.pdf"), None);
        assert_eq!(legacy_key_path(""), None);
        // A leading `/` alone is still a different path to look up.
        assert_eq!(legacy_key_path("/CC/plain.pdf").as_deref(), Some("CC/plain.pdf"));
        // Never out of the folder, never another client.
        assert_eq!(legacy_key_path("CC/a/%2E%2E/b.pdf"), None);
        assert_eq!(legacy_key_path("CC/a/x%2F..%2F..%2FDD%2Fb.pdf"), None);
        assert_eq!(legacy_key_path("C%43/a.pdf"), None);
    }
}
