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
pub fn make_tuple(path: &str) -> (String, String) {
    let path = path.strip_prefix('/').unwrap_or(path);
    let orig = path.to_string();
    let mut decoded = java_url_decode(path);
    if let Some(i) = decoded.find('?') {
        decoded.truncate(i);
    }
    if decoded.ends_with('/') {
        decoded.pop();
    }
    (decoded, orig)
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
        assert_eq!(make_tuple("/a%3Fb/c").0, "a");
        assert_eq!(make_tuple("x"), ("x".to_string(), "x".to_string()));
        assert_eq!(download_name(""), "file");
        assert_eq!(download_name("/"), "file");
        assert_eq!(uri_part(Kind::Secured), "api/files/secured");
        assert_eq!(java_url_decode("a+b%2Fc%ZZ"), "a b/c%ZZ");
    }
}
