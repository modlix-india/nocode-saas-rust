//! `FileDetail` as the controllers send it, with the path and URL the resource services add.

use serde_json::Value;

use crate::dao::FileDetail;
use crate::jackson::Obj;
use crate::paths::Kind;
use crate::spring::url_encode;

/// `api/files/static` or `api/files/secured`: `getResourceFileType()`.
pub fn type_uri(kind: Kind) -> &'static str {
    match kind {
        Kind::Static => "api/files/static",
        Kind::Secured => "api/files/secured",
    }
}

/// The Java model `FileDetail`, as Jackson writes it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetailOut {
    pub id: Option<u64>,
    pub name: Option<String>,
    pub directory: bool,
    pub size: u64,
    pub file_path: Option<String>,
    pub url: Option<String>,
    pub created: i64,
    pub last_modified: i64,
}

impl DetailOut {
    /// A row's detail as the DAO returns it (with its id).
    pub fn of(d: &FileDetail) -> Self {
        Self {
            id: (d.id != 0).then_some(d.id),
            name: (d.id != 0 || !d.name.is_empty()).then(|| d.name.clone()),
            directory: d.is_directory,
            size: d.size,
            file_path: None,
            url: None,
            created: d.created,
            last_modified: d.last_modified,
        }
    }

    /// `FileDetail.clone`, which the listing uses: no id.
    pub fn listed(d: &FileDetail) -> Self {
        Self { id: None, ..Self::of(d) }
    }

    fn name_str(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }

    /// `convertToFileDetailWhileCreation`.
    pub fn with_creation_paths(mut self, kind: Kind, resource_path: &str, client_code: &str) -> Self {
        let rp = if resource_path.starts_with('/') { resource_path.to_string() } else { format!("/{resource_path}") };
        if self.directory {
            self.file_path = Some(rp.clone());
            self.url = Some(format!("{}{rp}", type_uri(kind)));
        } else {
            self.file_path = Some(format!("{rp}/{}", self.name_str()));
            self.url = Some(format!(
                "{}/file/{client_code}{rp}/{}",
                type_uri(kind),
                url_encode(self.name_str())
            ));
        }
        self
    }

    /// The paths `AbstractFilesResourceService.list` sets on each entry.
    pub fn with_list_paths(mut self, kind: Kind, resource_path: &str, client_code: &str) -> Self {
        let folder = if resource_path.starts_with('/') || resource_path.trim().is_empty() {
            resource_path.to_string()
        } else {
            format!("/{resource_path}")
        };
        self.file_path = Some(format!("{folder}/{}", self.name_str()));
        let file_part = if self.directory { String::new() } else { format!("/file/{client_code}") };
        self.url = Some(format!("{}{file_part}{folder}/{}", type_uri(kind), url_encode(self.name_str())));
        self
    }

    /// Jackson's view of the bean: `getFilePath()` / `getUrl()` collapse `//`; `setName` derives
    /// `fileName` and `type`; `isDirectory` comes out as `directory`, after the fields.
    pub fn json(&self) -> Value {
        let (file_name, ext) = match self.name.as_deref().filter(|n| !n.trim().is_empty()) {
            None => (None, None),
            Some(n) => match n.rfind('.') {
                Some(i) if i > 0 => (Some(n[..i].to_string()), Some(n[i + 1..].to_lowercase())),
                _ => (Some(n.to_string()), None),
            },
        };
        // `isCompressedFile` checks the extension for ".zip" / ".gz", which an extension taken
        // after the last dot can never contain: always false, as in Java.
        let compressed = ext.as_deref().is_some_and(|t| t.ends_with(".zip") || t.ends_with(".gz"));
        Obj::new()
            .put("id", self.id.map(Value::from).unwrap_or(Value::Null))
            .put("name", self.name.clone().map(Value::from).unwrap_or(Value::Null))
            .put("size", self.size)
            .put("filePath", self.file_path.as_ref().map(|p| Value::from(p.replace("//", "/"))).unwrap_or(Value::Null))
            .put("url", self.url.as_ref().map(|p| Value::from(p.replace("//", "/"))).unwrap_or(Value::Null))
            .put("createdDate", self.created)
            .put("lastModifiedTime", self.last_modified)
            .put("type", ext.map(Value::from).unwrap_or(Value::Null))
            .put("fileName", file_name.map(Value::from).unwrap_or(Value::Null))
            .put("directory", self.directory)
            .put("isCompressedFile", compressed)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(id: u64, name: &str, dir: bool) -> FileDetail {
        FileDetail { id, name: name.into(), is_directory: dir, size: 12, created: 1, last_modified: 2 }
    }

    #[test]
    fn upload_response_shape_observed_on_the_java_service() {
        let out = DetailOut::of(&detail(74389, "hello.txt", false))
            .with_creation_paths(Kind::Static, "_rustparity/probe1", "SYSTEM");
        assert_eq!(
            crate::jackson::pretty(&out.json()),
            "{\n  \"id\" : 74389,\n  \"name\" : \"hello.txt\",\n  \"size\" : 12,\n  \"filePath\" : \"/_rustparity/probe1/hello.txt\",\n  \"url\" : \"api/files/static/file/SYSTEM/_rustparity/probe1/hello.txt\",\n  \"createdDate\" : 1,\n  \"lastModifiedTime\" : 2,\n  \"type\" : \"txt\",\n  \"fileName\" : \"hello\",\n  \"directory\" : false,\n  \"isCompressedFile\" : false\n}"
        );
    }

    #[test]
    fn listing_paths() {
        let out = DetailOut::listed(&detail(5, "a b.png", false)).with_list_paths(Kind::Secured, "x/y", "CC");
        assert_eq!(out.id, None);
        assert_eq!(out.url.as_deref(), Some("api/files/secured/file/CC/x/y/a+b.png"));
        let dir = DetailOut::listed(&detail(5, "sub", true)).with_list_paths(Kind::Static, "", "CC");
        assert_eq!(dir.file_path.as_deref(), Some("/sub"));
        assert_eq!(dir.url.as_deref(), Some("api/files/static/sub"));
    }

    #[test]
    fn names_without_extension() {
        let v = DetailOut::of(&detail(1, ".env", false)).json();
        assert_eq!(v["fileName"], ".env");
        assert!(v.get("type").is_none());
    }


    #[test]
    fn folders_and_nameless_details() {
        let out = DetailOut::of(&detail(3, "b", true)).with_creation_paths(Kind::Static, "a/b", "CC");
        assert_eq!(out.file_path.as_deref(), Some("/a/b"));
        assert_eq!(out.url.as_deref(), Some("api/files/static/a/b"));
        let root = DetailOut::of(&FileDetail::root()).json();
        assert!(root.get("name").is_none() && root.get("fileName").is_none() && root.get("id").is_none());
        assert_eq!(root["directory"], true);
        assert_eq!(type_uri(Kind::Secured), "api/files/secured");
    }
}
