//! `DownloadOptions`: the query parameters of a file download, and the part of the ETag they
//! contribute.

use std::collections::HashMap;

use platform::error::AppError;
use platform::java::sha256_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    ScaleDown,
    Contain,
    Cover,
    Crop,
    Pad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gravity {
    Auto,
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    General,
    Auto,
    Avif,
    Webp,
    Jpeg,
    Jpg,
    Png,
}

impl Fit {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "scale_down" => Self::ScaleDown,
            "contain" => Self::Contain,
            "cover" => Self::Cover,
            "crop" => Self::Crop,
            "pad" => Self::Pad,
            _ => return None,
        })
    }
    fn java_name(self) -> &'static str {
        match self {
            Self::ScaleDown => "scale_down",
            Self::Contain => "contain",
            Self::Cover => "cover",
            Self::Crop => "crop",
            Self::Pad => "pad",
        }
    }
}

impl Gravity {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "auto" => Self::Auto,
            "left" => Self::Left,
            "right" => Self::Right,
            "top" => Self::Top,
            "bottom" => Self::Bottom,
            _ => return None,
        })
    }
    fn java_name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Left => "left",
            Self::Right => "right",
            Self::Top => "top",
            Self::Bottom => "bottom",
        }
    }
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "general" => Self::General,
            "auto" => Self::Auto,
            "avif" => Self::Avif,
            "webp" => Self::Webp,
            "jpeg" => Self::Jpeg,
            "jpg" => Self::Jpg,
            "png" => Self::Png,
            _ => return None,
        })
    }
    fn java_name(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Auto => "auto",
            Self::Avif => "avif",
            Self::Webp => "webp",
            Self::Jpeg => "jpeg",
            Self::Jpg => "jpg",
            Self::Png => "png",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DownloadOptions {
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub fit: Fit,
    pub gravity: Gravity,
    pub background: Option<String>,
    /// As given: `jpg` stays `jpg` here because the ETag hashes the field, not the getter.
    pub format_raw: Format,
    pub no_cache: bool,
    pub download: bool,
    pub name: Option<String>,
}

impl Default for DownloadOptions {
    /// The controller defaults: `fit=contain`, `gravity=auto`, `format=general`.
    fn default() -> Self {
        Self {
            width: None,
            height: None,
            fit: Fit::Contain,
            gravity: Gravity::Auto,
            background: None,
            format_raw: Format::General,
            no_cache: false,
            download: false,
            name: None,
        }
    }
}

fn bad(param: &str, value: &str) -> AppError {
    crate::errors::param_invalid(param, format!("Invalid value '{value}' for parameter '{param}'"))
}

/// Spring's `StringToBooleanConverter`.
fn parse_bool(param: &str, v: &str) -> Result<bool, AppError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "" => Ok(false),
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" => Ok(false),
        _ => Err(bad(param, v)),
    }
}

impl DownloadOptions {
    /// From the query string. An unknown enum value or a non-number width is a 400 here; the
    /// Java service answers those with a 500 from its catch-all handler.
    pub fn from_query(q: &HashMap<String, String>) -> Result<Self, AppError> {
        let mut o = Self::default();
        let int = |k: &str| -> Result<Option<i32>, AppError> {
            match q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty()) {
                None => Ok(None),
                Some(v) => v.parse::<i32>().map(Some).map_err(|_| bad(k, v)),
            }
        };
        o.width = int("width")?;
        o.height = int("height")?;
        if let Some(v) = q.get("fit").filter(|s| !s.is_empty()) {
            o.fit = Fit::parse(v).ok_or_else(|| bad("fit", v))?;
        }
        if let Some(v) = q.get("gravity").filter(|s| !s.is_empty()) {
            o.gravity = Gravity::parse(v).ok_or_else(|| bad("gravity", v))?;
        }
        if let Some(v) = q.get("format").filter(|s| !s.is_empty()) {
            o.format_raw = Format::parse(v).ok_or_else(|| bad("format", v))?;
        }
        o.background = q.get("background").cloned();
        if let Some(v) = q.get("noCache") {
            o.no_cache = parse_bool("noCache", v)?;
        }
        if let Some(v) = q.get("download") {
            o.download = parse_bool("download", v)?;
        }
        o.name = q.get("name").cloned();
        Ok(o)
    }

    /// `getFormat()`: `jpg` read as `jpeg`.
    pub fn format(&self) -> Format {
        if self.format_raw == Format::Jpg {
            Format::Jpeg
        } else {
            self.format_raw
        }
    }

    /// `eTagCode()`.
    pub fn etag_code(&self) -> String {
        let s = format!(
            "{}{}{}-{}-{}-{}",
            self.width.map(|w| w.to_string()).unwrap_or_else(|| "-1".into()),
            self.height.map(|h| h.to_string()).unwrap_or_else(|| "-1".into()),
            self.background.as_deref().unwrap_or("no"),
            self.fit.java_name(),
            self.gravity.java_name(),
            self.format_raw.java_name(),
        );
        sha256_hex(&s)
    }

    /// `hasNoModification()`: the file can be sent as stored.
    pub fn has_no_modification(&self) -> bool {
        self.height.is_none()
            && self.width.is_none()
            && self.fit == Fit::Contain
            && self.gravity == Gravity::Auto
            && self.background.is_none()
            && self.format_raw == Format::General
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn etag_codes_match_the_java_service() {
        // Both observed on the Java files service on 2026-10-13.
        let plain = DownloadOptions::from_query(&q(&[])).unwrap();
        assert_eq!(
            plain.etag_code(),
            "a4d9da2831316f5021400cee04db02e1ca31413da29b52f2f7b7af51b4bd6809"
        );
        let w16 = DownloadOptions::from_query(&q(&[("width", "16")])).unwrap();
        assert_eq!(
            w16.etag_code(),
            "7b8d7669df74d66ef41f1ee555ca97ff1cc36562c2d25a529052525daf881fb3"
        );
    }

    #[test]
    fn no_modification_rules() {
        assert!(DownloadOptions::from_query(&q(&[("download", "true")])).unwrap().has_no_modification());
        assert!(!DownloadOptions::from_query(&q(&[("format", "png")])).unwrap().has_no_modification());
        assert!(!DownloadOptions::from_query(&q(&[("background", "")])).unwrap().has_no_modification());
    }

    #[test]
    fn rejects_unknown_values() {
        assert!(DownloadOptions::from_query(&q(&[("fit", "bogus")])).is_err());
        assert!(DownloadOptions::from_query(&q(&[("width", "x")])).is_err());
    }

    #[test]
    fn jpg_reads_as_jpeg_but_hashes_as_jpg() {
        let o = DownloadOptions::from_query(&q(&[("format", "jpg")])).unwrap();
        assert_eq!(o.format(), Format::Jpeg);
        assert_ne!(
            o.etag_code(),
            DownloadOptions::from_query(&q(&[("format", "jpeg")])).unwrap().etag_code()
        );
    }

    #[test]
    fn every_value_names_itself_in_the_etag() {
        let mut codes = std::collections::HashSet::new();
        for (k, values) in [
            ("fit", &["scale_down", "contain", "cover", "crop", "pad"][..]),
            ("gravity", &["auto", "left", "right", "top", "bottom"][..]),
            ("format", &["general", "auto", "avif", "webp", "jpeg", "jpg", "png"][..]),
        ] {
            for v in values {
                let o = DownloadOptions::from_query(&q(&[(k, v)])).unwrap();
                codes.insert(o.etag_code());
                assert!(!o.has_no_modification() || matches!(*v, "contain" | "auto" | "general"), "{k}={v}");
            }
        }
        // contain, auto (gravity) and general are the defaults: one code; auto (format) differs.
        assert_eq!(codes.len(), 17 - 2);
        let o = DownloadOptions::from_query(&q(&[("format", "auto"), ("height", " 7 "), ("noCache", ""), ("download", "on"), ("name", "n")])).unwrap();
        assert_eq!((o.format(), o.height, o.no_cache, o.download, o.name.as_deref()), (Format::Auto, Some(7), false, true, Some("n")));
        assert!(DownloadOptions::from_query(&q(&[("gravity", "middle")])).is_err());
        assert!(DownloadOptions::from_query(&q(&[("noCache", "sometimes")])).is_err());
        assert_eq!(DownloadOptions::from_query(&q(&[("width", "")])).unwrap().width, None);
    }
}
