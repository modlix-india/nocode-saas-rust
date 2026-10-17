//! The Spring and JDK behaviour the controllers lean on: query parameters as Tomcat reads them,
//! `Pageable` as `PageableHandlerMethodArgumentResolver` builds it, `Page` as Jackson writes a
//! `PageImpl`, and the small conversions (`URLEncoder`, `BooleanUtil`) that leave the process.

use percent_encoding::percent_decode_str;
use serde_json::Value;

use crate::jackson::Obj;

/// Query parameters in order, repeated names kept: `application/x-www-form-urlencoded` decoding.
pub fn parse_query(raw: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = raw else { return Vec::new() };
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

fn form_decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

/// The parameters of a request: `getParameter` (first value) and `getParameterValues`.
#[derive(Debug, Clone, Default)]
pub struct Params(pub Vec<(String, String)>);

impl Params {
    pub fn from_query(raw: Option<&str>) -> Self {
        Self(parse_query(raw))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.0.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }

    /// Adds form fields after the query ones, as `getParameter` sees a multipart request.
    pub fn extend(&mut self, more: impl IntoIterator<Item = (String, String)>) {
        self.0.extend(more);
    }
}

/// `java.net.URLEncoder.encode(s, UTF_8)`.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `BooleanUtil.safeValueOf(String)`.
pub fn safe_bool(v: Option<&str>) -> bool {
    let Some(v) = v else { return false };
    if v.trim().is_empty() {
        return false;
    }
    let l = v.to_ascii_lowercase();
    if matches!(l.as_str(), "yes" | "y" | "true" | "t" | "on") {
        return true;
    }
    v.parse::<i32>().map(|n| n != 0).unwrap_or(false)
}

/// One `Sort.Order`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub property: String,
    pub ascending: bool,
    pub ignore_case: bool,
}

impl Order {
    pub fn new(property: &str, ascending: bool) -> Self {
        Self { property: property.to_string(), ascending, ignore_case: false }
    }
}

/// `SortJsonComponent.SortSerializer`: the orders as an array.
pub fn sort_json(orders: &[Order]) -> Value {
    Value::Array(
        orders
            .iter()
            .map(|o| {
                Obj::new()
                    .put("direction", if o.ascending { "ASC" } else { "DESC" })
                    .put("property", o.property.as_str())
                    .put("ignoreCase", o.ignore_case)
                    .put("nullHandling", "NATIVE")
                    .put("ascending", o.ascending)
                    .put("descending", !o.ascending)
                    .build()
            })
            .collect(),
    )
}

/// A `PageRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pageable {
    pub page: i64,
    pub size: i64,
    pub sort: Vec<Order>,
}

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 2000;

impl Pageable {
    pub fn of(page: i64, size: i64, sort: Vec<Order>) -> Self {
        Self { page, size, sort }
    }

    /// `PageableHandlerMethodArgumentResolver` with its defaults: page 0, size 20 (at most
    /// 2000), unreadable numbers read as 0, `sort=a,b,desc` repeated.
    pub fn from_params(p: &Params) -> Self {
        let bounded = |s: Option<&str>, upper: i64| -> Option<i64> {
            let s = s.filter(|s| !s.trim().is_empty())?;
            Some(match s.parse::<i32>() {
                Ok(n) => (n as i64).clamp(0, upper),
                Err(_) => 0,
            })
        };
        let page = bounded(p.get("page"), i32::MAX as i64).unwrap_or(0);
        let mut size = bounded(p.get("size"), MAX_PAGE_SIZE).unwrap_or(DEFAULT_PAGE_SIZE);
        if size < 1 {
            size = DEFAULT_PAGE_SIZE;
        }
        let mut sort = Vec::new();
        for value in p.all("sort") {
            sort.extend(parse_sort(value));
        }
        Self { page, size, sort }
    }

    pub fn offset(&self) -> i64 {
        self.page * self.size
    }

    pub fn is_sorted(&self) -> bool {
        !self.sort.is_empty()
    }

    fn json(&self) -> Value {
        Obj::new()
            .put("pageNumber", self.page)
            .put("pageSize", self.size)
            .put_always("sort", sort_json(&self.sort))
            .put("offset", self.offset())
            .put("unpaged", false)
            .put("paged", true)
            .build()
    }
}

/// `SortOrderParser`: `prop[,prop...][,asc|desc][,ignorecase]`.
fn parse_sort(value: &str) -> Vec<Order> {
    let mut parts: Vec<&str> = value.split(',').collect();
    let mut ignore_case = false;
    if parts.last().is_some_and(|l| l.eq_ignore_ascii_case("ignorecase")) && parts.len() > 1 {
        ignore_case = true;
        parts.pop();
    }
    let mut ascending = true;
    if let Some(last) = parts.last() {
        if last.eq_ignore_ascii_case("asc") || last.eq_ignore_ascii_case("desc") {
            ascending = last.eq_ignore_ascii_case("asc");
            parts.pop();
        }
    }
    parts
        .into_iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| Order { property: p.to_string(), ascending, ignore_case })
        .collect()
}

/// `PageableExecutionUtils.getPage`: the total when it can be told from the page itself, so the
/// count query is only run when needed. `None` means run it.
pub fn known_total(content_len: usize, pageable: &Pageable) -> Option<i64> {
    let len = content_len as i64;
    if pageable.offset() == 0 {
        return (pageable.size > len).then_some(len);
    }
    (len != 0 && pageable.size > len).then_some(pageable.offset() + len)
}

/// `new PageImpl<>(content, pageable, total)` as Jackson writes it.
pub fn page_json(content: Vec<Value>, pageable: &Pageable, total: i64) -> Value {
    let len = content.len() as i64;
    let total = if len != 0 && pageable.offset() + pageable.size > total {
        pageable.offset() + len
    } else {
        total
    };
    let total_pages = if pageable.size == 0 {
        1
    } else {
        (total + pageable.size - 1) / pageable.size
    };
    let has_next = pageable.page + 1 < total_pages;
    Obj::new()
        .put("content", Value::Array(content))
        .put("pageable", pageable.json())
        .put("last", !has_next)
        .put("totalPages", total_pages)
        .put("totalElements", total)
        .put("first", pageable.page == 0)
        .put("numberOfElements", len)
        .put_always("sort", sort_json(&pageable.sort))
        .put("size", pageable.size)
        .put("number", pageable.page)
        .put("empty", len == 0)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(q: &str) -> Params {
        Params::from_query(Some(q))
    }

    #[test]
    fn pageable_defaults_and_bounds() {
        assert_eq!(Pageable::from_params(&params("")), Pageable::of(0, 20, vec![]));
        assert_eq!(Pageable::from_params(&params("page=-3&size=0")), Pageable::of(0, 20, vec![]));
        assert_eq!(Pageable::from_params(&params("page=x&size=5000")), Pageable::of(0, 2000, vec![]));
        let p = Pageable::from_params(&params("sort=name,desc&sort=size&sort=a,b,DESC,ignorecase"));
        assert_eq!(p.sort.len(), 4);
        assert_eq!(p.sort[0], Order::new("name", false));
        assert_eq!(p.sort[1], Order::new("size", true));
        assert!(!p.sort[2].ascending && p.sort[2].ignore_case && p.sort[3].property == "b");
    }

    #[test]
    fn page_shape_observed_on_the_java_service() {
        // GET /api/files/static/loopzump?size=1&page=1&sort=name,desc on 2026-10-15.
        let pageable = Pageable::from_params(&params("size=1&page=1&sort=name,desc"));
        let v = page_json(vec![json!({"name": "compare"})], &pageable, 2);
        let expected = "{\n  \"content\" : [ {\n    \"name\" : \"compare\"\n  } ],\n  \"pageable\" : {\n    \"pageNumber\" : 1,\n    \"pageSize\" : 1,\n    \"sort\" : [ {\n      \"direction\" : \"DESC\",\n      \"property\" : \"name\",\n      \"ignoreCase\" : false,\n      \"nullHandling\" : \"NATIVE\",\n      \"ascending\" : false,\n      \"descending\" : true\n    } ],\n    \"offset\" : 1,\n    \"unpaged\" : false,\n    \"paged\" : true\n  },\n  \"last\" : true,\n  \"totalPages\" : 2,\n  \"totalElements\" : 2,\n  \"first\" : false,\n  \"numberOfElements\" : 1,\n  \"sort\" : [ {\n    \"direction\" : \"DESC\",\n    \"property\" : \"name\",\n    \"ignoreCase\" : false,\n    \"nullHandling\" : \"NATIVE\",\n    \"ascending\" : false,\n    \"descending\" : true\n  } ],\n  \"size\" : 1,\n  \"number\" : 1,\n  \"empty\" : false\n}";
        assert_eq!(crate::jackson::pretty(&v), expected);
    }

    #[test]
    fn empty_page_has_no_content_key() {
        let v = page_json(vec![], &Pageable::of(0, 20, vec![]), 0);
        assert!(v.get("content").is_none());
        assert_eq!(v["totalPages"], 0);
        assert_eq!(v["last"], true);
        assert_eq!(v["empty"], true);
    }

    #[test]
    fn totals_like_pageable_execution_utils() {
        let p0 = Pageable::of(0, 20, vec![]);
        assert_eq!(known_total(3, &p0), Some(3));
        assert_eq!(known_total(20, &p0), None);
        let p1 = Pageable::of(2, 10, vec![]);
        assert_eq!(known_total(4, &p1), Some(24));
        assert_eq!(known_total(0, &p1), None);
    }

    #[test]
    fn url_encoder_and_booleans() {
        assert_eq!(url_encode("a b+c/é.png"), "a+b%2Bc%2F%C3%A9.png");
        assert!(safe_bool(Some("Yes")) && safe_bool(Some("2")) && safe_bool(Some("t")));
        assert!(!safe_bool(Some("no")) && !safe_bool(Some("")) && !safe_bool(None) && !safe_bool(Some("x")));
    }

    #[test]
    fn query_keeps_repeats() {
        let p = params("a=1&b=x+y&a=%2F&c");
        assert_eq!(p.all("a"), vec!["1", "/"]);
        assert_eq!(p.get("b"), Some("x y"));
        assert_eq!(p.get("c"), Some(""));
    }


    #[test]
    fn a_zero_size_page_has_one_page() {
        let v = page_json(vec![], &Pageable::of(0, 0, vec![]), 0);
        assert_eq!(v["totalPages"], 1);
        assert_eq!(parse_sort("ignorecase"), vec![Order::new("ignorecase", true)]);
        assert_eq!(parse_sort("a,ASC"), vec![Order::new("a", true)]);
        assert!(parse_sort(",desc").is_empty());
        assert_eq!(Params::from_query(None).0, vec![]);
    }
}
