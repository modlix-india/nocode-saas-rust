//! The Spring pieces the controllers lean on: query parameters as WebFlux reads them,
//! `Pageable` as `ReactivePageableHandlerMethodArgumentResolver` builds it, `Sort` (its
//! `toString`, which is part of a cache key, and its Mongo form), and `PageImpl` as Jackson
//! writes it.

use mongodb::bson::{Bson, Document};
use percent_encoding::percent_decode_str;

use crate::json::{JMap, JValue};

/// Query parameters in order, repeated names kept (`MultiValueMap`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Params(pub Vec<(String, String)>);

impl Params {
    /// From a raw query string, `application/x-www-form-urlencoded` decoding.
    pub fn from_query(raw: Option<&str>) -> Self {
        let Some(raw) = raw else { return Self::default() };
        Self(
            raw.split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    (form_decode(k), form_decode(v))
                })
                .collect(),
        )
    }

    pub fn of(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    /// `getFirst`.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.0.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    /// The distinct names in first-seen order (`LinkedMultiValueMap.keySet`).
    pub fn keys(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for (k, _) in &self.0 {
            if !out.contains(&k.as_str()) {
                out.push(k);
            }
        }
        out
    }

    /// `MultiValueMap.size()`: the number of distinct names.
    pub fn len(&self) -> usize {
        self.keys().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn add(&mut self, name: &str, value: &str) {
        self.0.push((name.to_string(), value.to_string()));
    }
}

fn form_decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

/// `Sort.Direction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

/// One `Sort.Order`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub property: String,
    pub direction: Direction,
    pub ignore_case: bool,
    /// `NATIVE`, `NULLS_FIRST` or `NULLS_LAST`.
    pub null_handling: String,
}

impl Order {
    pub fn asc(property: &str) -> Self {
        Self { property: property.to_string(), direction: Direction::Asc, ignore_case: false, null_handling: "NATIVE".into() }
    }

    pub fn desc(property: &str) -> Self {
        Self { direction: Direction::Desc, ..Self::asc(property) }
    }

    pub fn is_ascending(&self) -> bool {
        self.direction == Direction::Asc
    }

    /// `Order.toString()`: `name: DESC`, with the null handling and case noted when not default.
    fn java_string(&self) -> String {
        let mut s = format!("{}: {}", self.property, if self.is_ascending() { "ASC" } else { "DESC" });
        if self.null_handling != "NATIVE" {
            s.push_str(&format!(", {}", self.null_handling));
        }
        if self.ignore_case {
            s.push_str(", ignoring case");
        }
        s
    }
}

/// A `Sort`: its orders, empty for `Sort.unsorted()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sort(pub Vec<Order>);

impl Sort {
    pub fn unsorted() -> Self {
        Self(Vec::new())
    }

    pub fn by(orders: Vec<Order>) -> Self {
        Self(orders)
    }

    /// `Sort.toString()`: `UNSORTED`, or the orders joined by commas.
    pub fn java_string(&self) -> String {
        if self.0.is_empty() {
            return "UNSORTED".into();
        }
        self.0.iter().map(Order::java_string).collect::<Vec<_>>().join(",")
    }

    /// The Mongo sort document Spring Data makes (`id` is the `_id` field).
    pub fn to_mongo(&self) -> Document {
        let mut d = Document::new();
        for o in &self.0 {
            let field = if o.property == "id" { "_id" } else { o.property.as_str() };
            d.insert(field, Bson::Int32(if o.is_ascending() { 1 } else { -1 }));
        }
        d
    }

    /// `SortJsonComponent.SortSerializer`: the orders as an array.
    pub fn to_json(&self) -> JValue {
        JValue::Array(
            self.0
                .iter()
                .map(|o| {
                    let mut m = JMap::new();
                    m.insert("direction".into(), JValue::Str(if o.is_ascending() { "ASC" } else { "DESC" }.into()));
                    m.insert("property".into(), JValue::Str(o.property.clone()));
                    m.insert("ignoreCase".into(), JValue::Bool(o.ignore_case));
                    m.insert("nullHandling".into(), JValue::Str(o.null_handling.clone()));
                    m.insert("ascending".into(), JValue::Bool(o.is_ascending()));
                    m.insert("descending".into(), JValue::Bool(!o.is_ascending()));
                    JValue::Object(m)
                })
                .collect(),
        )
    }

    /// `SortSerializationModule.SortDeserializer`: an order object or an array of them. Its
    /// `ignoreCase` reads the node's text, which a JSON boolean has none of, so it never takes
    /// effect; kept.
    pub fn from_json(v: &JValue) -> Result<Option<Self>, String> {
        let one = |o: &JValue| -> Result<Order, String> {
            let m = o.as_object().ok_or("an order must be an object")?;
            let direction = match m.get("direction") {
                None => Direction::Asc,
                Some(JValue::Str(s)) if s == "ASC" => Direction::Asc,
                Some(JValue::Str(s)) if s == "DESC" => Direction::Desc,
                Some(other) => return Err(format!("No enum constant Direction.{}", other.java_to_string())),
            };
            let property = m.get("property").and_then(JValue::as_str).ok_or("an order needs a property")?;
            let null_handling = match m.get("nullHandling").and_then(JValue::as_str) {
                Some(n @ ("NATIVE" | "NULLS_FIRST" | "NULLS_LAST")) => n.to_string(),
                Some(n) => return Err(format!("No enum constant NullHandling.{n}")),
                None => "NATIVE".into(),
            };
            Ok(Order { property: property.to_string(), direction, ignore_case: false, null_handling })
        };
        match v {
            JValue::Object(_) => Ok(Some(Sort(vec![one(v)?]))),
            JValue::Array(a) => Ok(Some(Sort(a.iter().map(one).collect::<Result<_, _>>()?))),
            _ => Ok(None),
        }
    }
}

/// A `PageRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pageable {
    pub page: i64,
    pub size: i64,
    pub sort: Sort,
}

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 2000;

impl Pageable {
    pub fn of(page: i64, size: i64, sort: Sort) -> Self {
        Self { page, size, sort }
    }

    /// The resolver with its defaults: page 0, size 20 (at most 2000), unreadable numbers read
    /// as 0, `sort=a,b,desc` repeated.
    pub fn from_params(p: &Params) -> Self {
        let bounded = |s: Option<&str>, upper: i64| -> Option<i64> {
            let s = s.filter(|s| !s.trim().is_empty())?;
            Some(match s.parse::<i32>() {
                Ok(n) => (n as i64).clamp(0, upper),
                Err(_) => 0,
            })
        };
        let page = bounded(p.first("page"), i32::MAX as i64).unwrap_or(0);
        let mut size = bounded(p.first("size"), MAX_PAGE_SIZE).unwrap_or(DEFAULT_PAGE_SIZE);
        if size < 1 {
            size = DEFAULT_PAGE_SIZE;
        }
        let mut orders = Vec::new();
        for value in p.all("sort") {
            orders.extend(parse_sort(value));
        }
        Self { page, size, sort: Sort(orders) }
    }

    pub fn offset(&self) -> i64 {
        self.page * self.size
    }

    fn json(&self) -> JValue {
        let mut m = JMap::new();
        m.insert("pageNumber".into(), JValue::Int(self.page));
        m.insert("pageSize".into(), JValue::Int(self.size));
        m.insert("sort".into(), self.sort.to_json());
        m.insert("offset".into(), JValue::Int(self.offset()));
        m.insert("unpaged".into(), JValue::Bool(false));
        m.insert("paged".into(), JValue::Bool(true));
        JValue::Object(m)
    }
}

/// `SortOrderParser`: `prop[,prop...][,asc|desc][,ignorecase]`.
fn parse_sort(value: &str) -> Vec<Order> {
    let mut parts: Vec<&str> = value.split(',').collect();
    let mut ignore_case = false;
    if parts.len() > 1 && parts.last().is_some_and(|l| l.eq_ignore_ascii_case("ignorecase")) {
        ignore_case = true;
        parts.pop();
    }
    let mut direction = Direction::Asc;
    if let Some(last) = parts.last() {
        if last.eq_ignore_ascii_case("asc") || last.eq_ignore_ascii_case("desc") {
            if last.eq_ignore_ascii_case("desc") {
                direction = Direction::Desc;
            }
            parts.pop();
        }
    }
    parts
        .into_iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| Order { property: p.to_string(), direction, ignore_case, null_handling: "NATIVE".into() })
        .collect()
}

/// `PageableExecutionUtils.getPage`: the total when the page itself tells it, `None` when the
/// count is needed.
pub fn known_total(content_len: usize, pageable: &Pageable) -> Option<i64> {
    let len = content_len as i64;
    if pageable.offset() == 0 {
        return (pageable.size > len).then_some(len);
    }
    (len != 0 && pageable.size > len).then_some(pageable.offset() + len)
}

/// `new PageImpl<>(content, pageable, total)` as Jackson writes it (`NON_EMPTY`: an empty page
/// has no `content`).
pub fn page_json(content: Vec<JValue>, pageable: &Pageable, total: i64) -> JValue {
    let len = content.len() as i64;
    let total = if len != 0 && pageable.offset() + pageable.size > total { pageable.offset() + len } else { total };
    let total_pages = if pageable.size == 0 { 1 } else { (total + pageable.size - 1) / pageable.size };
    let mut m = JMap::new();
    if !content.is_empty() {
        m.insert("content".into(), JValue::Array(content));
    }
    m.insert("pageable".into(), pageable.json());
    m.insert("last".into(), JValue::Bool(pageable.page + 1 >= total_pages));
    m.insert("totalPages".into(), JValue::Int(total_pages));
    m.insert("totalElements".into(), JValue::Int(total));
    m.insert("first".into(), JValue::Bool(pageable.page == 0));
    m.insert("numberOfElements".into(), JValue::Int(len));
    m.insert("sort".into(), pageable.sort.to_json());
    m.insert("size".into(), JValue::Int(pageable.size));
    m.insert("number".into(), JValue::Int(pageable.page));
    m.insert("empty".into(), JValue::Bool(len == 0));
    JValue::Object(m)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::to_jackson_pretty;

    #[test]
    fn params_keep_order_and_repeats() {
        let p = Params::from_query(Some("a=1&b=x+y&a=%2F&c&&"));
        assert_eq!(p.all("a"), vec!["1", "/"]);
        assert_eq!(p.first("b"), Some("x y"));
        assert_eq!(p.first("c"), Some(""));
        assert_eq!(p.keys(), vec!["a", "b", "c"]);
        assert_eq!(p.len(), 3);
        assert!(p.contains("c") && !p.contains("d"));
        assert!(Params::from_query(None).is_empty());
        let mut q = Params::of(&[("x", "1")]);
        q.add("y", "2");
        assert_eq!(q.first("y"), Some("2"));
    }

    #[test]
    fn pageable_defaults_and_bounds() {
        let p = |q: &str| Pageable::from_params(&Params::from_query(Some(q)));
        assert_eq!(p(""), Pageable::of(0, 20, Sort::unsorted()));
        assert_eq!(p("page=-3&size=0"), Pageable::of(0, 20, Sort::unsorted()));
        assert_eq!(p("page=x&size=5000"), Pageable::of(0, 2000, Sort::unsorted()));
        let s = p("sort=name,desc&sort=size&sort=a,b,DESC,ignorecase");
        assert_eq!(s.sort.0.len(), 4);
        assert_eq!(s.sort.0[0], Order::desc("name"));
        assert_eq!(s.sort.0[1], Order::asc("size"));
        assert!(!s.sort.0[2].is_ascending() && s.sort.0[2].ignore_case && s.sort.0[3].property == "b");
        assert_eq!(parse_sort("ignorecase"), vec![Order::asc("ignorecase")]);
        assert!(parse_sort(",desc").is_empty());
    }

    #[test]
    fn sort_strings_and_mongo() {
        assert_eq!(Sort::unsorted().java_string(), "UNSORTED");
        let mut o = Order::desc("name");
        o.ignore_case = true;
        o.null_handling = "NULLS_LAST".into();
        let s = Sort::by(vec![Order::asc("id"), o]);
        assert_eq!(s.java_string(), "id: ASC,name: DESC, NULLS_LAST, ignoring case");
        assert_eq!(s.to_mongo(), mongodb::bson::doc! {"_id": 1, "name": -1});
    }

    #[test]
    fn sort_from_json() {
        let v = crate::json::parse(br#"[{"property":"a","direction":"DESC","ignoreCase":true},{"property":"b","nullHandling":"NULLS_FIRST"}]"#).unwrap();
        let s = Sort::from_json(&v).unwrap().unwrap();
        assert_eq!(s.0[0], Order::desc("a"), "ignoreCase never takes effect, as in Java");
        assert_eq!(s.0[1].null_handling, "NULLS_FIRST");
        let one = crate::json::parse(br#"{"property":"x"}"#).unwrap();
        assert_eq!(Sort::from_json(&one).unwrap().unwrap(), Sort::by(vec![Order::asc("x")]));
        assert_eq!(Sort::from_json(&JValue::Null).unwrap(), None);
        for bad in [r#"{"property":"x","direction":"UP"}"#, r#"{"direction":"ASC"}"#, r#"[1]"#, r#"{"property":"x","nullHandling":"Z"}"#] {
            assert!(Sort::from_json(&crate::json::parse(bad.as_bytes()).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn page_shape_as_the_java_services_write_it() {
        // GET /api/files/static/loopzump?size=1&page=1&sort=name,desc (observed on the files
        // service, same Spring Data).
        let pageable = Pageable::from_params(&Params::from_query(Some("size=1&page=1&sort=name,desc")));
        let mut c = JMap::new();
        c.insert("name".into(), JValue::Str("compare".into()));
        let v = page_json(vec![JValue::Object(c)], &pageable, 2);
        let expected = "{\n  \"content\" : [ {\n    \"name\" : \"compare\"\n  } ],\n  \"pageable\" : {\n    \"pageNumber\" : 1,\n    \"pageSize\" : 1,\n    \"sort\" : [ {\n      \"direction\" : \"DESC\",\n      \"property\" : \"name\",\n      \"ignoreCase\" : false,\n      \"nullHandling\" : \"NATIVE\",\n      \"ascending\" : false,\n      \"descending\" : true\n    } ],\n    \"offset\" : 1,\n    \"unpaged\" : false,\n    \"paged\" : true\n  },\n  \"last\" : true,\n  \"totalPages\" : 2,\n  \"totalElements\" : 2,\n  \"first\" : false,\n  \"numberOfElements\" : 1,\n  \"sort\" : [ {\n    \"direction\" : \"DESC\",\n    \"property\" : \"name\",\n    \"ignoreCase\" : false,\n    \"nullHandling\" : \"NATIVE\",\n    \"ascending\" : false,\n    \"descending\" : true\n  } ],\n  \"size\" : 1,\n  \"number\" : 1,\n  \"empty\" : false\n}";
        assert_eq!(to_jackson_pretty(&v), expected);
        let empty = page_json(vec![], &Pageable::of(0, 20, Sort::unsorted()), 0);
        assert!(empty.as_object().unwrap().get("content").is_none());
        let zero = page_json(vec![], &Pageable::of(0, 0, Sort::unsorted()), 0);
        assert_eq!(zero.as_object().unwrap()["totalPages"], JValue::Int(1));
    }

    #[test]
    fn totals_like_pageable_execution_utils() {
        let p0 = Pageable::of(0, 20, Sort::unsorted());
        assert_eq!(known_total(3, &p0), Some(3));
        assert_eq!(known_total(20, &p0), None);
        let p1 = Pageable::of(2, 10, Sort::unsorted());
        assert_eq!(known_total(4, &p1), Some(24));
        assert_eq!(known_total(0, &p1), None);
    }

    #[test]
    fn booleans_like_boolean_util() {
        assert!(safe_bool(Some("Yes")) && safe_bool(Some("2")) && safe_bool(Some("t")));
        assert!(!safe_bool(Some("no")) && !safe_bool(Some(" ")) && !safe_bool(None) && !safe_bool(Some("x")));
    }
}
