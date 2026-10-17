//! The Spring MVC behaviour the controller leans on: request parameters as Tomcat and Spring
//! bind them, `Pageable` as `PageableHandlerMethodArgumentResolver` builds it, and a `PageImpl`
//! as Jackson writes it (the same rules files-manage follows for its pages).

use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};

/// Query parameters in order, repeated names kept (`application/x-www-form-urlencoded`).
#[derive(Debug, Clone, Default)]
pub struct Params(Vec<(String, String)>);

fn form_decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

impl Params {
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

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.0.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }

    /// A `@RequestParam String`: one value as it is, several joined with `,` (Spring converts
    /// the `String[]` to a `String`).
    pub fn string(&self, name: &str) -> Option<String> {
        let all = self.all(name);
        (!all.is_empty()).then(|| all.join(","))
    }

    /// The first value, as `getParameter` returns it.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.all(name).into_iter().next()
    }
}

/// A `@RequestParam BigInteger`: Spring's `StringToNumberConverterFactory` (trimmed, `0x`/`#`
/// hex, a blank value is no value). `Err` is a `MethodArgumentTypeMismatchException`.
pub fn big_integer(raw: Option<&str>) -> Result<Option<i128>, String> {
    let Some(raw) = raw else { return Ok(None) };
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let (negative, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let (radix, digits) = if let Some(h) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        (16, h)
    } else if let Some(h) = digits.strip_prefix('#') {
        (16, h)
    } else {
        (10, digits)
    };
    let mismatch = || {
        format!(
            "Method parameter 'userId': Failed to convert value of type 'java.lang.String' to required type 'java.math.BigInteger'; For input string: \"{raw}\""
        )
    };
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return Err(mismatch());
    }
    let n = i128::from_str_radix(digits, radix).map_err(|_| mismatch())?;
    Ok(Some(if negative { -n } else { n }))
}

/// One `Sort.Order`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub property: String,
    pub ascending: bool,
    pub ignore_case: bool,
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

/// `SortHandlerMethodArgumentResolver`: `prop[,prop...][,asc|desc][,ignorecase]`.
fn parse_sort(value: &str) -> Vec<Order> {
    let mut parts: Vec<&str> = value.split(',').collect();
    let mut ignore_case = false;
    if parts.len() > 1 && parts.last().is_some_and(|l| l.eq_ignore_ascii_case("ignorecase")) {
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

impl Pageable {
    /// `PageableHandlerMethodArgumentResolver` with its defaults: page 0, size 20 (at most
    /// 2000, below 1 the default), unreadable numbers read as 0, `sort` repeated.
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
        let sort = p.all("sort").into_iter().flat_map(parse_sort).collect();
        Self { page, size, sort }
    }

    pub fn offset(&self) -> i64 {
        self.page * self.size
    }
}

/// `SortJsonComponent.SortSerializer`: the orders as an array.
fn sort_json(orders: &[Order]) -> Value {
    Value::Array(
        orders
            .iter()
            .map(|o| {
                let mut m = Map::new();
                m.insert("direction".into(), Value::from(if o.ascending { "ASC" } else { "DESC" }));
                m.insert("property".into(), Value::from(o.property.clone()));
                m.insert("ignoreCase".into(), Value::from(o.ignore_case));
                m.insert("nullHandling".into(), Value::from("NATIVE"));
                m.insert("ascending".into(), Value::from(o.ascending));
                m.insert("descending".into(), Value::from(!o.ascending));
                Value::Object(m)
            })
            .collect(),
    )
}

/// `PageableExecutionUtils.getPage(content, pageable, () -> -1)` then `new PageImpl(...)` as
/// Jackson writes it under `NON_EMPTY`: the total is known from the page itself when it can
/// be, else it is the supplier's -1 (a full page, or an empty page past the first).
///
/// Jackson's property order for `PageImpl` comes from reflection and differs between JVM runs
/// (two runs of the same jar on 2026-10-16 wrote different orders); this is one of them.
pub fn page_json(content: Vec<Value>, pageable: &Pageable) -> Value {
    let len = content.len() as i64;
    let known = if pageable.offset() == 0 {
        (pageable.size > len).then_some(len)
    } else {
        (len != 0 && pageable.size > len).then_some(pageable.offset() + len)
    };
    let supplied = known.unwrap_or(-1);
    // PageImpl: a non-empty page whose end is past the given total counts its own rows.
    let total = if len != 0 && pageable.offset() + pageable.size > supplied {
        pageable.offset() + len
    } else {
        supplied
    };
    // Math.ceil((double) total / size), cast to int.
    let total_pages = (total as f64 / pageable.size as f64).ceil() as i64;
    let has_next = pageable.page + 1 < total_pages;

    let mut pageable_json = Map::new();
    pageable_json.insert("pageNumber".into(), Value::from(pageable.page));
    pageable_json.insert("pageSize".into(), Value::from(pageable.size));
    pageable_json.insert("sort".into(), sort_json(&pageable.sort));
    pageable_json.insert("offset".into(), Value::from(pageable.offset()));
    pageable_json.insert("unpaged".into(), Value::from(false));
    pageable_json.insert("paged".into(), Value::from(true));

    let mut m = Map::new();
    if !content.is_empty() {
        m.insert("content".into(), Value::Array(content));
    }
    m.insert("pageable".into(), Value::Object(pageable_json));
    m.insert("last".into(), Value::from(!has_next));
    m.insert("totalElements".into(), Value::from(total));
    m.insert("totalPages".into(), Value::from(total_pages));
    m.insert("first".into(), Value::from(pageable.page == 0));
    m.insert("sort".into(), sort_json(&pageable.sort));
    m.insert("numberOfElements".into(), Value::from(len));
    m.insert("size".into(), Value::from(pageable.size));
    m.insert("number".into(), Value::from(pageable.page));
    m.insert("empty".into(), Value::from(len == 0));
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(q: &str) -> Params {
        Params::from_query(Some(q))
    }

    #[test]
    fn parameters_as_spring_binds_them() {
        let p = params("a=1&b=x+y&a=%2F&c&appCode=");
        assert_eq!(p.string("a").as_deref(), Some("1,/"));
        assert_eq!(p.first("a"), Some("1"));
        assert_eq!(p.string("b").as_deref(), Some("x y"));
        assert_eq!(p.string("c").as_deref(), Some(""));
        assert_eq!(p.string("appCode").as_deref(), Some(""));
        assert_eq!(p.string("none"), None);
        assert!(Params::from_query(None).all("a").is_empty());
    }

    #[test]
    fn big_integers_as_spring_converts_them() {
        assert_eq!(big_integer(None), Ok(None));
        assert_eq!(big_integer(Some("")), Ok(None));
        assert_eq!(big_integer(Some("  ")), Ok(None));
        assert_eq!(big_integer(Some(" 142 ")), Ok(Some(142)));
        assert_eq!(big_integer(Some("-5")), Ok(Some(-5)));
        assert_eq!(big_integer(Some("+7")), Ok(Some(7)));
        assert_eq!(big_integer(Some("0x10")), Ok(Some(16)));
        assert_eq!(big_integer(Some("#ff")), Ok(Some(255)));
        assert_eq!(big_integer(Some("-0X1")), Ok(Some(-1)));
        for bad in ["abc", "1.5", "--1", "0x", "-+1", "1e3"] {
            let e = big_integer(Some(bad)).unwrap_err();
            assert!(e.contains("Failed to convert value of type 'java.lang.String'"), "{bad}");
        }
        assert_eq!(
            big_integer(Some("abc")).unwrap_err(),
            "Method parameter 'userId': Failed to convert value of type 'java.lang.String' to required type 'java.math.BigInteger'; For input string: \"abc\""
        );
    }

    #[test]
    fn pageable_defaults_and_bounds() {
        assert_eq!(Pageable::from_params(&params("")), Pageable { page: 0, size: 20, sort: vec![] });
        assert_eq!(Pageable::from_params(&params("page=-3&size=0")), Pageable { page: 0, size: 20, sort: vec![] });
        assert_eq!(Pageable::from_params(&params("page=x&size=5000")), Pageable { page: 0, size: 2000, sort: vec![] });
        let p = Pageable::from_params(&params("sort=title,desc&sort=a,b,DESC,ignorecase&sort=ignorecase&sort=,desc"));
        assert_eq!(p.sort.len(), 4);
        assert!(!p.sort[0].ascending);
        assert!(p.sort[1].ignore_case && p.sort[2].property == "b");
        assert_eq!(p.sort[3].property, "ignorecase");
    }

    /// The pages Java answered on 2026-10-16 (key order aside).
    #[test]
    fn pages_observed_on_the_java_service() {
        let p = Pageable::from_params(&params("size=1&page=0&sort=title,desc"));
        let v = page_json(vec![json!({"id": 5686})], &p);
        assert_eq!(
            v,
            json!({
                "content": [{"id": 5686}],
                "pageable": {"pageNumber": 0, "pageSize": 1, "sort": [{"direction": "DESC", "property": "title", "ignoreCase": false,
                    "nullHandling": "NATIVE", "descending": true, "ascending": false}], "offset": 0, "unpaged": false, "paged": true},
                "totalPages": 1, "totalElements": 1, "last": true,
                "sort": [{"direction": "DESC", "property": "title", "ignoreCase": false, "nullHandling": "NATIVE", "descending": true, "ascending": false}],
                "first": true, "numberOfElements": 1, "size": 1, "number": 0, "empty": false
            })
        );
        // An empty page past the first: the supplier's -1 survives.
        let v = page_json(vec![], &Pageable::from_params(&params("page=1&size=5")));
        assert_eq!((v["totalElements"].clone(), v["totalPages"].clone(), v["last"].clone(), v["first"].clone()), (json!(-1), json!(0), json!(true), json!(false)));
        assert!(v.get("content").is_none());
        // The first, empty page.
        let v = page_json(vec![], &Pageable::from_params(&params("")));
        assert_eq!((v["totalElements"].clone(), v["totalPages"].clone(), v["empty"].clone()), (json!(0), json!(0), json!(true)));
    }

    #[test]
    fn page_totals() {
        // A full first page: the supplier says -1, PageImpl counts the page itself.
        let v = page_json(vec![json!(1), json!(2)], &Pageable { page: 0, size: 2, sort: vec![] });
        assert_eq!((v["totalElements"].clone(), v["totalPages"].clone(), v["last"].clone()), (json!(2), json!(1), json!(true)));
        // A partial later page.
        let v = page_json(vec![json!(1)], &Pageable { page: 2, size: 10, sort: vec![] });
        assert_eq!((v["totalElements"].clone(), v["totalPages"].clone()), (json!(21), json!(3)));
        // A full later page.
        let v = page_json(vec![json!(1)], &Pageable { page: 3, size: 1, sort: vec![] });
        assert_eq!((v["totalElements"].clone(), v["totalPages"].clone(), v["last"].clone()), (json!(4), json!(4), json!(true)));
        // An empty page past the first with size 1: ceil(-1.0) is -1.
        let v = page_json(vec![], &Pageable { page: 4, size: 1, sort: vec![] });
        assert_eq!(v["totalPages"], json!(-1));
    }
}
