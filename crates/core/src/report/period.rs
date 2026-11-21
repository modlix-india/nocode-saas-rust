//! Report periods and date buckets in the tenant's time zone (CXZ-1780).
//!
//! A period is resolved at run time, so a saved widget stays current: a pair of local dates
//! (both inclusive) and the UTC instants of their bounds (the start of the first day, the
//! start of the day after the last). Buckets are cut by MySQL in a fixed UTC offset (the
//! zone's offset now), which needs no named time zone tables on the server.

use chrono::{DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveDateTime, Offset, TimeZone, Utc};
use chrono_tz::Tz;

/// The catalog's `timeZone`: a region of the tz database, or a fixed offset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Zone {
    Region(Tz),
    Fixed(FixedOffset),
}

impl Zone {
    /// `Asia/Kolkata`, `UTC`, `+05:30`, `-08:00`; none for anything else.
    pub fn parse(s: &str) -> Option<Zone> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("UTC") || s == "Z" {
            return Some(Zone::Fixed(FixedOffset::east_opt(0)?));
        }
        if s.starts_with('+') || s.starts_with('-') {
            return parse_offset(s).map(Zone::Fixed);
        }
        s.parse::<Tz>().ok().map(Zone::Region)
    }

    /// The zone's offset from UTC at `at`.
    pub fn offset_at(&self, at: DateTime<Utc>) -> FixedOffset {
        match self {
            Zone::Region(tz) => tz.offset_from_utc_datetime(&at.naive_utc()).fix(),
            Zone::Fixed(o) => *o,
        }
    }

    /// The local date at `at`.
    pub fn today(&self, at: DateTime<Utc>) -> NaiveDate {
        (at.naive_utc() + Duration::seconds(self.offset_at(at).local_minus_utc() as i64)).date()
    }

    /// The UTC instant local midnight of `d` is. In a gap (a DST change at midnight) the
    /// first instant after it.
    pub fn midnight_utc(&self, d: NaiveDate) -> DateTime<Utc> {
        let naive = d.and_hms_opt(0, 0, 0).unwrap_or_default();
        match self {
            Zone::Region(tz) => match tz.from_local_datetime(&naive) {
                chrono::LocalResult::Single(t) | chrono::LocalResult::Ambiguous(t, _) => t.with_timezone(&Utc),
                chrono::LocalResult::None => {
                    let later = naive + Duration::hours(1);
                    tz.from_local_datetime(&later).earliest().map(|t| t.with_timezone(&Utc)).unwrap_or_else(|| Utc.from_utc_datetime(&naive))
                }
            },
            Zone::Fixed(o) => Utc.from_utc_datetime(&(naive - Duration::seconds(o.local_minus_utc() as i64))),
        }
    }
}

/// `±hh:mm` (or `±hh`, `±hhmm`) as an offset.
fn parse_offset(s: &str) -> Option<FixedOffset> {
    let sign = if s.starts_with('-') { -1 } else { 1 };
    let body: String = s[1..].chars().filter(|c| *c != ':').collect();
    if !body.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (h, m) = match body.len() {
        1 | 2 => (body.parse::<i32>().ok()?, 0),
        4 => (body[..2].parse::<i32>().ok()?, body[2..].parse::<i32>().ok()?),
        _ => return None,
    };
    if h > 18 || m > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

/// The offset as MySQL's `CONVERT_TZ` takes it: `+05:30`; `UTC` for zero.
pub fn mysql_offset(o: FixedOffset) -> String {
    let secs = o.local_minus_utc();
    if secs == 0 {
        return "UTC".into();
    }
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.abs();
    format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60)
}

pub const PERIODS: [&str; 15] = [
    "TODAY",
    "YESTERDAY",
    "THIS_WEEK",
    "THIS_MONTH",
    "LAST_MONTH",
    "LAST_7_DAYS",
    "LAST_30_DAYS",
    "LAST_90_DAYS",
    "THIS_QUARTER",
    "LAST_QUARTER",
    "THIS_FY",
    "LAST_FY",
    "LAST_12_MONTHS",
    "ALL_TIME",
    "CUSTOM",
];

/// A resolved period: local dates, both inclusive; none for ALL_TIME.
#[derive(Debug, Clone, PartialEq)]
pub struct Period {
    pub name: String,
    pub range: Option<(NaiveDate, NaiveDate)>,
    pub label: String,
}

impl Period {
    /// The output's `period`: `{"from":"2026-10-01","to":"2026-12-31","label":"This quarter"}`.
    pub fn to_json(&self) -> serde_json::Value {
        let (from, to) = match self.range {
            Some((f, t)) => (serde_json::Value::from(iso_date(f)), serde_json::Value::from(iso_date(t))),
            None => (serde_json::Value::Null, serde_json::Value::Null),
        };
        serde_json::json!({ "from": from, "to": to, "label": self.label })
    }
}

pub fn iso_date(d: NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

fn month_start(y: i32, m: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, 1).unwrap_or_default()
}

/// The first day of the month `n` months after `y`/`m` (n may be negative).
fn add_months(d: NaiveDate, n: i32) -> NaiveDate {
    let total = d.year() * 12 + d.month0() as i32 + n;
    month_start(total.div_euclid(12), total.rem_euclid(12) as u32 + 1)
}

/// The start of the quarter `d` is in, quarters starting on `fy_start` (1 to 12).
pub fn quarter_start(d: NaiveDate, fy_start: u32) -> NaiveDate {
    let months_in = (d.month0() as i32 - (fy_start as i32 - 1)).rem_euclid(3);
    add_months(month_start(d.year(), d.month()), -months_in)
}

/// The start of the financial year `d` is in.
pub fn fy_start_of(d: NaiveDate, fy_start: u32) -> NaiveDate {
    let year = if d.month() >= fy_start { d.year() } else { d.year() - 1 };
    month_start(year, fy_start)
}

/// Resolves a named period on `today`. `custom` holds CUSTOM's `from` / `to`. `Err` holds the
/// reason a CUSTOM range or an unknown name is refused.
pub fn resolve(name: &str, today: NaiveDate, fy_start: u32, custom: Option<(&str, &str)>) -> Result<Period, String> {
    let d = today;
    let month = month_start(d.year(), d.month());
    let q = quarter_start(d, fy_start);
    let fy = fy_start_of(d, fy_start);
    let last_day = |next_start: NaiveDate| next_start - Duration::days(1);
    let (range, label) = match name {
        "TODAY" => ((d, d), "Today".to_string()),
        "YESTERDAY" => ((d - Duration::days(1), d - Duration::days(1)), "Yesterday".into()),
        "THIS_WEEK" => {
            let monday = d - Duration::days(d.weekday().num_days_from_monday() as i64);
            ((monday, monday + Duration::days(6)), "This week".into())
        }
        "THIS_MONTH" => ((month, last_day(add_months(month, 1))), "This month".into()),
        "LAST_MONTH" => ((add_months(month, -1), last_day(month)), "Last month".into()),
        "LAST_7_DAYS" => ((d - Duration::days(6), d), "Last 7 days".into()),
        "LAST_30_DAYS" => ((d - Duration::days(29), d), "Last 30 days".into()),
        "LAST_90_DAYS" => ((d - Duration::days(89), d), "Last 90 days".into()),
        "THIS_QUARTER" => ((q, last_day(add_months(q, 3))), "This quarter".into()),
        "LAST_QUARTER" => ((add_months(q, -3), last_day(q)), "Last quarter".into()),
        "THIS_FY" => ((fy, last_day(add_months(fy, 12))), "This FY".into()),
        "LAST_FY" => ((add_months(fy, -12), last_day(fy)), "Last FY".into()),
        "LAST_12_MONTHS" => ((add_months(month, -11), last_day(add_months(month, 1))), "Last 12 months".into()),
        "ALL_TIME" => return Ok(Period { name: name.into(), range: None, label: "All time".into() }),
        "CUSTOM" => {
            let Some((f, t)) = custom else { return Err("CUSTOM needs from and to (ISO dates)".into()) };
            let parse = |s: &str| NaiveDate::parse_from_str(s.get(..10).unwrap_or(s), "%Y-%m-%d").ok();
            let (Some(from), Some(to)) = (parse(f), parse(t)) else {
                return Err(format!("CUSTOM from '{f}' / to '{t}' are not ISO dates"));
            };
            if from > to {
                return Err("CUSTOM from is after to".into());
            }
            let label = format!("{} to {}", from.format("%-d %b %Y"), to.format("%-d %b %Y"));
            ((from, to), label)
        }
        other => return Err(format!("'{other}' is not a period")),
    };
    Ok(Period { name: name.into(), range: Some(range), label })
}

/// A date bucket of the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Day,
    Week,
    Month,
    Quarter,
    Year,
}

impl Bucket {
    pub fn parse(s: &str) -> Option<Bucket> {
        match s {
            "DAY" => Some(Bucket::Day),
            "WEEK" => Some(Bucket::Week),
            "MONTH" => Some(Bucket::Month),
            "QUARTER" => Some(Bucket::Quarter),
            "YEAR" => Some(Bucket::Year),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Bucket::Day => "DAY",
            Bucket::Week => "WEEK",
            Bucket::Month => "MONTH",
            Bucket::Quarter => "QUARTER",
            Bucket::Year => "YEAR",
        }
    }

    /// The storage layer's unit as an aggregate query names it. A week starts on Monday (ISO).
    pub fn query_name(&self) -> &'static str {
        match self {
            Bucket::Day => "DAY",
            Bucket::Week => "ISO_WEEK",
            Bucket::Month => "MONTH",
            Bucket::Quarter => "QUARTER",
            Bucket::Year => "YEAR",
        }
    }

    /// The storage layer's unit. A week starts on Monday (ISO).
    pub fn unit(&self) -> appdata::model::DateBucketUnit {
        use appdata::model::DateBucketUnit as U;
        match self {
            Bucket::Day => U::Day,
            Bucket::Week => U::IsoWeek,
            Bucket::Month => U::Month,
            Bucket::Quarter => U::Quarter,
            Bucket::Year => U::Year,
        }
    }

    /// The start of the bucket `d` is in (`fy_start` is 1 unless the bucket is FY aware).
    pub fn start(&self, d: NaiveDate, fy_start: u32) -> NaiveDate {
        match self {
            Bucket::Day => d,
            Bucket::Week => d - Duration::days(d.weekday().num_days_from_monday() as i64),
            Bucket::Month => month_start(d.year(), d.month()),
            Bucket::Quarter => quarter_start(d, fy_start),
            Bucket::Year => fy_start_of(d, fy_start),
        }
    }

    /// The next bucket's start after the one starting at `start`.
    pub fn next(&self, start: NaiveDate) -> NaiveDate {
        match self {
            Bucket::Day => start + Duration::days(1),
            Bucket::Week => start + Duration::days(7),
            Bucket::Month => add_months(start, 1),
            Bucket::Quarter => add_months(start, 3),
            Bucket::Year => add_months(start, 12),
        }
    }

    /// "17 Nov", "Week of 17 Nov", "Nov 2026", "Q3 FY26" / "Q4 2026", "FY27" / "2026". An FY
    /// is named by the year it ends in (April 2025 to March 2026 is FY26).
    pub fn label(&self, start: NaiveDate, fy: bool, fy_start: u32) -> String {
        match self {
            Bucket::Day => start.format("%-d %b").to_string(),
            Bucket::Week => format!("Week of {}", start.format("%-d %b")),
            Bucket::Month => start.format("%b %Y").to_string(),
            Bucket::Quarter if fy => {
                let fy_begin = fy_start_of(start, fy_start);
                let n = (start.year() * 12 + start.month0() as i32 - (fy_begin.year() * 12 + fy_begin.month0() as i32)) / 3 + 1;
                format!("Q{n} FY{:02}", fy_end_year(fy_begin, fy_start) % 100)
            }
            Bucket::Quarter => format!("Q{} {}", start.month0() / 3 + 1, start.year()),
            Bucket::Year if fy => format!("FY{:02}", fy_end_year(start, fy_start) % 100),
            Bucket::Year => start.year().to_string(),
        }
    }
}

/// The calendar year an FY starting at `fy_begin` ends in.
fn fy_end_year(fy_begin: NaiveDate, fy_start: u32) -> i32 {
    if fy_start == 1 {
        fy_begin.year()
    } else {
        fy_begin.year() + 1
    }
}

/// A bucket key as the storage answered it, as the local date its bucket starts on. The
/// key is the bucket's start in UTC: an ISO text (`2026-10-31T18:30:00Z`), a datetime text,
/// or an epoch number (`millis` true for milliseconds); `offset` brings it back to the zone.
pub fn bucket_local_date(v: &serde_json::Value, offset: FixedOffset, millis: Option<bool>) -> Option<NaiveDate> {
    let utc: NaiveDateTime = match v {
        serde_json::Value::Number(n) => {
            let n = n.as_f64()?;
            let secs = if millis == Some(true) { n / 1000.0 } else { n };
            DateTime::from_timestamp(secs.floor() as i64, 0)?.naive_utc()
        }
        serde_json::Value::String(s) => parse_naive(s)?,
        _ => return None,
    };
    Some((utc + Duration::seconds(offset.local_minus_utc() as i64)).date())
}

fn parse_naive(s: &str) -> Option<NaiveDateTime> {
    let t = s.trim().trim_end_matches('Z');
    let t = t.get(..19).unwrap_or(t);
    for f in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"] {
        if let Ok(d) = NaiveDateTime::parse_from_str(t, f) {
            return Some(d);
        }
    }
    NaiveDate::parse_from_str(t.get(..10).unwrap_or(t), "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0))
}

/// The UTC instant as the `YYYY-MM-DDTHH:MM:SS` text ISO-string columns are compared with.
/// No `Z`: a stored `...:00Z` or `...:00.123Z` then sorts at or after the bound, as it should.
pub fn iso_bound(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// The UTC instant as a DATETIME column is compared with.
pub fn datetime_bound(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}
