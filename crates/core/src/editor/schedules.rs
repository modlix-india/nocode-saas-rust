//! `ScheduleConverter` and `EventScheduleViewService`: the builder's schedule model (every N
//! minutes, hourly, weekly, monthly, custom) to and from the UTC cron an EventDefinition
//! stores, with a description and the next runs in the viewer's zone; the zones a schedule may
//! use; and every client's view of one event's schedule.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Datelike, NaiveDate, Offset, TimeZone, Utc};
use overridable::{JMap, JValue};
use platform::security::ContextAuthentication;

use crate::cron::{parse_cron, zone_of, JavaZone};

pub const MINUTE_STEPS: [i32; 11] = [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30];
pub const HOUR_STEPS: [i32; 7] = [1, 2, 3, 4, 6, 8, 12];
const DAY_MINUTES: i32 = 1440;
const DAY_NAMES: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
const DAY_LABELS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const NEXT_RUNS: usize = 3;

/// `ScheduleModel`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScheduleModel {
    pub frequency: Option<String>,
    pub every: Option<i32>,
    pub minute: Option<i32>,
    pub hour: Option<i32>,
    pub days: Option<Vec<i32>>,
    pub day_of_month: Option<String>,
    pub cron: Option<String>,
}

/// What Java throws while converting (an `IllegalArgumentException`, a
/// `NumberFormatException`): the caller's 500.
#[derive(Debug, Clone, PartialEq)]
pub struct Thrown(pub String);

type R<T> = Result<T, Thrown>;

fn java_int(s: &str) -> R<i32> {
    s.parse::<i32>().map_err(|_| Thrown(format!("For input string: \"{s}\"")))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn floor_mod(n: i32, m: i32) -> i32 {
    n.rem_euclid(m)
}

fn nz(v: Option<i32>, fallback: i32) -> i32 {
    v.unwrap_or(fallback)
}

impl ScheduleModel {
    /// Jackson reading the body: `None` for a body it cannot read.
    pub fn from_json(v: &JValue) -> Option<Self> {
        let m = match v {
            JValue::Object(m) => m,
            JValue::Null => return Some(Self::default()),
            _ => return None,
        };
        let s = |k: &str| -> Option<Option<String>> {
            match m.get(k) {
                None | Some(JValue::Null) => Some(None),
                Some(JValue::Object(_)) | Some(JValue::Array(_)) => None,
                Some(x) => Some(Some(x.java_to_string())),
            }
        };
        let i = |k: &str| -> Option<Option<i32>> {
            match m.get(k) {
                None | Some(JValue::Null) => Some(None),
                Some(JValue::Int(n)) => Some(Some(*n as i32)),
                Some(JValue::Float(f)) => Some(Some(*f as i32)),
                Some(JValue::Str(t)) if t.trim().is_empty() => Some(None),
                Some(JValue::Str(t)) => t.trim().parse::<i32>().ok().map(Some),
                _ => None,
            }
        };
        let days = match m.get("days") {
            None | Some(JValue::Null) => None,
            Some(JValue::Array(a)) => {
                let mut out = Vec::new();
                for x in a {
                    match x {
                        JValue::Int(n) => out.push(*n as i32),
                        JValue::Float(f) => out.push(*f as i32),
                        JValue::Str(t) => out.push(t.trim().parse::<i32>().ok()?),
                        _ => return None,
                    }
                }
                Some(out)
            }
            Some(_) => return None,
        };
        Some(Self {
            frequency: s("frequency")?,
            every: i("every")?,
            minute: i("minute")?,
            hour: i("hour")?,
            days,
            day_of_month: s("dayOfMonth")?,
            cron: s("cron")?,
        })
    }

    /// Jackson writing it (`NON_EMPTY`).
    pub fn to_json(&self) -> JValue {
        let mut m = JMap::new();
        let mut put_s = |k: &str, v: &Option<String>| {
            if let Some(x) = v.as_ref().filter(|x| !x.is_empty()) {
                m.insert(k.into(), JValue::Str(x.clone()));
            }
        };
        put_s("frequency", &self.frequency);
        let mut m2 = m;
        for (k, v) in [("every", self.every), ("minute", self.minute), ("hour", self.hour)] {
            if let Some(x) = v {
                m2.insert(k.into(), JValue::Int(x as i64));
            }
        }
        if let Some(d) = self.days.as_ref().filter(|d| !d.is_empty()) {
            m2.insert("days".into(), JValue::Array(d.iter().map(|x| JValue::Int(*x as i64)).collect()));
        }
        if let Some(x) = self.day_of_month.as_ref().filter(|x| !x.is_empty()) {
            m2.insert("dayOfMonth".into(), JValue::Str(x.clone()));
        }
        if let Some(x) = self.cron.as_ref().filter(|x| !x.is_empty()) {
            m2.insert("cron".into(), JValue::Str(x.clone()));
        }
        JValue::Object(m2)
    }

    fn frequency(&self) -> &str {
        self.frequency.as_deref().unwrap_or("off")
    }
}

fn base() -> ScheduleModel {
    ScheduleModel {
        frequency: Some("off".into()),
        every: Some(5),
        minute: Some(0),
        hour: Some(9),
        days: Some(vec![1, 2, 3, 4, 5]),
        day_of_month: Some("1".into()),
        cron: Some(String::new()),
    }
}

struct Shift {
    hour: i32,
    minute: i32,
    days: i32,
}

fn shift(hour: i32, minute: i32, by: i32) -> Shift {
    let t = hour * 60 + minute + by;
    let local = floor_mod(t, DAY_MINUTES);
    Shift { hour: local / 60, minute: local % 60, days: t.div_euclid(DAY_MINUTES) }
}

fn join(values: &BTreeSet<i32>) -> String {
    values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
}

fn shift_day_of_month(day: Option<&str>, shift: i32) -> R<String> {
    match day {
        None | Some("L") => Ok(if shift == 0 {
            "L".into()
        } else if shift > 0 {
            "1".into()
        } else {
            "L-1".into()
        }),
        Some(d) => {
            let n = java_int(d)? + shift;
            Ok(if n < 1 { "L".into() } else { n.to_string() })
        }
    }
}

/// `ScheduleConverter.toUtcCron`: the model, read at `offset` minutes from UTC, as a UTC cron.
pub fn to_utc_cron(m: &ScheduleModel, offset: i32) -> R<String> {
    match m.frequency() {
        "off" => Ok(String::new()),
        "custom" => Ok(m.cron.as_deref().map(|c| c.trim().to_string()).unwrap_or_default()),
        "minutes" => {
            let every = nz(m.every, 5);
            Ok(if every <= 1 { "* * * * *".into() } else { format!("*/{every} * * * *") })
        }
        "hours" => {
            let every = nz(m.every, 1).max(1);
            let minute = nz(m.minute, 0);
            if every == 1 {
                return Ok(format!("{} * * * *", floor_mod(minute - offset, 60)));
            }
            let mut hours = BTreeSet::new();
            let mut h = floor_mod(nz(m.hour, 0), every);
            while h < 24 {
                hours.insert(floor_mod(h * 60 + minute - offset, DAY_MINUTES).div_euclid(60));
                h += every;
            }
            Ok(format!("{} {} * * *", floor_mod(minute - offset, 60), join(&hours)))
        }
        "weekly" => {
            let s = shift(nz(m.hour, 9), nz(m.minute, 0), -offset);
            let days = m.days.clone().unwrap_or_default();
            let dow = if days.is_empty() || days.len() >= 7 {
                "*".into()
            } else {
                join(&days.iter().map(|d| floor_mod(d + s.days, 7)).collect())
            };
            Ok(format!("{} {} * * {dow}", s.minute, s.hour))
        }
        "monthly" => {
            let s = shift(nz(m.hour, 9), nz(m.minute, 0), -offset);
            Ok(format!("{} {} {} * *", s.minute, s.hour, shift_day_of_month(m.day_of_month.as_deref(), s.days)?))
        }
        other => Err(Thrown(format!("Unknown frequency: {other}"))),
    }
}

/// `normalise(cron)`: the five fields (a leading `0` seconds field dropped, the macros
/// expanded, `?` read as `*`), upper case; `None` for anything else.
pub fn normalise_cron(cron: &str) -> Option<Vec<String>> {
    let mut text = cron.trim().to_string();
    if text.starts_with('@') {
        text = match text.to_lowercase().as_str() {
            "@hourly" => "0 * * * *",
            "@daily" | "@midnight" => "0 0 * * *",
            "@weekly" => "0 0 * * 0",
            "@monthly" => "0 0 1 * *",
            "@yearly" | "@annually" => "0 0 1 1 *",
            _ => return None,
        }
        .to_string();
    }
    let mut fields: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    if fields.len() == 6 {
        if fields[0] != "0" {
            return None;
        }
        fields.remove(0);
    }
    if fields.len() != 5 {
        return None;
    }
    Some(fields.into_iter().map(|f| if f == "?" { "*".into() } else { f.to_uppercase() }).collect())
}

fn value(s: &str, names: Option<&[&str]>) -> R<Option<i32>> {
    if let Some(n) = names {
        if let Some(i) = n.iter().position(|x| *x == s) {
            return Ok(Some(i as i32));
        }
    }
    if is_digits(s) {
        return java_int(s).map(Some);
    }
    Ok(None)
}

/// `expand(field, min, max, names)`: the values a cron field lists, `None` when it is not a
/// plain list of values, ranges and steps.
pub fn expand(field: &str, min: i32, max: i32, names: Option<&[&str]>) -> R<Option<Vec<i32>>> {
    let mut out = BTreeSet::new();
    for part in field.split(',') {
        let rs: Vec<&str> = part.split('/').collect();
        let range = rs[0];
        let step = if rs.len() > 1 {
            match rs[1].parse::<i32>() {
                Ok(s) => s,
                Err(_) => return Ok(None),
            }
        } else {
            1
        };
        if step < 1 {
            return Ok(None);
        }
        let (lo, hi) = if range == "*" {
            (Some(min), Some(max))
        } else if range.contains('-') {
            let ab: Vec<&str> = range.split('-').collect();
            (value(ab[0], names)?, if ab.len() > 1 { value(ab[1], names)? } else { None })
        } else {
            let lo = value(range, names)?;
            (lo, if rs.len() > 1 { Some(max) } else { lo })
        };
        let (Some(lo), Some(hi)) = (lo, hi) else { return Ok(None) };
        if lo < min || hi > max || lo > hi {
            return Ok(None);
        }
        let mut v = lo;
        while v <= hi {
            out.insert(v);
            v += step;
        }
    }
    Ok(Some(out.into_iter().collect()))
}

fn is_num(s: &str, max: i32) -> R<bool> {
    Ok(is_digits(s) && java_int(s)? <= max)
}

fn unshift_day_of_month(dom: &str, shift: i32) -> R<Option<String>> {
    if dom == "L" {
        return Ok(if shift == 0 {
            Some("L".into())
        } else if shift > 0 {
            Some("1".into())
        } else {
            None
        });
    }
    if dom == "L-1" {
        return Ok((shift == 1).then(|| "L".into()));
    }
    if !is_num(dom, 31)? {
        return Ok(None);
    }
    let d = java_int(dom)? + shift;
    Ok((1..=28).contains(&d).then(|| d.to_string()))
}

/// `ScheduleConverter.fromCron`: a stored cron as the builder's model, read `delta` minutes
/// from the cron's zone; `custom` for a cron the model cannot say.
pub fn from_cron(cron: Option<&str>, delta: i32) -> R<ScheduleModel> {
    let raw = cron.unwrap_or("").trim().to_string();
    if raw.is_empty() {
        return Ok(ScheduleModel { frequency: Some("off".into()), ..base() });
    }
    let custom = ScheduleModel { frequency: Some("custom".into()), cron: Some(raw.clone()), ..base() };
    let Some(f) = normalise_cron(&raw) else { return Ok(custom) };
    let (mi, ho, dom, mon, dow) = (&f[0], &f[1], &f[2], &f[3], &f[4]);
    if mon != "*" {
        return Ok(custom);
    }
    if ho == "*" && dom == "*" && dow == "*" {
        if mi == "*" {
            return Ok(ScheduleModel { frequency: Some("minutes".into()), every: Some(1), ..base() });
        }
        let step = mi.strip_prefix("*/").or_else(|| mi.strip_prefix("0/")).filter(|s| is_digits(s));
        if let Some(s) = step {
            let every = java_int(s)?;
            return Ok(if MINUTE_STEPS.contains(&every) {
                ScheduleModel { frequency: Some("minutes".into()), every: Some(every), ..base() }
            } else {
                custom
            });
        }
        if is_num(mi, 59)? {
            return Ok(ScheduleModel {
                frequency: Some("hours".into()),
                every: Some(1),
                hour: Some(0),
                minute: Some(floor_mod(java_int(mi)? + delta, 60)),
                ..base()
            });
        }
        return Ok(custom);
    }
    if !is_num(mi, 59)? {
        return Ok(custom);
    }
    let m = java_int(mi)?;
    let Some(hours) = expand(ho, 0, 23, None)? else { return Ok(custom) };
    if hours.is_empty() {
        return Ok(custom);
    }
    if hours.len() > 1 {
        if dom != "*" || dow != "*" {
            return Ok(custom);
        }
        let local: Vec<i32> = hours.iter().map(|h| floor_mod(h * 60 + m + delta, DAY_MINUTES)).collect();
        let minute = local[0] % 60;
        let mut lh: Vec<i32> = local.iter().map(|t| t / 60).collect();
        lh.sort();
        if 24 % lh.len() as i32 != 0 {
            return Ok(custom);
        }
        let every = 24 / lh.len() as i32;
        if !HOUR_STEPS.contains(&every) {
            return Ok(custom);
        }
        for i in 1..lh.len() {
            if lh[i] - lh[i - 1] != every {
                return Ok(custom);
            }
        }
        return Ok(ScheduleModel { frequency: Some("hours".into()), every: Some(every), hour: Some(lh[0]), minute: Some(minute), ..base() });
    }
    let s = shift(hours[0], m, delta);
    if dom == "*" {
        let days = if dow == "*" { Some(vec![0, 1, 2, 3, 4, 5, 6]) } else { expand(dow, 0, 7, Some(&DAY_NAMES))? };
        let Some(days) = days.filter(|d| !d.is_empty()) else { return Ok(custom) };
        let mut local: Vec<i32> = Vec::new();
        for d in days {
            let v = floor_mod(d % 7 + s.days, 7);
            if !local.contains(&v) {
                local.push(v);
            }
        }
        local.sort();
        return Ok(ScheduleModel { frequency: Some("weekly".into()), hour: Some(s.hour), minute: Some(s.minute), days: Some(local), ..base() });
    }
    if dow != "*" {
        return Ok(custom);
    }
    Ok(match unshift_day_of_month(dom, s.days)? {
        Some(day) => ScheduleModel { frequency: Some("monthly".into()), hour: Some(s.hour), minute: Some(s.minute), day_of_month: Some(day), ..base() },
        None => custom,
    })
}

fn time(hour: i32, minute: i32) -> String {
    format!("{hour:02}:{minute:02}")
}

/// `ScheduleConverter.describe`.
pub fn describe(m: &ScheduleModel, zone_label: Option<&str>) -> R<String> {
    let at = time(nz(m.hour, 0), nz(m.minute, 0));
    let r#in = zone_label.map(|z| format!(" ({z})")).unwrap_or_default();
    Ok(match m.frequency() {
        "off" => "Not scheduled".into(),
        "custom" => format!("Custom cron {} (UTC)", m.cron.as_deref().unwrap_or("")),
        "minutes" => {
            if nz(m.every, 1) <= 1 {
                "Every minute".into()
            } else {
                format!("Every {} minutes", m.every.map(|e| e.to_string()).unwrap_or_else(|| "null".into()))
            }
        }
        "hours" => {
            if nz(m.every, 1) <= 1 {
                format!("Every hour at :{:02}{}", nz(m.minute, 0), r#in)
            } else {
                format!("Every {} hours from {at}{}", m.every.map(|e| e.to_string()).unwrap_or_default(), r#in)
            }
        }
        "weekly" => {
            let d = m.days.clone().unwrap_or_default();
            let days = if d.len() >= 7 || d.is_empty() {
                "Every day".to_string()
            } else if d == [1, 2, 3, 4, 5] {
                "Weekdays".to_string()
            } else {
                let mut labels = Vec::new();
                for x in &d {
                    let l = usize::try_from(*x).ok().and_then(|i| DAY_LABELS.get(i)).ok_or_else(|| Thrown(format!("Index {x} out of bounds for length 7")))?;
                    labels.push(*l);
                }
                labels.join(", ")
            };
            format!("{days} at {at}{}", r#in)
        }
        "monthly" => {
            let day = if m.day_of_month.as_deref() == Some("L") {
                "Last day".to_string()
            } else {
                format!("Day {}", m.day_of_month.as_deref().unwrap_or("null"))
            };
            format!("{day} of every month at {at}{}", r#in)
        }
        other => other.to_string(),
    })
}

/// `ZoneOffset` seconds of `zone` at `at`.
pub fn offset_seconds(zone: &JavaZone, at: DateTime<Utc>) -> i32 {
    match zone {
        JavaZone::Fixed(s) => *s,
        JavaZone::Region(tz) => tz.offset_from_utc_datetime(&at.naive_utc()).fix().local_minus_utc(),
        JavaZone::SystemV(standard) => *standard,
    }
}

pub fn offset_minutes(zone: &JavaZone, at: DateTime<Utc>) -> i32 {
    offset_seconds(zone, at) / 60
}

/// Whether the zone's offset in January differs from July's.
pub fn observes_dst(zone: &JavaZone, year: i32) -> bool {
    let at = |m: u32| Utc.from_utc_datetime(&NaiveDate::from_ymd_opt(year, m, 1).unwrap_or_default().and_hms_opt(0, 0, 0).unwrap_or_default());
    offset_minutes(zone, at(1)) != offset_minutes(zone, at(7))
}

/// `UTC+05:30`.
pub fn format_offset(minutes: i32) -> String {
    let a = minutes.abs();
    format!("UTC{}{:02}:{:02}", if minutes < 0 { "-" } else { "+" }, a / 60, a % 60)
}

/// `ScheduleConverter.nextRuns`: the next `count` runs of a cron read in `cron_zone`, written
/// in `display` (`EEE d MMM yyyy, HH:mm`).
pub fn next_runs(cron: &str, cron_zone: &JavaZone, display: &JavaZone, from: DateTime<Utc>, count: usize) -> R<Vec<String>> {
    let expr = parse_cron(cron).map_err(Thrown)?;
    let mut out = Vec::new();
    let mut t = from;
    for _ in 0..count {
        let Some(next) = expr.next(t, cron_zone) else { break };
        t = next;
        let local = next.naive_utc() + chrono::Duration::seconds(offset_seconds(display, next) as i64);
        out.push(local.format("%a %-d %b %Y, %H:%M").to_string());
    }
    Ok(out)
}

/// `ZoneId.of(zone)`, UTC for a blank or unknown one; with the id Java reports for it.
pub fn zone_or_utc(zone: Option<&str>) -> (JavaZone, String) {
    match zone.map(str::trim).filter(|z| !z.is_empty()) {
        None => (JavaZone::Fixed(0), "UTC".into()),
        Some(z) => match zone_of(z) {
            Ok(j) => (j, z.to_string()),
            Err(_) => (JavaZone::Fixed(0), "UTC".into()),
        },
    }
}

/// `EventScheduleViewService.normalise`: the model with every value it needs in range.
pub fn normalise_model(mut m: ScheduleModel) -> ScheduleModel {
    if m.frequency.is_none() {
        m.frequency = Some("off".into());
    }
    if m.minute.is_none_or(|x| !(0..=59).contains(&x)) {
        m.minute = Some(0);
    }
    if m.hour.is_none_or(|x| !(0..=23).contains(&x)) {
        m.hour = Some(9);
    }
    if m.frequency() == "minutes" && !m.every.is_some_and(|e| MINUTE_STEPS.contains(&e)) {
        m.every = Some(5);
    }
    if m.frequency() == "hours" {
        if !m.every.is_some_and(|e| HOUR_STEPS.contains(&e)) {
            m.every = Some(1);
        }
        m.hour = Some(nz(m.hour, 9) % nz(m.every, 1));
    }
    if m.days.as_ref().is_none_or(|d| d.is_empty()) {
        m.days = Some(vec![1, 2, 3, 4, 5]);
    }
    if m.day_of_month.as_ref().is_none_or(|d| d.trim().is_empty()) {
        m.day_of_month = Some("1".into());
    }
    m
}

/// `SchedulePreview`.
#[derive(Debug, Clone)]
pub struct SchedulePreview {
    pub cron: String,
    pub timezone: String,
    pub model: ScheduleModel,
    pub display_zone: String,
    pub description: String,
    pub next_runs: Vec<String>,
    pub observes_dst: bool,
    pub valid: bool,
    pub error: Option<String>,
}

impl SchedulePreview {
    /// Jackson (`NON_EMPTY`: the empty cron and the empty run list are left out).
    pub fn to_json(&self) -> JValue {
        let mut m = JMap::new();
        if !self.cron.is_empty() {
            m.insert("cron".into(), JValue::Str(self.cron.clone()));
        }
        m.insert("timezone".into(), JValue::Str(self.timezone.clone()));
        let model = self.model.to_json();
        if !model.is_jackson_empty() {
            m.insert("model".into(), model);
        }
        m.insert("displayZone".into(), JValue::Str(self.display_zone.clone()));
        if !self.description.is_empty() {
            m.insert("description".into(), JValue::Str(self.description.clone()));
        }
        if !self.next_runs.is_empty() {
            m.insert("nextRuns".into(), JValue::Array(self.next_runs.iter().cloned().map(JValue::Str).collect()));
        }
        m.insert("observesDst".into(), JValue::Bool(self.observes_dst));
        m.insert("valid".into(), JValue::Bool(self.valid));
        if let Some(e) = self.error.as_ref().filter(|e| !e.is_empty()) {
            m.insert("error".into(), JValue::Str(e.clone()));
        }
        JValue::Object(m)
    }
}

fn preview(cron: &str, cron_zone: (&JavaZone, &str), display: (&JavaZone, &str), model: ScheduleModel, now: DateTime<Utc>) -> R<SchedulePreview> {
    let mut p = SchedulePreview {
        cron: cron.to_string(),
        timezone: cron_zone.1.to_string(),
        description: describe(&model, Some(display.1))?,
        model,
        display_zone: display.1.to_string(),
        next_runs: Vec::new(),
        observes_dst: observes_dst(display.0, now.year()),
        valid: true,
        error: None,
    };
    if cron.is_empty() {
        return Ok(p);
    }
    match next_runs(cron, cron_zone.0, display.0, now, NEXT_RUNS) {
        Ok(runs) => p.next_runs = runs,
        Err(e) => {
            p.valid = false;
            p.error = Some(format!("The scheduler cannot read this cron: {}", e.0));
        }
    }
    Ok(p)
}

/// `EventScheduleViewService.toCron`.
pub fn to_cron(model: ScheduleModel, zone: Option<&str>, now: DateTime<Utc>) -> R<SchedulePreview> {
    let (display, display_id) = zone_or_utc(zone);
    let offset = offset_minutes(&display, now);
    let model = normalise_model(model);
    let cron = to_utc_cron(&model, offset)?;
    let shown = if cron.is_empty() { model } else { from_cron(Some(&cron), offset)? };
    preview(&cron, (&JavaZone::Fixed(0), "UTC"), (&display, &display_id), shown, now)
}

/// `EventScheduleViewService.fromCron`.
pub fn from_cron_preview(cron: Option<&str>, cron_zone: Option<&str>, zone: Option<&str>, now: DateTime<Utc>) -> R<SchedulePreview> {
    let (display, display_id) = zone_or_utc(zone);
    let (stored, stored_id) = zone_or_utc(cron_zone);
    let delta = offset_minutes(&display, now) - offset_minutes(&stored, now);
    let model = from_cron(cron, delta)?;
    preview(cron.unwrap_or("").trim(), (&stored, &stored_id), (&display, &display_id), model, now)
}

/// `EventScheduleViewService.zones`: UTC, then every region with a `/` (no `Etc/`, no
/// `SystemV/`), sorted, labelled with its offset now.
pub fn zones(now: DateTime<Utc>) -> JValue {
    let mut names: Vec<&str> = chrono_tz::TZ_VARIANTS
        .iter()
        .map(|t| t.name())
        .filter(|z| z.contains('/') && !z.starts_with("Etc/") && !z.starts_with("SystemV/"))
        .collect();
    names.sort();
    let row = |zone: &str, label: String| {
        let mut m = JMap::new();
        m.insert("zone".into(), JValue::Str(zone.into()));
        m.insert("label".into(), JValue::Str(label));
        JValue::Object(m)
    };
    let mut out = vec![row("UTC", "UTC (UTC+00:00)".into())];
    for z in names {
        let off = zone_of(z).map(|j| offset_minutes(&j, now)).unwrap_or(0);
        out.push(row(z, format!("{z} ({})", format_offset(off))));
    }
    JValue::Array(out)
}

/// An `EventSchedule` description in the viewer's zone (`describe(schedule, display)`).
fn describe_schedule(s: Option<&crate::scheduler::EventSchedule>, display: (&JavaZone, &str), now: DateTime<Utc>) -> R<String> {
    let Some(s) = s.filter(|s| s.cron.as_deref().is_some_and(|c| !c.trim().is_empty())) else { return Ok("Not scheduled".into()) };
    let (stored, _) = zone_or_utc(s.timezone.as_deref());
    let delta = offset_minutes(display.0, now) - offset_minutes(&stored, now);
    describe(&from_cron(s.cron.as_deref(), delta)?, Some(display.1))
}

/// What one client's row needs that the view service reads elsewhere.
#[async_trait::async_trait]
pub trait ScheduleSources: Send + Sync {
    /// `readAllCopies(name, app)`: every client's stored copy.
    async fn copies(&self, app: &str, name: &str) -> Vec<JMap>;
    /// `getWriteAccessClientCodes(app)`; empty on a failure.
    async fn writers(&self, app: &str) -> Vec<String>;
    /// `runService.visibleAmong(ca, app, candidates, false)`.
    async fn visible_among(&self, own: &str, app: &str, candidates: &[String]) -> Result<Vec<String>, platform::error::AppError>;
    /// `runService.latestRuns`.
    async fn latest_runs(&self, app: &str, name: &str, clients: &[String]) -> HashMap<String, crate::event_runs::EventRun>;
    /// `readEffective(name, app, client)`'s schedule.
    async fn effective_schedule(&self, app: &str, name: &str, client: &str) -> Option<crate::scheduler::EventSchedule>;
    /// `readDraftWithVersion(copyId)`: the draft version (> 0) and its schedule.
    async fn draft(&self, ca: &ContextAuthentication, copy_id: &str) -> Option<(i64, Option<crate::scheduler::EventSchedule>)>;
    /// The client's name.
    async fn client_name(&self, client: &str) -> Option<String>;
}

fn schedule_json(s: &crate::scheduler::EventSchedule) -> Option<JValue> {
    let j = s.to_j();
    (!j.is_jackson_empty()).then_some(j)
}

/// `EventScheduleViewService.clientSchedules`: one page of the clients whose view of this event
/// the caller may read, holders of a copy first, then the caller's own client.
#[allow(clippy::too_many_arguments)]
pub async fn client_schedules(
    src: &dyn ScheduleSources,
    ca: &ContextAuthentication,
    app: &str,
    name: &str,
    zone: Option<&str>,
    client: Option<&str>,
    page: i64,
    size: i64,
    now: DateTime<Utc>,
) -> Result<JValue, platform::error::AppError> {
    let (display, display_id) = zone_or_utc(zone);
    let copies = src.copies(app, name).await;
    let writers = src.writers(app).await;
    let mut candidates: Vec<String> = Vec::new();
    for c in copies.iter().filter_map(|c| overridable::pojo::str_field(c, "clientCode")).chain(writers.iter().map(String::as_str)) {
        if !candidates.iter().any(|x| x == c) {
            candidates.push(c.to_string());
        }
    }
    let own = ca.client_code().to_string();
    let visible = src.visible_among(&own, app, &candidates).await?;
    let holders: HashSet<String> = copies.iter().filter_map(|c| overridable::pojo::str_field(c, "clientCode").map(str::to_string)).collect();
    let filter = client.map(str::trim).filter(|c| !c.is_empty());
    let mut ordered: Vec<String> = visible.into_iter().filter(|c| filter.is_none_or(|f| c == f)).collect();
    ordered.sort_by(|a, b| (!holders.contains(a), a != &own, a.as_str()).cmp(&(!holders.contains(b), b != &own, b.as_str())));
    let total = ordered.len() as i64;
    let from = (page * size).min(total) as usize;
    let to = (from + size as usize).min(ordered.len());
    let page_clients: Vec<String> = ordered[from..to].to_vec();
    let last_runs = src.latest_runs(app, name, &page_clients).await;

    let by_client: HashMap<String, &JMap> =
        copies.iter().filter_map(|c| overridable::pojo::str_field(c, "clientCode").map(|cc| (cc.to_string(), c))).collect();
    let roots: Vec<&JMap> = copies.iter().filter(|c| overridable::pojo::str_field(c, "baseClientCode").is_none_or(|b| b.trim().is_empty())).collect();
    let base_id = roots
        .iter()
        .find(|c| overridable::pojo::str_field(c, "clientCode") == Some(own.as_str()))
        .or_else(|| roots.first())
        .and_then(|c| overridable::pojo::str_field(c, "id"))
        .map(str::to_string);
    let writer_set: HashSet<&String> = writers.iter().collect();

    let mut rows = Vec::new();
    for c in &page_clients {
        let copy = by_client.get(c).copied();
        let live = src.effective_schedule(app, name, c).await;
        let draft = match copy.and_then(|cp| overridable::pojo::str_field(cp, "id")) {
            Some(id) => src.draft(ca, id).await,
            None => None,
        };
        let client_name = src.client_name(c).await.unwrap_or_else(|| c.clone());
        let writer = writer_set.contains(c);
        let own_schedule = copy.and_then(|cp| cp.get("schedule")).and_then(crate::scheduler::EventSchedule::from_j);
        let mut r = JMap::new();
        r.insert("clientCode".into(), JValue::Str(c.clone()));
        r.insert("clientName".into(), JValue::Str(client_name));
        r.insert("owner".into(), JValue::Bool(copy.is_some_and(|cp| overridable::pojo::str_field(cp, "baseClientCode").is_none_or(|b| b.trim().is_empty()))));
        if let Some(id) = copy.and_then(|cp| overridable::pojo::str_field(cp, "id")) {
            r.insert("copyId".into(), JValue::Str(id.into()));
        }
        if let Some(b) = copy.and_then(|cp| overridable::pojo::str_field(cp, "baseClientCode")).filter(|b| !b.is_empty()) {
            r.insert("baseClientCode".into(), JValue::Str(b.into()));
        }
        if let Some(b) = &base_id {
            r.insert("baseId".into(), JValue::Str(b.clone()));
        }
        if let Some(j) = own_schedule.as_ref().and_then(schedule_json) {
            r.insert("ownSchedule".into(), j);
        }
        if let Some(j) = live.as_ref().and_then(schedule_json) {
            r.insert("liveSchedule".into(), j);
        }
        let mut draft_description = None;
        if let Some((version, ds)) = &draft {
            if let Some(j) = ds.as_ref().and_then(schedule_json) {
                r.insert("draftSchedule".into(), j);
            }
            r.insert("draftVersion".into(), JValue::Int(*version));
            draft_description = Some(describe_schedule(ds.as_ref(), (&display, &display_id), now).map_err(|t| platform::error::AppError::Internal(anyhow::anyhow!(t.0)))?);
        }
        r.insert("hasWriteAccess".into(), JValue::Bool(writer));
        let holder = copy.is_some_and(|cp| cp.get("schedule").is_some_and(|s| !s.is_null()));
        let (state, reason, runs) = state_of(live.as_ref(), holder, writer, (&display, &display_id), now);
        r.insert("state".into(), JValue::Str(state.into()));
        r.insert("stateReason".into(), JValue::Str(reason));
        let description = describe_schedule(live.as_ref(), (&display, &display_id), now).unwrap_or_else(|t| t.0);
        r.insert("description".into(), JValue::Str(description));
        if let Some(d) = draft_description {
            r.insert("draftDescription".into(), JValue::Str(d));
        }
        if !runs.is_empty() {
            r.insert("nextRuns".into(), JValue::Array(runs.into_iter().map(JValue::Str).collect()));
        }
        if let Some(mut run) = last_runs.get(c).cloned() {
            crate::event_runs::decorate(&mut run, Some(&display_id));
            let j = overridable::json::parse(run.to_jackson().to_string().as_bytes()).unwrap_or_default();
            r.insert("lastRun".into(), j);
        }
        rows.push(JValue::Object(r));
    }
    let pageable = overridable::write::spring::Pageable::of(page, size, overridable::write::spring::Sort::unsorted());
    Ok(overridable::write::spring::page_json(rows, &pageable, total))
}

/// `state(...)`: whether the schedule runs for this client, and why not.
fn state_of(s: Option<&crate::scheduler::EventSchedule>, holder: bool, writer: bool, display: (&JavaZone, &str), now: DateTime<Utc>) -> (&'static str, String, Vec<String>) {
    let Some(s) = s.filter(|s| s.cron.as_deref().is_some_and(|c| !c.trim().is_empty())) else {
        return ("NOT_SCHEDULED", "No cron is set.".into(), Vec::new());
    };
    let zone = match zone_of(s.effective_timezone()) {
        Ok(z) => z,
        Err(e) => return ("INVALID", format!("The scheduler cannot read this schedule: {e}"), Vec::new()),
    };
    let cron = s.cron.clone().unwrap_or_default();
    if let Err(e) = parse_cron(&cron) {
        return ("INVALID", format!("The scheduler cannot read this schedule: {e}"), Vec::new());
    }
    if s.enabled == Some(false) {
        return ("PAUSED", "Paused.".into(), Vec::new());
    }
    let runs_here = if s.is_for_each_client() { writer } else { holder };
    if !runs_here {
        return (
            "NOT_RUNNING",
            if s.is_for_each_client() {
                "Runs once per client, but this client has no write access to the app.".into()
            } else {
                "Run once per client is off, so only clients whose own copy sets a schedule run it.".into()
            },
            Vec::new(),
        );
    }
    let runs = next_runs(&cron, &zone, display.0, now, NEXT_RUNS).unwrap_or_default();
    ("RUNS", String::new(), runs)
}

/// A default implementation of the sources, for wiring.
pub type Sources = Arc<dyn ScheduleSources>;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn m(f: &str) -> ScheduleModel {
        ScheduleModel { frequency: Some(f.into()), ..Default::default() }
    }

    // ── ScheduleConverterTest ──

    #[test]
    fn models_become_utc_crons() {
        assert_eq!(to_utc_cron(&m("off"), 0).unwrap(), "");
        assert_eq!(to_utc_cron(&ScheduleModel { cron: Some(" 0 5 * * * ".into()), ..m("custom") }, 0).unwrap(), "0 5 * * *");
        assert_eq!(to_utc_cron(&m("custom"), 0).unwrap(), "");
        assert_eq!(to_utc_cron(&ScheduleModel { every: Some(1), ..m("minutes") }, 0).unwrap(), "* * * * *");
        assert_eq!(to_utc_cron(&ScheduleModel { every: Some(15), ..m("minutes") }, 0).unwrap(), "*/15 * * * *");
        // India is UTC+05:30: 09:00 there is 03:30 UTC.
        assert_eq!(to_utc_cron(&ScheduleModel { every: Some(1), minute: Some(10), ..m("hours") }, 330).unwrap(), "40 * * * *");
        assert_eq!(to_utc_cron(&ScheduleModel { every: Some(6), hour: Some(0), minute: Some(0), ..m("hours") }, 330).unwrap(), "30 0,6,12,18 * * *");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(2), minute: Some(0), days: Some(vec![1]), ..m("weekly") }, 330).unwrap(), "30 20 * * 0");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(9), minute: Some(0), days: Some(vec![]), ..m("weekly") }, 0).unwrap(), "0 9 * * *");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(2), minute: Some(0), day_of_month: Some("1".into()), ..m("monthly") }, 330).unwrap(), "30 20 L * *");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(2), minute: Some(0), day_of_month: Some("5".into()), ..m("monthly") }, 330).unwrap(), "30 20 4 * *");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(23), minute: Some(0), day_of_month: Some("L".into()), ..m("monthly") }, -330).unwrap(), "30 4 1 * *");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(2), minute: Some(0), day_of_month: None, ..m("monthly") }, 330).unwrap(), "30 20 L-1 * *");
        assert_eq!(to_utc_cron(&ScheduleModel { hour: Some(9), minute: Some(0), day_of_month: Some("L".into()), ..m("monthly") }, 0).unwrap(), "0 9 L * *");
        assert!(to_utc_cron(&m("yearly"), 0).is_err());
        assert!(to_utc_cron(&ScheduleModel { day_of_month: Some("x".into()), ..m("monthly") }, 0).is_err());
    }

    #[test]
    fn crons_become_models() {
        assert_eq!(from_cron(None, 0).unwrap().frequency.as_deref(), Some("off"));
        assert_eq!(from_cron(Some("* * * * *"), 0).unwrap().every, Some(1));
        assert_eq!(from_cron(Some("*/15 * * * *"), 0).unwrap().every, Some(15));
        assert_eq!(from_cron(Some("0/7 * * * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        let h = from_cron(Some("40 * * * *"), 330).unwrap();
        assert_eq!((h.frequency.as_deref(), h.minute), (Some("hours"), Some(10)));
        let h = from_cron(Some("30 0,6,12,18 * * *"), 330).unwrap();
        assert_eq!((h.frequency.as_deref(), h.every, h.hour, h.minute), (Some("hours"), Some(6), Some(0), Some(0)));
        let w = from_cron(Some("30 20 * * 0"), 330).unwrap();
        assert_eq!((w.frequency.as_deref(), w.hour, w.minute, w.days.clone()), (Some("weekly"), Some(2), Some(0), Some(vec![1])));
        let w = from_cron(Some("0 9 * * MON-FRI"), 0).unwrap();
        assert_eq!(w.days, Some(vec![1, 2, 3, 4, 5]));
        let mo = from_cron(Some("30 20 L * *"), 330).unwrap();
        assert_eq!((mo.frequency.as_deref(), mo.day_of_month.as_deref()), (Some("monthly"), Some("1")));
        assert_eq!(from_cron(Some("0 9 30 * *"), 0).unwrap().frequency.as_deref(), Some("custom"), "past the 28th is custom");
        assert_eq!(from_cron(Some("30 20 L-1 * *"), 330).unwrap().day_of_month.as_deref(), Some("L"));
        assert_eq!(from_cron(Some("0 9 L-1 * *"), 330).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("30 20 L * *"), -1300).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 9 L * *"), 0).unwrap().day_of_month.as_deref(), Some("L"));
        assert_eq!(from_cron(Some("@daily"), 0).unwrap().frequency.as_deref(), Some("weekly"));
        assert_eq!(from_cron(Some("@nope"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 0 9 * * *"), 0).unwrap().frequency.as_deref(), Some("weekly"));
        assert_eq!(from_cron(Some("5 0 9 * * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 9 * 1 *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 1,5 * * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 1,5 1 * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("x 9 * * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 9 1 * MON"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 x * * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("0 9 * * x"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert_eq!(from_cron(Some("x * * * *"), 0).unwrap().frequency.as_deref(), Some("custom"));
        assert!(from_cron(Some("99999999999 9 * * *"), 0).is_err());
        assert_eq!(expand("1-3/2,5", 0, 7, None).unwrap(), Some(vec![1, 3, 5]));
        assert_eq!(expand("5/2", 0, 7, None).unwrap(), Some(vec![5, 7]));
        assert_eq!(expand("1/0", 0, 7, None).unwrap(), None);
        assert_eq!(expand("1/x", 0, 7, None).unwrap(), None);
        assert_eq!(expand("9", 0, 7, None).unwrap(), None);
        assert_eq!(expand("3-", 0, 7, None).unwrap(), None);
        assert_eq!(normalise_cron("0 0 ? * MON").unwrap()[2], "*");
    }

    #[test]
    fn descriptions_and_previews() {
        let d = |mo: ScheduleModel| describe(&mo, Some("Asia/Kolkata")).unwrap();
        assert_eq!(d(m("off")), "Not scheduled");
        assert_eq!(d(ScheduleModel { cron: Some("0 1 * * *".into()), ..m("custom") }), "Custom cron 0 1 * * * (UTC)");
        assert_eq!(d(ScheduleModel { every: Some(1), ..m("minutes") }), "Every minute");
        assert_eq!(d(ScheduleModel { every: Some(5), ..m("minutes") }), "Every 5 minutes");
        assert_eq!(d(ScheduleModel { every: Some(1), minute: Some(5), ..m("hours") }), "Every hour at :05 (Asia/Kolkata)");
        assert_eq!(d(ScheduleModel { every: Some(6), hour: Some(1), minute: Some(5), ..m("hours") }), "Every 6 hours from 01:05 (Asia/Kolkata)");
        assert_eq!(d(ScheduleModel { hour: Some(9), minute: Some(0), days: Some(vec![1, 2, 3, 4, 5]), ..m("weekly") }), "Weekdays at 09:00 (Asia/Kolkata)");
        assert_eq!(d(ScheduleModel { hour: Some(9), minute: Some(0), days: Some(vec![0, 6]), ..m("weekly") }), "Sun, Sat at 09:00 (Asia/Kolkata)");
        assert!(describe(&ScheduleModel { days: Some(vec![9]), ..m("weekly") }, None).is_err());
        assert_eq!(d(ScheduleModel { hour: Some(9), minute: Some(0), day_of_month: Some("L".into()), ..m("monthly") }), "Last day of every month at 09:00 (Asia/Kolkata)");
        assert_eq!(d(ScheduleModel { hour: Some(9), minute: Some(0), day_of_month: Some("3".into()), ..m("monthly") }), "Day 3 of every month at 09:00 (Asia/Kolkata)");
        assert_eq!(d(m("weird")), "weird");
        assert_eq!(format_offset(330), "UTC+05:30");
        assert_eq!(format_offset(-90), "UTC-01:30");

        let now = Utc.with_ymd_and_hms(2026, 10, 15, 10, 0, 0).unwrap();
        let p = to_cron(ScheduleModel { hour: Some(9), minute: Some(0), days: Some(vec![1]), ..m("weekly") }, Some("Asia/Kolkata"), now).unwrap();
        assert_eq!(p.cron, "30 3 * * 1");
        assert_eq!(p.next_runs, vec!["Mon 19 Oct 2026, 09:00", "Mon 26 Oct 2026, 09:00", "Mon 2 Nov 2026, 09:00"]);
        assert!(!p.observes_dst);
        let j = p.to_json();
        let o = j.as_object().unwrap();
        assert_eq!(o.keys().cloned().collect::<Vec<_>>(), vec!["cron", "timezone", "model", "displayZone", "description", "nextRuns", "observesDst", "valid"]);
        let off = to_cron(ScheduleModel::default(), None, now).unwrap();
        assert!(!off.to_json().as_object().unwrap().contains_key("cron"));
        let bad = from_cron_preview(Some("61 * * * *"), None, Some("Europe/London"), now).unwrap();
        assert!(!bad.valid && bad.error.as_deref().unwrap_or("").starts_with("The scheduler cannot read this cron"));
        let fine = from_cron_preview(Some("0 9 * * *"), Some("Europe/London"), Some("nonsense/zone"), now).unwrap();
        assert_eq!((fine.timezone.as_str(), fine.display_zone.as_str()), ("Europe/London", "UTC"));
        assert!(observes_dst(&zone_of("Europe/London").unwrap(), 2026));
        let zs = zones(now);
        let list = match &zs {
            JValue::Array(a) => a,
            _ => panic!(),
        };
        assert_eq!(list[0].as_object().unwrap()["label"], JValue::Str("UTC (UTC+00:00)".into()));
        assert!(list.iter().any(|z| z.as_object().unwrap()["label"] == JValue::Str("Asia/Kolkata (UTC+05:30)".into())));
        assert!(!list.iter().any(|z| z.as_object().unwrap()["zone"].as_str().unwrap_or("").starts_with("Etc/")));
    }

    #[test]
    fn the_model_is_read_and_normalised() {
        let parse = |s: &str| ScheduleModel::from_json(&overridable::json::parse(s.as_bytes()).unwrap());
        let mo = parse(r#"{"frequency":"hours","every":"7","hour":30,"days":[],"dayOfMonth":" "}"#).unwrap();
        let n = normalise_model(mo);
        assert_eq!((n.every, n.hour, n.days.clone(), n.day_of_month.as_deref()), (Some(1), Some(0), Some(vec![1, 2, 3, 4, 5]), Some("1")));
        let n = normalise_model(parse(r#"{"frequency":"minutes","every":7,"minute":99}"#).unwrap());
        assert_eq!((n.every, n.minute), (Some(5), Some(0)));
        assert!(parse(r#"{"every":{}}"#).is_none());
        assert!(parse(r#"{"days":"x"}"#).is_none());
        assert!(parse(r#"{"days":[{}]}"#).is_none());
        assert!(parse(r#"[1]"#).is_none());
        assert_eq!(parse("null").unwrap(), ScheduleModel::default());
        let full = parse(r#"{"frequency":"weekly","every":1,"minute":1,"hour":1,"days":[1,"2",3.0],"dayOfMonth":"1","cron":"x"}"#).unwrap();
        assert_eq!(full.days, Some(vec![1, 2, 3]));
        assert_eq!(full.to_json().as_object().unwrap().len(), 7);
    }
}
