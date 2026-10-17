//! Cron arithmetic of core's scheduler, computed as the Java services compute it:
//!
//! - [`CronExpression`]: Spring Framework 6.2.1 `org.springframework.scheduling.support.CronExpression`
//!   (`parse` and `next`) with its fields (`BitsCronField`, `QuartzCronField`,
//!   `CompositeCronField`) and the java.time arithmetic `next` stands on: `ZonedDateTime.with`,
//!   `plus` and `ofLocal` with the preferred offset, so a local time in a DST gap or overlap
//!   resolves as Java resolves it, and `Integer.parseInt`, which takes a sign and any Unicode
//!   decimal digit;
//! - [`JavaZone`] / [`zone_of`]: `ZoneId.of`, region ids from chrono-tz (the same IANA 2025b data
//!   as JDK 25), offsets in every form `ZoneOffset.of` reads, the `UTC` / `GMT` / `UT` prefixes and
//!   the JDK's own `SystemV/*` zones;
//! - [`parse_cron`], [`latest_tick`], [`latest_spread_tick`], [`spread_offset_seconds`] and
//!   [`shortest_gap_seconds`]: `CronGrid` of commons-core.
//!
//! Where Java throws inside `next` (a date past year 999,999,999), the answer here is `None`.
//! `cron_fixtures.json` holds Spring's own answers for a corpus of crons, zones and instants;
//! `tools/cron_fixtures.jsh` regenerates it.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Offset, TimeDelta, TimeZone, Utc};
use chrono_tz::Tz;

/// `CronExpression.MAX_ATTEMPTS`.
const MAX_ATTEMPTS: i32 = 366;

const NANOS_PER_SECOND: i64 = 1_000_000_000;
const NANOS_PER_MINUTE: i64 = 60 * NANOS_PER_SECOND;
const NANOS_PER_HOUR: i64 = 60 * NANOS_PER_MINUTE;
const SECONDS_PER_DAY: i64 = 86_400;

/// A java.time exception inside the arithmetic (a date beyond `LocalDate`'s years or a long
/// overflow). Java throws it out of `next`; the public functions answer `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Overflow;

type R<T> = Result<T, Overflow>;

// ------------------------------------------------------------------ Java strings and ints

/// The first code unit of every block of ten BMP characters `Character.digit(c, 10)` reads
/// (Unicode category Nd), so `Integer.parseInt` takes `٣` or `３` as 3, as Java does.
const DIGIT_ZEROS: [u16; 37] = [
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66,
    0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50,
    0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
];

const PLUS: u16 = b'+' as u16;
const MINUS: u16 = b'-' as u16;

/// `Character.digit(ch, 10)`.
fn java_digit(c: u16) -> i32 {
    DIGIT_ZEROS.iter().find(|&&z| c >= z && c < z + 10).map_or(-1, |&z| i32::from(c - z))
}

/// `Integer.parseInt(s)` (and `parseInt(s, begin, end, 10)` on a slice): an optional sign, then
/// digits, within `int`.
fn parse_int(s: &[u16]) -> Option<i32> {
    let len = s.len();
    if len == 0 {
        return None;
    }
    let mut digit: i32 = !0xFF;
    let first = s[0];
    let mut i = 1;
    if first != MINUS && first != PLUS {
        digit = java_digit(first);
    }
    if digit >= 0 || (digit == !0xFF && len > 1) {
        let limit = if first != MINUS { i32::MIN + 1 } else { i32::MIN };
        let multmin = limit / 10;
        let mut result = -(digit & 0xFF);
        let mut in_range = true;
        while i < len {
            digit = java_digit(s[i]);
            i += 1;
            if digit < 0 {
                break;
            }
            in_range = result > multmin || (result == multmin && digit <= 10 * multmin - limit);
            if !in_range {
                break;
            }
            result = 10 * result - digit;
        }
        if in_range && i == len && digit >= 0 {
            return Some(if first != MINUS { -result } else { result });
        }
    }
    None
}

/// `String.trim()`: everything up to U+0020 off both ends.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// `Character.isWhitespace(codePoint)`.
fn java_is_whitespace(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{D}' | '\u{1C}'..='\u{20}' | '\u{1680}' | '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200A}'
        | '\u{2028}' | '\u{2029}' | '\u{205F}' | '\u{3000}')
}

/// `String.equalsIgnoreCase` against an ASCII lower-case name: per UTF-16 unit, equal after
/// `Character.toUpperCase`, or after `toLowerCase` of that, which also lets `ı`, `İ` (as i) and
/// the Kelvin sign (as k) through.
fn equals_ignore_case(s: &str, ascii_lower: &str) -> bool {
    s.chars().count() == ascii_lower.len()
        && s.chars().zip(ascii_lower.chars()).all(|(c, l)| {
            c.to_ascii_lowercase() == l
                || (l == 'i' && (c == '\u{130}' || c == '\u{131}'))
                || (l == 'k' && c == '\u{212A}')
        })
}

/// `String.hashCode()`, over UTF-16 units.
fn java_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(i32::from(c)))
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn find(s: &[u16], c: u8) -> Option<usize> {
    s.iter().position(|&u| u == u16::from(c))
}

fn rfind(s: &[u16], c: u8) -> Option<usize> {
    s.iter().rposition(|&u| u == u16::from(c))
}

fn is(s: &[u16], text: &str) -> bool {
    s.iter().copied().eq(text.encode_utf16())
}

/// `StringUtils.delimitedListToStringArray(value, ",")` of a non-empty value.
fn split_commas(s: &[u16]) -> Vec<&[u16]> {
    s.split(|&u| u == u16::from(b',')).collect()
}

fn text(s: &[u16]) -> String {
    String::from_utf16_lossy(s)
}

// ------------------------------------------------------------------ java.time dates

const DAYS_PER_CYCLE: i64 = 146_097;
const DAYS_0000_TO_1970: i64 = DAYS_PER_CYCLE * 5 - (30 * 365 + 7);
const MIN_YEAR: i64 = -999_999_999;
const MAX_YEAR: i64 = 999_999_999;
const MIN_EPOCH_DAY: i64 = -365_243_219_162;
const MAX_EPOCH_DAY: i64 = 365_241_780_471;

fn is_leap(year: i64) -> bool {
    (year & 3) == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn month_length(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `LocalDate`, over Java's whole year range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Date {
    year: i64,
    month: i64,
    day: i64,
}

impl Date {
    fn new(year: i64, month: i64, day: i64) -> Date {
        Date { year, month, day }
    }

    fn epoch_day(self) -> i64 {
        let (y, m) = (self.year, self.month);
        let mut total = 365 * y;
        if y >= 0 {
            total += (y + 3) / 4 - (y + 99) / 100 + (y + 399) / 400;
        } else {
            total -= y / -4 - y / -100 + y / -400;
        }
        total += (367 * m - 362) / 12;
        total += self.day - 1;
        if m > 2 {
            total -= 1;
            if !is_leap(y) {
                total -= 1;
            }
        }
        total - DAYS_0000_TO_1970
    }

    fn of_epoch_day(epoch_day: i64) -> R<Date> {
        if !(MIN_EPOCH_DAY..=MAX_EPOCH_DAY).contains(&epoch_day) {
            return Err(Overflow);
        }
        let mut zero_day = epoch_day + DAYS_0000_TO_1970 - 60;
        let mut adjust = 0;
        if zero_day < 0 {
            let adjust_cycles = (zero_day + 1) / DAYS_PER_CYCLE - 1;
            adjust = adjust_cycles * 400;
            zero_day += -adjust_cycles * DAYS_PER_CYCLE;
        }
        let mut year_est = (400 * zero_day + 591) / DAYS_PER_CYCLE;
        let mut doy_est = zero_day - (365 * year_est + year_est / 4 - year_est / 100 + year_est / 400);
        if doy_est < 0 {
            year_est -= 1;
            doy_est = zero_day - (365 * year_est + year_est / 4 - year_est / 100 + year_est / 400);
        }
        year_est += adjust;
        let march_month0 = (doy_est * 5 + 2) / 153;
        let month = (march_month0 + 2) % 12 + 1;
        let day = doy_est - (march_month0 * 306 + 5) / 10 + 1;
        year_est += march_month0 / 10;
        if !(MIN_YEAR..=MAX_YEAR).contains(&year_est) {
            return Err(Overflow);
        }
        Ok(Date::new(year_est, month, day))
    }

    /// ISO day of week, Monday 1 to Sunday 7.
    fn day_of_week(self) -> i64 {
        (self.epoch_day() + 3).rem_euclid(7) + 1
    }

    fn length_of_month(self) -> i64 {
        month_length(self.year, self.month)
    }

    fn resolve_previous_valid(year: i64, month: i64, day: i64) -> Date {
        Date::new(year, month, day.min(month_length(year, month)))
    }

    fn plus_days(self, days: i64) -> R<Date> {
        if days == 0 {
            return Ok(self);
        }
        Date::of_epoch_day(self.epoch_day().checked_add(days).ok_or(Overflow)?)
    }

    fn plus_months(self, months: i64) -> R<Date> {
        if months == 0 {
            return Ok(self);
        }
        let calc = (self.year * 12 + (self.month - 1)).checked_add(months).ok_or(Overflow)?;
        let year = calc.div_euclid(12);
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return Err(Overflow);
        }
        Ok(Date::resolve_previous_valid(year, calc.rem_euclid(12) + 1, self.day))
    }

    fn plus_years(self, years: i64) -> R<Date> {
        if years == 0 {
            return Ok(self);
        }
        let year = self.year.checked_add(years).ok_or(Overflow)?;
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return Err(Overflow);
        }
        Ok(Date::resolve_previous_valid(year, self.month, self.day))
    }
}

/// The `ChronoField`s the cron fields touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum F {
    NanoOfSecond,
    SecondOfMinute,
    MinuteOfHour,
    HourOfDay,
    DayOfMonth,
    MonthOfYear,
    DayOfWeek,
    NanoOfDay,
}

/// The `ChronoUnit`s they move by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Nanos,
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
    Years,
}

impl F {
    /// `field.range()`: the minimum and the largest maximum.
    fn range(self) -> (i64, i64) {
        match self {
            F::NanoOfSecond => (0, NANOS_PER_SECOND - 1),
            F::SecondOfMinute | F::MinuteOfHour => (0, 59),
            F::HourOfDay => (0, 23),
            F::DayOfMonth => (1, 31),
            F::MonthOfYear => (1, 12),
            F::DayOfWeek => (1, 7),
            F::NanoOfDay => (0, SECONDS_PER_DAY * NANOS_PER_SECOND - 1),
        }
    }

    fn base_unit(self) -> Unit {
        match self {
            F::NanoOfSecond | F::NanoOfDay => Unit::Nanos,
            F::SecondOfMinute => Unit::Seconds,
            F::MinuteOfHour => Unit::Minutes,
            F::HourOfDay => Unit::Hours,
            F::DayOfMonth | F::DayOfWeek => Unit::Days,
            F::MonthOfYear => Unit::Months,
        }
    }
}

/// `LocalDateTime`: a date and the nanosecond of its day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ldt {
    date: Date,
    nod: i64,
}

impl Ldt {
    fn of_epoch_second(local_seconds: i64, nano: i64) -> R<Ldt> {
        let date = Date::of_epoch_day(local_seconds.div_euclid(SECONDS_PER_DAY))?;
        Ok(Ldt { date, nod: local_seconds.rem_euclid(SECONDS_PER_DAY) * NANOS_PER_SECOND + nano })
    }

    /// The local date-time read as if it were UTC, in seconds.
    fn local_seconds(&self) -> i64 {
        self.date.epoch_day() * SECONDS_PER_DAY + self.nod / NANOS_PER_SECOND
    }

    fn nano(&self) -> i64 {
        self.nod % NANOS_PER_SECOND
    }

    fn plus_seconds(self, seconds: i64) -> R<Ldt> {
        Ldt::of_epoch_second(self.local_seconds().checked_add(seconds).ok_or(Overflow)?, self.nano())
    }

    fn get(&self, f: F) -> i64 {
        match f {
            F::NanoOfSecond => self.nod % NANOS_PER_SECOND,
            F::SecondOfMinute => self.nod / NANOS_PER_SECOND % 60,
            F::MinuteOfHour => self.nod / NANOS_PER_MINUTE % 60,
            F::HourOfDay => self.nod / NANOS_PER_HOUR,
            F::NanoOfDay => self.nod,
            F::DayOfMonth => self.date.day,
            F::MonthOfYear => self.date.month,
            F::DayOfWeek => self.date.day_of_week(),
        }
    }

    /// `LocalDateTime.with(field, value)`.
    fn with(self, f: F, value: i64) -> R<Ldt> {
        let (min, max) = f.range();
        if value < min || value > max {
            return Err(Overflow);
        }
        let shift = |unit: i64| Ldt { nod: self.nod + (value - self.get(f)) * unit, ..self };
        Ok(match f {
            F::NanoOfSecond => shift(1),
            F::SecondOfMinute => shift(NANOS_PER_SECOND),
            F::MinuteOfHour => shift(NANOS_PER_MINUTE),
            F::HourOfDay => shift(NANOS_PER_HOUR),
            F::NanoOfDay => Ldt { nod: value, ..self },
            F::DayOfMonth => {
                if value > self.date.length_of_month() {
                    return Err(Overflow);
                }
                Ldt { date: Date { day: value, ..self.date }, ..self }
            }
            F::MonthOfYear => {
                Ldt { date: Date::resolve_previous_valid(self.date.year, value, self.date.day), ..self }
            }
            F::DayOfWeek => Ldt { date: self.date.plus_days(value - self.date.day_of_week())?, ..self },
        })
    }
}

/// `Instant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Instant {
    secs: i64,
    nanos: i64,
}

impl Instant {
    fn of_utc(t: DateTime<Utc>) -> Instant {
        Instant { secs: t.timestamp(), nanos: i64::from(t.timestamp_subsec_nanos()).min(NANOS_PER_SECOND - 1) }
    }

    fn to_utc(self) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(self.secs, self.nanos as u32)
    }

    fn plus_nanos(self, nanos: i128) -> R<Instant> {
        let total = i128::from(self.secs) * i128::from(NANOS_PER_SECOND) + i128::from(self.nanos) + nanos;
        let secs = i64::try_from(total.div_euclid(i128::from(NANOS_PER_SECOND))).map_err(|_| Overflow)?;
        Ok(Instant { secs, nanos: total.rem_euclid(i128::from(NANOS_PER_SECOND)) as i64 })
    }

    fn plus_seconds(self, seconds: i64) -> R<Instant> {
        self.plus_nanos(i128::from(seconds) * i128::from(NANOS_PER_SECOND))
    }

    fn minus_delta(self, d: TimeDelta) -> R<Instant> {
        let nanos = i128::from(d.num_seconds()) * i128::from(NANOS_PER_SECOND) + i128::from(d.subsec_nanos());
        self.plus_nanos(-nanos)
    }
}

// ------------------------------------------------------------------ zones

/// A `ZoneId` as `ZoneId.of` reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaZone {
    /// A tz database region (`Asia/Kolkata`, `Etc/GMT+5`, `UCT`, ...).
    Region(Tz),
    /// A fixed offset in seconds east of UTC: `Z`, `+05:30`, and `UTC`, `GMT`, `UT` with or
    /// without an offset.
    Fixed(i32),
    /// The JDK's `SystemV/AST4ADT`, `CST6CDT`, `EST5EDT`, `MST7MDT`, `PST8PDT` and `YST9YDT`,
    /// which no IANA zone matches: this standard offset in seconds, an hour ahead from the last
    /// Sunday of April to the last Sunday of October at 02:00 wall time (from 1900).
    SystemV(i32),
}

/// What a local date-time is in a zone: `ZoneRules.getValidOffsets` and, in a gap, the
/// transition's offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Local {
    One(i32),
    Gap(i32, i32),
    Overlap(i32, i32),
}

/// chrono-tz lists transitions up to 2099; Java goes on with the zone's last rules.
const TABLE_END_YEAR: i64 = 2100;

impl JavaZone {
    /// `ZoneRules.getOffset(instant)`, in seconds.
    fn offset_at(&self, secs: i64) -> i32 {
        match *self {
            JavaZone::Fixed(offset) => offset,
            JavaZone::Region(tz) => region_offset(tz, secs),
            JavaZone::SystemV(standard) => system_v_offset(standard, secs),
        }
    }

    fn local(&self, local_seconds: i64) -> Local {
        if let JavaZone::Fixed(offset) = *self {
            return Local::One(offset);
        }
        let before = self.offset_at(local_seconds - SECONDS_PER_DAY);
        let after = self.offset_at(local_seconds + SECONDS_PER_DAY);
        if before == after && self.offset_at(local_seconds - i64::from(before)) == before {
            return Local::One(before);
        }
        self.local_near_transition(local_seconds, before)
    }

    /// The transitions within a day either side, found by half-hour steps and bisection, and the
    /// offsets valid at the local time among them.
    fn local_near_transition(&self, u: i64, fallback: i32) -> Local {
        let (lo, hi) = (u - SECONDS_PER_DAY - 3600, u + SECONDS_PER_DAY + 3600);
        let mut transitions: Vec<(i64, i32, i32)> = Vec::new();
        let (mut t, mut offset) = (lo, self.offset_at(lo));
        while t < hi {
            let nt = (t + 1800).min(hi);
            let next = self.offset_at(nt);
            if next != offset {
                let (mut l, mut h) = (t, nt);
                while h - l > 1 {
                    let m = l + (h - l) / 2;
                    if self.offset_at(m) == offset {
                        l = m;
                    } else {
                        h = m;
                    }
                }
                transitions.push((h, offset, next));
            }
            (t, offset) = (nt, next);
        }
        let mut valid: Vec<i32> = transitions.iter().flat_map(|&(_, b, a)| [b, a]).collect();
        valid.push(fallback);
        valid.sort_unstable_by(|a, b| b.cmp(a));
        valid.dedup();
        valid.retain(|&o| self.offset_at(u - i64::from(o)) == o);
        match valid[..] {
            [one] => Local::One(one),
            [before, after, ..] => Local::Overlap(before, after),
            [] => transitions
                .iter()
                .find(|&&(at, b, a)| at + i64::from(b) <= u && u < at + i64::from(a))
                .map_or(Local::One(fallback), |&(_, b, a)| Local::Gap(b, a)),
        }
    }
}

fn utc_year(secs: i64) -> i64 {
    let day = secs.div_euclid(SECONDS_PER_DAY).clamp(MIN_EPOCH_DAY, MAX_EPOCH_DAY);
    Date::of_epoch_day(day).map_or(if secs < 0 { MIN_YEAR } else { MAX_YEAR }, |d| d.year)
}

fn chrono_offset(tz: Tz, secs: i64) -> i32 {
    // chrono's own range ends near year 262,000; before it the first offset (LMT) holds, after
    // it the last.
    const LIMIT: i64 = 8_000_000_000_000;
    let at = DateTime::from_timestamp(secs.clamp(-LIMIT, LIMIT), 0).unwrap_or_default().naive_utc();
    tz.offset_from_utc_datetime(&at).fix().local_minus_utc()
}

/// The offset of a region. From 2100 on, a zone that still changes its clocks in 2099 reads the
/// latest year before 2100 whose March 1st falls on the same weekday: every rule still in force
/// changes the clocks on a weekday of a month from March on, so that year's changes fall on the
/// same dates, as Java's last rules put them. The latest such year, because the tz data spells out
/// irregular years (Palestine's Ramadan changes) into the 2080s.
fn region_offset(tz: Tz, secs: i64) -> i32 {
    let year = utc_year(secs);
    if year >= TABLE_END_YEAR {
        let january = Date::new(2099, 1, 15).epoch_day() * SECONDS_PER_DAY;
        let july = Date::new(2099, 7, 15).epoch_day() * SECONDS_PER_DAY;
        if chrono_offset(tz, january) != chrono_offset(tz, july) {
            let march = Date::new(year, 3, 1);
            let same = (2072..TABLE_END_YEAR)
                .rev()
                .map(|y| Date::new(y, 3, 1))
                .find(|d| d.day_of_week() == march.day_of_week())
                .expect("any seven years in a row start March on every weekday");
            return chrono_offset(tz, secs + (same.epoch_day() - march.epoch_day()) * SECONDS_PER_DAY);
        }
    }
    chrono_offset(tz, secs)
}

fn last_sunday(year: i64, month: i64) -> Date {
    let last = Date::new(year, month, month_length(year, month));
    Date::new(year, month, last.day - last.day_of_week() % 7)
}

/// The JDK's `SystemV` rules: none before 1900, then April's last Sunday to October's, 02:00
/// wall time, except 1974 (January 6 to November's last Sunday) and 1975 (February 23 to
/// October's last Sunday).
fn system_v_offset(standard: i32, secs: i64) -> i32 {
    let daylight = standard + 3600;
    let year = utc_year(secs + i64::from(standard));
    if year < 1900 {
        return standard;
    }
    let (start, end) = match year {
        1974 => (Date::new(1974, 1, 6), last_sunday(1974, 11)),
        1975 => (Date::new(1975, 2, 23), last_sunday(1975, 10)),
        _ => (last_sunday(year, 4), last_sunday(year, 10)),
    };
    let start = start.epoch_day() * SECONDS_PER_DAY + 7200 - i64::from(standard);
    let end = end.epoch_day() * SECONDS_PER_DAY + 7200 - i64::from(daylight);
    if (start..end).contains(&secs) {
        daylight
    } else {
        standard
    }
}

/// Region ids chrono-tz knows and JDK 25's tz database does not.
const NOT_IN_JAVA: [&str; 4] = ["EST", "HST", "MST", "ROC"];

/// `ZoneId.of(id)`.
pub fn zone_of(id: &str) -> Result<JavaZone, String> {
    let u = utf16(id);
    if u.len() <= 1 || u[0] == PLUS || u[0] == MINUS {
        return zone_offset_of(&u).map(JavaZone::Fixed);
    }
    let prefix = if id.starts_with("UTC") || id.starts_with("GMT") {
        3
    } else if id.starts_with("UT") {
        2
    } else {
        return region_of(id, &u);
    };
    if u.len() == prefix {
        return Ok(JavaZone::Fixed(0));
    }
    if u[prefix] != PLUS && u[prefix] != MINUS {
        return region_of(id, &u);
    }
    zone_offset_of(&u[prefix..])
        .map(JavaZone::Fixed)
        .map_err(|e| format!("Invalid ID for offset-based ZoneId: {id} ({e})"))
}

/// `ZoneOffset.of(id)`: `Z`, `+h`, `+hh`, `+hhmm`, `+hh:mm`, `+hhmmss`, `+hh:mm:ss`, within ±18:00.
fn zone_offset_of(id: &[u16]) -> Result<i32, String> {
    let invalid = || format!("Invalid ID for ZoneOffset, invalid format: {}", text(id));
    if is(id, "Z") {
        return Ok(0);
    }
    let padded;
    let id = if id.len() == 2 {
        padded = [id[0], u16::from(b'0'), id[1]];
        &padded[..]
    } else {
        id
    };
    let number = |pos: usize, colon: bool| -> Result<i32, String> {
        if colon && id[pos - 1] != u16::from(b':') {
            return Err(invalid());
        }
        let digit = |c: u16| (u16::from(b'0')..=u16::from(b'9')).contains(&c).then(|| i32::from(c - u16::from(b'0')));
        match (digit(id[pos]), digit(id[pos + 1])) {
            (Some(a), Some(b)) => Ok(a * 10 + b),
            _ => Err(invalid()),
        }
    };
    let (hours, minutes, seconds) = match id.len() {
        3 => (number(1, false)?, 0, 0),
        5 => (number(1, false)?, number(3, false)?, 0),
        6 => (number(1, false)?, number(4, true)?, 0),
        7 => (number(1, false)?, number(3, false)?, number(5, false)?),
        9 => (number(1, false)?, number(4, true)?, number(7, true)?),
        _ => return Err(invalid()),
    };
    let (hours, minutes, seconds) = match id[0] {
        PLUS => (hours, minutes, seconds),
        MINUS => (-hours, -minutes, -seconds),
        _ => return Err(invalid()),
    };
    let valid = (-18..=18).contains(&hours)
        && (hours <= 0 || (minutes >= 0 && seconds >= 0))
        && (hours >= 0 || (minutes <= 0 && seconds <= 0))
        && (hours != 0 || !((minutes > 0 && seconds < 0) || (minutes < 0 && seconds > 0)))
        && (-59..=59).contains(&minutes)
        && (-59..=59).contains(&seconds)
        && (hours.abs() != 18 || (minutes | seconds) == 0);
    if !valid {
        return Err(format!("Zone offset not in valid range: {}", text(id)));
    }
    Ok(hours * 3600 + minutes * 60 + seconds)
}

/// `ZoneRegion.ofId(id, true)`.
fn region_of(id: &str, u: &[u16]) -> Result<JavaZone, String> {
    let legal = u.len() >= 2
        && u.iter().enumerate().all(|(i, &c)| {
            let c = char::from_u32(u32::from(c)).unwrap_or('\0');
            c.is_ascii_alphabetic() || (i != 0 && (c.is_ascii_digit() || "/~._+-".contains(c)))
        });
    if !legal {
        return Err(format!("Invalid ID for region-based ZoneId, invalid format: {id}"));
    }
    if let Some(name) = id.strip_prefix("SystemV/") {
        let fixed = |hours: i32| JavaZone::Fixed(-hours * 3600);
        let dst = |hours: i32| JavaZone::SystemV(-hours * 3600);
        match name {
            "AST4" => return Ok(fixed(4)),
            "AST4ADT" => return Ok(dst(4)),
            "CST6" => return Ok(fixed(6)),
            "CST6CDT" => return Ok(dst(6)),
            "EST5" => return Ok(fixed(5)),
            "EST5EDT" => return Ok(dst(5)),
            "HST10" => return Ok(fixed(10)),
            "MST7" => return Ok(fixed(7)),
            "MST7MDT" => return Ok(dst(7)),
            "PST8" => return Ok(fixed(8)),
            "PST8PDT" => return Ok(dst(8)),
            "YST9" => return Ok(fixed(9)),
            "YST9YDT" => return Ok(dst(9)),
            _ => {}
        }
    }
    if NOT_IN_JAVA.contains(&id) {
        return Err(format!("Unknown time-zone ID: {id}"));
    }
    Tz::from_str(id).map(JavaZone::Region).map_err(|_| format!("Unknown time-zone ID: {id}"))
}

// ------------------------------------------------------------------ ZonedDateTime

/// `ZonedDateTime` in a zone the caller passes along: the local date-time and its offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Zdt {
    ldt: Ldt,
    offset: i32,
}

impl Zdt {
    fn of_instant(at: Instant, zone: &JavaZone) -> R<Zdt> {
        let offset = zone.offset_at(at.secs);
        let local = at.secs.checked_add(i64::from(offset)).ok_or(Overflow)?;
        Ok(Zdt { ldt: Ldt::of_epoch_second(local, at.nanos)?, offset })
    }

    /// `ZonedDateTime.ofLocal(ldt, zone, preferred)`: a gap moves the time on by its length,
    /// an overlap keeps the preferred offset when it is one of the two, else the earlier.
    fn of_local(ldt: Ldt, zone: &JavaZone, preferred: i32) -> R<Zdt> {
        Ok(match zone.local(ldt.local_seconds()) {
            Local::One(offset) => Zdt { ldt, offset },
            Local::Gap(before, after) => Zdt { ldt: ldt.plus_seconds(i64::from(after - before))?, offset: after },
            Local::Overlap(before, after) => {
                Zdt { ldt, offset: if preferred == before || preferred == after { preferred } else { before } }
            }
        })
    }

    fn instant(&self) -> Instant {
        Instant { secs: self.ldt.local_seconds() - i64::from(self.offset), nanos: self.ldt.nano() }
    }

    fn get(&self, f: F) -> i64 {
        self.ldt.get(f)
    }

    /// `temporal.range(field)`.
    fn range(&self, f: F) -> (i64, i64) {
        match f {
            F::DayOfMonth => (1, self.ldt.date.length_of_month()),
            _ => f.range(),
        }
    }

    /// `with(field, value)`: the local date-time changed, resolved with this offset preferred.
    fn with(self, f: F, value: i64, zone: &JavaZone) -> R<Zdt> {
        Zdt::of_local(self.ldt.with(f, value)?, zone, self.offset)
    }

    /// `plus(amount, unit)`: time units on the instant, date units on the local date-time.
    fn plus(self, amount: i64, unit: Unit, zone: &JavaZone) -> R<Zdt> {
        let date = |d: R<Date>| -> R<Zdt> { Zdt::of_local(Ldt { date: d?, ..self.ldt }, zone, self.offset) };
        let nanos = |per: i64| -> R<Zdt> {
            Zdt::of_instant(self.instant().plus_nanos(i128::from(amount) * i128::from(per))?, zone)
        };
        match unit {
            Unit::Nanos => nanos(1),
            Unit::Seconds => nanos(NANOS_PER_SECOND),
            Unit::Minutes => nanos(NANOS_PER_MINUTE),
            Unit::Hours => nanos(NANOS_PER_HOUR),
            Unit::Days => date(self.ldt.date.plus_days(amount)),
            Unit::Weeks => date(self.ldt.date.plus_days(amount.checked_mul(7).ok_or(Overflow)?)),
            Unit::Months => date(self.ldt.date.plus_months(amount)),
            Unit::Years => date(self.ldt.date.plus_years(amount)),
        }
    }

    fn is_before(&self, other: &Zdt) -> bool {
        self.instant() < other.instant()
    }

    fn is_after(&self, other: &Zdt) -> bool {
        self.instant() > other.instant()
    }
}

// ------------------------------------------------------------------ cron fields

/// `CronField.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Nano,
    Second,
    Minute,
    Hour,
    DayOfMonth,
    Month,
    DayOfWeek,
}

impl Ty {
    fn field(self) -> F {
        match self {
            Ty::Nano => F::NanoOfSecond,
            Ty::Second => F::SecondOfMinute,
            Ty::Minute => F::MinuteOfHour,
            Ty::Hour => F::HourOfDay,
            Ty::DayOfMonth => F::DayOfMonth,
            Ty::Month => F::MonthOfYear,
            Ty::DayOfWeek => F::DayOfWeek,
        }
    }

    fn higher_order(self) -> Unit {
        match self {
            Ty::Nano => Unit::Seconds,
            Ty::Second => Unit::Minutes,
            Ty::Minute => Unit::Hours,
            Ty::Hour => Unit::Days,
            Ty::DayOfMonth => Unit::Months,
            Ty::Month => Unit::Years,
            Ty::DayOfWeek => Unit::Weeks,
        }
    }

    fn lower_orders(self) -> &'static [F] {
        const TIME: [F; 5] = [F::DayOfMonth, F::HourOfDay, F::MinuteOfHour, F::SecondOfMinute, F::NanoOfSecond];
        match self {
            Ty::Nano => &[],
            Ty::Second => &TIME[4..],
            Ty::Minute => &TIME[3..],
            Ty::Hour => &TIME[2..],
            Ty::DayOfMonth | Ty::DayOfWeek => &TIME[1..],
            Ty::Month => &TIME,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Ty::Nano => "NanoOfSecond",
            Ty::Second => "SecondOfMinute",
            Ty::Minute => "MinuteOfHour",
            Ty::Hour => "HourOfDay",
            Ty::DayOfMonth => "DayOfMonth",
            Ty::Month => "MonthOfYear",
            Ty::DayOfWeek => "DayOfWeek",
        }
    }

    fn range(self) -> (i32, i32) {
        let (min, max) = self.field().range();
        (min as i32, max as i32)
    }

    fn get(self, t: &Zdt) -> i64 {
        t.get(self.field())
    }

    /// `checkValidValue`: 0 is also a day of week (Sunday).
    fn check_valid_value(self, value: i32) -> Result<i32, String> {
        let (min, max) = self.range();
        if (self == Ty::DayOfWeek && value == 0) || (min..=max).contains(&value) {
            Ok(value)
        } else {
            Err(format!("Invalid value for {} (valid values {min} - {max}): {value}", self.name()))
        }
    }

    fn elapse_until(self, t: Zdt, goal: i64, zone: &JavaZone) -> R<Zdt> {
        let f = self.field();
        let current = t.get(f);
        let (min, max) = t.range(f);
        if current < goal {
            if (min..=max).contains(&goal) {
                t.with(f, goal, zone)
            } else {
                // goal is invalid, e.g. the 29th of February, so roll forward
                t.plus(max - current + 1, f.base_unit(), zone)
            }
        } else {
            t.plus(goal + max - current + 1 - min, f.base_unit(), zone)
        }
    }

    fn roll_forward(self, t: Zdt, zone: &JavaZone) -> R<Zdt> {
        let result = t.plus(1, self.higher_order(), zone)?;
        let (min, _) = result.range(self.field());
        result.with(self.field(), min, zone)
    }

    fn reset(self, mut t: Zdt, zone: &JavaZone) -> R<Zdt> {
        for &f in self.lower_orders() {
            let (min, _) = t.range(f);
            t = t.with(f, min, zone)?;
        }
        Ok(t)
    }
}

/// A `QuartzCronField`'s `TemporalAdjuster`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Adjuster {
    /// `L`
    LastDayOfMonth,
    /// `LW`
    LastWeekdayOfMonth,
    /// `L-n`
    LastDayWithOffset(i32),
    /// `nW`
    WeekdayNearestTo(i32),
    /// `nL`: the last given day of week of the month
    LastInMonth(i32),
    /// `n#k`
    DayOfWeekInMonth { ordinal: i32, day_of_week: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CronField {
    Bits { ty: Ty, bits: u64 },
    Quartz { ty: Ty, roll_forward: Ty, adjuster: Adjuster },
    Composite { ty: Ty, fields: Vec<CronField> },
}

fn next_set_bit(bits: u64, from: i64) -> i64 {
    let result = bits & (u64::MAX << ((from as i32 as u32) & 63));
    if result == 0 {
        -1
    } else {
        i64::from(result.trailing_zeros())
    }
}

impl CronField {
    fn next_or_same(&self, t: Zdt, zone: &JavaZone) -> R<Option<Zdt>> {
        match self {
            CronField::Bits { ty, bits } => bits_next_or_same(*ty, *bits, t, zone),
            CronField::Quartz { ty, roll_forward, adjuster } => {
                let Some(result) = adjuster.adjust(t, zone)? else {
                    return Ok(None);
                };
                if !result.is_before(&t) {
                    return Ok(Some(result));
                }
                // We ended up before the start, roll forward and try again
                let t = roll_forward.roll_forward(t, zone)?;
                match adjuster.adjust(t, zone)? {
                    Some(result) => Ok(Some(ty.reset(result, zone)?)),
                    None => Ok(None),
                }
            }
            CronField::Composite { fields, .. } => {
                let mut result: Option<Zdt> = None;
                for field in fields {
                    let candidate = field.next_or_same(t, zone)?;
                    match (result, candidate) {
                        (None, _) => result = candidate,
                        (Some(r), Some(c)) if c.is_before(&r) => result = candidate,
                        _ => {}
                    }
                }
                Ok(result)
            }
        }
    }
}

fn bits_next_or_same(ty: Ty, bits: u64, mut t: Zdt, zone: &JavaZone) -> R<Option<Zdt>> {
    let mut current = ty.get(&t);
    let mut next = next_set_bit(bits, current);
    if next == -1 {
        t = ty.roll_forward(t, zone)?;
        next = next_set_bit(bits, 0);
    }
    if next == current {
        return Ok(Some(t));
    }
    let mut count = 0;
    current = ty.get(&t);
    while current != next && {
        count += 1;
        count - 1 < MAX_ATTEMPTS
    } {
        t = ty.elapse_until(t, next, zone)?;
        current = ty.get(&t);
        next = next_set_bit(bits, current);
        if next == -1 {
            t = ty.roll_forward(t, zone)?;
            next = next_set_bit(bits, 0);
        }
    }
    if count >= MAX_ATTEMPTS {
        return Ok(None);
    }
    Ok(Some(ty.reset(t, zone)?))
}

fn at_midnight(t: Zdt, zone: &JavaZone) -> R<Zdt> {
    t.with(F::NanoOfDay, 0, zone)
}

/// The day kept when it did not change, else midnight of the new day.
fn rollback_to_midnight(current: Zdt, result: Zdt, zone: &JavaZone) -> R<Zdt> {
    if result.get(F::DayOfMonth) == current.get(F::DayOfMonth) {
        Ok(current)
    } else {
        at_midnight(result, zone)
    }
}

fn last_day_of_month(t: Zdt, zone: &JavaZone) -> R<Zdt> {
    t.with(F::DayOfMonth, t.range(F::DayOfMonth).1, zone)
}

impl Adjuster {
    fn adjust(self, t: Zdt, zone: &JavaZone) -> R<Option<Zdt>> {
        let result = match self {
            Adjuster::LastDayOfMonth => last_day_of_month(t, zone)?,
            Adjuster::LastWeekdayOfMonth => {
                let last = last_day_of_month(t, zone)?;
                match last.get(F::DayOfWeek) {
                    6 => last.plus(-1, Unit::Days, zone)?,
                    7 => last.plus(-2, Unit::Days, zone)?,
                    _ => last,
                }
            }
            Adjuster::LastDayWithOffset(offset) => {
                last_day_of_month(t, zone)?.plus(i64::from(offset), Unit::Days, zone)?
            }
            Adjuster::WeekdayNearestTo(day) => return weekday_nearest_to(t, i64::from(day), zone),
            Adjuster::LastInMonth(day_of_week) => {
                let last = last_day_of_month(t, zone)?;
                let diff = i64::from(day_of_week) - last.get(F::DayOfWeek);
                let diff = if diff > 0 { diff - 7 } else { diff };
                last.plus(diff, Unit::Days, zone)?
            }
            Adjuster::DayOfWeekInMonth { ordinal, day_of_week } => {
                let first = t.with(F::DayOfMonth, 1, zone)?;
                let diff = (day_of_week - first.get(F::DayOfWeek) as i32 + 7) % 7;
                let diff = diff.wrapping_add(((i64::from(ordinal) - 1) * 7) as i32);
                first.plus(i64::from(diff), Unit::Days, zone)?
            }
        };
        Ok(Some(rollback_to_midnight(t, result, zone)?))
    }
}

fn weekday_nearest_to(mut t: Zdt, day: i64, zone: &JavaZone) -> R<Option<Zdt>> {
    let mut current = t.get(F::DayOfMonth);
    let day_of_week = t.get(F::DayOfWeek);
    if (current == day && day_of_week < 6)
        || (day_of_week == 5 && current == day - 1)
        || (day_of_week == 1 && current == day + 1)
        || (day_of_week == 1 && day == 1 && current == 3)
    {
        return Ok(Some(t));
    }
    let mut count = 0;
    while count < MAX_ATTEMPTS {
        count += 1;
        if current == day {
            match t.get(F::DayOfWeek) {
                // a Saturday 1st moves to Monday the 3rd, any other Saturday to the Friday
                6 if day != 1 => t = t.plus(-1, Unit::Days, zone)?,
                6 => t = t.plus(2, Unit::Days, zone)?,
                7 => t = t.plus(1, Unit::Days, zone)?,
                _ => {}
            }
            return Ok(Some(at_midnight(t, zone)?));
        }
        t = Ty::DayOfMonth.elapse_until(t, day, zone)?;
        current = t.get(F::DayOfMonth);
    }
    Ok(None)
}

// ------------------------------------------------------------------ parsing

const MONTHS: [&str; 12] = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const DAYS: [&str; 7] = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"];

const MACROS: [(&str, &str); 7] = [
    ("@yearly", "0 0 0 1 1 *"),
    ("@annually", "0 0 0 1 1 *"),
    ("@monthly", "0 0 0 1 * *"),
    ("@weekly", "0 0 0 * * 0"),
    ("@daily", "0 0 0 * * *"),
    ("@midnight", "0 0 0 * * *"),
    ("@hourly", "0 0 * * * *"),
];

fn int_of(s: &[u16]) -> Result<i32, String> {
    parse_int(s).ok_or_else(|| format!("For input string: \"{}\"", text(s)))
}

/// `CronField.replaceOrdinals`: upper-cased, the names replaced by their numbers.
fn replace_ordinals(value: &str, names: &[&str]) -> Vec<u16> {
    let mut value = value.to_uppercase();
    for (i, name) in names.iter().enumerate() {
        value = value.replace(name, &(i + 1).to_string());
    }
    utf16(&value)
}

/// `BitsCronField.parseRange`.
fn parse_range(value: &[u16], ty: Ty) -> Result<(i32, i32), String> {
    if is(value, "*") {
        return Ok(ty.range());
    }
    match find(value, b'-') {
        None => {
            let v = ty.check_valid_value(int_of(value)?)?;
            Ok((v, v))
        }
        Some(hyphen) => {
            let min = int_of(&value[..hyphen])?;
            let max = int_of(&value[hyphen + 1..])?;
            let mut min = ty.check_valid_value(min)?;
            let max = ty.check_valid_value(max)?;
            if ty == Ty::DayOfWeek && min == 7 {
                // If used as a minimum in a range, Sunday means 0 (not 7)
                min = 0;
            }
            if min > max {
                return Err("Minimum value must be less than maximum value".to_string());
            }
            Ok((min, max))
        }
    }
}

fn set_bit(bits: &mut u64, index: i32) {
    *bits |= 1u64 << ((index as u32) & 63);
}

fn set_bits(bits: &mut u64, (min, max): (i32, i32), delta: i32) {
    if delta == 1 {
        if min == max {
            set_bit(bits, min);
        } else {
            let min_mask = u64::MAX << ((min as u32) & 63);
            let max_mask = u64::MAX >> ((-(i64::from(max) + 1)) as u32 & 63);
            *bits |= min_mask & max_mask;
        }
    } else {
        // int arithmetic, as Java's loop: a huge delta wraps round and sets odd bits
        let mut i = min;
        while i64::from(i) <= i64::from(max) {
            set_bit(bits, i);
            i = i.wrapping_add(delta);
        }
    }
}

/// `BitsCronField.parseField`.
fn parse_bits(value: &[u16], ty: Ty) -> Result<u64, String> {
    if value.is_empty() {
        return Err("Value must not be empty".to_string());
    }
    let wrap = |e: String| format!("{e} '{}'", text(value));
    let mut bits = 0u64;
    for field in split_commas(value) {
        match find(field, b'/') {
            None => set_bits(&mut bits, parse_range(field, ty).map_err(wrap)?, 1),
            Some(slash) => {
                let (range_str, delta_str) = (&field[..slash], &field[slash + 1..]);
                let mut range = parse_range(range_str, ty).map_err(wrap)?;
                if find(range_str, b'-').is_none() {
                    range.1 = ty.range().1;
                    if range.0 > range.1 {
                        return Err(wrap("Minimum value must be less than maximum value".to_string()));
                    }
                }
                let delta = int_of(delta_str).map_err(wrap)?;
                if delta <= 0 {
                    return Err(wrap("Incrementer delta must be 1 or higher".to_string()));
                }
                set_bits(&mut bits, range, delta);
            }
        }
    }
    Ok(bits)
}

/// `BitsCronField.parseDate`: `?` is `*`.
fn parse_date_bits(value: &[u16], ty: Ty) -> Result<CronField, String> {
    let star = utf16("*");
    let value = if is(value, "?") { &star[..] } else { value };
    let mut bits = parse_bits(value, ty)?;
    if ty == Ty::DayOfWeek && bits & 1 != 0 {
        // cron supports 0 for Sunday; we use 7 like java.time
        bits = (bits | 1 << 7) & !1;
    }
    Ok(CronField::Bits { ty, bits })
}

/// `CronField.parseList`: a field per comma, the earliest answer wins.
fn parse_list(
    value: &[u16],
    ty: Ty,
    parse: impl Fn(&[u16]) -> Result<CronField, String>,
) -> Result<CronField, String> {
    if value.is_empty() {
        return Err("Value must not be empty".to_string());
    }
    let mut fields = split_commas(value).into_iter().map(parse).collect::<Result<Vec<_>, _>>()?;
    Ok(if fields.len() == 1 { fields.remove(0) } else { CronField::Composite { ty, fields } })
}

fn is_quartz_days_of_month(value: &[u16]) -> bool {
    find(value, b'L').is_some() || find(value, b'W').is_some()
}

fn is_quartz_days_of_week(value: &[u16]) -> bool {
    find(value, b'L').is_some() || find(value, b'#').is_some()
}

fn quartz(ty: Ty, roll_forward: Ty, adjuster: Adjuster) -> CronField {
    CronField::Quartz { ty, roll_forward, adjuster }
}

/// `QuartzCronField.parseDaysOfMonth`: `L`, `LW`, `L-n`, `nW`.
fn parse_quartz_days_of_month(value: &[u16]) -> Result<CronField, String> {
    let v = text(value);
    if let Some(idx) = rfind(value, b'L') {
        if idx != 0 {
            return Err(format!("Unrecognized characters before 'L' in '{v}'"));
        }
        let adjuster = if value.len() == 2 && value[1] == u16::from(b'W') {
            Adjuster::LastWeekdayOfMonth
        } else if value.len() == 1 {
            Adjuster::LastDayOfMonth
        } else {
            let offset = int_of(&value[1..])?;
            if offset >= 0 {
                return Err(format!("Offset '{offset} should be < 0 '{v}'"));
            }
            Adjuster::LastDayWithOffset(offset)
        };
        return Ok(quartz(Ty::DayOfMonth, Ty::DayOfMonth, adjuster));
    }
    if let Some(idx) = rfind(value, b'W') {
        if idx == 0 {
            return Err(format!("No day-of-month before 'W' in '{v}'"));
        }
        if idx != value.len() - 1 {
            return Err(format!("Unrecognized characters after 'W' in '{v}'"));
        }
        let day = Ty::DayOfMonth.check_valid_value(int_of(&value[..idx])?)?;
        return Ok(quartz(Ty::DayOfMonth, Ty::DayOfMonth, Adjuster::WeekdayNearestTo(day)));
    }
    Err(format!("No 'L' or 'W' found in '{v}'"))
}

/// `QuartzCronField.parseDayOfWeek`: 0 and 7 are Sunday.
fn parse_day_of_week(value: &[u16]) -> Result<i32, String> {
    let day = int_of(value)?;
    let day = if day == 0 { 7 } else { day };
    if (1..=7).contains(&day) {
        Ok(day)
    } else {
        Err(format!("Invalid value for DayOfWeek: {day} '{}'", text(value)))
    }
}

/// `QuartzCronField.parseDaysOfWeek`: `nL`, `n#k`.
fn parse_quartz_days_of_week(value: &[u16]) -> Result<CronField, String> {
    let v = text(value);
    if let Some(idx) = rfind(value, b'L') {
        if idx != value.len() - 1 {
            return Err(format!("Unrecognized characters after 'L' in '{v}'"));
        }
        if idx == 0 {
            return Err(format!("No day-of-week before 'L' in '{v}'"));
        }
        let day_of_week = parse_day_of_week(&value[..idx])?;
        return Ok(quartz(Ty::DayOfWeek, Ty::DayOfMonth, Adjuster::LastInMonth(day_of_week)));
    }
    if let Some(idx) = rfind(value, b'#') {
        if idx == 0 {
            return Err(format!("No day-of-week before '#' in '{v}'"));
        }
        if idx == value.len() - 1 {
            return Err(format!("No ordinal after '#' in '{v}'"));
        }
        let day_of_week = parse_day_of_week(&value[..idx])?;
        let ordinal = int_of(&value[idx + 1..])?;
        if ordinal <= 0 {
            return Err(format!("Ordinal '{ordinal}' in '{v}' must be positive number "));
        }
        return Ok(quartz(Ty::DayOfWeek, Ty::DayOfMonth, Adjuster::DayOfWeekInMonth { ordinal, day_of_week }));
    }
    Err(format!("No 'L' or '#' found in '{v}'"))
}

fn parse_days_of_month(value: &str) -> Result<CronField, String> {
    let value = utf16(value);
    if !is_quartz_days_of_month(&value) {
        return parse_date_bits(&value, Ty::DayOfMonth);
    }
    parse_list(&value, Ty::DayOfMonth, |field| {
        if is_quartz_days_of_month(field) {
            parse_quartz_days_of_month(field)
        } else {
            parse_date_bits(field, Ty::DayOfMonth)
        }
    })
}

fn parse_days_of_week(value: &str) -> Result<CronField, String> {
    let value = replace_ordinals(value, &DAYS);
    if !is_quartz_days_of_week(&value) {
        return parse_date_bits(&value, Ty::DayOfWeek);
    }
    parse_list(&value, Ty::DayOfWeek, |field| {
        if is_quartz_days_of_week(field) {
            parse_quartz_days_of_week(field)
        } else {
            parse_date_bits(field, Ty::DayOfWeek)
        }
    })
}

fn parse_bits_field(value: &str, ty: Ty) -> Result<CronField, String> {
    Ok(CronField::Bits { ty, bits: parse_bits(&utf16(value), ty)? })
}

// ------------------------------------------------------------------ CronExpression

/// Spring's `CronExpression`: six fields (second minute hour day-of-month month day-of-week) or
/// a macro.
#[derive(Debug, Clone)]
pub struct CronExpression {
    /// day of week, month, day of month, hour, minute, second, and the zero nanosecond: the big
    /// changes first.
    fields: Vec<CronField>,
    expression: String,
}

impl fmt::Display for CronExpression {
    /// The expression parsed, a macro as its six fields.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.expression)
    }
}

impl CronExpression {
    /// `CronExpression.parse`, refusing what Spring refuses.
    pub fn parse(expression: &str) -> Result<CronExpression, String> {
        if expression.is_empty() {
            return Err("Expression must not be empty".to_string());
        }
        let trimmed = java_trim(expression);
        let expression = MACROS
            .iter()
            .find(|(name, _)| equals_ignore_case(trimmed, name))
            .map_or(trimmed, |&(_, fields)| fields)
            .to_string();
        // StringUtils.tokenizeToStringArray(expression, " "): split on spaces, trimmed, no empties
        let fields: Vec<&str> = expression.split(' ').map(java_trim).filter(|t| !t.is_empty()).collect();
        if fields.len() != 6 {
            return Err(format!(
                "Cron expression must consist of 6 fields (found {} in \"{expression}\")",
                fields.len()
            ));
        }
        let parsed = (|| -> Result<Vec<CronField>, String> {
            let seconds = parse_bits_field(fields[0], Ty::Second)?;
            let minutes = parse_bits_field(fields[1], Ty::Minute)?;
            let hours = parse_bits_field(fields[2], Ty::Hour)?;
            let days_of_month = parse_days_of_month(fields[3])?;
            let months = parse_bits(&replace_ordinals(fields[4], &MONTHS), Ty::Month)?;
            let months = CronField::Bits { ty: Ty::Month, bits: months };
            let days_of_week = parse_days_of_week(fields[5])?;
            let zero_nanos = CronField::Bits { ty: Ty::Nano, bits: 1 };
            Ok(vec![days_of_week, months, days_of_month, hours, minutes, seconds, zero_nanos])
        })()
        .map_err(|e| format!("{e} in cron expression \"{expression}\""))?;
        Ok(CronExpression { fields: parsed, expression })
    }

    /// `next(ZonedDateTime)`: the first time after `after` (in `zone`) the expression matches,
    /// or `None` where Spring answers null (or throws).
    pub fn next(&self, after: DateTime<Utc>, zone: &JavaZone) -> Option<DateTime<Utc>> {
        let t = Zdt::of_instant(Instant::of_utc(after), zone).ok()?;
        self.next_zoned(t, zone).ok()??.instant().to_utc()
    }

    fn next_zoned(&self, t: Zdt, zone: &JavaZone) -> R<Option<Zdt>> {
        let mut t = t.plus(1, Unit::Nanos, zone)?;
        for _ in 0..MAX_ATTEMPTS {
            let Some(result) = self.next_or_same_internal(t, zone)? else {
                return Ok(None);
            };
            if result == t {
                return Ok(Some(result));
            }
            t = result;
        }
        Ok(None)
    }

    fn next_or_same_internal(&self, mut t: Zdt, zone: &JavaZone) -> R<Option<Zdt>> {
        for field in &self.fields {
            match field.next_or_same(t, zone)? {
                Some(next) => t = next,
                None => return Ok(None),
            }
        }
        Ok(Some(t))
    }
}

// ------------------------------------------------------------------ CronGrid

/// `CronGrid.parse`: a Unix five-field cron gets Spring's seconds field (`0 `) prepended; six
/// fields and `@macros` are taken as they are; blank is refused.
pub fn parse_cron(cron: &str) -> Result<CronExpression, String> {
    if cron.chars().all(java_is_whitespace) {
        return Err("Cron is empty".to_string());
    }
    let trimmed = java_trim(cron);
    // trimmed.split("\\s+").length == 5
    let words = trimmed.split([' ', '\t', '\n', '\u{B}', '\u{C}', '\r']).filter(|w| !w.is_empty()).count();
    if !trimmed.starts_with('@') && words == 5 {
        return CronExpression::parse(&format!("0 {trimmed}"));
    }
    CronExpression::parse(trimmed)
}

/// `CronGrid.latestTick`: the latest tick at or before `now` and no older than `window`, or
/// `None` when the grid has none in that span. Searches backwards by doubling.
pub fn latest_tick(
    cron: &CronExpression,
    zone: &JavaZone,
    now: DateTime<Utc>,
    window: TimeDelta,
) -> Option<DateTime<Utc>> {
    latest_tick_at(cron, zone, Instant::of_utc(now), window).ok()?.and_then(Instant::to_utc)
}

fn latest_tick_at(cron: &CronExpression, zone: &JavaZone, now: Instant, window: TimeDelta) -> R<Option<Instant>> {
    let now_z = Zdt::of_instant(now, zone)?;
    let floor = Zdt::of_instant(now.minus_delta(window)?, zone)?;
    let mut back: i64 = 1;
    let first = loop {
        let mut from = now_z.plus(-back, Unit::Seconds, zone)?;
        if from.is_before(&floor) {
            from = floor;
        }
        if let Some(candidate) = cron.next_zoned(from, zone)? {
            if !candidate.is_after(&now_z) {
                break candidate;
            }
        }
        if !from.is_after(&floor) {
            return Ok(None);
        }
        back = back.checked_mul(2).ok_or(Overflow)?;
    };
    let mut latest = first;
    while let Some(next) = cron.next_zoned(latest, zone)? {
        if next.is_after(&now_z) {
            break;
        }
        latest = next;
    }
    Ok(Some(latest.instant()))
}

/// The instant `CronGrid`'s periods are measured from: 2026-01-05T00:00:00Z.
fn period_anchor() -> Instant {
    Instant { secs: Date::new(2026, 1, 5).epoch_day() * SECONDS_PER_DAY, nanos: 0 }
}

/// `CronGrid.latestSpreadTick`: the latest tick of `key`'s shifted grid, every tick moved later
/// by [`spread_offset_seconds`].
pub fn latest_spread_tick(
    cron: &CronExpression,
    zone: &JavaZone,
    now: DateTime<Utc>,
    window: TimeDelta,
    key: &str,
) -> Option<DateTime<Utc>> {
    latest_spread_tick_at(cron, zone, Instant::of_utc(now), window, key).ok()?.and_then(Instant::to_utc)
}

fn latest_spread_tick_at(
    cron: &CronExpression,
    zone: &JavaZone,
    now: Instant,
    window: TimeDelta,
    key: &str,
) -> R<Option<Instant>> {
    let offset = spread_offset_at(cron, zone, key)?;
    let tick = latest_tick_at(cron, zone, now.plus_seconds(-offset)?, window)?;
    tick.map(|t| t.plus_seconds(offset)).transpose()
}

/// `CronGrid.spreadOffsetSeconds`: `floorMod(key.hashCode(), period)` with the period
/// [`shortest_gap_seconds`], 0 for a period of a second or less (or where Java would throw).
pub fn spread_offset_seconds(cron: &CronExpression, zone: &JavaZone, key: &str) -> i64 {
    spread_offset_at(cron, zone, key).unwrap_or(0)
}

fn spread_offset_at(cron: &CronExpression, zone: &JavaZone, key: &str) -> R<i64> {
    let period = shortest_gap_at(cron, zone)?;
    if period <= 1 {
        return Ok(0);
    }
    Ok(i64::from(java_hash(key)).rem_euclid(period))
}

/// `CronGrid.shortestGapSeconds`: the shortest gap between consecutive ticks among the 17 from
/// 2026-01-05T00:00:00Z, 0 when there are fewer than two (or where Java would throw).
pub fn shortest_gap_seconds(cron: &CronExpression, zone: &JavaZone) -> i64 {
    shortest_gap_at(cron, zone).unwrap_or(0)
}

fn shortest_gap_at(cron: &CronExpression, zone: &JavaZone) -> R<i64> {
    let mut t = cron.next_zoned(Zdt::of_instant(period_anchor(), zone)?, zone)?;
    let mut shortest = i64::MAX;
    for _ in 0..16 {
        let Some(current) = t else { break };
        let Some(next) = cron.next_zoned(current, zone)? else { break };
        // Duration.between(t, next).getSeconds(): the ticks are whole seconds
        let (a, b) = (current.instant(), next.instant());
        let mut seconds = b.secs - a.secs;
        if b.nanos < a.nanos {
            seconds -= 1;
        }
        shortest = shortest.min(seconds);
        t = Some(next);
    }
    Ok(if shortest == i64::MAX { 0 } else { shortest })
}

#[cfg(test)]
#[path = "cron_tests.rs"]
mod tests;
