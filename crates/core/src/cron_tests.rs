//! `cron.rs` against Spring itself: `cron_fixtures.json` (from `tools/cron_fixtures.jsh`) holds
//! Spring 6.2.1's and JDK 25's answers for every case here; then `CronGridTest` of commons-core and
//! the small helpers.

use std::sync::OnceLock;

use chrono::Datelike;
use serde_json::Value;

use super::*;

fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| serde_json::from_str(include_str!("cron_fixtures.json")).expect("cron_fixtures.json"))
}

fn list(key: &str) -> &'static Vec<Value> {
    fixtures()[key].as_array().unwrap_or_else(|| panic!("{key} in cron_fixtures.json"))
}

fn str_at(v: &Value, i: usize) -> &str {
    v[i].as_str().expect("a string")
}

fn int_at(v: &Value, i: usize) -> i64 {
    v[i].as_i64().expect("a number")
}

fn ints(v: &Value) -> Vec<i64> {
    v.as_array().expect("an array").iter().map(|n| n.as_i64().expect("a number")).collect()
}

fn cron_text(i: i64) -> &'static str {
    str_at(&list("crons")[i as usize], 0)
}

fn next_zone(i: i64) -> JavaZone {
    let id = fixtures()["nextZones"][i as usize].as_str().expect("a zone id");
    zone_of(id).expect("a zone Java accepts")
}

fn instant_ms(ms: i64) -> Instant {
    Instant { secs: ms.div_euclid(1000), nanos: ms.rem_euclid(1000) * 1_000_000 }
}

/// A result as the fixture writes it: epoch seconds or milliseconds, null, or "E" for an exception.
fn encode(result: R<Option<Instant>>, millis: bool) -> Value {
    match result {
        Ok(Some(i)) if millis => Value::from(i.secs * 1000 + i.nanos / 1_000_000),
        Ok(Some(i)) => {
            assert_eq!(i.nanos, 0, "a tick on a whole second");
            Value::from(i.secs)
        }
        Ok(None) => Value::Null,
        Err(Overflow) => Value::from("E"),
    }
}

fn assert_none_failed(what: &str, total: usize, failures: Vec<String>) {
    assert!(total > 0, "no {what} cases");
    assert!(
        failures.is_empty(),
        "{} of {total} {what} cases differ from Java:\n{}",
        failures.len(),
        failures.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}

// ------------------------------------------------------------------ Spring's answers

#[test]
fn parse_accepts_and_refuses_what_spring_does() {
    let mut failures = Vec::new();
    for case in list("crons") {
        let (cron, grid, spring) = (str_at(case, 0), int_at(case, 1) == 1, int_at(case, 2) == 1);
        let (rust_grid, rust_spring) = (parse_cron(cron), CronExpression::parse(cron));
        if rust_grid.is_ok() != grid || rust_spring.is_ok() != spring {
            failures.push(format!(
                "{cron:?}: CronGrid.parse {grid} Spring {spring}, Rust {:?} / {:?}",
                rust_grid.err(),
                rust_spring.err()
            ));
        }
    }
    assert_none_failed("parse", list("crons").len(), failures);
}

#[test]
fn zone_of_accepts_what_java_does_with_its_offsets() {
    let samples = ints(&fixtures()["zoneSamples"]);
    let mut failures = Vec::new();
    for case in list("zones") {
        let (id, ok) = (str_at(case, 0), int_at(case, 1) == 1);
        match (zone_of(id), ok) {
            (Ok(zone), true) => {
                let java = ints(&case[2]);
                let rust: Vec<i64> = samples.iter().map(|&s| i64::from(zone.offset_at(s))).collect();
                if java != rust {
                    failures.push(format!("{id:?}: offsets Java {java:?} Rust {rust:?}"));
                }
            }
            (Err(_), false) => {}
            (rust, _) => failures.push(format!("{id:?}: Java accepts {ok}, Rust {rust:?}")),
        }
    }
    assert_none_failed("zone", list("zones").len(), failures);
}

#[test]
fn next_chains_match_spring() {
    let mut failures = Vec::new();
    for case in list("next") {
        let cron_index = int_at(case, 0);
        let cron = parse_cron(cron_text(cron_index)).expect("a cron Spring accepts");
        let zone = next_zone(int_at(case, 1));
        let start = int_at(case, 2);
        let java = case[3].as_array().expect("results");
        let mut rust = Vec::new();
        let mut at = Zdt::of_instant(instant_ms(start), &zone).expect("a start");
        for _ in 0..java.len() {
            let next = cron.next_zoned(at, &zone);
            rust.push(encode(next.map(|n| n.map(|z| z.instant())), false));
            match next {
                Ok(Some(z)) => at = z,
                _ => break,
            }
        }
        if &rust != java {
            let (cron, zone) = (cron_text(cron_index), &case[1]);
            failures.push(format!("{cron:?} in zone {zone} from {start}: Java {java:?} Rust {rust:?}"));
        }
    }
    assert_none_failed("next", list("next").len(), failures);
}

#[test]
fn ticks_match_cron_grid() {
    let keys = fixtures()["keys"].as_array().expect("keys");
    let mut failures = Vec::new();
    for case in list("tick") {
        let cron_index = int_at(case, 0);
        let cron = parse_cron(cron_text(cron_index)).expect("a cron Spring accepts");
        let zone = next_zone(int_at(case, 1));
        let now = instant_ms(int_at(case, 2));
        let window = TimeDelta::milliseconds(int_at(case, 3));
        let key = keys[int_at(case, 4) as usize].as_str().expect("a key");
        let rust = vec![
            encode(latest_tick_at(&cron, &zone, now, window), true),
            encode(latest_spread_tick_at(&cron, &zone, now, window, key), true),
            spread_offset_at(&cron, &zone, key).map_or(Value::from("E"), Value::from),
        ];
        if rust[..] != case.as_array().expect("a case")[5..] {
            failures.push(format!("{:?}: {case} Rust {rust:?}", cron_text(cron_index)));
        }
    }
    assert_none_failed("tick", list("tick").len(), failures);
}

// ------------------------------------------------------------------ CronGridTest

const UTC: JavaZone = JavaZone::Fixed(0);

fn at(iso: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(iso).expect("an instant").with_timezone(&Utc)
}

fn day() -> TimeDelta {
    TimeDelta::hours(25)
}

fn cron(s: &str) -> CronExpression {
    parse_cron(s).expect("a cron")
}

#[test]
fn five_field_cron_is_read_as_unix_cron() {
    let cron = cron("*/15 * * * *");
    assert_eq!(Some(at("2026-10-09T09:45:00Z")), latest_tick(&cron, &UTC, at("2026-10-09T09:52:31Z"), day()));
}

#[test]
fn six_field_cron_and_macros_are_taken_as_they_are() {
    assert_eq!(
        Some(at("2026-10-09T09:52:30Z")),
        latest_tick(&cron("*/10 * * * * *"), &UTC, at("2026-10-09T09:52:31Z"), day())
    );
    assert_eq!(
        Some(at("2026-10-09T09:00:00Z")),
        latest_tick(&cron("@hourly"), &UTC, at("2026-10-09T09:52:31Z"), day())
    );
    assert!(parse_cron(" ").is_err());
    assert!(parse_cron("not a cron").is_err());
}

#[test]
fn a_tick_exactly_now_is_the_latest() {
    assert_eq!(
        Some(at("2026-10-09T09:00:00Z")),
        latest_tick(&cron("0 * * * *"), &UTC, at("2026-10-09T09:00:00Z"), day())
    );
}

#[test]
fn instances_seconds_apart_land_on_the_same_grid_tick() {
    let cron = cron("* * * * *");
    let early = latest_tick(&cron, &UTC, at("2026-10-09T09:05:00.200Z"), day());
    let late = latest_tick(&cron, &UTC, at("2026-10-09T09:05:47Z"), day());
    assert_eq!(Some(at("2026-10-09T09:05:00Z")), early);
    assert_eq!(early, late);
}

#[test]
fn the_cron_is_read_in_its_zone() {
    // 09:00 in Kolkata is 03:30 UTC.
    let kolkata = zone_of("Asia/Kolkata").expect("a zone");
    assert_eq!(
        Some(at("2026-10-09T03:30:00Z")),
        latest_tick(&cron("0 9 * * *"), &kolkata, at("2026-10-09T05:00:00Z"), day())
    );
}

#[test]
fn sparse_crons_are_found_across_the_whole_window() {
    assert_eq!(
        Some(at("2026-10-01T00:00:00Z")),
        latest_tick(&cron("0 0 1 * *"), &UTC, at("2026-10-09T09:00:00Z"), TimeDelta::days(31))
    );
    // Older than the window: nothing to catch up.
    assert_eq!(None, latest_tick(&cron("0 0 1 * *"), &UTC, at("2026-10-09T09:00:00Z"), day()));
}

// ------------------------------------------------------------------ the public surface

#[test]
fn next_answers_in_utc_and_none_past_chrono() {
    let new_york = zone_of("America/New_York").expect("a zone");
    // 02:30 does not exist on 2026-03-08 in New York: setting the hour to 2 lands on 03:00 EDT,
    // past the hour, so Spring rolls on to the next day.
    assert_eq!(
        Some(at("2026-03-09T06:30:00Z")),
        cron("0 30 2 * * *").next(at("2026-03-08T05:00:00Z"), &new_york)
    );
    // 01:30 happens twice on 2026-11-01: once in EDT, and again in EST.
    let overlap = cron("0 30 1 * * *");
    assert_eq!(Some(at("2026-11-01T05:30:00Z")), overlap.next(at("2026-11-01T04:00:00Z"), &new_york));
    assert_eq!(Some(at("2026-11-01T06:30:00Z")), overlap.next(at("2026-11-01T05:30:00Z"), &new_york));
    assert_eq!(None, cron("0 0 0 30 2 *").next(at("2026-01-01T00:00:00Z"), &UTC));
    // Spring answers year 5881636, which chrono cannot hold.
    assert_eq!(None, cron("0 0 0 ? * 1#2147483647").next(at("2026-01-01T00:00:00Z"), &UTC));
}

#[test]
fn spread_offsets_and_gaps() {
    let every_quarter = cron("*/15 * * * *");
    assert_eq!(900, shortest_gap_seconds(&every_quarter, &UTC));
    // "Aa" and "BB" share Java's hash 2112
    assert_eq!(2112 % 900, spread_offset_seconds(&every_quarter, &UTC, "Aa"));
    assert_eq!(2112 % 900, spread_offset_seconds(&every_quarter, &UTC, "BB"));
    assert_eq!(0, spread_offset_seconds(&cron("* * * * * *"), &UTC, "Aa"));
    assert_eq!(0, shortest_gap_seconds(&cron("0 0 0 30 2 *"), &UTC));
    assert_eq!(0, spread_offset_seconds(&cron("0 0 0 ? * 1#2147483647"), &UTC, "Aa"));
    assert_eq!(
        Some(at("2026-10-09T09:50:12Z")),
        latest_spread_tick(&every_quarter, &UTC, at("2026-10-09T09:52:31Z"), day(), "Aa")
    );
    assert_eq!(None, latest_spread_tick(&cron("0 0 1 * *"), &UTC, at("2026-10-09T09:00:00Z"), day(), "Aa"));
}

#[test]
fn macros_print_as_their_fields() {
    assert_eq!("0 0 * * * *", cron("@HOURLY").to_string());
    assert_eq!("0 */15 * * * *", cron("*/15 * * * *").to_string());
    assert_eq!("0 0 0 * * *", cron("@da\u{131}ly").to_string());
}

#[test]
fn java_ints_hashes_and_zone_forms() {
    let p = |s: &str| parse_int(&utf16(s));
    assert_eq!(Some(5), p("+5"));
    assert_eq!(Some(0), p("-0"));
    assert_eq!(Some(3), p("\u{663}"));
    assert_eq!(Some(13), p("\u{FF11}\u{FF13}"));
    assert_eq!(Some(i32::MAX), p("2147483647"));
    assert_eq!(Some(i32::MIN), p("-2147483648"));
    for bad in ["2147483648", "-2147483649", "+", "-", "", "1a", "1 ", "+-1", "\u{1D7CE}"] {
        assert_eq!(None, p(bad), "{bad:?}");
    }
    assert_eq!(2112, java_hash("Aa"));
    assert_eq!(1_772_899, java_hash("\u{1F600}"));
    let forms = [
        ("Z", 0),
        ("UTC", 0),
        ("GMT", 0),
        ("UT", 0),
        ("+5", 18_000),
        ("-05", -18_000),
        ("+0530", 19_800),
        ("+05:30", 19_800),
        ("+05:30:15", 19_815),
        ("+053015", 19_815),
        ("UTC+05:30", 19_800),
        ("GMT+5", 18_000),
        ("UT-3", -10_800),
        ("-18:00", -64_800),
    ];
    for (id, seconds) in forms {
        assert_eq!(Ok(JavaZone::Fixed(seconds)), zone_of(id), "{id}");
    }
    for bad in ["", "z", "+", "+5:30", "+18:01", "+19", "UTC+", "UTC0", "asia/kolkata", " UTC", "EST", "05:30"] {
        assert!(zone_of(bad).is_err(), "{bad:?}");
    }
    assert_eq!(Ok(JavaZone::Region(Tz::Asia__Kolkata)), zone_of("Asia/Kolkata"));
    assert_eq!(Ok(JavaZone::SystemV(-18_000)), zone_of("SystemV/EST5EDT"));
    assert_eq!(Ok(JavaZone::Fixed(-18_000)), zone_of("SystemV/EST5"));
}

// ------------------------------------------------------------------ java.time edges the corpus cannot reach

#[test]
fn dates_match_the_proleptic_gregorian_calendar() {
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("a date");
    let (first, last) = (chrono::NaiveDate::MIN - epoch, chrono::NaiveDate::MAX - epoch);
    let mut day = first.num_days();
    while day <= last.num_days() {
        let date = Date::of_epoch_day(day).expect("a date");
        let c = epoch + TimeDelta::days(day);
        let chrono = (c.year(), c.month(), c.day(), c.weekday().number_from_monday());
        let chrono = (i64::from(chrono.0), i64::from(chrono.1), i64::from(chrono.2), i64::from(chrono.3));
        assert_eq!((date.year, date.month, date.day, date.day_of_week()), chrono, "epoch day {day}");
        assert_eq!(day, date.epoch_day());
        day += 9_973;
    }
    assert_eq!(Err(Overflow), Date::of_epoch_day(MAX_EPOCH_DAY + 1));
    assert_eq!(Err(Overflow), Date::of_epoch_day(MIN_EPOCH_DAY - 1));
    assert_eq!(Ok(Date::new(MAX_YEAR, 12, 31)), Date::of_epoch_day(MAX_EPOCH_DAY));
    assert_eq!(Ok(Date::new(MIN_YEAR, 1, 1)), Date::of_epoch_day(MIN_EPOCH_DAY));

    let leap_day = Date::new(2028, 2, 29);
    assert_eq!(Ok(leap_day), leap_day.plus_months(0));
    assert_eq!(Ok(leap_day), leap_day.plus_years(0));
    assert_eq!(Ok(Date::new(2029, 2, 28)), leap_day.plus_years(1));
    assert_eq!(Ok(Date::new(2028, 4, 29)), leap_day.plus_months(2));
    assert_eq!(Ok(Date::new(2027, 11, 29)), leap_day.plus_months(-3));
    assert_eq!(Err(Overflow), Date::new(MAX_YEAR, 12, 1).plus_months(1));
    assert_eq!(Err(Overflow), Date::new(MAX_YEAR, 1, 1).plus_years(1));
    assert_eq!(Err(Overflow), leap_day.plus_years(i64::MAX));
    assert_eq!(Err(Overflow), leap_day.plus_days(i64::MAX));
}

#[test]
fn local_date_times_refuse_what_java_refuses() {
    let ldt = Ldt::of_epoch_second(Date::new(2026, 2, 10).epoch_day() * SECONDS_PER_DAY, 5).expect("a time");
    assert_eq!(Err(Overflow), ldt.with(F::HourOfDay, 24));
    assert_eq!(Err(Overflow), ldt.with(F::DayOfMonth, 29));
    assert_eq!(Err(Overflow), ldt.with(F::MonthOfYear, 0));
    assert_eq!(Ok(Date::new(2026, 2, 15)), ldt.with(F::DayOfWeek, 7).map(|l| l.date));
    assert_eq!(Ok(5), ldt.with(F::SecondOfMinute, 59).map(|l| l.nano()));
    let last = Instant { secs: i64::MAX, nanos: 0 };
    assert_eq!(Err(Overflow), last.plus_seconds(1));
    assert_eq!(Err(Overflow), Zdt::of_instant(Instant { secs: i64::MAX - 10, nanos: 0 }, &UTC));
    assert_eq!(None, Instant { secs: i64::MAX / 2, nanos: 0 }.to_utc());
}

#[test]
fn system_v_zones_keep_the_old_us_rules() {
    let est5edt = zone_of("SystemV/EST5EDT").expect("a zone");
    let offset = |iso: &str| est5edt.offset_at(at(iso).timestamp());
    assert_eq!(-18_000, offset("1850-07-01T00:00:00Z"));
    assert_eq!(-14_400, offset("1974-01-07T00:00:00Z"));
    assert_eq!(-14_400, offset("1974-11-20T00:00:00Z"));
    assert_eq!(-18_000, offset("1974-12-01T00:00:00Z"));
    // April's last Sunday, not March's second.
    assert_eq!(-18_000, offset("2026-03-15T12:00:00Z"));
    assert_eq!(-14_400, offset("2026-04-26T07:00:00Z"));
    assert_eq!(-18_000, offset("2026-04-26T06:59:59Z"));
}

#[test]
fn fields_that_never_match_give_up_as_spring_does() {
    let monday = Zdt::of_instant(Instant::of_utc(at("2026-10-12T00:00:00Z")), &UTC).expect("a time");
    // a day-of-week bit 0 (Spring moves it to 7): the field never matches
    assert_eq!(Ok(None), bits_next_or_same(Ty::DayOfWeek, 1, monday, &UTC));
    // no month has a 32nd
    let never = CronField::Quartz {
        ty: Ty::DayOfMonth,
        roll_forward: Ty::DayOfMonth,
        adjuster: Adjuster::WeekdayNearestTo(32),
    };
    assert_eq!(Ok(None), never.next_or_same(monday, &UTC));
}
