// Regenerates crates/core/src/cron_fixtures.json: Spring's own answers for the cron corpus that
// crates/core/src/cron_tests.rs replays against crates/core/src/cron.rs.
//
// Run from the workspace root with JDK 25 (tzdata 2025b, the data chrono-tz 0.10.4 carries):
//
//   M2=~/.m2/repository/org/springframework
//   jshell --class-path $M2/spring-context/6.2.1/spring-context-6.2.1.jar:$M2/spring-core/6.2.1/spring-core-6.2.1.jar \
//       -R-Dout=crates/core/src/cron_fixtures.json tools/cron_fixtures.jsh
//
// The JSON:
//   crons  [cron, CronGrid.parse accepts (0/1), CronExpression.parse accepts (0/1)]
//   zones  [id, ZoneId.of accepts (0/1), offsets in seconds at zoneSamples (null when refused)]
//   zoneSamples  epoch seconds
//   nextZones    the zones the next and tick cases use
//   next   [cron index, zone index, start epoch ms, results]: each result is CronGrid.parse(cron).next
//          of the one before (the first of the start), as epoch seconds, null for null, "E" for an
//          exception; a chain stops at null or "E"
//   keys   the spread keys
//   tick   [cron index, zone index, now epoch ms, window ms, key index, latestTick ms,
//          latestSpreadTick ms, spreadOffsetSeconds] (null for null, "E" for an exception)

import java.time.*;
import java.time.zone.*;
import java.util.*;
import org.springframework.scheduling.support.CronExpression;

// ---- CronGrid.java of commons-core (com.fincity.saas.commons.core.scheduler), as it is

final class CronGrid {

    private CronGrid() {
    }

    public static CronExpression parse(String cron) {

        if (cron == null || cron.isBlank())
            throw new IllegalArgumentException("Cron is empty");

        String trimmed = cron.trim();
        if (!trimmed.startsWith("@") && trimmed.split("\\s+").length == 5)
            trimmed = "0 " + trimmed;

        return CronExpression.parse(trimmed);
    }

    public static Instant latestTick(CronExpression cron, ZoneId zone, Instant now, Duration window) {

        ZonedDateTime nowZ = now.atZone(zone);
        ZonedDateTime floor = now.minus(window).atZone(zone);

        Duration back = Duration.ofSeconds(1);
        ZonedDateTime first = null;

        while (true) {
            ZonedDateTime from = nowZ.minus(back);
            if (from.isBefore(floor))
                from = floor;

            ZonedDateTime candidate = cron.next(from);
            if (candidate != null && !candidate.isAfter(nowZ)) {
                first = candidate;
                break;
            }

            if (!from.isAfter(floor))
                return null;

            back = back.multipliedBy(2);
        }

        ZonedDateTime latest = first;
        ZonedDateTime next = cron.next(latest);
        while (next != null && !next.isAfter(nowZ)) {
            latest = next;
            next = cron.next(latest);
        }

        return latest.toInstant();
    }

    private static final Instant PERIOD_ANCHOR = Instant.parse("2026-01-05T00:00:00Z");

    public static Instant latestSpreadTick(CronExpression cron, ZoneId zone, Instant now, Duration window,
            String key) {

        long offset = spreadOffsetSeconds(cron, zone, key);
        Instant tick = latestTick(cron, zone, now.minusSeconds(offset), window);
        return tick == null ? null : tick.plusSeconds(offset);
    }

    static long spreadOffsetSeconds(CronExpression cron, ZoneId zone, String key) {

        long period = shortestGapSeconds(cron, zone);
        if (period <= 1)
            return 0;
        return Math.floorMod((long) key.hashCode(), period);
    }

    private static long shortestGapSeconds(CronExpression cron, ZoneId zone) {

        ZonedDateTime t = cron.next(PERIOD_ANCHOR.atZone(zone));
        long shortest = Long.MAX_VALUE;
        for (int i = 0; i < 16 && t != null; i++) {
            ZonedDateTime next = cron.next(t);
            if (next == null)
                break;
            shortest = Math.min(shortest, Duration.between(t, next).getSeconds());
            t = next;
        }
        return shortest == Long.MAX_VALUE ? 0 : shortest;
    }
}

// ---- JSON

String q(String s) {
    StringBuilder b = new StringBuilder("\"");
    for (char c : s.toCharArray()) {
        if (c == '"' || c == '\\') b.append('\\').append(c);
        else if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
        else b.append(c);
    }
    return b.append('"').toString();
}

long ms(String iso) { return Instant.parse(iso).toEpochMilli(); }

// ---- the crons

List<String> cronCorpus = new ArrayList<>();

// whole expressions: realistic ones, macros, token counts, whitespace
cronCorpus.addAll(List.of(
    "* * * * * *", "0 * * * * *", "*/10 * * * * *", "0 */5 * * * *", "0 0 * * * *", "0 30 * * * *",
    "0 0 0 * * *", "0 0 12 * * *", "0 15 10 * * *", "0 0 9-17 * * MON-FRI", "0 0/30 8-10 * * *",
    "0 0 8,12,18 * * *", "0 0 2 * * *", "0 30 2 * * *", "0 0 1 * * *", "0 30 1 * * *", "0 15 2 * * *",
    "0 45 1 * * *", "0 0 3 * * *", "0 30 0 * * *", "0 0 23 * * *", "0 59 23 * * *", "0 0/20 1-3 * * *",
    "0 0 2 * * SUN", "0 0 0 * * SUN", "0 45 1 * * SUN", "0 0 0 1 * *", "0 0 0 1 1 *", "0 0 0 29 2 *",
    "0 0 0 31 * *", "0 0 0 30 2 *", "0 0 0 31 4 *", "0 0 0 31 2,4,6 *", "0 0 0 29 2 MON", "0 0 0 13 * FRI",
    "0 0 12 1W * *", "0 0 0 L * *", "0 0 0 LW * *", "0 0 0 L-2 * *", "0 0 0 15W * *", "0 0 0 ? * 5L",
    "0 0 0 ? * MON#1", "0 0 0 ? * FRI#5", "0 0 6 ? * 6L", "0 30 9 L * ?", "0 0 0 L 2 *", "0 0 0 29W 2 *",
    "1 2 3 4 5 6", "59 59 23 31 12 *", "0 0 0 ? * 1#2147483647", "0 0 0 ? * 1#100000", "0 0 0 ? * 7#5",
    "0 0 0 ? * 1#306783379", "0 0 0 ? * 1#306783378", "0 0 0 ? * 3#613566757",
    "*/15 * * * *", "0 9 * * *", "0 9 * * 1-5", "30 2 * * *", "0 0 1 * *", "0 0 L * *", "0 0 * * 0",
    "* * * * *", "0 0 29 2 *", "15 1 * * SUN", "0 */4 * * *", "0 0 0 * *", "0 0 * * * * *", "0 0 * *",
    "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly", "@HOURLY", "@Daily",
    " @daily ", "@weekly\t", "@reboot", "@ daily", "@daily 0", "@hourly *", "@", "@daiıly", "@daıly",
    "@weekKly", "@DAİLY", "@daily ", " @daily",
    "", " ", "\t", " ", " ", "\u0000", "not a cron", "0", "0 0", "0 0 0", "0 0 0 *",
    "  0  0  *  *  *  *  ", "0\t0 * * * * *", "0\t0 * * *", "*\t* * * * *", "\t0 0 * * * *\t",
    "0 0 * * * *\n", "\n0 0 * * *", "0 0 * * * ", "0 0 * * * *", "0 0 0 * * * 2026",
    "0,30 0 0 * * *", "0 0 0 1-31/2 * *", "0 0 0 */2 * *", "0 0 0 2/3 * *", "0 0 0 * */3 *",
    "0 0 0 * 2/2 *", "0 0 0 1,15 * MON", "0 0 0 L * FRI", "0 0 0 1W * MON-FRI", "0 0 0 15 * 5L",
    "0 0 0 ? * 1-3,6#3", "0 0 0 ? * MON,5L", "0 0 0 ? * 1#1,5L", "0 0 0 1,L * *", "0 0 0 L,15 * *",
    "0 0 0 15W,L * *", "0 0 0 ?,L * *", "0 0 0 1W,15W * *", "0 0 0 1-5,L-2 * *", "0 0 0 * * 7-1",
    "0 0 0 31W * *", "0 0 0 1W * *", "0 0 0 L-30 * *", "0 0 0 L-31 * *", "0 0 0 L-1 * *",
    "5/2147483647 * * * * *", "1/2147483647 * * * * *", "0 0/2147483647 * * * *", "0 0 3/2147483646 * * *",
    "0 0 0 ? * 0#5", "0 0 0 ? * SUN#2", "0 0 0 ? * sun#2", "0 0 0 ? * 1#6", "0 0 0 ? * 2#53"
));

// one field at a time against "0 0 0 * * *"
String[] base = {"0", "0", "0", "*", "*", "*"};
String[][] variants = {
    {"0", "*", "*/5", "0/15", "5/15", "10-20", "10-20/3", "59", "60", "-1", "+5", "05", "1,2,3", "1,,2", "1,",
     ",", "?", "*/0", "*/-1", "*/+5", "*/60", "0-59/60", "30-10", "a", "٣", "３", "1-", "-5", "5-",
     "*/", "/5", "*/5/2", "0x1", "1.5", "2147483648", "-0", "+0", "1-2-3", "59-59", "0-59", "+1-+3",
     "١٥", "1/0", "7/7", "0-0", "*/1", "*/59", "1,30-40/5,59", "**", "*-5"},
    {"*", "0", "59", "60", "*/7", "3/7", "50-10/2", "0-59/30", "15,45", "٣٠", "-0", "1-1"},
    {"*", "0", "1", "2", "3", "12", "23", "24", "9-17", "*/2", "1/3", "0,12", "22-2", "0-23/6", "?", "1-3/2"},
    {"*", "?", "1", "15", "28", "29", "30", "31", "32", "0", "L", "LW", "L-1", "L-3", "L-15", "L-30", "L-31",
     "L-32", "L-0", "L3", "L+3", "1W", "15W", "28W", "30W", "31W", "0W", "32W", "W", "W1", "1W1", "1L", "l",
     "lw", "LW1", "LL", "WL", "1-15", "*/2", "2/3", "1,L", "L,15", "15W,L", "?,L", "L,?", "?,1", "1W,15W",
     "1-5,L-2", "L-٣", "15w", "L-2147483648", "L-2147483647", "2147483647W", "١W", "+1W", "L,", "LW,W",
     "1-31", "31-1", "?/2", "L/2", "1W-2"},
    {"*", "1", "2", "12", "13", "0", "JAN", "jan", "Feb", "JAN-MAR", "MAR-JAN", "2-4", "*/3", "2/2", "JAN,JUL",
     "DEC", "DECEMBER", "?", "FEB,APR,JUN", "4,6,9,11", "ſep", "jul-ſep", "MAYJUN", "1-12/4", "NOV-DEC",
     "jaɴ", "L"},
    {"*", "?", "0", "7", "1", "MON", "mon", "MON-FRI", "SUN", "SAT,SUN", "0-7", "7-7", "7-1", "6-0", "5-7", "1-5",
     "*/2", "0/2", "2/3", "7/2", "0-0", "8", "-1", "L", "5L", "0L", "7L", "8L", "l", "5l", "fril", "FRIL", "1#1",
     "1#2", "MON#1", "mon#2", "5#5", "7#5", "SUN#2", "1#0", "1#-1", "#1", "1#", "1#1#2", "1-5#2", "1#6", "1#100",
     "MON,5L", "1-3,6#3", "1#1,5L", "5L,1#1", "ſun", "MONDAY", "TUES", "1,L", "?,5L", "5L,?", "TUE-THU",
     "SUN-SAT", "SAT-SUN", "THU#٣", "٥L", "1#+2", "+5L", "5LL", "L5", "5L1", "1#2L", "2#1,3#2,4#3"}
};
for (int f = 0; f < 6; f++) {
    for (String v : variants[f]) {
        String[] parts = base.clone();
        parts[f] = v;
        cronCorpus.add(String.join(" ", parts));
    }
}
// the crons the clock-change chains and the ticks use
List<String> dstCrons = List.of("0 0 * * * *", "0 30 * * * *", "0 */15 * * * *", "0 0/20 1-3 * * *", "0 0 2 * * *",
    "0 30 2 * * *", "0 0 1 * * *", "0 30 1 * * *", "0 15 2 * * *", "0 45 1 * * *", "0 0 0 * * *", "0 30 0 * * *",
    "0 0 23 * * *", "0 0 3 * * *", "0 0 0 L * *", "0 0 0 LW * *", "0 0 0 ? * 5L", "0 0 0 ? * SUN#1",
    "0 0 0 1W * *", "0 0 2 * * SUN", "@daily", "@hourly", "@weekly", "0 59 23 * * *", "* * * * * *",
    "0 45 1 * * SUN", "0 0 0 L-2 * *", "0 0 0 15W * *");
List<String> tickCrons = List.of("*/15 * * * *", "*/10 * * * * *", "@hourly", "0 * * * *", "* * * * *",
    "0 9 * * *", "0 0 1 * *", "0 30 2 * * *", "0 30 1 * * *", "0 0 2 * * SUN", "0 */5 * * * *",
    "0 0 0 L * *", "0 0 0 ? * 5L", "0 0 9-17 * * MON-FRI", "0 0 0 29 2 *", "0 0 0 30 2 *", "@daily", "@weekly",
    "@monthly", "@yearly", "0 0/20 1-3 * * *", "0 15 2 * * *", "0 45 1 * * *", "0 0 0 * * *", "* * * * * *",
    "5/2147483647 * * * * *", "0 0 0 1W * *", "0 0 0 ? * 1#2147483647", "0 0 12 1W * *", "0 0 0 ? * MON#1");
cronCorpus.addAll(dstCrons);
cronCorpus.addAll(tickCrons);
List<String> crons = new ArrayList<>(new LinkedHashSet<>(cronCorpus));

// ---- the zones and instants

List<String> nextZones = List.of("UTC", "Asia/Kolkata", "America/New_York", "Europe/London",
        "Australia/Lord_Howe", "America/Sao_Paulo", "+05:45", "GMT-3");

List<Long> starts = new ArrayList<>();
for (String iso : List.of(
        "2026-01-31T23:59:59.999Z", "2026-02-28T12:00:00Z", "2028-02-28T23:30:00Z", "2028-02-29T12:00:00Z",
        "2024-02-29T00:00:00Z", "2026-12-31T23:59:59.999Z", "2027-12-31T22:00:00Z", "2026-10-09T09:52:31.123Z",
        "2026-03-08T06:59:59Z", "2026-11-01T05:30:00Z", "2026-03-29T00:59:59Z", "2026-10-25T00:30:00Z",
        "2026-04-04T14:45:00Z", "2026-10-03T15:30:00Z", "2018-11-04T02:59:59Z", "2019-02-17T01:30:00Z",
        "2099-12-31T12:00:00Z", "2100-02-28T12:00:00Z", "1999-12-31T23:59:59Z", "2026-06-30T23:59:59.500Z",
        "2026-01-05T00:00:00Z", "2030-03-31T00:00:00.001Z")) {
    starts.add(ms(iso));
}

// starts around each zone's own clock changes
Map<String, List<Long>> transitionStarts = new LinkedHashMap<>();
for (String id : nextZones) {
    ZoneRules rules = ZoneId.of(id).getRules();
    List<Long> list = new ArrayList<>();
    for (String from : List.of("2018-06-01T00:00:00Z", "2026-01-01T00:00:00Z", "2105-01-01T00:00:00Z")) {
        Instant at = Instant.parse(from);
        for (int i = 0; i < 2; i++) {
            ZoneOffsetTransition tr = rules.nextTransition(at);
            if (tr == null || tr.getInstant().isAfter(Instant.parse(from).plus(Duration.ofDays(800)))) break;
            long t = tr.getInstant().toEpochMilli();
            list.add(t - 7_201_000L);
            list.add(t - 1L);
            list.add(t + 1_800_000L);
            at = tr.getInstant();
        }
    }
    if (list.isEmpty()) list.addAll(List.of(ms("2026-02-28T23:59:59Z"), ms("2028-02-29T20:00:00Z"), ms("2026-12-31T18:30:00Z")));
    transitionStarts.put(id, list);
}

String result(ZonedDateTime z) {
    if (z.getNano() != 0) throw new AssertionError("nanos " + z);
    return Long.toString(z.toEpochSecond());
}

String chain(CronExpression cron, ZoneId zone, long startMs, int length) {
    List<String> out = new ArrayList<>();
    ZonedDateTime z = Instant.ofEpochMilli(startMs).atZone(zone);
    for (int n = 0; n < length; n++) {
        try {
            z = cron.next(z);
        } catch (RuntimeException e) {
            out.add("\"E\"");
            break;
        }
        if (z == null) {
            out.add("null");
            break;
        }
        out.add(result(z));
    }
    return "[" + String.join(",", out) + "]";
}

// ---- crons: parse

StringBuilder json = new StringBuilder("{\n");
json.append("\"crons\": [\n");
List<CronExpression> grid = new ArrayList<>();
for (int i = 0; i < crons.size(); i++) {
    String s = crons.get(i);
    CronExpression g = null;
    boolean springOk;
    try { g = CronGrid.parse(s); } catch (IllegalArgumentException e) { }
    try { CronExpression.parse(s); springOk = true; } catch (IllegalArgumentException e) { springOk = false; }
    grid.add(g);
    json.append("[").append(q(s)).append(",").append(g != null ? 1 : 0).append(",").append(springOk ? 1 : 0)
        .append("]").append(i + 1 < crons.size() ? ",\n" : "\n");
}
json.append("],\n");

// ---- zones: ZoneId.of

long[] zoneSamples = {
    Instant.parse("1950-07-01T00:00:00Z").getEpochSecond(), Instant.parse("2026-01-15T12:00:00Z").getEpochSecond(),
    Instant.parse("2026-07-15T12:00:00Z").getEpochSecond(), Instant.parse("2150-01-15T12:00:00Z").getEpochSecond(),
    Instant.parse("2150-07-15T12:00:00Z").getEpochSecond(), Instant.parse("1975-03-01T12:00:00Z").getEpochSecond()};
List<String> zoneIds = new ArrayList<>(new TreeSet<>(ZoneId.getAvailableZoneIds()));
zoneIds.addAll(List.of("EST", "MST", "HST", "ROC", "GMT+0", "GMT-0", "UTC0", "Z", "z", "UT", "UTC", "GMT",
    "+5", "-5", "+05", "+0530", "+05:30", "+05:30:15", "+053015", "+5:30", "+05:3", "+05:60", "+18", "+18:00",
    "+18:01", "-18:00", "+19", "+1800", "05:30", "+05-30", "+05:30:", "UTC+05:30", "UTC-05:30", "GMT+5", "GMT-5",
    "UT-3", "UT+3", "UTC+", "UTC-", "GMT+", "UT+", "UTC+18", "UTC+19", "UTC+00", "UTC-00", "UTC+0", "GMT+05:45:30",
    "UTCX", "UTC/", "GMT0", "UCT", "Universal", "Zulu", "asia/kolkata", "Asia/kolkata", "ASIA/KOLKATA", "",
    " ", "Asia/Kolkata ", " UTC", "Mars/Olympus", "A", "+", "-", "+٥", "1Asia", "/UTC", "Etc/GMT+5",
    "Etc/GMT-14", "SystemV/EST5EDT", "SystemV/AST4", "SystemV/XYZ", "US/Pacific", "Asia/Calcutta", "Factory",
    "posixrules", "localtime", "Etc/Unknown", "America/Coyhaique", "Asia/Kolkataé", "Europe/Kyiv",
    "Europe/Kiev", "WET", "CET", "EST5EDT", "PST8PDT", "+05:30:60", "-00:00", "+00", "Z0", "ZZ"));
zoneIds = new ArrayList<>(new LinkedHashSet<>(zoneIds));
json.append("\"zoneSamples\": ").append(Arrays.toString(zoneSamples)).append(",\n");
json.append("\"zones\": [\n");
for (int i = 0; i < zoneIds.size(); i++) {
    String id = zoneIds.get(i);
    String offsets = "null";
    int ok = 0;
    try {
        ZoneRules rules = ZoneId.of(id).getRules();
        ok = 1;
        List<String> o = new ArrayList<>();
        for (long s : zoneSamples) o.add(Integer.toString(rules.getOffset(Instant.ofEpochSecond(s)).getTotalSeconds()));
        offsets = "[" + String.join(",", o) + "]";
    } catch (DateTimeException e) { }
    json.append("[").append(q(id)).append(",").append(ok).append(",").append(offsets).append("]")
        .append(i + 1 < zoneIds.size() ? ",\n" : "\n");
}
json.append("],\n");

// ---- next chains

json.append("\"nextZones\": [");
for (int z = 0; z < nextZones.size(); z++) json.append(z > 0 ? "," : "").append(q(nextZones.get(z)));
json.append("],\n\"next\": [\n");
List<String> nextCases = new ArrayList<>();
for (int i = 0; i < crons.size(); i++) {
    CronExpression cron = grid.get(i);
    if (cron == null) continue;
    for (int k = 0; k < 6; k++) {
        int z = (i * 3 + k) % nextZones.size();
        long start = starts.get((i * 7 + k * 5) % starts.size());
        nextCases.add("[" + i + "," + z + "," + start + "," + chain(cron, ZoneId.of(nextZones.get(z)), start, 3) + "]");
    }
}
// clock changes: the crons near the changed hours, in every zone, around every change

for (String c : dstCrons) {
    int i = crons.indexOf(c);
    if (i < 0) throw new AssertionError("not in the corpus: " + c);
    for (int z = 0; z < nextZones.size(); z++) {
        for (long start : transitionStarts.get(nextZones.get(z))) {
            nextCases.add("[" + i + "," + z + "," + start + "," + chain(grid.get(i), ZoneId.of(nextZones.get(z)), start, 4) + "]");
        }
    }
}
json.append(String.join(",\n", nextCases)).append("\n],\n");

// ---- CronGrid ticks

List<String> keys = List.of("", "a", "tenant-42/schedule-7", "SYSTEM.cleanup", "ünïcødé",
    "😀", "Aa", "BB", "a-rather-long-key-for-a-schedule-of-some-client-and-some-app-0123456789");
json.append("\"keys\": [");
for (int k = 0; k < keys.size(); k++) json.append(k > 0 ? "," : "").append(q(keys.get(k)));
json.append("],\n\"tick\": [\n");

long[] nows = {
    ms("2026-10-09T09:52:31.123Z"), ms("2026-10-09T09:00:00Z"), ms("2026-03-08T07:30:00Z"),
    ms("2026-11-01T06:15:00Z"), ms("2026-11-01T05:45:00Z"), ms("2026-04-04T15:20:00Z"), ms("2026-10-03T16:00:00Z"),
    ms("2026-01-01T00:00:00Z"), ms("2028-02-29T12:00:00.999Z"), ms("2018-11-04T03:30:00Z"),
    ms("2019-02-17T02:30:00Z"), ms("2026-03-29T01:30:00Z"), ms("2026-10-25T01:30:00Z"), ms("2026-10-09T09:05:00.200Z")};
long[] windows = {1_000L, 60_000L, 3_600_000L, 90_000_000L, 31L * 86_400_000L, 400L * 86_400_000L, 0L, 1_500L,
    7L * 86_400_000L, -1_000L};
String instantOrNull(Instant i) { return i == null ? "null" : Long.toString(i.toEpochMilli()); }
List<String> tickCases = new ArrayList<>();
for (int t = 0; t < tickCrons.size(); t++) {
    int i = crons.indexOf(tickCrons.get(t));
    if (i < 0) throw new AssertionError("not in the corpus: " + tickCrons.get(t));
    CronExpression cron = grid.get(i);
    for (int k = 0; k < 16; k++) {
        int z = (t + k) % nextZones.size();
        long now = nows[(t * 5 + k * 3) % nows.length];
        long window = windows[(t + k * 7) % windows.length];
        int key = (t * 3 + k) % keys.size();
        ZoneId zone = ZoneId.of(nextZones.get(z));
        String latest, spread, offset;
        try { latest = instantOrNull(CronGrid.latestTick(cron, zone, Instant.ofEpochMilli(now), Duration.ofMillis(window))); }
        catch (RuntimeException e) { latest = "\"E\""; }
        try { spread = instantOrNull(CronGrid.latestSpreadTick(cron, zone, Instant.ofEpochMilli(now), Duration.ofMillis(window), keys.get(key))); }
        catch (RuntimeException e) { spread = "\"E\""; }
        try { offset = Long.toString(CronGrid.spreadOffsetSeconds(cron, zone, keys.get(key))); }
        catch (RuntimeException e) { offset = "\"E\""; }
        tickCases.add("[" + i + "," + z + "," + now + "," + window + "," + key + "," + latest + "," + spread + "," + offset + "]");
    }
}
json.append(String.join(",\n", tickCases)).append("\n]\n}\n");

String out = System.getProperty("out", "crates/core/src/cron_fixtures.json");
java.nio.file.Files.writeString(java.nio.file.Path.of(out), json.toString());
System.out.println("crons " + crons.size() + ", accepted " + grid.stream().filter(Objects::nonNull).count()
    + ", zones " + zoneIds.size() + ", next " + nextCases.size() + ", tick " + tickCases.size() + " -> " + out);
/exit
