//! `UserAgentInfo`: the device, OS and browser recorded with every token row.

use std::sync::OnceLock;

use regex::Regex;

pub const MAX_UA_LENGTH: usize = 512;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserAgentInfo {
    pub raw: Option<String>,
    pub device_type: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

struct Patterns {
    edge: Regex,
    opera: Regex,
    samsung: Regex,
    firefox: Regex,
    chrome: Regex,
    safari: Regex,
    ie: Regex,
    win: Regex,
    mac: Regex,
    ios: Regex,
    android: Regex,
    bot: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let r = |s: &str| Regex::new(s).expect("static regex");
        Patterns {
            edge: r(r"Edg(?:e|A|iOS)?/(\d+)"),
            opera: r(r"(?:OPR|Opera)/(\d+)"),
            samsung: r(r"SamsungBrowser/(\d+)"),
            firefox: r(r"Firefox/(\d+)"),
            chrome: r(r"(?:Chrome|CriOS)/(\d+)"),
            safari: r(r"Version/(\d+).*Safari/"),
            ie: r(r"(?:MSIE |Trident/.*rv:)(\d+)"),
            win: r(r"Windows NT (\d+\.\d+)"),
            mac: r(r"Mac OS X (\d+(?:[._]\d+)?)"),
            ios: r(r"OS (\d+(?:_\d+)?) like Mac"),
            android: r(r"Android (\d+(?:\.\d+)?)"),
            bot: r(r"(?i)bot|crawler|spider|slurp|bingpreview|facebookexternalhit|curl/|wget/|python-requests|okhttp/|java/|httpclient"),
        }
    })
}

fn group(re: &Regex, s: &str) -> Option<String> {
    re.captures(s).and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

impl UserAgentInfo {
    /// `UserAgentInfo.parse(header)`.
    pub fn parse(ua: Option<&str>) -> Self {
        let Some(ua) = ua.filter(|u| !u.trim().is_empty()) else {
            return Self::default();
        };
        // Java cuts at 512 UTF-16 units; for the ASCII user agents send that is 512 chars.
        let trimmed: String = ua.chars().take(MAX_UA_LENGTH).collect();
        let device = if patterns().bot.is_match(&trimmed) { "BOT".to_string() } else { detect_device(&trimmed) };
        Self {
            os: detect_os(&trimmed),
            browser: detect_browser(&trimmed),
            device_type: Some(device),
            raw: Some(trimmed),
        }
    }
}

fn detect_device(ua: &str) -> String {
    let d = if ua.contains("iPad") || (ua.contains("Android") && !ua.contains("Mobile")) || ua.contains("Tablet") {
        "TABLET"
    } else if ua.contains("Mobile") || ua.contains("iPhone") || ua.contains("iPod") || ua.contains("Android") {
        "MOBILE"
    } else {
        "DESKTOP"
    };
    d.to_string()
}

fn windows_name(nt: &str) -> &str {
    match nt {
        "10.0" => "10/11",
        "6.3" => "8.1",
        "6.2" => "8",
        "6.1" => "7",
        other => other,
    }
}

fn detect_os(ua: &str) -> Option<String> {
    let p = patterns();
    if let Some(v) = group(&p.win, ua) {
        return Some(format!("Windows {}", windows_name(&v)));
    }
    if let Some(v) = group(&p.ios, ua) {
        return Some(format!("iOS {}", v.replace('_', ".")));
    }
    if let Some(v) = group(&p.mac, ua) {
        return Some(format!("macOS {}", v.replace('_', ".")));
    }
    if let Some(v) = group(&p.android, ua) {
        return Some(format!("Android {v}"));
    }
    if ua.contains("CrOS") {
        return Some("ChromeOS".into());
    }
    if ua.contains("Linux") {
        return Some("Linux".into());
    }
    None
}

fn detect_browser(ua: &str) -> Option<String> {
    let p = patterns();
    // Chromium browsers all carry "Safari", so the order matters.
    for (re, name) in [
        (&p.edge, "Edge"),
        (&p.opera, "Opera"),
        (&p.samsung, "Samsung"),
        (&p.firefox, "Firefox"),
        (&p.chrome, "Chrome"),
        (&p.safari, "Safari"),
        (&p.ie, "IE"),
    ] {
        if let Some(v) = group(re, ua) {
            return Some(format!("{name} {v}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(ua: &str) -> (String, Option<String>, Option<String>) {
        let i = UserAgentInfo::parse(Some(ua));
        (i.device_type.unwrap(), i.os, i.browser)
    }

    #[test]
    fn desktop_browsers() {
        let chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        assert_eq!(p(chrome), ("DESKTOP".into(), Some("macOS 10.15".into()), Some("Chrome 131".into())));
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0";
        assert_eq!(p(edge), ("DESKTOP".into(), Some("Windows 10/11".into()), Some("Edge 120".into())));
        let ff = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
        assert_eq!(p(ff), ("DESKTOP".into(), Some("Linux".into()), Some("Firefox 128".into())));
        let opera = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 Chrome/99 Safari/537.36 OPR/85.0";
        assert_eq!(p(opera).2.as_deref(), Some("Opera 85"));
        assert_eq!(p(opera).1.as_deref(), Some("Windows 7"));
        let ie = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
        assert_eq!(p(ie).2.as_deref(), Some("IE 11"));
        assert_eq!(p(ie).1.as_deref(), Some("Windows 8.1"));
        assert_eq!(p("Mozilla/5.0 (Windows NT 6.2)").1.as_deref(), Some("Windows 8"));
        assert_eq!(p("Mozilla/5.0 (Windows NT 5.1)").1.as_deref(), Some("Windows 5.1"));
        let cros = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/120 Safari/537.36";
        assert_eq!(p(cros).1.as_deref(), Some("ChromeOS"));
    }

    #[test]
    fn phones_tablets_and_bots() {
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1";
        assert_eq!(p(iphone), ("MOBILE".into(), Some("iOS 17.4".into()), Some("Safari 17".into())));
        let ipad = "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) Version/16.0 Mobile Safari/604.1";
        assert_eq!(p(ipad).0, "TABLET");
        let android_tab = "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 Chrome/120 Safari/537.36";
        assert_eq!(p(android_tab), ("TABLET".into(), Some("Android 13".into()), Some("Chrome 120".into())));
        let samsung = "Mozilla/5.0 (Linux; Android 14; SM-S918B) SamsungBrowser/24.0 Chrome/117 Mobile Safari/537.36";
        assert_eq!(p(samsung), ("MOBILE".into(), Some("Android 14".into()), Some("Samsung 24".into())));
        assert_eq!(p("curl/8.7.1"), ("BOT".into(), None, None));
        assert_eq!(p("python-httpx/0.28.1").0, "DESKTOP");
        assert_eq!(p("Googlebot/2.1").0, "BOT");
        assert_eq!(p("Some Tablet thing").0, "TABLET");
    }

    #[test]
    fn empty_and_long() {
        assert_eq!(UserAgentInfo::parse(None), UserAgentInfo::default());
        assert_eq!(UserAgentInfo::parse(Some("  ")), UserAgentInfo::default());
        let long = "x".repeat(600);
        assert_eq!(UserAgentInfo::parse(Some(&long)).raw.unwrap().len(), MAX_UA_LENGTH);
    }
}
