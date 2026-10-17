//! Reads `MODE \t KEY \t VALUE` lines (MODE is `details` or `resolved`, VALUE may hold `\uXXXX`
//! escapes) and prints the guard's answer in the same format as the Java harness, for diffing.

use std::io::BufRead;

use connections::outbound;
use serde_json::{Map, Value};

fn unescape(s: &str) -> String {
    let units: Vec<char> = s.chars().collect();
    let mut out: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < units.len() {
        if units[i] == '\\' && i + 5 < units.len() + 0 && units[i + 1] == 'u' {
            let hex: String = units[i + 2..i + 6].iter().collect();
            out.push(u16::from_str_radix(&hex, 16).unwrap_or(0));
            i += 6;
        } else {
            let mut buf = [0u16; 2];
            out.extend_from_slice(units[i].encode_utf16(&mut buf));
            i += 1;
        }
    }
    String::from_utf16_lossy(&out)
}

#[tokio::main]
async fn main() {
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.is_empty() {
            continue;
        }
        let p: Vec<&str> = line.splitn(3, '\t').collect();
        let (mode, key, raw) = (p[0], p[1], p[2]);
        let value = unescape(raw);
        let res = if mode == "details" {
            let mut m = Map::new();
            m.insert(key.to_string(), Value::String(value));
            outbound::validate_connection_details(Some(&m)).await
        } else {
            outbound::validate_resolved(&value).await
        };
        let res = match res {
            Ok(()) => "OK".to_string(),
            Err(connections::error::ConnError::Generic { message, .. }) => format!("ERR GenericException: {message}"),
            Err(e) => format!("ERR Other: {e}"),
        };
        println!("{mode}\t{key}\t{raw}\t{}", res.replace('\n', "\\n"));
    }
}
