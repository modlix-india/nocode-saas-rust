//! Renders `{src, data}` JSON lines with the FreeMarker port and prints `{"ok": text}` or
//! `{"err": ...}`, for diffing against FreeMarker itself.

use std::io::BufRead;

use connections::template::process;
use serde_json::{json, Value};

fn main() {
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line).unwrap();
        let out = match process("t", v["src"].as_str(), v["data"].as_object().unwrap()) {
            Ok(s) => json!({"ok": s}),
            Err(e) => json!({"err": e.message()}),
        };
        println!("{out}");
    }
}
