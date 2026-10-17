//! The two binaries as processes: the container health check, and a start that cannot reach
//! its database (it must fail and say so, not hang). No local stack needed.

use std::process::{Command, Stdio};

/// A port that accepts connections and closes them at once: a MySQL that refuses every
/// session immediately.
fn closing_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            drop(s);
        }
    });
    port
}

fn run(bin: &str, args: &[&str], db_port: u16) -> (bool, String) {
    let mut cmd = Command::new(bin);
    cmd.args(args).env_clear().env("PATH", std::env::var("PATH").unwrap_or_default());
    // Under cargo-llvm-cov the children write their profiles where the tests' own go.
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    let out = cmd
        .env("CONFIG_FILE", "/nonexistent/files.toml")
        .env("MODLIX__DATABASE__HOST", "127.0.0.1")
        .env("MODLIX__DATABASE__PORT", db_port.to_string())
        .env("MODLIX__TELEMETRY__LOG_LEVEL", "error")
        .env("MODLIX__SERVER__PORT", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn both_binaries_fail_fast_without_a_database() {
    let port = closing_port();
    for bin in [env!("CARGO_BIN_EXE_files-serve"), env!("CARGO_BIN_EXE_files-manage")] {
        let (ok, output) = run(bin, &[], port);
        assert!(!ok, "{bin} started without a database");
        assert!(output.contains(&format!("connecting to mysql 127.0.0.1:{port}/files")), "{output}");
        // `healthcheck` probes the port and exits; nothing listens on port 1.
        let (ok, _) = run(bin, &["healthcheck", "1"], port);
        assert!(!ok);
    }
}
