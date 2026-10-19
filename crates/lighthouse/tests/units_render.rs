//! `lighthouse render` against `tools/render_config.py`: the synthetic fixture rendered for each
//! environment must give the same files byte for byte (goldens captured from the script in
//! `tests/fixtures/render/<env>/`), the same modes and the same report.

use std::path::{Path, PathBuf};

use lighthouse::config::cli::{render_command, render_to};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oci-config")
}

fn goldens(env: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/render").join(env)
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lighthouse-render-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn byte_identical_to_the_script() {
    for env in ["dev", "stage", "prod"] {
        let out = scratch(env);
        let (report, failed) = render_to(&fixture(), env, &out, "{out}").unwrap();
        let want_report = std::fs::read_to_string(goldens(env).with_extension("report.txt")).unwrap();
        assert_eq!(report, want_report, "{env}: the report");
        assert_eq!(failed, env != "dev", "{env}: the exit status");
        let mut want: Vec<String> = std::fs::read_dir(goldens(env)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        let mut got: Vec<String> = std::fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        want.sort();
        got.sort();
        assert_eq!(got, want, "{env}: the files written");
        for name in &want {
            let a = std::fs::read(goldens(env).join(name)).unwrap();
            let b = std::fs::read(out.join(name)).unwrap();
            assert!(a == b, "{env}/{name} differs from the script's");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(out.join(name)).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, if name.ends_with(".toml") { 0o644 } else { 0o600 }, "{env}/{name} mode");
            }
        }
        std::fs::remove_dir_all(&out).unwrap();
    }
}

#[test]
fn the_command_line() {
    let out = scratch("cli");
    let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = render_command(&args(&[fixture().to_str().unwrap(), "dev", out.to_str().unwrap()]), &mut o, &mut e);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&e));
    assert!(String::from_utf8(o).unwrap().starts_with("Rendered 15 unit configs, rust-units.env and ai.env, ssr.env, ssr-in.env for dev"));
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = render_command(&args(&[fixture().to_str().unwrap(), "prod", out.to_str().unwrap()]), &mut o, &mut e);
    assert_eq!(code, 1);
    let (mut o, mut e) = (Vec::new(), Vec::new());
    assert_eq!(render_command(&args(&[fixture().to_str().unwrap(), "qa", "x"]), &mut o, &mut e), 2);
    std::fs::remove_dir_all(&out).unwrap();

    // A directory without the manifest renders nothing.
    let bare = scratch("bare");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::write(bare.join("application.yml"), "a: 1\n").unwrap();
    std::fs::write(bare.join("application-ocidev.yml"), "a: 1\n").unwrap();
    let (mut o, mut e) = (Vec::new(), Vec::new());
    let code = render_command(&args(&[bare.to_str().unwrap(), "dev", bare.join("out").to_str().unwrap()]), &mut o, &mut e);
    assert_eq!(code, 1);
    assert!(String::from_utf8(e).unwrap().contains("rust/units.toml"));
    std::fs::remove_dir_all(&bare).unwrap();
}
