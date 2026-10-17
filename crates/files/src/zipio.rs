//! Zip reading and writing for folder import and export (blocking; run on a blocking thread).

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::fs::safe_join;

/// What a zip holds: each file (entry name, where it was extracted) and every folder named by
/// an entry, sorted, without the trailing `/` (`deflateFilesFolders`).
#[derive(Debug, Default)]
pub struct Extracted {
    pub files: Vec<(String, PathBuf)>,
    pub folders: Vec<String>,
}

/// Extracts `zip` into `dest`. An entry that would land outside `dest` (`../`, an absolute
/// name) is skipped; Java writes it wherever the name points.
pub fn extract(zip: &Path, dest: &Path) -> Result<Extracted> {
    let file = File::open(zip).with_context(|| format!("opening {}", zip.display()))?;
    let mut archive = ZipArchive::new(BufReader::new(file)).context("Unable to read zip file")?;
    let mut folders = BTreeSet::new();
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if entry.is_dir() {
            let folder = name.strip_suffix('/').unwrap_or(&name).to_string();
            if safe_join(dest, &folder).is_some() {
                std::fs::create_dir_all(dest.join(&folder))?;
                folders.insert(folder);
            }
            continue;
        }
        let Some(target) = safe_join(dest, &name) else {
            tracing::warn!(entry = name, "zip entry outside the target folder skipped");
            continue;
        };
        if let Some(i) = name.rfind('/') {
            folders.insert(name[..i].to_string());
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = BufWriter::new(File::create(&target)?);
        std::io::copy(&mut entry, &mut out)?;
        out.flush()?;
        files.push((name, target));
    }
    Ok(Extracted { files, folders: folders.into_iter().collect() })
}

/// Zips every regular file under `root`, named relative to it with `/` separators, deflated.
pub fn zip_folder(root: &Path, zip: &Path) -> Result<()> {
    let mut writer = ZipWriter::new(BufWriter::new(File::create(zip)?));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            let p = e.path();
            let ft = e.file_type()?;
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let rel = p
                    .strip_prefix(root)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                writer.start_file(rel, options)?;
                std::io::copy(&mut File::open(&p)?, &mut writer)?;
            }
        }
    }
    writer.finish()?.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_relative_names_and_folders() {
        let base = std::env::temp_dir().join(format!("zipio-test-{:x}", rand::random::<u64>()));
        let src = base.join("src");
        std::fs::create_dir_all(src.join("a/b")).unwrap();
        std::fs::write(src.join("top.txt"), b"t").unwrap();
        std::fs::write(src.join("a/b/deep.txt"), b"d").unwrap();
        let zip = base.join("x.zip");
        zip_folder(&src, &zip).unwrap();

        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let ex = extract(&zip, &out).unwrap();
        let mut names: Vec<&str> = ex.files.iter().map(|(n, _)| n.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["a/b/deep.txt", "top.txt"]);
        assert_eq!(ex.folders, vec!["a/b".to_string()]);
        assert_eq!(std::fs::read(out.join("a/b/deep.txt")).unwrap(), b"d");
        std::fs::remove_dir_all(&base).unwrap();
    }


    #[test]
    fn entries_outside_the_folder_are_skipped() {
        use std::io::Write;
        let base = std::env::temp_dir().join(format!("zipio-test-{:x}", rand::random::<u64>()));
        std::fs::create_dir_all(&base).unwrap();
        let zip = base.join("evil.zip");
        let mut w = ZipWriter::new(File::create(&zip).unwrap());
        let o = SimpleFileOptions::default();
        w.add_directory("../up/", o).unwrap();
        w.add_directory("ok/", o).unwrap();
        w.start_file("../x.txt", o).unwrap();
        w.write_all(b"x").unwrap();
        w.start_file("top.txt", o).unwrap();
        w.write_all(b"t").unwrap();
        w.finish().unwrap();
        let out = base.join("out");
        let ex = extract(&zip, &out).unwrap();
        assert_eq!(ex.files.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), vec!["top.txt"]);
        assert_eq!(ex.folders, vec!["ok".to_string()]);
        assert!(!base.join("x.txt").exists() && !base.join("up").exists());

        // Not a zip, and not there.
        std::fs::write(base.join("bad.zip"), b"nope").unwrap();
        assert!(extract(&base.join("bad.zip"), &out).unwrap_err().to_string().contains("Unable to read zip file"));
        assert!(extract(&base.join("none.zip"), &out).is_err());

        // Only regular files are zipped.
        let src = base.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f.txt"), b"f").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(src.join("f.txt"), src.join("link")).unwrap();
        let z = base.join("z.zip");
        zip_folder(&src, &z).unwrap();
        let names: Vec<String> = {
            let mut a = ZipArchive::new(File::open(&z).unwrap()).unwrap();
            (0..a.len()).map(|i| a.by_index(i).unwrap().name().to_string()).collect()
        };
        assert_eq!(names, vec!["f.txt"]);
        assert!(zip_folder(&base.join("missing"), &base.join("m.zip")).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
