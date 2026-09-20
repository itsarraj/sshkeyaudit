use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::audit::{evaluate, Finding};
use crate::keytype::analyze_blob;
use crate::parse::parse_line;

/// Scans one file line-by-line as an `authorized_keys`-shaped file
/// (works equally for a `.pub` file, which is just such a file with one
/// line). Malformed lines produce a `Finding` of their own describing
/// the parse error rather than aborting the whole scan, so one bad line
/// in a large `authorized_keys` doesn't hide problems in the rest.
pub fn scan_file(path: &Path) -> Result<Vec<Finding>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut findings = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let source = format!("{}:{}", path.display(), line_no);

        let parsed = match parse_line(line) {
            Ok(Some(p)) => p,
            Ok(None) => continue,
            Err(e) => {
                findings.push(Finding {
                    source,
                    key_label: "?".to_string(),
                    bits: None,
                    comment: None,
                    severity: crate::audit::Severity::Warning,
                    reasons: vec![format!("could not parse line: {e}")],
                });
                continue;
            }
        };

        let blob = match STANDARD.decode(parsed.blob_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                findings.push(Finding {
                    source,
                    key_label: parsed.key_type.clone(),
                    bits: None,
                    comment: parsed.comment.clone(),
                    severity: crate::audit::Severity::Warning,
                    reasons: vec![format!("key data is not valid base64: {e}")],
                });
                continue;
            }
        };

        let details = match analyze_blob(&parsed.key_type, &blob) {
            Ok(d) => d,
            Err(e) => {
                findings.push(Finding {
                    source,
                    key_label: parsed.key_type.clone(),
                    bits: None,
                    comment: parsed.comment.clone(),
                    severity: crate::audit::Severity::Warning,
                    reasons: vec![format!("could not decode key: {e}")],
                });
                continue;
            }
        };

        let (severity, reasons) = evaluate(&details.kind, details.bits, parsed.comment.is_some());

        findings.push(Finding {
            source,
            key_label: details.kind.label().to_string(),
            bits: details.bits,
            comment: parsed.comment,
            severity,
            reasons,
        });
    }

    Ok(findings)
}

/// Scans every `*.pub` file directly inside `dir` (non-recursive — a
/// `.ssh` directory or a keys-drop directory is flat in practice, and
/// recursing risks pulling in unrelated `.pub` files from vendored
/// dependencies elsewhere in a tree).
pub fn scan_dir(dir: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "pub"))
        .map(|e| e.path())
        .collect();
    entries.sort();

    for path in entries {
        findings.extend(scan_file(&path)?);
    }

    Ok(findings)
}

/// Scans `path`, dispatching to directory or single-file handling.
pub fn scan_path(path: &Path) -> Result<Vec<Finding>> {
    if path.is_dir() {
        scan_dir(path)
    } else {
        scan_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_temp(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn scan_file_flags_malformed_line_without_aborting_rest() {
        let tmp = TempDir::new().unwrap();
        let path = write_temp(
            tmp.path(),
            "authorized_keys",
            "this is garbage\nssh-ed25519 not-valid-base64!!! comment\n",
        );
        let findings = scan_file(&path).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, crate::audit::Severity::Warning);
        assert_eq!(findings[1].severity, crate::audit::Severity::Warning);
    }

    #[test]
    fn scan_file_skips_blank_and_comment_lines() {
        let tmp = TempDir::new().unwrap();
        let path = write_temp(tmp.path(), "authorized_keys", "\n# a comment\n   \n");
        let findings = scan_file(&path).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_dir_only_picks_up_pub_files() {
        let tmp = TempDir::new().unwrap();
        write_temp(tmp.path(), "notes.txt", "not a key file");
        write_temp(
            tmp.path(),
            "id_ed25519.pub",
            "this is garbage-but-recognized-as-a-line\n",
        );
        let findings = scan_dir(tmp.path()).unwrap();
        // notes.txt should be ignored entirely; the .pub file's one
        // unparseable line should still surface as a finding.
        assert_eq!(findings.len(), 1);
        assert!(findings[0].source.ends_with("id_ed25519.pub:1"));
    }
}
