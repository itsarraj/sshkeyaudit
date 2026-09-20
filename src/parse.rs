use anyhow::{anyhow, Result};

/// Every key-type token this tool knows how to recognize inside a raw
/// `authorized_keys`/`.pub` line. `authorized_keys` lines may be
/// prefixed with comma-separated options (`command="...",no-pty
/// ssh-rsa AAAA...`), so the parser scans tokens looking for one of
/// these rather than assuming the key type is always the first word.
const KNOWN_TYPES: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// One successfully tokenized key line, before the base64 blob has been
/// decoded or analyzed.
#[derive(Debug)]
pub struct ParsedLine {
    pub key_type: String,
    pub blob_b64: String,
    pub comment: Option<String>,
    pub has_options: bool,
}

/// Tokenizes a single line of an `authorized_keys` file or `.pub` file.
///
/// Returns `Ok(None)` for lines that carry no key at all (blank lines,
/// full-line `#` comments) — these are silently skipped, matching
/// OpenSSH's own `authorized_keys` parser. Returns `Err` for a
/// non-blank, non-comment line that doesn't contain any recognized key
/// type token, since that's a real malformed-input case worth
/// surfacing rather than skipping quietly.
///
/// Known limitation: this splits on whitespace, so an option value
/// containing a quoted space (`command="echo hi"`) will be split across
/// multiple tokens. That's fine for locating the key type token (which
/// never contains spaces) but means `has_options` detection is reliable
/// while reconstructing the *exact* option string is not attempted here
/// — this tool never renders it back out, only reports whether options
/// are present.
pub fn parse_line(line: &str) -> Result<Option<ParsedLine>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let type_idx = tokens
        .iter()
        .position(|t| KNOWN_TYPES.contains(t))
        .ok_or_else(|| anyhow!("no recognized SSH key type found on this line"))?;

    if type_idx + 1 >= tokens.len() {
        return Err(anyhow!(
            "key type '{}' has no key data after it",
            tokens[type_idx]
        ));
    }

    let key_type = tokens[type_idx].to_string();
    let blob_b64 = tokens[type_idx + 1].to_string();
    let comment = if tokens.len() > type_idx + 2 {
        Some(tokens[type_idx + 2..].join(" "))
    } else {
        None
    };

    Ok(Some(ParsedLine {
        key_type,
        blob_b64,
        comment,
        has_options: type_idx > 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_pub_file_line() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummy user@host";
        let parsed = parse_line(line).unwrap().unwrap();
        assert_eq!(parsed.key_type, "ssh-ed25519");
        assert_eq!(parsed.blob_b64, "AAAAC3NzaC1lZDI1NTE5AAAAIDummy");
        assert_eq!(parsed.comment.as_deref(), Some("user@host"));
        assert!(!parsed.has_options);
    }

    #[test]
    fn parses_line_with_multi_word_comment() {
        let line = "ssh-rsa AAAABdummy some body's laptop 2024";
        let parsed = parse_line(line).unwrap().unwrap();
        assert_eq!(parsed.comment.as_deref(), Some("some body's laptop 2024"));
    }

    #[test]
    fn parses_line_missing_comment() {
        let line = "ssh-rsa AAAABdummy";
        let parsed = parse_line(line).unwrap().unwrap();
        assert_eq!(parsed.comment, None);
    }

    #[test]
    fn parses_authorized_keys_line_with_options() {
        let line = "no-pty,no-agent-forwarding ssh-rsa AAAABdummy deploy@ci";
        let parsed = parse_line(line).unwrap().unwrap();
        assert!(parsed.has_options);
        assert_eq!(parsed.key_type, "ssh-rsa");
        assert_eq!(parsed.blob_b64, "AAAABdummy");
    }

    #[test]
    fn skips_blank_lines() {
        assert!(parse_line("").unwrap().is_none());
        assert!(parse_line("   ").unwrap().is_none());
    }

    #[test]
    fn skips_comment_lines() {
        assert!(parse_line("# this is a comment").unwrap().is_none());
        assert!(parse_line("   # indented comment").unwrap().is_none());
    }

    #[test]
    fn errors_on_unrecognized_line() {
        assert!(parse_line("this is not a key at all")
            .unwrap_err()
            .to_string()
            .contains("no recognized"));
    }

    #[test]
    fn errors_on_key_type_with_no_data() {
        assert!(parse_line("ssh-rsa").is_err());
    }
}
