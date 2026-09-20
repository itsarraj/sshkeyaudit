use crate::keytype::KeyKind;

/// The minimum RSA modulus size this tool accepts without flagging it.
/// NIST has recommended against RSA-1024 since 2010; 2048 is the
/// floor most current guidance (and OpenSSH itself) treats as the
/// minimum acceptable size.
pub const MIN_RSA_BITS: u32 = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Warning,
    Weak,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Ok => "OK",
            Severity::Warning => "WARN",
            Severity::Weak => "WEAK",
        }
    }
}

pub struct Finding {
    pub source: String,
    pub key_label: String,
    pub bits: Option<u32>,
    pub comment: Option<String>,
    pub severity: Severity,
    pub reasons: Vec<String>,
}

/// Applies this tool's weak-key rules to one already-decoded key.
///
/// Rules, in the order the task that defined this tool specified them:
/// - DSA is flagged regardless of size — it's been deprecated/disabled
///   by default in OpenSSH since 7.0 (2015), so any DSA key found in
///   the wild is by definition old and due for rotation.
/// - RSA below `MIN_RSA_BITS` (2048) is flagged.
/// - A missing comment is flagged as a `Warning`, not a `Weak` — an
///   uncommented key isn't cryptographically weaker, it's an
///   operational hazard (nobody can tell whose key it is or safely
///   remove it later). Kept as a strictly lower severity so it never
///   masks or is confused with an actual weak-crypto finding.
/// - An unrecognized key type is a `Warning`: this tool can't assess
///   strength for an algorithm it doesn't parse, so it says so rather
///   than silently passing it as OK.
pub fn evaluate(
    kind: &KeyKind,
    bits: Option<u32>,
    comment_present: bool,
) -> (Severity, Vec<String>) {
    let mut reasons = Vec::new();
    let mut severity = Severity::Ok;

    match kind {
        KeyKind::Dsa => {
            reasons.push(
                "DSA is deprecated - OpenSSH has disabled it by default since 7.0 (2015)"
                    .to_string(),
            );
            severity = Severity::Weak;
        }
        KeyKind::Rsa => {
            if let Some(b) = bits {
                if b < MIN_RSA_BITS {
                    reasons.push(format!(
                        "RSA key is {b} bits, below the {MIN_RSA_BITS}-bit minimum"
                    ));
                    severity = Severity::Weak;
                }
            }
        }
        KeyKind::Unknown(t) => {
            reasons.push(format!(
                "unrecognized key type '{t}' - cannot assess its strength"
            ));
            severity = Severity::Warning;
        }
        KeyKind::Ed25519 | KeyKind::Ecdsa256 | KeyKind::Ecdsa384 | KeyKind::Ecdsa521 => {}
    }

    if !comment_present {
        reasons.push("no comment - can't tell whose key this is or when it was issued".to_string());
        severity = severity.max(Severity::Warning);
    }

    (severity, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsa_is_always_weak_regardless_of_bits() {
        let (sev, reasons) = evaluate(&KeyKind::Dsa, Some(3072), true);
        assert_eq!(sev, Severity::Weak);
        assert!(reasons[0].contains("deprecated"));
    }

    #[test]
    fn rsa_1024_is_weak() {
        let (sev, reasons) = evaluate(&KeyKind::Rsa, Some(1024), true);
        assert_eq!(sev, Severity::Weak);
        assert!(reasons[0].contains("1024"));
    }

    #[test]
    fn rsa_2048_is_ok() {
        let (sev, reasons) = evaluate(&KeyKind::Rsa, Some(2048), true);
        assert_eq!(sev, Severity::Ok);
        assert!(reasons.is_empty());
    }

    #[test]
    fn rsa_4096_is_ok() {
        let (sev, _) = evaluate(&KeyKind::Rsa, Some(4096), true);
        assert_eq!(sev, Severity::Ok);
    }

    #[test]
    fn rsa_2047_is_still_weak_boundary_check() {
        let (sev, _) = evaluate(&KeyKind::Rsa, Some(2047), true);
        assert_eq!(sev, Severity::Weak);
    }

    #[test]
    fn ed25519_is_always_ok_with_comment() {
        let (sev, reasons) = evaluate(&KeyKind::Ed25519, Some(256), true);
        assert_eq!(sev, Severity::Ok);
        assert!(reasons.is_empty());
    }

    #[test]
    fn missing_comment_is_warning_not_weak() {
        let (sev, reasons) = evaluate(&KeyKind::Ed25519, Some(256), false);
        assert_eq!(sev, Severity::Warning);
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("no comment"));
    }

    #[test]
    fn missing_comment_does_not_downgrade_weak_to_warning() {
        let (sev, reasons) = evaluate(&KeyKind::Dsa, Some(1024), false);
        assert_eq!(sev, Severity::Weak);
        assert_eq!(reasons.len(), 2);
    }

    #[test]
    fn unknown_type_is_warning() {
        let (sev, reasons) = evaluate(&KeyKind::Unknown("ssh-mystery".into()), None, true);
        assert_eq!(sev, Severity::Warning);
        assert!(reasons[0].contains("ssh-mystery"));
    }

    #[test]
    fn severity_ordering_for_max() {
        assert!(Severity::Weak > Severity::Warning);
        assert!(Severity::Warning > Severity::Ok);
    }

    #[test]
    fn ecdsa_variants_all_ok() {
        for kind in [KeyKind::Ecdsa256, KeyKind::Ecdsa384, KeyKind::Ecdsa521] {
            let (sev, _) = evaluate(&kind, Some(256), true);
            assert_eq!(sev, Severity::Ok);
        }
    }
}
