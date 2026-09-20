use anyhow::{bail, Result};

use crate::wire::{mpint_bit_length, read_string};

/// The SSH public key algorithms this tool recognizes. `Unknown` carries
/// the raw type string so it can still be reported, just without a
/// strength verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    Dsa,
    Ed25519,
    Ecdsa256,
    Ecdsa384,
    Ecdsa521,
    Unknown(String),
}

impl KeyKind {
    pub fn from_type_str(s: &str) -> Self {
        match s {
            "ssh-rsa" => KeyKind::Rsa,
            "ssh-dss" => KeyKind::Dsa,
            "ssh-ed25519" => KeyKind::Ed25519,
            "ecdsa-sha2-nistp256" => KeyKind::Ecdsa256,
            "ecdsa-sha2-nistp384" => KeyKind::Ecdsa384,
            "ecdsa-sha2-nistp521" => KeyKind::Ecdsa521,
            other => KeyKind::Unknown(other.to_string()),
        }
    }

    pub fn label(&self) -> &str {
        match self {
            KeyKind::Rsa => "RSA",
            KeyKind::Dsa => "DSA",
            KeyKind::Ed25519 => "Ed25519",
            KeyKind::Ecdsa256 => "ECDSA (nistp256)",
            KeyKind::Ecdsa384 => "ECDSA (nistp384)",
            KeyKind::Ecdsa521 => "ECDSA (nistp521)",
            KeyKind::Unknown(t) => t.as_str(),
        }
    }
}

/// The result of decoding a base64 key blob: its algorithm and, where
/// meaningful, its key size in bits. `None` for key kinds this tool
/// doesn't compute a size for (currently only `Unknown` types, since the
/// wire layout of an unrecognized algorithm can't be assumed).
#[derive(Debug)]
pub struct KeyDetails {
    pub kind: KeyKind,
    pub bits: Option<u32>,
}

/// Decodes a base64-decoded SSH public key blob. `type_str` is the
/// algorithm token that preceded the blob in the `authorized_keys`/`.pub`
/// line (e.g. `"ssh-rsa"`); it's cross-checked against the type embedded
/// as the blob's own first field, since a mismatch there means the line
/// is malformed or has been hand-edited incorrectly.
pub fn analyze_blob(type_str: &str, blob: &[u8]) -> Result<KeyDetails> {
    let mut pos = 0usize;
    let embedded_type = read_string(blob, &mut pos)?;
    let embedded_type_str = std::str::from_utf8(embedded_type)
        .map_err(|_| anyhow::anyhow!("key blob's embedded type is not valid UTF-8"))?;
    if embedded_type_str != type_str {
        bail!(
            "key type mismatch: line says '{type_str}' but the key blob says '{embedded_type_str}'"
        );
    }

    let kind = KeyKind::from_type_str(type_str);
    let bits = match &kind {
        KeyKind::Rsa => {
            let _exponent = read_string(blob, &mut pos)?;
            let modulus = read_string(blob, &mut pos)?;
            Some(mpint_bit_length(modulus))
        }
        KeyKind::Dsa => {
            let p = read_string(blob, &mut pos)?;
            Some(mpint_bit_length(p))
        }
        KeyKind::Ed25519 => Some(256),
        KeyKind::Ecdsa256 => Some(256),
        KeyKind::Ecdsa384 => Some(384),
        KeyKind::Ecdsa521 => Some(521),
        KeyKind::Unknown(_) => None,
    };

    Ok(KeyDetails { kind, bits })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn encode_string_field(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn from_type_str_recognizes_all_known_types() {
        assert_eq!(KeyKind::from_type_str("ssh-rsa"), KeyKind::Rsa);
        assert_eq!(KeyKind::from_type_str("ssh-dss"), KeyKind::Dsa);
        assert_eq!(KeyKind::from_type_str("ssh-ed25519"), KeyKind::Ed25519);
        assert_eq!(
            KeyKind::from_type_str("ecdsa-sha2-nistp256"),
            KeyKind::Ecdsa256
        );
        assert_eq!(
            KeyKind::from_type_str("ecdsa-sha2-nistp384"),
            KeyKind::Ecdsa384
        );
        assert_eq!(
            KeyKind::from_type_str("ecdsa-sha2-nistp521"),
            KeyKind::Ecdsa521
        );
        assert_eq!(
            KeyKind::from_type_str("ssh-weird-future-thing"),
            KeyKind::Unknown("ssh-weird-future-thing".to_string())
        );
    }

    #[test]
    fn analyze_blob_rsa_bits() {
        let mut blob = encode_string_field(b"ssh-rsa");
        blob.extend(encode_string_field(&[0x01, 0x00, 0x01])); // e = 65537
        let mut modulus = vec![0x00, 0x80];
        modulus.extend(std::iter::repeat_n(0u8, 254));
        modulus.push(0x01);
        blob.extend(encode_string_field(&modulus));

        let details = analyze_blob("ssh-rsa", &blob).unwrap();
        assert_eq!(details.kind, KeyKind::Rsa);
        assert_eq!(details.bits, Some(2048));
    }

    #[test]
    fn analyze_blob_ed25519_is_fixed_256_bits() {
        let mut blob = encode_string_field(b"ssh-ed25519");
        blob.extend(encode_string_field(&[0u8; 32]));
        let details = analyze_blob("ssh-ed25519", &blob).unwrap();
        assert_eq!(details.kind, KeyKind::Ed25519);
        assert_eq!(details.bits, Some(256));
    }

    #[test]
    fn analyze_blob_type_mismatch_errors() {
        let blob = encode_string_field(b"ssh-ed25519");
        let err = analyze_blob("ssh-rsa", &blob).unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn analyze_blob_unknown_type_has_no_bits() {
        let blob = encode_string_field(b"ssh-something-new");
        let details = analyze_blob("ssh-something-new", &blob).unwrap();
        assert_eq!(details.bits, None);
        assert!(matches!(details.kind, KeyKind::Unknown(_)));
    }

    #[test]
    fn real_base64_roundtrip_sanity() {
        // Sanity-check the base64 engine we depend on decodes cleanly
        // for a blob shaped like a real key's.
        let mut blob = encode_string_field(b"ssh-ed25519");
        blob.extend(encode_string_field(&[7u8; 32]));
        let encoded = STANDARD.encode(&blob);
        let decoded = STANDARD.decode(&encoded).unwrap();
        assert_eq!(decoded, blob);
    }
}
