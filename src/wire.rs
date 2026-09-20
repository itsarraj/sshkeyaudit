//! Minimal reader for the SSH public-key wire format (RFC 4253 §6.6 /
//! RFC 4251 §5): a sequence of `string` and `mpint` fields, each a
//! big-endian `uint32` length prefix followed by that many bytes. This is
//! the format base64-encoded inside every line of an `authorized_keys`
//! file or `.pub` file, after the leading `ssh-rsa`/`ssh-ed25519`/etc.
//! token.
//!
//! No external SSH/crypto crate is used here on purpose — extracting a
//! key's bit length only requires reading length-prefixed fields, not
//! parsing or validating the key material itself.

use anyhow::{bail, Result};

/// Reads a big-endian `uint32` at `pos`, advancing `pos` past it.
pub fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        bail!("truncated: expected a 4-byte length prefix at offset {pos}");
    }
    let bytes = [data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]];
    *pos += 4;
    Ok(u32::from_be_bytes(bytes))
}

/// Reads a length-prefixed `string` (used for both `string` and `mpint`
/// fields — they share the same wire representation) at `pos`, advancing
/// `pos` past it.
pub fn read_string<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        bail!(
            "truncated: field claims {len} bytes but only {} remain",
            data.len() - *pos
        );
    }
    let s = &data[*pos..*pos + len];
    *pos += len;
    Ok(s)
}

/// Computes the bit length of a positive integer encoded as an SSH
/// `mpint`: big-endian, with a leading `0x00` byte if the natural
/// encoding's high bit would otherwise be set (to keep it unambiguously
/// positive per RFC 4251 §5). Bit length must ignore that sign byte and
/// any other leading zero bytes, then count only the significant bits of
/// the first nonzero byte.
pub fn mpint_bit_length(bytes: &[u8]) -> u32 {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    if i == bytes.len() {
        return 0;
    }
    let first = bytes[i];
    let remaining = (bytes.len() - i) as u32;
    let bits_in_first = 8 - first.leading_zeros();
    (remaining - 1) * 8 + bits_in_first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u32_basic() {
        let data = [0x00, 0x00, 0x00, 0x05, 0xaa];
        let mut pos = 0;
        assert_eq!(read_u32(&data, &mut pos).unwrap(), 5);
        assert_eq!(pos, 4);
    }

    #[test]
    fn read_u32_truncated_errors() {
        let data = [0x00, 0x00];
        let mut pos = 0;
        assert!(read_u32(&data, &mut pos).is_err());
    }

    #[test]
    fn read_string_basic() {
        // length-prefixed "abc"
        let data = [0x00, 0x00, 0x00, 0x03, b'a', b'b', b'c', 0xff];
        let mut pos = 0;
        let s = read_string(&data, &mut pos).unwrap();
        assert_eq!(s, b"abc");
        assert_eq!(pos, 7);
    }

    #[test]
    fn read_string_claims_more_than_available_errors() {
        let data = [0x00, 0x00, 0x00, 0x10, b'a'];
        let mut pos = 0;
        assert!(read_string(&data, &mut pos).is_err());
    }

    #[test]
    fn mpint_bit_length_zero() {
        assert_eq!(mpint_bit_length(&[]), 0);
        assert_eq!(mpint_bit_length(&[0x00]), 0);
        assert_eq!(mpint_bit_length(&[0x00, 0x00]), 0);
    }

    #[test]
    fn mpint_bit_length_no_leading_zero() {
        // 0x01 = 1, needs 1 bit
        assert_eq!(mpint_bit_length(&[0x01]), 1);
        // 0xff = 255, needs 8 bits
        assert_eq!(mpint_bit_length(&[0xff]), 8);
    }

    #[test]
    fn mpint_bit_length_with_sign_padding() {
        // A real mpint prepends 0x00 when the high bit of the first
        // "real" byte is set, purely to keep the value unambiguously
        // positive. That padding byte must not count towards bit length.
        assert_eq!(mpint_bit_length(&[0x00, 0xff]), 8);
        assert_eq!(mpint_bit_length(&[0x00, 0x80]), 8);
    }

    #[test]
    fn mpint_bit_length_2048_bit_modulus_shape() {
        // A typical 2048-bit RSA modulus: 256 bytes, high bit of the
        // first byte set (so encoded with a leading 0x00 sign byte,
        // 257 bytes total on the wire).
        let mut bytes = vec![0x00u8];
        bytes.push(0x80); // high bit set -> exactly 2048 bits from here
        bytes.extend(std::iter::repeat_n(0x00, 254));
        bytes.push(0x01);
        assert_eq!(bytes.len(), 257);
        assert_eq!(mpint_bit_length(&bytes), 2048);
    }

    #[test]
    fn mpint_bit_length_1024_bit_modulus_shape() {
        let mut bytes = vec![0x80u8]; // no sign-padding byte needed... but real encoders
                                      // still add one since 0x80's high bit is set.
        bytes.extend(std::iter::repeat_n(0x00, 126));
        bytes.push(0x01);
        assert_eq!(bytes.len(), 128);
        assert_eq!(mpint_bit_length(&bytes), 1024);
    }

    #[test]
    fn mpint_bit_length_ignores_multiple_leading_zero_bytes() {
        // Pathological but should still resolve to the true bit length
        // of the first nonzero byte onward.
        assert_eq!(mpint_bit_length(&[0x00, 0x00, 0x00, 0x0f]), 4);
    }
}
