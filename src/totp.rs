//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s) with replay protection.
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

pub fn gen_secret() -> Vec<u8> {
    let mut b = vec![0u8; 20];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHA[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHA[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| *c != b'=' && *c != b' ') {
        let v = ALPHA.iter().position(|a| *a == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0xf) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 1_000_000
}

/// Accepts the current step +-1. Returns the matched step; callers must store
/// it and pass it as `last_step` so a code cannot be used twice.
pub fn verify(secret: &[u8], code: &str, now_secs: i64, last_step: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: u32 = code.parse().ok()?;
    let cur = (now_secs / 30) as u64;
    for step in [cur.saturating_sub(1), cur, cur + 1] {
        if step > last_step && code_at(secret, step) == n {
            return Some(step);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 appendix B: T=59 -> 94287082 (8 digits) -> 287082 (6 digits)
        assert_eq!(code_at(b"12345678901234567890", 59 / 30), 287082);
    }

    #[test]
    fn base32_roundtrip_and_replay() {
        let s = gen_secret();
        assert_eq!(b32_decode(&b32_encode(&s)).unwrap(), s);
        let code = format!("{:06}", code_at(&s, 1000));
        let step = verify(&s, &code, 1000 * 30, 0).unwrap();
        assert_eq!(step, 1000);
        assert!(verify(&s, &code, 1000 * 30, step).is_none());
    }
}
