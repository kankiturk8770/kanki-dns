//! Minimal TLS ClientHello parser: extracts the SNI host name, nothing else.

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// None when the buffer is not (yet) a ClientHello carrying an SNI.
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    let mut c = Cur(buf);
    if c.u8()? != 0x16 {
        return None;
    }
    c.take(2)?;
    let rec_len = c.u16()? as usize;
    let avail = rec_len.min(c.0.len());
    let mut r = Cur(c.take(avail)?);
    if r.u8()? != 0x01 {
        return None;
    }
    r.take(3 + 2 + 32)?;
    let n = r.u8()? as usize;
    r.take(n)?;
    let n = r.u16()? as usize;
    r.take(n)?;
    let n = r.u8()? as usize;
    r.take(n)?;
    let el = r.u16()? as usize;
    let avail = el.min(r.0.len());
    let mut e = Cur(r.take(avail)?);
    while e.0.len() >= 4 {
        let ty = e.u16()?;
        let len = e.u16()? as usize;
        let body = e.take(len)?;
        if ty == 0 {
            let mut b = Cur(body);
            b.u16()?;
            if b.u8()? != 0 {
                return None;
            }
            let nl = b.u16()? as usize;
            let name = std::str::from_utf8(b.take(nl)?).ok()?;
            let ok = !name.is_empty()
                && name.len() <= 253
                && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'));
            return ok.then(|| name.to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut sni = vec![0u8];
        sni.extend((h.len() as u16).to_be_bytes());
        sni.extend(h);
        let mut list = (sni.len() as u16).to_be_bytes().to_vec();
        list.extend(sni);
        let mut ext = vec![0, 0];
        ext.extend((list.len() as u16).to_be_bytes());
        ext.extend(list);
        let mut body = vec![3, 3];
        body.extend([0u8; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 0x01]);
        body.extend([1, 0]);
        body.extend((ext.len() as u16).to_be_bytes());
        body.extend(ext);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn parses_sni() {
        assert_eq!(parse_sni(&hello("Discord.com")).as_deref(), Some("discord.com"));
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        assert!(parse_sni(b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse_sni(&hello("a.example")[..20]).is_none());
    }
}
