//! Allocation-light DNS wire helpers. The hot path never builds a full
//! message tree: it reads the question, walks resource records in place and
//! patches TTLs directly in the byte buffer.
use std::net::IpAddr;

pub const A: u16 = 1;
pub const CNAME: u16 = 5;
pub const TXT: u16 = 16;
pub const AAAA: u16 = 28;
const OPT: u16 = 41;

pub struct Q {
    pub name: String,
    pub qtype: u16,
    pub q_end: usize,
    pub edns: bool,
    pub do_bit: bool,
}

pub struct Ans<'a> {
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

pub fn skip_name(buf: &[u8], i: &mut usize) -> Option<()> {
    loop {
        let l = *buf.get(*i)? as usize;
        if l == 0 {
            *i += 1;
            return Some(());
        }
        if l & 0xC0 == 0xC0 {
            *i += 2;
            return if *i <= buf.len() { Some(()) } else { None };
        }
        if l & 0xC0 != 0 {
            return None;
        }
        *i += 1 + l;
        if *i > buf.len() {
            return None;
        }
    }
}

/// Calls f(rtype, ttl_offset, rdata_offset, rdata_len) for every RR after the question.
fn walk<F: FnMut(u16, usize, usize, usize)>(buf: &[u8], mut f: F) -> Option<()> {
    if buf.len() < 12 {
        return None;
    }
    let be = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    let qd = be(4);
    let rrs = be(6) + be(8) + be(10);
    let mut i = 12;
    for _ in 0..qd {
        skip_name(buf, &mut i)?;
        i += 4;
        if i > buf.len() {
            return None;
        }
    }
    for _ in 0..rrs {
        skip_name(buf, &mut i)?;
        if i + 10 > buf.len() {
            return None;
        }
        let t = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        f(t, i + 4, i + 10, rdlen);
        i += 10 + rdlen;
        if i > buf.len() {
            return None;
        }
    }
    Some(())
}

fn parse_question(pkt: &[u8]) -> Option<(String, u16, usize)> {
    let mut i = 12;
    let mut name = String::with_capacity(32);
    loop {
        let l = *pkt.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l > 63 {
            return None; // also rejects compression pointers in the question
        }
        let lab = pkt.get(i..i + l)?;
        i += l;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in lab {
            name.push(b.to_ascii_lowercase() as char);
        }
        if name.len() > 253 {
            return None;
        }
    }
    let t = pkt.get(i..i + 4)?;
    Some((name, u16::from_be_bytes([t[0], t[1]]), i + 4))
}

/// Err(None) = drop silently, Err(Some(rcode)) = answer with a bare error.
pub fn parse_query(pkt: &[u8]) -> Result<Q, Option<u8>> {
    if pkt.len() < 12 {
        return Err(None);
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    if flags & 0x8000 != 0 {
        return Err(None);
    }
    if (flags >> 11) & 0xF != 0 {
        return Err(Some(4));
    }
    if u16::from_be_bytes([pkt[4], pkt[5]]) != 1 {
        return Err(Some(1));
    }
    let (name, qtype, q_end) = parse_question(pkt).ok_or(Some(1))?;
    let mut q = Q { name, qtype, q_end, edns: false, do_bit: false };
    let _ = walk(pkt, |t, ttl_off, _, _| {
        if t == OPT {
            q.edns = true;
            q.do_bit = pkt[ttl_off + 2] & 0x80 != 0;
        }
    });
    Ok(q)
}

pub fn reply(pkt: &[u8], q: &Q, rcode: u8, ans: &[Ans]) -> Vec<u8> {
    let cap = q.q_end + 11 + ans.iter().map(|a| 12 + a.rdata.len()).sum::<usize>();
    let mut o = Vec::with_capacity(cap);
    o.extend_from_slice(&pkt[..q.q_end]);
    o[2] = 0x80 | (pkt[2] & 0x01);
    o[3] = 0x80 | (rcode & 0x0F);
    o[6..8].copy_from_slice(&(ans.len() as u16).to_be_bytes());
    o[8..12].copy_from_slice(&[0, 0, 0, q.edns as u8]);
    for a in ans {
        o.extend_from_slice(&[0xC0, 0x0C]);
        o.extend_from_slice(&a.rtype.to_be_bytes());
        o.extend_from_slice(&[0, 1]);
        o.extend_from_slice(&a.ttl.to_be_bytes());
        o.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
        o.extend_from_slice(a.rdata);
    }
    if q.edns {
        o.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, if q.do_bit { 0x80 } else { 0 }, 0, 0, 0]);
    }
    o
}

pub fn error_reply(pkt: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if pkt.len() < 12 {
        return None;
    }
    let mut o = vec![0u8; 12];
    o[0] = pkt[0];
    o[1] = pkt[1];
    o[2] = 0x80 | (pkt[2] & 0x01);
    o[3] = 0x80 | (rcode & 0x0F);
    Some(o)
}

pub fn rcode(buf: &[u8]) -> u8 {
    buf.get(3).map(|b| b & 0x0F).unwrap_or(2)
}
pub fn truncated(buf: &[u8]) -> bool {
    buf.get(2).map(|b| b & 0x02 != 0).unwrap_or(false)
}
pub fn ancount(buf: &[u8]) -> u16 {
    if buf.len() >= 8 { u16::from_be_bytes([buf[6], buf[7]]) } else { 0 }
}

pub fn min_ttl(buf: &[u8]) -> Option<u32> {
    let mut m: Option<u32> = None;
    walk(buf, |t, off, _, _| {
        if t != OPT {
            let ttl = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            m = Some(m.map_or(ttl, |x| x.min(ttl)));
        }
    })?;
    m
}

/// Subtract `age` seconds from every RR TTL (floor 1).
pub fn adjust_ttls(buf: &mut [u8], age: u32) {
    if age == 0 {
        return;
    }
    let mut offs: Vec<usize> = Vec::with_capacity(8);
    if walk(buf, |t, off, _, _| {
        if t != OPT {
            offs.push(off)
        }
    })
    .is_none()
    {
        return;
    }
    for o in offs {
        let ttl = u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        buf[o..o + 4].copy_from_slice(&ttl.saturating_sub(age).max(1).to_be_bytes());
    }
}

/// A/AAAA addresses found in a reply.
pub fn answer_ips(buf: &[u8]) -> Vec<IpAddr> {
    let mut v = Vec::new();
    let _ = walk(buf, |t, _, off, len| {
        if t == A && len == 4 {
            v.push(IpAddr::from([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]));
        } else if t == AAAA && len == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[off..off + 16]);
            v.push(IpAddr::from(a));
        }
    });
    v
}

/// Keep only header + question, set TC.
pub fn truncate_for_udp(buf: &mut Vec<u8>, limit: usize) {
    if buf.len() <= limit || buf.len() < 12 {
        return;
    }
    let mut i = 12;
    if skip_name(buf, &mut i).is_none() {
        return;
    }
    i += 4;
    if i > buf.len() {
        return;
    }
    buf.truncate(i);
    buf[2] |= 0x02;
    buf[6..12].copy_from_slice(&[0; 6]);
}

pub fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut o = Vec::with_capacity(name.len() + 2);
    for l in name.trim_end_matches('.').split('.') {
        if l.is_empty() || l.len() > 63 {
            return None;
        }
        o.push(l.len() as u8);
        o.extend_from_slice(l.as_bytes());
    }
    o.push(0);
    if o.len() > 255 { None } else { Some(o) }
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut o = Vec::with_capacity(name.len() + 18);
    o.extend_from_slice(&id.to_be_bytes());
    o.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    o.extend_from_slice(&encode_name(name)?);
    o.extend_from_slice(&qtype.to_be_bytes());
    o.extend_from_slice(&[0, 1]);
    Some(o)
}

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

pub fn parse_qtype(s: &str) -> Option<u16> {
    Some(match s.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "HTTPS" => 65,
        "ANY" => 255,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_response(name: &str, ttl: u32) -> Vec<u8> {
        let q = build_query(0x1234, name, A).unwrap();
        let parsed = parse_query(&q).ok().unwrap();
        reply(&q, &parsed, 0, &[Ans { rtype: A, ttl, rdata: &[1, 2, 3, 4] }])
    }

    #[test]
    fn parse_and_reply_roundtrip() {
        let q = build_query(7, "WWW.Example.COM", A).unwrap();
        let p = parse_query(&q).ok().unwrap();
        assert_eq!(p.name, "www.example.com");
        assert_eq!(p.qtype, A);
        let r = reply(&q, &p, 0, &[Ans { rtype: A, ttl: 30, rdata: &[9, 9, 9, 9] }]);
        assert_eq!(&r[0..2], &q[0..2]);
        assert_eq!(rcode(&r), 0);
        assert_eq!(ancount(&r), 1);
        assert_eq!(answer_ips(&r), vec![IpAddr::from([9, 9, 9, 9])]);
    }

    #[test]
    fn ttl_walk_and_patch() {
        let mut r = fake_response("a.example", 100);
        assert_eq!(min_ttl(&r), Some(100));
        adjust_ttls(&mut r, 40);
        assert_eq!(min_ttl(&r), Some(60));
        adjust_ttls(&mut r, 1000);
        assert_eq!(min_ttl(&r), Some(1));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_query(&[0; 5]).is_err());
        let mut q = build_query(1, "a.b", A).unwrap();
        q[2] |= 0x80; // looks like a response
        assert!(matches!(parse_query(&q), Err(None)));
    }

    #[test]
    fn udp_truncation_sets_tc() {
        let mut r = fake_response("big.example", 10);
        r.extend(vec![0u8; 2000]);
        truncate_for_udp(&mut r, 1232);
        assert!(truncated(&r));
        assert_eq!(ancount(&r), 0);
    }
}
