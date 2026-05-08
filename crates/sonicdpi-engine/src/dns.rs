//! Passive DNS response sniffer + (IP -> SNI suffix) cache.
//!
//! Why: post-handshake TCP segments and QUIC datagrams to
//! `*.googlevideo.com` carry no SNI we can read; identifying them
//! requires knowing which IPs belong to which target domain. We learn
//! that by watching DNS responses fly past on UDP/53.
//!
//! The cache only stores entries for hostnames that match a target
//! pattern, so memory stays bounded even on a busy machine.

use crate::flow::L4Proto;
use crate::packet::Packet;
use crate::target::{Target, TargetSet};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy)]
struct Entry {
    target: Target,
    expires: Instant,
}

#[derive(Default)]
pub struct DnsCache {
    inner: RwLock<HashMap<IpAddr, Entry>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<Target> {
        let now = Instant::now();
        let g = self.inner.read();
        g.get(ip).filter(|e| e.expires > now).map(|e| e.target)
    }

    pub fn insert(&self, ip: IpAddr, target: Target) {
        let mut g = self.inner.write();
        if g.len() > 65_536 {
            // Evict expired before flooding.
            let now = Instant::now();
            g.retain(|_, e| e.expires > now);
            // If still too big, clear half. Bounded-memory beats LRU bookkeeping.
            if g.len() > 65_536 {
                let drop_at = g.len() / 2;
                let to_remove: Vec<_> = g.keys().take(drop_at).copied().collect();
                for k in to_remove {
                    g.remove(&k);
                }
            }
        }
        g.insert(
            ip,
            Entry {
                target,
                expires: Instant::now() + CACHE_TTL,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// Try to extract `(qname, [A/AAAA records])` from a DNS response and,
/// if `qname` matches one of the target SNI suffixes, populate the
/// cache.
pub fn observe_dns(pkt: &Packet, targets: &TargetSet, cache: &DnsCache) {
    if pkt.proto != L4Proto::Udp || pkt.src_port != 53 {
        return;
    }
    let payload = pkt.payload();
    let Some((qname, ips)) = parse_dns_response(payload) else {
        return;
    };
    let qname = qname.to_ascii_lowercase();
    let mut matched = None;
    for (needle, t) in &targets.sni_patterns {
        if qname == *needle || qname.ends_with(&format!(".{needle}")) {
            matched = Some(*t);
            break;
        }
    }
    if let Some(target) = matched {
        for ip in ips {
            cache.insert(ip, target);
        }
    }
}

/// Minimal DNS parser: returns the question's qname and any A/AAAA
/// records present in the answer section. Best-effort; malformed
/// inputs return None.
fn parse_dns_response(buf: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        // Not a response.
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    if qd == 0 {
        return None;
    }

    let mut p = 12usize;
    let qname = read_name(buf, &mut p)?;
    if p + 4 > buf.len() {
        return None;
    }
    p += 4; // QTYPE + QCLASS

    let mut ips = Vec::with_capacity(an as usize);
    for _ in 0..an {
        // skip name
        let _ = read_name(buf, &mut p)?;
        if p + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        // skip class(2) + ttl(4)
        p += 8;
        let rdlen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if p + rdlen > buf.len() {
            return None;
        }
        match rtype {
            1 if rdlen == 4 => {
                let octets = [buf[p], buf[p + 1], buf[p + 2], buf[p + 3]];
                ips.push(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
            }
            28 if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[p..p + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(o)));
            }
            _ => {}
        }
        p += rdlen;
    }
    Some((qname, ips))
}

/// Read a DNS name with compression-pointer support. Caps at 255 chars
/// per the RFC; bails on loops.
fn read_name(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let mut out = String::new();
    let mut p = *cursor;
    let mut hops = 0usize;
    let mut jumped = false;
    let mut original_cursor = *cursor;

    loop {
        if p >= buf.len() {
            return None;
        }
        let len = buf[p];
        if len == 0 {
            p += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if p + 1 >= buf.len() {
                return None;
            }
            let off = (((len & 0x3F) as usize) << 8) | (buf[p + 1] as usize);
            if !jumped {
                original_cursor = p + 2;
                jumped = true;
            }
            p = off;
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        let label_end = p + 1 + len as usize;
        if label_end > buf.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(&buf[p + 1..label_end]).ok()?);
        if out.len() > 255 {
            return None;
        }
        p = label_end;
    }

    *cursor = if jumped { original_cursor } else { p };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_response_a(qname: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[
            0x12, 0x34, // id
            0x81, 0x80, // flags: response, recursion
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, 0x00, 0x00,
        ]);
        // qname
        for label in qname.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype=A, qclass=IN
                                                          // answer: pointer to qname (offset 12)
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
        out.extend_from_slice(&[0x00, 0x04]); // rdlength
        out.extend_from_slice(&ip);
        out
    }

    #[test]
    fn parses_a_record() {
        let b = build_dns_response_a("rr1.googlevideo.com", [142, 251, 1, 2]);
        let (n, ips) = parse_dns_response(&b).unwrap();
        assert_eq!(n, "rr1.googlevideo.com");
        assert_eq!(
            ips,
            vec![IpAddr::V4(std::net::Ipv4Addr::new(142, 251, 1, 2))]
        );
    }

    #[test]
    fn ignores_query() {
        let mut b = build_dns_response_a("x.com", [1, 2, 3, 4]);
        b[2] = 0x01; // clear QR bit
        b[3] = 0x00;
        assert!(parse_dns_response(&b).is_none());
    }

    #[test]
    fn cache_roundtrip() {
        let c = DnsCache::new();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        c.insert(ip, Target::YouTube);
        assert_eq!(c.lookup(&ip), Some(Target::YouTube));
    }
}
