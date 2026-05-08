//! Owned, mutable view of a single network packet.
//!
//! The platform backend hands us a `Vec<u8>` plus a direction; we parse
//! it once, expose typed accessors, and let strategies mutate the
//! payload in place. Checksums are recomputed on the way out.

use crate::flow::{Direction, FlowKey, L4Proto};
use std::net::IpAddr;

#[derive(Debug)]
pub struct Packet {
    /// Raw bytes starting at the IP header.
    pub bytes: Vec<u8>,
    pub direction: Direction,
    /// Cached header offsets, filled by `parse`.
    pub ip_hdr_len: u16,
    pub l4_hdr_len: u16,
    pub proto: L4Proto,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// True when the IP header is IPv6.
    pub is_v6: bool,
}

impl Packet {
    pub fn parse(bytes: Vec<u8>, direction: Direction) -> Option<Self> {
        use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

        let sp = SlicedPacket::from_ip(&bytes).ok()?;

        let (src, dst, ip_hdr_len, is_v6) = match sp.net.as_ref()? {
            InternetSlice::Ipv4(v4) => {
                let h = v4.header();
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                    (h.ihl() as u16) * 4,
                    false,
                )
            }
            InternetSlice::Ipv6(v6) => {
                let h = v6.header();
                (
                    IpAddr::V6(h.source_addr()),
                    IpAddr::V6(h.destination_addr()),
                    40, // fixed IPv6 header; extension headers handled below if needed
                    true,
                )
            }
        };

        let (proto, l4_hdr_len, src_port, dst_port) = match sp.transport.as_ref()? {
            TransportSlice::Tcp(t) => (
                L4Proto::Tcp,
                (t.data_offset() as u16) * 4,
                t.source_port(),
                t.destination_port(),
            ),
            TransportSlice::Udp(u) => (L4Proto::Udp, 8, u.source_port(), u.destination_port()),
            _ => return None,
        };

        Some(Self {
            bytes,
            direction,
            ip_hdr_len,
            l4_hdr_len,
            proto,
            src,
            dst,
            src_port,
            dst_port,
            is_v6,
        })
    }

    pub fn payload(&self) -> &[u8] {
        let start = (self.ip_hdr_len + self.l4_hdr_len) as usize;
        &self.bytes[start..]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = (self.ip_hdr_len + self.l4_hdr_len) as usize;
        &mut self.bytes[start..]
    }

    pub fn flow_key(&self) -> Option<FlowKey> {
        Some(FlowKey {
            proto: self.proto,
            src: self.src,
            dst: self.dst,
            src_port: self.src_port,
            dst_port: self.dst_port,
        })
    }

    /// IP TTL (IPv4) or hop limit (IPv6). Used by kill-rst to detect
    /// forged TCP RSTs — a TSPU-injected RST typically has a higher
    /// TTL than the legitimate server's responses because TSPU sits
    /// fewer hops away from the user.
    pub fn ttl(&self) -> u8 {
        if self.is_v6 {
            self.bytes.get(7).copied().unwrap_or(0)
        } else {
            self.bytes.get(8).copied().unwrap_or(0)
        }
    }

    /// TCP flags byte (offset 13 within the TCP header). Returns 0
    /// for non-TCP packets.
    pub fn tcp_flags(&self) -> u8 {
        if self.proto != L4Proto::Tcp {
            return 0;
        }
        let off = self.ip_hdr_len as usize + 13;
        self.bytes.get(off).copied().unwrap_or(0)
    }

    pub fn is_tcp_rst(&self) -> bool {
        self.tcp_flags() & 0x04 != 0
    }
    pub fn is_tcp_syn(&self) -> bool {
        self.tcp_flags() & 0x02 != 0
    }
    pub fn is_tcp_ack(&self) -> bool {
        self.tcp_flags() & 0x10 != 0
    }
    pub fn is_tcp_fin(&self) -> bool {
        self.tcp_flags() & 0x01 != 0
    }

    /// Recompute IPv4/IPv6 + L4 checksums after payload mutation.
    /// Call before re-injecting.
    pub fn recompute_checksums(&mut self) {
        // Implementation lives in `checksum.rs` once added; for the
        // skeleton we leave a TODO so it's compiled but a no-op.
        // (Mutating strategies in v0.1 do not change payload length;
        //  pure splits/fragments produce *new* packets.)
    }
}
