//! Flow tracking — a small TCP/UDP state machine keyed by 5-tuple.
//!
//! Strategies need to know "is this the very first data segment after
//! the TCP handshake" or "have we already injected a fake for this
//! flow". This module owns that state.

use crate::packet::Packet;
use crate::target::Target;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: L4Proto,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowKey {
    /// Canonical key — same in both directions, used as the hash-map
    /// key so outbound and inbound packets land on the same flow.
    pub fn canonical(self) -> Self {
        if (self.src, self.src_port) <= (self.dst, self.dst_port) {
            self
        } else {
            FlowKey {
                proto: self.proto,
                src: self.dst,
                dst: self.src,
                src_port: self.dst_port,
                dst_port: self.src_port,
            }
        }
    }
}

#[derive(Debug)]
pub struct Flow {
    pub key: FlowKey,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub packet_count: u64,
    /// True once we've parsed a TLS ClientHello (TCP) or QUIC Initial (UDP).
    pub hello_seen: bool,
    /// Filled in by the target matcher.
    pub target: Option<Target>,
    pub target_resolved: bool,
    /// How many packets we've already mangled — strategies use this to
    /// fire only on the first segment.
    pub modified_count: u32,
    /// TTL of the FIRST inbound packet on this flow (typically the
    /// server's SYN-ACK). Used by the kill-rst module to identify
    /// forged TSPU RSTs whose TTL diverges from the real server's.
    pub baseline_inbound_ttl: Option<u8>,
    /// Number of inbound packets observed on this flow. We learn the
    /// baseline TTL from the first 1-2 inbound packets.
    pub inbound_count: u32,
    /// How many forged RSTs we've dropped on this flow. For diagnostics.
    pub killed_rsts: u32,
    /// True after `TcpMssClamp` rewrote the SYN's MSS option.
    /// Self-gate to prevent re-clamping on TCP retransmits.
    pub mss_clamped: bool,
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        let now = Instant::now();
        Self {
            key,
            created_at: now,
            last_seen: now,
            packet_count: 0,
            hello_seen: false,
            target: None,
            target_resolved: false,
            modified_count: 0,
            baseline_inbound_ttl: None,
            inbound_count: 0,
            killed_rsts: 0,
            mss_clamped: false,
        }
    }

    pub fn observe(&mut self, _pkt: &Packet) {
        self.last_seen = Instant::now();
        self.packet_count += 1;
    }
}

/// Bounded flow table with simple LRU-ish eviction.
/// 64k flows is plenty for a desktop and bounds memory at ~8 MiB.
pub struct FlowTable {
    inner: HashMap<FlowKey, Flow>,
    cap: usize,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::with_capacity(65_536)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: HashMap::with_capacity(cap.min(4096)),
            cap,
        }
    }

    pub fn entry(&mut self, key: FlowKey) -> &mut Flow {
        let canon = key.canonical();
        if !self.inner.contains_key(&canon) {
            if self.inner.len() >= self.cap {
                self.evict_oldest();
            }
            self.inner.insert(canon, Flow::new(canon));
        }
        self.inner.get_mut(&canon).expect("just inserted")
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn evict_oldest(&mut self) {
        if let Some((&k, _)) = self.inner.iter().min_by_key(|(_, f)| f.last_seen) {
            self.inner.remove(&k);
        }
    }
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}
