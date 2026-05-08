//! Packet builder — turns a parsed `Packet` plus a desired mutation
//! into one or more fully-formed IP datagrams ready for re-injection.
//!
//! Strategies declare *intent* (split this segment, prepend a decoy);
//! this module turns intent into bytes with correct seq numbers and
//! checksums. Platform backends just push the resulting `FakePacket`s
//! to the wire.
//!
//! Scope of v0.2:
//!   - IPv4 + IPv6 carriers
//!   - TCP segment builder with seq/ack/flags/options
//!   - UDP datagram builder
//!   - IPv4/IPv6/TCP/UDP checksum recomputation (delegated to etherparse)
//!   - TTL override for "fake" packets
//!
//! Out of scope:
//!   - TCP MD5SIG option emission (placeholder; some kernels strip)
//!   - IP options other than TTL

use crate::action::FakePacket;
use crate::flow::L4Proto;
use crate::packet::Packet;
use etherparse::PacketBuilder;
use std::net::IpAddr;

/// A description of a packet we want the platform layer to send.
/// Built from an `Original` reference so we inherit the 5-tuple.
#[derive(Debug, Clone)]
pub struct Crafted {
    pub bytes: Vec<u8>,
    pub ttl_override: Option<u8>,
}

impl From<Crafted> for FakePacket {
    fn from(c: Crafted) -> Self {
        FakePacket {
            bytes: c.bytes,
            ttl_override: c.ttl_override,
        }
    }
}

/// Default TTL used for outbound fake packets. Real OSes default to
/// 64 (Linux/macOS) or 128 (Windows); we follow the strategy's
/// suggestion if any, else 128.
pub const DEFAULT_TTL: u8 = 128;

/// Build a fresh TCP segment that mirrors the original 5-tuple but
/// carries `payload`, with `seq_offset` added to the original seq.
///
/// Uses `etherparse::PacketBuilder` so checksums are correct.
pub fn build_tcp_segment(
    orig: &Packet,
    payload: &[u8],
    seq_offset: i64,
    ttl: u8,
) -> Option<Vec<u8>> {
    if orig.proto != L4Proto::Tcp {
        return None;
    }
    let (orig_seq, orig_ack, orig_flags, orig_window) = read_tcp_header(orig)?;
    let new_seq = (orig_seq as i64).wrapping_add(seq_offset) as u32;

    let builder = match (orig.src, orig.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), ttl).tcp(
            orig.src_port,
            orig.dst_port,
            new_seq,
            orig_window,
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), ttl).tcp(
            orig.src_port,
            orig.dst_port,
            new_seq,
            orig_window,
        ),
        _ => return None,
    };

    // Preserve ACK and PSH flags from the original to keep the
    // segment looking like a normal data segment.
    let (mut builder, _) = (builder, ());
    if orig_flags & TCP_FLAG_ACK != 0 {
        builder = builder.ack(orig_ack);
    }
    if orig_flags & TCP_FLAG_PSH != 0 {
        builder = builder.psh();
    }

    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}

/// Build a fresh UDP datagram.
pub fn build_udp_datagram(orig: &Packet, payload: &[u8], ttl: u8) -> Option<Vec<u8>> {
    if orig.proto != L4Proto::Udp {
        return None;
    }
    let builder = match (orig.src, orig.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            PacketBuilder::ipv4(s.octets(), d.octets(), ttl).udp(orig.src_port, orig.dst_port)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            PacketBuilder::ipv6(s.octets(), d.octets(), ttl).udp(orig.src_port, orig.dst_port)
        }
        _ => return None,
    };
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}

/// TLS multisplit + seqovl. Produces TWO segments:
///   seg1: orig_payload[0..split_pos], seq = orig_seq
///   seg2: fake_padding(seqovl) || orig_payload[split_pos..],
///         seq = orig_seq + split_pos - seqovl
///
/// Result: server reassembles correctly (overlap is discarded by
/// kernel TCP); DPIs that first-write-win see fake_padding overlaid
/// on the segment start and fail to recognize the ClientHello.
pub fn craft_multisplit(
    orig: &Packet,
    split_pos: usize,
    seqovl: u32,
    fake_filler_byte: u8,
) -> Option<Vec<Crafted>> {
    craft_multisplit_with_pattern(orig, split_pos, seqovl, &[fake_filler_byte])
}

/// Multi-disorder: split the ClientHello into TWO segments and emit
/// the TAIL FIRST, the HEAD SECOND on the wire. Both have correct
/// non-overlapping seq numbers (server's TCP reorders by seq and
/// reassembles the real CH). DPIs whose reassembler greedily ingests
/// the first-arriving bytes try to parse from offset `split_pos`
/// (mid-record), bail with "not a valid TLS record start", and
/// commit a "no-SNI" verdict before the head arrives.
///
/// Different reassembly path than multisplit (no overlap), so DPIs
/// that defeat `multisplit + seqovl` may not yet defeat this. Useful
/// alternative when the gentle multisplit is being detected.
pub fn craft_multidisorder(orig: &Packet, split_pos: usize) -> Option<Vec<Crafted>> {
    let payload = orig.payload();
    if split_pos == 0 || split_pos >= payload.len() {
        return None;
    }
    let head = &payload[..split_pos];
    let tail = &payload[split_pos..];

    // Build both segments preserving original TCP options (TS, SACK,
    // window-scale) — Cloudflare/Discord drop derived segments
    // without TS once TS was negotiated in SYN.
    let head_seg = clone_with_payload(orig, head, 0, 0)?;
    let tail_seg = clone_with_payload(orig, tail, split_pos as i64, 1)?;

    // EMIT TAIL FIRST, HEAD SECOND. Returned vec order = wire emission order.
    Some(vec![
        Crafted {
            bytes: tail_seg,
            ttl_override: None,
        },
        Crafted {
            bytes: head_seg,
            ttl_override: None,
        },
    ])
}

/// Same as `craft_multisplit` but the seqovl region is filled with
/// the bytes of `pattern` (repeated/truncated to seqovl bytes).
///
/// Built from the **original packet as a template** so all TCP
/// options (timestamps, SACK-permitted, MSS, window-scale) propagate
/// to seg1/seg2. Earlier versions used etherparse's
/// `PacketBuilder` which drops every option, producing segments
/// without TS — Cloudflare/Discord servers then dropped them as
/// malformed mid-stream and the user saw "Update failed".
pub fn craft_multisplit_with_pattern(
    orig: &Packet,
    split_pos: usize,
    seqovl: u32,
    pattern: &[u8],
) -> Option<Vec<Crafted>> {
    let payload = orig.payload();
    if split_pos == 0 || split_pos >= payload.len() {
        return None;
    }
    let seg1_payload = &payload[..split_pos];
    let seg2_real = &payload[split_pos..];

    // seg1 keeps the original IP id; seg2 gets +1 to avoid being
    // mistaken for a fragmentation duplicate by middleboxes/NIC.
    let seg1_bytes = clone_with_payload(orig, seg1_payload, 0, 0)?;

    let mut seg2_payload = Vec::with_capacity(seqovl as usize + seg2_real.len());
    if pattern.is_empty() {
        seg2_payload.resize(seqovl as usize, 0);
    } else {
        let mut filled = 0usize;
        while filled < seqovl as usize {
            let take = ((seqovl as usize) - filled).min(pattern.len());
            seg2_payload.extend_from_slice(&pattern[..take]);
            filled += take;
        }
    }
    seg2_payload.extend_from_slice(seg2_real);

    let seq_offset = (split_pos as i64) - (seqovl as i64);
    let seg2_bytes = clone_with_payload(orig, &seg2_payload, seq_offset, 1)?;

    // WIRE ORDER: seg2 (lower seq, with seqovl pattern) emitted FIRST,
    // seg1 (higher seq, real first byte) emitted SECOND. This matches
    // Flowseal/zapret canonical multisplit emission order. The point:
    // DPI's first-arrival-wins reassembler ingests seg2's pattern bytes
    // at the overlap position before seg1's real byte arrives — DPI's
    // TLS parser then sees garbage at the supposed record start and
    // bails. The server (Linux/Cloudflare TCP, first-write-wins on
    // overlap) keeps whichever arrived first there too, but for the
    // server we need seg1's `0x16` to win — which it does because
    // both packets cross the wire within microseconds and the server's
    // TCP stack receives them basically simultaneously, then resolves
    // overlap by sequence-number ordering: seg1 covers [N..N+1) (one
    // byte at exactly seq N) which the server's reassembler accepts
    // first as the in-window first byte. seg2's overlap byte at the
    // same seq N is then discarded as duplicate.
    //
    // Earlier versions emitted seg1 first, which made DPI win the
    // reassembly race and extract the real SNI → block.
    Some(vec![
        Crafted {
            bytes: seg2_bytes,
            ttl_override: None,
        },
        Crafted {
            bytes: seg1_bytes,
            ttl_override: None,
        },
    ])
}

/// Hard cap on cloned-segment size. WinDivert can in principle inject
/// up to 64 KB IP packets (the OS handles segmentation downstream via
/// TSO), but we keep a sanity cap of 16 KB to catch pathological
/// callers without no-oping on real Chrome ClientHellos which routinely
/// hit ~2.3 KB with Kyber-PQ key share + seqovl=568 → ~2.9 KB seg2.
/// Setting this too low silently disables desync on big CHs (which
/// are the typical case in 2026, not edge), so don't tighten it
/// without checking.
const SAFE_MAX_PACKET: usize = 16384;

/// Clone the original packet's IP+TCP headers verbatim (preserving
/// all TCP options) and replace only the L4 payload + sequence
/// number (offset by `seq_offset`). IP id is bumped by `ip_id_delta`
/// so derived clones don't reuse the original's id (middleboxes can
/// treat duplicate IP ids as fragmentation aliases or drop them as
/// suspected scan retransmits). IP total-length and the IP+TCP
/// checksums are recomputed. Returns None when the result would
/// exceed `SAFE_MAX_PACKET` so the caller falls back to passthrough
/// instead of crashing WinDivert.
fn clone_with_payload(
    orig: &Packet,
    new_payload: &[u8],
    seq_offset: i64,
    ip_id_delta: u16,
) -> Option<Vec<u8>> {
    let ip_hdr_len = orig.ip_hdr_len as usize;
    let l4_hdr_len = orig.l4_hdr_len as usize;
    let header_len = ip_hdr_len + l4_hdr_len;
    if header_len > orig.bytes.len() {
        return None;
    }
    if header_len + new_payload.len() > SAFE_MAX_PACKET {
        return None;
    }

    let mut buf = Vec::with_capacity(header_len + new_payload.len());
    buf.extend_from_slice(&orig.bytes[..header_len]);
    buf.extend_from_slice(new_payload);

    // Patch IP total-length / payload-length and bump IP id.
    if !orig.is_v6 {
        let total_len = buf.len() as u16;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        // Bump IP id (offset 4-5) by ip_id_delta to avoid duplicates.
        let cur_id = u16::from_be_bytes([buf[4], buf[5]]);
        let new_id = cur_id.wrapping_add(ip_id_delta);
        buf[4..6].copy_from_slice(&new_id.to_be_bytes());
        // Reset and recompute IPv4 header checksum.
        buf[10] = 0;
        buf[11] = 0;
        let cs = ip_checksum_inline(&buf[..ip_hdr_len]);
        buf[10..12].copy_from_slice(&cs.to_be_bytes());
    } else {
        let payload_len = (buf.len() as u16).saturating_sub(40);
        buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
        // No IPv6 header checksum.
    }

    // Patch TCP sequence number with the requested offset.
    let seq_off = ip_hdr_len + 4;
    let cur_seq = u32::from_be_bytes([
        buf[seq_off],
        buf[seq_off + 1],
        buf[seq_off + 2],
        buf[seq_off + 3],
    ]);
    let new_seq = (cur_seq as i64).wrapping_add(seq_offset) as u32;
    buf[seq_off..seq_off + 4].copy_from_slice(&new_seq.to_be_bytes());

    // Recompute TCP checksum (delegates to fooling.rs::recompute_tcp_checksum
    // which knows IPv4/IPv6 pseudo-headers).
    crate::fooling::recompute_tcp_checksum_pub(&mut buf)?;

    Some(buf)
}

fn ip_checksum_inline(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// "Fake then real" — emit `repeats` copies of `fake_payload` on the
/// same 5-tuple at original seq with the given fooling primitive
/// applied so the server discards them while the DPI ingests them.
pub fn craft_fakes_for_tcp(
    orig: &Packet,
    fake_payload: &[u8],
    repeats: u8,
    fooling: FoolingKind,
) -> Option<Vec<Crafted>> {
    let mut out = Vec::with_capacity(repeats as usize);
    for _ in 0..repeats {
        let mut bytes = build_tcp_segment(orig, fake_payload, 0, fooling.ttl())?;
        match fooling {
            FoolingKind::Ttl(_) => {} // TTL was applied at build time
            FoolingKind::Md5sig => {
                crate::fooling::apply_md5sig(&mut bytes)?;
            }
            FoolingKind::Badseq => {
                crate::fooling::apply_badseq(&mut bytes, 0x10000)?;
            }
            FoolingKind::Badsum => {
                crate::fooling::apply_badsum(&mut bytes)?;
            }
            FoolingKind::Timestamp => {
                crate::fooling::apply_timestamp(&mut bytes)?;
            }
            FoolingKind::TsMd5sig => {
                // Match Flowseal `general (ALT9).bat` general-list line:
                // `--dpi-desync-fooling=ts,md5sig`. Timestamp first
                // (PAWS rejects via TSval=1 on every TCP stack);
                // md5sig second (kernels without configured key drop
                // independently). Both options must fit in the 60-byte
                // TCP-options budget — TS=12B + MD5=20B = 32B, OK.
                crate::fooling::apply_timestamp(&mut bytes)?;
                crate::fooling::apply_md5sig(&mut bytes)?;
            }
        }
        out.push(Crafted {
            bytes,
            ttl_override: match fooling {
                FoolingKind::Ttl(n) => Some(n),
                _ => None,
            },
        });
    }
    Some(out)
}

/// Carrier-agnostic representation of a fooling primitive that the
/// builder accepts. Mirrors `strategy::Fooling` but lives here to
/// avoid a strategy → builder dep cycle.
#[derive(Copy, Clone, Debug)]
pub enum FoolingKind {
    Ttl(u8),
    Md5sig,
    Badseq,
    Badsum,
    Timestamp,
    /// Apply both Timestamp (PAWS via TSval=1) and Md5sig — matches
    /// zapret `--dpi-desync-fooling=ts,md5sig`.
    TsMd5sig,
}

impl FoolingKind {
    fn ttl(self) -> u8 {
        match self {
            FoolingKind::Ttl(n) => n,
            _ => DEFAULT_TTL,
        }
    }
}

/// Same idea for UDP: emit `repeats` copies of `fake_payload` on the
/// same 5-tuple before the real datagram.
pub fn craft_fakes_for_udp(
    orig: &Packet,
    fake_payload: &[u8],
    repeats: u8,
    ttl: u8,
) -> Option<Vec<Crafted>> {
    let mut out = Vec::with_capacity(repeats as usize);
    for _ in 0..repeats {
        let bytes = build_udp_datagram(orig, fake_payload, ttl)?;
        out.push(Crafted {
            bytes,
            ttl_override: Some(ttl),
        });
    }
    Some(out)
}

// ----- TCP header introspection ----------------------------------

const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_PSH: u8 = 0x08;

fn read_tcp_header(p: &Packet) -> Option<(u32, u32, u8, u16)> {
    let l4_off = p.ip_hdr_len as usize;
    let bytes = &p.bytes;
    if bytes.len() < l4_off + 20 {
        return None;
    }
    let seq = u32::from_be_bytes([
        bytes[l4_off + 4],
        bytes[l4_off + 5],
        bytes[l4_off + 6],
        bytes[l4_off + 7],
    ]);
    let ack = u32::from_be_bytes([
        bytes[l4_off + 8],
        bytes[l4_off + 9],
        bytes[l4_off + 10],
        bytes[l4_off + 11],
    ]);
    let flags = bytes[l4_off + 13];
    let window = u16::from_be_bytes([bytes[l4_off + 14], bytes[l4_off + 15]]);
    Some((seq, ack, flags, window))
}
