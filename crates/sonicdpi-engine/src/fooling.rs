//! TCP "fooling" primitives — make a decoy packet that DPI ingests as
//! valid flow data but the server discards.
//!
//! Each function operates in-place on a fully-formed IPv4 / IPv6 + TCP
//! packet (the byte buffer produced by `builder::build_tcp_segment`).
//! After mutation the IP and TCP checksums are recomputed.
//!
//! All offsets are derived freshly from the IP header to support both
//! v4 and v6 carriers.

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

/// In-place: corrupt the TCP checksum so the server's NIC/kernel
/// drops the segment. DPI generally trusts the IP-layer checksum and
/// keeps the data.
pub fn apply_badsum(bytes: &mut [u8]) -> Option<()> {
    let (_, l4_off) = header_offsets(bytes)?;
    let cs_off = l4_off + 16;
    if cs_off + 2 > bytes.len() {
        return None;
    }
    bytes[cs_off] ^= 0xFF;
    bytes[cs_off + 1] ^= 0xFF;
    Some(())
}

/// In-place: bump the TCP sequence number by a large delta so the
/// segment lands outside the receive window. Server drops; DPI may
/// still ingest it as flow data depending on its state machine.
pub fn apply_badseq(bytes: &mut [u8], delta: i64) -> Option<()> {
    let (_, l4_off) = header_offsets(bytes)?;
    let seq_off = l4_off + 4;
    if seq_off + 4 > bytes.len() {
        return None;
    }
    let cur = u32::from_be_bytes([
        bytes[seq_off],
        bytes[seq_off + 1],
        bytes[seq_off + 2],
        bytes[seq_off + 3],
    ]);
    let new = (cur as i64).wrapping_add(delta) as u32;
    bytes[seq_off..seq_off + 4].copy_from_slice(&new.to_be_bytes());
    recompute_tcp_checksum(bytes)
}

/// In-place: append a TCP MD5 signature option (RFC 2385, kind=19).
/// Servers without a configured MD5SIG association silently drop the
/// segment; most middleboxes ignore the option and accept the data.
///
/// This grows the TCP header by 20 bytes (option = 18 + 2 NOP padding
/// to keep 4-byte alignment) — we shift the payload right and update
/// IP total-length, TCP data-offset, and checksums.
pub fn apply_md5sig(bytes: &mut Vec<u8>) -> Option<()> {
    apply_tcp_option(
        bytes,
        &[
            0x01, 0x01, 0x13, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    )
}

/// In-place: append a TCP timestamp option (RFC 7323, kind=8) with
/// `TSval = 1`. The server's PAWS check (RFC 7323 §5.3) discards
/// segments whose TSval is older than `TS.recent` for the connection.
/// Since real TS counters are large monotonic values, `TSval=1` is
/// guaranteed to be older → server-side kernel drop, no TLS layer
/// involvement. DPI middleboxes don't track per-flow TS state, so
/// they accept the decoy as valid flow data.
///
/// This matches zapret's `--dpi-desync-fooling=ts`. Earlier versions
/// of this function used `TSval = 0xDEADBEEF` which has the OPPOSITE
/// effect — large TSval is "newer", PAWS accepts, server processes
/// the decoy ClientHello → multiple-CH-on-one-flow → Alert/RST.
pub fn apply_timestamp(bytes: &mut Vec<u8>) -> Option<()> {
    apply_tcp_option(
        bytes,
        &[
            0x01, 0x01, // NOP, NOP padding (keeps option 4-byte aligned)
            0x08, 0x0A, // kind=8 (TS), length=10
            0x00, 0x00, 0x00, 0x01, // TSval = 1 (forces PAWS rejection)
            0x00, 0x00, 0x00, 0x00, // TSecr = 0
        ],
    )
}

// ----- internals ----------------------------------------------------

fn header_offsets(bytes: &[u8]) -> Option<(u16, usize)> {
    let sp = SlicedPacket::from_ip(bytes).ok()?;
    let ip_hdr_len = match sp.net.as_ref()? {
        InternetSlice::Ipv4(v4) => (v4.header().ihl() as u16) * 4,
        InternetSlice::Ipv6(_) => 40,
    };
    let l4_off = ip_hdr_len as usize;
    match sp.transport.as_ref()? {
        TransportSlice::Tcp(_) => {}
        _ => return None,
    }
    Some((ip_hdr_len, l4_off))
}

/// Append `option_bytes` to the TCP header. `option_bytes` length
/// MUST be a multiple of 4 (TCP data-offset is in 4-byte words).
fn apply_tcp_option(bytes: &mut Vec<u8>, option_bytes: &[u8]) -> Option<()> {
    if !option_bytes.len().is_multiple_of(4) {
        return None;
    }
    let (ip_hdr_len, l4_off) = header_offsets(bytes)?;

    // Current TCP header length (data-offset * 4)
    let do_byte = bytes[l4_off + 12];
    let cur_tcp_hdr_len = ((do_byte >> 4) as usize) * 4;
    let new_tcp_hdr_len = cur_tcp_hdr_len + option_bytes.len();
    if new_tcp_hdr_len > 60 {
        // TCP header max is 60 bytes (data-offset is 4 bits => 15 words).
        return None;
    }

    // Splice option bytes into the TCP header right at its tail.
    let insert_at = l4_off + cur_tcp_hdr_len;
    let mut new_buf = Vec::with_capacity(bytes.len() + option_bytes.len());
    new_buf.extend_from_slice(&bytes[..insert_at]);
    new_buf.extend_from_slice(option_bytes);
    new_buf.extend_from_slice(&bytes[insert_at..]);
    *bytes = new_buf;

    // Update TCP data-offset.
    let new_do = ((new_tcp_hdr_len / 4) as u8) << 4;
    bytes[l4_off + 12] = (bytes[l4_off + 12] & 0x0F) | new_do;

    // Update IP total length.
    match bytes[0] >> 4 {
        4 => {
            let total = (bytes.len() as u16).to_be_bytes();
            bytes[2] = total[0];
            bytes[3] = total[1];
            // Reset IP header checksum and recompute.
            bytes[10] = 0;
            bytes[11] = 0;
            let cs = ip_checksum(&bytes[..ip_hdr_len as usize]);
            bytes[10..12].copy_from_slice(&cs.to_be_bytes());
        }
        6 => {
            // IPv6 payload length = total - 40
            let payload_len = (bytes.len() as u16).saturating_sub(40).to_be_bytes();
            bytes[4] = payload_len[0];
            bytes[5] = payload_len[1];
            // No IP-layer checksum on IPv6.
        }
        _ => return None,
    }

    recompute_tcp_checksum(bytes)
}

fn ip_checksum(header: &[u8]) -> u16 {
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

/// Re-export of `recompute_tcp_checksum` for `builder.rs` (which
/// needs it after rewriting seq numbers in cloned packet headers).
pub fn recompute_tcp_checksum_pub(bytes: &mut [u8]) -> Option<()> {
    recompute_tcp_checksum(bytes)
}

/// In-place: rewrite the TCP MSS option (kind=2, length=4) in a SYN
/// packet to the given MSS value. If no MSS option exists in the
/// header (rare on SYNs), returns None — caller should fall back to
/// passthrough.
///
/// Why: TSPU's 2026 mid-stream re-classifier reassembles HTTP/2
/// framing across TCP segments. By clamping MSS=536 in the SYN, we
/// force the server's TCP stack to send every subsequent data
/// segment at ≤536 payload bytes. HTTP/2 frame headers straddle TCP
/// boundaries unpredictably, defeating the classifier's reassembly.
/// Source: bol-van/zapret #1806, crayfos/mtproxy-setup. The empirical
/// "sweet spot" is 536; lower works but is slow, higher doesn't
/// fragment enough.
pub fn apply_mss_clamp(bytes: &mut [u8], mss: u16) -> Option<()> {
    let (_, l4_off) = header_offsets(bytes)?;
    let do_byte = bytes[l4_off + 12];
    let tcp_hdr_len = ((do_byte >> 4) as usize) * 4;
    if tcp_hdr_len <= 20 {
        return None; // no options
    }

    // Walk options at l4_off + 20 .. l4_off + tcp_hdr_len.
    let opts_start = l4_off + 20;
    let opts_end = l4_off + tcp_hdr_len;
    let mut i = opts_start;
    while i < opts_end {
        let kind = bytes[i];
        match kind {
            0 => break,  // EOL
            1 => i += 1, // NOP, no length byte
            _ => {
                if i + 1 >= opts_end {
                    return None;
                }
                let len = bytes[i + 1] as usize;
                if len < 2 || i + len > opts_end {
                    return None;
                }
                if kind == 2 && len == 4 {
                    // MSS option found. Patch bytes [i+2..i+4].
                    let mss_be = mss.to_be_bytes();
                    bytes[i + 2] = mss_be[0];
                    bytes[i + 3] = mss_be[1];
                    return recompute_tcp_checksum(bytes);
                }
                i += len;
            }
        }
    }
    None
}

fn recompute_tcp_checksum(bytes: &mut [u8]) -> Option<()> {
    let (_, l4_off) = header_offsets(bytes)?;
    // Zero the existing checksum field.
    bytes[l4_off + 16] = 0;
    bytes[l4_off + 17] = 0;

    let tcp_len = bytes.len() - l4_off;
    let mut sum: u32 = 0;
    match bytes[0] >> 4 {
        4 => {
            // Pseudo-header: src(4), dst(4), zero(1), proto(1), tcp_len(2)
            sum += u16::from_be_bytes([bytes[12], bytes[13]]) as u32;
            sum += u16::from_be_bytes([bytes[14], bytes[15]]) as u32;
            sum += u16::from_be_bytes([bytes[16], bytes[17]]) as u32;
            sum += u16::from_be_bytes([bytes[18], bytes[19]]) as u32;
            sum += 6u32; // protocol = TCP
            sum += tcp_len as u32;
        }
        6 => {
            // Pseudo-header v6: src(16), dst(16), tcp_len(4), zero(3), nh(1)
            for i in (8..40).step_by(2) {
                sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            }
            sum += (tcp_len >> 16) as u32 & 0xFFFF;
            sum += tcp_len as u32 & 0xFFFF;
            sum += 6u32;
        }
        _ => return None,
    }
    let mut i = l4_off;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cs = !(sum as u16);
    bytes[l4_off + 16..l4_off + 18].copy_from_slice(&cs.to_be_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn sample_v4_tcp(payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).tcp(12345, 443, 1000, 65535);
        let mut out = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn badsum_changes_checksum() {
        let mut p = sample_v4_tcp(b"hello");
        let l4_off = ((p[0] & 0x0F) as usize) * 4;
        let before = u16::from_be_bytes([p[l4_off + 16], p[l4_off + 17]]);
        apply_badsum(&mut p).unwrap();
        let after = u16::from_be_bytes([p[l4_off + 16], p[l4_off + 17]]);
        assert_ne!(before, after);
    }

    #[test]
    fn badseq_changes_seq_and_checksum() {
        let mut p = sample_v4_tcp(b"hi");
        let before_seq = u32::from_be_bytes([p[20 + 4], p[20 + 5], p[20 + 6], p[20 + 7]]);
        let before_cs = u16::from_be_bytes([p[20 + 16], p[20 + 17]]);
        apply_badseq(&mut p, 0x10000).unwrap();
        let after_seq = u32::from_be_bytes([p[20 + 4], p[20 + 5], p[20 + 6], p[20 + 7]]);
        let after_cs = u16::from_be_bytes([p[20 + 16], p[20 + 17]]);
        assert_eq!(after_seq, before_seq.wrapping_add(0x10000));
        assert_ne!(before_cs, after_cs);
    }

    #[test]
    fn md5sig_grows_header_by_20() {
        let mut p = sample_v4_tcp(b"hello world");
        let len_before = p.len();
        let do_before = (p[20 + 12] >> 4) as usize * 4;
        apply_md5sig(&mut p).unwrap();
        let len_after = p.len();
        let do_after = (p[20 + 12] >> 4) as usize * 4;
        assert_eq!(len_after - len_before, 20);
        assert_eq!(do_after - do_before, 20);
        // IP total length matches buffer length
        let ip_total = u16::from_be_bytes([p[2], p[3]]) as usize;
        assert_eq!(ip_total, p.len());
    }

    #[test]
    fn timestamp_grows_header_by_12() {
        let mut p = sample_v4_tcp(b"x");
        let len_before = p.len();
        apply_timestamp(&mut p).unwrap();
        assert_eq!(p.len() - len_before, 12);
    }
}
