//! Minimal TLS / QUIC parsers — just enough to find SNI and detect
//! ClientHello / QUIC Initial packets. We deliberately do NOT pull in
//! a full TLS library: we never decrypt, and reading 30 lines of the
//! handshake is cheaper than rustls.

/// Returns true iff `payload` looks like a TLS 1.x ClientHello sitting
/// at offset 0 of a TCP segment.
pub fn is_client_hello(payload: &[u8]) -> bool {
    // TLS record:  ContentType(0x16) | Version(2) | Length(2) | ...
    // Handshake:   HandshakeType(0x01 = ClientHello) | Length(3) | ...
    payload.len() >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

/// Returns true iff `payload` looks like a QUIC long-header Initial
/// packet (RFC 9000 §17.2.2).
pub fn is_quic_initial(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let b0 = payload[0];
    // Long-header form bit + fixed bit + Initial type bits (00).
    // For QUIC v1: 0b1100xxxx for Initial. Reserved+packet-number bits
    // make the low nibble vary, so mask.
    (b0 & 0xF0) == 0xC0
}

/// Extract the SNI hostname from a TLS ClientHello payload, if present.
/// Returns lowercase ASCII to make matching trivial.
///
/// This is best-effort: malformed records simply yield None. We never
/// allocate beyond the returned String.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    if !is_client_hello(payload) {
        return None;
    }
    // Walk the handshake structure.
    let mut p = 5; // skip TLS record header
    p += 4; // HandshakeType(1) + length(3)
    p += 2; // legacy_version
    p += 32; // random

    // session_id
    let sid_len = *payload.get(p)? as usize;
    p += 1 + sid_len;

    // cipher_suites
    let cs_len = u16::from_be_bytes([*payload.get(p)?, *payload.get(p + 1)?]) as usize;
    p += 2 + cs_len;

    // compression_methods
    let cm_len = *payload.get(p)? as usize;
    p += 1 + cm_len;

    // extensions
    let ext_total = u16::from_be_bytes([*payload.get(p)?, *payload.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = p + ext_total;

    while p + 4 <= ext_end && p + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[p], payload[p + 1]]);
        let ext_len = u16::from_be_bytes([payload[p + 2], payload[p + 3]]) as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name
            // skip 2-byte server_name_list length
            let list_end = p + ext_len;
            p += 2;
            // name_type(1) + name_len(2) + name(name_len)
            if p + 3 <= list_end {
                let _name_type = payload[p];
                let name_len = u16::from_be_bytes([payload[p + 1], payload[p + 2]]) as usize;
                p += 3;
                if p + name_len <= payload.len() {
                    let host = std::str::from_utf8(&payload[p..p + name_len]).ok()?;
                    return Some(host.to_ascii_lowercase());
                }
            }
            return None;
        }
        p += ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_minimal_clienthello_marker() {
        let buf = [0x16, 0x03, 0x01, 0x00, 0x00, 0x01];
        assert!(is_client_hello(&buf));
    }

    #[test]
    fn rejects_non_handshake() {
        let buf = [0x17, 0x03, 0x03, 0x00, 0x00, 0x01];
        assert!(!is_client_hello(&buf));
    }
}
