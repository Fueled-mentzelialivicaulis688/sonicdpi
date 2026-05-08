//! Generators for synthetic decoy payloads.
//!
//! We construct fake TLS ClientHello, QUIC Initial, STUN binding
//! request, and Discord-IP-Discovery-shaped buffers in code instead
//! of shipping captured `.bin` files. Captured files would fingerprint
//! every SonicDPI deployment identically — a stable hash that DPI
//! vendors would publish on day one. Generating with randomness per
//! run avoids that.

/// Inline xorshift32 — keeps engine deps minimal (no `rand`).
struct XorShift(u32);
impl XorShift {
    fn new(seed: u32) -> Self {
        Self(if seed == 0 { 0xDEAD_BEEF } else { seed })
    }
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
    fn fill(&mut self, dst: &mut [u8]) {
        let mut i = 0;
        while i < dst.len() {
            let v = self.next_u32().to_le_bytes();
            for b in v.iter() {
                if i >= dst.len() {
                    return;
                }
                dst[i] = *b;
                i += 1;
            }
        }
    }
}

fn fresh_rng() -> XorShift {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0xC0FFEE);
    XorShift::new(nanos ^ 0xA5A5_5A5A)
}

// ============================================================
//   Fake TLS 1.3 ClientHello with arbitrary SNI.
// ============================================================
//
// Just enough to fool a SNI-matcher: record / handshake / extensions
// framing is correct, cipher suites and groups look like a modern
// browser, the SNI extension carries the host we picked. We
// deliberately omit ALPN, GREASE rotation, key_share entropy etc;
// they don't affect SNI-based DPIs and bloating ClientHello past one
// MTU is exactly what we want to avoid.
pub fn build_fake_clienthello(host: &str) -> Vec<u8> {
    let mut rng = fresh_rng();
    let host = host.as_bytes();

    let mut hs = Vec::with_capacity(256);
    // Handshake type = ClientHello (0x01); 3-byte length placeholder
    hs.push(0x01);
    hs.extend_from_slice(&[0, 0, 0]);

    // legacy_version = TLS 1.2
    hs.extend_from_slice(&[0x03, 0x03]);
    // random
    let mut random = [0u8; 32];
    rng.fill(&mut random);
    hs.extend_from_slice(&random);
    // session_id (32 random bytes)
    hs.push(32);
    let mut sid = [0u8; 32];
    rng.fill(&mut sid);
    hs.extend_from_slice(&sid);

    // cipher_suites
    let ciphers: &[u16] = &[
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02b, 0xc02f, 0xc02c, 0xc030,
    ];
    let cs_len = (ciphers.len() * 2) as u16;
    hs.extend_from_slice(&cs_len.to_be_bytes());
    for c in ciphers {
        hs.extend_from_slice(&c.to_be_bytes());
    }
    // compression methods: null
    hs.push(0x01);
    hs.push(0x00);

    // ----- extensions -----
    let mut exts = Vec::with_capacity(128);
    // server_name (0x0000)
    {
        let mut sn = Vec::with_capacity(host.len() + 5);
        sn.push(0x00); // host_name type
        sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sn.extend_from_slice(host);
        exts.extend_from_slice(&[0x00, 0x00]);
        let inner_len = sn.len() as u16;
        let outer_len = inner_len + 2;
        exts.extend_from_slice(&outer_len.to_be_bytes());
        exts.extend_from_slice(&inner_len.to_be_bytes());
        exts.extend_from_slice(&sn);
    }
    // supported_versions (0x002b) — TLS 1.3
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    // supported_groups (0x000a)
    exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    // signature_algorithms (0x000d)
    exts.extend_from_slice(&[0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);

    let exts_len = exts.len() as u16;
    hs.extend_from_slice(&exts_len.to_be_bytes());
    hs.extend_from_slice(&exts);

    // patch handshake length
    let hs_body_len = hs.len() - 4;
    hs[1] = ((hs_body_len >> 16) & 0xFF) as u8;
    hs[2] = ((hs_body_len >> 8) & 0xFF) as u8;
    hs[3] = (hs_body_len & 0xFF) as u8;

    // wrap in TLS record: ContentType=Handshake(0x16), version=TLS1.0
    let mut out = Vec::with_capacity(hs.len() + 5);
    out.push(0x16);
    out.extend_from_slice(&[0x03, 0x01]);
    out.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    out.extend_from_slice(&hs);
    out
}

/// Rewrite an existing ClientHello's SNI host with `new_host` of the
/// same length. Returns None if the host length differs.
pub fn rewrite_sni_same_length(orig: &[u8], new_host: &str) -> Option<Vec<u8>> {
    let new = new_host.as_bytes();
    let orig_host = crate::tls::extract_sni(orig)?;
    if orig_host.len() != new.len() {
        return None;
    }
    let needle = orig_host.as_bytes();
    let mut buf = orig.to_vec();
    let mut idx = None;
    for i in 0..=buf.len().saturating_sub(needle.len()) {
        if buf[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            idx = Some(i);
            break;
        }
    }
    let i = idx?;
    buf[i..i + new.len()].copy_from_slice(new);
    Some(buf)
}

// ============================================================
//   Fake QUIC v1 Initial packet.
// ============================================================
//
// Long header form, version = 0x00000001, random CIDs, AEAD-shaped
// random ciphertext. A real Initial's CRYPTO frame is derived from a
// DCID-pinned key schedule (RFC 9001 §5.2); a decoy doesn't need to
// pass cryptographic decryption — a SNI-matcher that tries will hit
// junk and bail, locking the wrong fingerprint.
pub fn build_fake_quic_initial(_host: &str) -> Vec<u8> {
    let mut rng = fresh_rng();

    let dcid_len = 8usize;
    let scid_len = 0usize;
    // Aim for ~1200 bytes total (typical browser MTU-padded Initial).
    let header_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 2 + 1;
    let payload_len = 1200usize.saturating_sub(header_len);

    let mut out = Vec::with_capacity(1200);
    // 0xC0 = long-header(1) + fixed-bit(1) + type Initial(00) + low4 PN-len/reserved
    out.push(0xC0);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version 1

    out.push(dcid_len as u8);
    let mut dcid = vec![0u8; dcid_len];
    rng.fill(&mut dcid);
    out.extend_from_slice(&dcid);

    out.push(scid_len as u8);
    out.push(0x00); // token length (varint, 0)

    // Length (varint, 2-byte form for 64..=16383): 0x4000 | len
    let varint = 0x4000u16 | (payload_len as u16 + 1);
    out.extend_from_slice(&varint.to_be_bytes());

    // 1-byte packet number
    out.push(0x00);

    // Random ciphertext + AEAD tag region
    let mut body = vec![0u8; payload_len];
    rng.fill(&mut body);
    out.extend_from_slice(&body);
    out
}

// ============================================================
//   Fake STUN binding request (RFC 5389).
// ============================================================
pub fn build_fake_stun() -> Vec<u8> {
    let mut rng = fresh_rng();
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&[0x00, 0x01]); // Binding Request
    out.extend_from_slice(&[0x00, 0x00]); // length 0
    out.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    let mut tid = [0u8; 12];
    rng.fill(&mut tid);
    out.extend_from_slice(&tid);
    out
}

// ============================================================
//   Fake Discord-shaped UDP packet (IP-Discovery look-alike).
// ============================================================
pub fn build_fake_discord() -> Vec<u8> {
    let mut rng = fresh_rng();
    let mut out = Vec::with_capacity(74);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x46]);
    let mut body = [0u8; 70];
    rng.fill(&mut body);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clienthello_has_expected_sni() {
        let bytes = build_fake_clienthello("www.google.com");
        let sni = crate::tls::extract_sni(&bytes).expect("parses");
        assert_eq!(sni, "www.google.com");
    }

    #[test]
    fn rewrite_sni_preserves_layout() {
        let bytes = build_fake_clienthello("www.google.com"); // 14 chars
                                                              // Same-length replacement (also 14 chars).
        let rewritten = rewrite_sni_same_length(&bytes, "ww1.google.com").expect("same length");
        assert_eq!(rewritten.len(), bytes.len());
        let new_sni = crate::tls::extract_sni(&rewritten).expect("parses");
        assert_eq!(new_sni, "ww1.google.com");
    }

    #[test]
    fn rewrite_sni_rejects_different_length() {
        let bytes = build_fake_clienthello("www.google.com");
        assert!(rewrite_sni_same_length(&bytes, "google.com").is_none());
    }

    #[test]
    fn quic_initial_has_long_header() {
        let bytes = build_fake_quic_initial("www.google.com");
        assert_eq!(bytes[0] & 0xF0, 0xC0);
        assert_eq!(&bytes[1..5], &[0x00, 0x00, 0x00, 0x01]);
    }
}
