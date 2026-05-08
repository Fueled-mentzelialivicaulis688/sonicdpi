//! Real captured decoy payloads from Flowseal/zapret-discord-youtube.
//!
//! These bytes are **not** synthetic — they are fully-formed packets
//! captured against actual servers. Using them as decoys gives our
//! injected fakes a real-browser TLS fingerprint (JA3) and a real
//! QUIC Initial CRYPTO frame layout. Synthetic decoys built in
//! `fakes.rs` lack modern TLS extensions (key_share, GREASE, ALPN,
//! psk_key_exchange_modes) and have a static fingerprint TSPU 2026
//! has been observed to score as "junk decoy".
//!
//! Source: `C:\Users\Sonic\Desktop\2\bin\` (Flowseal repackaged).
//!
//! Sizes (also seqovl values used by Flowseal `general.bat`):
//!   - tls_clienthello_4pda_to.bin       284 B  (general.bat seqovl=568 = 2x)
//!   - tls_clienthello_max_ru.bin        664 B  (ALT11 seqovl=664)
//!   - tls_clienthello_www_google_com.bin 681 B (general.bat seqovl=681)
//!   - quic_initial_www_google_com.bin   1200 B
//!   - quic_initial_dbankcloud_ru.bin    1357 B (used as fake-discord + fake-stun)
//!   - stun.bin                           100 B

pub const TLS_CH_4PDA_TO: &[u8] =
    include_bytes!("../../../vendor/fakes/tls_clienthello_4pda_to.bin");
pub const TLS_CH_MAX_RU: &[u8] = include_bytes!("../../../vendor/fakes/tls_clienthello_max_ru.bin");
pub const TLS_CH_GOOGLE: &[u8] =
    include_bytes!("../../../vendor/fakes/tls_clienthello_www_google_com.bin");
pub const QUIC_INITIAL_GOOGLE: &[u8] =
    include_bytes!("../../../vendor/fakes/quic_initial_www_google_com.bin");
pub const QUIC_INITIAL_DBANKCLOUD: &[u8] =
    include_bytes!("../../../vendor/fakes/quic_initial_dbankcloud_ru.bin");
pub const STUN_REAL: &[u8] = include_bytes!("../../../vendor/fakes/stun.bin");

/// Resolve a SNI host string to an embedded captured ClientHello, if
/// we have one. Falls back to None — caller can synthesize via
/// `fakes::build_fake_clienthello`.
pub fn lookup_tls_ch(host: &str) -> Option<&'static [u8]> {
    match host {
        "4pda.to" => Some(TLS_CH_4PDA_TO),
        "max.ru" => Some(TLS_CH_MAX_RU),
        "www.google.com" => Some(TLS_CH_GOOGLE),
        _ => None,
    }
}

/// Resolve a host string to a captured QUIC Initial.
pub fn lookup_quic_initial(host: &str) -> Option<&'static [u8]> {
    match host {
        "www.google.com" => Some(QUIC_INITIAL_GOOGLE),
        "dbankcloud.ru" => Some(QUIC_INITIAL_DBANKCLOUD),
        _ => None,
    }
}
