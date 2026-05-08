//! Target identification.
//!
//! Heuristics, in order of confidence:
//!  1. TLS ClientHello SNI substring (TCP/443)
//!  2. QUIC Initial — packet shape match (UDP/443)
//!  3. Discord voice — RTP shape on known UDP port ranges
//!  4. IP prefix in known target ranges (Discord ASN, Google CDN)
//!  5. Sticky: inherit a target already assigned to this flow

use crate::flow::Flow;
use crate::packet::Packet;
use crate::tls::{extract_sni, is_quic_initial};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    YouTube,           // *.googlevideo.com, youtube.com etc. — TLS/TCP
    YouTubeQuic,       // same hosts over QUIC/UDP/443
    DiscordGateway,    // discord.gg, *.discord.media — Discord-direct AS49544
    DiscordCloudflare, // discord.com, discordapp.com, discordapp.net — Cloudflare-fronted
    DiscordVoice,      // RTP/UDP to Discord media servers
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetSet {
    /// SNI suffix patterns ("googlevideo.com" matches "rr1.googlevideo.com").
    pub sni_patterns: Vec<(String, Target)>,
    /// IP prefixes (CIDR) — used as fallback when SNI is unavailable.
    pub ip_prefixes: Vec<(IpNet, Target)>,
    /// UDP port ranges that look like Discord voice (RTP shape).
    pub discord_voice_udp_ports: Vec<(u16, u16)>,
}

impl TargetSet {
    pub fn identify(&self, pkt: &Packet, flow: &Flow) -> Option<Target> {
        // 1. TLS SNI
        if pkt.proto == crate::flow::L4Proto::Tcp {
            if let Some(host) = extract_sni(pkt.payload()) {
                for (needle, t) in &self.sni_patterns {
                    if host == *needle || host.ends_with(&format!(".{needle}")) {
                        return Some(*t);
                    }
                }
            }
        }
        // 2. QUIC Initial — only classify when we can VERIFY the
        //    destination belongs to YouTube via an IP-prefix match.
        //    Default-tagging every QUIC packet as YouTubeQuic broke
        //    every other HTTP/3 site (Cloudflare, Discord CDN, GitHub
        //    pages, …) because we'd desync their Initials too.
        //    The Engine's DNS-cache fallback (in lib.rs::handle) will
        //    upgrade the flow target later if a recent A/AAAA response
        //    bound this IP to googlevideo.com et al.
        if pkt.proto == crate::flow::L4Proto::Udp
            && pkt.dst_port == 443
            && is_quic_initial(pkt.payload())
        {
            for (net, t) in &self.ip_prefixes {
                if net.contains(&pkt.dst) && matches!(t, Target::YouTube) {
                    return Some(Target::YouTubeQuic);
                }
            }
            // Unknown destination → leave it alone. fall through.
        }
        // 3. Discord voice RTP shape
        if pkt.proto == crate::flow::L4Proto::Udp
            && self.is_discord_voice_port(pkt.dst_port)
            && (looks_like_discord_rtp(pkt.payload()) || looks_like_ip_discovery(pkt.payload()))
        {
            return Some(Target::DiscordVoice);
        }
        // 4. IP-prefix fallback
        for (net, t) in &self.ip_prefixes {
            if net.contains(&pkt.dst) {
                return Some(*t);
            }
        }
        // 5. Sticky inheritance
        flow.target
    }

    fn is_discord_voice_port(&self, port: u16) -> bool {
        self.discord_voice_udp_ports
            .iter()
            .any(|&(lo, hi)| port >= lo && port <= hi)
    }
}

/// Discord voice over RTP: V=2, payload type 120 (Opus).
///   byte0: 0x80 (no ext) or 0x90 (ext set)
///   byte1: 0x78 (PT 120) or 0xF8 (PT 120 + marker bit)
fn looks_like_discord_rtp(p: &[u8]) -> bool {
    p.len() >= 12 && (p[0] == 0x80 || p[0] == 0x90) && (p[1] == 0x78 || p[1] == 0xF8)
}

/// Discord IP-Discovery first datagram: 74 bytes, type=0x0001, length=0x0046.
fn looks_like_ip_discovery(p: &[u8]) -> bool {
    p.len() == 74 && p[0] == 0x00 && p[1] == 0x01 && p[2] == 0x00 && p[3] == 0x46
}
