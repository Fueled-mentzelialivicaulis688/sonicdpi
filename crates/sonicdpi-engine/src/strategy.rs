//! Strategy pipeline.
//!
//! Each `Strategy` inspects a packet and may return an `Action`. The
//! first non-Pass result wins for that packet. Strategies are
//! stateless wrt the packet bytes — anything they need to remember
//! lives on the `Flow`.
//!
//! Concrete strategies match the primitives documented in
//! `docs/research-techniques-2026.md`.

use crate::action::{Action, FakePacket};
use crate::builder::{
    craft_fakes_for_tcp, craft_fakes_for_udp, craft_multidisorder, craft_multisplit_with_pattern,
    Crafted, FoolingKind,
};
#[allow(unused_imports)]
use crate::fakes::rewrite_sni_same_length;
use crate::flow::{Flow, L4Proto};
use crate::packet::Packet;
use crate::target::Target;
use crate::tls::{is_client_hello, is_quic_initial};

pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action>;
}

pub struct StrategyPipeline {
    chain: Vec<Box<dyn Strategy>>,
}

impl StrategyPipeline {
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }
    pub fn push<S: Strategy + 'static>(&mut self, s: S) {
        self.chain.push(Box::new(s));
    }
    pub fn run(&self, pkt: &mut Packet, flow: &mut Flow) -> Action {
        for s in &self.chain {
            if let Some(a) = s.apply(pkt, flow) {
                tracing::debug!(
                    strategy = s.name(),
                    target = ?flow.target,
                    dst = %pkt.dst,
                    dst_port = pkt.dst_port,
                    "strategy fired"
                );
                // Note: we do NOT increment a shared "modified" counter
                // here — that was a major bug. Each strategy fires on a
                // DIFFERENT packet kind in the connection lifecycle
                // (SYN for tcp_mss_clamp; ClientHello for tls_multisplit;
                // etc.). A shared counter caused MSS clamp on the SYN
                // to BLOCK the ClientHello-time desync from firing.
                // Each strategy now self-gates via flow.hello_seen
                // (for CH-time), flow.mss_clamped (for SYN-time), or
                // its own per-strategy condition.
                // Hex-dump first 96 bytes of each emitted packet at
                // trace level — invaluable for verifying our byte
                // output is actually correct on the wire (seq numbers,
                // checksums, TCP options preserved). Compare with a
                // pcap of working zapret to spot subtle bugs.
                match &a {
                    Action::InjectThenPass(fakes) | Action::Replace(fakes) => {
                        for (i, f) in fakes.iter().enumerate() {
                            let n = f.bytes.len().min(96);
                            let hex: String = f.bytes[..n]
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ");
                            tracing::debug!(
                                strategy = s.name(),
                                seg = i,
                                len = f.bytes.len(),
                                ttl = ?f.ttl_override,
                                hex = %hex,
                                "emit"
                            );
                        }
                    }
                    _ => {}
                }
                if !matches!(a, Action::Pass) {
                    flow.modified_count = flow.modified_count.saturating_add(1);
                }
                return a;
            }
        }
        Action::Pass
    }
}

impl Default for StrategyPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Fooling {
    Ttl(u8),
    Md5sig,
    Badseq,
    Badsum,
    Timestamp,
    TsMd5sig,
}

impl Fooling {
    pub(crate) fn to_kind(self) -> FoolingKind {
        match self {
            Fooling::Ttl(n) => FoolingKind::Ttl(n),
            Fooling::Md5sig => FoolingKind::Md5sig,
            Fooling::Badseq => FoolingKind::Badseq,
            Fooling::Badsum => FoolingKind::Badsum,
            Fooling::Timestamp => FoolingKind::Timestamp,
            Fooling::TsMd5sig => FoolingKind::TsMd5sig,
        }
    }
}

// ============================================================
//   TLS multisplit + seqovl (Flowseal-default, YouTube + Discord)
// ============================================================
pub struct TlsMultisplit {
    pub split_pos: usize,
    pub seqovl: u32,
    /// Bytes used as the seqovl-overlay pattern. A real-looking TLS
    /// ClientHello to a Russian-CDN host (Flowseal's
    /// `tls_clienthello_4pda_to.bin`-style) makes TSPU's
    /// first-write-wins reassembler classify the connection as
    /// benign. A single zero byte is the legacy fall-back.
    pub seqovl_pattern: Vec<u8>,
    /// Restrict to specific targets. Empty = applies to YT + both
    /// Discord families. Lets `build_pipeline` push multiple
    /// per-target TlsMultisplit instances with different seqovl /
    /// pattern (mirrors Flowseal `general.bat` having separate lines
    /// for `discord.media` (seqovl=681 + google) and the general
    /// list (seqovl=568 + 4pda.to)).
    pub target_filter: Vec<Target>,
}

impl Strategy for TlsMultisplit {
    fn name(&self) -> &'static str {
        "tls-multisplit"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        // Self-gate by hello_seen — fires once per flow on the
        // ClientHello packet. Don't gate on flow.modified_count
        // because SYN-time strategies (tcp_mss_clamp) increment that
        // before we ever see the CH on the same flow.
        if flow.hello_seen || pkt.proto != L4Proto::Tcp {
            return None;
        }
        if !is_client_hello(pkt.payload()) {
            return None;
        }
        let allowed: &[Target] = if self.target_filter.is_empty() {
            &[
                Target::YouTube,
                Target::DiscordGateway,
                Target::DiscordCloudflare,
            ]
        } else {
            &self.target_filter
        };
        let t = flow.target?;
        if !allowed.contains(&t) {
            return None;
        }
        flow.hello_seen = true;
        let segs =
            craft_multisplit_with_pattern(pkt, self.split_pos, self.seqovl, &self.seqovl_pattern)?;
        Some(Action::Replace(
            segs.into_iter().map(Crafted::into).collect(),
        ))
    }
}

// ============================================================
//   Fake + multidisorder (zapret-default, YouTube)
// ============================================================
pub struct FakeMultidisorder {
    pub fooling: Fooling,
    pub repeats: u8,
    pub fake_payload: Vec<u8>,
}

impl Strategy for FakeMultidisorder {
    fn name(&self) -> &'static str {
        "fake-multidisorder"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        // Self-gate by hello_seen — fires once per flow on the
        // ClientHello packet. Don't gate on flow.modified_count
        // because SYN-time strategies (tcp_mss_clamp) increment that
        // before we ever see the CH on the same flow.
        if flow.hello_seen || pkt.proto != L4Proto::Tcp {
            return None;
        }
        if !is_client_hello(pkt.payload()) {
            return None;
        }
        // Hostfakesplit-style: emit N fake CHs with benign-SNI +
        // TS PAWS fooling (server kernel drops them), then the real
        // CH passes through unmodified. Verbatim port of Flowseal
        // `general (ALT9).bat`. Applies to ALL TLS-target categories.
        if !matches!(
            flow.target,
            Some(Target::YouTube) | Some(Target::DiscordGateway) | Some(Target::DiscordCloudflare)
        ) {
            return None;
        }
        flow.hello_seen = true;
        let fakes = craft_fakes_for_tcp(
            pkt,
            &self.fake_payload,
            self.repeats,
            self.fooling.to_kind(),
        )?;
        Some(Action::InjectThenPass(
            fakes.into_iter().map(Crafted::into).collect(),
        ))
    }
}

// ============================================================
//   HostFakeSplit (defeats first-sight SNI matchers)
// ============================================================
pub struct HostFakeSplit {
    /// Pre-built decoy ClientHello bytes (self-contained, with SNI of
    /// `fake_host` baked in). Built at profile pipeline time via
    /// `embedded_or_synth_ch` so we don't need an in-place SNI rewrite
    /// of the real CH (which fails when fake_host length differs from
    /// real SNI length — `discord.com` 11B vs `ozon.ru` 7B etc).
    pub fake_payload: Vec<u8>,
    /// Restrict to specific targets. Empty = applies to YT + both
    /// Discord families (matches Flowseal `general (ALT9).bat` which
    /// uses hostfakesplit for the general list with `host=ozon.ru`).
    pub target_filter: Vec<Target>,
    /// Decoy CH count. Mirrors zapret `--dpi-desync-repeats`.
    pub repeats: u8,
    /// Fooling primitive applied to the decoys (TS / md5sig / etc).
    pub fooling: Fooling,
}

impl Strategy for HostFakeSplit {
    fn name(&self) -> &'static str {
        "hostfakesplit"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        // Self-gate by hello_seen — fires once per flow on the
        // ClientHello packet. Don't gate on flow.modified_count
        // because SYN-time strategies (tcp_mss_clamp) increment that
        // before we ever see the CH on the same flow.
        if flow.hello_seen || pkt.proto != L4Proto::Tcp {
            return None;
        }
        if !is_client_hello(pkt.payload()) {
            return None;
        }
        let allowed: &[Target] = if self.target_filter.is_empty() {
            &[
                Target::YouTube,
                Target::DiscordGateway,
                Target::DiscordCloudflare,
            ]
        } else {
            &self.target_filter
        };
        let t = flow.target?;
        if !allowed.contains(&t) {
            return None;
        }
        flow.hello_seen = true;

        // Emit `repeats` decoys of the pre-built fake ClientHello
        // (carries `fake_host` SNI, self-contained, length independent
        // of real CH) with the configured fooling (TS-PAWS / md5sig
        // / etc) so the server discards each at L4 while DPI commits
        // to the fake host. Then the original CH goes through
        // unmodified. Mirrors zapret `--dpi-desync=hostfakesplit
        //   --dpi-desync-repeats=N --dpi-desync-fooling=...
        //   --dpi-desync-hostfakesplit-mod=host=...` (ALT9 line 19/21).
        let payload = pkt.payload();
        let decoys = crate::builder::craft_fakes_for_tcp(
            pkt,
            &self.fake_payload,
            self.repeats,
            self.fooling.to_kind(),
        )?;
        let real_seg =
            crate::builder::build_tcp_segment(pkt, payload, 0, crate::builder::DEFAULT_TTL)?;

        let mut out: Vec<crate::action::FakePacket> = decoys.into_iter().map(Into::into).collect();
        out.push(crate::action::FakePacket {
            bytes: real_seg,
            ttl_override: None,
        });
        Some(Action::Replace(out))
    }
}

// ============================================================
//   TCP MSS clamp on SYN (Cloudflare 2026 mid-stream defeat)
// ============================================================
//
// TSPU added mid-stream HTTP/2 framing reassembly classifier in
// Q1-2026. Single-shot ClientHello desync is no longer enough:
// the classifier re-runs on the established connection and kills
// it after ~16-25 KB of payload — exactly when Discord's update
// binary download starts after the small manifest fetch.
//
// Counter-measure (per bol-van/zapret #1806, crayfos/mtproxy-setup,
// BypassCore 2026 comparison): clamp the MSS option in the
// outbound SYN to 536 bytes. The server's TCP stack will then send
// every subsequent data segment at ≤536 payload bytes. HTTP/2
// frame boundaries straddle TCP boundaries unpredictably ⇒ the
// classifier's reassembly buffer fragments mid-frame ⇒ pattern
// match fails ⇒ no mid-stream RST.
//
// Performance cost: ~3× more TCP segments per stream (1460 → 536
// payload). Acceptable for Discord update download; we gate by IP
// to avoid clamping YouTube/Google (which doesn't have this
// problem and where we WANT full-MTU speed).
pub struct TcpMssClamp {
    pub mss: u16,
    /// IP prefixes whose outbound SYNs get the clamp. Typically
    /// just Cloudflare's main range. Empty = clamp every SYN to
    /// our target ports (don't do that — it nukes throughput on
    /// every flow).
    pub target_prefixes: Vec<ipnet::IpNet>,
}

impl Strategy for TcpMssClamp {
    fn name(&self) -> &'static str {
        "tcp-mss-clamp"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        if pkt.proto != L4Proto::Tcp {
            return None;
        }
        // Self-gate so we don't re-clamp on TCP retransmits of the SYN.
        if flow.mss_clamped {
            return None;
        }
        // Only outbound SYNs (client → server, no ACK yet).
        if !pkt.is_tcp_syn() || pkt.is_tcp_ack() {
            return None;
        }
        if !matches!(pkt.direction, crate::flow::Direction::Outbound) {
            return None;
        }
        // Gate by destination IP — don't clamp YouTube/Google, only
        // Cloudflare-fronted Discord.
        if !self
            .target_prefixes
            .iter()
            .any(|net| net.contains(&pkt.dst))
        {
            return None;
        }

        // Clone the original SYN and rewrite the MSS option.
        let mut new_bytes = pkt.bytes.clone();
        crate::fooling::apply_mss_clamp(&mut new_bytes, self.mss)?;
        flow.mss_clamped = true;

        Some(Action::Replace(vec![FakePacket {
            bytes: new_bytes,
            ttl_override: None,
        }]))
    }
}

/// Helper for IpNet (which is Vec-friendly serde-able) — kept here
/// so consumers in profile.rs don't need to depend on ipnet directly
/// when they're already going through this module.
pub use ipnet::IpNet as MssClampNet;

// ============================================================
//   TLS multidisorder (out-of-order TCP segments)
// ============================================================
//
// Splits the ClientHello and emits TAIL-FIRST, HEAD-SECOND on the
// wire. Server's TCP reorders by seq and reassembles correctly.
// DPIs that greedily parse from the first-arriving byte stream see
// mid-record garbage, bail. Different reassembly attack surface
// than multisplit+seqovl — useful when the gentle multisplit is
// being detected on a particular ISP.
pub struct TlsMultidisorder {
    pub split_pos: usize,
}

impl Strategy for TlsMultidisorder {
    fn name(&self) -> &'static str {
        "tls-multidisorder"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        // Self-gate by hello_seen — fires once per flow on the
        // ClientHello packet. Don't gate on flow.modified_count
        // because SYN-time strategies (tcp_mss_clamp) increment that
        // before we ever see the CH on the same flow.
        if flow.hello_seen || pkt.proto != L4Proto::Tcp {
            return None;
        }
        if !is_client_hello(pkt.payload()) {
            return None;
        }
        // Same target gates as TlsMultisplit — applies to YouTube +
        // both Discord-direct AND Cloudflare-fronted (no fake burst,
        // CF tolerates this).
        if !matches!(
            flow.target,
            Some(Target::YouTube) | Some(Target::DiscordGateway) | Some(Target::DiscordCloudflare)
        ) {
            return None;
        }
        flow.hello_seen = true;
        let segs = craft_multidisorder(pkt, self.split_pos)?;
        Some(Action::Replace(
            segs.into_iter().map(Crafted::into).collect(),
        ))
    }
}

// ============================================================
//   FakeMultisplit — Flowseal ALT11 (Discord, May 2026)
// ============================================================
//
// Combined `fake + multisplit` desync in a single firing:
//   1. Inject N decoy ClientHello packets on the same 5-tuple,
//      with TCP-option fooling so the server discards them.
//   2. Split the real ClientHello into two segments where seg2's
//      seq overlaps seg1's tail by `seqovl` bytes, with the overlap
//      filled by the bytes of a (benign) Russian-CDN ClientHello
//      decoy.
//
// This is the recipe the active Russian Discord-bypass community
// converged on after TSPU hardened against pure `multisplit` and
// `badsum` fooling on Discord ASN. See ALT11.bat and ntc.party
// thread #13883. Use this for `Target::DiscordGateway`; for YouTube
// the simpler `tls_multisplit` still works.
pub struct FakeMultisplit {
    pub fooling: Fooling,
    pub repeats: u8,
    pub fake_payload: Vec<u8>,
    pub split_pos: usize,
    pub seqovl: u32,
    /// Targets this instance applies to. Empty = legacy hardcoded
    /// `DiscordGateway`-only behaviour for backward compat with
    /// pre-2026-05 ALT11 profiles. Non-empty = exact target gate.
    /// 2026-05: the default profile pushes one entry for
    /// `DiscordGateway` (heavy: repeats=6, fooling=ts) and a second
    /// for `DiscordCloudflare` (light: repeats=2, fooling=ttl=4,
    /// decoy=vk.me) so CF-edge rate-limit isn't tripped while TSPU
    /// still sees a vk.me-SNI fake CH first and locks the
    /// classifier on the whitelisted RU host.
    pub target_filter: Vec<Target>,
}

impl Strategy for FakeMultisplit {
    fn name(&self) -> &'static str {
        "fake-multisplit"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        // Self-gate by hello_seen — fires once per flow on the
        // ClientHello packet. Don't gate on flow.modified_count
        // because SYN-time strategies (tcp_mss_clamp) increment that
        // before we ever see the CH on the same flow.
        if flow.hello_seen || pkt.proto != L4Proto::Tcp {
            return None;
        }
        if !is_client_hello(pkt.payload()) {
            return None;
        }
        // Empty filter = legacy ALT11 hardcoded `DiscordGateway` gate.
        // Non-empty = use it; this is how the 2026-05 default attaches
        // a separate gentle CF entry (decoy=vk.me, repeats=2,
        // fooling=ttl=4) without touching the existing aggressive
        // gateway entry.
        let allowed: &[Target] = if self.target_filter.is_empty() {
            &[Target::DiscordGateway]
        } else {
            &self.target_filter
        };
        let t = flow.target?;
        if !allowed.contains(&t) {
            return None;
        }
        flow.hello_seen = true;

        // 1. Decoy packets — fake CH with TCP-option fooling so the
        //    server discards them at the kernel/TLS layer but the DPI
        //    accepts them as plausible flow data.
        let decoys = craft_fakes_for_tcp(
            pkt,
            &self.fake_payload,
            self.repeats,
            self.fooling.to_kind(),
        )?;

        // 2026-05: `split_pos == 0` is the sentinel for "decoy-only"
        // mode — emit fakes, let the real ClientHello flow through
        // untouched. Required for Cloudflare-fronted Discord, where
        // any split of the real CH (even gentle 1-byte split_pos=1)
        // is detected by CF's edge and the connection gets RST'd.
        // Pure decoy-with-TTL=4 (fake dies in transit, TSPU still
        // sees vk.me SNI first) is the only thing that survives CF.
        if self.split_pos == 0 {
            return Some(Action::InjectThenPass(
                decoys.into_iter().map(Crafted::into).collect(),
            ));
        }

        // 2. Multisplit with the same fake CH bytes used as the
        //    seqovl overlay pattern. Used by Discord-direct
        //    (Gateway) where the edge tolerates the split.
        let segs =
            craft_multisplit_with_pattern(pkt, self.split_pos, self.seqovl, &self.fake_payload)?;

        let mut out = Vec::with_capacity(decoys.len() + segs.len());
        out.extend(decoys);
        out.extend(segs);
        Some(Action::Replace(
            out.into_iter().map(Crafted::into).collect(),
        ))
    }
}

// ============================================================
//   QUIC fake-initial (YouTube QUIC)
// ============================================================
pub struct QuicFakeInitial {
    pub fake_initial: Vec<u8>,
    pub repeats: u8,
}

impl Strategy for QuicFakeInitial {
    fn name(&self) -> &'static str {
        "quic-fake-initial"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        if flow.hello_seen || pkt.proto != L4Proto::Udp {
            return None;
        }
        if !is_quic_initial(pkt.payload()) {
            return None;
        }
        if !matches!(flow.target, Some(Target::YouTubeQuic)) {
            return None;
        }
        flow.hello_seen = true;
        let fakes = craft_fakes_for_udp(pkt, &self.fake_initial, self.repeats, 4)?;
        Some(Action::InjectThenPass(
            fakes.into_iter().map(Crafted::into).collect(),
        ))
    }
}

// ============================================================
//   Discord voice prime (fake-discord + fake-stun)
// ============================================================
pub struct DiscordVoicePrime {
    pub fake_stun: Vec<u8>,
    pub fake_discord: Vec<u8>,
    pub repeats: u8,
    pub cutoff: u32,
}

impl Strategy for DiscordVoicePrime {
    fn name(&self) -> &'static str {
        "discord-voice-prime"
    }
    fn apply(&self, pkt: &mut Packet, flow: &mut Flow) -> Option<Action> {
        if pkt.proto != L4Proto::Udp {
            return None;
        }
        if !matches!(flow.target, Some(Target::DiscordVoice)) {
            return None;
        }
        if flow.packet_count > self.cutoff as u64 {
            // Voice cadence is 50pps — only desync the first N
            // datagrams of the call, not every frame.
            return None;
        }
        let mut fakes = Vec::with_capacity((self.repeats as usize) * 2);
        for _ in 0..self.repeats {
            if let Some(b) = crate::builder::build_udp_datagram(pkt, &self.fake_stun, 4) {
                fakes.push(crate::action::FakePacket {
                    bytes: b,
                    ttl_override: Some(4),
                });
            }
            if let Some(b) = crate::builder::build_udp_datagram(pkt, &self.fake_discord, 4) {
                fakes.push(crate::action::FakePacket {
                    bytes: b,
                    ttl_override: Some(4),
                });
            }
        }
        Some(Action::InjectThenPass(fakes))
    }
}
