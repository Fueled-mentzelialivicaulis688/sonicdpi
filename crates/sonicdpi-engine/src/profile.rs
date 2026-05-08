//! Profiles — declarative configuration for which targets the engine
//! identifies and which strategies to run.
//!
//! Profiles can be loaded from a TOML file, picked from the built-in
//! presets, or composed programmatically.
//!
//! Default decoy payloads are *captured real packets* embedded via
//! `include_bytes!` (see `embedded_fakes.rs`). Synthetic builders in
//! `fakes.rs` remain available as fallback when an SNI host has no
//! captured equivalent on disk — but the synthetic CHs lack modern
//! TLS extensions (key_share, GREASE, ALPN, psk_key_exchange_modes)
//! and present a static fingerprint TSPU 2026 has been observed to
//! score as "junk decoy". Real captured `.bin` decoys give us a real
//! browser JA3 and pass DPI's "looks like a real browser" gate.

use crate::embedded_fakes::QUIC_INITIAL_GOOGLE;
use crate::fakes::{build_fake_clienthello, build_fake_quic_initial};
use crate::strategy::{
    DiscordVoicePrime, FakeMultidisorder, FakeMultisplit, Fooling, HostFakeSplit, QuicFakeInitial,
    StrategyPipeline, TcpMssClamp, TlsMultidisorder, TlsMultisplit,
};
use crate::target::{Target, TargetSet};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub targets: TargetSet,
    #[serde(default)]
    pub strategies: StrategyConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StrategyConfig {
    /// Clamps MSS=536 on outbound SYNs to specified IP prefixes.
    /// Defeats TSPU's 2026 mid-stream HTTP/2 reassembly classifier.
    pub tcp_mss_clamp: Option<TcpMssClampCfg>,
    /// Per-target multisplit configurations. Empty = no multisplit.
    /// Multiple entries push multiple `TlsMultisplit` instances into
    /// the pipeline, each gated on its own `targets` filter — mirrors
    /// Flowseal `general.bat` having distinct `--filter-tcp` lines for
    /// `discord.media` (seqovl=681 + google pattern) and the general
    /// list (seqovl=568 + 4pda.to pattern).
    #[serde(default)]
    pub tls_multisplit: Vec<TlsMultisplitCfg>,
    pub tls_multidisorder: Option<TlsMultidisorderCfg>,
    pub fake_multidisorder: Option<FakeMultidisorderCfg>,
    /// 2026-05: switched from `Option<>` to `Vec<>` so the default
    /// profile can push one entry per Discord target with
    /// per-target tuning (Gateway = heavy, CF = gentle vk.me).
    /// Backward-compatible because `#[serde(default)]` on the field
    /// turns a missing TOML section into an empty vec.
    #[serde(default)]
    pub fake_multisplit: Vec<FakeMultisplitCfg>,
    /// Per-target hostfakesplit configurations. Empty = no
    /// hostfakesplit. Multiple entries push multiple `HostFakeSplit`
    /// instances into the pipeline, each gated on its own `targets`
    /// filter — mirrors Flowseal `general (ALT9).bat` having distinct
    /// `--filter-tcp` lines for `discord.media` (host=www.google.com)
    /// and the general list (host=ozon.ru, fooling=ts,md5sig).
    #[serde(default)]
    pub host_fake_split: Vec<HostFakeSplitCfg>,
    pub quic_fake_initial: Option<QuicFakeInitialCfg>,
    pub discord_voice_prime: Option<DiscordVoicePrimeCfg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpMssClampCfg {
    pub mss: u16,
    /// CIDR prefixes (IPv4 or IPv6). SYNs to addresses outside these
    /// prefixes are NOT clamped — keeping full-MTU throughput on
    /// non-target traffic.
    pub target_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMultidisorderCfg {
    pub split_pos: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMultisplitCfg {
    pub split_pos: usize,
    pub seqovl: u32,
    /// Optional Russian-CDN SNI baked into a fake ClientHello whose
    /// bytes fill the seqovl overlap region. When the DPI reassembles
    /// (first-write-wins) it sees benign-looking TLS to a domestic
    /// host and stops scrutinising. Mirrors Flowseal's
    /// `--dpi-desync-split-seqovl-pattern=tls_clienthello_4pda_to.bin`.
    /// When None, falls back to `fake_filler_byte`.
    #[serde(default)]
    pub seqovl_decoy_host: Option<String>,
    /// Legacy: byte to fill seqovl region with when `seqovl_decoy_host`
    /// is None. Default 0x00.
    #[serde(default)]
    pub fake_filler_byte: u8,
    /// Targets this multisplit applies to. Empty = YT + both Discord
    /// (legacy behaviour). Use to express per-target seqovl/pattern.
    #[serde(default)]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeMultidisorderCfg {
    pub fooling: String, // "md5sig" | "badseq" | "ttl=N" | "badsum" | "ts" | "ts,md5sig"
    pub repeats: u8,
    /// Optional path to a custom fake CH (.bin). Default: in-code generator.
    pub fake_payload_path: Option<String>,
    /// SNI host placed inside the in-code generated decoy.
    #[serde(default = "default_decoy_host")]
    pub decoy_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeMultisplitCfg {
    /// "ts" recommended (Flowseal ALT11). TSPU has hardened against
    /// `badsum` on the Discord ASN per ntc.party #13883.
    /// "ttl=4" recommended for CF-edge entries — the fake dies in
    /// transit so CF only sees the real CH and rate-limit isn't
    /// tripped, while TSPU still sees the fake first.
    pub fooling: String,
    pub repeats: u8,
    /// SNI baked into the in-code generated decoy ClientHello.
    /// 2026-05: `vk.me` is the current TSPU whitelist hit
    /// (Flowseal v4.5+, 08.01.2026); `max.ru` was the v4.4 default
    /// and still works on most ISPs as a fallback.
    #[serde(default = "default_ru_decoy_host")]
    pub decoy_host: String,
    pub split_pos: usize,
    pub seqovl: u32,
    /// Targets this entry applies to. Empty = legacy hardcoded
    /// `DiscordGateway` only.
    #[serde(default)]
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFakeSplitCfg {
    pub fake_host: String,
    /// Targets this hostfakesplit applies to. Empty = all 3.
    #[serde(default)]
    pub targets: Vec<Target>,
    /// Number of decoy ClientHellos with the renamed SNI emitted
    /// before the real one. Mirrors zapret `--dpi-desync-repeats`.
    /// 4 = ALT9 default; raise if TSPU classifier is sticky.
    #[serde(default = "default_hfs_repeats")]
    pub repeats: u8,
    /// Fooling applied to the decoys. Recognised: `ts`, `md5sig`,
    /// `ts,md5sig`, `badseq`, `badsum`, `ttl=N`. ALT9 uses `ts` for
    /// Discord-direct/YouTube and `ts,md5sig` for the general/CF list.
    #[serde(default = "default_hfs_fooling")]
    pub fooling: String,
}

fn default_hfs_repeats() -> u8 {
    4
}
fn default_hfs_fooling() -> String {
    "ts".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicFakeInitialCfg {
    pub repeats: u8,
    pub fake_initial_path: Option<String>,
    #[serde(default = "default_decoy_host")]
    pub decoy_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordVoicePrimeCfg {
    pub repeats: u8,
    pub cutoff: u32,
    pub fake_stun_path: Option<String>,
    pub fake_discord_path: Option<String>,
}

fn default_decoy_host() -> String {
    "www.google.com".to_string()
}

/// Russian-CDN SNI for decoys aimed at TSPU. Flowseal v4.5
/// (08.01.2026) switched canonical decoy `max.ru → vk.me`,
/// but field reports on ER-Telecom (AS9049) and several other
/// regional ISPs in May 2026 confirm `vk.me` was rotated out of
/// the TSPU classifier whitelist there while `max.ru` stayed in.
/// `max.ru` is the safer cross-region default; `vk.me` and
/// `4pda.to` are still good backups depending on the ISP.
fn default_ru_decoy_host() -> String {
    "max.ru".to_string()
}

impl Profile {
    pub fn build_pipeline(&self) -> StrategyPipeline {
        let mut p = StrategyPipeline::new();
        // MSS clamp must run FIRST — it operates on SYN, before any
        // ClientHello-targeting strategy can fire.
        if let Some(c) = &self.strategies.tcp_mss_clamp {
            let nets: Vec<IpNet> = c
                .target_prefixes
                .iter()
                .filter_map(|s| IpNet::from_str(s).ok())
                .collect();
            p.push(TcpMssClamp {
                mss: c.mss,
                target_prefixes: nets,
            });
        }
        // ORDER MATTERS — first-match-wins per packet. Aggressive
        // strategies (FakeMultisplit ALT11) come before gentler ones
        // (TlsMultisplit) so an aggressive profile can override a
        // gentle one when both are pushed.
        // 2026-05: Vec instead of Option — the default profile pushes
        // multiple per-target entries (Gateway-aggressive,
        // CF-gentle-vk.me) so the pipeline auto-selects the right
        // recipe per classified target without profile switching.
        for c in &self.strategies.fake_multisplit {
            let fake = embedded_or_synth_ch(&c.decoy_host);
            p.push(FakeMultisplit {
                fooling: parse_fooling(&c.fooling),
                repeats: c.repeats,
                fake_payload: fake,
                split_pos: c.split_pos,
                seqovl: c.seqovl,
                target_filter: c.targets.clone(),
            });
        }
        if let Some(c) = &self.strategies.fake_multidisorder {
            let fake = load_or_build(c.fake_payload_path.as_deref(), || {
                embedded_or_synth_ch(&c.decoy_host)
            });
            p.push(FakeMultidisorder {
                fooling: parse_fooling(&c.fooling),
                repeats: c.repeats,
                fake_payload: fake,
            });
        }
        // Per-target multisplit entries — push each one as its own
        // pipeline strategy. Each gates on its `targets` filter so
        // they don't conflict.
        for c in &self.strategies.tls_multisplit {
            let pattern = c
                .seqovl_decoy_host
                .as_deref()
                .map(embedded_or_synth_ch)
                .unwrap_or_else(|| vec![c.fake_filler_byte]);
            p.push(TlsMultisplit {
                split_pos: c.split_pos,
                seqovl: c.seqovl,
                seqovl_pattern: pattern,
                target_filter: c.targets.clone(),
            });
        }
        if let Some(c) = &self.strategies.tls_multidisorder {
            p.push(TlsMultidisorder {
                split_pos: c.split_pos,
            });
        }
        for c in &self.strategies.host_fake_split {
            p.push(HostFakeSplit {
                fake_payload: embedded_or_synth_ch(&c.fake_host),
                target_filter: c.targets.clone(),
                repeats: c.repeats,
                fooling: parse_fooling(&c.fooling),
            });
        }
        if let Some(c) = &self.strategies.quic_fake_initial {
            let fake = load_or_build(c.fake_initial_path.as_deref(), || {
                embedded_or_synth_quic(&c.decoy_host)
            });
            p.push(QuicFakeInitial {
                repeats: c.repeats,
                fake_initial: fake,
            });
        }
        if let Some(c) = &self.strategies.discord_voice_prime {
            // 2026-05: Flowseal v4.4 (24.12.2025) swapped the
            // `fake-discord` and `fake-stun` decoys from raw 0x00 /
            // dbankcloud-QUIC to the captured Google QUIC Initial,
            // and v4.6 (13.02.2026) keeps it. The dbankcloud variant
            // stopped passing TSPU around autumn 2025 — RU-bank
            // QUIC isn't whitelisted the way it used to be. Custom
            // paths override; pass `fake_stun_path` / `fake_discord_path`
            // in the profile to opt out.
            let fake_stun = load_or_build(c.fake_stun_path.as_deref(), || {
                QUIC_INITIAL_GOOGLE.to_vec()
            });
            let fake_discord = load_or_build(c.fake_discord_path.as_deref(), || {
                QUIC_INITIAL_GOOGLE.to_vec()
            });
            p.push(DiscordVoicePrime {
                repeats: c.repeats,
                cutoff: c.cutoff,
                fake_stun,
                fake_discord,
            });
        }
        p
    }

    /// Built-in preset: `youtube-discord` — port of Flowseal
    /// `general (Dronatar) v4.6` (13.02.2026), trimmed to what the
    /// current engine can express. This is the recommended default
    /// for Russian residential ISPs as of May 2026.
    ///
    /// Strategy chain (per-target):
    ///   - **YouTube TLS/443**: `multisplit` seqovl=681 with embedded
    ///     `tls_clienthello_www_google_com.bin` as the seqovl pattern.
    ///     Flowseal v4.5+ switched this lane to `multidisorder`; we
    ///     keep `multisplit` because the engine doesn't yet emit
    ///     out-of-order TLS-segment bursts. See
    ///     `docs/2026-05-status.md` for the v0.3 gap list.
    ///   - **DiscordGateway (discord.media etc.) TLS**: same params.
    ///   - **DiscordCloudflare (discord.com, discordapp.{com,net},
    ///     etc.)**: `multisplit` seqovl=568 with embedded
    ///     `tls_clienthello_4pda_to.bin` pattern — TSPU classifies
    ///     these CF-fronted hosts under the general lane.
    ///   - **YouTube QUIC/UDP/443**: `fake` repeats=11 (bumped from
    ///     6 in v4.4, 24.12.2025; current TSPU drops short bursts)
    ///     with embedded `quic_initial_www_google_com.bin`.
    ///   - **Discord voice (UDP 19294-19344, 50000-50032)**:
    ///     fake-stun + fake-discord both = embedded
    ///     `quic_initial_www_google_com.bin`. The dbankcloud-QUIC
    ///     decoy (used through autumn 2025) stopped passing — TSPU
    ///     no longer whitelists RU-bank QUIC the way it used to.
    ///
    /// MSS-clamp / kill-rst / ALT11 fake_multisplit are NOT in default —
    /// they live in alt profiles.
    ///
    /// **What this profile cannot yet do** (engine work for v0.3):
    /// `fake-tls-mod=rnd,dupsid,sni=vk.me`, `badseq-increment` /
    /// `badack-increment` knobs, `multidisorder` for real (non-fake)
    /// TLS, the HTTP/80 `fake-http` lane, `syndata` for Cloudflare
    /// WARP, and Discord's wide TCP port set (2053/2083/2087/2096/8443).
    /// All tracked in `docs/2026-05-status.md`.
    pub fn builtin_youtube_discord() -> Self {
        // 2026-05-08: rebuilt from sweep.ps1 results (89 configs tested
        // against discord.com / gateway.discord.gg / dl.discordapp.net /
        // www.youtube.com on the user's residential RU ISP). Only
        // `fake_multidisorder` with `fooling=badseq` survived. Every
        // hostfakesplit / fake_multisplit / tls_multisplit variant lost.
        // Decoy host irrelevant for this primitive — ozon.ru / vk.me /
        // max.ru / 4pda.to all scored 4/4. Picked ozon.ru to match the
        // Flowseal ALT9 line-21 conceptual choice (RU e-commerce).
        //
        // Why `badseq` and not `ts`: TSPU on this ISP stopped dropping
        // server-bound decoys with TSval=1 (PAWS), so TS-foolied decoys
        // now reach the server's TLS layer, get rejected with TLS
        // Alert/RST, and the real CH connection breaks. `badseq`
        // (out-of-window TCP seq) is still silently dropped at the
        // server's L4 — server never RSTs the flow, real CH proceeds.
        //
        // QUIC + voice unchanged from prior recipe.
        Self {
            name: "youtube-discord".into(),
            targets: default_target_set(),
            strategies: StrategyConfig {
                tcp_mss_clamp: None,
                tls_multidisorder: None,
                tls_multisplit: vec![],
                fake_multidisorder: Some(FakeMultidisorderCfg {
                    fooling: "badseq".into(),
                    repeats: 4,
                    fake_payload_path: None,
                    decoy_host: "ozon.ru".into(),
                }),
                fake_multisplit: vec![],
                host_fake_split: vec![],
                quic_fake_initial: Some(QuicFakeInitialCfg {
                    // ALT9 line 17/22: --dpi-desync=fake --dpi-desync-repeats=6
                    // with quic_initial_www_google_com.bin.
                    repeats: 6,
                    fake_initial_path: None,
                    decoy_host: default_decoy_host(),
                }),
                discord_voice_prime: Some(DiscordVoicePrimeCfg {
                    repeats: 6,
                    cutoff: 4,
                    fake_stun_path: None,
                    fake_discord_path: None,
                }),
            },
        }
    }

    /// Aggressive ALT11 preset for Discord — only useful if the
    /// default fails. Adds the fake+multisplit combo on Discord-direct
    /// (NOT Cloudflare, which rate-limits the burst). The default
    /// already includes a CF-gentle entry, so this profile keeps it
    /// AND adds an aggressive Gateway entry on top.
    pub fn builtin_aggressive() -> Self {
        let mut p = Self::builtin_youtube_discord();
        p.name = "youtube-discord-aggressive".into();
        p.strategies.fake_multisplit.push(FakeMultisplitCfg {
            fooling: "ts".into(),
            repeats: 6,
            decoy_host: default_ru_decoy_host(),
            split_pos: 1,
            seqovl: 664,
            targets: vec![Target::DiscordGateway],
        });
        p
    }

    /// Alias preset — kept for compatibility with CLI/tray menu
    /// callers that select `youtube-discord-seqovl`. After the
    /// May-2026 refactor the default profile IS the seqovl recipe,
    /// so this just returns the default.
    pub fn builtin_alt_seqovl() -> Self {
        let mut p = Self::builtin_youtube_discord();
        p.name = "youtube-discord-seqovl".into();
        p
    }

    /// ALT9-equivalent — `hostfakesplit` with `host=ozon.ru` + ts
    /// PAWS fooling on TLS-target connections. Use when the default
    /// `multisplit + seqovl` recipe is detected on a particular ISP.
    /// Mirrors Flowseal `general (ALT9).bat` lines 21+23.
    pub fn builtin_alt_hostfakesplit() -> Self {
        let mut p = Self::builtin_youtube_discord();
        p.name = "youtube-discord-hostfakesplit".into();
        p.strategies.tls_multisplit.clear();
        p.strategies.host_fake_split = vec![HostFakeSplitCfg {
            fake_host: "ozon.ru".into(),
            // Empty targets = applies to YT + both Discord families.
            targets: vec![],
            repeats: 4,
            fooling: "ts".into(),
        }];
        p
    }

    /// Multidisorder alternative — same target coverage as default
    /// but uses out-of-order TCP segment emission instead of seqovl
    /// pattern overlay. Different DPI-reassembly attack surface;
    /// useful when default's seqovl approach is detected on a
    /// particular ISP.
    pub fn builtin_multidisorder() -> Self {
        let mut p = Self::builtin_youtube_discord();
        p.name = "youtube-discord-multidisorder".into();
        p.strategies.tls_multisplit.clear();
        p.strategies.tls_multidisorder = Some(TlsMultidisorderCfg { split_pos: 1 });
        p
    }
}

fn parse_fooling(s: &str) -> Fooling {
    if let Some(n) = s.strip_prefix("ttl=") {
        if let Ok(v) = n.parse::<u8>() {
            return Fooling::Ttl(v);
        }
    }
    // Multi-fooling combos. Order-insensitive but only the documented
    // combos are recognized. Add more as needed.
    let lower = s.to_ascii_lowercase().replace(' ', "");
    if matches!(
        lower.as_str(),
        "ts,md5sig" | "md5sig,ts" | "ts+md5sig" | "md5sig+ts"
    ) {
        return Fooling::TsMd5sig;
    }
    match s {
        "md5sig" => Fooling::Md5sig,
        "badseq" => Fooling::Badseq,
        "badsum" => Fooling::Badsum,
        "ts" | "timestamp" => Fooling::Timestamp,
        _ => Fooling::Ttl(4),
    }
}

fn load_or_build<F: FnOnce() -> Vec<u8>>(path: Option<&str>, default: F) -> Vec<u8> {
    if let Some(p) = path {
        match std::fs::read(p) {
            Ok(b) => return b,
            Err(e) => {
                tracing::warn!(path = p, error = %e, "fake-payload load failed; using built-in generator")
            }
        }
    }
    default()
}

/// Prefer a captured real ClientHello if we have one for the host;
/// otherwise synthesize via `fakes::build_fake_clienthello`. This is
/// the central decoy-resolution path — using it everywhere ensures
/// "decoy_host=4pda.to" actually means the embedded `.bin`, not a
/// mocked-up synthetic.
fn embedded_or_synth_ch(host: &str) -> Vec<u8> {
    if let Some(b) = crate::embedded_fakes::lookup_tls_ch(host) {
        return b.to_vec();
    }
    build_fake_clienthello(host)
}

/// Same idea for QUIC Initial — captured-first.
fn embedded_or_synth_quic(host: &str) -> Vec<u8> {
    if let Some(b) = crate::embedded_fakes::lookup_quic_initial(host) {
        return b.to_vec();
    }
    build_fake_quic_initial(host)
}

fn default_target_set() -> TargetSet {
    TargetSet {
        // The full Discord brand-domain family is matched. RU TSPU
        // (post-2025-03-20) SNI-blocks every host in this set,
        // including the splash-gating `updates.discord.com`. Earlier
        // versions of SonicDPI excluded these hoping to avoid breaking
        // the updater — that was exactly inverted: not desyncing them
        // is what caused the "Checking for updates..." infinite hang.
        // See docs/research-techniques-2026.md and Flowseal ALT11.
        sni_patterns: vec![
            ("googlevideo.com".into(), Target::YouTube),
            ("youtube.com".into(), Target::YouTube),
            ("ytimg.com".into(), Target::YouTube),
            ("ggpht.com".into(), Target::YouTube),
            ("googleusercontent.com".into(), Target::YouTube),
            ("youtu.be".into(), Target::YouTube),
            ("googleapis.com".into(), Target::YouTube),
            // Discord brand domains, split by CDN:
            //
            // DiscordGateway (Discord-direct, AS49544): more permissive
            // edge, accepts ALT11 fake+multisplit when needed.
            //   discord.gg            → gateway.discord.gg (control WSS)
            //   discord.media         → *.discord.media (voice signaling)
            //
            // DiscordCloudflare (CF-fronted, AS13335): strict edge,
            // rate-limits 6+ rapid TLS attempts. Only gentle multisplit.
            //   discord.com           → web + api + updates.discord.com
            //   discordapp.com        → cdn.discordapp.com
            //   discordapp.net        → media.discordapp.net + dl.discordapp.net
            ("discord.gg".into(), Target::DiscordGateway),
            ("discord.media".into(), Target::DiscordGateway),
            ("discord.com".into(), Target::DiscordCloudflare),
            ("discordapp.com".into(), Target::DiscordCloudflare),
            ("discordapp.net".into(), Target::DiscordCloudflare),
            // Full Discord brand-domain family ported from Flowseal
            // ALT9's lists/list-general.txt — the updater, status,
            // CDN, and auxiliary services all hit these hosts during
            // splash, and TSPU SNI-blocks every one. Without coverage
            // here the client hangs on "Checking for updates...".
            ("discord.app".into(), Target::DiscordCloudflare),
            ("discord.co".into(), Target::DiscordCloudflare),
            ("discord.dev".into(), Target::DiscordCloudflare),
            ("discord.design".into(), Target::DiscordCloudflare),
            ("discord.gift".into(), Target::DiscordCloudflare),
            ("discord.gifts".into(), Target::DiscordCloudflare),
            ("discord.new".into(), Target::DiscordCloudflare),
            ("discord.store".into(), Target::DiscordCloudflare),
            ("discord.status".into(), Target::DiscordCloudflare),
            ("discord-activities.com".into(), Target::DiscordCloudflare),
            ("discordactivities.com".into(), Target::DiscordCloudflare),
            ("discordcdn.com".into(), Target::DiscordCloudflare),
            ("discordmerch.com".into(), Target::DiscordCloudflare),
            ("discordpartygames.com".into(), Target::DiscordCloudflare),
            ("discordsays.com".into(), Target::DiscordCloudflare),
            ("discordsez.com".into(), Target::DiscordCloudflare),
            ("discordstatus.com".into(), Target::DiscordCloudflare),
            ("dis.gd".into(), Target::DiscordCloudflare),
        ],
        ip_prefixes: vec![],
        discord_voice_udp_ports: vec![(19294, 19344), (50000, 50100)],
    }
}
