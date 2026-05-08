# DPI evasion techniques — operational reference (2025–2026)

Snapshot of what is currently effective against TSPU and similar
stateful DPI deployments, captured 2026-05-07. Treat as a living
document; per-ISP variation is the norm.

## Threat model

TSPU in 2025–2026 is **stateful per-flow**, performs full TLS
reassembly before SNI inspection, and reached IPv6 parity. Plain
ClientHello fragmentation alone no longer works. Effective evasion
manipulates flow state in ways the DPI's state machine
mis-interprets while the server's stack resolves correctly.

YouTube enforcement is dominantly **throttling** (`*.googlevideo.com`).
Discord enforcement is hard **block** of both control plane
(`*.discord.com`, `*.discord.gg`, `*.discord.media`) and media plane
(UDP voice 19294–19344 and 50000–50100).

## Working primitives

| # | Name | Mechanism | Targets |
|---|---|---|---|
| 1 | `fake` + fooling (md5sig / badseq / badsum / ts / autottl) | Decoy ClientHello DPI accepts but server discards | YT TCP, Discord TCP |
| 2 | `multisplit` + `split-seqovl=N` | TCP segments with overlapping seq; server resolves to real, DPI to fake | YT TCP (Flowseal default seqovl=568) |
| 3 | `fake,multidisorder` `split-pos=1,midsld` | Out-of-order segments, fake first, real later | YT TCP (zapret default) |
| 4 | `fakedsplit` / `fakeddisorder` | Mix fake + real segments forward / reverse | YT TCP, Discord TCP |
| 5 | `hostfakesplit` | Rewrite SNI label with same-length random host, then send real | YT TCP, Discord TCP (defeats first-sight SNI matchers) |
| 6 | `oob` / `disoob` | TCP urgent byte mid-handshake | Mod-only |
| 7 | `tlsrec` | Wrap ClientHello in two TLS records | Modifier-only (dead alone) |
| 8 | `mod-http` (host casing/spaces) | Plain-HTTP host header munging | HTTP/80 fallback |
| 9 | IPv6 `hopbyhop` / `destopt` | HBH header before TCP | Narrowed by 2026 |
| 10 | `fake` + `fake-quic` + `repeats=6` | Decoy QUIC Initials with fake SNI | YT QUIC |
| 11 | `udplen` | Length-pad UDP datagrams | STUN, voice |
| 12 | `ipfrag2` | IP-level UDP fragmentation | Voice fallback |
| 13 | `fake-discord` + `fake-stun` + `repeats=6` | Pre-prime DPI classifier with unparsable plausible packet | Discord voice |
| 14 | `syndata` | Push payload bytes inside SYN | TCP state-confusion |
| 15 | `synack` | Fake SYN-ACK from client | TCP state-confusion |

## Recommended starting profiles

**YouTube TCP/443 — primary** (zapret default)
```
fake,multidisorder
split-pos=1,midsld
fooling=md5sig
repeats=6
fake-payload=tls_clienthello_www_google_com.bin
```

**YouTube TCP/443 — ALT (md5sig filtered)** (Flowseal current default)
```
multisplit
split-seqovl=568
split-pos=1
```

**YouTube QUIC/443**
```
fake
fake-quic=quic_initial_www_google_com.bin
repeats=6
```

**Discord gateway TCP** (443, 2053, 2083, 2087, 2096, 8443)
```
fake,fakedsplit
fooling=ts
repeats=6
fake=tls_clienthello_www_google_com.bin
fakedsplit-pattern=0x00
```

**Discord voice UDP** (19294–19344, 50000–50100)
```
filter-l7=discord,stun
fake
fake-discord
fake-stun
repeats=6
fallback: fake any-protocol cutoff=n2
```

**Probing ladder**: ship `general`, `ALT-md5sig`, `ALT-badseq`,
`ALT-hostfakesplit`, `ALT-seqovl-only`. Round-robin starting from
lowest side-effect.

## Known not-working / patched

- Plain ClientHello fragmentation alone — DPI does full reassembly.
- Single-`fake` QUIC w/o repeats — regressed in zapret 72.5.
- Hostlist-by-SNI for UDP — UDP voice has no SNI.
- `preset_russia` removed; Flowseal-style external strategy bundles
  are the new packaging norm.
- iptables hooks degrading on Linux 6.17+; use nftables.
- Chrome Kyber-PQ inflates ClientHello past 1 MTU; some splits break.
- TSPU correlates TCP retransmissions; keep `repeats ≤ 11`.
- IPv6 `hopbyhop` was a freebie through 2024, narrowed in 2026.

## Authoritative references

- https://github.com/bol-van/zapret — canonical engine
- https://github.com/bol-van/zapret2 — successor branch
- https://github.com/Flowseal/zapret-discord-youtube — current Win RU profile
- https://github.com/Flowseal/zapret-discord-youtube/blob/main/general.bat
- https://github.com/StressOzz/Zapret-Manager/blob/main/Strategies_For_Youtube.md — Yv01–Yv25 matrix
- https://github.com/hufrea/byedpi — userspace SOCKS proxy
- https://github.com/hufrea/byedpi/blob/main/desync.c — primitive impls
- https://github.com/ValdikSS/GoodbyeDPI — Windows reference
- https://ensa.fi/papers/tspu-imc22.pdf — Xue et al. TSPU IMC '22
- https://github.com/bol-van/zapret/discussions/1716 — "what's new"
- https://github.com/bol-van/zapret/discussions/2013 — QUIC 72.5 regression
- https://github.com/bol-van/zapret/discussions/456 — Discord UDP

## Endpoint inventory

### YouTube
| Hostname pattern | Protocol | Port | Notes |
|---|---|---|---|
| `*.googlevideo.com` | TLS/TCP + QUIC/UDP | 443 | The throttled video CDN |
| `youtube.com`, `*.youtube.com` | TLS/TCP + QUIC | 443 | Web/app control |
| `youtubei.googleapis.com` | TLS/TCP + QUIC | 443 | API |
| `*.ytimg.com`, `yt3.ggpht.com` | TLS/TCP + QUIC | 443 | Images |

### Discord
| Hostname pattern | Protocol | Port | Notes |
|---|---|---|---|
| `discord.com`, `discord.gg` | TLS/TCP | 443 | Web + API |
| `gateway.discord.gg` | WSS/TLS/TCP | 443 | Real-time control plane |
| `cdn.discordapp.com`, `media.discordapp.net` | TLS/TCP | 443 | CDN |
| `*.discord.media` | WSS/TLS/TCP | 443 | Voice signaling |
| (IP from Voice Op2 Ready) | UDP RTP/SRTP | 19294–19344, 50000–50100 | Voice media |

**Discord voice RTP wire shape** (per RFC 3550 + Discord Opus):
```
byte 0: 0x80 (V=2, no padding/ext/CC) or 0x90 (ext set)
byte 1: 0x78 = PT 120 (Opus); 0xF8 with marker bit
bytes 2..3:  seq
bytes 4..7:  timestamp
bytes 8..11: SSRC
bytes 12+:   encrypted Opus (Salsa20 / XChaCha20-Poly1305; DAVE-AEAD post-2026-03)
```

First UDP datagram is **IP Discovery**: 74 bytes, starts `0x00 0x01 0x00 0x46`.

### Detection stack
1. Per-TCP-flow: parse first segment → TLS ClientHello → SNI lookup.
2. Per-UDP-packet: `is_quic_initial()` → QUIC SNI parse; else
   `dst_port ∈ {19294..=19344, 50000..=50100} && byte0 ∈ {0x80,0x90} && byte1 ∈ {0x78,0xF8}` → Discord RTP.
3. DNS sidecar: passive `(dst_ip → SNI)` cache for googlevideo flows.
4. IP-set lookup for Discord ASN AS49544 + Cloudflare AS13335
   (Discord-tagged 162.159.135.0/24 etc.) for fallback.
