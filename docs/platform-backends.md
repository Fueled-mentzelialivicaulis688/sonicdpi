# Platform backends

SonicDPI uses one packet-interception backend per OS, all behind the
same `Interceptor` trait in `sonicdpi-platform`. This file documents
what each backend depends on and the gotchas the user/installer must
handle.

## Windows — WinDivert

- Crate: `windivert` 0.6 (Rubensei fork) + `windivert-sys` 0.5.
- Driver: `WinDivert64.sys` ships next to the binary, signed by
  Basil Futuriste's EV cert (LGPL-3 redistributable).
- Layer: `WINDIVERT_LAYER_NETWORK` (not `_FORWARD`).
- Filter: `outbound and !loopback and (tcp.DstPort==443 or udp.DstPort==443 or (udp.DstPort >= 19294 and udp.DstPort <= 19344) or (udp.DstPort >= 50000 and udp.DstPort <= 50100))`
- Privilege: requires Administrator on first run (driver service install).
- Win 11 26H2 caveat: Smart App Control may quarantine an unsigned
  launcher; sign at least with an OV cert.

## Linux — NFQUEUE

- Crate: `nfq` 0.2 (pure-Rust; avoids GPL `libnetfilter_queue`).
- Hook: `output` chain at priority `-150` so we run before mangle.
- Default rules (nftables, IPv4+IPv6 via `inet` family):
  ```
  table inet sonicdpi {
      chain out {
          type filter hook output priority -150;
          tcp dport { 80, 443 } ct state new,established queue num 0 bypass
          udp dport 443 queue num 0 bypass
          udp dport 19294-19344 queue num 0 bypass
          udp dport 50000-50100 queue num 0 bypass
      }
  }
  ```
- Privilege: `CAP_NET_ADMIN`. Use `setcap cap_net_admin=eip` on the
  binary or `AmbientCapabilities=` in the systemd unit.
- `--queue-bypass` keeps connectivity if SonicDPI crashes.
- L4 checksum recomputation is **our** job (kernel only redoes IP).

## macOS — pf rdr-to + transparent proxy

`IPPROTO_DIVERT` was removed from XNU; `pf`'s `divert-to` is
half-broken on Sequoia/Tahoe per Apple dev forum reports. We follow
the zapret-mac / byedpi pattern: redirect traffic with `pf rdr-to`
to a local listener and act as a transparent TCP proxy.

- Anchor: `sonicdpi`. Loaded via `pfctl -a sonicdpi -f /etc/sonicdpi/pf.conf`.
- Rule:
  ```
  rdr on en0 inet  proto tcp from any to any port {80, 443} -> 127.0.0.1 port 7443
  rdr on en0 inet6 proto tcp from any to any port {80, 443} -> 127.0.0.1 port 7443
  ```
- Original destination retrieved via `DIOCNATLOOK` ioctl on `/dev/pf`.
- Privilege: requires root or `/dev/pf` rw access. Document `sudo`
  and ship a privileged helper for the GUI later (`SMJobBless`).
- Production path: package as `.app` with a NetworkExtension
  `NEFilterPacketProvider` once the Apple `com.apple.developer.networking.networkextension` entitlement is granted.
- **Voice (UDP) on macOS — limitation v0.1**: the rdr-to approach
  cannot relay UDP. macOS support in v0.1 is **TCP-only** (YouTube,
  Discord gateway). Discord voice on macOS will need either the
  NetworkExtension path or a TUN-based approach in a later release.

## Cross-platform parsing

`etherparse` 0.16 for IP/TCP/UDP slicing and checksum recomputation
(uses correct IPv6 pseudo-header). Avoid `pnet` for the hot path;
keep it for raw sending if needed.

## Threading model

Each backend runs in its own dedicated OS thread (recv is blocking
on all three platforms). Packets are passed to the engine through a
bounded `crossbeam-channel` (capacity 1024). The engine returns an
`Action` synchronously and the same thread re-injects. No async
runtime is required on the hot path.
