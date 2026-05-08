# Third-party components

SonicDPI itself is dual-licensed under MIT OR Apache-2.0. The
following third-party components are bundled or required at runtime
and retain their original licenses.

## WinDivert (Windows backend)

- Component: `WinDivert64.sys` driver and `WinDivert.dll` user-mode library
- Upstream: https://reqrypt.org/windivert.html
- License: **LGPL-3.0** (driver also dual-licensed GPL-2.0)
- Bundled with: Windows binary releases of SonicDPI
- User rights under LGPL-3: you may replace `WinDivert.dll` with a
  modified copy and SonicDPI will continue to function. The driver
  binary is signed by Basil Futuriste — replacement requires a fresh
  Microsoft kernel-mode signature.

## Rust crates (build-time dependencies)

Permissive (MIT or Apache-2.0 or both):
- `windivert`, `windivert-sys` (Rubensei) — MIT/Apache-2.0
- `nfq` (nbdd0121) — MIT/Apache-2.0
- `etherparse` — MIT/Apache-2.0
- `nix` — MIT
- `libc` — MIT/Apache-2.0
- `socket2` — MIT/Apache-2.0
- `clap` — MIT/Apache-2.0
- `tracing`, `tracing-subscriber` — MIT
- `serde`, `serde_json`, `toml` — MIT/Apache-2.0
- `anyhow`, `thiserror` — MIT/Apache-2.0
- `parking_lot`, `crossbeam-channel`, `bytes`, `once_cell` — MIT/Apache-2.0
- `ctrlc` — MIT/Apache-2.0
- `caps` — MIT/Apache-2.0
- `ipnet` — MIT/Apache-2.0

Run `cargo deny check licenses` (CI) to verify no GPL leakage into
the SonicDPI binary itself.

## Reference research

The `docs/research-techniques-2026.md` file synthesizes prior art from
the open-source DPI-bypass community: zapret (bol-van), byedpi
(hufrea), GoodbyeDPI (ValdikSS), Flowseal/zapret-discord-youtube, and
the TSPU IMC '22 paper (Xue et al.). No code is copied — only the
documented techniques are referenced.
