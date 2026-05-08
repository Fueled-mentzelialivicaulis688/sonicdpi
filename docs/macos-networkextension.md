# macOS NetworkExtension backend

> Status: **scaffolded in main, awaiting Apple-side artifacts.** Code compiles, bundle structure ready, signing/notarize/Apple-entitlement steps are user-side.

## Why we need it

The v0.2 macOS interceptor (`crates/sonicdpi-platform/src/macos.rs`) is a transparent proxy gated by pf `rdr-to`. That gives us **TCP** for HTTPS-targets:

- ✅ YouTube TLS (port 443)
- ✅ Discord-Cloudflare (`discord.com`, `discordapp.{com,net}`, …)
- ✅ Discord-Gateway (`gateway.discord.gg`, `discord.media`)

But **UDP** is invisible to pf `rdr-to`. So:

- ❌ YouTube QUIC (UDP/443) — falls back to TCP-TLS, slower
- ❌ Discord voice (UDP `*.discord.media:19294-19344, 50000-50100`) — completely broken

`IPPROTO_DIVERT` is gone from XNU since macOS 10.15. `pf divert-to` is half-broken on Sequoia/Tahoe per Apple Developer Forum threads. The only remaining sanctioned path is `NetworkExtension`.

## What we shipped (v0.3-pre)

- **Rust core** — `crates/sonicdpi-macos-nex/`. Compiles into a universal `libsonicdpi_macos_nex.dylib` (arm64 + x86_64). Exposes a 4-function C-ABI: `init / process / take_modified / shutdown`.

- **Swift harness** — `macos-nex/Extension/PacketFilterProvider.swift`. Subclasses `NEFilterPacketProvider`, calls into Rust via `@_silgen_name` extern declarations.

- **Bundle layout** — `macos-nex/Extension/{Info.plist, Extension.entitlements}` and `macos-nex/HostApp/{Info.plist, HostApp.entitlements, HostAppMain.swift}`.

- **Build harness** — `macos-nex/Makefile`. `make build → sign → notarize → install` pipeline.

- **README** — `macos-nex/README.md` with the full Apple-side checklist.

## What's required from you (Apple side)

1. **Apple Developer Program** — $99/year, [developer.apple.com/programs](https://developer.apple.com/programs).
2. **Request the entitlement** `com.apple.developer.networking.networkextension`. This is a *hand-reviewed* entitlement — open the request at [developer.apple.com/contact/request/system-extension](https://developer.apple.com/contact/request/system-extension), describe the use case (open-source DPI-desync engine for specific hosts), wait 1–2 weeks for Apple's response.
3. **Developer ID Application certificate** (Xcode → Preferences → Accounts → Manage Certificates).
4. **App Group ID** — host app and the System Extension must share `group.com.bysonic.sonicdpi`.
5. **Notarization profile** — set up via `xcrun notarytool store-credentials`.

Without entitlement (#2), the System Extension simply will not load. There is no workaround that ships to end users.

## Build flow

From repo root:

```bash
# 1. Compile both Rust and Swift sides into a .app bundle.
cd macos-nex
make build
# -> build/SonicDPI.app  (unsigned — won't actually load yet)

# 2. Codesign with your Developer ID.
make sign DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"

# 3. Notarize for distribution outside the App Store.
make notarize

# 4. Install locally and launch the host app.
make install
```

After `make install`, open **System Settings → Privacy & Security → Security**, click **Allow** next to "System extension blocked." Without that click, the SX never starts.

## Where the engine plugs in

`crates/sonicdpi-macos-nex/src/ffi.rs::sonicdpi_nex_process` is the per-packet hook. It:

1. Wraps the incoming bytes in `sonicdpi_engine::Packet::parse(...)`.
2. Calls `Engine::handle(&mut pkt)`.
3. Translates `Action::{Pass, Drop, Replace, InjectThenPass}` into a `Verdict` code (`PASS / DROP / MODIFIED`).
4. If MODIFIED, stashes the new bytes in a Mutex-guarded buffer; Swift fetches them on the next call.

This is the **same engine** that runs inside `sonicdpi.exe` on Windows and inside the systemd service on Linux. No duplication, no per-OS strategy code — that was the point of having the platform layer separate.

## Known limitations of the current scaffold

- **Single replacement packet per input.** When a strategy emits a burst (e.g. `discord-voice-prime` sends 6+ STUN/Discord-shape fakes ahead of the real datagram), only the first is currently injected. Need to extend the FFI to expose a "take burst" call and have Swift use `packetFlow.writePackets(_:withProtocols:)` with the array. **Easy follow-up.**
- **No buffer recycling.** Every modified packet allocates a `Vec<u8>` and frees it. Fine at typical voice rates (~50 pps per RTP stream), watch if we extend to high-throughput targets.
- **No live profile reload.** `sonicdpi_nex_init` is one-shot; profile change requires SX restart. Will revisit when v0.4's adaptive harness lands.

## Why a System Extension and not a content filter

Apple has three packet-related extension types:

| Extension type | Per-packet visibility | Modify? | Verdict needs entitlement |
|---|---|---|---|
| `NEFilterDataProvider` | Stream-level only | No (allow/drop on flow) | No (built into Apple Mail/Safari/etc) |
| `NEFilterPacketProvider` | Per-packet bytes | Yes (drop + reinject) | **Yes** (`...packet-filter-provider-systemextension`) |
| `NEAppProxyProvider` | Whole connection | Yes (full proxy) | **Yes** (`...app-proxy-provider-systemextension`) |

We need byte-level modify on UDP packets to inject voice-prime fakes. Only `NEFilterPacketProvider` gives that. The trade-off: it's the **most-gated** Apple extension, the entitlement is the hardest to get, and the user has to click "Allow" once per install.

## Next milestones

Tracked in [issue #1](https://github.com/by-sonic/sonicdpi/issues/1):

- [ ] Burst-inject array support (currently single-packet).
- [ ] Validate against a real Discord voice call (live test, requires hardware + entitlement).
- [ ] Wire `discord_voice_prime` cutoff logic to the SX's per-flow state.
- [ ] Add CI matrix entry that compiles `sonicdpi-macos-nex` on macOS-latest (no signing — just compile-check).
