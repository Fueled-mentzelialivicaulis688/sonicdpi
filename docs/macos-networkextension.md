# macOS NetworkExtension path (v0.4 plan)

The v0.2/v0.3 macOS backend uses `pf rdr-to` + a transparent TCP
proxy. It works for YouTube and the Discord control plane because
those are TCP/443. **It cannot intercept UDP**, which means Discord
voice and YouTube QUIC are not bypassed on macOS.

The only supported way to intercept UDP on modern macOS without root
+ kernel hacks is Apple's **NetworkExtension** framework, specifically
a **System Extension** packaged inside an `.app` bundle. This file
documents what that requires so a contributor can pick it up.

## Prerequisites

1. **Apple Developer Program membership** ($99/year). Free Apple ID
   accounts cannot sign System Extensions.
2. **`com.apple.developer.networking.networkextension`** entitlement,
   specifically the `packet-tunnel-provider` and/or
   `app-proxy-provider` and `content-filter-provider` capabilities.
   This entitlement is **manually granted by Apple Developer
   Relations** after a written request explaining the use case.
   Typical lead time: 2–6 weeks.
3. **Developer ID Application** signing certificate.
4. **Notarization** through Apple's notary service before
   distribution.

There is no way to short-circuit any of these for a public release.
A self-signed System Extension can be loaded for development on a
single machine after disabling SIP partially, but that is not a
viable distribution path.

## Architecture

```
sonicdpi.app/
├── Contents/
│   ├── Info.plist
│   ├── MacOS/
│   │   └── sonicdpi              # CLI host (Rust binary)
│   └── Library/
│       └── SystemExtensions/
│           └── org.sonicdpi.netext.systemextension/
│               ├── Contents/
│               │   ├── Info.plist
│               │   ├── MacOS/
│               │   │   └── netext   # Swift host that calls into Rust
│               │   └── _CodeSignature/
│               └── ...
```

The CLI ("host") activates the System Extension via
`OSSystemExtensionRequest.activationRequest`. The user gets a one-time
prompt in System Settings → Privacy & Security to allow the
extension. Once running, the extension lives in its own process under
`endpointsecurityd`, sandboxed.

Inside the extension we register an `NEFilterPacketProvider` that
receives every IP packet flowing through the system before it hits
the NIC. It returns a verdict (`allow`, `drop`) and can optionally
inject crafted packets via `NEPacket`. This is the macOS equivalent
of WinDivert.

## Bridging Rust into the Swift extension host

The cleanest pattern (used by Mullvad, Tailscale, etc.):

1. Build `sonicdpi-engine` + `sonicdpi-platform-mac-nex` (new crate)
   as a **staticlib** + **C-ABI**:

   ```toml
   [lib]
   crate-type = ["staticlib"]
   ```

2. Use `cbindgen` to produce a `sonicdpi.h` header with the four
   functions the Swift side needs:

   ```c
   void sonicdpi_init(const char *profile_toml);
   int  sonicdpi_handle_packet(const uint8_t *bytes, size_t len, int direction);
   void sonicdpi_get_fakes(uint8_t **out, size_t *out_len);
   void sonicdpi_free_fakes(uint8_t *p);
   ```

3. The Swift host:

   ```swift
   class FilterProvider: NEFilterPacketProvider {
       override func handle(_ context: NEFilterPacketContext,
                            packet: UnsafeRawPointer,
                            offset: Int,
                            length: Int) -> NEFilterPacketProviderVerdict {
           let verdict = sonicdpi_handle_packet(packet, length, /* outbound */ 1)
           if let fakes = collectFakes() {
               for f in fakes { self.injectPacket(f, direction: .outbound) }
           }
           return verdict == 0 ? .allow : .drop
       }
   }
   ```

4. The CLI host on first launch calls
   `OSSystemExtensionManager.shared.submitRequest(...)`. After approval
   it talks to the extension over `XPC` to push profile changes.

## Build pipeline

- Wrap with `cargo-bundle` (or a hand-rolled `xcodebuild` script) to
  produce the `.app`.
- `codesign --options runtime --entitlements sonicdpi.entitlements`.
- `xcrun notarytool submit sonicdpi.dmg`.
- `xcrun stapler staple sonicdpi.app`.

## Why we haven't built this yet

It is a multi-week effort gated on an Apple Developer account, the
entitlement application, and a Mac with full Xcode. None of that is
in scope for the current open-source skeleton. The architecture above
is the recommended path; PRs welcome from anyone with the
prerequisites.

Until then, **macOS support is TCP-only**: YouTube web/app and
Discord control plane work, but Discord voice and YouTube QUIC
require Linux or Windows.

## References

- [NetworkExtension – NEFilterPacketProvider](https://developer.apple.com/documentation/networkextension/nefilterpacketprovider)
- [System Extensions – Activation request](https://developer.apple.com/documentation/systemextensions)
- [Mullvad Mac architecture (worth studying)](https://github.com/mullvad/mullvadvpn-app/tree/main/macos)
- [Tailscale macOS NetworkExtension wrapper](https://github.com/tailscale/tailscale/tree/main/cmd/tailscaled-mac-app)
- [Apple's NetworkExtension entitlement request form](https://developer.apple.com/contact/request/networking-entitlement)
