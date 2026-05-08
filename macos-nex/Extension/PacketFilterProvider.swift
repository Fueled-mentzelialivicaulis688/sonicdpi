// PacketFilterProvider.swift
// SonicDPI — NEFilterPacketProvider subclass.
//
// Apple's NetworkExtension framework gates per-packet inspect+modify
// behind System Extensions. This file is the Swift harness that the
// .systemextension bundle exports as its principal class. All packet
// logic is delegated to the Rust core via libsonicdpi_macos_nex.dylib.

import Foundation
import NetworkExtension
import os.log

/// Verdict codes — must match `sonicdpi_macos_nex::ffi::Verdict`.
@_silgen_name("sonicdpi_nex_init")
func sonicdpi_nex_init(_ name: UnsafePointer<UInt8>, _ len: Int) -> Int32

@_silgen_name("sonicdpi_nex_process")
func sonicdpi_nex_process(_ bytes: UnsafePointer<UInt8>, _ len: Int, _ direction: UInt8) -> UInt8

@_silgen_name("sonicdpi_nex_take_modified")
func sonicdpi_nex_take_modified(_ out: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int

@_silgen_name("sonicdpi_nex_shutdown")
func sonicdpi_nex_shutdown()

private let log = OSLog(subsystem: "com.bysonic.sonicdpi.nex", category: "PacketFilter")

/// Verdict mirror — same numbers as Rust enum.
private let VERDICT_PASS: UInt8 = 0
private let VERDICT_DROP: UInt8 = 1
private let VERDICT_MODIFIED: UInt8 = 2

class PacketFilterProvider: NEFilterPacketProvider {

    /// Buffer for retrieving modified packet bytes from Rust.
    /// 64 KiB is the upper bound of any single IPv4/IPv6 datagram.
    private var modifiedBuf = [UInt8](repeating: 0, count: 65_536)

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let profile = "youtube-discord"
        let result = profile.withCString { (cstr: UnsafePointer<CChar>) -> Int32 in
            cstr.withMemoryRebound(to: UInt8.self, capacity: profile.utf8.count) { ptr in
                sonicdpi_nex_init(ptr, profile.utf8.count)
            }
        }
        if result != 0 {
            os_log("Rust engine init failed: %d", log: log, type: .error, result)
            completionHandler(NSError(
                domain: "com.bysonic.sonicdpi.nex",
                code: Int(result),
                userInfo: [NSLocalizedDescriptionKey: "engine init failed"]
            ))
            return
        }
        os_log("SonicDPI filter started with profile=%{public}s", log: log, type: .info, profile)
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        sonicdpi_nex_shutdown()
        os_log("SonicDPI filter stopped reason=%{public}d", log: log, type: .info, reason.rawValue)
        completionHandler()
    }

    /// Per-packet hook. Apple invokes this on the provider's dispatch
    /// queue for every IP packet matching the host app's filter rules.
    override func handle(_ packet: NEPacket) -> NEFilterPacketProviderVerdict {
        let direction: UInt8 = (packet.direction == .outbound) ? 0 : 1
        let data = packet.data

        let verdict: UInt8 = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> UInt8 in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return VERDICT_PASS
            }
            return sonicdpi_nex_process(base, data.count, direction)
        }

        switch verdict {
        case VERDICT_DROP:
            return .drop
        case VERDICT_MODIFIED:
            // Pull modified bytes out of Rust and inject back via the
            // packet flow. Note: NEFilterPacketProvider doesn't expose
            // an in-place "replace this packet" API; the canonical
            // pattern is to .drop the original and write the new packet
            // through `packetFlow.writeMessages(_:withDirections:)`.
            let n = modifiedBuf.withUnsafeMutableBufferPointer { buf -> Int in
                guard let p = buf.baseAddress else { return 0 }
                return sonicdpi_nex_take_modified(p, buf.count)
            }
            if n > 0 {
                let modifiedData = Data(modifiedBuf.prefix(n))
                let injected = NEPacket(data: modifiedData, protocolFamily: packet.protocolFamily)
                packetFlow.writePackets([injected],
                                        withProtocols: [NSNumber(value: packet.protocolFamily)])
            }
            return .drop
        default:
            return .allow
        }
    }
}
