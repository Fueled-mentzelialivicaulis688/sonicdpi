// HostAppMain.swift
// SonicDPI host app — launches once, requests OS to install the
// SystemExtension, configures the NEFilterManager, then exits.
//
// Lives at minimum size because the real work happens in the
// .systemextension bundle. The host .app exists because Apple requires
// System Extensions to be packaged inside an application bundle.

import Foundation
import NetworkExtension
import SystemExtensions
import os.log

private let log = OSLog(subsystem: "com.bysonic.sonicdpi", category: "HostApp")
private let extensionBundleID = "com.bysonic.sonicdpi.nex.extension"

class ExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        os_log("Replacing existing extension %{public}s -> %{public}s",
               log: log, type: .info, existing.bundleVersion, ext.bundleVersion)
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        os_log("System extension needs user approval — open System Settings -> Privacy & Security",
               log: log, type: .info)
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        os_log("System extension install finished: %{public}d",
               log: log, type: .info, result.rawValue)
        if result == .completed {
            installFilterManager()
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        os_log("System extension install failed: %{public}@",
               log: log, type: .error, String(describing: error))
        exit(1)
    }
}

func installSystemExtension() {
    let request = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extensionBundleID,
        queue: .main
    )
    let delegate = ExtensionRequestDelegate()
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
    os_log("Submitted activation request for %{public}s", log: log, type: .info, extensionBundleID)
    // Keep the runloop alive until the request completes.
    RunLoop.main.run()
}

func installFilterManager() {
    NEFilterManager.shared().loadFromPreferences { error in
        if let error = error {
            os_log("loadFromPreferences failed: %{public}@",
                   log: log, type: .error, String(describing: error))
            return
        }
        let cfg = NEFilterProviderConfiguration()
        cfg.filterPackets = true
        cfg.filterSockets = false
        cfg.filterDataProviderBundleIdentifier = extensionBundleID
        cfg.filterPacketProviderBundleIdentifier = extensionBundleID

        NEFilterManager.shared().providerConfiguration = cfg
        NEFilterManager.shared().localizedDescription = "SonicDPI"
        NEFilterManager.shared().isEnabled = true

        NEFilterManager.shared().saveToPreferences { error in
            if let error = error {
                os_log("saveToPreferences failed: %{public}@",
                       log: log, type: .error, String(describing: error))
            } else {
                os_log("Filter manager configured and enabled", log: log, type: .info)
                exit(0)
            }
        }
    }
    RunLoop.main.run()
}

// Entry point.
installSystemExtension()
