// iOS plugin glue for veil_flutter (Epic 489.6 + 489.10).
//
// Two surfaces:
//
//   1. **Lifecycle channel** (`veil_flutter/lifecycle`):
//      `startBackgroundService` / `stopBackgroundService` —
//      Android-only operations.  iOS doesn't have foreground services;
//      we accept the calls and silently no-op so cross-platform code
//      doesn't need a Platform check.
//
//   2. **Push channel** (`veil_flutter/push`):
//      * `notifyWakeup` — called by Dart when an APNs silent push
//        arrives.  Schedules a `BGProcessingTask` that gives the
//        daemon ~30 s to drain pending operations BEFORE iOS suspends
//        the process.  Without this, the silent push wakes the
//        daemon for ~5 s and then iOS suspends mid-fetch.
//      * `registerDeviceToken` / `getRegisteredToken` — APNs token
//        storage in the **iOS Keychain** so the daemon can include
//        it in rendezvous-ad announcements.  Audit batch 2026-05-23:
//        promoted from `UserDefaults` to Keychain so the token lives at
//        the same trust level as Android's `EncryptedSharedPreferences`
//        (file-level encryption, never in iCloud backup, never in
//        plaintext in the app sandbox).  Legacy UserDefaults entries
//        are migrated transparently on the first `getRegisteredToken`
//        and then removed.
//
// Background-task registration:
//   The plugin registers `com.veil.veil_flutter.refresh` as
//   a `BGProcessingTask` identifier at app launch (consumer must
//   ALSO add the same identifier to `Info.plist` under key
//   `BGTaskSchedulerPermittedIdentifiers`).  When iOS schedules the
//   task, we call back into Dart via the push channel so that
//   higher-level code can complete fetches.

import Flutter
import UIKit
import Security
import NetworkExtension
#if canImport(BackgroundTasks)
import BackgroundTasks
#endif

public class VeilFlutterPlugin: NSObject, FlutterPlugin {

    private static let LIFECYCLE_CHANNEL = "veil_flutter/lifecycle"
    private static let PUSH_CHANNEL      = "veil_flutter/push"
    private static let VPN_CHANNEL       = "network.veil.xveil/vpn"
    // PacketTunnel owns a separate ephemeral Veil/SOCKS node. It survives host
    // suspension and its provider-owned sockets stay outside the default route.
    private static let VPN_HAS_EXTENSION_OWNED_UPSTREAM = true
    private static let BG_TASK_IDENTIFIER = "com.veil.veil_flutter.refresh"

    // Keychain coordinates for the APNs device token.  Service identifier
    // matches the plugin's bundle namespace; account is the human-readable
    // tag so multiple credentials could coexist if ever needed.
    private static let KEYCHAIN_SERVICE = "com.veil.veil_flutter"
    private static let KEYCHAIN_ACCOUNT = "deviceToken"
    // Receiver's wake-HMAC secret (Epic 489.10).  Distinct Keychain
    // account under the SAME service so it sits at the exact same trust
    // level as the APNs token (same accessibility class, iCloud-excluded).
    // Anyone holding it can forge silent-push wake authenticators for this
    // device, so it must never live in plaintext.
    private static let KEYCHAIN_ACCOUNT_WAKE_HMAC = "wake_hmac_key"
    // Wake-HMAC keys are fixed 32-byte secrets (veil_crypto's
    // `WakeHmacKey`); mirrors the Dart `veilWakeHmacKeyLen`.
    private static let WAKE_HMAC_KEY_LEN = 32

    // Legacy UserDefaults key — kept ONLY for one-shot migration.  After
    // the first `getRegisteredToken` call following the audit batch
    // 2026-05-23 upgrade, the value is read, copied into Keychain, and
    // the UserDefaults entry is removed.  Future versions can delete
    // this constant once a reasonable upgrade-grace-period has passed.
    private static let LEGACY_DEFAULTS_KEY_TOKEN = "VeilFlutter.deviceToken"

    /// Signal armed at the start of each BGProcessingTask invocation;
    /// consumed by the matching `notifyDrained` MethodChannel call.
    /// Per-task instance (recreated on every `handleBackgroundProcessing`
    /// entry) avoids stale signals carrying over between independent
    /// wake cycles.  When `nil`, `notifyDrained` becomes a silent no-op
    /// (signal arrived while no BG task is awaiting it — common race
    /// when drain completes inside the silent-push handler BEFORE iOS
    /// schedules the BG task).  The hardcoded-timeout fallback in
    /// `handleBackgroundProcessing` keeps that race benign.
    private var drainSignal: DispatchSemaphore?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = VeilFlutterPlugin()
        let lifecycleChannel = FlutterMethodChannel(
            name: LIFECYCLE_CHANNEL, binaryMessenger: registrar.messenger(),
        )
        registrar.addMethodCallDelegate(instance, channel: lifecycleChannel)
        let pushChannel = FlutterMethodChannel(
            name: PUSH_CHANNEL, binaryMessenger: registrar.messenger(),
        )
        registrar.addMethodCallDelegate(instance, channel: pushChannel)
        let vpnChannel = FlutterMethodChannel(
            name: VPN_CHANNEL, binaryMessenger: registrar.messenger(),
        )
        registrar.addMethodCallDelegate(instance, channel: vpnChannel)

        // Register the BGProcessingTask handler at plugin init.  iOS
        // refuses to schedule a task whose identifier isn't registered
        // ON THIS RUN (BGTaskScheduler is per-launch state).  Skip
        // gracefully on iOS < 13 (BackgroundTasks framework absent).
        #if canImport(BackgroundTasks)
        if #available(iOS 13.0, *) {
            BGTaskScheduler.shared.register(
                forTaskWithIdentifier: BG_TASK_IDENTIFIER, using: nil,
            ) { task in
                // Guarded cast: a forced `as!` would crash the host app if iOS
                // ever hands a task of an unexpected type. Mark the task done
                // (unsuccessfully) and bail instead.
                guard let task = task as? BGProcessingTask else {
                    task.setTaskCompleted(success: false)
                    return
                }
                instance.handleBackgroundProcessing(task)
            }
        }
        #endif
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "startBackgroundService", "stopBackgroundService":
            // Android-only; iOS has no equivalent.  Silent no-op so
            // cross-platform code doesn't need a Platform.isAndroid check.
            result(nil)
        case "notifyWakeup":
            scheduleBackgroundProcessing()
            result(nil)
        case "registerDeviceToken":
            let token = (call.arguments as? [String: Any])?["token"] as? String ?? ""
            Self.keychainSaveToken(token)
            // Also clear any legacy UserDefaults entry in case caller did
            // not previously call `getRegisteredToken` (which performs the
            // one-shot migration).  Keeps the device clean.
            UserDefaults.standard.removeObject(forKey: Self.LEGACY_DEFAULTS_KEY_TOKEN)
            result(nil)
        case "notifyDrained":
            // Mailbox drain (fetch) completed on the Dart side.  If a
            // BGProcessingTask currently armed a signal, release it so
            // `setTaskCompleted` fires precisely at drain completion
            // rather than padding to the 28-second fallback.  Outside
            // a BG-task window the call is a silent no-op.
            drainSignal?.signal()
            result(nil)
        case "getRegisteredToken":
            // One-shot migration: if Keychain is empty but UserDefaults has
            // a legacy token, lift it into Keychain and delete the original.
            // After the next launch the UserDefaults branch never fires.
            if Self.keychainReadToken().isEmpty,
               let legacy = UserDefaults.standard.string(forKey: Self.LEGACY_DEFAULTS_KEY_TOKEN),
               !legacy.isEmpty
            {
                Self.keychainSaveToken(legacy)
                UserDefaults.standard.removeObject(forKey: Self.LEGACY_DEFAULTS_KEY_TOKEN)
            }
            result(Self.keychainReadToken())
        case "storeWakeHmacKey":
            // Receiver's wake-HMAC secret — persisted in the Keychain at the
            // same trust level as the APNs token (see KEYCHAIN_ACCOUNT_WAKE_HMAC).
            // Raw 32-byte secret, so it goes in as `Data` (NOT UTF-8 String
            // like the token) under its own account.
            guard let typed = (call.arguments as? [String: Any])?["key"] as? FlutterStandardTypedData,
                  typed.data.count == Self.WAKE_HMAC_KEY_LEN
            else {
                let got = ((call.arguments as? [String: Any])?["key"] as? FlutterStandardTypedData)?.data.count ?? 0
                result(FlutterError(
                    code: "BAD_WAKE_HMAC_KEY",
                    message: "wake-HMAC key must be \(Self.WAKE_HMAC_KEY_LEN) bytes, got \(got)",
                    details: nil,
                ))
                return
            }
            Self.keychainSaveData(typed.data, account: Self.KEYCHAIN_ACCOUNT_WAKE_HMAC)
            result(nil)
        case "loadWakeHmacKey":
            // Returns the stored 32-byte secret as typed bytes, or nil when
            // nothing is stored (parallels Android's null-on-absent contract).
            if let data = Self.keychainReadData(account: Self.KEYCHAIN_ACCOUNT_WAKE_HMAC) {
                result(FlutterStandardTypedData(bytes: data))
            } else {
                result(nil)
            }
        case "probe", "status", "confirmRunning":
            vpnStatus(result)
        case "start":
            vpnStart(call.arguments, result: result)
        case "stop", "abort":
            vpnStop(result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - System packet tunnel

    private static var packetTunnelBundleIdentifier: String? {
        Bundle.main.bundleIdentifier.map { "\($0).PacketTunnel" }
    }

    private static func vpnState(_ phase: String, detail: String? = nil) -> [String: Any] {
        var state: [String: Any] = ["phase": phase]
        if let detail { state["detail"] = detail }
        return state
    }

    private static func vpnPhase(_ status: NEVPNStatus) -> String {
        switch status {
        case .connected:
            return "running"
        case .connecting, .reasserting:
            return "starting"
        case .disconnecting:
            return "stopping"
        case .invalid, .disconnected:
            return "stopped"
        @unknown default:
            return "error"
        }
    }

    private func finish(_ result: @escaping FlutterResult, _ value: Any?) {
        if Thread.isMainThread {
            result(value)
        } else {
            DispatchQueue.main.async { result(value) }
        }
    }

    private func loadPacketTunnelManager(
        completion: @escaping (NETunnelProviderManager?, Error?) -> Void
    ) {
        guard let providerBundleIdentifier = Self.packetTunnelBundleIdentifier else {
            completion(nil, NSError(
                domain: "VeilVPN", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "host bundle identifier is unavailable"]
            ))
            return
        }
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            let manager = managers?.first { candidate in
                (candidate.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == providerBundleIdentifier
            }
            completion(manager, error)
        }
    }

    private func vpnStatus(_ result: @escaping FlutterResult) {
        loadPacketTunnelManager { manager, error in
            if let error {
                self.finish(result, Self.vpnState("error", detail: error.localizedDescription))
                return
            }
            guard let manager else {
                self.finish(result, Self.vpnState(
                    Self.VPN_HAS_EXTENSION_OWNED_UPSTREAM ? "stopped" : "unsupported",
                    detail: Self.VPN_HAS_EXTENSION_OWNED_UPSTREAM ? nil
                        : "Apple VPN awaits an extension-owned veil upstream"
                ))
                return
            }
            let phase = Self.vpnPhase(manager.connection.status)
            if !Self.VPN_HAS_EXTENSION_OWNED_UPSTREAM && phase == "stopped" {
                self.finish(result, Self.vpnState(
                    "unsupported",
                    detail: "Apple VPN awaits an extension-owned veil upstream"
                ))
                return
            }
            self.finish(result, Self.vpnState(phase))
        }
    }

    private func vpnStart(_ arguments: Any?, result: @escaping FlutterResult) {
        guard Self.VPN_HAS_EXTENSION_OWNED_UPSTREAM else {
            finish(result, Self.vpnState(
                "unsupported",
                detail: "Apple VPN awaits an extension-owned veil upstream"
            ))
            return
        }
        guard let arguments = arguments as? [String: Any],
              let policy = arguments["policy"] as? [String: Any],
              let exitNodeId = arguments["exitNodeId"] as? String,
              exitNodeId.count == 64,
              let obfs4Psk = arguments["obfs4Psk"] as? String,
              !obfs4Psk.isEmpty,
              let providerBundleIdentifier = Self.packetTunnelBundleIdentifier
        else {
            finish(result, Self.vpnState("error", detail: "invalid VPN arguments"))
            return
        }

        loadPacketTunnelManager { existing, loadError in
            if let loadError {
                self.finish(result, Self.vpnState("error", detail: loadError.localizedDescription))
                return
            }
            let manager = existing ?? NETunnelProviderManager()
            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
            tunnelProtocol.serverAddress = "xVeil extension-owned upstream"
            var providerConfiguration = policy
            providerConfiguration["exitNodeId"] = exitNodeId
            providerConfiguration["exitNodeIds"] = arguments["exitNodeIds"] ?? [exitNodeId]
            providerConfiguration["obfs4Psk"] = obfs4Psk
            tunnelProtocol.providerConfiguration = providerConfiguration
            manager.protocolConfiguration = tunnelProtocol
            manager.localizedDescription = "xVeil"
            manager.isEnabled = true
            manager.saveToPreferences { saveError in
                if let saveError {
                    self.finish(result, Self.vpnState("error", detail: saveError.localizedDescription))
                    return
                }
                // Apple requires a reload after the first save; starting the
                // stale in-memory manager can otherwise fail with configurationInvalid.
                manager.loadFromPreferences { reloadError in
                    if let reloadError {
                        self.finish(result, Self.vpnState("error", detail: reloadError.localizedDescription))
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                    } catch {
                        self.finish(result, Self.vpnState("error", detail: error.localizedDescription))
                        return
                    }
                    self.waitForVPN(
                        manager.connection,
                        targetRunning: true,
                        deadline: .now() + .seconds(12),
                        result: result
                    )
                }
            }
        }
    }

    private func vpnStop(_ result: @escaping FlutterResult) {
        loadPacketTunnelManager { manager, error in
            if let error {
                self.finish(result, Self.vpnState("error", detail: error.localizedDescription))
                return
            }
            guard let manager else {
                self.finish(result, Self.vpnState("stopped"))
                return
            }
            manager.connection.stopVPNTunnel()
            self.waitForVPN(
                manager.connection,
                targetRunning: false,
                deadline: .now() + .seconds(5),
                result: result
            )
        }
    }

    private func waitForVPN(
        _ connection: NEVPNConnection,
        targetRunning: Bool,
        deadline: DispatchTime,
        result: @escaping FlutterResult
    ) {
        let phase = Self.vpnPhase(connection.status)
        if targetRunning && phase == "running" {
            finish(result, Self.vpnState("running"))
            return
        }
        if !targetRunning && phase == "stopped" {
            finish(result, Self.vpnState("stopped"))
            return
        }
        if .now() >= deadline {
            let expected = targetRunning ? "start" : "stop"
            finish(result, Self.vpnState(
                "error",
                detail: "VPN did not \(expected) before timeout (\(phase))"
            ))
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(100)) {
            self.waitForVPN(
                connection,
                targetRunning: targetRunning,
                deadline: deadline,
                result: result
            )
        }
    }

    /// Schedule a BGProcessingTask that gives the daemon ~30 s to
    /// drain pending veil operations after a silent push wake.
    /// iOS may delay execution — silent pushes don't guarantee
    /// immediate task scheduling, but background-task is the
    /// supported "give me longer" mechanism.
    private func scheduleBackgroundProcessing() {
        #if canImport(BackgroundTasks)
        if #available(iOS 13.0, *) {
            let request = BGProcessingTaskRequest(
                identifier: Self.BG_TASK_IDENTIFIER,
            )
            request.requiresNetworkConnectivity = true
            request.requiresExternalPower = false
            do {
                try BGTaskScheduler.shared.submit(request)
            } catch {
                NSLog("VeilFlutter: BGProcessingTask submit failed: \(error)")
            }
        }
        #endif
    }

    @available(iOS 13.0, *)
    private func handleBackgroundProcessing(_ task: BGProcessingTask) {
        // Arm a fresh signal so any pending `notifyDrained` call from
        // the Dart side (typically inside `VeilPush.drainMailbox`)
        // wakes us precisely at drain completion.  Previous behaviour
        // was a blind 25-second sleep; now we complete as soon as
        // drain finishes, falling back to a 28-second timeout if the
        // signal never arrives (slow cellular, daemon stall, or the
        // common race where drain completed BEFORE iOS scheduled this
        // task — see the `drainSignal` field docstring).
        //
        // 28-second budget leaves ~2 seconds of safety margin under
        // iOS' typical ~30 s BG-task window; iOS expirationHandler
        // catches the worst case if we somehow blow past that.
        let signal = DispatchSemaphore(value: 0)
        drainSignal = signal
        task.expirationHandler = { [weak self] in
            // iOS is about to suspend — drop the reference so a later
            // `notifyDrained` doesn't fire into a dead semaphore.
            self?.drainSignal = nil
            NSLog("VeilFlutter: BGProcessingTask expired")
        }
        DispatchQueue.global(qos: .background).async { [weak self] in
            let waitResult = signal.wait(timeout: .now() + 28.0)
            DispatchQueue.main.async {
                self?.drainSignal = nil
                // success=true means we observed the drained signal;
                // false = timed out (best-effort, iOS will count it as
                // a normal completion either way — distinguishing helps
                // future operator-side analytics if added).
                task.setTaskCompleted(success: waitResult == .success)
            }
        }
    }

    // MARK: - Keychain storage for APNs device token (audit batch 2026-05-23)
    //
    // The APNs token is sensitive — it lets ANY holder issue silent-push
    // wakeups to this device, draining battery and (depending on push HMAC
    // status; see Epic 489.10) potentially probing presence.  Keychain
    // protects it via the same file-level encryption iOS uses for
    // Touch/Face ID secrets, AND excludes it from iCloud backups.
    //
    // `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:
    //   * `AfterFirstUnlock` — readable as soon as the user has unlocked
    //     the device once since boot.  APNs delivery happens long before
    //     the user explicitly unlocks again, so `WhenUnlocked*` would
    //     break wakeup-on-locked-screen.
    //   * `ThisDeviceOnly` — never migrated to a new device via iCloud
    //     backup or device-to-device transfer.  Forces fresh APNs
    //     enrollment after a device swap (intentional — the new device
    //     should not pretend to be the old one).

    /// Persist `token` to the Keychain, overwriting any existing entry
    /// under `(service, account)`.  Empty `token` deletes the entry
    /// (matches the historical UserDefaults `set(""..)` semantics).
    private static func keychainSaveToken(_ token: String) {
        if token.isEmpty {
            keychainDeleteToken()
            return
        }
        keychainSaveData(Data(token.utf8), account: KEYCHAIN_ACCOUNT)
    }

    /// Read the stored APNs token, returning `""` when absent or
    /// unreadable (matches the historical UserDefaults `string(forKey:)
    /// ?? ""` contract so the Dart side does not need a separate
    /// not-bound vs empty-string branch).
    private static func keychainReadToken() -> String {
        guard let data = keychainReadData(account: KEYCHAIN_ACCOUNT),
              let s = String(data: data, encoding: .utf8)
        else {
            return ""
        }
        return s
    }

    /// Remove the stored APNs token from the Keychain.  No-op when
    /// nothing is stored.  Used both from `registerDeviceToken` with empty
    /// string and from tests.
    private static func keychainDeleteToken() {
        keychainDeleteData(account: KEYCHAIN_ACCOUNT)
    }

    // MARK: - Keychain storage primitives (account-parameterised)
    //
    // Byte-exact extraction of the token store's mechanism so the APNs
    // token and the wake-HMAC secret (Epic 489.10) share ONE query shape and
    // ONE accessibility class — `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
    // (see the section header above for why).  They differ ONLY by
    // `kSecAttrAccount`.  These operate on raw `Data` because the wake-HMAC
    // key is a 32-byte secret, not a UTF-8 string; the token wrappers above
    // adapt String ⇄ Data exactly as before.

    /// Persist `data` to the Keychain under `(service, account)`, overwriting
    /// any existing entry.  Mirrors the historical token save (update-then-add).
    private static func keychainSaveData(_ data: Data, account: String) {
        // SecItemAdd refuses when an entry already exists, so try update
        // first; if nothing to update, fall through to add.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KEYCHAIN_SERVICE,
            kSecAttrAccount as String: account,
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            NSLog("VeilFlutter: Keychain update failed (status=\(updateStatus))")
        }
        var addAttrs = query
        addAttrs[kSecValueData as String] = data
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
        if addStatus != errSecSuccess {
            NSLog("VeilFlutter: Keychain add failed (status=\(addStatus))")
        }
    }

    /// Read the raw bytes stored under `(service, account)`, or `nil` when
    /// absent / unreadable.  (The token wrapper maps `nil` → `""`.)
    private static func keychainReadData(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KEYCHAIN_SERVICE,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return data
    }

    /// Remove the entry under `(service, account)`.  No-op when nothing is
    /// stored.
    private static func keychainDeleteData(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KEYCHAIN_SERVICE,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            NSLog("VeilFlutter: Keychain delete failed (status=\(status))")
        }
    }
}
