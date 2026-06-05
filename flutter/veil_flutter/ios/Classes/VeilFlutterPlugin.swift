// iOS plugin glue для veil_flutter (Epic 489.6 + 489.10).
//
// Two surfaces:
//
//   1. **Lifecycle channel** (`veil_flutter/lifecycle`):
//      `startBackgroundService` / `stopBackgroundService` —
//      Android-only operations.  iOS doesn't have foreground services;
//      we accept the calls и silently no-op so cross-platform code
//      doesn't need а Platform check.
//
//   2. **Push channel** (`veil_flutter/push`):
//      * `notifyWakeup` — called by Dart when an APNs silent push
//        arrives.  Schedules а `BGProcessingTask` that gives the
//        daemon ~30 s к drain pending operations BEFORE iOS suspends
//        the process.  Without this, the silent push wakes the
//        daemon for ~5 s и then iOS suspends mid-fetch.
//      * `registerDeviceToken` / `getRegisteredToken` — APNs token
//        storage в the **iOS Keychain** so the daemon can include
//        it в rendezvous-ad announcements.  Audit batch 2026-05-23:
//        promoted от `UserDefaults` к Keychain so the token lives at
//        the same trust level as Android's `EncryptedSharedPreferences`
//        (file-level encryption, never в iCloud backup, never in
//        plaintext в the app sandbox).  Legacy UserDefaults entries
//        are migrated transparently on the first `getRegisteredToken`
//        и then removed.
//
// Background-task registration:
//   The plugin registers `com.veil.veil_flutter.refresh` as
//   а `BGProcessingTask` identifier при app launch (consumer must
//   ALSO add the same identifier к `Info.plist` под key
//   `BGTaskSchedulerPermittedIdentifiers`).  When iOS schedules the
//   task, we call back into Dart via the push channel так that
//   higher-level code can complete fetches.

import Flutter
import UIKit
import Security
#if canImport(BackgroundTasks)
import BackgroundTasks
#endif

public class VeilFlutterPlugin: NSObject, FlutterPlugin {

    private static let LIFECYCLE_CHANNEL = "veil_flutter/lifecycle"
    private static let PUSH_CHANNEL      = "veil_flutter/push"
    private static let BG_TASK_IDENTIFIER = "com.veil.veil_flutter.refresh"

    // Keychain coordinates для the APNs device token.  Service identifier
    // matches the plugin's bundle namespace; account is the human-readable
    // tag so multiple credentials could coexist if ever needed.
    private static let KEYCHAIN_SERVICE = "com.veil.veil_flutter"
    private static let KEYCHAIN_ACCOUNT = "deviceToken"
    // Receiver's wake-HMAC secret (Epic 489.10).  Distinct Keychain
    // account под the SAME service so it sits at the exact same trust
    // level as the APNs token (same accessibility class, iCloud-excluded).
    // Anyone holding it can forge silent-push wake authenticators for this
    // device, so it must never live в plaintext.
    private static let KEYCHAIN_ACCOUNT_WAKE_HMAC = "wake_hmac_key"
    // Wake-HMAC keys are fixed 32-byte secrets (veil_crypto's
    // `WakeHmacKey`); mirrors the Dart `veilWakeHmacKeyLen`.
    private static let WAKE_HMAC_KEY_LEN = 32

    // Legacy UserDefaults key — kept ONLY for one-shot migration.  After
    // the first `getRegisteredToken` call following the audit batch
    // 2026-05-23 upgrade, the value is read, copied into Keychain, и
    // the UserDefaults entry is removed.  Future versions can delete
    // this constant once а reasonable upgrade-grace-period has passed.
    private static let LEGACY_DEFAULTS_KEY_TOKEN = "VeilFlutter.deviceToken"

    /// Signal armed at the start of each BGProcessingTask invocation;
    /// consumed by the matching `notifyDrained` MethodChannel call.
    /// Per-task instance (recreated on every `handleBackgroundProcessing`
    /// entry) avoids stale signals carrying over between independent
    /// wake cycles.  When `nil`, `notifyDrained` becomes а silent no-op
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

        // Register the BGProcessingTask handler at plugin init.  iOS
        // refuses к schedule а task whose identifier isn't registered
        // ON THIS RUN (BGTaskScheduler is per-launch state).  Skip
        // gracefully on iOS < 13 (BackgroundTasks framework absent).
        #if canImport(BackgroundTasks)
        if #available(iOS 13.0, *) {
            BGTaskScheduler.shared.register(
                forTaskWithIdentifier: BG_TASK_IDENTIFIER, using: nil,
            ) { task in
                instance.handleBackgroundProcessing(task as! BGProcessingTask)
            }
        }
        #endif
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "startBackgroundService", "stopBackgroundService":
            // Android-only; iOS has no equivalent.  Silent no-op so
            // cross-platform code doesn't need а Platform.isAndroid check.
            result(nil)
        case "notifyWakeup":
            scheduleBackgroundProcessing()
            result(nil)
        case "registerDeviceToken":
            let token = (call.arguments as? [String: Any])?["token"] as? String ?? ""
            Self.keychainSaveToken(token)
            // Also clear any legacy UserDefaults entry в case caller did
            // not previously call `getRegisteredToken` (which performs the
            // one-shot migration).  Keeps the device clean.
            UserDefaults.standard.removeObject(forKey: Self.LEGACY_DEFAULTS_KEY_TOKEN)
            result(nil)
        case "notifyDrained":
            // Mailbox drain (fetch) completed на the Dart side.  If а
            // BGProcessingTask currently armed а signal, release it so
            // `setTaskCompleted` fires precisely at drain completion
            // rather than padding к the 28-second fallback.  Outside
            // а BG-task window the call is а silent no-op.
            drainSignal?.signal()
            result(nil)
        case "getRegisteredToken":
            // One-shot migration: if Keychain is empty но UserDefaults has
            // а legacy token, lift it into Keychain и delete the original.
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
            // Receiver's wake-HMAC secret — persisted в the Keychain at the
            // same trust level as the APNs token (см. KEYCHAIN_ACCOUNT_WAKE_HMAC).
            // Raw 32-byte secret, so it goes in as `Data` (NOT UTF-8 String
            // like the token) под its own account.
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
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    /// Schedule а BGProcessingTask that gives the daemon ~30 s к
    /// drain pending veil operations after а silent push wake.
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
        // Arm а fresh signal so any pending `notifyDrained` call from
        // the Dart side (typically inside `VeilPush.drainMailbox`)
        // wakes us precisely at drain completion.  Previous behaviour
        // was а blind 25-second sleep; now we complete as soon as
        // drain finishes, falling back к а 28-second timeout if the
        // signal never arrives (slow cellular, daemon stall, или the
        // common race где drain completed BEFORE iOS scheduled this
        // task — see the `drainSignal` field docstring).
        //
        // 28-second budget leaves ~2 seconds of safety margin under
        // iOS' typical ~30 s BG-task window; iOS expirationHandler
        // catches the worst case if we somehow blow past that.
        let signal = DispatchSemaphore(value: 0)
        drainSignal = signal
        task.expirationHandler = { [weak self] in
            // iOS is about к suspend — drop the reference so а later
            // `notifyDrained` doesn't fire into а dead semaphore.
            self?.drainSignal = nil
            NSLog("VeilFlutter: BGProcessingTask expired")
        }
        DispatchQueue.global(qos: .background).async { [weak self] in
            let waitResult = signal.wait(timeout: .now() + 28.0)
            DispatchQueue.main.async {
                self?.drainSignal = nil
                // success=true means we observed the drained signal;
                // false = timed out (best-effort, iOS will count it as
                // а normal completion either way — distinguishing helps
                // future operator-side analytics if added).
                task.setTaskCompleted(success: waitResult == .success)
            }
        }
    }

    // MARK: - Keychain storage для APNs device token (audit batch 2026-05-23)
    //
    // The APNs token is sensitive — it lets ANY holder issue silent-push
    // wakeups к this device, draining battery и (depending on push HMAC
    // status; см. Epic 489.10) potentially probing presence.  Keychain
    // protects it via the same file-level encryption iOS uses для
    // Touch/Face ID secrets, AND excludes it от iCloud backups.
    //
    // `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:
    //   * `AfterFirstUnlock` — readable as soon as the user has unlocked
    //     the device once since boot.  APNs delivery happens long before
    //     the user explicitly unlocks again, so `WhenUnlocked*` would
    //     break wakeup-on-locked-screen.
    //   * `ThisDeviceOnly` — never migrated к а new device via iCloud
    //     backup или device-к-device transfer.  Forces fresh APNs
    //     enrollment after а device swap (intentional — the new device
    //     should not pretend к be the old one).

    /// Persist `token` к the Keychain, overwriting any existing entry
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
    /// ?? ""` contract so the Dart side does not need а separate
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
    /// nothing is stored.  Used both от `registerDeviceToken` с empty
    /// string и от tests.
    private static func keychainDeleteToken() {
        keychainDeleteData(account: KEYCHAIN_ACCOUNT)
    }

    // MARK: - Keychain storage primitives (account-parameterised)
    //
    // Byte-exact extraction of the token store's mechanism so the APNs
    // token и the wake-HMAC secret (Epic 489.10) share ONE query shape и
    // ONE accessibility class — `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
    // (см. the section header above for why).  They differ ONLY by
    // `kSecAttrAccount`.  These operate on raw `Data` because the wake-HMAC
    // key is а 32-byte secret, not а UTF-8 string; the token wrappers above
    // adapt String ⇄ Data exactly as before.

    /// Persist `data` к the Keychain под `(service, account)`, overwriting
    /// any existing entry.  Mirrors the historical token save (update-then-add).
    private static func keychainSaveData(_ data: Data, account: String) {
        // SecItemAdd refuses when an entry already exists, so try update
        // first; if nothing к update, fall through к add.
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

    /// Read the raw bytes stored под `(service, account)`, or `nil` when
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

    /// Remove the entry под `(service, account)`.  No-op when nothing is
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
