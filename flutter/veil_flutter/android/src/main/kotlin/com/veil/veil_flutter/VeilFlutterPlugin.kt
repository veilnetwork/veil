// MethodChannel bridge for foreground-service control from Dart side
// (Epic 489.6).
//
// The veil-flutter plugin is primarily an `ffiPlugin` (Dart-FFI
// directly into the Rust .so), but Android-specific lifecycle hooks
// — namely starting / stopping a foreground service — require a
// JNI thunk because Android's `startForegroundService` is a Java API
// not exposed via NDK.
//
// MethodChannel surface:
//   * `startBackgroundService` — args:
//       { title?, text?, hangupAction?, ringing?, microphone?, camera? } → null
//   * `stopBackgroundService`  — args: {}                 → null

package com.veil.veil_flutter

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

class VeilFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    companion object {
        private const val LIFECYCLE_CHANNEL = "veil_flutter/lifecycle"
        private const val PUSH_CHANNEL = "veil_flutter/push"
        // Legacy plain-text prefs file — read-once-then-delete migration
        // target.  Existing installs may have a cleartext token here;
        // we move it to the encrypted store on first read so older app
        // versions don't strand the token.
        private const val LEGACY_PREFS_FILE = "veil_flutter_push"
        private const val PREFS_FILE = "veil_flutter_push_enc"
        private const val PREFS_KEY_TOKEN = "device_token"
        // Receiver's wake-HMAC secret (Epic 489.10).  Lives in the SAME
        // encrypted store as the push token, under its own key so the
        // two credentials never collide.  Persisted base64-encoded.
        private const val PREFS_KEY_WAKE_HMAC = "wake_hmac_key"
        // Wake-HMAC keys are fixed 32-byte secrets (veil_crypto's
        // `WakeHmacKey`); mirrors the Dart `veilWakeHmacKeyLen`.
        private const val WAKE_HMAC_KEY_LEN = 32
        // Whether legacy migration already ran. Set the first time we
        // open the encrypted prefs successfully.  Stored in the
        // encrypted prefs itself so an attacker downgrading the apk
        // cannot replay the cleartext path.
        private const val PREFS_KEY_MIGRATED = "legacy_migrated_v1"
    }

    private lateinit var lifecycleChannel: MethodChannel
    private lateinit var pushChannel: MethodChannel
    private var appContext: Context? = null
    private var activity: Activity? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        lifecycleChannel = MethodChannel(binding.binaryMessenger, LIFECYCLE_CHANNEL)
        lifecycleChannel.setMethodCallHandler(this)
        pushChannel = MethodChannel(binding.binaryMessenger, PUSH_CHANNEL)
        pushChannel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        lifecycleChannel.setMethodCallHandler(null)
        pushChannel.setMethodCallHandler(null)
        appContext = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() { activity = null }

    override fun onReattachedToActivityForConfigChanges(b: ActivityPluginBinding) {
        activity = b.activity
    }

    override fun onDetachedFromActivityForConfigChanges() { activity = null }

    override fun onMethodCall(call: MethodCall, result: Result) {
        val ctx = appContext
        if (ctx == null) {
            result.error("NO_CONTEXT", "Plugin not attached to an Android engine", null)
            return
        }
        when (call.method) {
            "startBackgroundService" -> {
                val title = call.argument<String>("title")
                val text  = call.argument<String>("text")
                val hangupAction = call.argument<Boolean>("hangupAction") ?: false
                val ringing = call.argument<Boolean>("ringing") ?: false
                val microphone = call.argument<Boolean>("microphone") ?: false
                val camera = call.argument<Boolean>("camera") ?: false
                val intent = Intent(ctx, VeilDaemonService::class.java).apply {
                    action = VeilDaemonService.ACTION_START
                    if (title != null) putExtra(VeilDaemonService.EXTRA_NOTIFICATION_TITLE, title)
                    if (text  != null) putExtra(VeilDaemonService.EXTRA_NOTIFICATION_TEXT, text)
                    putExtra(VeilDaemonService.EXTRA_HANGUP_ACTION, hangupAction)
                    putExtra(VeilDaemonService.EXTRA_RINGING, ringing)
                    putExtra(VeilDaemonService.EXTRA_MICROPHONE, microphone)
                    putExtra(VeilDaemonService.EXTRA_CAMERA, camera)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ctx.startForegroundService(intent)
                } else {
                    ctx.startService(intent)
                }
                result.success(null)
            }
            "stopBackgroundService" -> {
                val intent = Intent(ctx, VeilDaemonService::class.java).apply {
                    action = VeilDaemonService.ACTION_STOP
                }
                ctx.startService(intent)
                result.success(null)
            }
            // ── Background-execution permission (battery optimisation) ───────
            // A foreground service alone is NOT enough on Doze + aggressive
            // OEMs (MIUI/HyperOS, OneUI): unless the app is battery-exempt the
            // OS still suspends/kills the process when backgrounded, so the
            // node stops receiving and notifications/replies die. These let the
            // app check + request the exemption (and deep-link to the per-app
            // settings where OEMs hide "Autostart").
            "isIgnoringBatteryOptimizations" -> {
                val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
                val ok = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    pm?.isIgnoringBatteryOptimizations(ctx.packageName) ?: true
                } else {
                    true
                }
                result.success(ok)
            }
            "requestIgnoreBatteryOptimizations" -> {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                    result.success(true)
                    return
                }
                try {
                    val intent = Intent(
                        Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:${ctx.packageName}"),
                    )
                    val act = activity
                    if (act != null) {
                        act.startActivity(intent)
                    } else {
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        ctx.startActivity(intent)
                    }
                    result.success(true)
                } catch (e: Exception) {
                    result.success(false)
                }
            }
            "openBackgroundSettings" -> {
                // The app-details screen, where MIUI/HyperOS exposes "Autostart"
                // and "No battery restrictions" — the per-app knobs a foreground
                // service still needs on those OEMs.
                try {
                    val intent = Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:${ctx.packageName}"),
                    )
                    val act = activity
                    if (act != null) {
                        act.startActivity(intent)
                    } else {
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        ctx.startActivity(intent)
                    }
                    result.success(true)
                } catch (e: Exception) {
                    result.success(false)
                }
            }
            // ── Push channel (Epic 489.10) ──────────────────────────────
            "notifyWakeup" -> {
                // TELEMETRY-ONLY by design (audit): this is NOT where the
                // mailbox drain / daemon reconnect happens — that is the
                // consumer's `VeilPush.handleWakeup(onWake: ...)` callback,
                // which closes over the app's `VeilClient` (unreachable from
                // this plugin's background isolate). By the time this fires the
                // consumer has already promoted the foreground service via the
                // lifecycle channel. Kept as a log/metric hook so operators can
                // observe wake cadence; wire real reconnect here only if a
                // future design moves the client handle into the plugin.
                android.util.Log.i("VeilFlutterPlugin",
                    "wake-up received (push notification)")
                result.success(null)
            }
            "registerDeviceToken" -> {
                val token = call.argument<String>("token") ?: ""
                tokenPrefs(ctx)
                    .edit()
                    .putString(PREFS_KEY_TOKEN, token)
                    .apply()
                result.success(null)
            }
            "getRegisteredToken" -> {
                val token = tokenPrefs(ctx).getString(PREFS_KEY_TOKEN, "")
                result.success(token)
            }
            "storeWakeHmacKey" -> {
                // Receiver's wake-HMAC secret (Epic 489.10).  Same trust
                // level as the push token — anyone holding it can forge
                // silent-push wake authenticators for this device — so it
                // rides the SAME EncryptedSharedPreferences store, under a
                // distinct prefs key, never in plaintext.  Stored base64 so
                // the raw 32 bytes survive the String-valued prefs (the
                // token store is String-typed; see PREFS_KEY_TOKEN).
                val key = call.argument<ByteArray>("key")
                if (key == null || key.size != WAKE_HMAC_KEY_LEN) {
                    result.error(
                        "BAD_WAKE_HMAC_KEY",
                        "wake-HMAC key must be $WAKE_HMAC_KEY_LEN bytes, got ${key?.size ?: 0}",
                        null,
                    )
                    return
                }
                val encoded = android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)
                tokenPrefs(ctx)
                    .edit()
                    .putString(PREFS_KEY_WAKE_HMAC, encoded)
                    .apply()
                result.success(null)
            }
            "loadWakeHmacKey" -> {
                val encoded = tokenPrefs(ctx).getString(PREFS_KEY_WAKE_HMAC, null)
                if (encoded.isNullOrEmpty()) {
                    result.success(null)
                } else {
                    result.success(android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP))
                }
            }
            "notifyDrained" -> {
                // Drain complete on the Dart side (typically called
                // from `VeilPush.drainMailbox`).  Android currently
                // does not gate background work on this — pacing is
                // handled via the foreground service notification —
                // but ack the channel call so future BG-task wiring
                // can hook here without a Dart-side API change.
                val count = call.argument<Int>("count") ?: 0
                android.util.Log.i("VeilFlutterPlugin",
                    "mailbox drained (count=$count)")
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    /// Open the EncryptedSharedPreferences store, migrating any
    /// pre-existing cleartext token from the legacy file on first
    /// access.  Throws IllegalStateException on Keystore unavailability —
    /// rare (very old / damaged devices), surfaces to the MethodChannel
    /// caller as a PlatformException the consumer can handle (we
    /// deliberately don't silently fall back to cleartext).
    private fun tokenPrefs(ctx: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val prefs = EncryptedSharedPreferences.create(
            ctx,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        if (!prefs.getBoolean(PREFS_KEY_MIGRATED, false)) {
            migrateLegacyToken(ctx, prefs)
        }
        return prefs
    }

    /// One-shot: read any stored token from the legacy cleartext file,
    /// re-store it through the encrypted prefs, then delete the legacy
    /// file so the cleartext copy doesn't linger.  Marks the
    /// migrated-flag inside the encrypted store, so this only runs
    /// once.  Failure modes (legacy file unreadable, delete fails) are
    /// non-fatal — a fresh install just enters the encrypted flow with
    /// no token, and subsequent registerDeviceToken calls populate it.
    private fun migrateLegacyToken(ctx: Context, prefs: SharedPreferences) {
        try {
            val legacy = ctx.getSharedPreferences(LEGACY_PREFS_FILE, Context.MODE_PRIVATE)
            val token = legacy.getString(PREFS_KEY_TOKEN, "") ?: ""
            val editor = prefs.edit()
            if (token.isNotEmpty()) {
                editor.putString(PREFS_KEY_TOKEN, token)
            }
            editor.putBoolean(PREFS_KEY_MIGRATED, true)
            editor.apply()
            // Best-effort: delete legacy file + its XML on disk.
            // Failures here are logged but do not block — worst case the
            // cleartext file lingers, but subsequent reads come from the
            // encrypted store thanks to the migrated-flag.
            legacy.edit().clear().apply()
            // `Context.deleteSharedPreferences` is API 24+; on API 21-23
            // the cleared-content xml stays on disk.  Cleared values
            // are safe (just the legacy file name), but removing entirely
            // is preferable when the SDK level allows.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                ctx.deleteSharedPreferences(LEGACY_PREFS_FILE)
            }
        } catch (e: Exception) {
            android.util.Log.w(
                "VeilFlutterPlugin",
                "legacy push-token migration failed: ${e.message}",
            )
            // Mark migrated anyway so we don't retry on every read —
            // if legacy is truly broken, re-trying won't help.
            prefs.edit().putBoolean(PREFS_KEY_MIGRATED, true).apply()
        }
    }
}
