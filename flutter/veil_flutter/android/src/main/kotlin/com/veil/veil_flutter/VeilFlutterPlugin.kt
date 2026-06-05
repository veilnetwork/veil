// MethodChannel bridge for foreground-service control от Dart side
// (Epic 489.6).
//
// The veil-flutter plugin is primarily an `ffiPlugin` (Dart-FFI
// directly into the Rust .so), но Android-specific lifecycle hooks
// — namely starting / stopping а foreground service — require а
// JNI thunk because Android's `startForegroundService` is а Java API
// not exposed via NDK.
//
// MethodChannel surface:
//   * `startBackgroundService` — args: { title?, text? } → null
//   * `stopBackgroundService`  — args: {}                 → null

package com.veil.veil_flutter

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
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
        // target.  Existing installs may have а cleartext token here;
        // we move it к the encrypted store on first read so older app
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
                val intent = Intent(ctx, VeilDaemonService::class.java).apply {
                    action = VeilDaemonService.ACTION_START
                    if (title != null) putExtra(VeilDaemonService.EXTRA_NOTIFICATION_TITLE, title)
                    if (text  != null) putExtra(VeilDaemonService.EXTRA_NOTIFICATION_TEXT, text)
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
                // rides the SAME EncryptedSharedPreferences store, under а
                // distinct prefs key, never в plaintext.  Stored base64 so
                // the raw 32 bytes survive the String-valued prefs (the
                // token store is String-typed; см. PREFS_KEY_TOKEN).
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
                // can hook here без а Dart-side API change.
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
    /// rare (very old / damaged devices), surfaces к the MethodChannel
    /// caller as а PlatformException the consumer can handle (we
    /// deliberately don't silently fall back к cleartext).
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

    /// One-shot: read any stored token из the legacy cleartext file,
    /// re-store it через the encrypted prefs, then delete the legacy
    /// file so the cleartext copy doesn't linger.  Marks the
    /// migrated-flag inside the encrypted store, so this only runs
    /// once.  Failure modes (legacy file unreadable, delete fails) ара
    /// non-fatal — а fresh install just enters the encrypted flow с
    /// no token, и subsequent registerDeviceToken calls populate it.
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
            // Failures here are logged but не block — worst case the
            // cleartext file lingers, но subsequent reads come из the
            // encrypted store thanks к the migrated-flag.
            legacy.edit().clear().apply()
            // `Context.deleteSharedPreferences` is API 24+; on API 21-23
            // the cleared-content xml stays on disk.  Cleared values
            // ара safe (just the legacy file name), но removing entirely
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
            // если legacy is truly broken, re-trying won't help.
            prefs.edit().putBoolean(PREFS_KEY_MIGRATED, true).apply()
        }
    }
}
