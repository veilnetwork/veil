// Push-notification wake-up integration (Epic 489.10).
//
// Threat-model design:
//   * Push payload is EMPTY ("wake up and check") — message content
//     never crosses Google/Apple infrastructure.  Censor pressuring
//     FCM/APNs to leak data sees only "user-X got a wake-up at time T".
//   * Daemon wakes, queries veil for new content via the existing
//     end-to-end-encrypted message flow (mailbox / rendezvous).
//   * Push token is a separate identifier from the user's
//     `node_id` — register the token with a relay over an encrypted
//     veil channel, so Google/Apple don't link token → identity.
//
// Architectural split:
//   * **Plugin** (this code): exposes `VeilPush.handleWakeup()`
//     to be called from the consumer app's push handler.  Eagerly
//     starts foreground service, kicks daemon reconnection,
//     returns when daemon is "ready to receive".
//   * **Consumer app** (NOT this code): brings its own FCM /
//     APNs integration via popular Flutter packages
//     (`firebase_messaging`, `flutter_apns`).  Consumer's push
//     handler calls `VeilPush.handleWakeup()` upon receiving a
//     wake-push.  We don't bundle Firebase SDK because
//      (a) it adds ~5 MiB to every consumer app (some don't want push),
//      (b) Firebase SDK pulls 50+ Java methods that conflict with
//          ProGuard rules and bloat APKs unnecessarily,
//      (c) APNs setup is per-app provisioning (cert + entitlement)
//          which can't be shared across apps.
//
// Typical integration:
//
// ```dart
// // Consumer app — main.dart
// import 'package:firebase_messaging/firebase_messaging.dart';
// import 'package:veil_flutter/veil_flutter.dart';
//
// Future<void> main() async {
//   WidgetsFlutterBinding.ensureInitialized();
//   await Firebase.initializeApp();
//
//   FirebaseMessaging.onBackgroundMessage(_onPush);
//   FirebaseMessaging.onMessage.listen(_onPush);
//
//   final fcmToken = await FirebaseMessaging.instance.getToken();
//   await VeilPush.registerDeviceToken(fcmToken!);
//
//   runApp(MyApp());
// }
//
// // Top-level OR static function (FCM background-handler restriction).
// Future<void> _onPush(RemoteMessage msg) async {
//   await VeilPush.handleWakeup();
// }
// ```
//
// iOS notes:
//   * Consumer app's `Info.plist` must include `UIBackgroundModes`
//     with `remote-notification`, and the app's provisioning profile
//     must have the Push Notifications capability.
//   * `BGProcessingTask` registration in the plugin gives the daemon
//     ~30 s to drain pending operations after a silent push wakes
//     the app.

import 'dart:ffi';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart' show MethodChannel;

import 'background.dart';
import 'bindings.dart' as ffi;
import 'client.dart';
import 'secure_wipe.dart';
import 'types.dart';

const MethodChannel _channel = MethodChannel('veil_flutter/push');

/// Push-notification wake-up controls.
///
/// All methods are silent no-ops on platforms without a push system
/// (Linux, macOS, Windows).  iOS and Android have full implementations.
class VeilPush {
  VeilPush._();

  /// Phase 6.47 / Audit-H28: minimum gap between accepted wake-ups.
  ///
  /// `handleWakeup()` runs on **any** push the OS delivers. Wake-payload
  /// authentication IS available — `handleWakeup` verifies a wake-HMAC when the
  /// caller supplies `wakePayload + wakeHmacKey + receiverId`, silently
  /// rejecting forged/replayed/expired wakes. It is OPT-IN: the relay/provider
  /// that MINTS the HMAC payload is the deferred push-relay (TASKS.md 489.10
  /// slice 4.4), so until that ships — or when no key is supplied — this
  /// rate-limit is the active defence. Without the HMAC, an attacker with a
  /// leaked FCM/APNs token can spam pushes to either drain battery (DoS) or
  /// time-correlate the resulting wakeups to infer when the user is online —
  /// bounded to 1/min by [_minWakeupGap].
  ///
  /// As a stop-gap until the HMAC rolls out, gate every wake-up by a
  /// monotonic-clock timestamp cached in-process: if the
  /// previous accepted wakeup was less than [_minWakeupGap] ago,
  /// silently no-op.  60 s is conservative (legitimate pushes from a
  /// well-behaved relay do not arrive faster than the relay's own
  /// per-recipient rate-limit, currently 1/min).
  static const Duration _minWakeupGap = Duration(seconds: 60);

  /// Last accepted wake-up timestamp (process-local).  Survives
  /// across handleWakeup() calls within a single Dart isolate.
  /// Reset on process restart, which is acceptable — a cold start
  /// is itself a wake-up boundary.
  static DateTime? _lastWakeupAt;

  /// Called from consumer app's FCM/APNs push handler upon receiving
  /// a wake-up push.  Performs:
  ///
  ///   1. Starts the Android foreground service if not already running
  ///      (so the OS doesn't kill the process while we drain messages).
  ///   2. Invokes [onWake] if supplied — the place where the consumer
  ///      app's main isolate drains its mailbox / forces session
  ///      reconnection via its existing `VeilClient` handle.  The
  ///      plugin itself can't drive that drain because the FCM/APNs
  ///      background isolate has no access to the app's `VeilClient`
  ///      instance; instead the consumer's wakeup-handler closes over it.
  ///
  /// Phase 6.47 / Audit-H28: rate-limited to one accepted call per
  /// [_minWakeupGap] (60 s).  Excess calls return immediately as
  /// no-ops to limit battery DoS / online-presence-oracle attacks
  /// from anyone holding a leaked push token.
  ///
  /// Idempotent — safe to call repeatedly.  Returns when the daemon is
  /// "ready to receive": Android foreground promoted, peer reconnection
  /// requested.  Caller (FCM background handler) typically awaits before
  /// returning to Android, ensuring the OS doesn't suspend mid-fetch.
  ///
  /// On platforms without push integration (desktop), returns
  /// immediately as a no-op.
  ///
  /// **Authentication ([requireAuth])** — production callers pass
  /// `requireAuth: true` to fail CLOSED: an incomplete verify tuple
  /// (`wakePayload` / `wakeHmacKey` / `receiverId`) OR a non-[
  /// WakePayloadVerdict.valid] verdict makes the call return early
  /// (reject) BEFORE the rate-limit accept path — so a forged / replayed
  /// / expired wake never promotes the foreground service or fires
  /// [onWake].  The default is now `requireAuth: true` (fail-closed). Pass
  /// `requireAuth: false` only for the legacy back-compat path (verify only
  /// when the full tuple is supplied, otherwise wake-on-any-push gated solely
  /// by [_minWakeupGap]).
  ///
  /// Wiring the inputs: the 72-byte wake payload arrives base64-encoded
  /// under the push data key `"w"` — `message.data["w"]` on FCM, the
  /// top-level `"w"` key on APNs.  Base64-decode it to [wakePayload];
  /// supply [wakeHmacKey] from [loadWakeHmacKey] and [receiverId] from the
  /// local node id (`VeilClient.nodeId()`).
  ///
  /// **Open follow-ups** (daemon-side):
  ///   * HMAC-authenticated wake payloads are now MINTED by the daemon
  ///     when a sealed `WakeHmacKey` envelope is configured (see
  ///     `mint_wake_payload`) and VERIFIED here when the full tuple is
  ///     supplied (`requireAuth: true` by default — fail-closed). The
  ///     remaining gap is automatic per-relay HMAC-key DISTRIBUTION over
  ///     the rendezvous channel; until a relay has provisioned that key,
  ///     wakes degrade to the rate-limited ([_minWakeupGap]) wake-only
  ///     path, where a leaked push token can still drive battery-DoS /
  ///     presence-oracle attacks.
  ///   * A NO-ARG `VeilPush.drainMailbox()` convenience. The
  ///     explicit-args `drainMailbox({socketPath, receiverId,
  ///     authCookie})` already EXISTS (see below) and is fully wired;
  ///     only the zero-arg form — which would read a plugin-persisted
  ///     IPC socket path + receiver creds from platform-secure storage
  ///     so callers need pass nothing — is deferred (that persistence
  ///     is the unwired part).
  static Future<void> handleWakeup({
    Future<void> Function()? onWake,
    Uint8List? wakePayload,
    Uint8List? wakeHmacKey,
    Uint8List? receiverId,
    bool requireAuth = true,
  }) async {
    // Epic 489.10 slice 4.3.4 follow-up — HMAC verification before any
    // observable side-effect (battery promotion, daemon reconnect).
    //
    // All three of `wakePayload` / `wakeHmacKey` / `receiverId` must be
    // supplied for verification to kick in.  When supplied, a non-Valid
    // verdict aborts the wake before promoting the foreground service
    // or calling `onWake` — defeats presence-oracle and battery-DoS
    // attacks from leaked-push-token holders.
    //
    // `requireAuth` selects the policy:
    //   * true (default, production) — fail CLOSED: an incomplete tuple OR
    //     a non-Valid verdict rejects (returns early) BEFORE the rate-limit
    //     accept path, so an unauthenticated/forged wake never proceeds.
    //   * false (legacy back-compat) — verify ONLY when the full tuple is
    //     supplied; otherwise fall back to the unauthenticated
    //     wake-on-any-push path gated solely by `_minWakeupGap`.
    final hasFullVerifyTuple =
        wakePayload != null && wakeHmacKey != null && receiverId != null;
    if (requireAuth && !hasFullVerifyTuple) {
      // Fail-closed: production caller demanded auth but the verify tuple
      // is incomplete — reject before any observable side-effect.
      return;
    }
    if (hasFullVerifyTuple) {
      WakePayloadVerdict verdict;
      try {
        verdict = verifyWakePayload(
          key: wakeHmacKey,
          payload: wakePayload,
          receiverId: receiverId,
          nowSecs: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        );
      } catch (_) {
        // Defensive (audit F1): `verifyWakePayload` throws `ArgumentError` on a
        // wrong-length key/receiverId — e.g. a corrupt/truncated
        // `loadWakeHmacKey()` read. Treat ANY failure as a non-valid verdict so
        // this never throws out of an FCM/APNs background isolate (which would
        // surface as an ANR/crash); fail CLOSED rather than crash.
        return;
      }
      if (verdict != WakePayloadVerdict.valid) {
        // Silent drop.  Every non-Valid verdict (TamperedOrForged,
        // Expired, MalformedLength, unknown) maps to "do nothing
        // observable".  Operators can subscribe to internal metrics
        // through their own instrumentation if needed (e.g., log a
        // counter in the consumer-side wrap of `handleWakeup`).  Applies
        // identically whether `requireAuth` is true or false — a
        // present-but-bad tuple is always rejected.
        return;
      }
    }

    final now = DateTime.now();
    if (_lastWakeupAt != null &&
        now.difference(_lastWakeupAt!) < _minWakeupGap) {
      // Phase 6.47-H28: throttled — too many wakeups in too short
      // a window.  Silent no-op so a malicious sender cannot
      // distinguish "your token is being used" from "OS is busy".
      return;
    }
    _lastWakeupAt = now;

    if (Platform.isAndroid) {
      // Promote process to foreground so OS doesn't suspend us mid-fetch.
      await VeilBackground.start(
        title: 'Checking for new messages…',
        text: null,
      );
    }
    // Both platforms: notify the plugin's native side that a wake
    // happened (logs metric, future hook for daemon reconnect).
    if (Platform.isAndroid || Platform.isIOS) {
      await _channel.invokeMethod<void>('notifyWakeup');
    }

    // Consumer-supplied hook: drain mailbox / force reconnect via the
    // app's own `VeilClient`.  Errors are swallowed so the OS still
    // sees handleWakeup() succeed — a failed drain shouldn't block
    // foreground promotion (the user might still see the notification).
    if (onWake != null) {
      try {
        await onWake();
      } catch (_) {
        // Best-effort.  The consumer is free to instrument failures
        // through its own observability — re-throwing here would leak
        // background-handler errors to the OS, surfacing as confusing
        // ANR/crash reports.
      }
    }
  }

  /// Test-only hook: reset the wake-up rate-limit clock so unit
  /// tests can drive multiple back-to-back calls without sleeping.
  /// Production code never calls this.
  static void debugResetWakeupRateLimit() {
    _lastWakeupAt = null;
  }

  /// Seal a raw FCM/APNs token to a push-relay's X25519 public key
  /// (Epic 489.10).  Output is a fresh `Uint8List` of length
  /// `token.length + 60` (eph_pk + nonce + AEAD tag overhead) that
  /// the caller passes to a daemon via `veil_set_push_envelope`.
  ///
  /// Stateless — does NOT touch any daemon connection.  Pure crypto:
  /// per-call ephemeral X25519 keypair + ChaCha20-Poly1305 AEAD.
  /// Domain-separated under `b"veil-push-envelope-v1"`.
  ///
  /// [relayPk] MUST be exactly 32 bytes (the push-relay's published
  /// X25519 public key — typically baked into the consumer app
  /// per-deployment).  [token] MUST be ≤ 384 bytes (cap matches FCM
  /// HTTP v1 + APNs token sizes with slack).
  ///
  /// Throws [ArgumentError] on size violations; throws
  /// [VeilException] on rare crypto failures.
  static Uint8List sealPushEnvelope({
    required Uint8List token,
    required Uint8List relayPk,
  }) {
    if (relayPk.length != 32) {
      throw ArgumentError('relayPk must be 32 bytes, got ${relayPk.length}');
    }
    if (token.length > ffi.veilMaxPushTokenLen) {
      throw ArgumentError(
        'token length ${token.length} exceeds veilMaxPushTokenLen '
        '(${ffi.veilMaxPushTokenLen})',
      );
    }
    final cap = token.length + ffi.veilPushEnvelopeOverhead;
    final tokenPtr = token.isEmpty ? nullptr : calloc<Uint8>(token.length);
    final relayPtr = calloc<Uint8>(32);
    final outBuf = calloc<Uint8>(cap);
    final outLen = calloc<IntPtr>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      if (token.isNotEmpty) {
        tokenPtr.asTypedList(token.length).setAll(0, token);
      }
      relayPtr.asTypedList(32).setAll(0, relayPk);
      final rc = ffi.veilSealPushEnvelope(
        tokenPtr,
        token.length,
        relayPtr,
        outBuf,
        cap,
        outLen,
        errOut,
      );
      if (rc != ffi.veilPushOk) {
        final errPtr = errOut.value;
        final msg = errPtr == nullptr ? '<no detail>' : errPtr.toDartString();
        if (errPtr != nullptr) ffi.veilFreeString(errPtr);
        throw VeilException('seal_push_envelope failed: $msg', code: rc);
      }
      return Uint8List.fromList(outBuf.asTypedList(outLen.value));
    } finally {
      // `tokenPtr` held the plaintext push token — and, via sealWakeHmacKey,
      // the raw 32-byte wake-HMAC key. Wipe before free.
      if (tokenPtr != nullptr) {
        zeroizeNative(tokenPtr, token.length);
        calloc.free(tokenPtr);
      }
      calloc.free(relayPtr);
      calloc.free(outBuf);
      calloc.free(outLen);
      calloc.free(errOut);
    }
  }

  /// Generate a fresh 32-byte wake-HMAC key via `OsRng` (Epic 489.10
  /// slice 4.3.3).  Receivers call this once at app onboarding /
  /// identity-rotation, persist the key platform-side (iOS Keychain
  /// / Android Keystore — sibling slice), and seal it to their chosen
  /// push-relay via [sealWakeHmacKey] before publishing the resulting
  /// envelope in the rendezvous ad.
  ///
  /// Output is always 32 bytes.  Throws [VeilException] on the
  /// (extremely rare) FFI failure path.
  static Uint8List generateWakeHmacKey() {
    final out = calloc<Uint8>(ffi.veilWakeHmacKeyLen);
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = ffi.veilGenerateWakeHmacKey(out, errOut);
      if (rc != ffi.veilOk) {
        final errPtr = errOut.value;
        final msg = errPtr == nullptr ? '<no detail>' : errPtr.toDartString();
        if (errPtr != nullptr) ffi.veilFreeString(errPtr);
        throw VeilException(
          'generate_wake_hmac_key failed: $msg',
          code: rc,
        );
      }
      return Uint8List.fromList(out.asTypedList(ffi.veilWakeHmacKeyLen));
    } finally {
      // `out` held the freshly-generated 32-byte wake-HMAC key — wipe before free.
      zeroizeNative(out, ffi.veilWakeHmacKeyLen);
      calloc.free(out);
      calloc.free(errOut);
    }
  }

  /// Seal a wake-HMAC key to a push-relay's X25519 public key (Epic
  /// 489.10 slice 4.3.3).  Same envelope shape as [sealPushEnvelope]
  /// — pure crypto, no daemon dependency.  The resulting bytes are
  /// what the receiver puts into `wake_hmac_envelope` on the rendezvous
  /// ad (RendezvousAd v4, sibling slice 4.3.2).
  ///
  /// [key] MUST be exactly 32 bytes (use [generateWakeHmacKey]).
  /// [relayPk] MUST be exactly 32 bytes (the chosen push-relay's
  /// X25519 pubkey, fetched via `veil_get_relay_x25519_pubkey`).
  ///
  /// Output length is `key.length + 60` = 92 bytes — fits within the
  /// `MAX_WAKE_HMAC_ENVELOPE_LEN = 128` cap on the rendezvous-ad
  /// wire field with slack for future rotation-epoch metadata.
  ///
  /// Throws [ArgumentError] on size violations; [VeilException] on
  /// rare crypto failures.
  static Uint8List sealWakeHmacKey({
    required Uint8List key,
    required Uint8List relayPk,
  }) {
    if (key.length != ffi.veilWakeHmacKeyLen) {
      throw ArgumentError(
        'key must be ${ffi.veilWakeHmacKeyLen} bytes, got ${key.length}',
      );
    }
    // Reuse the existing push-envelope sealing primitive — same threat
    // model (sealed blob to relay's X25519 pubkey, opaque to senders).
    // The size check above pins us at 32 B, well within the push-token
    // cap, so `sealPushEnvelope` will not reject.
    return sealPushEnvelope(token: key, relayPk: relayPk);
  }

  /// Verify a wake-up payload delivered via OS push (FCM / APNs body),
  /// returning the verdict (Epic 489.10 slice 4.3.3).
  ///
  /// Receiver's `handleWakeup` call should invoke this BEFORE any
  /// expensive veil work (daemon reconnect, mailbox drain).  Only
  /// proceed when `verdict == WakePayloadVerdict.valid`.
  ///
  /// [key] MUST be exactly 32 bytes (the receiver's persisted
  /// `WakeHmacKey`).  [receiverId] MUST be 32 bytes (local node_id).
  /// [payload] is the raw 72-byte wire from the push body.  [nowSecs]
  /// is the receiver's current unix time.
  static WakePayloadVerdict verifyWakePayload({
    required Uint8List key,
    required Uint8List payload,
    required Uint8List receiverId,
    required int nowSecs,
  }) {
    if (key.length != ffi.veilWakeHmacKeyLen) {
      throw ArgumentError(
        'key must be ${ffi.veilWakeHmacKeyLen} bytes, got ${key.length}',
      );
    }
    if (receiverId.length != 32) {
      throw ArgumentError(
        'receiverId must be 32 bytes, got ${receiverId.length}',
      );
    }
    final keyPtr = calloc<Uint8>(ffi.veilWakeHmacKeyLen);
    final ridPtr = calloc<Uint8>(32);
    final payloadPtr =
        payload.isEmpty ? nullptr : calloc<Uint8>(payload.length);
    final outVerdict = calloc<Int32>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      keyPtr.asTypedList(ffi.veilWakeHmacKeyLen).setAll(0, key);
      ridPtr.asTypedList(32).setAll(0, receiverId);
      if (payload.isNotEmpty) {
        payloadPtr.asTypedList(payload.length).setAll(0, payload);
      }
      final rc = ffi.veilVerifyWakeHmac(
        keyPtr,
        payloadPtr,
        payload.length,
        ridPtr,
        nowSecs,
        outVerdict,
        errOut,
      );
      if (rc != ffi.veilOk) {
        final errPtr = errOut.value;
        final msg = errPtr == nullptr ? '<no detail>' : errPtr.toDartString();
        if (errPtr != nullptr) ffi.veilFreeString(errPtr);
        throw VeilException(
          'verify_wake_hmac failed: $msg',
          code: rc,
        );
      }
      return WakePayloadVerdict.fromWire(outVerdict.value);
    } finally {
      // `keyPtr` held a copy of the secret 32-byte wake-HMAC key — wipe before free.
      zeroizeNative(keyPtr, ffi.veilWakeHmacKeyLen);
      calloc.free(keyPtr);
      calloc.free(ridPtr);
      if (payloadPtr != nullptr) calloc.free(payloadPtr);
      calloc.free(outVerdict);
      calloc.free(errOut);
    }
  }

  /// Register the device's push token with the plugin's local store.
  /// Consumer app retrieves the token from FCM/APNs and passes it
  /// here; plugin persists it locally so the daemon can include it
  /// in outgoing rendezvous-ad announcements (relay knows where to
  /// push wake-ups for THIS receiver).
  ///
  /// Tokens are device-scoped and rotate occasionally (FCM returns a
  /// new token after app reinstall / data clear; APNs after device
  /// restore).  Consumer should call `registerDeviceToken` again when
  /// the SDK reports a token change.
  ///
  /// Empty / null tokens are accepted as a no-op (clears any stored
  /// token).  Useful when user disables push in app settings.
  static Future<void> registerDeviceToken(String? token) async {
    if (!Platform.isAndroid && !Platform.isIOS) return;
    await _channel.invokeMethod<void>('registerDeviceToken', <String, dynamic>{
      'token': token ?? '',
    });
  }

  /// Get the most recently registered token, or `null` if not set.
  /// Useful when the consumer app's UI wants to display "push
  /// configured" status.
  static Future<String?> getRegisteredToken() async {
    if (!Platform.isAndroid && !Platform.isIOS) return null;
    final result = await _channel.invokeMethod<String?>('getRegisteredToken');
    return (result?.isEmpty ?? true) ? null : result;
  }

  /// Persist the device's raw 32-byte wake-HMAC key in platform-secure
  /// storage (iOS Keychain / Android Keystore — native handlers live in
  /// the sibling Kotlin/Swift slice).  The receiver later loads it via
  /// [loadWakeHmacKey] to authenticate incoming wake pushes inside
  /// [handleWakeup].
  ///
  /// [key] is the raw key from [generateWakeHmacKey] (32 bytes).  Silent
  /// no-op on platforms without a push channel (desktop).
  static Future<void> storeWakeHmacKey(Uint8List key) async {
    if (!Platform.isAndroid && !Platform.isIOS) return;
    await _channel.invokeMethod<void>('storeWakeHmacKey', <String, dynamic>{
      'key': key,
    });
  }

  /// Load the device's persisted raw wake-HMAC key, or `null` if none
  /// has been stored (or on platforms without a push channel).  Feed the
  /// result into [handleWakeup]'s `wakeHmacKey` (with `requireAuth:
  /// true`) so forged / replayed / expired wakes are rejected.
  static Future<Uint8List?> loadWakeHmacKey() async {
    if (!Platform.isAndroid && !Platform.isIOS) return null;
    final result = await _channel.invokeMethod<Uint8List?>('loadWakeHmacKey');
    return (result == null || result.isEmpty) ? null : result;
  }

  /// One-shot receiver onboarding for push wake-HMAC end-to-end: mints a
  /// fresh wake-HMAC key, persists it device-side, seals it to the chosen
  /// push-relay, and publishes the sealed envelope in the daemon's
  /// rendezvous ad.  Call once at onboarding / identity-rotation.
  ///
  /// Composes the existing primitives:
  ///   1. [generateWakeHmacKey] — fresh 32-byte key via `OsRng`.
  ///   2. [storeWakeHmacKey] — persist raw key (iOS Keychain / Android
  ///      Keystore) so [handleWakeup] can verify wakes later.
  ///   3. [sealWakeHmacKey] — seal the key to [relayPk] (X25519).
  ///   4. [VeilClient.setWakeHmacEnvelope] — register the sealed
  ///      envelope so the daemon embeds it in every RendezvousAd refresh.
  ///
  /// [relayPk] (32 B) is the push-relay's X25519 pubkey; [rendezvousNodeId]
  /// (32 B) + [authCookie] (16 B) identify the receiver's rendezvous
  /// registration on the daemon (same pair used by
  /// [VeilClient.setWakeHmacEnvelope]).  Returns the
  /// `setWakeHmacEnvelope` result (`true` = OK, `false` = no matching
  /// rendezvous); throws [VeilException] / [ArgumentError] on the
  /// underlying failures.
  ///
  /// The raw key never leaves the device except sealed — only the device
  /// store ([storeWakeHmacKey]) and the relay-sealed envelope hold it.
  static Future<bool> generateAndRegisterWakeHmacKey({
    required VeilClient client,
    required Uint8List relayPk,
    required Uint8List rendezvousNodeId,
    required Uint8List authCookie,
  }) async {
    final key = generateWakeHmacKey();
    await storeWakeHmacKey(key);
    final envelope = sealWakeHmacKey(key: key, relayPk: relayPk);
    return client.setWakeHmacEnvelope(
      rendezvousNodeId: rendezvousNodeId,
      authCookie: authCookie,
      envelope: envelope,
    );
  }

  /// Drain a receiver's mailbox in one call, returning the fetched blobs.
  ///
  /// Convenience wrapper for the FCM/APNs background-handler pattern:
  /// instead of plumbing an `VeilClient` through to the consumer's
  /// `_onPush` (which fails in a separate Dart isolate where the app's
  /// main-isolate `VeilClient` is unreachable), the handler opens
  /// a fresh client from the saved IPC socket path, drains, and closes.
  ///
  /// Pre-conditions:
  ///   * Daemon process must already be running (push wake-up assumes
  ///     daemon is alive).  Caller can use [VeilPush.handleWakeup]
  ///     to promote the Android foreground service first.
  ///   * The receiver's [authCookie] must be the 16-byte rendezvous-
  ///     cookie that the receiver-side rendezvous-ad publishes; passing
  ///     a wrong cookie surfaces as `mailbox_fetch_count failed`.
  ///
  /// Returns an empty list when no blobs are pending.  Throws
  /// [VeilException] on transport / IPC errors.  Always closes the
  /// fresh client connection before returning (or throwing) — caller
  /// does not own its lifetime.
  ///
  /// Typical use in a top-level FCM background handler:
  /// ```dart
  /// Future<void> _onPush(RemoteMessage msg) async {
  ///   await VeilPush.handleWakeup(onWake: () async {
  ///     final blobs = await VeilPush.drainMailbox(
  ///       socketPath: kVeilSocketPath,
  ///       receiverId: kLocalNodeId,
  ///       authCookie: kRendezvousCookie,
  ///     );
  ///     // ... process blobs locally (encrypted-storage handoff) ...
  ///   });
  /// }
  /// ```
  ///
  /// **Design note**: this is explicit-args ONLY (`socketPath` / `receiverId`
  /// / `authCookie`) — there is NO no-arg `VeilPush.drainMailbox()` form,
  /// and none is promised (audit: don't rely on one appearing). Consumers
  /// store these locally after pairing (the receiver's app learns both values
  /// then). A no-arg convenience backed by platform-secure storage
  /// (Keychain / Keystore) was considered but is not implemented.
  static Future<List<MailboxBlob>> drainMailbox({
    required String socketPath,
    required Uint8List receiverId,
    required Uint8List authCookie,
  }) async {
    final client = await VeilClient.connect(socketPath);
    try {
      final blobs = await client.mailbox.fetch(
        receiverId: receiverId,
        authCookie: authCookie,
      );
      // Notify the native side that drain has completed so an
      // iOS BGProcessingTask currently armed by [handleWakeup] can
      // `setTaskCompleted` precisely instead of padding to its
      // hardcoded fallback timeout.  Best-effort: silent no-op on
      // platforms without a push channel (desktop) and swallowed errors
      // on transient channel failures (the BG task's own timeout
      // catches any stall).
      if (Platform.isAndroid || Platform.isIOS) {
        try {
          await _channel.invokeMethod<void>(
            'notifyDrained',
            <String, dynamic>{'count': blobs.length},
          );
        } catch (_) {
          // Best-effort signaling — iOS BG task has its own 28-s
          // fallback timeout, and Android currently treats the
          // notification as a stub (drain pacing is handled through
          // the foreground service notification rather than a
          // BG-task window).
        }
      }
      return blobs;
    } finally {
      client.close();
    }
  }
}
