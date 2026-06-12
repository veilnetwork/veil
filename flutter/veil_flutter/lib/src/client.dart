// High-level idiomatic Dart wrapper around the veilclient-ffi C API.
//
// Threading: every FFI call is synchronous from Dart's POV (the Rust
// runtime owns its own tokio worker pool, the FFI surface block_on's
// internally).  We schedule those calls onto an Isolate.run() so they
// don't stall the UI isolate during connect/bind handshakes.
//
// Memory: every Pointer<Utf8> from C must be freed with veilFreeString
// after consumption.  Every malloc'd buffer we hand to FFI is freed in
// a try/finally.  Pointer<VeilHandle> + Pointer<VeilApp> are
// owned by Dart wrappers and freed on close().

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'mailbox.dart';
import 'secure_wipe.dart';
import 'stream.dart';
import 'types.dart';

String _readErrAndFree(Pointer<Pointer<Utf8>> errOut) {
  final errPtr = errOut.value;
  if (errPtr == nullptr) return '<no detail>';
  final msg = errPtr.toDartString();
  ffi.veilFreeString(errPtr);
  errOut.value = nullptr;
  return msg;
}

/// GC-time safety-net: if a Dart `VeilClient` becomes unreachable
/// without calling [VeilClient.close], the finalizer fires
/// `veil_close` to release the daemon-side handle.  Explicit close
/// detaches the finalizer first to avoid double-free (the C-side magic
/// guard would catch it anyway, but a clean detach is cheaper).
final _veilClientFinalizer = NativeFinalizer(
  ffi.veilCloseFinalizerPtr.cast<NativeFinalizerFunction>(),
);

/// Connected veil client.  Construct via [VeilClient.connect].
class VeilClient implements Finalizable {
  VeilClient._(this._handle, this.socketPath) {
    _veilClientFinalizer.attach(this, _handle.cast(), detach: this);
  }

  final Pointer<ffi.VeilHandle> _handle;

  /// Path used to open this connection (verbatim from [connect]).  Retained
  /// so background-handler helpers like [VeilPush.drainMailbox] can
  /// re-open a fresh client from a separate Dart isolate without
  /// requiring the consumer to thread the path through the app's own
  /// state.  Treated as an anchor (parent-dir ipc.port / ipc.token
  /// sidecars detected automatically), same as the `connect` arg.
  final String socketPath;

  bool _closed = false;

  StreamController<VeilEvent>? _eventController;
  NativeCallable<ffi.VeilEventCbNative>? _eventCallable;

  /// Lazy-constructed mailbox surface sharing this client's daemon
  /// connection.  Re-use the same instance across calls — Mailbox
  /// is stateless on the Dart side, the borrowed handle gives it
  /// access to the daemon.
  VeilMailbox? _mailbox;

  /// Connect to the veil daemon's IPC socket and perform the
  /// APP_HELLO handshake.  Throws [VeilException] on failure.
  ///
  /// `socketPath` is treated as an anchor — if its parent dir contains
  /// `ipc.port` + `ipc.token` sidecars, TCP-loopback with token auth is
  /// used; otherwise plain Unix socket.
  static Future<VeilClient> connect(String socketPath) async {
    return Future(() {
      final pathC = socketPath.toNativeUtf8();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final h = ffi.veilConnect(pathC, errOut);
        if (h == nullptr) {
          throw VeilException('connect failed: ${_readErrAndFree(errOut)}');
        }
        return VeilClient._(h, socketPath);
      } finally {
        calloc.free(pathC);
        calloc.free(errOut);
      }
    });
  }

  /// Mailbox surface — deposit blobs to offline recipients and fetch
  /// blobs deposited for this node (Epic 489.3).  Lazily constructed
  /// on first access; subsequent calls return the same instance.
  /// Throws [VeilException] if called after [close].
  VeilMailbox get mailbox {
    _ensureOpen();
    return _mailbox ??= VeilMailbox.forHandle(_handle);
  }

  /// Subscribe to push events from the daemon.  Replaces any previous
  /// subscription — single-subscriber semantics matches the FFI
  /// surface.  The returned stream is `broadcast` so multiple Dart
  /// listeners can fan out from the same FFI subscription.
  ///
  /// Closing the stream subscription does NOT close the FFI handler;
  /// call [close] to fully tear down.
  Stream<VeilEvent> events() {
    _ensureOpen();
    if (_eventController != null) {
      return _eventController!.stream;
    }
    final controller = StreamController<VeilEvent>.broadcast();
    final callable = NativeCallable<ffi.VeilEventCbNative>.listener(
      (Pointer<Void> _, int kind, Pointer<Uint8> payload, int len) {
        final bytes = len > 0
            ? Uint8List.fromList(payload.asTypedList(len))
            : Uint8List(0);
        // cycle-7 H6: the native payload buffer is now callee-owned — free it
        // immediately after copying. This callback runs on the isolate AFTER
        // the Rust frame returned (NativeCallable.listener defers), so reading
        // `payload` here was a use-after-free before the buffer became owned.
        if (len > 0) {
          ffi.veilFreeBuf(payload, len);
        }
        controller.add(VeilEvent(
          kind: VeilEventKind.fromWire(kind),
          rawKind: kind,
          payload: bytes,
        ));
      },
    );
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = ffi.veilSetEventHandler(
        _handle,
        callable.nativeFunction,
        nullptr,
        errOut,
      );
      if (rc != ffi.veilOk) {
        callable.close();
        controller.close();
        throw VeilException(
            'set_event_handler failed: ${_readErrAndFree(errOut)}',
            code: rc);
      }
    } finally {
      calloc.free(errOut);
    }
    _eventController = controller;
    _eventCallable = callable;
    return controller.stream;
  }

  /// Read the daemon's `node_id` (32 bytes BLAKE3 of its signing pubkey).
  Future<Uint8List> nodeId() async {
    _ensureOpen();
    return Future(() {
      final out = calloc<Uint8>(32);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilGetNodeId(_handle, out, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'get_node_id failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
        return Uint8List.fromList(out.asTypedList(32));
      } finally {
        calloc.free(out);
        calloc.free(errOut);
      }
    });
  }

  /// Register this node as a LOCATION-anonymous (onion) service: the daemon
  /// builds an onion circuit to a rendezvous relay (which never learns this
  /// node's location) and publishes the ad so clients can reach it by identity.
  /// [hopCount] is clamped to ≥ 2 by the daemon. Throws on rejection (e.g. no
  /// relays available yet — retry after a back-off). Connection-level.
  Future<void> registerOnionService({int hopCount = 3}) async {
    _ensureOpen();
    return Future(() {
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilRegisterOnionService(_handle, hopCount, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'register_onion_service failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(errOut);
      }
    });
  }

  /// Send [data] to a LOCATION-anonymous (onion) service addressed by its
  /// Ed25519 IDENTITY key ([serviceIdentityVk], 32 bytes — a `.onion`-like
  /// handle), NOT its node_id. The daemon resolves the service's unlinkable
  /// per-period blinded descriptor, decrypts it (we know the identity), and
  /// routes over an onion circuit. [hopCount] is clamped to ≥ 2 by the daemon.
  /// Fire-and-forget (no end-to-end ack); throws on rejection (e.g. no
  /// resolvable descriptor — the service is offline or hasn't published).
  Future<void> sendToOnionService({
    required Uint8List serviceIdentityVk,
    required Uint8List targetAppId,
    required int targetEndpointId,
    required Uint8List data,
    int hopCount = 3,
  }) async {
    _ensureOpen();
    if (serviceIdentityVk.length != 32 || targetAppId.length != 32) {
      throw ArgumentError('service_identity_vk and target_app_id must be 32 bytes');
    }
    return Future(() {
      final idVk = calloc<Uint8>(32);
      final appId = calloc<Uint8>(32);
      final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
      final errOut = calloc<Pointer<Utf8>>();
      try {
        idVk.asTypedList(32).setAll(0, serviceIdentityVk);
        appId.asTypedList(32).setAll(0, targetAppId);
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc = ffi.veilSendToOnionService(_handle, idVk, appId,
            targetEndpointId, hopCount, dataPtr, data.length, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'send_to_onion_service failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(idVk);
        calloc.free(appId);
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Consume a bootstrap-invite URI (Epic 489.7) — typically scanned
  /// from a QR code or pasted from a sharing channel.  The daemon
  /// decodes plain / encrypted / signed formats automatically and
  /// (on success) registers the encoded peer for outbound dial.
  ///
  /// [uri] is the full invite string (the bytes from the QR / paste).
  /// [password] — UTF-8 passphrase for encrypted invites.  Pass `null`
  /// for plain or signed invites; daemon will return
  /// [JoinBootstrapStatus.passwordRequired] if needed.
  /// [expectedIssuerPk] — base64-encoded issuer Ed25519 pubkey used to
  /// verify signed invites.  Required for `veil:signed-invite?…`
  /// URIs (else verify fails with [JoinBootstrapStatus.signatureInvalid]);
  /// ignored for plain/encrypted.
  ///
  /// Returns a [JoinBootstrapResult] describing the outcome.  Throws
  /// [VeilException] only on transport-level failures (IPC stall,
  /// daemon panic) — invalid URIs / wrong passwords are NOT exceptions,
  /// they surface as [JoinBootstrapStatus] codes the UI should branch on.
  Future<JoinBootstrapResult> joinBootstrapUri({
    required String uri,
    String? password,
    String? expectedIssuerPk,
  }) async {
    _ensureOpen();
    return Future(() {
      final uriC = uri.toNativeUtf8();
      final pwC = (password == null) ? nullptr : password.toNativeUtf8();
      final pkC = (expectedIssuerPk == null)
          ? nullptr
          : expectedIssuerPk.toNativeUtf8();
      final outNodeId = calloc<Uint8>(32);
      final outStatus = calloc<Uint8>();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilJoinBootstrapUri(
          _handle,
          uriC,
          pwC,
          pkC,
          outNodeId,
          outStatus,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'join_bootstrap_uri failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        // err_out on success-paths carries a detail string (decode
        // error message or similar) — surface it but don't throw.
        final errPtr = errOut.value;
        String? detail;
        if (errPtr != nullptr) {
          detail = errPtr.toDartString();
          ffi.veilFreeString(errPtr);
          errOut.value = nullptr;
        }
        return JoinBootstrapResult(
          status: JoinBootstrapStatus.fromWire(outStatus.value),
          peerNodeId: Uint8List.fromList(outNodeId.asTypedList(32)),
          detail: detail,
        );
      } finally {
        calloc.free(uriC);
        if (pwC != nullptr) {
          // Wipe the passphrase bytes before releasing the native buffer
          // (mirrors the cookie/HMAC zeroize) so the secret can't linger in
          // freed heap / a core dump.
          zeroizeNative(pwC.cast<Uint8>(), pwC.length);
          calloc.free(pwC);
        }
        if (pkC != nullptr) calloc.free(pkC);
        calloc.free(outNodeId);
        calloc.free(outStatus);
        calloc.free(errOut);
      }
    });
  }

  /// Ask the daemon to assemble a bootstrap-invite URI from its own
  /// `[identity]` + first `[[listen]]` advertise (Epic 489.7 generator
  /// side, "share my invite" flow).  Returns the canonical URI suitable
  /// for encoding as a QR code OR pasting into a sharing channel.
  ///
  /// [password] = `null` → plain `veil:bootstrap?…` URI (most
  /// common, fastest QR render).  [password] = `'…'` → encrypted
  /// `veil:pair?…` envelope (Argon2id-derived KEK).  Empty /
  /// whitespace-only passwords surface as
  /// [CreateBootstrapInviteStatus.badPassword] so the UI can re-prompt
  /// rather than emitting an envelope encrypted under a trivial key.
  ///
  /// Throws [VeilException] only on transport-level failures (IPC
  /// stall, daemon panic) — missing-config / invalid-password come
  /// through as status codes the UI should branch on.
  Future<CreateBootstrapInviteResult> createBootstrapInvite({
    String? password,
  }) async {
    _ensureOpen();
    return Future(() {
      final pwC = (password == null) ? nullptr : password.toNativeUtf8();
      final outStatus = calloc<Uint8>();
      final outUri = calloc<Pointer<Utf8>>();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilCreateBootstrapInvite(
          _handle,
          pwC,
          outStatus,
          outUri,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'create_bootstrap_invite failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        final status = CreateBootstrapInviteStatus.fromWire(outStatus.value);
        final uriPtr = outUri.value;
        String uri = '';
        if (uriPtr != nullptr) {
          uri = uriPtr.toDartString();
          ffi.veilFreeString(uriPtr);
          outUri.value = nullptr;
        }
        // Detail (if any) are written via err_out — see FFI implementation.
        final errPtr = errOut.value;
        String? detail;
        if (errPtr != nullptr) {
          detail = errPtr.toDartString();
          ffi.veilFreeString(errPtr);
          errOut.value = nullptr;
        }
        return CreateBootstrapInviteResult(
          status: status,
          uri: uri,
          detail: detail,
        );
      } finally {
        if (pwC != nullptr) {
          // Wipe the passphrase bytes before releasing the native buffer
          // (mirrors the cookie/HMAC zeroize) so the secret can't linger in
          // freed heap / a core dump.
          zeroizeNative(pwC.cast<Uint8>(), pwC.length);
          calloc.free(pwC);
        }
        calloc.free(outStatus);
        calloc.free(outUri);
        calloc.free(errOut);
      }
    });
  }

  /// Register a sealed push envelope with the daemon (Epic 489.10).
  /// Daemon attaches it to the matching rendezvous-publisher entry so
  /// the next maintenance tick re-signs every active RendezvousAd with
  /// the new envelope.  Pass an empty [envelope] (`Uint8List(0)`) to
  /// clear push registration without disrupting the rendezvous itself —
  /// use case: user disabled push in settings.
  ///
  /// [rendezvousNodeId] and [authCookie] must match a previously-
  /// registered rendezvous-publisher entry (the daemon's
  /// `register_rendezvous_publisher_with_push` call).
  ///
  /// [envelope] must already be sealed against the push-relay's
  /// X25519 pubkey — typically built via
  /// [VeilPush.sealPushEnvelope].  Daemon does NOT seal — keeps
  /// the FCM/APNs token out of daemon plaintext.
  ///
  /// Throws [VeilException] on transport / argument errors.
  /// Returns true on OK, false on NoMatchingRendezvous (graceful
  /// "no active rendezvous to attach to"); throws on TOO_LARGE.
  Future<bool> setPushEnvelope({
    required Uint8List rendezvousNodeId,
    required Uint8List authCookie,
    required Uint8List envelope,
  }) async {
    _ensureOpen();
    if (rendezvousNodeId.length != 32) {
      throw ArgumentError(
          'rendezvousNodeId must be 32 bytes, got ${rendezvousNodeId.length}');
    }
    if (authCookie.length != 16) {
      throw ArgumentError(
          'authCookie must be 16 bytes, got ${authCookie.length}');
    }
    if (envelope.length > ffi.veilMaxPushEnvelopeLen) {
      throw ArgumentError(
        'envelope length ${envelope.length} exceeds veilMaxPushEnvelopeLen '
        '(${ffi.veilMaxPushEnvelopeLen})',
      );
    }
    return Future(() {
      final rzPtr = calloc<Uint8>(32);
      final cookiePtr = calloc<Uint8>(16);
      final envPtr =
          envelope.isEmpty ? nullptr : calloc<Uint8>(envelope.length);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        rzPtr.asTypedList(32).setAll(0, rendezvousNodeId);
        cookiePtr.asTypedList(16).setAll(0, authCookie);
        if (envelope.isNotEmpty) {
          envPtr.asTypedList(envelope.length).setAll(0, envelope);
        }
        final rc = ffi.veilSetPushEnvelope(
          _handle,
          rzPtr,
          cookiePtr,
          envPtr,
          envelope.length,
          errOut,
        );
        switch (rc) {
          case ffi.veilPushOk:
            return true;
          case ffi.veilPushNoRendezvous:
            return false;
          case ffi.veilPushTooLarge:
            throw VeilException('envelope exceeds 512 B cap', code: rc);
          default:
            throw VeilException(
              'set_push_envelope failed: ${_readErrAndFree(errOut)}',
              code: rc,
            );
        }
      } finally {
        calloc.free(rzPtr);
        // authCookie is a 16-byte mailbox capability secret — wipe before free.
        zeroizeNative(cookiePtr, 16);
        calloc.free(cookiePtr);
        if (envPtr != nullptr) calloc.free(envPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Register a sealed wake-HMAC envelope with the daemon (Epic 489.10
  /// slice 4.3.4 — analog to [setPushEnvelope]).  The daemon embeds
  /// the envelope in every subsequent signed RendezvousAd refresh.
  ///
  /// `envelope` is a sealed [`veil_crypto::wake_hmac::WakeHmacKey`]
  /// (build via [VeilPush.sealWakeHmacKey]).  Empty envelope clears
  /// the registration — receiver falls back to the legacy rate-limited
  /// wake path.
  ///
  /// Returns `true` on OK, `false` on NoMatchingRendezvous; throws on
  /// TOO_LARGE or other failure.
  Future<bool> setWakeHmacEnvelope({
    required Uint8List rendezvousNodeId,
    required Uint8List authCookie,
    required Uint8List envelope,
  }) async {
    _ensureOpen();
    if (rendezvousNodeId.length != 32) {
      throw ArgumentError(
          'rendezvousNodeId must be 32 bytes, got ${rendezvousNodeId.length}');
    }
    if (authCookie.length != 16) {
      throw ArgumentError(
          'authCookie must be 16 bytes, got ${authCookie.length}');
    }
    if (envelope.length > ffi.veilMaxWakeHmacEnvelopeLen) {
      throw ArgumentError(
        'envelope length ${envelope.length} exceeds veilMaxWakeHmacEnvelopeLen '
        '(${ffi.veilMaxWakeHmacEnvelopeLen})',
      );
    }
    return Future(() {
      final rzPtr = calloc<Uint8>(32);
      final cookiePtr = calloc<Uint8>(16);
      final envPtr =
          envelope.isEmpty ? nullptr : calloc<Uint8>(envelope.length);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        rzPtr.asTypedList(32).setAll(0, rendezvousNodeId);
        cookiePtr.asTypedList(16).setAll(0, authCookie);
        if (envelope.isNotEmpty) {
          envPtr.asTypedList(envelope.length).setAll(0, envelope);
        }
        final rc = ffi.veilSetWakeHmacEnvelope(
          _handle,
          rzPtr,
          cookiePtr,
          envPtr,
          envelope.length,
          errOut,
        );
        switch (rc) {
          case ffi.veilPushOk:
            return true;
          case ffi.veilPushNoRendezvous:
            return false;
          case ffi.veilPushTooLarge:
            throw VeilException('wake_hmac_envelope exceeds 128 B cap',
                code: rc);
          default:
            throw VeilException(
              'set_wake_hmac_envelope failed: ${_readErrAndFree(errOut)}',
              code: rc,
            );
        }
      } finally {
        calloc.free(rzPtr);
        // authCookie is a 16-byte mailbox capability secret — wipe before free.
        zeroizeNative(cookiePtr, 16);
        calloc.free(cookiePtr);
        if (envPtr != nullptr) calloc.free(envPtr);
        calloc.free(errOut);
      }
    });
  }

  // ── Multi-device pairing (Epic 489.8) ─────────────────────────────

  /// Source-side: generate a pair-invite URI + initialize ceremony.
  /// [password] is the master_sk decryption passphrase (required —
  /// daemon's `master.enc` lives encrypted at rest).
  Future<PairCreateInviteResult> pairSourceCreateInvite({
    required String password,
  }) async {
    _ensureOpen();
    return Future(() {
      final pwC = password.toNativeUtf8();
      final outStatus = calloc<Uint8>();
      final outUri = calloc<Pointer<Utf8>>();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilPairSourceCreateInvite(
          _handle,
          pwC,
          outStatus,
          outUri,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'pair_source_create_invite failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        final status = PairSourceStatus.fromWire(outStatus.value);
        String uri = '';
        final uriPtr = outUri.value;
        if (uriPtr != nullptr) {
          uri = uriPtr.toDartString();
          ffi.veilFreeString(uriPtr);
          outUri.value = nullptr;
        }
        String? detail;
        final errPtr = errOut.value;
        if (errPtr != nullptr) {
          detail = errPtr.toDartString();
          ffi.veilFreeString(errPtr);
          errOut.value = nullptr;
        }
        return PairCreateInviteResult(status: status, uri: uri, detail: detail);
      } finally {
        // Wipe the passphrase bytes before releasing the native buffer.
        zeroizeNative(pwC.cast<Uint8>(), pwC.length);
        calloc.free(pwC);
        calloc.free(outStatus);
        calloc.free(outUri);
        calloc.free(errOut);
      }
    });
  }

  /// Source-side: process Hello bytes from Target, returns Cert
  /// bytes + 6-digit OOB code.
  Future<PairOobResult> pairSourceHandleHello({
    required Uint8List helloBytes,
  }) async {
    _ensureOpen();
    return Future(() => _pairOobCall(
          helloBytes,
          (helloPtr, helloLen, statusPtr, oobPtr, certBuf, certCap, certLen,
                  errOut) =>
              ffi.veilPairSourceHandleHello(
            _handle,
            helloPtr,
            helloLen,
            statusPtr,
            oobPtr,
            certBuf,
            certCap,
            certLen,
            errOut,
          ),
        ));
  }

  /// Source-side: process Confirm bytes — finalizes the ceremony.
  Future<PairStatusResult> pairSourceHandleConfirm({
    required Uint8List confirmBytes,
  }) async {
    _ensureOpen();
    return Future(() {
      final confirmPtr =
          confirmBytes.isEmpty ? nullptr : calloc<Uint8>(confirmBytes.length);
      final outStatus = calloc<Uint8>();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        if (confirmBytes.isNotEmpty) {
          confirmPtr.asTypedList(confirmBytes.length).setAll(0, confirmBytes);
        }
        final rc = ffi.veilPairSourceHandleConfirm(
          _handle,
          confirmPtr,
          confirmBytes.length,
          outStatus,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'pair_source_handle_confirm failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        final status = PairSourceStatus.fromWire(outStatus.value);
        String? detail;
        final errPtr = errOut.value;
        if (errPtr != nullptr) {
          detail = errPtr.toDartString();
          ffi.veilFreeString(errPtr);
          errOut.value = nullptr;
        }
        return PairStatusResult(status: status, detail: detail);
      } finally {
        if (confirmPtr != nullptr) calloc.free(confirmPtr);
        calloc.free(outStatus);
        calloc.free(errOut);
      }
    });
  }

  /// Target-side: consume scanned URI, returns Hello bytes to relay
  /// back to Source.
  Future<PairFrameResult> pairTargetConsumeUri({required String uri}) async {
    _ensureOpen();
    return Future(() => _pairFrameCall(
          (statusPtr, bufPtr, bufCap, lenPtr, errOut) {
            final uriC = uri.toNativeUtf8();
            try {
              return ffi.veilPairTargetConsumeUri(
                _handle,
                uriC,
                statusPtr,
                bufPtr,
                bufCap,
                lenPtr,
                errOut,
              );
            } finally {
              calloc.free(uriC);
            }
          },
        ));
  }

  /// Target-side: process Cert bytes, returns 6-digit OOB code.
  Future<PairOobResult> pairTargetHandleCert({
    required Uint8List certBytes,
  }) async {
    _ensureOpen();
    return Future(() {
      // Target.handle_cert returns no Cert bytes (only OOB) — pass a
      // zero-cap output buffer; FFI checks len before write.
      final certPtr =
          certBytes.isEmpty ? nullptr : calloc<Uint8>(certBytes.length);
      final outStatus = calloc<Uint8>();
      final outOob = calloc<Uint8>(6);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        if (certBytes.isNotEmpty) {
          certPtr.asTypedList(certBytes.length).setAll(0, certBytes);
        }
        final rc = ffi.veilPairTargetHandleCert(
          _handle,
          certPtr,
          certBytes.length,
          outStatus,
          outOob,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'pair_target_handle_cert failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        final statusByte = outStatus.value;
        final oobCode =
            String.fromCharCodes(outOob.asTypedList(6).where((b) => b != 0));
        String? detail;
        final errPtr = errOut.value;
        if (errPtr != nullptr) {
          detail = errPtr.toDartString();
          ffi.veilFreeString(errPtr);
          errOut.value = nullptr;
        }
        return PairOobResult(
          statusByte: statusByte,
          oobCode: oobCode,
          responseBytes: Uint8List(0),
          detail: detail,
        );
      } finally {
        if (certPtr != nullptr) calloc.free(certPtr);
        calloc.free(outStatus);
        calloc.free(outOob);
        calloc.free(errOut);
      }
    });
  }

  /// Target-side: emit Confirm bytes based on user's OOB-compare
  /// decision.  `confirmed = true` triggers identity persistence.
  Future<PairFrameResult> pairTargetBuildConfirm({
    required bool confirmed,
  }) async {
    _ensureOpen();
    return Future(() => _pairFrameCall(
          (statusPtr, bufPtr, bufCap, lenPtr, errOut) =>
              ffi.veilPairTargetBuildConfirm(
            _handle,
            confirmed ? 1 : 0,
            statusPtr,
            bufPtr,
            bufCap,
            lenPtr,
            errOut,
          ),
        ));
  }

  /// Shared helper for ops that take input bytes + return OOB + Cert
  /// bytes (Source.handle_hello shape).
  PairOobResult _pairOobCall(
    Uint8List inputBytes,
    int Function(
      Pointer<Uint8> inputPtr,
      int inputLen,
      Pointer<Uint8> statusPtr,
      Pointer<Uint8> oobPtr,
      Pointer<Uint8> certBuf,
      int certCap,
      Pointer<IntPtr> certLen,
      Pointer<Pointer<Utf8>> errOut,
    ) call,
  ) {
    final inputPtr =
        inputBytes.isEmpty ? nullptr : calloc<Uint8>(inputBytes.length);
    final outStatus = calloc<Uint8>();
    final outOob = calloc<Uint8>(6);
    final certBuf = calloc<Uint8>(ffi.veilMaxPairCeremonyBytes);
    final certLen = calloc<IntPtr>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      if (inputBytes.isNotEmpty) {
        inputPtr.asTypedList(inputBytes.length).setAll(0, inputBytes);
      }
      final rc = call(
        inputPtr,
        inputBytes.length,
        outStatus,
        outOob,
        certBuf,
        ffi.veilMaxPairCeremonyBytes,
        certLen,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(
          'pair op failed: ${_readErrAndFree(errOut)}',
          code: rc,
        );
      }
      final responseBytes =
          Uint8List.fromList(certBuf.asTypedList(certLen.value));
      final oobCode =
          String.fromCharCodes(outOob.asTypedList(6).where((b) => b != 0));
      String? detail;
      final errPtr = errOut.value;
      if (errPtr != nullptr) {
        detail = errPtr.toDartString();
        ffi.veilFreeString(errPtr);
        errOut.value = nullptr;
      }
      return PairOobResult(
        statusByte: outStatus.value,
        oobCode: oobCode,
        responseBytes: responseBytes,
        detail: detail,
      );
    } finally {
      if (inputPtr != nullptr) calloc.free(inputPtr);
      calloc.free(outStatus);
      calloc.free(outOob);
      calloc.free(certBuf);
      calloc.free(certLen);
      calloc.free(errOut);
    }
  }

  /// Shared helper for ops that return only a byte payload (Hello /
  /// Confirm shape).
  PairFrameResult _pairFrameCall(
    int Function(
      Pointer<Uint8> statusPtr,
      Pointer<Uint8> bufPtr,
      int bufCap,
      Pointer<IntPtr> lenPtr,
      Pointer<Pointer<Utf8>> errOut,
    ) call,
  ) {
    final outStatus = calloc<Uint8>();
    final outBuf = calloc<Uint8>(ffi.veilMaxPairCeremonyBytes);
    final outLen = calloc<IntPtr>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = call(
        outStatus,
        outBuf,
        ffi.veilMaxPairCeremonyBytes,
        outLen,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(
          'pair frame op failed: ${_readErrAndFree(errOut)}',
          code: rc,
        );
      }
      final bytes = Uint8List.fromList(outBuf.asTypedList(outLen.value));
      String? detail;
      final errPtr = errOut.value;
      if (errPtr != nullptr) {
        detail = errPtr.toDartString();
        ffi.veilFreeString(errPtr);
        errOut.value = nullptr;
      }
      return PairFrameResult(
        status: PairTargetStatus.fromWire(outStatus.value),
        bytes: bytes,
        detail: detail,
      );
    } finally {
      calloc.free(outStatus);
      calloc.free(outBuf);
      calloc.free(outLen);
      calloc.free(errOut);
    }
  }

  /// Notify the daemon that the host's mobile-background tier changed.
  /// Drives keepalive scaling and suppresses background maintenance on
  /// `lowPower` (Epic 489.4).
  Future<void> setBackgroundMode(MobileBackgroundMode mode) async {
    _ensureOpen();
    return Future(() {
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilSetBackgroundMode(_handle, mode.wireByte, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'set_background_mode failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(errOut);
      }
    });
  }

  /// Notify the daemon that the local network attachment changed
  /// (Epic 489.5).  Triggers eager gateway-failover so the app does
  /// not wait for keepalive timeout to detect dead sessions on a
  /// Wi-Fi → Cellular flip.
  Future<void> notifyNetworkChanged(NetworkKind kind, {int mtuHint = 0}) async {
    _ensureOpen();
    return Future(() {
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilNotifyNetworkChanged(
          _handle,
          kind.wireByte,
          mtuHint,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
              'notify_network_changed failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(errOut);
      }
    });
  }

  /// Bind an ephemeral application endpoint.  Returns an [AppHandle]
  /// the caller uses to send + receive datagrams.
  Future<AppHandle> bind({
    required String namespace,
    required String name,
    int endpointId = 0,
  }) async {
    return _bindCommon(
        namespace: namespace, name: name, endpointId: endpointId, named: false);
  }

  /// Bind a well-known persistent endpoint — `app_id = BLAKE3(node_id || ns || name)`,
  /// stable across reconnects.  Only one client per node may hold a
  /// given (ns, name, endpointId) at a time.
  Future<AppHandle> bindNamed({
    required String namespace,
    required String name,
    int endpointId = 0,
  }) async {
    return _bindCommon(
        namespace: namespace, name: name, endpointId: endpointId, named: true);
  }

  Future<AppHandle> _bindCommon({
    required String namespace,
    required String name,
    required int endpointId,
    required bool named,
  }) async {
    _ensureOpen();
    return Future(() {
      final nsC = namespace.toNativeUtf8();
      final nameC = name.toNativeUtf8();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final app = named
            ? ffi.veilBindNamed(_handle, nsC, nameC, endpointId, errOut)
            : ffi.veilBind(_handle, nsC, nameC, endpointId, errOut);
        if (app == nullptr) {
          throw VeilException('bind failed: ${_readErrAndFree(errOut)}');
        }
        return AppHandle._(app);
      } finally {
        calloc.free(nsC);
        calloc.free(nameC);
        calloc.free(errOut);
      }
    });
  }

  /// Close the connection.  Aborts any active event subscription and
  /// releases the C handle.  Safe to call multiple times.
  ///
  /// Order matters: the native handle is closed FIRST so the daemon-
  /// side event task is signalled to stop emitting callbacks before
  /// the `NativeCallable` trampoline is deallocated.  Otherwise a
  /// late-firing trampoline call lands in freed memory (use-after-free,
  /// audit-flagged race).  Two microtask yields give any in-flight
  /// Rust-side trampoline call a chance to post its message before
  /// the listener is torn down.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final ec = _eventCallable;
    final ctl = _eventController;
    _eventCallable = null;
    _eventController = null;
    _veilClientFinalizer.detach(this);
    ffi.veilClose(_handle);
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    if (ec != null) ec.close();
    if (ctl != null) await ctl.close();
  }

  void _ensureOpen() {
    if (_closed) {
      throw VeilException('handle already closed',
          code: ffi.veilErrClosed);
    }
  }
}

/// GC-time safety-net for [AppHandle].  Same shape as
/// [_veilClientFinalizer] — fires `veil_app_close` if the Dart
/// object is GC'd without an explicit [AppHandle.close].
final _appHandleFinalizer = NativeFinalizer(
  ffi.veilAppCloseFinalizerPtr.cast<NativeFinalizerFunction>(),
);

/// Bound application endpoint — used to send + receive datagrams.
class AppHandle implements Finalizable {
  AppHandle._(this._app) {
    final out = calloc<Uint8>(32);
    try {
      ffi.veilAppGetAppId(_app, out);
      _appId = Uint8List.fromList(out.asTypedList(32));
    } finally {
      calloc.free(out);
    }
    _endpointId = ffi.veilAppGetEndpointId(_app);
    _appHandleFinalizer.attach(this, _app.cast(), detach: this);
  }

  final Pointer<ffi.VeilApp> _app;
  late final Uint8List _appId;
  late final int _endpointId;
  bool _closed = false;

  StreamController<IncomingMessage>? _msgController;
  NativeCallable<ffi.VeilRecvCbNative>? _recvCallable;

  /// 32-byte deterministic identifier of this endpoint.
  Uint8List get appId => _appId;

  /// Configured local endpoint id.
  int get endpointId => _endpointId;

  /// Send a datagram to a remote peer.
  Future<void> send({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
    required int dstEndpointId,
    required Uint8List data,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dst_node_id and dst_app_id must be 32 bytes');
    }
    return Future(() {
      final dstNode = calloc<Uint8>(32);
      final dstApp = calloc<Uint8>(32);
      final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
      final errOut = calloc<Pointer<Utf8>>();
      try {
        dstNode.asTypedList(32).setAll(0, dstNodeId);
        dstApp.asTypedList(32).setAll(0, dstAppId);
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc = ffi.veilSend(
          _app,
          dstNode,
          dstApp,
          dstEndpointId,
          dataPtr,
          data.length,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException('send failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(dstNode);
        calloc.free(dstApp);
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Send [data] as an AUTHENTICATED anonymous message over the
  /// onion/rendezvous transport: the relays don't learn our location while the
  /// recipient cryptographically verifies WHO sent it. Fire-and-forget (no
  /// end-to-end ack); the recipient must have opted in to receiving.
  Future<void> sendAnonymousAuthenticated({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
    required int dstEndpointId,
    required Uint8List data,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dst_node_id and dst_app_id must be 32 bytes');
    }
    return Future(() {
      final dstNode = calloc<Uint8>(32);
      final dstApp = calloc<Uint8>(32);
      final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
      final errOut = calloc<Pointer<Utf8>>();
      try {
        dstNode.asTypedList(32).setAll(0, dstNodeId);
        dstApp.asTypedList(32).setAll(0, dstAppId);
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc = ffi.veilSendAnonymousAuthenticated(
            _app, dstNode, dstApp, dstEndpointId, dataPtr, data.length, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'anonymous authenticated send failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(dstNode);
        calloc.free(dstApp);
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Like [sendAnonymousAuthenticated], but attach a one-time reply block so the
  /// recipient can answer WITHOUT either side publishing a public ad. The reply
  /// is delivered back to (this app, [replyEndpointId]) and surfaces as a
  /// non-zero [IncomingMessage.replyId]; answer it with [sendReply].
  Future<void> sendAnonymousAuthenticatedWithReply({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
    required int dstEndpointId,
    required int replyEndpointId,
    required Uint8List data,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dst_node_id and dst_app_id must be 32 bytes');
    }
    return Future(() {
      final dstNode = calloc<Uint8>(32);
      final dstApp = calloc<Uint8>(32);
      final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
      final errOut = calloc<Pointer<Utf8>>();
      try {
        dstNode.asTypedList(32).setAll(0, dstNodeId);
        dstApp.asTypedList(32).setAll(0, dstAppId);
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc = ffi.veilSendAnonymousAuthenticatedWithReply(_app, dstNode,
            dstApp, dstEndpointId, replyEndpointId, dataPtr, data.length, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'anonymous authenticated send failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(dstNode);
        calloc.free(dstApp);
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Reply to a message received over the authenticated anonymous transport,
  /// addressing it by the opaque [IncomingMessage.replyId] it carried. Routed
  /// back over the original sender's rendezvous path — no public ad either side.
  Future<void> sendReply({
    required int replyId,
    required Uint8List data,
  }) async {
    _ensureOpen();
    return Future(() {
      final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
      final errOut = calloc<Pointer<Utf8>>();
      try {
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc =
            ffi.veilSendReply(_app, replyId, dataPtr, data.length, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException('reply send failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Open a reliable bidirectional byte-stream to a remote endpoint.
  /// Returns once the daemon-side stream FSM is established (the open
  /// handshake doesn't await peer ACK — call [VeilStream.write] and
  /// the daemon flow-controls against the configured `initialWindow`).
  ///
  /// [initialWindow] sets the receive-window the daemon advertises to
  /// the peer (bytes the peer may send before waiting for a window
  /// update).  Default 64 KiB matches the FFI surface default.
  Future<VeilStream> openStream({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
    required int dstEndpointId,
    int initialWindow = 65536,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dst_node_id and dst_app_id must be 32 bytes');
    }
    if (initialWindow <= 0) {
      throw ArgumentError('initialWindow must be > 0, got $initialWindow');
    }
    return Future(() {
      final dstNode = calloc<Uint8>(32);
      final dstApp = calloc<Uint8>(32);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        dstNode.asTypedList(32).setAll(0, dstNodeId);
        dstApp.asTypedList(32).setAll(0, dstAppId);
        final ptr = ffi.veilStreamOpen(
          _app,
          dstNode,
          dstApp,
          dstEndpointId,
          initialWindow,
          errOut,
        );
        if (ptr == nullptr) {
          throw VeilException(
            'stream open failed: ${_readErrAndFree(errOut)}',
          );
        }
        return VeilStream.fromFfi(ptr);
      } finally {
        calloc.free(dstNode);
        calloc.free(dstApp);
        calloc.free(errOut);
      }
    });
  }

  /// Subscribe to inbound datagrams.  Replaces any prior handler —
  /// matches the C-FFI single-subscriber contract.
  Stream<IncomingMessage> messages() {
    _ensureOpen();
    if (_msgController != null) {
      return _msgController!.stream;
    }
    final controller = StreamController<IncomingMessage>.broadcast();
    final callable = NativeCallable<ffi.VeilRecvCbNative>.listener(
      (Pointer<Void> _, Pointer<Uint8> srcNode, Pointer<Uint8> srcApp,
          int replyId, Pointer<Uint8> dataPtr, int len) {
        final src = Uint8List.fromList(srcNode.asTypedList(32));
        final app = Uint8List.fromList(srcApp.asTypedList(32));
        final data = len > 0
            ? Uint8List.fromList(dataPtr.asTypedList(len))
            : Uint8List(0);
        // cycle-7 H6: srcNode/srcApp/dataPtr are offsets into ONE callee-owned
        // buffer ([nodeId(32) | appId(32) | data]); free it via the base
        // pointer (srcNode) with the total length, after copying all three.
        // `replyId` is a by-value scalar (not in the buffer) — nothing to free.
        // This callback runs on the isolate AFTER the Rust frame returned, so
        // reading these pointers was a use-after-free before they became owned.
        ffi.veilFreeBuf(srcNode, 64 + len);
        controller.add(IncomingMessage(
            srcNodeId: src, srcAppId: app, data: data, replyId: replyId));
      },
    );
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = ffi.veilAppSetRecvHandler(
        _app,
        callable.nativeFunction,
        nullptr,
        errOut,
      );
      if (rc != ffi.veilOk) {
        callable.close();
        controller.close();
        throw VeilException(
            'set_recv_handler failed: ${_readErrAndFree(errOut)}',
            code: rc);
      }
    } finally {
      calloc.free(errOut);
    }
    _msgController = controller;
    _recvCallable = callable;
    return controller.stream;
  }

  /// Close the endpoint.  Aborts any active recv loop and releases the
  /// C-side AppHandle.  Safe to call multiple times.
  ///
  /// Same close-ordering as `VeilClient.close` — native handle
  /// first, then `NativeCallable` trampoline — to avoid the
  /// audit-flagged use-after-free race when the Rust runtime fires
  /// one more recv callback between abort-signal and trampoline drop.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final cb = _recvCallable;
    final ctl = _msgController;
    _recvCallable = null;
    _msgController = null;
    _appHandleFinalizer.detach(this);
    ffi.veilAppClose(_app);
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    if (cb != null) cb.close();
    if (ctl != null) await ctl.close();
  }

  void _ensureOpen() {
    if (_closed) {
      throw VeilException('app already closed', code: ffi.veilErrClosed);
    }
  }
}
