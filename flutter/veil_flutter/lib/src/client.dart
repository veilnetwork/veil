// High-level idiomatic Dart wrapper around the veilclient-ffi C API.
//
// Threading: every FFI call is synchronous from Dart's POV (the Rust
// runtime owns its own tokio worker pool, the FFI surface block_on's
// internally).  Most calls here are wrapped in `Future(() {...})`, which
// defers them onto the SAME (UI) isolate's event loop — it yields once but
// does NOT offload work to another thread (diff-audit H3 corrected the prior
// comment that wrongly claimed `Isolate.run`).  Genuinely blocking / CPU-heavy
// calls must use `Isolate.run` to avoid freezing the UI: `connect` (IPC
// APP_HELLO handshake), `joinBootstrapUri` (network join), and
// `restoreIdentity{,Encrypted}` (key derivation / Argon2id) now do, as does
// `VeilStream.read()`.  The remaining `Future(() {...})` calls are quick IPC
// round-trips; drive any that prove heavy from a worker isolate too.
//
// Memory: every Pointer<Utf8> from C must be freed with veilFreeString
// after consumption.  Every malloc'd buffer we hand to FFI is freed in
// a try/finally.  Pointer<VeilHandle> + Pointer<VeilApp> are
// owned by Dart wrappers and freed on close().

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';
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

/// XChaCha20-Poly1305 seal (key 32 B, nonce 24 B; no associated data) — encrypts
/// [plaintext] for the out-of-container blob store. Returns ciphertext + 16-B
/// tag. Synchronous; chunk a large blob into segments and run on a worker
/// isolate for big inputs. Crypto runs in audited Rust (`veil_seal`).
Uint8List veilSealBytes(Uint8List key, Uint8List nonce, Uint8List plaintext) =>
    _aead(ffi.veilSeal, key, nonce, plaintext, 'seal');

/// Inverse of [veilSealBytes]; throws [VeilException] on a bad key/nonce/tag.
Uint8List veilUnsealBytes(
        Uint8List key, Uint8List nonce, Uint8List ciphertext) =>
    _aead(ffi.veilUnseal, key, nonce, ciphertext, 'unseal');

Uint8List _aead(
  int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int,
          Pointer<Pointer<Uint8>>, Pointer<IntPtr>, Pointer<Pointer<Utf8>>)
      fn,
  Uint8List key,
  Uint8List nonce,
  Uint8List input,
  String label,
) {
  if (key.length != 32) throw ArgumentError('key must be 32 bytes');
  if (nonce.length != 24) throw ArgumentError('nonce must be 24 bytes');
  final keyP = calloc<Uint8>(32);
  final nonceP = calloc<Uint8>(24);
  final Pointer<Uint8> inP =
      input.isEmpty ? nullptr : calloc<Uint8>(input.length);
  final outBuf = calloc<Pointer<Uint8>>();
  final outLen = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    keyP.asTypedList(32).setAll(0, key);
    nonceP.asTypedList(24).setAll(0, nonce);
    if (input.isNotEmpty) inP.asTypedList(input.length).setAll(0, input);
    final rc = fn(keyP, nonceP, inP, input.length, outBuf, outLen, errOut);
    if (rc != 0) {
      throw VeilException('$label failed: ${_readErrAndFree(errOut)}');
    }
    final out = Uint8List.fromList(outBuf.value.asTypedList(outLen.value));
    ffi.veilFreeBuf(outBuf.value, outLen.value);
    return out;
  } finally {
    calloc.free(keyP);
    calloc.free(nonceP);
    if (input.isNotEmpty) calloc.free(inP);
    calloc.free(outBuf);
    calloc.free(outLen);
    calloc.free(errOut);
  }
}

// ── Off-isolate workers ──────────────────────────────────────────────
// TOP-LEVEL (never instance methods/closures) so an `Isolate.run(() =>
// _xWorker(handleAddr, ...))` computation captures only sendable values and can
// be sent to the worker isolate. The veil connection handle is a process-global
// token (the generational handle table lives in native memory), so the worker
// re-derives the same connection from the raw int address.

/// Off-isolate body of [AppHandle.openStream] — veil_stream_open blocks the
/// thread until the stream FSM is set up, so it runs here. Returns the new
/// stream's raw pointer address (re-wrapped on the main isolate).
int _openStreamWorker(int appAddr, Uint8List dstNode, Uint8List dstApp,
    int endpoint, int window) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
  final dn = calloc<Uint8>(32)..asTypedList(32).setAll(0, dstNode);
  final da = calloc<Uint8>(32)..asTypedList(32).setAll(0, dstApp);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final ptr = ffi.veilStreamOpen(app, dn, da, endpoint, window, errOut);
    if (ptr == nullptr) {
      throw VeilException('stream open failed: ${_readErrAndFree(errOut)}');
    }
    return ptr.address;
  } finally {
    calloc.free(dn);
    calloc.free(da);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [AppHandle.acceptStream] — the blocking veil_stream_accept
/// runs here so an accept loop never freezes the UI. Returns null on timeout,
/// throws on a fatal error, or the accepted stream's raw pointer address + the
/// initiator node_id (re-wrapped on the main isolate via the global handle table).
({int streamAddr, Uint8List src})? _acceptStreamWorker(
    int appAddr, int timeoutMs) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
  final outNode = calloc<Uint8>(32);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final ptr = ffi.veilStreamAccept(app, timeoutMs, outNode, errOut);
    if (ptr == nullptr) {
      if (errOut.value == nullptr) return null; // timeout
      throw VeilException('stream accept failed: ${_readErrAndFree(errOut)}');
    }
    return (
      streamAddr: ptr.address,
      src: Uint8List.fromList(outNode.asTypedList(32)),
    );
  } finally {
    calloc.free(outNode);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [VeilClient.openAnonStream] — veil_anon_stream_open
/// blocks until the hub binds + the stream is set up. Returns the stream's raw
/// pointer address.
int _anonStreamOpenWorker(int handleAddr, Uint8List dstNode, Uint8List dstApp) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final dn = calloc<Uint8>(32)..asTypedList(32).setAll(0, dstNode);
  final da = calloc<Uint8>(32)..asTypedList(32).setAll(0, dstApp);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final ptr = ffi.veilAnonStreamOpen(handle, dn, da, errOut);
    if (ptr == nullptr) {
      throw VeilException(
          'anon stream open failed: ${_readErrAndFree(errOut)}');
    }
    return ptr.address;
  } finally {
    calloc.free(dn);
    calloc.free(da);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [VeilClient.warmAnonStreamPeer] — the native call is
/// fire-and-forget but the first invocation may lazily bind the stream hub,
/// so keep it off the UI isolate like the other anon-stream entry points.
void _anonStreamWarmPeerWorker(int handleAddr, Uint8List dstNode) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final dn = calloc<Uint8>(32)..asTypedList(32).setAll(0, dstNode);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilAnonStreamWarmPeer(handle, dn, errOut);
    if (rc != 0) {
      throw VeilException(
          'anon stream warm failed: ${_readErrAndFree(errOut)}');
    }
  } finally {
    calloc.free(dn);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [VeilClient.openMediaChannel] — the first call may
/// lazily bind the stream hub, so keep it off the UI isolate. Returns the
/// opaque channel id (0 on error → thrown here).
int _mediaOpenChannelWorker(int handleAddr, Uint8List peerNode) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final pn = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerNode);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final chan = ffi.veilMediaOpenChannel(handle, pn, errOut);
    if (chan == 0) {
      throw VeilException('media open failed: ${_readErrAndFree(errOut)}');
    }
    return chan;
  } finally {
    calloc.free(pn);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [AppHandle.openDirectMediaChannel]. The native media
/// channel keeps the app sender and pumps RTP/RTCP over direct app datagrams.
int _directMediaOpenChannelWorker(
    int appAddr, Uint8List peerNode, Uint8List peerApp, int peerEndpoint) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
  final pn = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerNode);
  final pa = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerApp);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final chan =
        ffi.veilMediaOpenDirectChannel(app, pn, pa, peerEndpoint, errOut);
    if (chan == 0) {
      throw VeilException(
          'direct media open failed: ${_readErrAndFree(errOut)}');
    }
    return chan;
  } finally {
    calloc.free(pn);
    calloc.free(pa);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [AppHandle.openRelayMediaChannel].
int _relayMediaOpenChannelWorker(
    int appAddr, Uint8List peerNode, Uint8List peerApp, int peerEndpoint) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
  final pn = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerNode);
  final pa = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerApp);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final chan =
        ffi.veilMediaOpenRelayChannel(app, pn, pa, peerEndpoint, errOut);
    if (chan == 0) {
      throw VeilException(
          'relay media open failed: ${_readErrAndFree(errOut)}');
    }
    return chan;
  } finally {
    calloc.free(pn);
    calloc.free(pa);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [VeilClient.nodeId] — the native call performs an IPC
/// request via tokio block_on, so it must not run on Flutter's UI isolate.
Uint8List _nodeIdWorker(int handleAddr) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final out = calloc<Uint8>(32);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilGetNodeId(handle, out, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException('get_node_id failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
    return Uint8List.fromList(out.asTypedList(32));
  } finally {
    calloc.free(out);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [VeilClient.joinBootstrapUri]. The daemon may dial and
/// negotiate a transport before returning, so this is not a quick IPC query:
/// Android recorded an input-dispatch ANR with the UI thread blocked in
/// `veil_join_bootstrap_uri` when it ran through `Future(() {...})`.
({int status, Uint8List peerNodeId, String? detail}) _joinBootstrapUriWorker(
  int handleAddr,
  String uri,
  String? password,
  String? expectedIssuerPk,
) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final uriC = uri.toNativeUtf8();
  final pwC = password == null ? nullptr : password.toNativeUtf8();
  final pkC =
      expectedIssuerPk == null ? nullptr : expectedIssuerPk.toNativeUtf8();
  final outNodeId = calloc<Uint8>(32);
  final outStatus = calloc<Uint8>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilJoinBootstrapUri(
      handle,
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
    // err_out on success-paths carries a detail string (decode error message
    // or similar) rather than a transport error.
    final errPtr = errOut.value;
    String? detail;
    if (errPtr != nullptr) {
      detail = errPtr.toDartString();
      ffi.veilFreeString(errPtr);
      errOut.value = nullptr;
    }
    return (
      status: outStatus.value,
      peerNodeId: Uint8List.fromList(outNodeId.asTypedList(32)),
      detail: detail,
    );
  } finally {
    calloc.free(uriC);
    if (pwC != nullptr) {
      zeroizeNative(pwC.cast<Uint8>(), pwC.length);
      calloc.free(pwC);
    }
    if (pkC != nullptr) calloc.free(pkC);
    calloc.free(outNodeId);
    calloc.free(outStatus);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [VeilClient.acceptAnonStream]. Null on timeout; throws on
/// a fatal error; else the stream address + the initiator's node id + onion-
/// stream app id.
({int streamAddr, Uint8List src, Uint8List srcApp})? _anonStreamAcceptWorker(
    int handleAddr, int timeoutMs) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final outNode = calloc<Uint8>(32);
  final outApp = calloc<Uint8>(32);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final ptr =
        ffi.veilAnonStreamAccept(handle, timeoutMs, outNode, outApp, errOut);
    if (ptr == nullptr) {
      if (errOut.value == nullptr) return null; // timeout
      throw VeilException(
          'anon stream accept failed: ${_readErrAndFree(errOut)}');
    }
    return (
      streamAddr: ptr.address,
      src: Uint8List.fromList(outNode.asTypedList(32)),
      srcApp: Uint8List.fromList(outApp.asTypedList(32)),
    );
  } finally {
    calloc.free(outNode);
    calloc.free(outApp);
    calloc.free(errOut);
  }
}

Uint8List? _lookupRelayX25519Worker(int handleAddr, Uint8List nodeId) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final node = calloc<Uint8>(32);
  final out = calloc<Uint8>(32);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    node.asTypedList(32).setAll(0, nodeId);
    final rc = ffi.veilLookupRelayX25519(handle, node, out, errOut);
    if (rc == ffi.veilRelayX25519Unavailable) return null;
    if (rc != ffi.veilOk) {
      throw VeilException(
          'lookup_relay_x25519 failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
    return Uint8List.fromList(out.asTypedList(32));
  } finally {
    calloc.free(node);
    calloc.free(out);
    calloc.free(errOut);
  }
}

List<VeilPeer> _peersWorker(int handleAddr) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final out = <VeilPeer>[];
  final errOut = calloc<Pointer<Utf8>>();
  // The callback is created INSIDE this worker isolate, so `isolateLocal` runs
  // it inline on this isolate for the duration of veil_peers_list — we
  // accumulate into `out` directly and return it (plain data, sendable back).
  final cb = NativeCallable<ffi.VeilPeerCbNative>.isolateLocal(
    (Pointer<Void> user, Pointer<Uint8> nodeId, int state, int direction,
        Pointer<Uint8> transport, int transportLen) {
      final id = Uint8List.fromList(nodeId.asTypedList(32));
      final uri = transportLen > 0
          ? utf8.decode(transport.asTypedList(transportLen),
              allowMalformed: true)
          : '';
      out.add(VeilPeer(
        nodeId: id,
        state: VeilPeerState.fromWire(state),
        direction: VeilPeerDirection.fromWire(direction),
        transport: uri,
      ));
    },
  );
  try {
    final rc = ffi.veilPeersList(handle, cb.nativeFunction, nullptr, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException('peers_list failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
    return out;
  } finally {
    cb.close();
    calloc.free(errOut);
  }
}

void _registerRendezvousPublisherWorker(
  int handleAddr,
  Uint8List rendezvousNodeId,
  Uint8List authCookie,
  int validityWindowSecs,
  int relayKemAlgo,
  Uint8List kem,
) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final nodeId = calloc<Uint8>(32);
  final cookie = calloc<Uint8>(16);
  final kemPtr = kem.isNotEmpty ? calloc<Uint8>(kem.length) : nullptr;
  final errOut = calloc<Pointer<Utf8>>();
  try {
    nodeId.asTypedList(32).setAll(0, rendezvousNodeId);
    cookie.asTypedList(16).setAll(0, authCookie);
    if (kem.isNotEmpty) kemPtr.asTypedList(kem.length).setAll(0, kem);
    final rc = ffi.veilRegisterRendezvousPublisher(handle, nodeId, cookie,
        validityWindowSecs, relayKemAlgo, kemPtr, kem.length, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(
          'register_rendezvous_publisher failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
  } finally {
    calloc.free(nodeId);
    calloc.free(cookie);
    if (kemPtr != nullptr) calloc.free(kemPtr);
    calloc.free(errOut);
  }
}

Uint8List _registerEphemeralOnionServiceWorker(
  int handleAddr,
  Uint8List seed,
  int hopCount,
  int providerSlot,
) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final seedPtr = calloc<Uint8>(32)..asTypedList(32).setAll(0, seed);
  final publicKey = calloc<Uint8>(32);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilRegisterEphemeralOnionServiceZeroizeV2(
      handle,
      seedPtr,
      hopCount,
      providerSlot,
      publicKey,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException(
        'register_ephemeral_onion_service failed: ${_readErrAndFree(errOut)}',
        code: rc,
      );
    }
    return Uint8List.fromList(publicKey.asTypedList(32));
  } finally {
    seed.fillRange(0, seed.length, 0);
    seedPtr.asTypedList(32).fillRange(0, 32, 0);
    calloc.free(seedPtr);
    calloc.free(publicKey);
    calloc.free(errOut);
  }
}

int _bindCapabilityWorker(
  int handleAddr,
  Uint8List namespace,
  Uint8List name,
  int endpointId,
) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final nsPtr = calloc<Uint8>(namespace.length)
    ..asTypedList(namespace.length).setAll(0, namespace);
  final namePtr = calloc<Uint8>(name.length)
    ..asTypedList(name.length).setAll(0, name);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final app = ffi.veilBindCapability(
      handle,
      nsPtr,
      namespace.length,
      namePtr,
      name.length,
      endpointId,
      errOut,
    );
    if (app == nullptr) {
      throw VeilException(
        'bind capability failed: ${_readErrAndFree(errOut)}',
      );
    }
    return app.address;
  } finally {
    calloc.free(nsPtr);
    calloc.free(namePtr);
    calloc.free(errOut);
  }
}

// The four anonymous-send entrypoints below were originally wrapped in
// `Future(() {...})`, which only DEFERS the work to a later microtask on the
// SAME isolate — the synchronous, network-blocking FFI still ran on the UI
// isolate. On a busy/slow node (mobile, NAT'd relay churn) the send can block
// for seconds; on Android a >5s block on the main thread is a fatal ANR, which
// is exactly what crashed the phone (chronic ANRs parked in
// `veil_send_anonymous_*`). Mirroring peers()/seal()/lookup(), these now run on
// a worker isolate via `Isolate.run` so a blocking send can never freeze the UI
// (or ANR-kill the app). The send remains fire-and-forget from the caller's POV.

void _sendAnonymousDirectWorker(
  int handleAddr,
  Uint8List targetNodeId,
  Uint8List targetX25519Pk,
  Uint8List targetAppId,
  int targetEndpointId,
  Uint8List srcAppId,
  int hopCount,
  Uint8List data,
) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final nodeId = calloc<Uint8>(32);
  final x25519 = calloc<Uint8>(32);
  final appId = calloc<Uint8>(32);
  final srcApp = calloc<Uint8>(32);
  final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
  final errOut = calloc<Pointer<Utf8>>();
  try {
    nodeId.asTypedList(32).setAll(0, targetNodeId);
    x25519.asTypedList(32).setAll(0, targetX25519Pk);
    appId.asTypedList(32).setAll(0, targetAppId);
    srcApp.asTypedList(32).setAll(0, srcAppId);
    if (data.isNotEmpty) {
      dataPtr.asTypedList(data.length).setAll(0, data);
    }
    final rc = ffi.veilSendAnonymousDirect(handle, nodeId, x25519, appId,
        targetEndpointId, srcApp, hopCount, dataPtr, data.length, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(
          'send_anonymous_direct failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
  } finally {
    calloc.free(nodeId);
    calloc.free(x25519);
    calloc.free(appId);
    calloc.free(srcApp);
    if (dataPtr != nullptr) calloc.free(dataPtr);
    calloc.free(errOut);
  }
}

void _sendAnonymousAuthenticatedWorker(int appAddr, Uint8List dstNodeId,
    Uint8List dstAppId, int dstEndpointId, Uint8List data) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
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
        app, dstNode, dstApp, dstEndpointId, dataPtr, data.length, errOut);
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
}

void _sendAnonymousAuthenticatedWithReplyWorker(
    int appAddr,
    Uint8List dstNodeId,
    Uint8List dstAppId,
    int dstEndpointId,
    int replyEndpointId,
    Uint8List data) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
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
    final rc = ffi.veilSendAnonymousAuthenticatedWithReply(app, dstNode, dstApp,
        dstEndpointId, replyEndpointId, dataPtr, data.length, errOut);
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
}

void _sendAnonymousAuthenticatedDirectWithReplyWorker(
    int appAddr,
    Uint8List dstNodeId,
    Uint8List dstX25519Pk,
    Uint8List dstAppId,
    int dstEndpointId,
    int replyEndpointId,
    Uint8List data) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
  final dstNode = calloc<Uint8>(32);
  final dstX25519 = calloc<Uint8>(32);
  final dstApp = calloc<Uint8>(32);
  final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
  final errOut = calloc<Pointer<Utf8>>();
  try {
    dstNode.asTypedList(32).setAll(0, dstNodeId);
    dstX25519.asTypedList(32).setAll(0, dstX25519Pk);
    dstApp.asTypedList(32).setAll(0, dstAppId);
    if (data.isNotEmpty) {
      dataPtr.asTypedList(data.length).setAll(0, data);
    }
    final rc = ffi.veilSendAnonymousAuthenticatedDirectWithReply(
        app,
        dstNode,
        dstX25519,
        dstApp,
        dstEndpointId,
        replyEndpointId,
        dataPtr,
        data.length,
        errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(
          'anonymous authenticated direct send failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
  } finally {
    calloc.free(dstNode);
    calloc.free(dstX25519);
    calloc.free(dstApp);
    if (dataPtr != nullptr) calloc.free(dataPtr);
    calloc.free(errOut);
  }
}

void _sendReplyWorker(int appAddr, int replyId, Uint8List data) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
  final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
  final errOut = calloc<Pointer<Utf8>>();
  try {
    if (data.isNotEmpty) {
      dataPtr.asTypedList(data.length).setAll(0, data);
    }
    final rc = ffi.veilSendReply(app, replyId, dataPtr, data.length, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException('reply send failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
  } finally {
    if (dataPtr != nullptr) calloc.free(dataPtr);
    calloc.free(errOut);
  }
}

/// Off-isolate body of [AppHandle.send]. The native `veil_send` takes the app
/// sender lock and `block_on`s the daemon send path. That is usually quick, but
/// call signaling heartbeats exercise it during exactly the busy media periods
/// where a contended node can park the caller; keep it off Flutter's UI isolate.
void _sendWorker(int appAddr, Uint8List dstNodeId, Uint8List dstAppId,
    int dstEndpointId, Uint8List data) {
  final app = Pointer<ffi.VeilApp>.fromAddress(appAddr);
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
      app,
      dstNode,
      dstApp,
      dstEndpointId,
      dataPtr,
      data.length,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException('send failed: ${_readErrAndFree(errOut)}', code: rc);
    }
  } finally {
    calloc.free(dstNode);
    calloc.free(dstApp);
    if (dataPtr != nullptr) calloc.free(dataPtr);
    calloc.free(errOut);
  }
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
    // diff-audit H3 follow-up: the native connect performs a BLOCKING IPC
    // round-trip (APP_HELLO handshake via tokio `block_on`), so run it on a
    // worker isolate instead of `Future(() {...})` (which only defers onto the
    // SAME UI isolate and still freezes it for the handshake duration).
    //
    // SAFE across isolates: the tokio runtime + IPC connection live in
    // PROCESS-GLOBAL native memory keyed by a generational handle TABLE, so the
    // worker creates them and we carry back the opaque handle TOKEN as an int
    // address (sendable). The main isolate's later FFI calls resolve that token
    // against the same global table — no isolate-bound memory is shared, and
    // the worker isolate exiting does NOT drop the native runtime (it lives
    // until `veil_close`). `_eventController` / `_eventCallable` stay bound to
    // the main isolate, set up lazily by `events()` after connect returns.
    final handleAddr = await Isolate.run(() {
      final pathC = socketPath.toNativeUtf8();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final h = ffi.veilConnect(pathC, errOut);
        if (h == nullptr) {
          throw VeilException('connect failed: ${_readErrAndFree(errOut)}');
        }
        return h.address;
      } finally {
        calloc.free(pathC);
        calloc.free(errOut);
      }
    });
    return VeilClient._(
        Pointer<ffi.VeilHandle>.fromAddress(handleAddr), socketPath);
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
    final handleAddr = _handle.address;
    return Isolate.run(() => _nodeIdWorker(handleAddr));
  }

  /// Open an ANONYMOUS reliable byte-stream to a peer (onion-routed +
  /// congestion-controlled — reaches NAT'd/anonymous peers the direct
  /// [AppHandle.openStream] can't). [dstAppId] is the peer's onion-stream
  /// endpoint app id (derived from the peer node + the "onion-stream" endpoint
  /// name, the same way the chat app id is derived). Blocks off the UI isolate.
  Future<VeilAnonStream> openAnonStream({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dstNodeId and dstAppId must be 32 bytes');
    }
    final handleAddr = _handle.address;
    final addr = await Isolate.run(
        () => _anonStreamOpenWorker(handleAddr, dstNodeId, dstAppId));
    return VeilAnonStream.fromFfi(
        Pointer<ffi.VeilAnonStreamFfi>.fromAddress(addr));
  }

  /// Pre-warm the anonymous-stream outbound circuit pool toward a peer.
  /// Fire-and-forget on the native side (the pool opens in the background);
  /// call it when a transfer to [dstNodeId] is likely soon (pending offer /
  /// download resume) so the first stream attempt doesn't pay the cold-pool
  /// price. Idempotent and cheap when the pool is already warm.
  Future<void> warmAnonStreamPeer({required Uint8List dstNodeId}) async {
    _ensureOpen();
    if (dstNodeId.length != 32) {
      throw ArgumentError('dstNodeId must be 32 bytes');
    }
    final handleAddr = _handle.address;
    await Isolate.run(() => _anonStreamWarmPeerWorker(handleAddr, dstNodeId));
  }

  /// Open a lossy MEDIA datagram channel to [dstNodeId] (calls: RTP/RTCP). It
  /// reuses the anon-stream circuit pool and warms the circuit in the
  /// background. Returns an opaque channel id for [sendMediaDatagram] /
  /// [closeMediaChannel]. Bind may lazily create the hub, so run off the UI
  /// isolate like the anon-stream entry points.
  Future<int> openMediaChannel({required Uint8List dstNodeId}) async {
    _ensureOpen();
    if (dstNodeId.length != 32) {
      throw ArgumentError('dstNodeId must be 32 bytes');
    }
    final handleAddr = _handle.address;
    return Isolate.run(() => _mediaOpenChannelWorker(handleAddr, dstNodeId));
  }

  /// Enqueue one media datagram on [chan]. NON-BLOCKING (returns immediately);
  /// no handle needed. Returns 0 queued / 1 dropped (queue full) / -1 invalid.
  /// The native side drops rather than blocks when the circuit can't keep up.
  int sendMediaDatagram(int chan, Uint8List payload) {
    _ensureOpen();
    if (payload.isEmpty) return -1;
    final buf = calloc<Uint8>(payload.length)
      ..asTypedList(payload.length).setAll(0, payload);
    try {
      return ffi.veilMediaSendDatagram(chan, buf, payload.length);
    } finally {
      calloc.free(buf);
    }
  }

  /// Ask an anonymous media channel to make-before-break refresh its outbound
  /// rendezvous/circuit pool. Returns 0 queued / 1 already pending / -1 when
  /// [chan] is invalid or direct-P2P.
  int repairMediaChannel(int chan) {
    _ensureOpen();
    return ffi.veilMediaRepairChannel(chan);
  }

  /// Close a media channel (stops the drain task + clears its recv callback).
  /// Idempotent.
  void closeMediaChannel(int chan) {
    ffi.veilMediaCloseChannel(chan);
  }

  /// Diagnostic: number of inbound media datagrams received from [peerNodeId]
  /// since process start (lets a host confirm receipt without a recv callback).
  int mediaRecvCount(Uint8List peerNodeId) {
    if (peerNodeId.length != 32) {
      throw ArgumentError('peerNodeId must be 32 bytes');
    }
    final pn = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerNodeId);
    try {
      return ffi.veilMediaRecvCount(pn);
    } finally {
      calloc.free(pn);
    }
  }

  /// Deliver a direct media datagram received on a Dart-bound media app endpoint
  /// into the native media callback registry used by veil_media.
  int dispatchDirectMediaDatagram({
    required Uint8List srcNodeId,
    required Uint8List payload,
  }) {
    if (srcNodeId.length != 32) {
      throw ArgumentError('srcNodeId must be 32 bytes');
    }
    if (payload.isEmpty) return -1;
    final pn = calloc<Uint8>(32)..asTypedList(32).setAll(0, srcNodeId);
    final buf = calloc<Uint8>(payload.length)
      ..asTypedList(payload.length).setAll(0, payload);
    try {
      return ffi.veilMediaDispatchDirectDatagram(pn, buf, payload.length);
    } finally {
      calloc.free(pn);
      calloc.free(buf);
    }
  }

  /// Accept the next inbound anonymous stream, or null on [timeout] (a server
  /// loop polls). Returns the stream + the initiator's node id and onion-stream
  /// app id. Blocks off the UI isolate.
  Future<({VeilAnonStream stream, Uint8List srcNodeId, Uint8List srcAppId})?>
      acceptAnonStream({Duration timeout = const Duration(seconds: 2)}) async {
    _ensureOpen();
    final handleAddr = _handle.address;
    final r = await Isolate.run(
        () => _anonStreamAcceptWorker(handleAddr, timeout.inMilliseconds));
    if (r == null) return null;
    return (
      stream: VeilAnonStream.fromFfi(
          Pointer<ffi.VeilAnonStreamFfi>.fromAddress(r.streamAddr)),
      srcNodeId: r.src,
      srcAppId: r.srcApp,
    );
  }

  /// Read the daemon's relay-side X25519 public key (32 bytes) — the seal
  /// target a sender uses to anonymously deliver to this relay's app
  /// endpoints (e.g. depositing a mailbox PUT). Returns `null` when the
  /// daemon is not relay-capable (`anonymity.relay_capable` off).
  Future<Uint8List?> getRelayX25519Pubkey() async {
    _ensureOpen();
    return Future(() {
      final out = calloc<Uint8>(32);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilGetRelayX25519Pubkey(_handle, out, errOut);
        if (rc == ffi.veilRelayX25519Unavailable) {
          return null;
        }
        if (rc != ffi.veilOk) {
          throw VeilException(
              'get_relay_x25519_pubkey failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
        return Uint8List.fromList(out.asTypedList(32));
      } finally {
        calloc.free(out);
        calloc.free(errOut);
      }
    });
  }

  /// Resolve ANOTHER node's relay X25519 KEM public key (32 bytes) by its
  /// [nodeId], over the DHT. Unlike [getRelayX25519Pubkey] (the LOCAL node's
  /// own key), the daemon fetches + verifies the target's signed relay-key
  /// record against its identity document. Returns `null` when unresolved (no
  /// record published / DHT miss / verification failed). Lets a receiver
  /// advertise an always-on third-party relay as its mailbox host knowing only
  /// that relay's node_id.
  Future<Uint8List?> lookupRelayX25519(Uint8List nodeId) async {
    _ensureOpen();
    if (nodeId.length != 32) {
      throw ArgumentError('nodeId must be 32 bytes, got ${nodeId.length}');
    }
    // Blocking DHT FIND_VALUE (waits on a network timeout when the relay record
    // isn't resolvable) — run on a WORKER ISOLATE so it never congests/blocks the
    // calling isolate (which would stall the registration retries + the mailbox
    // drain, and freeze the UI). Delegates to a TOP-LEVEL worker so the sent
    // computation captures only sendable values (handle address int + the id) —
    // an inline closure over this instance method was captured as unsendable
    // ("object is unsendable - Class: VeilClient"). The handle is a process-global
    // token (see [connect]); the worker re-derives it from the raw address.
    final handleAddr = _handle.address;
    return Isolate.run(() => _lookupRelayX25519Worker(handleAddr, nodeId));
  }

  /// Snapshot the daemon's peer sessions: each [VeilPeer] carries node_id,
  /// session state, direction and transport URI. A point-in-time list (bounded
  /// at 256 entries server-side) with NO timestamps at the FFI boundary, so a
  /// caller that wants "last seen" must stamp it on observation. Returns an
  /// empty list when the daemon reports no sessions.
  Future<List<VeilPeer>> peers() async {
    _ensureOpen();
    // veil_peers_list is a BLOCKING FFI that takes the node's session-state
    // lock; while the node is busy (e.g. a NAT'd-mobile session-churn storm)
    // that lock is contended, so running it on the calling isolate froze the UI
    // whenever the peers screen polled it. Off-isolate via a TOP-LEVEL worker
    // (the handle address is sendable; the result is plain data) so a busy node
    // can never block the UI. Mirrors the mailbox seal/fetch workers.
    final handleAddr = _handle.address;
    return Isolate.run(() => _peersWorker(handleAddr));
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

  /// Register a location-anonymous service under a random per-capability
  /// Ed25519 [identitySeed], never this node's sovereign identity. The caller's
  /// writable 32-byte list is scrubbed before this method yields; native scrubs
  /// its FFI copy on every path and retains the seed only in zeroizing runtime
  /// memory for descriptor refresh. Returns the public `.onion`-like service
  /// identity suitable for a capability link.
  Future<Uint8List> registerEphemeralOnionService(
    Uint8List identitySeed, {
    int hopCount = 3,
    int providerSlot = 0,
  }) async {
    _ensureOpen();
    if (identitySeed.length != 32) {
      throw ArgumentError('identitySeed must be exactly 32 writable bytes');
    }
    if (providerSlot < 0 || providerSlot >= 8) {
      throw ArgumentError.value(
          providerSlot, 'providerSlot', 'must be in 0..8');
    }
    final seed = Uint8List.fromList(identitySeed);
    identitySeed.fillRange(0, identitySeed.length, 0);
    final handleAddr = _handle.address;
    try {
      return await Isolate.run(
        () => _registerEphemeralOnionServiceWorker(
          handleAddr,
          seed,
          hopCount,
          providerSlot,
        ),
      );
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  /// Stop refreshing one ephemeral service. Idempotent and deliberately does
  /// not reveal whether the public key was currently registered.
  Future<void> withdrawEphemeralOnionService(Uint8List identityVk) async {
    _ensureOpen();
    if (identityVk.length != 32) {
      throw ArgumentError('identityVk must be exactly 32 bytes');
    }
    return Future(() {
      final publicKey = calloc<Uint8>(32)
        ..asTypedList(32).setAll(0, identityVk);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final rc = ffi.veilWithdrawEphemeralOnionService(
          _handle,
          publicKey,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'withdraw_ephemeral_onion_service failed: '
            '${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
      } finally {
        calloc.free(publicKey);
        calloc.free(errOut);
      }
    });
  }

  /// Register a PLAIN rendezvous-publisher entry (mailbox-by-discovery): the
  /// daemon's maintenance tick signs + publishes a v5 RendezvousAd under THIS
  /// node's real id at [rendezvousNodeId]'s rendezvous slot, advertising the
  /// relay's KEM key ([relayKemPk], `algo 0` = X25519 — e.g. a self-relay key
  /// from [getRelayX25519Pubkey]) so a sender resolving the ad via
  /// [VeilMailbox.lookupRendezvousReplicas] can anonymously deposit a mailbox
  /// PUT. Replaces any existing entry with the same ([rendezvousNodeId],
  /// [authCookie]). Pass an empty [relayKemPk] to advertise no key.
  Future<void> registerRendezvousPublisher({
    required Uint8List rendezvousNodeId,
    required Uint8List authCookie,
    required int validityWindowSecs,
    int relayKemAlgo = 0,
    Uint8List? relayKemPk,
  }) async {
    _ensureOpen();
    if (rendezvousNodeId.length != 32 || authCookie.length != 16) {
      throw ArgumentError(
          'rendezvous_node_id must be 32 bytes and auth_cookie 16 bytes');
    }
    final kem = relayKemPk ?? Uint8List(0);
    // Blocking IPC round-trip (DHT publish) — off-isolate via a TOP-LEVEL worker
    // (sendable captures only) so the mailbox-registration path never blocks the
    // calling isolate or freezes the UI. See [_lookupRelayX25519Worker] note.
    final handleAddr = _handle.address;
    return Isolate.run(() => _registerRendezvousPublisherWorker(
          handleAddr,
          rendezvousNodeId,
          authCookie,
          validityWindowSecs,
          relayKemAlgo,
          kem,
        ));
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
      throw ArgumentError(
          'service_identity_vk and target_app_id must be 32 bytes');
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

  /// Like [sendToOnionService], but UNAUTHENTICATED: the service receives
  /// `src_node_id = [0;32]` and never learns who sent the message. Combined with
  /// the unlinkable descriptor, neither the relays, the rendezvous relay, nor the
  /// service learn the sender's location or identity — the fully-anonymous
  /// "anonymous user → anonymous service" path. [srcAppId] rides inside the
  /// sealed payload for the service's app-level routing only (no node identity).
  Future<void> sendToOnionServiceAnonymous({
    required Uint8List serviceIdentityVk,
    required Uint8List targetAppId,
    required int targetEndpointId,
    required Uint8List srcAppId,
    required Uint8List data,
    int hopCount = 3,
  }) async {
    _ensureOpen();
    if (serviceIdentityVk.length != 32 ||
        targetAppId.length != 32 ||
        srcAppId.length != 32) {
      throw ArgumentError(
          'service_identity_vk, target_app_id and src_app_id must be 32 bytes');
    }
    return Future(() {
      final idVk = calloc<Uint8>(32);
      final appId = calloc<Uint8>(32);
      final srcApp = calloc<Uint8>(32);
      final dataPtr = data.isNotEmpty ? calloc<Uint8>(data.length) : nullptr;
      final errOut = calloc<Pointer<Utf8>>();
      try {
        idVk.asTypedList(32).setAll(0, serviceIdentityVk);
        appId.asTypedList(32).setAll(0, targetAppId);
        srcApp.asTypedList(32).setAll(0, srcAppId);
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc = ffi.veilSendToOnionServiceAnonymous(_handle, idVk, appId,
            targetEndpointId, srcApp, hopCount, dataPtr, data.length, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
              'send_to_onion_service_anonymous failed: ${_readErrAndFree(errOut)}',
              code: rc);
        }
      } finally {
        calloc.free(idVk);
        calloc.free(appId);
        calloc.free(srcApp);
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// DIRECT (non-rendezvous) sender-anonymous send to a KNOWN peer addressed by
  /// its [targetNodeId] + [targetX25519Pk] (each 32 bytes). The source-routed
  /// onion hides our location from every relay; the receiver sees
  /// `src_node_id = [0;32]` and never learns who sent it. For reaching a peer
  /// whose transport node_id + anonymity x25519 you already know — NOT a
  /// location-anonymous service (use [sendToOnionService] for those).
  /// Fire-and-forget (no end-to-end ack).
  Future<void> sendAnonymousDirect({
    required Uint8List targetNodeId,
    required Uint8List targetX25519Pk,
    required Uint8List targetAppId,
    required int targetEndpointId,
    required Uint8List srcAppId,
    required Uint8List data,
    int hopCount = 3,
  }) async {
    _ensureOpen();
    if (targetNodeId.length != 32 ||
        targetX25519Pk.length != 32 ||
        targetAppId.length != 32 ||
        srcAppId.length != 32) {
      throw ArgumentError(
          'target_node_id, target_x25519_pk, target_app_id and src_app_id must be 32 bytes');
    }
    final handleAddr = _handle.address;
    return Isolate.run(() => _sendAnonymousDirectWorker(
          handleAddr,
          targetNodeId,
          targetX25519Pk,
          targetAppId,
          targetEndpointId,
          srcAppId,
          hopCount,
          data,
        ));
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
    final handleAddr = _handle.address;
    final result = await Isolate.run(
      () => _joinBootstrapUriWorker(
        handleAddr,
        uri,
        password,
        expectedIssuerPk,
      ),
    );
    return JoinBootstrapResult(
      status: JoinBootstrapStatus.fromWire(result.status),
      peerNodeId: result.peerNodeId,
      detail: result.detail,
    );
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

  /// Bind a secret stable capability alias. Unlike [bindNamed], its app id is
  /// independent of this node id and can therefore be shared by several
  /// sovereign devices hosting the same capability.
  Future<AppHandle> bindCapability({
    required String namespace,
    required String name,
    int endpointId = 0,
  }) async {
    _ensureOpen();
    final ns = Uint8List.fromList(utf8.encode(namespace));
    final nm = Uint8List.fromList(utf8.encode(name));
    if (ns.isEmpty || nm.isEmpty) {
      throw ArgumentError('capability namespace and name must not be empty');
    }
    final handleAddr = _handle.address;
    final appAddr = await Isolate.run(
      () => _bindCapabilityWorker(handleAddr, ns, nm, endpointId),
    );
    return AppHandle._(Pointer<ffi.VeilApp>.fromAddress(appAddr));
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
      throw VeilException('handle already closed', code: ffi.veilErrClosed);
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
    final appAddr = _app.address;
    return Isolate.run(
        () => _sendWorker(appAddr, dstNodeId, dstAppId, dstEndpointId, data));
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
    final appAddr = _app.address;
    return Isolate.run(() => _sendAnonymousAuthenticatedWorker(
        appAddr, dstNodeId, dstAppId, dstEndpointId, data));
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
    final appAddr = _app.address;
    return Isolate.run(() => _sendAnonymousAuthenticatedWithReplyWorker(
        appAddr, dstNodeId, dstAppId, dstEndpointId, replyEndpointId, data));
  }

  /// Like [sendAnonymousAuthenticatedWithReply], but the caller GIVES the
  /// relay's KEM key ([dstX25519Pk], 32 bytes) directly — so the daemon routes
  /// the source-routed onion STRAIGHT to ([dstNodeId], [dstX25519Pk]) with NO
  /// rendezvous-ad self-resolve (the flaky lookup that returned NoRendezvous).
  /// Still authenticated (the relay verifies us) and still attaches a one-time
  /// reply block delivered back to (this app, [replyEndpointId]), surfacing as a
  /// non-zero [IncomingMessage.replyId]. The KEM-key-given mailbox FETCH;
  /// [dstX25519Pk] is a PUBLIC key (the relay's published KEM key).
  Future<void> sendAnonymousAuthenticatedDirectWithReply({
    required Uint8List dstNodeId,
    required Uint8List dstX25519Pk,
    required Uint8List dstAppId,
    required int dstEndpointId,
    required int replyEndpointId,
    required Uint8List data,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 ||
        dstX25519Pk.length != 32 ||
        dstAppId.length != 32) {
      throw ArgumentError(
          'dst_node_id, dst_x25519_pk and dst_app_id must be 32 bytes');
    }
    final appAddr = _app.address;
    return Isolate.run(() => _sendAnonymousAuthenticatedDirectWithReplyWorker(
        appAddr,
        dstNodeId,
        dstX25519Pk,
        dstAppId,
        dstEndpointId,
        replyEndpointId,
        data));
  }

  /// Reply to a message received over the authenticated anonymous transport,
  /// addressing it by the opaque [IncomingMessage.replyId] it carried. Routed
  /// back over the original sender's rendezvous path — no public ad either side.
  Future<void> sendReply({
    required int replyId,
    required Uint8List data,
  }) async {
    _ensureOpen();
    final appAddr = _app.address;
    return Isolate.run(() => _sendReplyWorker(appAddr, replyId, data));
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
    // veil_stream_open BLOCKS the calling thread until the daemon-side stream
    // FSM is set up (observed ~seconds on-device — it does NOT return instantly).
    // Run it on a worker isolate so it can never ANR/freeze the UI.
    final appAddr = _app.address;
    final addr = await Isolate.run(() => _openStreamWorker(
        appAddr, dstNodeId, dstAppId, dstEndpointId, initialWindow));
    return VeilStream.fromFfi(Pointer<ffi.VeilStreamFfi>.fromAddress(addr));
  }

  /// Open a media channel whose outgoing RTP/RTCP is sent as direct app
  /// datagrams from this endpoint to the peer's media endpoint.
  Future<int> openDirectMediaChannel({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
    required int dstEndpointId,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dst_node_id and dst_app_id must be 32 bytes');
    }
    final appAddr = _app.address;
    return Isolate.run(() => _directMediaOpenChannelWorker(
        appAddr, dstNodeId, dstAppId, dstEndpointId));
  }

  /// Open a media channel over the non-onion Delivery relay path. This is the
  /// fallback for calls where both identities are direct but P2P is unavailable.
  Future<int> openRelayMediaChannel({
    required Uint8List dstNodeId,
    required Uint8List dstAppId,
    required int dstEndpointId,
  }) async {
    _ensureOpen();
    if (dstNodeId.length != 32 || dstAppId.length != 32) {
      throw ArgumentError('dst_node_id and dst_app_id must be 32 bytes');
    }
    final appAddr = _app.address;
    return Isolate.run(() => _relayMediaOpenChannelWorker(
        appAddr, dstNodeId, dstAppId, dstEndpointId));
  }

  /// Install the native direct-media receive pump on this endpoint. Incoming
  /// RTP/RTCP is source-app verified and dispatched native-to-native, avoiding
  /// a copy and scheduling hop through the Dart UI isolate for every packet.
  void startDirectMediaReceiver({
    required String sourceNamespace,
    required String sourceName,
  }) {
    _ensureOpen();
    final ns = Uint8List.fromList(utf8.encode(sourceNamespace));
    final name = Uint8List.fromList(utf8.encode(sourceName));
    if (ns.isEmpty || name.isEmpty) {
      throw ArgumentError('sourceNamespace and sourceName must be non-empty');
    }
    final nsPtr = calloc<Uint8>(ns.length)
      ..asTypedList(ns.length).setAll(0, ns);
    final namePtr = calloc<Uint8>(name.length)
      ..asTypedList(name.length).setAll(0, name);
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = ffi.veilMediaStartDirectReceiver(
        _app,
        nsPtr,
        ns.length,
        namePtr,
        name.length,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(
          'direct media receiver failed: ${_readErrAndFree(errOut)}',
          code: rc,
        );
      }
    } finally {
      calloc.free(nsPtr);
      calloc.free(namePtr);
      calloc.free(errOut);
    }
  }

  /// Wait up to [timeout] for a remote peer to open an inbound byte-stream to
  /// this endpoint. Returns the [VeilStream] + the initiator's 32-byte node_id,
  /// or `null` on TIMEOUT (so a server loop can poll/abort). The receive-side
  /// counterpart to [openStream]; used for any-size file transfer.
  Future<({VeilStream stream, Uint8List srcNodeId})?> acceptStream({
    Duration timeout = const Duration(seconds: 2),
  }) async {
    _ensureOpen();
    // veil_stream_accept BLOCKS the calling thread for up to `timeout` — run it
    // on a worker isolate (like VeilStream.read) so an accept LOOP can't freeze
    // the UI. The native handle table is process-global, so the worker hands back
    // the raw pointer address and we re-wrap it here.
    final appAddr = _app.address;
    final ms = timeout.inMilliseconds;
    final r = await Isolate.run(() => _acceptStreamWorker(appAddr, ms));
    if (r == null) return null;
    return (
      stream: VeilStream.fromFfi(
          Pointer<ffi.VeilStreamFfi>.fromAddress(r.streamAddr)),
      srcNodeId: r.src,
    );
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
