// High-level Dart wrapper around the `veil_mailbox_*` FFI surface
// (Epic 489.3).
//
// Mailboxes are offline message stores hosted by relay nodes (relays
// configured as `MailboxConfig.enabled = true`).  Sender deposits an
// encrypted blob keyed by `(receiver_id, content_id)`; receiver later
// fetches all pending blobs for its `receiver_id`, then acks each one
// after E2E decryption succeeds so the relay can release the slot.
//
// See `crates/veil-mailbox/` for the wire-level contract.  The Dart
// surface is a thin lifecycle + memory-management wrapper.

import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'secure_wipe.dart';
import 'types.dart';

/// Mailbox client surface.  Construct via [VeilClient.mailbox] —
/// the instance shares the client's daemon connection (no separate
/// IPC handshake) so calls are cheap.
class VeilMailbox {
  VeilMailbox._(this._handle);

  /// Borrowed handle from the parent [VeilClient].  Mailbox does
  /// NOT take ownership — when the client closes, all mailbox calls
  /// start failing as expected.
  final Pointer<ffi.VeilHandle> _handle;

  /// Serializes [fetch] calls (diff-audit M23). The count→into protocol uses a
  /// single-slot daemon-side cache, so two concurrent fetches on the same
  /// mailbox would interleave; each fetch chains behind this gate.
  Future<void> _fetchGate = Future<void>.value();

  /// Deposit a blob in the recipient's mailbox.  Caller MUST encrypt
  /// the payload end-to-end before calling — relays cannot decrypt
  /// stored content.
  ///
  /// [receiverId], [contentId], [senderId] are each 32 bytes.
  /// [pushEnvelope] (optional) — sealed FCM/APNs envelope; when present
  /// AND the relay accepts the PUT, the relay fires a wake-push to the
  /// receiver after this call returns.
  /// [capabilityToken] (optional) — receiver-signed token obtained
  /// from the receiver's RendezvousAd.  Required only when targeting
  /// relays configured with `require_capability_token = true`; the
  /// status [MailboxPutStatus.capabilityRequired] tells callers when
  /// they need to add it.
  /// [wakeHmacEnvelope] (optional) — sealed wake-HMAC envelope obtained
  /// from the receiver's RendezvousAd ([RendezvousReplica.wakeHmacEnvelope]).
  /// When present, the relay stamps it into the wake-push it fires so
  /// the receiver's device can authenticate the wake (defeats presence-
  /// oracle / battery-DoS from leaked push tokens).  Supplying it routes
  /// the PUT through `veil_mailbox_put_with_wake_hmac`, which also
  /// carries [pushEnvelope] and [capabilityToken]; omitting it preserves
  /// the back-compat call path.
  ///
  /// Returns a [MailboxPutResult] describing the outcome.  Throws
  /// [VeilException] on transport / argument errors.
  Future<MailboxPutResult> put({
    required Uint8List receiverId,
    required Uint8List contentId,
    required Uint8List senderId,
    required Uint8List blob,
    Uint8List? pushEnvelope,
    Uint8List? capabilityToken,
    Uint8List? wakeHmacEnvelope,
  }) async {
    _validateId(receiverId, 'receiverId');
    _validateId(contentId, 'contentId');
    _validateId(senderId, 'senderId');
    if (blob.length > ffi.veilMaxDataLen) {
      throw ArgumentError(
        'blob length ${blob.length} exceeds veilMaxDataLen '
        '(${ffi.veilMaxDataLen})',
      );
    }
    // Blocking onion deposit to the relay — off-isolate via a TOP-LEVEL worker
    // (sendable captures only) so a slow/unreachable relay never blocks the
    // calling isolate or freezes the UI. MailboxPutResult is plain data.
    final handleAddr = _handle.address;
    return Isolate.run(() => _putWorker(handleAddr, receiverId, contentId,
        senderId, blob, pushEnvelope, capabilityToken, wakeHmacEnvelope));
  }

  /// Fetch all blobs currently pending for [receiverId].  [authCookie]
  /// (16 bytes) must match a previously-registered rendezvous-publisher
  /// entry on the daemon — typically the cookie persisted alongside the
  /// receiver's identity.
  ///
  /// Implementation note: the FFI surface is a two-call protocol
  /// ([veil_mailbox_fetch_count] + [veil_mailbox_fetch_into])
  /// to avoid hidden allocations through the boundary.  This wrapper
  /// hides the dance: caller just gets back a `List<MailboxBlob>`.
  ///
  /// Returns an empty list when no blobs are pending.  Throws
  /// [VeilException] on transport / argument errors.
  Future<List<MailboxBlob>> fetch({
    required Uint8List receiverId,
    required Uint8List authCookie,
  }) async {
    _validateId(receiverId, 'receiverId');
    if (authCookie.length != 16) {
      throw ArgumentError(
        'authCookie must be 16 bytes, got ${authCookie.length}',
      );
    }
    // M23: serialize behind any in-flight fetch on this mailbox (single-slot
    // daemon cache). Ignore a prior fetch's outcome so one failure can't block
    // the next; always release the gate when this fetch finishes.
    final prev = _fetchGate;
    final gate = Completer<void>();
    _fetchGate = gate.future;
    try {
      await prev;
    } catch (_) {}
    try {
      // The two-call fetch hits the daemon/relay over the network — off-isolate
      // via a TOP-LEVEL worker (sendable captures only) so the 30s drain never
      // blocks the calling isolate / UI. The _fetchGate serialization stays here.
      final handleAddr = _handle.address;
      return await Isolate.run(
          () => _fetchWorker(handleAddr, receiverId, authCookie));
    } finally {
      gate.complete();
    }
  }

  /// Acknowledge end-to-end receipt of a blob.  Daemon deletes the
  /// blob and releases its quota slice.  Call this AFTER the receiver
  /// has successfully decrypted and persisted the payload.
  ///
  /// Idempotent: re-acking an already-removed blob is a silent no-op
  /// and returns `false`.  Returns `true` iff the daemon removed a
  /// blob in response to this call.
  ///
  /// Throws [VeilException] on transport / argument errors.
  Future<bool> ack({
    required Uint8List receiverId,
    required Uint8List contentId,
    required Uint8List authCookie,
  }) async {
    _validateId(receiverId, 'receiverId');
    _validateId(contentId, 'contentId');
    if (authCookie.length != 16) {
      throw ArgumentError(
        'authCookie must be 16 bytes, got ${authCookie.length}',
      );
    }
    return Future(() {
      final recv = calloc<Uint8>(32);
      final content = calloc<Uint8>(32);
      final cookie = calloc<Uint8>(16);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        recv.asTypedList(32).setAll(0, receiverId);
        content.asTypedList(32).setAll(0, contentId);
        cookie.asTypedList(16).setAll(0, authCookie);
        final rc = ffi.veilMailboxAck(_handle, recv, content, cookie, errOut);
        if (rc < 0) {
          throw VeilException(
            'mailbox_ack failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        return rc == 1;
      } finally {
        calloc.free(recv);
        calloc.free(content);
        // authCookie is a 16-byte mailbox capability secret — wipe before free.
        zeroizeNative(cookie, 16);
        calloc.free(cookie);
        calloc.free(errOut);
      }
    });
  }

  /// Look up the rendezvous replicas currently advertised for
  /// [receiverId] (push wake-HMAC end-to-end).  Each entry bundles the
  /// relay's node_id plus the three per-replica blobs a sender needs to
  /// deposit an authenticated, wake-pushing message: the sealed push
  /// envelope, the receiver-signed capability token, and the sealed
  /// wake-HMAC envelope.  Feed a chosen [RendezvousReplica] straight
  /// into [put] (`pushEnvelope` / `capabilityToken` / `wakeHmacEnvelope`).
  ///
  /// [maxReplicas] caps how many entries the daemon returns; `0` (the
  /// default) lets the daemon pick its own cap.  Values are clamped to
  /// the `u8` wire field (`0..255`).
  ///
  /// Returns an empty list when the receiver advertises no replicas.
  /// Throws [VeilException] on transport / argument errors, and on a
  /// malformed / truncated reply buffer (defensive — a well-behaved
  /// daemon never emits one).
  Future<List<RendezvousReplica>> lookupRendezvousReplicas(
    Uint8List receiverId, {
    int maxReplicas = 0,
  }) async {
    _validateId(receiverId, 'receiverId');
    if (maxReplicas < 0 || maxReplicas > 255) {
      throw ArgumentError(
        'maxReplicas must be in 0..255, got $maxReplicas',
      );
    }
    // Blocking DHT FIND (hit on every stash/drain to resolve the receiver's
    // relay) — off-isolate via a TOP-LEVEL worker (sendable captures only) so it
    // never blocks the calling isolate / UI. RendezvousReplica is plain data
    // (sendable across the isolate boundary).
    final handleAddr = _handle.address;
    return Isolate.run(
        () => _lookupReplicasWorker(handleAddr, receiverId, maxReplicas));
  }

  /// Seal [data] for [recipient]'s ([appId], [endpointId]) into an offline
  /// mailbox blob: the node signs an auth-deliver, resolves the recipient's
  /// ML-KEM cert over the DHT, and fan-out-encrypts. Returns the blob to hand to
  /// [put]. Throws [VeilException] if the node has no identity, can't resolve the
  /// recipient, or the seal fails.
  Future<Uint8List> seal({
    required Uint8List recipient,
    required Uint8List appId,
    required int endpointId,
    required Uint8List data,
  }) async {
    _validateId(recipient, 'recipient');
    _validateId(appId, 'appId');
    // ML-KEM cert resolution over the DHT + fan-out encryption — blocking, hit on
    // every stash. Off-isolate via a TOP-LEVEL worker (sendable captures only).
    final handleAddr = _handle.address;
    return Isolate.run(
        () => _sealWorker(handleAddr, recipient, appId, endpointId, data));
  }

  /// Open + verify a fetched mailbox [blob] claimed to be from [sender],
  /// decrypting under our current cert version [ourCertVersion]. Returns the
  /// verified destination + plaintext. Throws [VeilException] on a failed
  /// decrypt / signature / freshness check.
  Future<MailboxOpened> open({
    required Uint8List blob,
    required int ourCertVersion,
  }) async {
    return Future(() {
      final blobPtr = calloc<Uint8>(blob.isEmpty ? 1 : blob.length);
      final outSender = calloc<Uint8>(32);
      final outAppId = calloc<Uint8>(32);
      final outEndpoint = calloc<Uint32>();
      final outData = calloc<Pointer<Uint8>>();
      final outDataLen = calloc<IntPtr>();
      final errOut = calloc<Pointer<Utf8>>();
      try {
        if (blob.isNotEmpty) blobPtr.asTypedList(blob.length).setAll(0, blob);
        final rc = ffi.veilMailboxOpen(
          _handle,
          ourCertVersion,
          blobPtr,
          blob.length,
          outSender,
          outAppId,
          outEndpoint,
          outData,
          outDataLen,
          errOut,
        );
        if (rc != ffi.veilOk) {
          throw VeilException(
            'mailbox_open failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
        final senderNodeId = Uint8List.fromList(outSender.asTypedList(32));
        final appId = Uint8List.fromList(outAppId.asTypedList(32));
        final endpointId = outEndpoint.value;
        final dataPtr = outData.value;
        final dataLen = outDataLen.value;
        Uint8List payload;
        if (dataPtr == nullptr) {
          payload = Uint8List(0);
        } else {
          try {
            payload = Uint8List.fromList(dataPtr.asTypedList(dataLen));
          } finally {
            ffi.veilFreeBuf(dataPtr, dataLen);
          }
        }
        return MailboxOpened(
          senderNodeId: senderNodeId,
          appId: appId,
          endpointId: endpointId,
          data: payload,
        );
      } finally {
        calloc.free(blobPtr);
        calloc.free(outSender);
        calloc.free(outAppId);
        calloc.free(outEndpoint);
        calloc.free(outData);
        calloc.free(outDataLen);
        calloc.free(errOut);
      }
    });
  }

  /// Library-internal: construct against a client's borrowed handle.
  /// External code goes through [VeilClient.mailbox] which calls
  /// this with the right pointer.
  static VeilMailbox forHandle(Pointer<ffi.VeilHandle> handle) =>
      VeilMailbox._(handle);
}

/// Result of [VeilMailbox.open]: the verified sender + destination + plaintext
/// of an opened offline-mailbox blob.
class MailboxOpened {
  /// The verified sender + destination routing target + payload.
  const MailboxOpened({
    required this.senderNodeId,
    required this.appId,
    required this.endpointId,
    required this.data,
  });

  /// Verified sender node_id (32 bytes) — recovered from the blob's sidecar and
  /// confirmed by the auth-deliver signature, NOT a relay-supplied wire hint.
  final Uint8List senderNodeId;

  /// Verified destination app id (32 bytes).
  final Uint8List appId;

  /// Verified destination endpoint id.
  final int endpointId;

  /// Verified plaintext.
  final Uint8List data;
}

/// Parse the length-prefixed replica buffer returned by
/// `veil_lookup_rendezvous_replicas`.  All integers are
/// LITTLE-ENDIAN.  Layout:
///
///   count:u32
///   per entry ×count:
///     relay_node_id : u8[32]
///     valid_until_unix : u64
///     push_len : u16  + push_envelope      [push_len bytes]
///     cap_len  : u16  + capability_token   [cap_len  bytes]
///     wake_len : u16  + wake_hmac_envelope [wake_len bytes]
///
/// Every field read is bounds-checked against [bytes.length]; a short
/// or inconsistent buffer throws [VeilException] rather than reading
/// out of range.
// ── Off-isolate workers (TOP-LEVEL: capture only sendable values) ────────
// An inline `Isolate.run(() {...})` over these instance methods was captured as
// unsendable ("object is unsendable - Class: VeilMailbox"); delegating to a
// top-level function keeps the sent computation free of `this`. The veil handle
// is a process-global token, re-derived in the worker from its raw int address.

List<RendezvousReplica> _lookupReplicasWorker(
    int handleAddr, Uint8List receiverId, int maxReplicas) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final recv = calloc<Uint8>(32);
  final outBuf = calloc<Pointer<Uint8>>();
  final outLen = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    recv.asTypedList(32).setAll(0, receiverId);
    final rc = ffi.veilLookupRendezvousReplicas(
        handle, recv, maxReplicas, outBuf, outLen, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(
          'lookup_rendezvous_replicas failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
    final bufPtr = outBuf.value;
    final len = outLen.value;
    if (bufPtr == nullptr || len == 0) return <RendezvousReplica>[];
    try {
      final bytes = Uint8List.fromList(bufPtr.asTypedList(len));
      return _parseReplicaBuffer(bytes);
    } finally {
      ffi.veilFreeReplicaBuf(bufPtr, len);
    }
  } finally {
    calloc.free(recv);
    calloc.free(outBuf);
    calloc.free(outLen);
    calloc.free(errOut);
  }
}

Uint8List _sealWorker(int handleAddr, Uint8List recipient, Uint8List appId,
    int endpointId, Uint8List data) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final rec = calloc<Uint8>(32);
  final app = calloc<Uint8>(32);
  final dataPtr = calloc<Uint8>(data.isEmpty ? 1 : data.length);
  final outBuf = calloc<Pointer<Uint8>>();
  final outLen = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    rec.asTypedList(32).setAll(0, recipient);
    app.asTypedList(32).setAll(0, appId);
    if (data.isNotEmpty) dataPtr.asTypedList(data.length).setAll(0, data);
    final rc = ffi.veilMailboxSeal(
        handle, rec, app, endpointId, dataPtr, data.length, outBuf, outLen, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException('mailbox_seal failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
    final bufPtr = outBuf.value;
    final len = outLen.value;
    if (bufPtr == nullptr) return Uint8List(0);
    try {
      return Uint8List.fromList(bufPtr.asTypedList(len));
    } finally {
      ffi.veilFreeBuf(bufPtr, len);
    }
  } finally {
    calloc.free(rec);
    calloc.free(app);
    calloc.free(dataPtr);
    calloc.free(outBuf);
    calloc.free(outLen);
    calloc.free(errOut);
  }
}

MailboxPutResult _putWorker(
    int handleAddr,
    Uint8List receiverId,
    Uint8List contentId,
    Uint8List senderId,
    Uint8List blob,
    Uint8List? pushEnvelope,
    Uint8List? capabilityToken,
    Uint8List? wakeHmacEnvelope) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final recv = calloc<Uint8>(32);
  final content = calloc<Uint8>(32);
  final sender = calloc<Uint8>(32);
  final blobPtr = blob.isEmpty ? nullptr : calloc<Uint8>(blob.length);
  final pushPtr = (pushEnvelope == null || pushEnvelope.isEmpty)
      ? nullptr
      : calloc<Uint8>(pushEnvelope.length);
  final tokenPtr = (capabilityToken == null || capabilityToken.isEmpty)
      ? nullptr
      : calloc<Uint8>(capabilityToken.length);
  final wakePtr = (wakeHmacEnvelope == null || wakeHmacEnvelope.isEmpty)
      ? nullptr
      : calloc<Uint8>(wakeHmacEnvelope.length);
  final outEvicted = calloc<Uint32>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    recv.asTypedList(32).setAll(0, receiverId);
    content.asTypedList(32).setAll(0, contentId);
    sender.asTypedList(32).setAll(0, senderId);
    if (blob.isNotEmpty) blobPtr.asTypedList(blob.length).setAll(0, blob);
    if (pushEnvelope != null && pushEnvelope.isNotEmpty) {
      pushPtr.asTypedList(pushEnvelope.length).setAll(0, pushEnvelope);
    }
    if (capabilityToken != null && capabilityToken.isNotEmpty) {
      tokenPtr.asTypedList(capabilityToken.length).setAll(0, capabilityToken);
    }
    if (wakeHmacEnvelope != null && wakeHmacEnvelope.isNotEmpty) {
      wakePtr.asTypedList(wakeHmacEnvelope.length).setAll(0, wakeHmacEnvelope);
    }
    final int rc;
    if (wakeHmacEnvelope != null && wakeHmacEnvelope.isNotEmpty) {
      rc = ffi.veilMailboxPutWithWakeHmac(
          handle,
          recv,
          content,
          sender,
          blobPtr,
          blob.length,
          pushPtr,
          pushEnvelope?.length ?? 0,
          tokenPtr,
          capabilityToken?.length ?? 0,
          wakePtr,
          wakeHmacEnvelope.length,
          outEvicted,
          errOut);
    } else if (tokenPtr == nullptr) {
      rc = ffi.veilMailboxPut(handle, recv, content, sender, blobPtr, blob.length,
          pushPtr, pushEnvelope?.length ?? 0, outEvicted, errOut);
    } else {
      rc = ffi.veilMailboxPutWithCapability(
          handle,
          recv,
          content,
          sender,
          blobPtr,
          blob.length,
          pushPtr,
          pushEnvelope?.length ?? 0,
          tokenPtr,
          capabilityToken!.length,
          outEvicted,
          errOut);
    }
    if (rc < 0) {
      throw VeilException('mailbox_put failed: ${_readErrAndFree(errOut)}',
          code: rc);
    }
    return MailboxPutResult(
        status: MailboxPutStatus.fromWire(rc), evicted: outEvicted.value);
  } finally {
    calloc.free(recv);
    calloc.free(content);
    calloc.free(sender);
    if (blobPtr != nullptr) calloc.free(blobPtr);
    if (pushPtr != nullptr) calloc.free(pushPtr);
    if (tokenPtr != nullptr) {
      zeroizeNative(tokenPtr, capabilityToken!.length);
      calloc.free(tokenPtr);
    }
    if (wakePtr != nullptr) calloc.free(wakePtr);
    calloc.free(outEvicted);
    calloc.free(errOut);
  }
}

List<MailboxBlob> _fetchWorker(
    int handleAddr, Uint8List receiverId, Uint8List authCookie) {
  final handle = Pointer<ffi.VeilHandle>.fromAddress(handleAddr);
  final recv = calloc<Uint8>(32);
  final cookie = calloc<Uint8>(16);
  final outCount = calloc<Uint32>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    recv.asTypedList(32).setAll(0, receiverId);
    cookie.asTypedList(16).setAll(0, authCookie);
    final rc1 = ffi.veilMailboxFetchCount(handle, recv, cookie, outCount, errOut);
    if (rc1 != ffi.veilOk) {
      throw VeilException(
          'mailbox_fetch_count failed: ${_readErrAndFree(errOut)}', code: rc1);
    }
    final count = outCount.value;
    if (count == 0) return <MailboxBlob>[];
    const maxPendingBlobs = 8192;
    if (count > maxPendingBlobs) {
      throw VeilException(
          'mailbox returned an implausible pending count ($count > '
          '$maxPendingBlobs) — refusing to allocate',
          code: ffi.veilErr);
    }
    const blobBufLen = ffi.veilMaxDataLen;
    final descriptors = calloc<ffi.VeilMailboxBlobStruct>(count);
    final blobBuf = calloc<Uint8>(blobBufLen);
    try {
      final rc2 = ffi.veilMailboxFetchInto(
          handle, descriptors, count, blobBuf, blobBufLen, errOut);
      if (rc2 < 0) {
        throw VeilException(
            'mailbox_fetch_into failed: ${_readErrAndFree(errOut)}', code: rc2);
      }
      final result = <MailboxBlob>[];
      for (var i = 0; i < rc2; i++) {
        final d = descriptors[i];
        final senderId = Uint8List(32);
        final contentId = Uint8List(32);
        for (var j = 0; j < 32; j++) {
          senderId[j] = d.senderId[j];
          contentId[j] = d.contentId[j];
        }
        final blob = d.blobLen > 0
            ? Uint8List.fromList(d.blob.asTypedList(d.blobLen))
            : Uint8List(0);
        result.add(MailboxBlob(
            senderId: senderId,
            contentId: contentId,
            depositedAt: d.depositedAt,
            data: blob));
      }
      return result;
    } finally {
      calloc.free(descriptors);
      calloc.free(blobBuf);
    }
  } finally {
    calloc.free(recv);
    zeroizeNative(cookie, 16);
    calloc.free(cookie);
    calloc.free(outCount);
    calloc.free(errOut);
  }
}

List<RendezvousReplica> _parseReplicaBuffer(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  final total = bytes.length;
  var off = 0;

  int needU16() {
    if (off + 2 > total) {
      throw VeilException(
        'malformed replica buffer: want u16 at $off, have $total',
      );
    }
    final v = data.getUint16(off, Endian.little);
    off += 2;
    return v;
  }

  if (off + 4 > total) {
    throw VeilException(
      'malformed replica buffer: want count:u32, have $total bytes',
    );
  }
  final count = data.getUint32(off, Endian.little);
  off += 4;

  Uint8List takeBytes(int n, String field) {
    if (n < 0 || off + n > total) {
      throw VeilException(
        'malformed replica buffer: $field len $n at $off overruns $total',
      );
    }
    // Copy (not view) so each blob owns its backing store independently
    // of the parse buffer.
    final out = Uint8List.fromList(bytes.sublist(off, off + n));
    off += n;
    return out;
  }

  final replicas = <RendezvousReplica>[];
  for (var i = 0; i < count; i++) {
    final relayNodeId = takeBytes(32, 'relay_node_id');
    if (off + 8 > total) {
      throw VeilException(
        'malformed replica buffer: want valid_until_unix:u64 at $off, '
        'have $total',
      );
    }
    final validUntilUnix = data.getUint64(off, Endian.little);
    off += 8;
    final pushLen = needU16();
    final pushEnvelope = takeBytes(pushLen, 'push_envelope');
    final capLen = needU16();
    final capabilityToken = takeBytes(capLen, 'capability_token');
    final wakeLen = needU16();
    final wakeHmacEnvelope = takeBytes(wakeLen, 'wake_hmac_envelope');
    // v5 KEM trailer: algo byte + u16-length-prefixed relay KEM pubkey.
    if (off + 1 > total) {
      throw VeilException(
        'malformed replica buffer: want rendezvous_kem_algo:u8 at $off, '
        'have $total',
      );
    }
    final rendezvousKemAlgo = data.getUint8(off);
    off += 1;
    final kemLen = needU16();
    final rendezvousKemPk = takeBytes(kemLen, 'rendezvous_kem_pk');
    replicas.add(RendezvousReplica(
      relayNodeId: relayNodeId,
      validUntilUnix: validUntilUnix,
      pushEnvelope: pushEnvelope,
      capabilityToken: capabilityToken,
      wakeHmacEnvelope: wakeHmacEnvelope,
      rendezvousKemAlgo: rendezvousKemAlgo,
      rendezvousKemPk: rendezvousKemPk,
    ));
  }
  // Defensive (audit F3): the buffer must be fully consumed. A daemon bug that
  // emitted `count` smaller than the actual entry data would otherwise silently
  // drop trailing replicas; surface it instead of masking it.
  if (off != total) {
    throw VeilException(
      'malformed replica buffer: consumed $off of $total bytes (count=$count)',
    );
  }
  return replicas;
}

void _validateId(Uint8List id, String name) {
  if (id.length != 32) {
    throw ArgumentError('$name must be 32 bytes, got ${id.length}');
  }
}

String _readErrAndFree(Pointer<Pointer<Utf8>> errOut) {
  final errPtr = errOut.value;
  if (errPtr == nullptr) return '<no detail>';
  final msg = errPtr.toDartString();
  ffi.veilFreeString(errPtr);
  errOut.value = nullptr;
  return msg;
}
