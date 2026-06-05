// Reliable bidirectional byte-stream wrapper (Epic 489.3).
//
// Wraps the C-FFI `veil_stream_*` surface in `crates/veilclient-ffi/src/lib.rs`.
// Wire-level guarantees come from the daemon's SCTP-like reliable transport
// (window-based flow control, ordered delivery, retransmission); the Dart
// wrapper just plumbs bytes through.
//
// Lifetime:
//   * Open one via [AppHandle.openStream] — returns immediately once the
//     daemon has acknowledged the open handshake.
//   * Write with [write], read with [read] OR consume via [reads].
//   * Always call [close] when done (or rely on the attached
//     [NativeFinalizer] at line ~37, which invokes
//     `veil_stream_close_finalizer` when the Dart object is GC'd —
//     belt-and-suspenders against а forgotten `.close()`).
//
// Threading note: the underlying FFI calls block the calling Dart thread
// for the duration of one daemon round-trip (`block_on` in Rust on a
// pre-existing tokio worker pool).  We schedule each call via
// `Future(() { ... })` to match the rest of the high-level surface
// (see `client.dart` top-of-file).  A proper `Isolate.run` offload is
// listed in the audit-trail for a future refactor.

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'types.dart';

/// GC-time safety-net for [VeilStream].  Fires
/// `veil_stream_close` if the Dart object is GC'd without an
/// explicit [VeilStream.close] — every live stream keeps an
/// Arc'd `VeilStreamFfi` (which itself holds an Arc к the
/// runtime bundle), so а forgotten close stalls runtime tear-down.
final _veilStreamFinalizer = NativeFinalizer(
  ffi.veilStreamCloseFinalizerPtr.cast<NativeFinalizerFunction>(),
);

/// Reliable bidirectional byte-stream to a remote endpoint.
///
/// Construct via [AppHandle.openStream] — this class has no public
/// constructor and cannot be instantiated outside the library.
class VeilStream implements Finalizable {
  VeilStream._(this._stream) {
    _veilStreamFinalizer.attach(this, _stream.cast(), detach: this);
  }

  final Pointer<ffi.VeilStreamFfi> _stream;
  bool _closed = false;

  /// Background read-loop controller, lazily started on first [reads]
  /// subscription.  Single-subscriber broadcast — `null` until first use.
  StreamController<Uint8List>? _readsController;

  /// Write all of [data] to the stream.  Completes when the daemon has
  /// buffered the bytes (flow-controlled — applies daemon-side back-pressure
  /// if the peer's receive window is full).
  ///
  /// Throws [VeilException] on:
  ///   * Stream already closed (locally or by peer FIN).
  ///   * Daemon-side I/O error (peer reset, transport torn down, etc.).
  ///   * Argument error: empty [data] is OK (no-op); oversized [data] is
  ///     not — the FFI surface caps a single call at
  ///     [ffi.veilMaxDataLen] (16 MiB).  Chunk larger payloads.
  Future<void> write(Uint8List data) async {
    _ensureOpen();
    if (data.length > ffi.veilMaxDataLen) {
      throw ArgumentError(
        'data length ${data.length} exceeds veilMaxDataLen '
        '(${ffi.veilMaxDataLen})',
      );
    }
    return Future(() {
      final dataPtr = data.isEmpty ? nullptr : calloc<Uint8>(data.length);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        if (data.isNotEmpty) {
          dataPtr.asTypedList(data.length).setAll(0, data);
        }
        final rc = ffi.veilStreamWrite(_stream, dataPtr, data.length, errOut);
        if (rc != ffi.veilOk) {
          throw VeilException(
            'stream write failed: ${_readErrAndFree(errOut)}',
            code: rc,
          );
        }
      } finally {
        if (dataPtr != nullptr) calloc.free(dataPtr);
        calloc.free(errOut);
      }
    });
  }

  /// Read up to [maxBytes] bytes from the stream.  Returns an empty
  /// list ONLY when the peer has cleanly closed its write half (EOF) —
  /// subsequent calls keep returning empty.  Use [close] to release
  /// the local resources after EOF.
  ///
  /// Default `maxBytes` matches the typical TCP-ish chunk that a stream
  /// surfaces; can be raised to [ffi.veilMaxDataLen] (16 MiB) but the
  /// daemon will return whatever happens to be in the receive window —
  /// caller still needs to loop until the desired total is read.
  ///
  /// Throws [VeilException] on stream errors (closed, transport).
  Future<Uint8List> read({int maxBytes = 65536}) async {
    _ensureOpen();
    if (maxBytes <= 0) {
      throw ArgumentError('maxBytes must be > 0, got $maxBytes');
    }
    if (maxBytes > ffi.veilMaxDataLen) {
      throw ArgumentError(
        'maxBytes $maxBytes exceeds veilMaxDataLen '
        '(${ffi.veilMaxDataLen})',
      );
    }
    return Future(() {
      final buf = calloc<Uint8>(maxBytes);
      final errOut = calloc<Pointer<Utf8>>();
      try {
        final n = ffi.veilStreamRead(_stream, buf, maxBytes, errOut);
        if (n < 0) {
          throw VeilException(
            'stream read failed: ${_readErrAndFree(errOut)}',
            code: n,
          );
        }
        if (n == 0) return Uint8List(0);
        return Uint8List.fromList(buf.asTypedList(n));
      } finally {
        calloc.free(buf);
        calloc.free(errOut);
      }
    });
  }

  /// Convenience: convert the pull-based [read] API into a push-based
  /// `Stream<Uint8List>`.  Starts a background read-loop on first
  /// subscription; closes the controller cleanly on EOF or on [close].
  ///
  /// Single-subscriber semantics — calling twice returns the same
  /// underlying controller.  Wrap with `.asBroadcastStream()` if you
  /// need multiple listeners.
  ///
  /// [chunkSize] is the per-call `maxBytes` passed to [read].
  Stream<Uint8List> reads({int chunkSize = 65536}) {
    _ensureOpen();
    final existing = _readsController;
    if (existing != null) return existing.stream;
    final controller = StreamController<Uint8List>(
      onCancel: () async {
        // Subscription cancelled — drop the controller so a future
        // listener gets a fresh loop.  Does NOT close the stream
        // itself (caller must call [close] explicitly).
        _readsController = null;
      },
    );
    _readsController = controller;
    // Background loop — fires read() in a tight cycle.  Each read awaits
    // the daemon's block_on so the loop doesn't busy-spin.  Errors stop
    // the loop, EOF closes the controller.
    () async {
      try {
        while (!_closed && !controller.isClosed) {
          final chunk = await read(maxBytes: chunkSize);
          if (chunk.isEmpty) {
            // EOF — peer closed write half cleanly.
            await controller.close();
            break;
          }
          controller.add(chunk);
        }
      } catch (e, st) {
        if (!controller.isClosed) {
          controller.addError(e, st);
          await controller.close();
        }
      }
    }();
    return controller.stream;
  }

  /// Close the stream and release the C handle.  Safe to call multiple
  /// times.  Outstanding [reads] subscriptions receive a clean EOF
  /// (controller closed) once the next loop iteration observes
  /// [_closed].
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final ctl = _readsController;
    _readsController = null;
    _veilStreamFinalizer.detach(this);
    ffi.veilStreamClose(_stream);
    if (ctl != null && !ctl.isClosed) {
      await ctl.close();
    }
  }

  void _ensureOpen() {
    if (_closed) {
      throw VeilException('stream already closed', code: ffi.veilErrClosed);
    }
  }

  /// Internal: construct from a raw FFI pointer returned by
  /// `veil_stream_open`.  Called from `AppHandle.openStream`.
  static VeilStream fromFfi(Pointer<ffi.VeilStreamFfi> ptr) =>
      VeilStream._(ptr);
}

String _readErrAndFree(Pointer<Pointer<Utf8>> errOut) {
  final errPtr = errOut.value;
  if (errPtr == nullptr) return '<no detail>';
  final msg = errPtr.toDartString();
  ffi.veilFreeString(errPtr);
  errOut.value = nullptr;
  return msg;
}
