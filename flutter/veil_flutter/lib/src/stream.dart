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
//     belt-and-suspenders against a forgotten `.close()`).
//
// Threading note (diff-audit H3): the underlying FFI calls block the calling
// Dart thread for one daemon round-trip (`block_on` in Rust).  `read()` — which
// can block INDEFINITELY waiting for data — runs on a WORKER isolate via
// `Isolate.run` so it never freezes the UI isolate (Android ANR).  `write()`
// completes promptly (flow-controlled) so it stays on `Future(() {...})` like
// the rest of the surface.  Safe to drive the stream from a worker isolate: the
// stream handle is a generational handle-table KEY (see `veil_stream_close` in
// veilclient-ffi), Arc-looked-up per call, so a read racing `close()` returns a
// clean table-miss error rather than a use-after-free.

import 'dart:async';
import 'dart:collection';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'types.dart';

const _anonStreamReadConcurrency = int.fromEnvironment(
  'VEIL_ANON_STREAM_READ_CONCURRENCY',
  defaultValue: 4,
);
const _anonStreamWriteConcurrency = int.fromEnvironment(
  'VEIL_ANON_STREAM_WRITE_CONCURRENCY',
  defaultValue: 1,
);

int _clampAnonStreamConcurrency(int value) {
  if (value < 1) return 1;
  if (value > 16) return 16;
  return value;
}

final _anonStreamReadGate = _AsyncGate(
  _clampAnonStreamConcurrency(_anonStreamReadConcurrency),
);
final _anonStreamWriteGate = _AsyncGate(
  _clampAnonStreamConcurrency(_anonStreamWriteConcurrency),
);

/// Tiny FIFO async semaphore for native anonymous-stream calls.
///
/// `Isolate.run` protects the UI isolate from a blocking FFI call, but firing a
/// new worker isolate for every concurrent range-stream chunk lets the Dart side
/// pre-buffer multiple 256 KiB writes into independent onion-stream drivers. The
/// Rust sender already paces DATA cells per destination; this gate keeps the FFI
/// boundary from building a second, larger queue above that pacer. Reads have a
/// separate gate so a slow write can never starve receive-window draining.
class _AsyncGate {
  _AsyncGate(this._capacity) : _available = _capacity;

  final int _capacity;
  int _available;
  final _waiters = Queue<Completer<void>>();

  Future<T> run<T>(Future<T> Function() op) async {
    await _acquire();
    try {
      return await op();
    } finally {
      _release();
    }
  }

  Future<void> _acquire() {
    if (_available > 0) {
      _available--;
      return Future<void>.value();
    }
    final waiter = Completer<void>();
    _waiters.addLast(waiter);
    return waiter.future;
  }

  void _release() {
    if (_waiters.isNotEmpty) {
      _waiters.removeFirst().complete();
      return;
    }
    if (_available < _capacity) {
      _available++;
    }
  }
}

/// Top-level FFI stream read, run on a WORKER isolate via [Isolate.run]
/// (diff-audit H3). Top-level (not a method) so the closure captures only the
/// sendable `int` address + `maxBytes`, never `this`. The stream handle is a
/// generational table key; `Pointer.fromAddress` + the FFI's own Arc lookup make
/// cross-isolate use safe.
Uint8List _ffiStreamReadOffIsolate(int streamAddr, int maxBytes) {
  final stream = Pointer<ffi.VeilStreamFfi>.fromAddress(streamAddr);
  final buf = calloc<Uint8>(maxBytes);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final n = ffi.veilStreamRead(stream, buf, maxBytes, errOut);
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
}

/// GC-time safety-net for [VeilStream].  Fires
/// `veil_stream_close` if the Dart object is GC'd without an
/// explicit [VeilStream.close] — every live stream keeps an
/// Arc'd `VeilStreamFfi` (which itself holds an Arc to the
/// runtime bundle), so a forgotten close stalls runtime tear-down.
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
    // H3: run the (potentially indefinitely-blocking) FFI read on a WORKER
    // isolate so a read with no data never freezes the UI isolate. The handle is
    // passed by address (sendable); see `_ffiStreamReadOffIsolate`.
    final addr = _stream.address;
    return Isolate.run(() => _ffiStreamReadOffIsolate(addr, maxBytes));
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

/// Off-isolate FFI write for [VeilAnonStream]. Top-level so the closure captures
/// only the sendable address + bytes. CRITICAL: the FFI write `block_on`s and can
/// BLOCK when the send buffer back-pressures (a slow onion can't drain it) — on
/// the UI isolate that is an ANR, so writes run on a worker isolate like reads.
void _ffiAnonStreamWriteOffIsolate(int streamAddr, Uint8List data) {
  final stream = Pointer<ffi.VeilAnonStreamFfi>.fromAddress(streamAddr);
  final dataPtr = data.isEmpty ? nullptr : calloc<Uint8>(data.length);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    if (data.isNotEmpty) {
      dataPtr.asTypedList(data.length).setAll(0, data);
    }
    final rc = ffi.veilAnonStreamWrite(stream, dataPtr, data.length, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(
        'anon stream write failed: ${_readErrAndFree(errOut)}',
        code: rc,
      );
    }
  } finally {
    if (dataPtr != nullptr) calloc.free(dataPtr);
    calloc.free(errOut);
  }
}

/// Off-isolate FFI finish for [VeilAnonStream] (same ANR concern as write).
void _ffiAnonStreamFinishOffIsolate(int streamAddr) {
  final stream = Pointer<ffi.VeilAnonStreamFfi>.fromAddress(streamAddr);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilAnonStreamFinish(stream, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(
        'anon stream finish failed: ${_readErrAndFree(errOut)}',
        code: rc,
      );
    }
  } finally {
    calloc.free(errOut);
  }
}

/// Off-isolate FFI read for [VeilAnonStream] (mirrors [_ffiStreamReadOffIsolate]).
Uint8List _ffiAnonStreamReadOffIsolate(int streamAddr, int maxBytes) {
  final stream = Pointer<ffi.VeilAnonStreamFfi>.fromAddress(streamAddr);
  final buf = calloc<Uint8>(maxBytes);
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final n = ffi.veilAnonStreamRead(stream, buf, maxBytes, errOut);
    if (n < 0) {
      throw VeilException(
        'anon stream read failed: ${_readErrAndFree(errOut)}',
        code: n,
      );
    }
    if (n == 0) return Uint8List(0);
    return Uint8List.fromList(buf.asTypedList(n));
  } finally {
    calloc.free(buf);
    calloc.free(errOut);
  }
}

/// An ANONYMOUS reliable bidirectional byte-stream (onion-routed, congestion-
/// controlled). Same surface as [VeilStream], but reaches NAT'd/anonymous peers
/// the direct stream can't (it rides the rendezvous transport with app-layer
/// ARQ + CC). Construct via [VeilClient.openAnonStream] / [acceptAnonStream].
///
/// `read` returns empty on clean EOF; a [VeilException] (negative code) means
/// the stream was RESET (interrupted) — the app should resume, not treat it as
/// a clean end.
class VeilAnonStream {
  VeilAnonStream._(this._stream);

  final Pointer<ffi.VeilAnonStreamFfi> _stream;
  bool _closed = false;

  /// Queue [data] for reliable delivery (flow-controlled). Empty is a no-op.
  /// Runs on a worker isolate — the FFI write can block on back-pressure, which
  /// on the UI isolate would freeze the app (ANR).
  Future<void> write(Uint8List data) async {
    _ensureOpen();
    if (data.length > ffi.veilMaxDataLen) {
      throw ArgumentError(
        'data length ${data.length} exceeds veilMaxDataLen (${ffi.veilMaxDataLen})',
      );
    }
    final addr = _stream.address;
    return _anonStreamWriteGate.run(
      () => Isolate.run(() => _ffiAnonStreamWriteOffIsolate(addr, data)),
    );
  }

  /// Read up to [maxBytes]. Empty = clean EOF. Runs on a worker isolate (the
  /// FFI read blocks until data arrives).
  Future<Uint8List> read({int maxBytes = 65536}) async {
    _ensureOpen();
    if (maxBytes <= 0 || maxBytes > ffi.veilMaxDataLen) {
      throw ArgumentError('maxBytes out of range: $maxBytes');
    }
    final addr = _stream.address;
    return _anonStreamReadGate.run(
      () => Isolate.run(() => _ffiAnonStreamReadOffIsolate(addr, maxBytes)),
    );
  }

  /// Half-close the send direction (a FIN follows the last queued byte); the
  /// peer reads EOF. Off-isolate (same ANR concern as [write]).
  Future<void> finish() async {
    _ensureOpen();
    final addr = _stream.address;
    return _anonStreamWriteGate.run(
      () => Isolate.run(() => _ffiAnonStreamFinishOffIsolate(addr)),
    );
  }

  /// Close + release the handle (idempotent).
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    ffi.veilAnonStreamClose(_stream);
  }

  void _ensureOpen() {
    if (_closed) {
      throw VeilException('anon stream already closed',
          code: ffi.veilErrClosed);
    }
  }

  /// Internal: wrap a raw FFI pointer from `veil_anon_stream_open/accept`.
  static VeilAnonStream fromFfi(Pointer<ffi.VeilAnonStreamFfi> ptr) =>
      VeilAnonStream._(ptr);
}
