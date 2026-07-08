/// veil_media — control API for the veil call media engine.
///
/// Drives a codec-stripped libwebrtc over the veil media datagram channel.
/// Per-packet RTP/RTCP flows native<->native (see the C++ Transport shim); this
/// Dart surface is CONTROL ONLY: create/start/stop, mute, device select, stats.
///
/// Typical use (Phase 3 audio call):
///   final chan = await transport.openMediaChannel(peerNode);  // veilclient-ffi
///   final engine = VeilMediaEngine.create(veilChan: chan, peerId: peerNode)!;
///   engine.startAudio();
///   ...
///   engine.stopAudio();
///   engine.dispose();           // caller closes `chan` separately
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart' as ffi;

/// An enumerated audio device.
class MediaDevice {
  const MediaDevice({required this.id, required this.label, required this.kind});

  final String id;
  final String label;
  final String kind; // "input" | "output"

  factory MediaDevice.fromJson(Map<String, dynamic> j) => MediaDevice(
        id: j['id'] as String? ?? '',
        label: j['label'] as String? ?? '',
        kind: j['kind'] as String? ?? '',
      );
}

/// A decoded remote video frame: tightly-packed RGBA (width*height*4 bytes).
class VeilVideoFrame {
  const VeilVideoFrame(
      {required this.rgba, required this.width, required this.height});
  final Uint8List rgba;
  final int width;
  final int height;
}

/// A live media engine bound to one veil media datagram channel.
class VeilMediaEngine {
  VeilMediaEngine._(this._ptr);

  final Pointer<ffi.VeilMediaEngineHandle> _ptr;
  bool _disposed = false;
  Pointer<Uint8>? _frameBuf; // reused RGBA pull buffer
  int _frameCap = 0;
  int _lastFrameSeq = 0;

  /// Create an engine over an already-open veil media channel [veilChan]
  /// (from `VeilFlutterTransport.openMediaChannel`). [localId] is OUR 32-byte
  /// node id and [peerId] the peer's — SSRCs are derived from them so the two
  /// ends agree without extra negotiation. Returns null if native create fails.
  static VeilMediaEngine? create({
    required int veilChan,
    required Uint8List localId,
    required Uint8List peerId,
  }) {
    if (localId.length != 32 || peerId.length != 32) {
      throw ArgumentError('localId and peerId must be 32 bytes');
    }
    final local = calloc<Uint8>(32)..asTypedList(32).setAll(0, localId);
    final peer = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerId);
    try {
      final ptr = ffi.veilMediaEngineCreate(veilChan, local, peer);
      if (ptr == nullptr) return null;
      return VeilMediaEngine._(ptr);
    } finally {
      calloc.free(local);
      calloc.free(peer);
    }
  }

  /// Start the Opus audio session. Idempotent per direction.
  bool startAudio({bool send = true, bool recv = true}) {
    _ensure();
    return ffi.veilMediaEngineStartAudio(_ptr, send ? 1 : 0, recv ? 1 : 0) == 0;
  }

  bool stopAudio() {
    _ensure();
    return ffi.veilMediaEngineStopAudio(_ptr) == 0;
  }

  /// Start the VP8 video session over the same veil channel (distinct SSRC).
  /// With VEIL_MEDIA_TEST_VIDEO=1 the send stream is driven by a built-in
  /// synthetic frame generator (pipeline bring-up); otherwise feed it via a
  /// platform capturer (native). Idempotent per direction.
  bool startVideo({bool send = true, bool recv = true}) {
    _ensure();
    return ffi.veilMediaEngineStartVideo(_ptr, send ? 1 : 0, recv ? 1 : 0) == 0;
  }

  bool stopVideo() {
    _ensure();
    return ffi.veilMediaEngineStopVideo(_ptr) == 0;
  }

  /// Open the platform camera and drive the video send stream from it (video
  /// send must already be started). Returns false if this platform has no
  /// camera backend (Android, for now) or the device can't be opened — the
  /// call still runs (receive/render unaffected). Idempotent.
  bool startCamera({int width = 352, int height = 198, int fps = 15}) {
    _ensure();
    return ffi.veilMediaEngineStartCamera(_ptr, width, height, fps) == 0;
  }

  bool stopCamera() {
    _ensure();
    return ffi.veilMediaEngineStopCamera(_ptr) == 0;
  }

  Pointer<Uint8>? _pushBuf; // reused Y|U|V staging buffer for pushVideoFrame
  int _pushCap = 0;

  /// Push one captured I420 frame (tightly packed: [y]=w*h, [u]=[v]=cw*ch) into
  /// the video send stream. For platforms without a native camera backend
  /// (Android), a Dart capturer converts camera frames to I420 and calls this.
  /// Returns false if video send isn't started. Not thread-safe; call from one
  /// isolate at the capture rate.
  bool pushVideoFrame(Uint8List y, Uint8List u, Uint8List v, int width, int height) {
    _ensure();
    final total = y.length + u.length + v.length;
    if (total <= 0) return false;
    if (_pushBuf == null || _pushCap < total) {
      if (_pushBuf != null) calloc.free(_pushBuf!);
      _pushCap = total;
      _pushBuf = calloc<Uint8>(_pushCap);
    }
    final buf = _pushBuf!;
    final view = buf.asTypedList(total);
    view.setRange(0, y.length, y);
    view.setRange(y.length, y.length + u.length, u);
    view.setRange(y.length + u.length, total, v);
    final yp = buf;
    final up = buf + y.length;
    final vp = buf + (y.length + u.length);
    final cw = (width + 1) ~/ 2;
    final rc = ffi.veilMediaEnginePushVideoFrame(
        _ptr, yp, up, vp, width, height, width, cw, cw, 0);
    return rc == 0;
  }

  /// The latest decoded remote video frame (RGBA), or null if there is no NEW
  /// frame since the last call. Poll at the display rate.
  VeilVideoFrame? getVideoFrame() {
    _ensure();
    final wp = calloc<Int32>();
    final hp = calloc<Int32>();
    try {
      _frameBuf ??= (() {
        _frameCap = 640 * 480 * 4;
        return calloc<Uint8>(_frameCap);
      })();
      var seq = ffi.veilMediaEngineGetVideoFrame(_ptr, _frameBuf!, _frameCap, wp, hp);
      if (seq == -1) {
        // Buffer too small — grow to the reported dimensions and retry once.
        final need = wp.value * hp.value * 4;
        if (need > 0) {
          calloc.free(_frameBuf!);
          _frameCap = need;
          _frameBuf = calloc<Uint8>(_frameCap);
          seq = ffi.veilMediaEngineGetVideoFrame(_ptr, _frameBuf!, _frameCap, wp, hp);
        }
      }
      if (seq <= 0 || seq == _lastFrameSeq) return null;
      _lastFrameSeq = seq;
      final w = wp.value, h = hp.value;
      if (w <= 0 || h <= 0) return null;
      final rgba = Uint8List.fromList(_frameBuf!.asTypedList(w * h * 4));
      return VeilVideoFrame(rgba: rgba, width: w, height: h);
    } finally {
      calloc.free(wp);
      calloc.free(hp);
    }
  }

  void setMicMuted(bool muted) {
    _ensure();
    ffi.veilMediaEngineSetMicMuted(_ptr, muted ? 1 : 0);
  }

  void setSpeakerMuted(bool muted) {
    _ensure();
    ffi.veilMediaEngineSetSpeakerMuted(_ptr, muted ? 1 : 0);
  }

  List<MediaDevice> listAudioInputs() =>
      _devices(ffi.veilMediaEngineListAudioInputs(_ptr));

  List<MediaDevice> listAudioOutputs() =>
      _devices(ffi.veilMediaEngineListAudioOutputs(_ptr));

  bool selectAudioInput(String id) => _select(id, ffi.veilMediaEngineSelectAudioInput);

  bool selectAudioOutput(String id) =>
      _select(id, ffi.veilMediaEngineSelectAudioOutput);

  /// Latest engine stats (packets/bytes tx/rx, rtt, jitter, loss, bitrate).
  Map<String, dynamic> getStats() {
    _ensure();
    final s = ffi.veilMediaEngineGetStats(_ptr);
    if (s == nullptr) return const {};
    try {
      final decoded = jsonDecode(s.toDartString());
      return decoded is Map<String, dynamic> ? decoded : const {};
    } finally {
      ffi.veilMediaFreeString(s);
    }
  }

  /// Tear down the engine. The veil media channel is owned by the caller and is
  /// NOT closed here.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    ffi.veilMediaEngineDestroy(_ptr);
    if (_frameBuf != null) {
      calloc.free(_frameBuf!);
      _frameBuf = null;
    }
    if (_pushBuf != null) {
      calloc.free(_pushBuf!);
      _pushBuf = null;
    }
  }

  /// Native engine build/version string.
  static String version() {
    final v = ffi.veilMediaVersion();
    return v == nullptr ? '' : v.toDartString();
  }

  // ---- helpers ----
  void _ensure() {
    if (_disposed) throw StateError('VeilMediaEngine used after dispose()');
  }

  bool _select(
      String id, int Function(Pointer<ffi.VeilMediaEngineHandle>, Pointer<Utf8>) fn) {
    _ensure();
    final c = id.toNativeUtf8();
    try {
      return fn(_ptr, c) == 0;
    } finally {
      calloc.free(c);
    }
  }

  List<MediaDevice> _devices(Pointer<Utf8> json) {
    if (json == nullptr) return const [];
    try {
      final decoded = jsonDecode(json.toDartString());
      if (decoded is! List) return const [];
      return decoded
          .whereType<Map<String, dynamic>>()
          .map(MediaDevice.fromJson)
          .toList(growable: false);
    } finally {
      ffi.veilMediaFreeString(json);
    }
  }
}
