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
  const MediaDevice(
      {required this.id, required this.label, required this.kind, this.facing});

  final String id;
  final String label;
  final String kind; // "input" | "output"
  final String? facing; // "front" | "back" | "external" for cameras

  factory MediaDevice.fromJson(Map<String, dynamic> j) => MediaDevice(
        id: j['id'] as String? ?? '',
        label: j['label'] as String? ?? '',
        kind: j['kind'] as String? ?? '',
        facing: j['facing'] as String?,
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
  Pointer<Uint8>? _localFrameBuf; // reused local RGBA pull buffer
  int _localFrameCap = 0;
  int _lastLocalFrameSeq = 0;

  /// Address used only by platform-native frame producers. It is valid until
  /// [dispose] and must never be retained after their awaited stop barrier.
  int get nativeAddress {
    _ensure();
    return _ptr.address;
  }

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
  bool startVideo({
    bool send = true,
    bool recv = true,
    int maxBitrateKbps = 150,
    int maxFps = 15,
  }) {
    _ensure();
    return ffi.veilMediaEngineStartVideo(
          _ptr,
          send ? 1 : 0,
          recv ? 1 : 0,
          maxBitrateKbps,
          maxFps,
        ) ==
        0;
  }

  bool stopVideo() {
    _ensure();
    return ffi.veilMediaEngineStopVideo(_ptr) == 0;
  }

  /// Set the route-specific RTP packet ceiling before [startVideo]. Passing
  /// zero restores libwebrtc's default. Returns false after video send starts.
  bool setMaxRtpPacketSize(int bytes) {
    _ensure();
    if (bytes < 0) throw ArgumentError.value(bytes, 'bytes');
    return ffi.veilMediaEngineSetMaxRtpPacketSize(_ptr, bytes) == 0;
  }

  /// Retune the running video send stream to a new bitrate/fps budget without
  /// restarting it (link-quality adaptation). Returns false when video send
  /// isn't running.
  bool setVideoBitrate({required int maxBitrateKbps, required int maxFps}) {
    _ensure();
    return ffi.veilMediaEngineSetVideoBitrate(_ptr, maxBitrateKbps, maxFps) ==
        0;
  }

  /// Open the platform camera and drive the video send stream from it (video
  /// send must already be started). Returns false if this platform has no
  /// camera backend (Android, for now) or the device can't be opened — the
  /// call still runs (receive/render unaffected). Idempotent.
  bool startCamera({
    int width = 352,
    int height = 198,
    int fps = 15,
    String? deviceId,
  }) {
    _ensure();
    if (deviceId == null || deviceId.isEmpty) {
      return ffi.veilMediaEngineStartCamera(_ptr, width, height, fps) == 0;
    }
    final id = deviceId.toNativeUtf8();
    try {
      return ffi.veilMediaEngineStartCameraDevice(
            _ptr,
            id,
            width,
            height,
            fps,
          ) ==
          0;
    } finally {
      calloc.free(id);
    }
  }

  bool stopCamera() {
    _ensure();
    return ffi.veilMediaEngineStopCamera(_ptr) == 0;
  }

  /// Share the main display into the video send stream (video send must be
  /// started). Replaces a running camera as the single video source — the
  /// receiver renders it with no changes. Returns false where this platform
  /// has no screen backend (macOS only for now) or capture can't start. The
  /// first ever use triggers the OS Screen Recording consent prompt; until
  /// granted (plus an app restart) the share runs black. Idempotent.
  bool startScreen({int width = 640, int fps = 10}) {
    _ensure();
    return ffi.veilMediaEngineStartScreen(_ptr, width, fps) == 0;
  }

  bool stopScreen() {
    _ensure();
    return ffi.veilMediaEngineStopScreen(_ptr) == 0;
  }

  Pointer<Uint8>? _pushBuf; // reused Y|U|V staging buffer for pushVideoFrame
  int _pushCap = 0;

  /// Push one captured I420 frame (tightly packed: [y]=w*h, [u]=[v]=cw*ch) into
  /// the video send stream. For platforms without a native camera backend
  /// (Android), a Dart capturer converts camera frames to I420 and calls this.
  /// Returns false if video send isn't started. Not thread-safe; call from one
  /// isolate at the capture rate.
  bool pushVideoFrame(
      Uint8List y, Uint8List u, Uint8List v, int width, int height) {
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

  /// Push one Android Camera2 YUV_420_888 frame without doing per-pixel work
  /// in Dart. Plane buffers are copied once into reusable native staging;
  /// libyuv de-strides, converts and rotates them before WebRTC sees I420.
  bool pushAndroid420Frame(
    Uint8List y,
    Uint8List u,
    Uint8List v,
    int width,
    int height, {
    required int yStride,
    required int uStride,
    required int vStride,
    required int uvPixelStride,
    required int rotation,
  }) {
    _ensure();
    if (width <= 0 ||
        height <= 0 ||
        yStride <= 0 ||
        uStride <= 0 ||
        vStride <= 0 ||
        uvPixelStride <= 0 ||
        !const <int>{0, 90, 180, 270}.contains(rotation)) {
      return false;
    }
    final cw = (width + 1) ~/ 2;
    final ch = (height + 1) ~/ 2;
    final yNeeded = (height - 1) * yStride + width;
    final uNeeded = (ch - 1) * uStride + (cw - 1) * uvPixelStride + 1;
    final vNeeded = (ch - 1) * vStride + (cw - 1) * uvPixelStride + 1;
    if (y.length < yNeeded || u.length < uNeeded || v.length < vNeeded) {
      return false;
    }
    final total = y.length + u.length + v.length;
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
    return ffi.veilMediaEnginePushAndroid420Frame(
          _ptr,
          buf,
          buf + y.length,
          buf + y.length + u.length,
          width,
          height,
          yStride,
          uStride,
          vStride,
          uvPixelStride,
          rotation,
          0,
        ) ==
        0;
  }

  /// The latest decoded remote video frame (RGBA), or null if there is no NEW
  /// frame since the last call. Poll at the display rate.
  VeilVideoFrame? getVideoFrame() {
    return _getFrame(
      buffer: () => _frameBuf,
      setBuffer: (p) => _frameBuf = p,
      capacity: () => _frameCap,
      setCapacity: (v) => _frameCap = v,
      lastSeq: () => _lastFrameSeq,
      setLastSeq: (v) => _lastFrameSeq = v,
      pull: ffi.veilMediaEngineGetVideoFrame,
    );
  }

  /// The latest local camera frame (RGBA), or null if there is no NEW frame
  /// since the last call. Poll at the display rate for a self-preview tile.
  VeilVideoFrame? getLocalVideoFrame() {
    return _getFrame(
      buffer: () => _localFrameBuf,
      setBuffer: (p) => _localFrameBuf = p,
      capacity: () => _localFrameCap,
      setCapacity: (v) => _localFrameCap = v,
      lastSeq: () => _lastLocalFrameSeq,
      setLastSeq: (v) => _lastLocalFrameSeq = v,
      pull: ffi.veilMediaEngineGetLocalVideoFrame,
    );
  }

  VeilVideoFrame? _getFrame({
    required Pointer<Uint8>? Function() buffer,
    required void Function(Pointer<Uint8>?) setBuffer,
    required int Function() capacity,
    required void Function(int) setCapacity,
    required int Function() lastSeq,
    required void Function(int) setLastSeq,
    required int Function(Pointer<ffi.VeilMediaEngineHandle>, Pointer<Uint8>,
            int, Pointer<Int32>, Pointer<Int32>)
        pull,
  }) {
    _ensure();
    final wp = calloc<Int32>();
    final hp = calloc<Int32>();
    try {
      var frameBuf = buffer();
      var frameCap = capacity();
      if (frameBuf == null) {
        frameCap = 640 * 480 * 4;
        frameBuf = calloc<Uint8>(frameCap);
        setCapacity(frameCap);
        setBuffer(frameBuf);
      }
      var seq = pull(_ptr, frameBuf, frameCap, wp, hp);
      if (seq == -1) {
        // Buffer too small — grow to the reported dimensions and retry once.
        final need = wp.value * hp.value * 4;
        if (need > 0) {
          calloc.free(frameBuf);
          frameCap = need;
          frameBuf = calloc<Uint8>(frameCap);
          setCapacity(frameCap);
          setBuffer(frameBuf);
          seq = pull(_ptr, frameBuf, frameCap, wp, hp);
        }
      }
      if (seq <= 0 || seq == lastSeq()) return null;
      setLastSeq(seq);
      final w = wp.value, h = hp.value;
      if (w <= 0 || h <= 0) return null;
      final rgba = Uint8List.fromList(frameBuf.asTypedList(w * h * 4));
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

  List<MediaDevice> listVideoInputs() =>
      _devices(ffi.veilMediaEngineListVideoInputs(_ptr));

  bool selectAudioInput(String id) =>
      _select(id, ffi.veilMediaEngineSelectAudioInput);

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
    if (_localFrameBuf != null) {
      calloc.free(_localFrameBuf!);
      _localFrameBuf = null;
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

  bool _select(String id,
      int Function(Pointer<ffi.VeilMediaEngineHandle>, Pointer<Utf8>) fn) {
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

/// One native N-party audio engine: a single mic/Opus send stream is fanned out
/// to peer channels while WebRTC mixes every peer receive stream into one ADM
/// playout. The caller owns and closes all channels.
class VeilGroupMediaEngine {
  VeilGroupMediaEngine._(this._ptr);

  final Pointer<ffi.VeilGroupMediaEngineHandle> _ptr;
  bool _disposed = false;
  final Map<String, _GroupFrameBuffer> _peerFrameBuffers = {};
  final _GroupFrameBuffer _localFrameBuffer = _GroupFrameBuffer();
  Pointer<Uint8>? _pushBuf;
  int _pushCap = 0;

  static VeilGroupMediaEngine? create({required Uint8List localId}) {
    if (localId.length != 32) {
      throw ArgumentError('localId must be 32 bytes');
    }
    final local = calloc<Uint8>(32)..asTypedList(32).setAll(0, localId);
    try {
      final ptr = ffi.veilMediaGroupEngineCreate(local);
      return ptr == nullptr ? null : VeilGroupMediaEngine._(ptr);
    } finally {
      calloc.free(local);
    }
  }

  bool addPeer({required int veilChan, required Uint8List peerId}) =>
      _withPeer(peerId, (peer) {
        return ffi.veilMediaGroupEngineAddPeer(_ptr, veilChan, peer) == 0;
      });

  bool removePeer(Uint8List peerId) {
    final removed = _withPeer(peerId, (peer) {
      return ffi.veilMediaGroupEngineRemovePeer(_ptr, peer) == 0;
    });
    if (removed) _peerFrameBuffers.remove(base64Encode(peerId))?.dispose();
    return removed;
  }

  int peerRxPackets(Uint8List peerId) => _withPeer(peerId, (peer) {
        return ffi.veilMediaGroupEnginePeerRxPackets(_ptr, peer);
      });

  bool startAudio() {
    _ensure();
    return ffi.veilMediaGroupEngineStartAudio(_ptr) == 0;
  }

  bool stopAudio() {
    _ensure();
    return ffi.veilMediaGroupEngineStopAudio(_ptr) == 0;
  }

  void setMicMuted(bool muted) {
    _ensure();
    ffi.veilMediaGroupEngineSetMicMuted(_ptr, muted ? 1 : 0);
  }

  bool startVideo() {
    _ensure();
    return ffi.veilMediaGroupEngineStartVideo(_ptr) == 0;
  }

  bool stopVideo() {
    _ensure();
    return ffi.veilMediaGroupEngineStopVideo(_ptr) == 0;
  }

  bool startCamera({int width = 352, int height = 198, int fps = 15}) {
    _ensure();
    return ffi.veilMediaGroupEngineStartCamera(_ptr, width, height, fps) == 0;
  }

  bool stopCamera() {
    _ensure();
    return ffi.veilMediaGroupEngineStopCamera(_ptr) == 0;
  }

  bool startScreen({int width = 640, int fps = 10}) {
    _ensure();
    return ffi.veilMediaGroupEngineStartScreen(_ptr, width, fps) == 0;
  }

  bool stopScreen() {
    _ensure();
    return ffi.veilMediaGroupEngineStopScreen(_ptr) == 0;
  }

  bool pushVideoFrame(
    Uint8List y,
    Uint8List u,
    Uint8List v,
    int width,
    int height,
  ) {
    _ensure();
    final total = y.length + u.length + v.length;
    if (total <= 0) return false;
    if (_pushBuf == null || _pushCap < total) {
      if (_pushBuf != null) calloc.free(_pushBuf!);
      _pushCap = total;
      _pushBuf = calloc<Uint8>(_pushCap);
    }
    final buffer = _pushBuf!;
    final view = buffer.asTypedList(total);
    view.setRange(0, y.length, y);
    view.setRange(y.length, y.length + u.length, u);
    view.setRange(y.length + u.length, total, v);
    final chromaWidth = (width + 1) ~/ 2;
    return ffi.veilMediaGroupEnginePushVideoFrame(
          _ptr,
          buffer,
          buffer + y.length,
          buffer + y.length + u.length,
          width,
          height,
          width,
          chromaWidth,
          chromaWidth,
          0,
        ) ==
        0;
  }

  VeilVideoFrame? getPeerVideoFrame(Uint8List peerId) {
    final state = _peerFrameBuffers.putIfAbsent(
      base64Encode(peerId),
      _GroupFrameBuffer.new,
    );
    return _withPeer(peerId, (peer) {
      return state.pull((dst, capacity, width, height) {
        return ffi.veilMediaGroupEngineGetPeerVideoFrame(
          _ptr,
          peer,
          dst,
          capacity,
          width,
          height,
        );
      });
    });
  }

  VeilVideoFrame? getLocalVideoFrame() => _localFrameBuffer.pull(
        (dst, capacity, width, height) =>
            ffi.veilMediaGroupEngineGetLocalVideoFrame(
          _ptr,
          dst,
          capacity,
          width,
          height,
        ),
      );

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    ffi.veilMediaGroupEngineDestroy(_ptr);
    for (final state in _peerFrameBuffers.values) {
      state.dispose();
    }
    _peerFrameBuffers.clear();
    _localFrameBuffer.dispose();
    if (_pushBuf != null) {
      calloc.free(_pushBuf!);
      _pushBuf = null;
    }
  }

  T _withPeer<T>(Uint8List peerId, T Function(Pointer<Uint8>) action) {
    _ensure();
    if (peerId.length != 32) throw ArgumentError('peerId must be 32 bytes');
    final peer = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerId);
    try {
      return action(peer);
    } finally {
      calloc.free(peer);
    }
  }

  void _ensure() {
    if (_disposed) {
      throw StateError('VeilGroupMediaEngine used after dispose()');
    }
  }
}

typedef _GroupFramePull = int Function(
  Pointer<Uint8> dst,
  int capacity,
  Pointer<Int32> width,
  Pointer<Int32> height,
);

class _GroupFrameBuffer {
  Pointer<Uint8>? _buffer;
  int _capacity = 0;
  int _lastSeq = 0;

  VeilVideoFrame? pull(_GroupFramePull pull) {
    final width = calloc<Int32>();
    final height = calloc<Int32>();
    try {
      var buffer = _buffer;
      if (buffer == null) {
        _capacity = 640 * 480 * 4;
        buffer = calloc<Uint8>(_capacity);
        _buffer = buffer;
      }
      var seq = pull(buffer, _capacity, width, height);
      if (seq == -1) {
        final need = width.value * height.value * 4;
        if (need > 0) {
          calloc.free(buffer);
          _capacity = need;
          buffer = calloc<Uint8>(_capacity);
          _buffer = buffer;
          seq = pull(buffer, _capacity, width, height);
        }
      }
      if (seq <= 0 || seq == _lastSeq) return null;
      _lastSeq = seq;
      final w = width.value, h = height.value;
      if (w <= 0 || h <= 0) return null;
      return VeilVideoFrame(
        rgba: Uint8List.fromList(buffer.asTypedList(w * h * 4)),
        width: w,
        height: h,
      );
    } finally {
      calloc.free(width);
      calloc.free(height);
    }
  }

  void dispose() {
    if (_buffer != null) {
      calloc.free(_buffer!);
      _buffer = null;
    }
    _capacity = 0;
    _lastSeq = 0;
  }
}

/// A finished voice recording: the VOICE_OPUS byte stream (store this), the
/// clip duration, and a peak-normalized amplitude waveform (0..1 per bar).
class VoiceRecording {
  const VoiceRecording({
    required this.bytes,
    required this.durationMs,
    required this.waveform,
  });

  final Uint8List bytes;
  final int durationMs;
  final List<double> waveform;
}

/// Records the microphone to an in-RAM Opus stream via the veil_media native
/// recorder (no plaintext ever hits disk). One recorder == one clip; create,
/// [start], poll [level]/[elapsedMs] for the live UI, then [stop] to get the
/// bytes + waveform. [dispose] frees the native handle (also stops capture).
///
/// All calls are on the control isolate. The native capture runs on the OS
/// audio thread; [level] is lock-free so the UI can poll it at frame rate.
class VeilAudioRecorder {
  VeilAudioRecorder._(this._ptr);

  Pointer<ffi.VeilAudioRecorderHandle> _ptr;

  /// Create a recorder (builds the platform ADM + Opus encoder). Returns null
  /// if the native layer is unavailable or the encoder can't be built.
  static VeilAudioRecorder? create() {
    final p = ffi.veilMediaRecorderCreate();
    if (p == nullptr) return null;
    return VeilAudioRecorder._(p);
  }

  bool get _alive => _ptr != nullptr;

  /// Begin capturing. Returns true on success; false if the mic can't be opened
  /// (e.g. the OS permission was denied) — the caller should surface that.
  bool start() => _alive && ffi.veilMediaRecorderStart(_ptr) == 0;

  /// Most-recent smoothed capture level in 0..1, for a live meter.
  double get level => _alive ? ffi.veilMediaRecorderLevel(_ptr) : 0;

  /// Elapsed captured milliseconds so far.
  int get elapsedMs => _alive ? ffi.veilMediaRecorderElapsedMs(_ptr) : 0;

  /// Stop capture and finalize. [waveformBars] amplitude bars are computed
  /// natively. Returns null if nothing usable was captured (empty clip).
  VoiceRecording? stop({int waveformBars = 48}) {
    if (!_alive) return null;
    final outBytes = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    final outDur = calloc<Int32>();
    final wf = calloc<Uint8>(waveformBars);
    try {
      final rc = ffi.veilMediaRecorderStop(
          _ptr, outBytes, outLen, outDur, wf, waveformBars);
      if (rc != 0) return null;
      final len = outLen.value;
      final durationMs = outDur.value;
      final waveform = [
        for (var i = 0; i < waveformBars; i++) wf[i] / 255.0,
      ];
      if (len == 0 || outBytes.value == nullptr) {
        return null; // empty clip (silence / instant release)
      }
      final bytes = Uint8List.fromList(outBytes.value.asTypedList(len));
      ffi.veilMediaRecorderFreeBytes(outBytes.value);
      return VoiceRecording(
          bytes: bytes, durationMs: durationMs, waveform: waveform);
    } finally {
      calloc.free(outBytes);
      calloc.free(outLen);
      calloc.free(outDur);
      calloc.free(wf);
    }
  }

  /// Free the native recorder (stops capture if still running). Idempotent.
  void dispose() {
    if (_ptr != nullptr) {
      ffi.veilMediaRecorderDestroy(_ptr);
      _ptr = nullptr;
    }
  }
}

/// A finished video note: the VNOTE1 byte stream (store this) + duration.
class VnoteRecording {
  const VnoteRecording({required this.bytes, required this.durationMs});
  final Uint8List bytes;
  final int durationMs;
}

/// Records a round video note: camera + mic -> VP8 + Opus -> the
/// in-RAM VNOTE1 container (no plaintext ever hits disk). On platforms with a
/// native camera backend (macOS/Linux) [start] opens it; on Android the Dart
/// camera capturer feeds [pushFrame] instead. Poll [level]/[elapsedMs] for
/// the UI and [frame] for the live round self-preview.
class VeilVnoteRecorder {
  VeilVnoteRecorder._(this._ptr);

  Pointer<ffi.VeilVnoteRecorderHandle> _ptr;
  Pointer<Uint8>? _frameBuf;
  int _frameCap = 0;
  int _lastFrameSeq = 0;
  Pointer<Uint8>? _pushBuf;
  int _pushCap = 0;

  static VeilVnoteRecorder? create(
      {int width = 480, int fps = 24, bool nativeCamera = true}) {
    final p = ffi.veilVnoteRecorderCreate(width, fps, nativeCamera ? 1 : 0);
    if (p == nullptr) return null;
    return VeilVnoteRecorder._(p);
  }

  bool get _alive => _ptr != nullptr;

  bool start() => _alive && ffi.veilVnoteRecorderStart(_ptr) == 0;

  double get level => _alive ? ffi.veilVnoteRecorderLevel(_ptr) : 0;
  int get elapsedMs => _alive ? ffi.veilVnoteRecorderElapsedMs(_ptr) : 0;

  /// Push one tightly-packed I420 frame (the Android Dart capturer path).
  bool pushFrame(Uint8List y, Uint8List u, Uint8List v, int width, int height) {
    if (!_alive) return false;
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
    final cw = (width + 1) ~/ 2;
    final rc = ffi.veilVnoteRecorderPushFrame(_ptr, buf, buf + y.length,
        buf + y.length + u.length, width, height, width, cw, cw, 0);
    return rc == 0;
  }

  /// The latest captured frame (RGBA, post crop/scale — exactly what is being
  /// encoded), or null if there is no NEW frame since the last call.
  VeilVideoFrame? frame() {
    if (!_alive) return null;
    final wp = calloc<Int32>();
    final hp = calloc<Int32>();
    try {
      var buf = _frameBuf;
      if (buf == null) {
        _frameCap = 480 * 480 * 4;
        buf = calloc<Uint8>(_frameCap);
        _frameBuf = buf;
      }
      var seq = ffi.veilVnoteRecorderFrame(_ptr, buf, _frameCap, wp, hp);
      if (seq == -1) {
        final need = wp.value * hp.value * 4;
        if (need > 0) {
          calloc.free(buf);
          _frameCap = need;
          buf = calloc<Uint8>(_frameCap);
          _frameBuf = buf;
          seq = ffi.veilVnoteRecorderFrame(_ptr, buf, _frameCap, wp, hp);
        }
      }
      if (seq <= 0 || seq == _lastFrameSeq) return null;
      _lastFrameSeq = seq;
      final w = wp.value, h = hp.value;
      if (w <= 0 || h <= 0) return null;
      return VeilVideoFrame(
          rgba: Uint8List.fromList(buf.asTypedList(w * h * 4)),
          width: w,
          height: h);
    } finally {
      calloc.free(wp);
      calloc.free(hp);
    }
  }

  /// Stop and finalize. Null when the clip is empty.
  VnoteRecording? stop() {
    if (!_alive) return null;
    final outBytes = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    final outDur = calloc<Int32>();
    try {
      final rc = ffi.veilVnoteRecorderStop(_ptr, outBytes, outLen, outDur);
      if (rc != 0 || outLen.value == 0 || outBytes.value == nullptr) {
        return null;
      }
      final bytes =
          Uint8List.fromList(outBytes.value.asTypedList(outLen.value));
      ffi.veilVnoteFreeBytes(outBytes.value);
      return VnoteRecording(bytes: bytes, durationMs: outDur.value);
    } finally {
      calloc.free(outBytes);
      calloc.free(outLen);
      calloc.free(outDur);
    }
  }

  void dispose() {
    if (_ptr != nullptr) {
      ffi.veilVnoteRecorderDestroy(_ptr);
      _ptr = nullptr;
    }
    if (_frameBuf != null) {
      calloc.free(_frameBuf!);
      _frameBuf = null;
    }
    if (_pushBuf != null) {
      calloc.free(_pushBuf!);
      _pushBuf = null;
    }
  }
}

/// Plays a VNOTE1 clip: pull-driven — play the [audio] block through the
/// voice path (exact position/pause/speed) and poll [frameAt] with that
/// position; the native side decodes forward on demand and rewinds via the
/// nearest keyframe.
class VeilVnotePlayer {
  VeilVnotePlayer._(this._ptr);

  Pointer<ffi.VeilVnotePlayerHandle> _ptr;
  Pointer<Uint8>? _frameBuf;
  int _frameCap = 0;

  /// Null on a malformed container (strict native parse — clips arrive over
  /// the network).
  static VeilVnotePlayer? create(Uint8List vnote) {
    if (vnote.isEmpty) return null;
    final buf = calloc<Uint8>(vnote.length);
    buf.asTypedList(vnote.length).setAll(0, vnote);
    final p = ffi.veilVnotePlayerCreate(buf, vnote.length);
    calloc.free(buf); // the native side copies
    if (p == nullptr) return null;
    return VeilVnotePlayer._(p);
  }

  bool get _alive => _ptr != nullptr;

  int get durationMs => _alive ? ffi.veilVnotePlayerDurationMs(_ptr) : 0;
  int get width => _alive ? ffi.veilVnotePlayerWidth(_ptr) : 0;
  int get height => _alive ? ffi.veilVnotePlayerHeight(_ptr) : 0;
  bool get hasAudio => _alive && ffi.veilVnotePlayerHasAudio(_ptr) != 0;

  /// The embedded VOICE_OPUS audio block (decode/play it with the voice
  /// bricks), or null for a silent note.
  Uint8List? audio() {
    if (!_alive) return null;
    final outBytes = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = ffi.veilVnotePlayerAudio(_ptr, outBytes, outLen);
      if (rc != 0 || outBytes.value == nullptr || outLen.value == 0) {
        return null;
      }
      final bytes =
          Uint8List.fromList(outBytes.value.asTypedList(outLen.value));
      ffi.veilVnoteFreeBytes(outBytes.value);
      return bytes;
    } finally {
      calloc.free(outBytes);
      calloc.free(outLen);
    }
  }

  /// The frame at [ms] into the clip (RGBA), or null when nothing decoded
  /// yet. Safe to call at the UI frame rate.
  VeilVideoFrame? frameAt(int ms) {
    if (!_alive) return null;
    final wp = calloc<Int32>();
    final hp = calloc<Int32>();
    try {
      var buf = _frameBuf;
      if (buf == null) {
        _frameCap = width > 0 ? width * height * 4 : 480 * 480 * 4;
        if (_frameCap <= 0) _frameCap = 480 * 480 * 4;
        buf = calloc<Uint8>(_frameCap);
        _frameBuf = buf;
      }
      var seq = ffi.veilVnotePlayerFrameAt(_ptr, ms, buf, _frameCap, wp, hp);
      if (seq == -1) {
        final need = wp.value * hp.value * 4;
        if (need > 0) {
          calloc.free(buf);
          _frameCap = need;
          buf = calloc<Uint8>(_frameCap);
          _frameBuf = buf;
          seq = ffi.veilVnotePlayerFrameAt(_ptr, ms, buf, _frameCap, wp, hp);
        }
      }
      if (seq <= 0) return null;
      final w = wp.value, h = hp.value;
      if (w <= 0 || h <= 0) return null;
      return VeilVideoFrame(
          rgba: Uint8List.fromList(buf.asTypedList(w * h * 4)),
          width: w,
          height: h);
    } finally {
      calloc.free(wp);
      calloc.free(hp);
    }
  }

  void dispose() {
    if (_ptr != nullptr) {
      ffi.veilVnotePlayerDestroy(_ptr);
      _ptr = nullptr;
    }
    if (_frameBuf != null) {
      calloc.free(_frameBuf!);
      _frameBuf = null;
    }
  }
}

/// Decode a VOICE_OPUS clip (from [VeilAudioRecorder]) into a complete
/// RIFF/WAV byte stream held in RAM (mono int16 PCM at the clip's rate), so
/// playback can ride the OS media players — which cannot decode Opus
/// (AVFoundation) — via a loopback URL with seeking. Returns null on a bad
/// container / decoder failure / native unavailability.
Uint8List? decodeVoiceWav(Uint8List voiceOpus) {
  if (voiceOpus.isEmpty) return null;
  final inBuf = calloc<Uint8>(voiceOpus.length);
  inBuf.asTypedList(voiceOpus.length).setAll(0, voiceOpus);
  final outWav = calloc<Pointer<Uint8>>();
  final outLen = calloc<Size>();
  try {
    final rc = ffi.veilMediaDecodeWav(inBuf, voiceOpus.length, outWav, outLen);
    if (rc != 0 || outWav.value == nullptr || outLen.value == 0) return null;
    final wav = Uint8List.fromList(outWav.value.asTypedList(outLen.value));
    ffi.veilMediaFreeWav(outWav.value);
    return wav;
  } finally {
    calloc.free(inBuf);
    calloc.free(outWav);
    calloc.free(outLen);
  }
}

/// Plays a VOICE_OPUS clip (from [VeilAudioRecorder]/sendVoice) through the
/// native decoder + ADM speaker — no OS media framework, no plaintext on disk.
/// Create with the clip bytes, [start], poll [positionMs]/[isPlaying] for the
/// progress UI, and [dispose] when done. Supports [pause]/[resume]/[seek] and
/// variable [setSpeed] (1.0 / 1.5 / 2.0).
class VeilAudioPlayer {
  VeilAudioPlayer._(this._ptr, this._buf);

  Pointer<ffi.VeilAudioPlayerHandle> _ptr;
  Pointer<Uint8>? _buf; // the native copy of the clip bytes, freed on dispose

  /// Create a player over [voiceOpus] (the stored clip). Returns null on a bad
  /// container / decoder failure / native unavailability.
  static VeilAudioPlayer? create(Uint8List voiceOpus) {
    if (voiceOpus.isEmpty) return null;
    final buf = calloc<Uint8>(voiceOpus.length);
    buf.asTypedList(voiceOpus.length).setAll(0, voiceOpus);
    final p = ffi.veilMediaPlayerCreate(buf, voiceOpus.length);
    if (p == nullptr) {
      calloc.free(buf);
      return null;
    }
    return VeilAudioPlayer._(p, buf);
  }

  bool get _alive => _ptr != nullptr;

  bool start() => _alive && ffi.veilMediaPlayerStart(_ptr) == 0;
  void pause() {
    if (_alive) ffi.veilMediaPlayerPause(_ptr);
  }

  void resume() {
    if (_alive) ffi.veilMediaPlayerResume(_ptr);
  }

  void seekMs(int ms) {
    if (_alive) ffi.veilMediaPlayerSeek(_ptr, ms);
  }

  void setSpeed(double speed) {
    if (_alive) ffi.veilMediaPlayerSetSpeed(_ptr, speed);
  }

  int get positionMs => _alive ? ffi.veilMediaPlayerPositionMs(_ptr) : 0;
  int get durationMs => _alive ? ffi.veilMediaPlayerDurationMs(_ptr) : 0;
  bool get isPlaying => _alive && ffi.veilMediaPlayerIsPlaying(_ptr) != 0;

  /// Stop playout + free the player and its clip buffer. Idempotent.
  void dispose() {
    if (_ptr != nullptr) {
      ffi.veilMediaPlayerDestroy(_ptr);
      _ptr = nullptr;
    }
    if (_buf != null) {
      calloc.free(_buf!);
      _buf = null;
    }
  }
}
