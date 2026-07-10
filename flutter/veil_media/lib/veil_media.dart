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
      {required this.id, required this.label, required this.kind});

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
  Pointer<Uint8>? _localFrameBuf; // reused local RGBA pull buffer
  int _localFrameCap = 0;
  int _lastLocalFrameSeq = 0;

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
