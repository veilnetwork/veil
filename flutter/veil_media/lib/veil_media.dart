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

/// A live media engine bound to one veil media datagram channel.
class VeilMediaEngine {
  VeilMediaEngine._(this._ptr);

  final Pointer<ffi.VeilMediaEngineHandle> _ptr;
  bool _disposed = false;

  /// Create an engine over an already-open veil media channel [veilChan]
  /// (from `VeilFlutterTransport.openMediaChannel`). [peerId] is the 32-byte
  /// peer node id. Returns null if the native create failed.
  static VeilMediaEngine? create({
    required int veilChan,
    required Uint8List peerId,
  }) {
    if (peerId.length != 32) {
      throw ArgumentError('peerId must be 32 bytes');
    }
    final peer = calloc<Uint8>(32)..asTypedList(32).setAll(0, peerId);
    try {
      final ptr = ffi.veilMediaEngineCreate(veilChan, peer);
      if (ptr == nullptr) return null;
      return VeilMediaEngine._(ptr);
    } finally {
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
