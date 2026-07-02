import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;

/// Stateless native crypto helpers backed by `libveilclient_ffi`.
class VeilCrypto {
  VeilCrypto._();

  /// Native SHA-256. ~30-50x faster than Dart's pure `package:crypto` digest
  /// on a phone (the pure digest made hashing a large file the dominant
  /// pre-offer latency of a content send). Synchronous: one FFI call, no
  /// isolate hop — a 256 KiB piece digests in well under a millisecond.
  ///
  /// Throws [ArgumentError] if the native library rejects the input (never
  /// happens for a well-formed Dart list) — callers that must survive an old
  /// native library missing the symbol should probe once inside a try/catch
  /// and fall back to a Dart digest.
  static Uint8List sha256(Uint8List data) {
    final out = malloc<Uint8>(32);
    final buf = data.isEmpty ? nullptr : malloc<Uint8>(data.length);
    try {
      if (data.isNotEmpty) {
        buf.asTypedList(data.length).setAll(0, data);
      }
      final rc = ffi.veilSha256Raw(buf, data.length, out);
      if (rc != 0) {
        throw ArgumentError('veil_sha256 failed with rc=$rc');
      }
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      if (data.isNotEmpty) {
        malloc.free(buf);
      }
      malloc.free(out);
    }
  }
}
