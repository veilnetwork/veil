import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'types.dart';

final NativeFinalizer _sovereignSignerFinalizer =
    NativeFinalizer(ffi.veilSovereignSignerClosePointer);

/// A short-lived sovereign signing burst derived from a recovery phrase.
///
/// The phrase copy passed over FFI is wiped by native code before [open]
/// returns. The private seed never crosses back into Dart and is erased when
/// [close] drops the opaque native handle. Keep the burst as short as possible:
/// open, sign the complete membership transaction, then close in `finally`.
final class VeilSovereignSigner implements Finalizable {
  VeilSovereignSigner._(
    this._handle,
    this.nodeId,
    this.publicKey,
  ) {
    _sovereignSignerFinalizer.attach(
      this,
      _handle.cast<Void>(),
      detach: this,
    );
  }

  Pointer<ffi.VeilSovereignSigner> _handle;

  /// BLAKE3-derived sovereign node id (32 bytes).
  final Uint8List nodeId;

  /// Sovereign Ed25519 public key (32 bytes).
  final Uint8List publicKey;

  bool get isClosed => _handle == nullptr;

  /// Decode [phrase] and open an opaque native signer.
  ///
  /// The immutable Dart [String] remains subject to Dart's normal lifetime;
  /// the mutable native UTF-8 copy is wiped on every native return path.
  factory VeilSovereignSigner.open(String phrase) {
    final phraseC = phrase.toNativeUtf8();
    final signerOut = calloc<Pointer<ffi.VeilSovereignSigner>>();
    final nodeIdOut = calloc<Uint8>(32);
    final publicKeyOut = calloc<Uint8>(32);
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = ffi.veilSovereignSignerOpenFromPhraseZeroize(
        phraseC,
        signerOut,
        nodeIdOut,
        publicKeyOut,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(_takeError(errOut), code: rc);
      }
      return VeilSovereignSigner._(
        signerOut.value,
        Uint8List.fromList(nodeIdOut.asTypedList(32)),
        Uint8List.fromList(publicKeyOut.asTypedList(32)),
      );
    } finally {
      calloc.free(phraseC);
      calloc.free(signerOut);
      calloc.free(nodeIdOut);
      calloc.free(publicKeyOut);
      calloc.free(errOut);
    }
  }

  /// Sign arbitrary canonical membership bytes with the sovereign key.
  Uint8List sign(Uint8List message) {
    final handle = _handle;
    if (handle == nullptr) {
      throw StateError('Sovereign signer is closed');
    }
    final messageBuf = calloc<Uint8>(message.isEmpty ? 1 : message.length);
    final signatureOut = calloc<Uint8>(64);
    final errOut = calloc<Pointer<Utf8>>();
    try {
      if (message.isNotEmpty) {
        messageBuf.asTypedList(message.length).setAll(0, message);
      }
      final rc = ffi.veilSovereignSignerSign(
        handle,
        messageBuf,
        message.length,
        signatureOut,
        64,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(_takeError(errOut), code: rc);
      }
      return Uint8List.fromList(signatureOut.asTypedList(64));
    } finally {
      calloc.free(messageBuf);
      calloc.free(signatureOut);
      calloc.free(errOut);
    }
  }

  /// Erase the native seed and permanently end this signing burst.
  void close() {
    final handle = _handle;
    if (handle == nullptr) return;
    _handle = nullptr;
    _sovereignSignerFinalizer.detach(this);
    ffi.veilSovereignSignerClose(handle.cast<Void>());
  }
}

String _takeError(Pointer<Pointer<Utf8>> errOut) {
  final err = errOut.value;
  if (err == nullptr) return '<no detail>';
  try {
    return err.toDartString();
  } finally {
    ffi.veilFreeString(err);
    errOut.value = nullptr;
  }
}
