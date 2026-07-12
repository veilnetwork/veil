import 'dart:ffi';
import 'dart:convert';
import 'dart:math';
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
    this.algorithm,
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

  /// Canonical Veil signature algorithm name.
  final String algorithm;

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
        'ed25519',
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

  /// Decrypt [bundle] with [phrase] and open a hybrid one-burst signer.
  factory VeilSovereignSigner.openBundle(
    Uint8List bundle,
    String phrase,
  ) {
    final bundleBuf = calloc<Uint8>(bundle.length);
    final phraseC = phrase.toNativeUtf8();
    final signerOut = calloc<Pointer<ffi.VeilSovereignSigner>>();
    final algorithmOut = calloc<Uint8>();
    final nodeIdOut = calloc<Uint8>(32);
    final publicKeyOut = calloc<Uint8>(1024);
    final publicKeyLenOut = calloc<IntPtr>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      bundleBuf.asTypedList(bundle.length).setAll(0, bundle);
      final rc = ffi.veilSovereignSignerOpenBundleZeroize(
        bundleBuf,
        bundle.length,
        phraseC.cast<Uint8>(),
        phraseC.length,
        signerOut,
        algorithmOut,
        nodeIdOut,
        32,
        publicKeyOut,
        1024,
        publicKeyLenOut,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(_takeError(errOut), code: rc);
      }
      final publicKeyLen = publicKeyLenOut.value;
      return VeilSovereignSigner._(
        signerOut.value,
        _algorithmName(algorithmOut.value),
        Uint8List.fromList(nodeIdOut.asTypedList(32)),
        Uint8List.fromList(publicKeyOut.asTypedList(publicKeyLen)),
      );
    } finally {
      calloc.free(bundleBuf);
      calloc.free(phraseC);
      calloc.free(signerOut);
      calloc.free(algorithmOut);
      calloc.free(nodeIdOut);
      calloc.free(publicKeyOut);
      calloc.free(publicKeyLenOut);
      calloc.free(errOut);
    }
  }

  /// Open an XVRC recovery certificate with its independent recovery code.
  /// The restored signer has the exact same full public key and node id as the
  /// XVSB from which the certificate was exported.
  factory VeilSovereignSigner.openRecoveryCertificate(
    Uint8List certificate,
    String recoveryCode,
  ) {
    final certificateBuf = calloc<Uint8>(certificate.length);
    final codeC = recoveryCode.toNativeUtf8();
    final signerOut = calloc<Pointer<ffi.VeilSovereignSigner>>();
    final algorithmOut = calloc<Uint8>();
    final nodeIdOut = calloc<Uint8>(32);
    final publicKeyOut = calloc<Uint8>(1024);
    final publicKeyLenOut = calloc<IntPtr>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      certificateBuf.asTypedList(certificate.length).setAll(0, certificate);
      final rc = ffi.veilSovereignSignerOpenRecoveryCertificateZeroize(
        certificateBuf,
        certificate.length,
        codeC.cast<Uint8>(),
        codeC.length,
        signerOut,
        algorithmOut,
        nodeIdOut,
        32,
        publicKeyOut,
        1024,
        publicKeyLenOut,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(_takeError(errOut), code: rc);
      }
      final publicKeyLen = publicKeyLenOut.value;
      return VeilSovereignSigner._(
        signerOut.value,
        _algorithmName(algorithmOut.value),
        Uint8List.fromList(nodeIdOut.asTypedList(32)),
        Uint8List.fromList(publicKeyOut.asTypedList(publicKeyLen)),
      );
    } finally {
      calloc.free(certificateBuf);
      calloc.free(codeC);
      calloc.free(signerOut);
      calloc.free(algorithmOut);
      calloc.free(nodeIdOut);
      calloc.free(publicKeyOut);
      calloc.free(publicKeyLenOut);
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
    final signatureOut = calloc<Uint8>(1024);
    final signatureLenOut = calloc<IntPtr>();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      if (message.isNotEmpty) {
        messageBuf.asTypedList(message.length).setAll(0, message);
      }
      final rc = ffi.veilSovereignSignerSignInto(
        handle,
        messageBuf,
        message.length,
        signatureOut,
        1024,
        signatureLenOut,
        errOut,
      );
      if (rc != ffi.veilOk) {
        throw VeilException(_takeError(errOut), code: rc);
      }
      return Uint8List.fromList(
        signatureOut.asTypedList(signatureLenOut.value),
      );
    } finally {
      calloc.free(messageBuf);
      calloc.free(signatureOut);
      calloc.free(signatureLenOut);
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

/// Create a fresh hybrid sovereign bundle. Only encrypted bytes return to
/// Dart; the mutable native phrase copy and all plaintext key bytes are wiped.
Uint8List createHybrid512SovereignBundle(String phrase) {
  final phraseC = phrase.toNativeUtf8();
  final bundleOut = calloc<Pointer<Uint8>>();
  final bundleLenOut = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilSovereignBundleCreateHybrid512Zeroize(
      phraseC.cast<Uint8>(),
      phraseC.length,
      bundleOut,
      bundleLenOut,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException(_takeError(errOut), code: rc);
    }
    return Uint8List.fromList(
      bundleOut.value.asTypedList(bundleLenOut.value),
    );
  } finally {
    if (bundleOut.value != nullptr) {
      ffi.veilFreeBuf(bundleOut.value, bundleLenOut.value);
    }
    calloc.free(phraseC);
    calloc.free(bundleOut);
    calloc.free(bundleLenOut);
    calloc.free(errOut);
  }
}

/// Generate an independent 256-bit recovery code. Store it separately from the
/// XVRC file: possessing both grants the same sovereign authority as the phrase.
String generateSovereignRecoveryCode() {
  final random = Random.secure();
  final bytes = List<int>.generate(32, (_) => random.nextInt(256));
  return 'xvrc-${base64Url.encode(bytes).replaceAll('=', '')}';
}

/// Re-wrap an existing XVSB or XVRC credential as a fresh XVRC recovery
/// certificate. Plaintext key material never crosses into Dart; mutable
/// current-secret/new-code FFI copies are wiped.
Uint8List exportSovereignRecoveryCertificate(
  Uint8List bundle,
  String phrase,
  String recoveryCode,
) {
  final bundleBuf = calloc<Uint8>(bundle.length);
  final phraseC = phrase.toNativeUtf8();
  final codeC = recoveryCode.toNativeUtf8();
  final certificateOut = calloc<Pointer<Uint8>>();
  final certificateLenOut = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    bundleBuf.asTypedList(bundle.length).setAll(0, bundle);
    final rc = ffi.veilSovereignRecoveryCertificateExportZeroize(
      bundleBuf,
      bundle.length,
      phraseC.cast<Uint8>(),
      phraseC.length,
      codeC.cast<Uint8>(),
      codeC.length,
      certificateOut,
      certificateLenOut,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException(_takeError(errOut), code: rc);
    }
    return Uint8List.fromList(
      certificateOut.value.asTypedList(certificateLenOut.value),
    );
  } finally {
    if (certificateOut.value != nullptr) {
      ffi.veilFreeBuf(certificateOut.value, certificateLenOut.value);
    }
    calloc.free(bundleBuf);
    calloc.free(phraseC);
    calloc.free(codeC);
    calloc.free(certificateOut);
    calloc.free(certificateLenOut);
    calloc.free(errOut);
  }
}

/// Verify a sovereign signature and its full-public-key node-id binding.
bool verifySovereignSignature({
  required String algorithm,
  required Uint8List nodeId,
  required Uint8List publicKey,
  required Uint8List message,
  required Uint8List signature,
}) {
  if (nodeId.length != 32) return false;
  final algorithmWire = _algorithmWire(algorithm);
  if (algorithmWire == null) return false;
  final nodeBuf = calloc<Uint8>(32);
  final publicBuf = calloc<Uint8>(publicKey.length);
  final messageBuf = calloc<Uint8>(message.isEmpty ? 1 : message.length);
  final signatureBuf = calloc<Uint8>(signature.length);
  final validOut = calloc<Bool>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    nodeBuf.asTypedList(32).setAll(0, nodeId);
    publicBuf.asTypedList(publicKey.length).setAll(0, publicKey);
    if (message.isNotEmpty) {
      messageBuf.asTypedList(message.length).setAll(0, message);
    }
    signatureBuf.asTypedList(signature.length).setAll(0, signature);
    final rc = ffi.veilSovereignVerify(
      algorithmWire,
      nodeBuf,
      publicBuf,
      publicKey.length,
      messageBuf,
      message.length,
      signatureBuf,
      signature.length,
      validOut,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException(_takeError(errOut), code: rc);
    }
    return validOut.value;
  } finally {
    calloc.free(nodeBuf);
    calloc.free(publicBuf);
    calloc.free(messageBuf);
    calloc.free(signatureBuf);
    calloc.free(validOut);
    calloc.free(errOut);
  }
}

String _algorithmName(int wire) => switch (wire) {
      1 => 'ed25519',
      2 => 'falcon512',
      3 => 'ed25519+falcon512',
      4 => 'ed25519+falcon1024',
      _ => throw VeilException('unsupported sovereign algorithm $wire'),
    };

int? _algorithmWire(String name) => switch (name) {
      'ed25519' => 1,
      'falcon512' => 2,
      'ed25519+falcon512' => 3,
      'ed25519+falcon1024' => 4,
      _ => null,
    };

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
