import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/veil_flutter.dart';

void main() {
  final nativeDylib = Platform.environment['VEIL_FFI_DYLIB'];

  test(
    'opens one signing burst and refuses use after close',
    () {
      final phrase = generateMasterPhrase();
      final signer = VeilSovereignSigner.open(phrase);
      expect(signer.nodeId, hasLength(32));
      expect(signer.publicKey, hasLength(32));
      expect(
        signer.sign(Uint8List.fromList('membership-v2'.codeUnits)),
        hasLength(64),
      );

      signer.close();
      expect(signer.isClosed, isTrue);
      expect(
        () => signer.sign(Uint8List(0)),
        throwsA(isA<StateError>()),
      );
      signer.close(); // idempotent
    },
    skip: nativeDylib == null || nativeDylib.isEmpty
        ? 'set VEIL_FFI_DYLIB to run native FFI coverage'
        : false,
  );

  test(
    'encrypted hybrid bundle opens, signs and rejects wrong phrase',
    () {
      final phrase = generateMasterPhrase();
      final bundle = createHybrid512SovereignBundle(phrase);
      expect(bundle, isNotEmpty);
      final signer = VeilSovereignSigner.openBundle(bundle, phrase);
      expect(signer.algorithm, 'ed25519+falcon512');
      expect(signer.nodeId, hasLength(32));
      expect(signer.publicKey, hasLength(929));
      final message = Uint8List.fromList('hybrid-membership-v2'.codeUnits);
      final signature = signer.sign(message);
      expect(signature.length, greaterThan(64));
      expect(
        verifySovereignSignature(
          algorithm: signer.algorithm,
          nodeId: signer.nodeId,
          publicKey: signer.publicKey,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
      signer.close();

      expect(
        () => VeilSovereignSigner.openBundle(
          bundle,
          generateMasterPhrase(),
        ),
        throwsA(isA<VeilException>()),
      );
      final tampered = Uint8List.fromList(bundle)..last ^= 1;
      expect(
        () => VeilSovereignSigner.openBundle(tampered, phrase),
        throwsA(isA<VeilException>()),
      );
    },
    skip: nativeDylib == null || nativeDylib.isEmpty
        ? 'set VEIL_FFI_DYLIB to run native FFI coverage'
        : false,
  );

  test(
    'recovery certificate preserves the full sovereign node id',
    () {
      final phrase = generateMasterPhrase();
      final bundle = createHybrid512SovereignBundle(phrase);
      final original = VeilSovereignSigner.openBundle(bundle, phrase);
      final code = generateSovereignRecoveryCode();
      expect(code, startsWith('xvrc-'));
      final certificate = exportSovereignRecoveryCertificate(
        bundle,
        phrase,
        code,
      );
      expect(String.fromCharCodes(certificate.take(4)), 'XVRC');

      final restored = VeilSovereignSigner.openRecoveryCertificate(
        certificate,
        code,
      );
      expect(restored.algorithm, original.algorithm);
      expect(restored.nodeId, original.nodeId);
      expect(restored.publicKey, original.publicKey);
      expect(certificate.sublist(6, 38), original.nodeId);
      restored.close();
      original.close();

      expect(
        () => VeilSovereignSigner.openRecoveryCertificate(
          certificate,
          generateSovereignRecoveryCode(),
        ),
        throwsA(isA<VeilException>()),
      );
      final tampered = Uint8List.fromList(certificate);
      tampered[6] ^= 1;
      expect(
        () => VeilSovereignSigner.openRecoveryCertificate(tampered, code),
        throwsA(isA<VeilException>()),
      );
    },
    skip: nativeDylib == null || nativeDylib.isEmpty
        ? 'set VEIL_FFI_DYLIB to run native FFI coverage'
        : false,
  );
}
