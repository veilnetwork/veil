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
}
