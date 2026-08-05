// The FFI ABI contract check, exercised against a REAL veilclient-ffi library.
//
// Set VEIL_FFI_DYLIB to a built `libveilclient_ffi.{dylib,so,dll}` and these
// run; without it there is nothing to load and they skip. Build it with:
//
//     cargo build -p veilclient-ffi --no-default-features
//     VEIL_FFI_DYLIB=target/debug/libveilclient_ffi.dylib \
//       flutter test test/abi_contract_test.dart
//
// What is being proved is an ORDERING, not just a comparison: a library whose
// ABI hash does not match these bindings must be refused at LOAD, before any
// other symbol is resolved through it. A check that ran after the first call
// would be checking for a corruption that had already happened — the failure
// this guards is a symbol that still exists under the same name with a
// different signature, and one such call is already undefined behaviour.

import 'dart:io' show Platform;

import 'package:flutter_test/flutter_test.dart';
import 'package:veil_flutter/src/abi_contract.dart' as abi;
import 'package:veil_flutter/src/native.dart';

void main() {
  final dylib = Platform.environment['VEIL_FFI_DYLIB'];
  final haveLib = dylib != null && dylib.isNotEmpty;

  group('ABI contract hash', () {
    test('the generated hash is a full lowercase SHA-256', () {
      expect(abi.veilAbiContractHash, matches(RegExp(r'^[0-9a-f]{64}$')));
    });

    test(
      'a matching library loads and reports the expected hash',
      () {
        final lib = openVeilLibrary();
        expect(readAbiContractHash(lib), abi.veilAbiContractHash);
      },
      skip: haveLib ? false : 'set VEIL_FFI_DYLIB to a built veilclient-ffi',
    );

    test(
      'a mismatched contract is refused at load, before any other symbol',
      () {
        // Same real library, different expectation — exactly the shape of a
        // Dart package built against an older header than the .so it ships
        // next to.
        expect(
          () => openVeilLibrary(expectedAbiHash: 'deadbeef' * 8),
          throwsA(isA<VeilAbiContractMismatch>()),
          reason: 'a contract mismatch must prevent the library from loading',
        );

        // And the refusal names both sides, so the operator can tell WHICH
        // half is stale rather than guessing.
        try {
          openVeilLibrary(expectedAbiHash: 'deadbeef' * 8);
          fail('expected VeilAbiContractMismatch');
        } on VeilAbiContractMismatch catch (e) {
          expect(e.expected, 'deadbeef' * 8);
          expect(e.actual, abi.veilAbiContractHash);
          expect(e.toString(), contains('regen-ffi-header.sh'));
        }
      },
      skip: haveLib ? false : 'set VEIL_FFI_DYLIB to a built veilclient-ffi',
    );

    test(
      'a library with no contract symbol at all is refused too',
      () {
        // Every libc has neither `veil_abi_contract_hash` nor any veil symbol,
        // so it stands in for a build from before the contract existed — old
        // enough that its call signatures cannot be assumed either. The point
        // is that the absence is treated as a mismatch and not as "nothing to
        // check, carry on".
        final libc = Platform.isMacOS
            ? '/usr/lib/libSystem.B.dylib'
            : '/lib/x86_64-linux-gnu/libc.so.6';
        if (!Platform.isMacOS && !Platform.isLinux) {
          return;
        }
        expect(
          () => openVeilLibraryAt(libc),
          throwsA(isA<VeilAbiContractMismatch>()),
        );
      },
      skip: (Platform.isMacOS || Platform.isLinux)
          ? false
          : 'needs a known system library path',
    );
  });
}
