import 'dart:ffi';
import 'dart:io' show File, Platform;

import 'package:ffi/ffi.dart' show Utf8, Utf8Pointer;

import 'abi_contract.dart' as abi;

/// The loaded library disagrees with the ABI these bindings were generated
/// from, so nothing may be called through it.
///
/// Every other binding in this package is reached through [nativeLib], and
/// [nativeLib] is this check — so a mismatched library cannot be called at
/// all, not even once. That ordering is the whole point: the failure this
/// guards is not a missing symbol (which fails loudly on its own), it is a
/// symbol that still exists and no longer means the same thing. Commit
/// `78d57520` inserted a trust-level byte into the MIDDLE of the receive
/// callback's parameter list; an older caller invoking the unchanged symbol
/// name reads the message pointer from a register that now holds one byte.
/// One such call is already memory corruption, so the check has to come
/// before the first one, not after a failure.
class VeilAbiContractMismatch implements Exception {
  VeilAbiContractMismatch({required this.expected, required this.actual});

  /// The hash these Dart bindings were generated from.
  final String expected;

  /// What the loaded library reported, or `null` when it has no
  /// `veil_abi_contract_hash` symbol at all (a build from before the contract
  /// existed — old enough that its layout cannot be assumed either).
  final String? actual;

  @override
  String toString() {
    final got = actual ?? '<no veil_abi_contract_hash symbol>';
    return 'VeilAbiContractMismatch: the loaded veilclient-ffi library was '
        'built from a different C ABI than these Dart bindings.\n'
        '  bindings expect: $expected\n'
        '  library reports: $got\n'
        'Rebuild the native library and regenerate the bindings from the same '
        'tree (./scripts/regen-ffi-header.sh). Calling through a mismatched '
        'ABI is memory corruption, not a recoverable error, so the library '
        'has not been loaded.';
  }
}

typedef _AbiHashNative = Pointer<Utf8> Function();
typedef _AbiHashDart = Pointer<Utf8> Function();

DynamicLibrary _open() {
  // diff-audit H3 (test support): on macOS/iOS the library is normally linked
  // into the host app and resolved via `DynamicLibrary.process()`. A Dart/Flutter
  // TEST VM has no such symbols, so when `VEIL_FFI_DYLIB` points at a built
  // `libveilclient_ffi.{dylib,so}` we `open` it explicitly. Production never sets
  // this env var, so the platform branches below are unchanged at runtime.
  final overridePath = Platform.environment['VEIL_FFI_DYLIB'];
  if (overridePath != null && overridePath.isNotEmpty) {
    return DynamicLibrary.open(overridePath);
  }
  final bundled = File(Platform.resolvedExecutable)
      .parent
      .parent
      .uri
      .resolve('lib/${_fileName()}')
      .toFilePath();
  if (File(bundled).existsSync()) return DynamicLibrary.open(bundled);
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libveilclient_ffi.so');
  }
  if (Platform.isLinux) {
    return DynamicLibrary.open('libveilclient_ffi.so');
  }
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('veilclient_ffi.dll');
  }
  throw UnsupportedError('veil_flutter: unsupported platform ${Platform.operatingSystem}');
}

String _fileName() {
  if (Platform.isWindows) return 'veilclient_ffi.dll';
  if (Platform.isMacOS || Platform.isIOS) {
    return 'libveilclient_ffi.dylib';
  }
  return 'libveilclient_ffi.so';
}

/// Read `veil_abi_contract_hash()` from [lib], or `null` when the symbol is
/// absent (pre-contract build).
String? readAbiContractHash(DynamicLibrary lib) {
  final _AbiHashDart fn;
  try {
    fn = lib.lookupFunction<_AbiHashNative, _AbiHashDart>(
      'veil_abi_contract_hash',
    );
  } on ArgumentError {
    return null;
  }
  final p = fn();
  if (p == nullptr) return null;
  return p.toDartString();
}

/// Open the native library and refuse it unless its ABI contract hash matches
/// [expectedAbiHash].
///
/// The lookup of `veil_abi_contract_hash` is the FIRST symbol resolution
/// performed against the library and the only one that happens before the
/// comparison; on mismatch this throws [VeilAbiContractMismatch] and no
/// handle to the library escapes, so no other entry point can be reached.
///
/// [expectedAbiHash] is a parameter rather than a constant read inline so the
/// refusal itself is testable against a REAL library — see
/// `test/abi_contract_test.dart`.
DynamicLibrary openVeilLibrary({String expectedAbiHash = abi.veilAbiContractHash}) =>
    _checked(_open(), expectedAbiHash);

/// [openVeilLibrary] against an explicit path.
///
/// A test / diagnostic seam: production resolution belongs to
/// [openVeilLibrary], which knows the platform's bundling rules.  Exposed so
/// the refusal can be exercised against a real library rather than a mock —
/// there is no mocking a `DynamicLibrary`.
DynamicLibrary openVeilLibraryAt(
  String path, {
  String expectedAbiHash = abi.veilAbiContractHash,
}) =>
    _checked(DynamicLibrary.open(path), expectedAbiHash);

DynamicLibrary _checked(DynamicLibrary lib, String expectedAbiHash) {
  final actual = readAbiContractHash(lib);
  if (actual != expectedAbiHash) {
    throw VeilAbiContractMismatch(expected: expectedAbiHash, actual: actual);
  }
  return lib;
}

final DynamicLibrary nativeLib = openVeilLibrary();
