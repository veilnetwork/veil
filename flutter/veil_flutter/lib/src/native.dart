import 'dart:ffi';
import 'dart:io' show File, Platform;

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

final DynamicLibrary nativeLib = _open();
