import 'dart:ffi';
import 'dart:io' show Platform;

DynamicLibrary _open() {
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

final DynamicLibrary nativeLib = _open();
