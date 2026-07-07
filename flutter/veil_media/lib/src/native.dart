import 'dart:ffi';
import 'dart:io';

/// Resolve the native veil_media library.
///
/// FFI plugin: on Apple platforms the symbols are statically linked into the
/// host app (there is no standalone dylib to open at runtime), so we bind
/// against the process. On Android/Linux the plugin ships `libveil_media.so`;
/// on Windows `veil_media.dll`. `VEIL_MEDIA_DYLIB` overrides for tests.
DynamicLibrary _open() {
  final override = Platform.environment['VEIL_MEDIA_DYLIB'];
  if (override != null && override.isNotEmpty) {
    return DynamicLibrary.open(override);
  }
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('libveil_media.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('veil_media.dll');
  }
  throw UnsupportedError('veil_media: unsupported platform');
}

final DynamicLibrary nativeLib = _open();
