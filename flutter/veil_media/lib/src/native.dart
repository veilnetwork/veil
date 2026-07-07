import 'dart:ffi';
import 'dart:io';

/// Resolve the native veil_media library.
///
/// Unlike veilclient_ffi (which is linked into the host app and found via
/// `DynamicLibrary.process()`), libveil_media.dylib is bundled into the app's
/// Frameworks separately (scripts/bundle-macos-dylibs.sh) and NOT linked at
/// build time, so we open it explicitly:
///   * macOS: `<app>/Contents/Frameworks/libveil_media.dylib` (absolute, via
///     the resolved executable) — falls back to a bare name / process().
///   * Android/Linux: `libveil_media.so` from the loader path.
///   * iOS: statically embedded → `process()`.
/// `VEIL_MEDIA_DYLIB` overrides for tests.
DynamicLibrary _open() {
  final override = Platform.environment['VEIL_MEDIA_DYLIB'];
  if (override != null && override.isNotEmpty) {
    return DynamicLibrary.open(override);
  }
  if (Platform.isMacOS) {
    // resolvedExecutable = <app>/Contents/MacOS/xveil → ../../Frameworks/…
    final contents = File(Platform.resolvedExecutable).parent.parent.path;
    final fw = '$contents/Frameworks/libveil_media.dylib';
    if (File(fw).existsSync()) return DynamicLibrary.open(fw);
    try {
      return DynamicLibrary.open('libveil_media.dylib');
    } catch (_) {
      return DynamicLibrary.process();
    }
  }
  if (Platform.isIOS) {
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
