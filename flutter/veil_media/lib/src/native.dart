import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

// bionic dlopen flags (android). RTLD_LOCAL is 0 (Dart's default), so a bare
// DynamicLibrary.open does NOT expose the loaded lib's symbols to later loads.
const int _rtldNow = 0x00002;
const int _rtldGlobal = 0x00100;

/// Android: re-open [soname] with RTLD_GLOBAL so its symbols join the global
/// scope. libveil_media.so leaves veil_media_send_datagram /
/// veil_media_set_recv_callback undefined (they live in libveilclient_ffi.so);
/// on ELF they only resolve if veilclient_ffi is global BEFORE veil_media loads.
void _preloadGlobalAndroid(String soname) {
  try {
    final proc = DynamicLibrary.process();
    final dlopen = proc.lookupFunction<
        Pointer<Void> Function(Pointer<Utf8>, Int32),
        Pointer<Void> Function(Pointer<Utf8>, int)>('dlopen');
    final name = soname.toNativeUtf8();
    try {
      dlopen(name, _rtldNow | _rtldGlobal);
    } finally {
      malloc.free(name);
    }
  } catch (_) {
    // best effort; veil_media may still resolve if veilclient_ffi is global
  }
}

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
  if (Platform.isAndroid) {
    _preloadGlobalAndroid('libveilclient_ffi.so');
    return DynamicLibrary.open('libveil_media.so');
  }
  if (Platform.isLinux) {
    return DynamicLibrary.open('libveil_media.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('veil_media.dll');
  }
  throw UnsupportedError('veil_media: unsupported platform');
}

final DynamicLibrary nativeLib = _open();
