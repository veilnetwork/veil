import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

// bionic dlopen flags (android). RTLD_LOCAL is 0 (Dart's default), so a bare
// DynamicLibrary.open does NOT expose the loaded lib's symbols to later loads.
const int _rtldNow = 0x00002;
const int _rtldGlobal = 0x00100;
String? _androidNativeLibraryDir() {
  try {
    final lines = File('/proc/self/maps').readAsLinesSync();
    for (final line in lines) {
      final marker = line.contains('/libveilclient_ffi.so')
          ? '/libveilclient_ffi.so'
          : line.contains('/libflutter.so')
              ? '/libflutter.so'
              : null;
      if (marker == null) continue;
      final idx = line.indexOf('/data/app/');
      final end = line.indexOf(marker);
      if (idx >= 0 && end > idx) return line.substring(idx, end);
    }
  } catch (_) {}
  return null;
}

Pointer<Void> _dlopenGlobalAndroidPath(String path) {
  final proc = DynamicLibrary.process();
  final dlopen = proc.lookupFunction<
      Pointer<Void> Function(Pointer<Utf8>, Int32),
      Pointer<Void> Function(Pointer<Utf8>, int)>('dlopen');
  final dlerror =
      proc.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>(
          'dlerror');
  final name = path.toNativeUtf8();
  try {
    final handle = dlopen(name, _rtldNow | _rtldGlobal);
    if (handle == nullptr) {
      final err = dlerror();
      final msg = err == nullptr ? 'unknown error' : err.toDartString();
      debugPrint('veil_media: dlopen $path global failed: $msg');
    }
    return handle;
  } finally {
    malloc.free(name);
  }
}

/// Android: re-open [soname] with RTLD_GLOBAL so its symbols join the global
/// scope. libveil_media.so leaves veil_media_send_datagram /
/// veil_media_set_recv_callback undefined (they live in libveilclient_ffi.so);
/// on ELF they only resolve if veilclient_ffi is global BEFORE veil_media loads.
void _preloadGlobalAndroid(String soname) {
  try {
    if (soname == 'libveil_media_camera_stub.so') {
      final nativeDir = _androidNativeLibraryDir();
      if (nativeDir != null && nativeDir.isNotEmpty) {
        _dlopenGlobalAndroidPath('$nativeDir/$soname');
      }
    }
    _dlopenGlobalAndroidPath(soname);
  } catch (e) {
    debugPrint('veil_media: dlopen $soname global threw: $e');
    // best effort; veil_media may still resolve if veilclient_ffi is global
  }
}

DynamicLibrary _openAndroid() {
  _preloadGlobalAndroid('libveilclient_ffi.so');
  _preloadGlobalAndroid('libveil_media_camera_stub.so');
  final nativeDir = _androidNativeLibraryDir();
  if (nativeDir != null && nativeDir.isNotEmpty) {
    final path = '$nativeDir/libveil_media.so';
    final handle = _dlopenGlobalAndroidPath(path);
    if (handle != nullptr) return DynamicLibrary.open(path);
  }
  return DynamicLibrary.open('libveil_media.so');
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
    return _openAndroid();
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
