# The Flutter tooling requires CMake 3.14 or later on Windows.
cmake_minimum_required(VERSION 3.14)

project(veil_media LANGUAGES C)

# veil_media is a Flutter *ffiPlugin* on Windows and compiles no C/C++ here:
# the call media engine ships as a prebuilt veil_media.dll (a from-source
# win-x64 WebRTC + the engine/shim/Media-Foundation-camera/GDI-screen,
# statically linked), produced by windows/build_veil_media_dll_windows.ps1 on a
# Windows host with Visual Studio. All the Flutter tool needs is the .dll path
# via <plugin>_bundled_libraries so it lands next to the executable; the Dart
# FFI layer LoadLibrary's it by name at call time.
#
# Unlike the ELF platforms there is no DT_NEEDED to arrange: veilclient_ffi.dll
# exports veil_media_send_datagram / veil_media_set_recv_callback and Windows
# resolves an import by DLL name from the application directory, where
# veil_flutter already bundles it. The import table is written at link time by
# the build script, which links against veilclient_ffi.lib.
#
# Reached via flutter/ephemeral/.plugin_symlinks/veil_media, so resolve our real
# location first (REALPATH follows the symlink); the .dll sits next to this file.
get_filename_component(_veil_media_windows "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
set(_veil_media_dll "${_veil_media_windows}/veil_media.dll")

if(NOT EXISTS "${_veil_media_dll}")
  message(FATAL_ERROR
    "veil_media (windows): prebuilt engine missing:\n"
    "  ${_veil_media_dll}\n"
    "Build it on a Windows host with a from-source win-x64 libwebrtc:\n"
    "  windows/build_veil_media_dll_windows.ps1\n"
    "or download the artifact the webrtc-windows workflow produces, then place\n"
    "veil_media.dll next to this CMakeLists before flutter build windows.\n"
    "Failing here is deliberate: a bundle without it starts, looks healthy and\n"
    "throws at the first voice message.")
endif()

set(veil_media_bundled_libraries
  "${_veil_media_dll}"
  PARENT_SCOPE
)
