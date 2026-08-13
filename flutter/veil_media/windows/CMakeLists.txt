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
# Unlike the ELF platforms there is no DT_NEEDED to arrange, and no import
# either: veil_media.dll does NOT link against veilclient_ffi.lib. Doing so
# would make this build depend on a Rust artifact produced on another machine
# by another toolchain, for two function pointers, so the two datagram entry
# points are resolved at runtime instead - GetProcAddress against the already
# loaded veilclient_ffi.dll. See src/veil_win_datagram_thunk.cc.
#
# That module is present because builder.py copies it next to xveil.exe after
# the Flutter build, not because a plugin bundles it: veil_flutter declares no
# windows platform at all. Dart opens it by that exact name, which is what
# makes GetModuleHandleW find it.
#
# Reached via flutter/ephemeral/.plugin_symlinks/veil_media, so resolve our real
# location first (REALPATH follows the symlink); the .dll sits next to this file.
get_filename_component(_veil_media_windows "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
set(_veil_media_dll "${_veil_media_windows}/veil_media.dll")

# Whether a missing engine is fatal here or merely loud is a decision, and it
# is made in one place for both desktop platforms. See the long note there.
include("${_veil_media_windows}/../cmake/veil_media_engine_policy.cmake")
veil_media_engine_policy(_veil_media_required _veil_media_why)

if(EXISTS "${_veil_media_dll}")
  set(veil_media_bundled_libraries
    "${_veil_media_dll}"
    PARENT_SCOPE
  )
elseif(_veil_media_required)
  message(FATAL_ERROR
    "veil_media (windows): prebuilt engine missing:\n"
    "  ${_veil_media_dll}\n"
    "Refusing to build without it because ${_veil_media_why}.\n"
    "Failing here is deliberate: a bundle without it starts, looks healthy and\n"
    "throws at the first voice message — every zip through v0.9.1 did.\n"
    "Build it on a Windows host with a from-source win-x64 libwebrtc:\n"
    "  windows/build_veil_media_dll_windows.ps1\n"
    "or download the artifact the webrtc-windows workflow produces, then place\n"
    "veil_media.dll next to this CMakeLists before flutter build windows.")
else()
  # One string, not three — see the linux CMakeLists.
  veil_media_engine_absent_warning("${_veil_media_dll}" "windows"
    "    windows/build_veil_media_dll_windows.ps1 (Windows host, from-source win-x64 libwebrtc)\n    or the libveil_media-win-x64 artifact from the webrtc-windows workflow.\n")
  # Empty, and set explicitly — see the linux CMakeLists for why.
  set(veil_media_bundled_libraries "" PARENT_SCOPE)
endif()
