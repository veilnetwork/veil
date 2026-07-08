# The Flutter tooling requires CMake 3.10 or later. Do not raise this minimum.
cmake_minimum_required(VERSION 3.10)

project(veil_media LANGUAGES C)

# veil_media is a Flutter *ffiPlugin* on Linux and compiles no C/C++ here: the
# call media engine ships as a prebuilt libveil_media.so (a from-source
# linux-x64 WebRTC + the engine/shim/V4L2-camera, statically linked), produced
# by linux/build_veil_media_so_linux.sh on an x86_64 Linux host. All the Flutter
# tool needs is the .so path via <plugin>_bundled_libraries so it lands in the
# app bundle's lib/; the Dart FFI layer dlopen's it by soname at call time.
#
# libveil_media.so has a DT_NEEDED on libveilclient_ffi.so (for the two
# veil_media_send_datagram / set_recv_callback datagram symbols) plus an $ORIGIN
# rpath, so it resolves those from the sibling .so that veil_flutter bundles
# into the same lib/ dir. Nothing to do here but point at the artifact.
#
# Reached via flutter/ephemeral/.plugin_symlinks/veil_media, so resolve our real
# location first (REALPATH follows the symlink); the .so sits next to this file.
get_filename_component(_veil_media_linux "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
set(_veil_media_so "${_veil_media_linux}/libveil_media.so")

if(NOT EXISTS "${_veil_media_so}")
  message(FATAL_ERROR
    "veil_media (linux): prebuilt engine missing:\n"
    "  ${_veil_media_so}\n"
    "Build it on an x86_64 Linux host with a from-source linux-x64 libwebrtc.a:\n"
    "  veil_media/linux/build_veil_media_so_linux.sh\n"
    "then place libveil_media.so next to this CMakeLists before flutter build linux.")
endif()

set(veil_media_bundled_libraries
  "${_veil_media_so}"
  PARENT_SCOPE
)
