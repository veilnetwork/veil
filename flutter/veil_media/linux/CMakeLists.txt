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

# Whether a missing engine is fatal here or merely loud is a decision, and it
# is made in one place for both desktop platforms. See the long note there.
include("${_veil_media_linux}/../cmake/veil_media_engine_policy.cmake")
veil_media_engine_policy(_veil_media_required _veil_media_why)

if(EXISTS "${_veil_media_so}")
  set(veil_media_bundled_libraries
    "${_veil_media_so}"
    PARENT_SCOPE
  )
elseif(_veil_media_required)
  message(FATAL_ERROR
    "veil_media (linux): prebuilt engine missing:\n"
    "  ${_veil_media_so}\n"
    "Refusing to build without it because ${_veil_media_why}.\n"
    "A bundle with no engine starts, looks healthy, and throws at the first\n"
    "voice message — v0.9.1 shipped exactly that.\n"
    "Build it on an x86_64 Linux host with a from-source linux-x64 libwebrtc.a:\n"
    "  veil_media/linux/build_veil_media_so_linux.sh\n"
    "or download the artifact the webrtc-linux workflow produces, then place\n"
    "libveil_media.so next to this CMakeLists before flutter build linux.")
else()
  # One string, not three: the third parameter is a single argument and any
  # extra quoted pieces would land in ARGN and be silently dropped.
  veil_media_engine_absent_warning("${_veil_media_so}" "linux"
    "    veil_media/linux/build_veil_media_so_linux.sh (x86_64 Linux host, from-source linux-x64 libwebrtc.a)\n    or the libveil_media-linux-x64 artifact from the webrtc-linux workflow.\n")
  # Empty, and set explicitly rather than left undefined: the parent's
  # generated_plugins.cmake list(APPEND)s this, and an undefined variable there
  # would be indistinguishable from a plugin that forgot to answer.
  set(veil_media_bundled_libraries "" PARENT_SCOPE)
endif()
