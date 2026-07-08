# The Flutter tooling requires CMake 3.10 or later. Do not raise this minimum —
# doing so makes the plugin fail to configure for downstream consumers.
cmake_minimum_required(VERSION 3.10)

project(veil_flutter LANGUAGES C)

# veil_flutter is a Flutter *ffiPlugin* on Linux: it compiles no C/C++ of its
# own. The Dart FFI layer (native_libs.dart) loads two prebuilt Rust shared
# objects at runtime via DynamicLibrary.open, so all we owe the Flutter tool is
# the list of libraries to copy into the app bundle's lib/ dir, exposed through
# the conventional <plugin>_bundled_libraries variable that the app's
# linux/flutter/generated_plugins.cmake FFI loop reads.
#
#   libveilclient_ffi.so    — veil overlay-network client + embedded node
#   libhidden_volume_ffi.so — deniable storage FFI
#
# hidden_volume has no Linux plugin registration of its own (it is not in
# FLUTTER_FFI_PLUGIN_LIST), so its .so is bundled here alongside veilclient's.
# Both are produced by scripts/build-native.sh into each submodule's
# target/<profile>/ directory.
#
# This CMakeLists is reached through
# flutter/ephemeral/.plugin_symlinks/veil_flutter, so resolve our real on-disk
# location first (REALPATH follows the symlink). Without that, the ".." walk
# would climb the app's build tree instead of the third_party/ source tree. All
# paths below are derived from this resolved location — no machine-specific
# absolute paths.
get_filename_component(_veil_flutter_linux "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
# .../third_party/veil/flutter/veil_flutter/linux  ->  up 3 == the veil submodule
get_filename_component(_veil_root "${_veil_flutter_linux}/../../.." REALPATH)
# up 1 more == third_party/, where the sibling hidden-volume submodule lives
get_filename_component(_third_party "${_veil_root}/.." REALPATH)

# Match the native profile to the Flutter build mode: a Debug flutter build
# pairs with `build-native.sh` (debug), every other mode with
# `build-native.sh --release`. This mirrors build-native.sh's own split.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(_veil_profile "debug")
else()
  set(_veil_profile "release")
endif()

set(_veilclient_so    "${_veil_root}/target/${_veil_profile}/libveilclient_ffi.so")
set(_hidden_volume_so "${_third_party}/hidden-volume/target/${_veil_profile}/libhidden_volume_ffi.so")

foreach(_lib "${_veilclient_so}" "${_hidden_volume_so}")
  if(NOT EXISTS "${_lib}")
    message(FATAL_ERROR
      "veil_flutter (linux): prebuilt library missing:\n"
      "  ${_lib}\n"
      "Run  scripts/build-native.sh --release  from the xVeil repo root before "
      "flutter build linux (use the flag matching CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}).")
  endif()
endforeach()

set(veil_flutter_bundled_libraries
  "${_veilclient_so}"
  "${_hidden_volume_so}"
  PARENT_SCOPE
)
