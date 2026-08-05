/* SPDX-License-Identifier: MIT
 *
 * The C boundary, and what can and cannot be caught at it.
 *
 * Every veil_media_* entry point is `extern "C"`, and the callers are Dart
 * through dart:ffi and Rust through veilclient-ffi. Neither has a stack an
 * exception can unwind through, so anything thrown that reaches the boundary
 * ends the process — the app, its keys and its live sessions with it.
 *
 * READ THIS BEFORE RELYING ON THE MACROS BELOW.
 *
 * This library is compiled with -fno-exceptions on every target that ships.
 * All five build scripts (macos, ios, android, linux, windows) take their
 * compile command verbatim from WebRTC's own call/call.cc entry in
 * compile_commands.json, and WebRTC's gn args carry -fno-exceptions -fno-rtti.
 * Under that flag, with Chromium's libc++, a `throw` is not an exception at
 * all: std::vector's length_error and operator new's bad_alloc are compiled to
 * abort(). There is no handler that can run, here or anywhere else, and adding
 * one is a compile error rather than a defence.
 *
 * So the only protection against a container that asks for more memory than
 * can be had is to never make the request: every length taken off the wire is
 * checked against what the producer could actually have written BEFORE it
 * sizes an allocation. That check is the fix; see kVoiceOpusMax* in
 * veil_audio_play.cc and the frame-count proof in veil_video_note.cc.
 *
 * The macros stay because the entry points should state their contract, and
 * because a toolchain that does have exceptions — a host test, a future build
 * without WebRTC — then gets a real handler for free instead of a crash. Where
 * exceptions are disabled they expand to nothing, which is the honest
 * expansion: nothing is what can be done.
 *
 * Usage — the whole body, so the platform #if/#else branches are inside it:
 *
 *   int veil_media_thing(Handle* h) {
 *     VEIL_MEDIA_GUARD_BEGIN
 *     ...
 *     VEIL_MEDIA_GUARD_END(VEIL_MEDIA_ERR)
 *   }
 *
 * The value handed to VEIL_MEDIA_GUARD_END is what the caller sees, so it must
 * be that ABI's failure value — never one a caller would read as success.
 */
#pragma once

#include "veil_diag_log.h"

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#define VEIL_MEDIA_HAVE_EXCEPTIONS 1
#endif

namespace veil_media::guard {

// Diagnostics are off unless an operator asked for them (see veil_diag_log.h),
// so this says nothing on a distribution build. The name is a compile-time
// constant, never anything off the wire.
inline void note(const char* fn) {
  veil_media::diag::log("guard: exception escaped %s, refused", fn);
}

}  // namespace veil_media::guard

#if defined(VEIL_MEDIA_HAVE_EXCEPTIONS)

#define VEIL_MEDIA_GUARD_BEGIN try {

#define VEIL_MEDIA_GUARD_END(fallback)   \
  }                                      \
  catch (...) {                          \
    ::veil_media::guard::note(__func__); \
    return fallback;                     \
  }

#define VEIL_MEDIA_GUARD_END_VOID        \
  }                                      \
  catch (...) {                          \
    ::veil_media::guard::note(__func__); \
  }

#else  // -fno-exceptions: nothing to catch, and no way to catch it.

#define VEIL_MEDIA_GUARD_BEGIN
#define VEIL_MEDIA_GUARD_END(fallback)
#define VEIL_MEDIA_GUARD_END_VOID

#endif
