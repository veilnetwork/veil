/* SPDX-License-Identifier: MIT
 *
 * veil_win_datagram_thunk.cc — resolve the two veilclient datagram entry
 * points at runtime instead of importing them.
 *
 * veil_media_send_datagram and veil_media_set_recv_callback are defined by
 * veilclient_ffi, not by this engine. On ELF they are simply left undefined
 * and the loader resolves them from the sibling library (a DT_NEEDED plus an
 * $ORIGIN rpath — see build_veil_media_so_linux.sh). A Windows DLL cannot do
 * that: every symbol must be resolved at link time, which would make building
 * the engine depend on veilclient_ffi.lib, which is a Rust build output. That
 * is a build-order dependency between two artifacts produced on different
 * machines by different toolchains, for two function pointers.
 *
 * So resolve them the way Windows actually offers: GetProcAddress against the
 * veilclient_ffi.dll the host process has already loaded. GetModuleHandle
 * rather than LoadLibrary on purpose — if the app has not loaded it, the media
 * engine has nothing to send over anyway, and quietly loading a second copy
 * from some other directory is how you get two Veil clients in one process.
 *
 * The thunks are NOT exported: the .def the build script generates skips them,
 * so the app's own veil_media_send_datagram remains the only one visible.
 *
 * ⚠️ Never compiled — see veil_mf_camera.cc.
 */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <mutex>

#include "veil_diag_log.h"

// Must match veil_transport_shim.cc's declarations exactly: the callback takes
// (ctx, ptr, len) in that order and the setter returns int, not void. Declared
// at file scope, not inside the anonymous namespace below, so the extern "C"
// definitions do not name an internal-linkage type in their signature.
extern "C" {
typedef void (*VeilMediaRecvFn)(void* ctx, const uint8_t* ptr, size_t len);
}

namespace {

using SendDatagramFn = int (*)(uint64_t, const uint8_t*, size_t);
using SetRecvCallbackFn = int (*)(uint64_t, VeilMediaRecvFn, void*);

struct Resolved {
  SendDatagramFn send = nullptr;
  SetRecvCallbackFn set_recv = nullptr;
};

const Resolved& resolved() {
  // Function-local static: thread-safe initialisation without an atexit
  // ordering problem, and the lookup happens on the first packet rather than
  // at DLL attach, where calling GetProcAddress across modules is unsafe.
  static const Resolved value = [] {
    Resolved out;
    HMODULE module = GetModuleHandleW(L"veilclient_ffi.dll");
    if (module == nullptr) {
      veil_media::diag::log(
          "veilclient_ffi.dll is not loaded — media datagrams go nowhere");
      return out;
    }
    out.send = reinterpret_cast<SendDatagramFn>(
        GetProcAddress(module, "veil_media_send_datagram"));
    out.set_recv = reinterpret_cast<SetRecvCallbackFn>(
        GetProcAddress(module, "veil_media_set_recv_callback"));
    if (out.send == nullptr || out.set_recv == nullptr) {
      veil_media::diag::log(
          "veilclient_ffi.dll is loaded but exports no datagram ABI — "
          "version mismatch between the engine and the client");
    }
    return out;
  }();
  return value;
}

}  // namespace

extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* ptr,
                                        size_t len) {
  const SendDatagramFn fn = resolved().send;
  // -1 rather than 0: the engine treats a short write as backpressure and
  // retries, and a silent success would drop every packet of the call while
  // reporting a healthy stream.
  return fn != nullptr ? fn(chan, ptr, len) : -1;
}

extern "C" int veil_media_set_recv_callback(uint64_t chan, VeilMediaRecvFn cb,
                                            void* ctx) {
  const SetRecvCallbackFn fn = resolved().set_recv;
  // Non-zero is failure here too (veil_transport_shim.cc checks rc != 0), so a
  // missing client must not look like a successful subscription.
  return fn != nullptr ? fn(chan, cb, ctx) : -1;
}

#endif  // defined(_WIN32)
