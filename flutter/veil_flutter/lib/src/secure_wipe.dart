// Secret-material hygiene for native (FFI) buffers.
//
// Several FFI call sites copy secret material — wake-HMAC keys, mailbox
// auth cookies, capability tokens, sealed push tokens — into a short-lived
// `calloc`-backed buffer, hand it to the Rust side, then free it. Freeing
// alone leaves the plaintext secret in native heap that the allocator may
// later hand to an unrelated allocation. [zeroizeNative] wipes the buffer
// first so the window in which the secret is recoverable closes at free
// time rather than "whenever the page is next overwritten".

import 'dart:ffi';
import 'dart:typed_data';

/// Best-effort wipe of a `calloc`-backed native buffer that held secret
/// material, to be called immediately before `calloc.free(ptr)`.
///
/// The typed-list view writes through to the native region; the Dart runtime
/// cannot prove that region is unobserved, so the zero stores are not elided
/// the way a dead write to a pure-Dart list might be.
///
/// Scope/limitation: this covers only buffers we allocate and free on the
/// Dart side. Secret values returned to callers as a [Uint8List] are
/// GC-managed and cannot be reliably wiped in-process — callers should hand
/// them to the platform keystore (iOS Keychain / Android Keystore) and drop
/// the reference promptly.
void zeroizeNative(Pointer<Uint8> ptr, int len) {
  if (ptr == nullptr || len <= 0) return;
  ptr.asTypedList(len).fillRange(0, len, 0);
}
