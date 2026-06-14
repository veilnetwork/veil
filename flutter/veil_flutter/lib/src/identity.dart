// BIP-39 identity recovery (Epic 489.8).
//
// User flow:
//   1. App launches on a fresh device.
//   2. User picks "Restore identity" → enters their 24-word BIP-39
//      phrase (paper backup from a previous device).
//   3. App calls [validateBip39Phrase] for live feedback as they type.
//   4. On submit, app calls [restoreIdentity] which derives the
//      device's identity files into [veilDir] (typically the
//      app's `getApplicationSupportDirectory()`).
//   5. App starts the daemon — it loads the freshly-written
//      identity_document.bin / instance.toml / identity_sk.bin and
//      joins the network with the SAME node_id the original device
//      had.  Name, reputation, contacts, sessions all survive.
//
// Crypto-side details: BIP-39 phrase → 32 B master_seed → HKDF →
// master_sk (Ed25519) → master_pk → node_id = BLAKE3(master_pk).
// The node_id is **deterministic** in the phrase, so any two
// devices that restore from the same phrase agree on the network
// address.

import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import 'bindings.dart' as ffi;
import 'types.dart';

/// Validate a BIP-39 master phrase synchronously (no disk I/O, no
/// daemon).  Returns `true` if the phrase is exactly 24 words from
/// the English BIP-39 wordlist AND the checksum verifies.
///
/// Use this in the UI to give immediate feedback as the user types
/// — light enough to call on every keystroke.
///
/// On failure, throws [VeilException] with the specific reason
/// (unknown word / wrong word count / bad checksum).
bool validateBip39Phrase(String phrase) {
  final phraseC = phrase.toNativeUtf8();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    // Zeroize variant: native buffer is wiped in place before return,
    // so the plaintext window in heap memory collapses to the lifetime
    // of this single FFI call.  Caller still owns/frees the allocation
    // (now zeroed).  The immutable Dart `phrase` String survives —
    // unavoidable without a Uint8List-based input path.
    final rc = ffi.veilValidateBip39PhraseZeroize(phraseC, errOut);
    if (rc == ffi.veilOk) return true;
    final errPtr = errOut.value;
    final msg = errPtr == nullptr ? '<no detail>' : errPtr.toDartString();
    if (errPtr != nullptr) ffi.veilFreeString(errPtr);
    throw VeilException(msg, code: rc);
  } finally {
    calloc.free(phraseC);
    calloc.free(errOut);
  }
}

/// Restore an identity from a BIP-39 master phrase, writing identity
/// files into [veilDir].
///
/// On success the directory contains:
///   * `identity_document.bin` — signed master+device cert chain
///   * `instance.toml`         — per-device instance label + sig key index
///   * `identity_sk.bin`       — this device's per-instance signing key
///
/// The daemon, on subsequent launch, reads these files and brings
/// up the network connection with the recovered `node_id`.
///
/// [instanceLabel] is the human-readable name shown in
/// `identity show` for this device (e.g. "Phone — May 2024").  Cap
/// is 64 ASCII chars; longer labels truncate.
///
/// Idempotent: re-running with the same phrase + same dir regenerates
/// the per-device identity_sk and rewrites the document.  The
/// `node_id` stays stable across calls (BIP-39 → master is
/// deterministic).
///
/// Throws [VeilException] on:
///   * malformed phrase (use [validateBip39Phrase] for UI feedback first),
///   * cannot create / write to [veilDir],
///   * any underlying crypto failure (rare — would indicate a bug).
Future<void> restoreIdentity({
  required String phrase,
  required String veilDir,
  required String instanceLabel,
}) {
  // diff-audit H3 follow-up: this derives the master seed → identity_sk
  // (Ed25519 keygen + signing) and writes the document/instance/sk files to
  // disk — seconds of synchronous work on a budget device. Offload to a worker
  // isolate (like `restoreIdentityEncrypted`) so it can't freeze the UI isolate.
  // All four args are `String` (sendable); the native lib + bindings re-init in
  // the spawned isolate; `VeilException` (String + int) marshals back on failure.
  return Isolate.run(() {
    final phraseC = phrase.toNativeUtf8();
    final dirC = veilDir.toNativeUtf8();
    final labelC = instanceLabel.toNativeUtf8();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      // Zeroize variant: phrase buffer is wiped in place after the master
      // seed is decoded, regardless of success/error path.
      final rc = ffi.veilRestoreIdentityFromPhraseZeroize(
        phraseC, dirC, labelC, errOut,
      );
      if (rc == ffi.veilOk) return;
      final errPtr = errOut.value;
      final msg = errPtr == nullptr ? '<no detail>' : errPtr.toDartString();
      if (errPtr != nullptr) ffi.veilFreeString(errPtr);
      throw VeilException(msg, code: rc);
    } finally {
      calloc.free(phraseC);
      calloc.free(dirC);
      calloc.free(labelC);
      calloc.free(errOut);
    }
  });
}

/// Restore identity AND save a passphrase-encrypted master-seed backup
/// (`master.enc`) alongside it.  Combines [restoreIdentity] with the
/// Argon2id-encrypted backup path so apps can offer "recovery via
/// passphrase only" — user provides the passphrase to decrypt; no
/// BIP-39 phrase needs to leave the device once the encrypted blob
/// is written.
///
/// Both [phrase] AND [passphrase] are passed via FFI buffers that
/// get zeroed in place before this function returns (success AND
/// error paths).  The immutable Dart `String`s survive (unavoidable
/// without Uint8List-based input) — caller should drop references
/// promptly.
///
/// [passphrase] is encoded as UTF-8.  Strength is the caller's
/// responsibility — veil-identity uses Argon2id with production
/// parameters (64 MiB memory, t=3, p=4), which makes brute-force
/// expensive but cannot save user-supplied "password123".  Consider
/// gating on length (≥ 12 chars) and/or a strength meter in the UI.
///
/// Files written to [veilDir]:
///   * `identity_document.bin` — signed master+device cert chain
///   * `instance.toml`         — per-device instance label + sig key
///   * `identity_sk.bin`       — this device's per-instance signing key
///   * `master.enc`            — Argon2id-derived-key-encrypted master
///                               seed (allows offline restore with only
///                               the passphrase)
///
/// Throws [VeilException] on:
///   * malformed [phrase],
///   * invalid UTF-8 [passphrase],
///   * cannot create / write to [veilDir],
///   * crypto failure (rare — would indicate a bug).
Future<void> restoreIdentityEncrypted({
  required String phrase,
  required String veilDir,
  required String instanceLabel,
  required String passphrase,
}) {
  // diff-audit H3: this call runs Argon2id (64 MiB, t=3, p=4) — multiple seconds
  // on budget Android — so it MUST NOT run on the UI isolate (it previously was a
  // plain synchronous function → hard UI freeze / ANR). Offload it to a worker
  // isolate via `Isolate.run`. The native library + bindings are top-level
  // lazies (`native.dart`'s `nativeLib`), so they re-initialise inside the
  // spawned isolate; all four args are `String` (sendable) and `VeilException`
  // (String + int) marshals back across the boundary on failure.
  return Isolate.run(() {
    final phraseC = phrase.toNativeUtf8();
    final dirC = veilDir.toNativeUtf8();
    final labelC = instanceLabel.toNativeUtf8();
    final passC = passphrase.toNativeUtf8();
    final errOut = calloc<Pointer<Utf8>>();
    try {
      final rc = ffi.veilRestoreIdentityFromPhraseZeroizeWithPassword(
        phraseC, dirC, labelC, passC, errOut,
      );
      if (rc == ffi.veilOk) return;
      final errPtr = errOut.value;
      final msg = errPtr == nullptr ? '<no detail>' : errPtr.toDartString();
      if (errPtr != nullptr) ffi.veilFreeString(errPtr);
      throw VeilException(msg, code: rc);
    } finally {
      calloc.free(phraseC);
      calloc.free(dirC);
      calloc.free(labelC);
      calloc.free(passC);
      calloc.free(errOut);
    }
  });
}

/// Sanity-check helper for UI: returns `true` iff [phrase], when
/// trimmed and split on whitespace, has exactly 24 tokens.  Lightweight
/// pre-check that the phrase has the right shape without calling FFI.
/// Use in UI to gate the "Restore" button BEFORE the heavyweight
/// [validateBip39Phrase] call (which validates the BIP-39 checksum).
bool hasBip39WordCount(String phrase) {
  return phrase.trim().split(RegExp(r'\s+')).where((w) => w.isNotEmpty).length == 24;
}
