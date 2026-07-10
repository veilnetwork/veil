// Nicknames over veil — Dart wrappers (brick 4-1 of the nicknames epic).
//
// Pure helpers (normalize / floor / mine / verify) are synchronous FFI with
// no network. Mining is CPU-bound and MUST run off the UI isolate: call
// [mineNicknameChunk] in a loop inside `Isolate.run`, threading `seeds` back
// in as `priorSeeds`; cancel by simply not calling again.
//
// [claimNickname] / [resolveNickname] talk to the in-process embedded node
// (sovereign identities only — the app must never claim/resolve-publish for
// anonymous identities: a public name is a linkability signal). They block
// for up to `timeoutMs`, so call them through `Isolate.run` too.

import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'dart:ffi';

import 'bindings.dart' as ffi;
import 'types.dart';

/// Outcome of one bounded [mineNicknameChunk] call.
class NicknameMineOutcome {
  const NicknameMineOutcome({
    required this.hitTarget,
    required this.weight,
    required this.hashesDone,
    required this.seeds,
  });

  /// Whether the cumulative weight reached the requested target.
  final bool hitTarget;

  /// Cumulative weight proven by [seeds].
  final int weight;

  /// Hashes actually computed in this chunk (progress/effort reporting).
  final int hashesDone;

  /// The running best seed set (concatenated 32-byte seeds) — thread it back
  /// into the next chunk as `priorSeeds`, and hand it to [claimNickname]
  /// when done.
  final Uint8List seeds;
}

/// The current owner of a resolved nickname.
class ResolvedNickname {
  const ResolvedNickname({
    required this.ownerNodeId,
    required this.weight,
    required this.issuedAtUnix,
  });

  /// Sovereign node id of the owner (32 bytes) — the id an invite targets.
  final Uint8List ownerNodeId;

  /// Cumulative PoW weight backing the record (the moat a contester must
  /// strictly exceed).
  final int weight;

  /// Owner-declared freshness stamp (unix seconds).
  final int issuedAtUnix;
}

String _takeErr(Pointer<Pointer<Utf8>> errOut, int rc) {
  final errPtr = errOut.value;
  final msg = errPtr == nullptr ? 'error $rc' : errPtr.toDartString();
  if (errPtr != nullptr) ffi.veilFreeString(errPtr);
  return msg;
}

/// Normalize a candidate nickname to canonical form (lowercase,
/// `[a-z0-9_]`, 3..=32 chars). Throws [VeilException] if it cannot be.
String normalizeNickname(String name) {
  final nameC = name.toNativeUtf8();
  final outBuf = calloc<Pointer<Uint8>>();
  final outLen = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    final rc = ffi.veilNicknameNormalize(
        nameC.cast(), nameC.length, outBuf, outLen, errOut);
    if (rc != ffi.veilOk) {
      throw VeilException(_takeErr(errOut, rc), code: rc);
    }
    final bytes = Uint8List.fromList(outBuf.value.asTypedList(outLen.value));
    ffi.veilFreeBuf(outBuf.value, outLen.value);
    return String.fromCharCodes(bytes);
  } finally {
    calloc.free(nameC);
    calloc.free(outBuf);
    calloc.free(outLen);
    calloc.free(errOut);
  }
}

/// The cumulative PoW weight a name of this length must reach (the
/// anti-squat floor). Returns 0 for an un-normalizable name.
int nicknameLengthFloor(String name) {
  final nameC = name.toNativeUtf8();
  try {
    return ffi.veilNicknameLengthFloor(nameC.cast(), nameC.length);
  } finally {
    calloc.free(nameC);
  }
}

/// Mine one bounded chunk of PoW seeds for `name` under `ownerNodeId`
/// (32 bytes), continuing from `priorSeeds` (concatenated 32-byte seeds).
/// The call computes at most `maxHashes` hashes, so chunk sizes directly
/// bound UI-progress latency. CPU-bound — run inside `Isolate.run`.
NicknameMineOutcome mineNicknameChunk({
  required String name,
  required Uint8List ownerNodeId,
  required int targetWeight,
  required int maxHashes,
  Uint8List? priorSeeds,
}) {
  if (ownerNodeId.length != 32) {
    throw VeilException('ownerNodeId must be 32 bytes');
  }
  final prior = priorSeeds ?? Uint8List(0);
  if (prior.length % 32 != 0) {
    throw VeilException('priorSeeds length must be a multiple of 32');
  }
  final nameC = name.toNativeUtf8();
  final ownerC = calloc<Uint8>(32);
  final priorC = prior.isEmpty ? nullptr : calloc<Uint8>(prior.length);
  final outBuf = calloc<Pointer<Uint8>>();
  final outLen = calloc<IntPtr>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    ownerC.asTypedList(32).setAll(0, ownerNodeId);
    if (prior.isNotEmpty) {
      priorC.asTypedList(prior.length).setAll(0, prior);
    }
    final rc = ffi.veilNicknameMine(
      nameC.cast(),
      nameC.length,
      ownerC,
      priorC,
      prior.length,
      targetWeight,
      maxHashes,
      outBuf,
      outLen,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException(_takeErr(errOut, rc), code: rc);
    }
    final raw = Uint8List.fromList(outBuf.value.asTypedList(outLen.value));
    ffi.veilFreeBuf(outBuf.value, outLen.value);
    // hit_target:u8 | weight:u64 LE | hashes:u64 LE | count:u32 LE | seeds.
    final bd = ByteData.sublistView(raw);
    final hitTarget = raw[0] != 0;
    final weight = bd.getUint64(1, Endian.little);
    final hashes = bd.getUint64(9, Endian.little);
    final count = bd.getUint32(17, Endian.little);
    final seeds = Uint8List.sublistView(raw, 21, 21 + count * 32);
    return NicknameMineOutcome(
      hitTarget: hitTarget,
      weight: weight,
      hashesDone: hashes,
      seeds: Uint8List.fromList(seeds),
    );
  } finally {
    calloc.free(nameC);
    calloc.free(ownerC);
    if (priorC != nullptr) calloc.free(priorC);
    calloc.free(outBuf);
    calloc.free(outLen);
    calloc.free(errOut);
  }
}

/// Sign an already-mined seed set with the sovereign key of the embedded
/// node running as `ownerNodeId` and publish the nickname record to the
/// DHT. Returns the published cumulative weight. Throws [VeilException]
/// with the node-side reason on failure (weight under the per-length
/// floor, name taken with weight W — mine strictly more, multi-device
/// subkey, no embedded node). Blocking — call through `Isolate.run`.
int claimNickname({
  required Uint8List ownerNodeId,
  required String name,
  required Uint8List seeds,
  int timeoutMs = 0,
}) {
  if (ownerNodeId.length != 32) {
    throw VeilException('ownerNodeId must be 32 bytes');
  }
  if (seeds.length % 32 != 0) {
    throw VeilException('seeds length must be a multiple of 32');
  }
  final nameC = name.toNativeUtf8();
  final ownerC = calloc<Uint8>(32);
  final seedsC = seeds.isEmpty ? nullptr : calloc<Uint8>(seeds.length);
  final outWeight = calloc<Uint64>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    ownerC.asTypedList(32).setAll(0, ownerNodeId);
    if (seeds.isNotEmpty) {
      seedsC.asTypedList(seeds.length).setAll(0, seeds);
    }
    final rc = ffi.veilNicknameClaim(
      ownerC,
      nameC.cast(),
      nameC.length,
      seedsC,
      seeds.length,
      timeoutMs,
      outWeight,
      errOut,
    );
    if (rc != ffi.veilOk) {
      throw VeilException(_takeErr(errOut, rc), code: rc);
    }
    return outWeight.value;
  } finally {
    calloc.free(nameC);
    calloc.free(ownerC);
    if (seedsC != nullptr) calloc.free(seedsC);
    calloc.free(outWeight);
    calloc.free(errOut);
  }
}

/// Resolve the current owner of a nickname via the embedded node running
/// as `selfNodeId`. Returns `null` when the name has no valid owner
/// (available). Throws [VeilException] on error (no embedded node, bad
/// name). Blocking — call through `Isolate.run`.
ResolvedNickname? resolveNickname({
  required Uint8List selfNodeId,
  required String name,
  int timeoutMs = 0,
}) {
  if (selfNodeId.length != 32) {
    throw VeilException('selfNodeId must be 32 bytes');
  }
  final nameC = name.toNativeUtf8();
  final selfC = calloc<Uint8>(32);
  final outOwner = calloc<Uint8>(32);
  final outWeight = calloc<Uint64>();
  final outIssued = calloc<Uint64>();
  final errOut = calloc<Pointer<Utf8>>();
  try {
    selfC.asTypedList(32).setAll(0, selfNodeId);
    final rc = ffi.veilNicknameResolve(
      selfC,
      nameC.cast(),
      nameC.length,
      timeoutMs,
      outOwner,
      outWeight,
      outIssued,
      errOut,
    );
    if (rc == ffi.veilNicknameFree) return null;
    if (rc != ffi.veilOk) {
      throw VeilException(_takeErr(errOut, rc), code: rc);
    }
    return ResolvedNickname(
      ownerNodeId: Uint8List.fromList(outOwner.asTypedList(32)),
      weight: outWeight.value,
      issuedAtUnix: outIssued.value,
    );
  } finally {
    calloc.free(nameC);
    calloc.free(selfC);
    calloc.free(outOwner);
    calloc.free(outWeight);
    calloc.free(outIssued);
    calloc.free(errOut);
  }
}
