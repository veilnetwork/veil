import 'dart:typed_data';

import 'bindings.dart' as ffi;

/// Mobile background tier — mirrors `veil_proto::MobileBackgroundMode`.
enum MobileBackgroundMode {
  foreground(ffi.veilBgForeground),
  active(ffi.veilBgActive),
  lowPower(ffi.veilBgLowPower);

  const MobileBackgroundMode(this.wireByte);
  final int wireByte;
}

/// Local network attachment kind — mirrors `veil_proto::NetworkKind`.
enum NetworkKind {
  offline(ffi.veilNetOffline),
  wifi(ffi.veilNetWifi),
  cellular(ffi.veilNetCellular),
  ethernet(ffi.veilNetEthernet),
  unknown(ffi.veilNetUnknown);

  const NetworkKind(this.wireByte);
  final int wireByte;
}

/// Push event kind — mirrors `veil_proto::event_kind`.
///
/// Forward-compat: a daemon emitting a kind we don't recognise yields
/// [VeilEventKind.unknown] и the raw byte is preserved on
/// [VeilEvent.rawKind] for forensic display.
enum VeilEventKind {
  sessionsChanged(ffi.veilEventSessionsChanged),
  mobileTierChanged(ffi.veilEventMobileTierChanged),
  identityRotated(ffi.veilEventIdentityRotated),
  /// Mailbox fetch (drain) completed.  Carries а 4-byte BE blob-count.
  /// Background-handler consumers (iOS BGProcessingTask, Android
  /// background workers) subscribe to this so they can `setTaskCompleted`
  /// precisely when the daemon is done draining rather than padding к
  /// а hardcoded timeout.  See [VeilEvent.drainedCount] helper.
  mailboxDrained(ffi.veilEventMailboxDrained),
  unknown(-1);

  const VeilEventKind(this.wireByte);
  final int wireByte;

  static VeilEventKind fromWire(int b) {
    for (final k in values) {
      if (k.wireByte == b) return k;
    }
    return VeilEventKind.unknown;
  }
}

/// One push event delivered by the daemon.  [payload] layout depends on
/// [kind] — see `veil_proto::event_kind` module docs:
///   - [VeilEventKind.sessionsChanged] → `[u16 BE active_session_count]`
///   - [VeilEventKind.mobileTierChanged] → `[u8 tier]`
///   - [VeilEventKind.identityRotated] → `[u8; 32] new_node_id`
class VeilEvent {
  const VeilEvent({required this.kind, required this.rawKind, required this.payload});

  final VeilEventKind kind;

  /// Raw kind byte from the wire — useful when [kind] is
  /// [VeilEventKind.unknown] so the consumer can still log/forward.
  final int rawKind;

  final Uint8List payload;

  /// Convenience: decode `SESSIONS_CHANGED` payload as a `u16 BE`
  /// session count.  Returns `null` if [kind] is not
  /// [VeilEventKind.sessionsChanged] or the payload is malformed.
  int? get sessionCount {
    if (kind != VeilEventKind.sessionsChanged || payload.length < 2) {
      return null;
    }
    return (payload[0] << 8) | payload[1];
  }

  /// Convenience: decode `MOBILE_TIER_CHANGED` payload as a tier byte.
  /// Returns `null` if mismatched.
  MobileBackgroundMode? get tierAfterChange {
    if (kind != VeilEventKind.mobileTierChanged || payload.isEmpty) {
      return null;
    }
    final byte = payload[0];
    for (final m in MobileBackgroundMode.values) {
      if (m.wireByte == byte) return m;
    }
    return null;
  }

  /// Convenience: decode `MAILBOX_DRAINED` payload as а `u32 BE` blob
  /// count (number of blobs delivered by the just-completed mailbox
  /// fetch).  Returns `null` if [kind] is not
  /// [VeilEventKind.mailboxDrained] или the payload is malformed.
  ///
  /// Background-handlers typically await this event с а timeout (e.g.,
  /// iOS BGProcessingTask's ~30 s budget): event arrives → call
  /// `setTaskCompleted(success: true)`; budget expires → fall back.
  int? get drainedCount {
    if (kind != VeilEventKind.mailboxDrained || payload.length < 4) {
      return null;
    }
    return (payload[0] << 24)
        | (payload[1] << 16)
        | (payload[2] << 8)
        | payload[3];
  }

  @override
  String toString() => 'VeilEvent(kind=$kind, rawKind=$rawKind, payloadLen=${payload.length})';
}

/// Status return from a mailbox PUT operation.  Mirrors
/// `veil_proto::MailboxPutStatus` on the wire (bytes 0..8).
///
/// Values ≥ [stored] represent а structured outcome from the daemon;
/// negative codes (transport / argument errors) are surfaced through
/// [VeilException].
enum MailboxPutStatus {
  /// Blob accepted и stored.  [MailboxPutResult.evicted] may indicate
  /// older blobs the relay dropped to fit.
  stored(ffi.veilMailboxPutStored),

  /// Same `(receiver_id, content_id)` is already present — no-op,
  /// caller can treat as success.
  duplicate(ffi.veilMailboxPutDuplicate),

  /// Receiver's per-receiver byte quota would be exceeded.
  quotaPerReceiver(ffi.veilMailboxPutQuotaPerReceiver),

  /// Relay's global byte quota is full.
  quotaGlobal(ffi.veilMailboxPutQuotaGlobal),

  /// Per-source rate limit triggered.
  rateLimited(ffi.veilMailboxPutRateLimited),

  /// Targeted node is not configured as а mailbox relay.
  notRelay(ffi.veilMailboxPutNotRelay),

  /// Relay requires capability tokens но this PUT had none.  Caller
  /// should re-fetch the receiver's RendezvousAd, extract the
  /// per-replica `capability_token`, и retry с it.
  capabilityRequired(ffi.veilMailboxPutCapabilityRequired),

  /// Supplied capability token decoded but failed verification
  /// (expired, wrong receiver, bad signature, или wrong relay binding
  /// for the targeted replica).
  capabilityInvalid(ffi.veilMailboxPutCapabilityInvalid),

  /// Per-sender byte cap exceeded на the relay (`sender_id` пишет
  /// больше своей доли).
  quotaPerSender(ffi.veilMailboxPutQuotaPerSender),

  /// Forward-compat: daemon returned а status byte we don't recognise.
  unknown(-1);

  const MailboxPutStatus(this.wireByte);
  final int wireByte;

  /// Map а wire byte from the FFI surface back to an enum value.
  /// Unrecognised bytes yield [MailboxPutStatus.unknown] — the consumer
  /// can still inspect the raw byte through whatever logged it.
  static MailboxPutStatus fromWire(int b) {
    for (final s in values) {
      if (s.wireByte == b) return s;
    }
    return MailboxPutStatus.unknown;
  }
}

/// Result of а mailbox PUT operation.
class MailboxPutResult {
  const MailboxPutResult({required this.status, required this.evicted});

  /// Structured daemon outcome.
  final MailboxPutStatus status;

  /// On [MailboxPutStatus.stored], count of older blobs the relay had
  /// к evict к fit this one.  Zero on other statuses.
  final int evicted;

  @override
  String toString() => 'MailboxPutResult(status=$status, evicted=$evicted)';
}

/// One blob fetched from the daemon's local mailbox.
class MailboxBlob {
  const MailboxBlob({
    required this.senderId,
    required this.contentId,
    required this.depositedAt,
    required this.data,
  });

  /// 32-byte BLAKE3 of the depositing node's signing pubkey.
  final Uint8List senderId;

  /// 32-byte content identifier (typically BLAKE3 of the blob body).
  final Uint8List contentId;

  /// Unix-seconds timestamp the relay stamped at deposit time.
  final int depositedAt;

  /// Encrypted application payload — the receiver decrypts using its
  /// own keys (veil-mailbox does NOT decrypt at the relay layer).
  final Uint8List data;
}

/// One rendezvous replica advertised for а receiver (push wake-HMAC
/// end-to-end).  Returned by [VeilMailbox.lookupRendezvousReplicas];
/// senders use it to deposit а blob via [VeilMailbox.put] together
/// with the matching [pushEnvelope] / [capabilityToken] /
/// [wakeHmacEnvelope] so the relay can fire an authenticated wake-push.
class RendezvousReplica {
  const RendezvousReplica({
    required this.relayNodeId,
    required this.validUntilUnix,
    required this.pushEnvelope,
    required this.capabilityToken,
    required this.wakeHmacEnvelope,
  });

  /// 32-byte node_id of the relay hosting this replica.
  final Uint8List relayNodeId;

  /// Unix-seconds expiry — the replica entry is stale past this point
  /// и senders should re-look-up rather than deposit against it.
  final int validUntilUnix;

  /// Sealed FCM/APNs push envelope (opaque to the sender); pass через
  /// to [VeilMailbox.put]'s `pushEnvelope`.  Empty when the receiver
  /// published no push envelope for this replica.
  final Uint8List pushEnvelope;

  /// Receiver-signed capability token for this replica; pass через to
  /// [VeilMailbox.put]'s `capabilityToken`.  Empty when the replica's
  /// relay does not require capability tokens.
  final Uint8List capabilityToken;

  /// Sealed wake-HMAC envelope (opaque to the sender); pass через to
  /// [VeilMailbox.put]'s `wakeHmacEnvelope`.  Empty when the receiver
  /// published no wake-HMAC envelope for this replica.
  final Uint8List wakeHmacEnvelope;

  @override
  String toString() =>
      'RendezvousReplica(relayNodeId=<${relayNodeId.length}B>, '
      'validUntilUnix=$validUntilUnix, pushLen=${pushEnvelope.length}, '
      'capLen=${capabilityToken.length}, wakeLen=${wakeHmacEnvelope.length})';
}

/// Result wire byte from а bootstrap-invite consume (Epic 489.7).
/// Mirrors `veil_proto::JoinBootstrapStatus`.
enum JoinBootstrapStatus {
  /// Invite accepted, peer is now registered for outbound dial.
  ok(ffi.veilJoinOk),

  /// URI failed plain / encrypted / signed decoding.  Could be typo
  /// or wrong invite-protocol version (e.g. ancient invite from а
  /// pre-v3 daemon).
  invalidUri(ffi.veilJoinInvalidUri),

  /// Invite is encrypted but caller passed no passphrase.  UI should
  /// prompt и retry с the user-supplied secret.
  passwordRequired(ffi.veilJoinPasswordRequired),

  /// Caller supplied а passphrase that failed Argon2id verify.  UI
  /// should re-prompt — wrong passphrases ара indistinguishable from
  /// "expired key", so guidance should suggest checking case / spaces.
  passwordWrong(ffi.veilJoinPasswordWrong),

  /// Invite was signed но the signature didn't verify against the
  /// `expectedIssuerPk` (или the invite was tampered).  Refusal-к-pair
  /// — do NOT prompt the user к "try again" с the same URI.
  signatureInvalid(ffi.veilJoinSignatureInvalid),

  /// Daemon-side I/O или RPC failure — typically transient.  UI can
  /// suggest "check connection и retry".
  internalError(ffi.veilJoinInternalError),

  /// Peer was already registered before this call (idempotent re-pair).
  /// Treat as success in most UIs — the `node_id` field is still
  /// populated correctly.
  alreadyRegistered(ffi.veilJoinAlreadyRegistered),

  /// Forward-compat: daemon returned а status byte we don't recognise.
  unknown(-1);

  const JoinBootstrapStatus(this.wireByte);
  final int wireByte;

  static JoinBootstrapStatus fromWire(int b) {
    for (final s in values) {
      if (s.wireByte == b) return s;
    }
    return JoinBootstrapStatus.unknown;
  }
}

/// Status return from [VeilClient.createBootstrapInvite] (Epic
/// 489.7 generator side).  Mirrors `veil_proto::create_invite_status`.
enum CreateBootstrapInviteStatus {
  /// Invite assembled и encoded.  [CreateBootstrapInviteResult.uri] is
  /// populated.
  ok(ffi.veilCreateInviteOk),

  /// Daemon's config has no `[identity]` или no `[[listen]]` entry.
  /// Detail names which.  Surface as а setup-required nudge in the
  /// UI ("run identity create first").
  notConfigured(ffi.veilCreateInviteNotConfigured),

  /// Caller-supplied password failed validation (empty / oversized).
  /// UI should re-prompt с а strength hint.
  badPassword(ffi.veilCreateInviteBadPassword),

  /// Daemon-internal failure (encode error, hybrid identity на encrypted
  /// path, …).  Surface as а transient retry suggestion.
  internalError(ffi.veilCreateInviteInternalError),

  /// Forward-compat: daemon returned а status byte we don't recognise.
  unknown(-1);

  const CreateBootstrapInviteStatus(this.wireByte);
  final int wireByte;

  static CreateBootstrapInviteStatus fromWire(int b) {
    for (final s in values) {
      if (s.wireByte == b) return s;
    }
    return CreateBootstrapInviteStatus.unknown;
  }
}

/// Outcome of [VeilClient.createBootstrapInvite].
class CreateBootstrapInviteResult {
  const CreateBootstrapInviteResult({
    required this.status,
    required this.uri,
    this.detail,
  });

  /// Structured daemon outcome.
  final CreateBootstrapInviteStatus status;

  /// Encoded invite URI on success (empty on any non-OK status).
  final String uri;

  /// Human-readable detail (best-effort UTF-8); typically empty on
  /// success, populated with daemon's diagnostic text on errors.
  final String? detail;

  @override
  String toString() => 'CreateBootstrapInviteResult(status=$status, '
      'uriLen=${uri.length}, detail=${detail ?? "<none>"})';
}

/// Status return от Source-side multi-device pairing ops
/// (Epic 489.8).  Mirrors `veil_proto::pair_source_status`.
enum PairSourceStatus {
  /// Operation succeeded.
  ok(ffi.veilPairSourceOk),

  /// Daemon has no sovereign identity OR caller did not supply
  /// а master_password to decrypt `master.enc`.  Detail names which.
  notConfigured(ffi.veilPairSourceNotConfigured),

  /// А Source ceremony is already в progress; cancel it OR wait for
  /// timeout before issuing а new `createInvite`.
  alreadyInProgress(ffi.veilPairSourceAlreadyInProgress),

  /// Daemon-internal failure (encode error, master.enc decrypt fail,
  /// I/O error on persist, …).
  internalError(ffi.veilPairSourceInternalError),

  /// Ceremony state mismatch — e.g. `handleHello` без prior
  /// `createInvite`, или `handleConfirm` без prior `handleHello`.
  wrongState(ffi.veilPairSourceWrongState),

  /// `handleHello`: Target's Hello payload failed MAC / pair_secret
  /// correlation (most common cause: stale QR scan).
  badHello(ffi.veilPairSourceBadHello),

  /// `handleConfirm`: Target reported user aborted (codes didn't
  /// match).  Caller MUST drop the in-progress IdentityKey.
  userAborted(ffi.veilPairSourceUserAborted),

  /// `handleConfirm`: Confirm proof failed verification.
  badConfirm(ffi.veilPairSourceBadConfirm),

  /// Forward-compat: daemon returned а status byte we don't recognise.
  unknown(-1);

  const PairSourceStatus(this.wireByte);
  final int wireByte;

  static PairSourceStatus fromWire(int b) {
    for (final s in values) {
      if (s.wireByte == b) return s;
    }
    return PairSourceStatus.unknown;
  }
}

/// Status return от Target-side ops (Epic 489.8).  Mirrors
/// `veil_proto::pair_target_status`.
enum PairTargetStatus {
  ok(ffi.veilPairTargetOk),
  badUri(ffi.veilPairTargetBadUri),
  expired(ffi.veilPairTargetExpired),
  alreadyInProgress(ffi.veilPairTargetAlreadyInProgress),
  badCert(ffi.veilPairTargetBadCert),
  wrongState(ffi.veilPairTargetWrongState),
  internalError(ffi.veilPairTargetInternalError),
  unknown(-1);

  const PairTargetStatus(this.wireByte);
  final int wireByte;

  static PairTargetStatus fromWire(int b) {
    for (final s in values) {
      if (s.wireByte == b) return s;
    }
    return PairTargetStatus.unknown;
  }
}

/// Result of [VeilClient.pairSourceCreateInvite].
class PairCreateInviteResult {
  const PairCreateInviteResult({
    required this.status,
    required this.uri,
    this.detail,
  });
  final PairSourceStatus status;

  /// Pairing URI к QR-encode + show к target user.  Empty на error.
  final String uri;

  /// Daemon-side advisory message (e.g. "ttl expired", "master.enc
  /// not found").
  final String? detail;
}

/// Result for `handleHello` / `handleCert` ops — carries OOB code +
/// optional response bytes (Source.handleHello returns Cert;
/// Target.handleCert returns no response bytes — only OOB).
class PairOobResult {
  const PairOobResult({
    required this.statusByte,
    required this.oobCode,
    required this.responseBytes,
    this.detail,
  });

  /// Raw wire byte — каллер decodes к `PairSourceStatus` (for source
  /// ops) или `PairTargetStatus` (for target ops).
  final int statusByte;

  /// 6-character ASCII OOB code (empty string на error).  User
  /// visually compares against the peer's screen.
  final String oobCode;

  /// Source.handleHello → Cert bytes; Target.handleCert → empty.
  final Uint8List responseBytes;

  final String? detail;
}

/// Status-only reply (Source.handleConfirm).
class PairStatusResult {
  const PairStatusResult({
    required this.status,
    this.detail,
  });
  final PairSourceStatus status;
  final String? detail;
}

/// Result carrying status + opaque bytes (Target.consumeUri →
/// Hello; Target.buildConfirm → Confirm).
class PairFrameResult {
  const PairFrameResult({
    required this.status,
    required this.bytes,
    this.detail,
  });
  final PairTargetStatus status;
  final Uint8List bytes;
  final String? detail;
}

/// Outcome of [VeilClient.joinBootstrapUri].
class JoinBootstrapResult {
  const JoinBootstrapResult({
    required this.status,
    required this.peerNodeId,
    this.detail,
  });

  /// Structured daemon outcome.
  final JoinBootstrapStatus status;

  /// 32-byte BLAKE3 hash of the new peer's signing pubkey.  Zero-filled
  /// when [status] is а terminal failure (invalidUri / signatureInvalid /
  /// internalError) — daemon couldn't extract а node_id from а
  /// failed-decode invite.
  final Uint8List peerNodeId;

  /// Free-form daemon-side message — typically empty on success, fills
  /// с decode-error details on failure (e.g. "version 1 invite, daemon
  /// supports v3+").
  final String? detail;

  @override
  String toString() =>
      'JoinBootstrapResult(status=$status, peerNodeId=<${peerNodeId.length}B>, '
      'detail=${detail ?? "<none>"})';
}

/// Inbound datagram delivered to a bound [AppHandle].
class IncomingMessage {
  const IncomingMessage({
    required this.srcNodeId,
    required this.srcAppId,
    required this.data,
  });

  /// 32-byte BLAKE3 hash of the originating node's signing pubkey.
  final Uint8List srcNodeId;

  /// 32-byte deterministic identifier of the originating endpoint.
  final Uint8List srcAppId;

  /// Application payload bytes.
  final Uint8List data;
}

/// Exception raised from the high-level Dart API on FFI failures.
class VeilException implements Exception {
  VeilException(this.message, {this.code = ffi.veilErr});
  final String message;
  final int code;

  @override
  String toString() => 'VeilException(code=$code): $message';
}

/// Outcome of [VeilPush.verifyWakePayload] (Epic 489.10 slice 4.3.3).
///
/// Distinct values для each failure mode so receivers can surface
/// each differently — operators care about clock-skew rate as а
/// separate metric от active forging attempts.
///
/// Receiver's `handleWakeup` flow:
///   * [valid] — proceed к drain mailbox + foreground promotion.
///   * [tamperedOrForged] / [expired] / [malformedLength] — silent
///     no-op (defeats presence oracle); optionally log metric.
///   * [unknown] — forward-compat fallback for future verdict values.
enum WakePayloadVerdict {
  valid(ffi.veilWakeVerdictValid),
  tamperedOrForged(ffi.veilWakeVerdictTampered),
  expired(ffi.veilWakeVerdictExpired),
  malformedLength(ffi.veilWakeVerdictMalformed),
  /// Forward-compat: FFI returned а verdict byte the Dart binding
  /// does not recognise.  Should be treated as а silent failure
  /// (do not drain).
  unknown(-1);

  const WakePayloadVerdict(this.wireByte);
  final int wireByte;

  static WakePayloadVerdict fromWire(int b) {
    for (final v in values) {
      if (v.wireByte == b) return v;
    }
    return WakePayloadVerdict.unknown;
  }
}
