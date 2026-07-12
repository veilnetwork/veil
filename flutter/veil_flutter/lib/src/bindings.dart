// Raw FFI bindings to veilclient-ffi (C ABI, hand-written).
//
// Mirrors `crates/veilclient-ffi/src/lib.rs` — keep in lockstep when the
// C surface evolves.  Higher-level Dart wrappers in `client.dart` build on
// these typedefs and avoid surfacing raw `Pointer<…>` types to consumers.

import 'dart:ffi';

import 'package:ffi/ffi.dart' show Utf8, Utf8Pointer;

import 'native.dart';

// ── Status codes ─────────────────────────────────────────────────────────────

const int veilOk = 0;
const int veilErr = -1;
const int veilErrInvalidArg = -2;
const int veilErrClosed = -3;
const int veilErrReentrant = -4;

/// Per-call payload cap shared by datagram + stream write/read primitives.
/// Mirrors `VEIL_MAX_DATA_LEN` in `crates/veilclient-ffi/src/lib.rs`.
const int veilMaxDataLen = 16 * 1024 * 1024;

// ── Network kind enum (veil_proto::NetworkKind wire bytes) ────────────────

const int veilNetOffline = 0;
const int veilNetWifi = 1;
const int veilNetCellular = 2;
const int veilNetEthernet = 3;
const int veilNetUnknown = 255;

// ── Mobile background tier (MobileBackgroundMode wire bytes) ─────────────────

const int veilBgForeground = 0;
const int veilBgActive = 1;
const int veilBgLowPower = 2;

// ── Push-event kind constants (mirror veil_proto::event_kind) ─────────────

const int veilEventSessionsChanged = 0;
const int veilEventMobileTierChanged = 1;
const int veilEventIdentityRotated = 2;
const int veilEventMailboxDrained = 3;
const int veilEventMailboxWake = 5;

// ── Wake-HMAC constants + verdict codes (Epic 489.10 slice 4.3.3) ────────────

const int veilWakeVerdictValid = 0;
const int veilWakeVerdictTampered = 1;
const int veilWakeVerdictExpired = 2;
const int veilWakeVerdictMalformed = 3;
const int veilWakeHmacKeyLen = 32;
const int veilWakePayloadLen = 72;

// ── Opaque pointer types ─────────────────────────────────────────────────────

final class VeilHandle extends Opaque {}

final class VeilApp extends Opaque {}

final class VeilStreamFfi extends Opaque {}

final class VeilSovereignSigner extends Opaque {}

// ── Callback typedefs ────────────────────────────────────────────────────────

typedef VeilRecvCbNative = Void Function(
  Pointer<Void> user,
  Pointer<Uint8> srcNodeId,
  Pointer<Uint8> srcAppId,
  Uint64 replyId,
  Pointer<Uint8> data,
  IntPtr len,
);
typedef VeilRecvCb = void Function(
  Pointer<Void> user,
  Pointer<Uint8> srcNodeId,
  Pointer<Uint8> srcAppId,
  int replyId,
  Pointer<Uint8> data,
  int len,
);

typedef VeilEventCbNative = Void Function(
  Pointer<Void> user,
  Uint8 kind,
  Pointer<Uint8> payload,
  IntPtr payloadLen,
);
typedef VeilEventCb = void Function(
  Pointer<Void> user,
  int kind,
  Pointer<Uint8> payload,
  int payloadLen,
);

// Per-peer iteration callback for `veil_peers_list`. Invoked synchronously,
// once per peer, for the duration of the call only — copy out anything kept.
// node_id is 32 bytes; state/direction are wire bytes (VEIL_PEER_STATE_* /
// VEIL_PEER_DIR_*); transport is a UTF-8 URI (NOT NUL-terminated; use len).
typedef VeilPeerCbNative = Void Function(
  Pointer<Void> user,
  Pointer<Uint8> nodeId,
  Uint8 state,
  Uint8 direction,
  Pointer<Uint8> transport,
  IntPtr transportLen,
);
typedef VeilPeerCb = void Function(
  Pointer<Void> user,
  Pointer<Uint8> nodeId,
  int state,
  int direction,
  Pointer<Uint8> transport,
  int transportLen,
);

// Wire-byte session-state values for VeilPeerCb.state (mirrors veil_ffi.h).
const int veilPeerStateConnecting = 0;
const int veilPeerStateActive = 1;
const int veilPeerStateClosed = 2;
const int veilPeerStateUnknown = 255;

// Wire-byte direction values for VeilPeerCb.direction.
const int veilPeerDirInbound = 0;
const int veilPeerDirOutbound = 1;

// ── C-function lookups ───────────────────────────────────────────────────────

final void Function(Pointer<Utf8>) veilFreeString = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>('veil_free_string')
    .asFunction();

// Explicit-length text ABI: native takes (ptr, len); the Dart wrapper keeps a
// `Pointer<Utf8>` arg (from `toNativeUtf8()`) and forwards its byte pointer +
// `.length` so call sites are unchanged. (Utf8 `.length` is strlen — excludes
// the NUL — which is exactly the content byte count the native side reads.)
final Pointer<VeilHandle> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)
    _connectNative = nativeLib
        .lookup<
            NativeFunction<
                Pointer<VeilHandle> Function(
                  Pointer<Uint8>,
                  IntPtr,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_connect')
        .asFunction();

Pointer<VeilHandle> veilConnect(
  Pointer<Utf8> socketPath,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _connectNative(socketPath.cast<Uint8>(), socketPath.length, errOut);

final void Function(Pointer<VeilHandle>) veilClose = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<VeilHandle>)>>(
      'veil_close',
    )
    .asFunction();

final Pointer<VeilApp> Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Pointer<Utf8>>,
) _bindNative = nativeLib
    .lookup<
        NativeFunction<
            Pointer<VeilApp> Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Uint32,
              Pointer<Pointer<Utf8>>,
            )>>('veil_bind')
    .asFunction();

Pointer<VeilApp> veilBind(
  Pointer<VeilHandle> handle,
  Pointer<Utf8> namespace,
  Pointer<Utf8> name,
  int endpointId,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _bindNative(handle, namespace.cast<Uint8>(), namespace.length,
        name.cast<Uint8>(), name.length, endpointId, errOut);

final Pointer<VeilApp> Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Pointer<Utf8>>,
) _bindNamedNative = nativeLib
    .lookup<
        NativeFunction<
            Pointer<VeilApp> Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Uint32,
              Pointer<Pointer<Utf8>>,
            )>>('veil_bind_named')
    .asFunction();

Pointer<VeilApp> veilBindNamed(
  Pointer<VeilHandle> handle,
  Pointer<Utf8> namespace,
  Pointer<Utf8> name,
  int endpointId,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _bindNamedNative(handle, namespace.cast<Uint8>(), namespace.length,
        name.cast<Uint8>(), name.length, endpointId, errOut);

final int Function(Pointer<VeilApp>, Pointer<Uint8>) veilAppGetAppId = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
            )>>('veil_app_get_app_id')
    .asFunction();

final int Function(Pointer<VeilApp>) veilAppGetEndpointId = nativeLib
    .lookup<NativeFunction<Uint32 Function(Pointer<VeilApp>)>>(
      'veil_app_get_endpoint_id',
    )
    .asFunction();

final void Function(Pointer<VeilApp>) veilAppClose = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<VeilApp>)>>(
      'veil_app_close',
    )
    .asFunction();

final int Function(
  Pointer<VeilApp>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSend = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send')
    .asFunction();

final int Function(
  Pointer<VeilApp>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSendAnonymousAuthenticated = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_anonymous_authenticated')
    .asFunction();

final int Function(
  Pointer<VeilApp>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSendAnonymousAuthenticatedWithReply = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_anonymous_authenticated_with_reply')
    .asFunction();

/// Like [veilSendAnonymousAuthenticatedWithReply], but with an explicit relay
/// KEM key (`dstX25519Pk`, 32 bytes) so the daemon routes straight to the relay
/// with NO rendezvous-ad self-resolve. The KEM-key-given mailbox FETCH.
final int Function(
  Pointer<VeilApp>,
  Pointer<Uint8>, // dstNodeId
  Pointer<Uint8>, // dstX25519Pk
  Pointer<Uint8>, // dstAppId
  int, // dstEndpointId
  int, // replyEndpointId
  Pointer<Uint8>, // data
  int, // len
  Pointer<Pointer<Utf8>>, // errOut
) veilSendAnonymousAuthenticatedDirectWithReply = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_anonymous_authenticated_direct_with_reply')
    .asFunction();

final int Function(
  Pointer<VeilApp>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSendReply = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Uint64,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_reply')
    .asFunction();

final int Function(
  Pointer<VeilApp>,
  Pointer<NativeFunction<VeilRecvCbNative>>,
  Pointer<Void>,
  Pointer<Pointer<Utf8>>,
) veilAppSetRecvHandler = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilApp>,
              Pointer<NativeFunction<VeilRecvCbNative>>,
              Pointer<Void>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_app_set_recv_handler')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<NativeFunction<VeilEventCbNative>>,
  Pointer<Void>,
  Pointer<Pointer<Utf8>>,
) veilSetEventHandler = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<NativeFunction<VeilEventCbNative>>,
              Pointer<Void>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_set_event_handler')
    .asFunction();

final int Function(Pointer<VeilHandle>, Pointer<Uint8>, Pointer<Pointer<Utf8>>)
    veilGetNodeId = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilHandle>,
                  Pointer<Uint8>,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_get_node_id')
        .asFunction();

/// Snapshot the daemon's peer sessions. Calls [cb] once per peer (bounded at
/// 256 entries server-side). Returns [veilOk] or a negative error code.
final int Function(Pointer<VeilHandle>,
        Pointer<NativeFunction<VeilPeerCbNative>>, Pointer<Void>, Pointer<Pointer<Utf8>>)
    veilPeersList = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilHandle>,
                  Pointer<NativeFunction<VeilPeerCbNative>>,
                  Pointer<Void>,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_peers_list')
        .asFunction();

/// Daemon is not relay-capable — `veil_get_relay_x25519_pubkey` returns this
/// (mirrors `VEIL_RELAY_X25519_UNAVAILABLE` in veilclient-ffi).
const int veilRelayX25519Unavailable = -10;

/// Read the daemon's relay-side X25519 public key (32 bytes) into the
/// out-buffer. Returns `veilOk` when populated, or
/// `veilRelayX25519Unavailable` when the daemon is not relay-capable.
final int Function(Pointer<VeilHandle>, Pointer<Uint8>, Pointer<Pointer<Utf8>>)
    veilGetRelayX25519Pubkey = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilHandle>,
                  Pointer<Uint8>,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_get_relay_x25519_pubkey')
        .asFunction();

/// Resolve ANOTHER node's relay X25519 public key by node_id over the DHT
/// (node_id in, 32-byte key out). Returns `veilOk` when populated, or
/// `veilRelayX25519Unavailable` when unresolved.
final int Function(Pointer<VeilHandle>,
        Pointer<Uint8>, Pointer<Uint8>, Pointer<Pointer<Utf8>>)
    veilLookupRelayX25519 = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilHandle>,
                  Pointer<Uint8>,
                  Pointer<Uint8>,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_lookup_relay_x25519')
        .asFunction();

final int Function(Pointer<VeilHandle>, int, Pointer<Pointer<Utf8>>)
    veilRegisterOnionService = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilHandle>,
                  Uint32,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_register_onion_service')
        .asFunction();

/// Register a blinded onion service under a caller-owned random Ed25519 seed.
/// The native function ZEROIZES the writable 32-byte seed buffer and writes the
/// corresponding public service identity to the 32-byte out buffer.
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilRegisterEphemeralOnionServiceZeroize = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_register_ephemeral_onion_service_zeroize')
    .asFunction();

/// Idempotently stop maintaining one ephemeral onion service by its public key.
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilWithdrawEphemeralOnionService = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_withdraw_ephemeral_onion_service')
    .asFunction();

/// Register a plain rendezvous-publisher entry advertising the relay KEM key
/// (mailbox-by-discovery). Args: handle, rendezvous_node_id(32B), auth_cookie
/// (16B), validity_window_secs(u64), relay_kem_algo(u8), relay_kem_pk(ptr),
/// kem_len, err_out. Returns `veilOk` once the daemon records the entry.
final int Function(Pointer<VeilHandle>, Pointer<Uint8>, Pointer<Uint8>, int,
        int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)
    veilRegisterRendezvousPublisher = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilHandle>,
                  Pointer<Uint8>,
                  Pointer<Uint8>,
                  Uint64,
                  Uint8,
                  Pointer<Uint8>,
                  IntPtr,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_register_rendezvous_publisher')
        .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSendToOnionService = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_to_onion_service')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSendToOnionServiceAnonymous = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_to_onion_service_anonymous')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSendAnonymousDirect = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_send_anonymous_direct')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSetBackgroundMode = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Int32,
              Pointer<Pointer<Utf8>>,
            )>>('veil_set_background_mode')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  int,
  int,
  Pointer<Pointer<Utf8>>,
) veilNotifyNetworkChanged = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Int32,
              Uint16,
              Pointer<Pointer<Utf8>>,
            )>>('veil_notify_network_changed')
    .asFunction();

// ── Identity restore (Epic 489.8) ──────────────────────────────────────────

// Explicit-length text ABI: native takes (ptr, len). The Dart wrappers keep
// `Pointer<Utf8>` args (from `toNativeUtf8()`) and forward each buffer's byte
// pointer + `.length`. The non-zeroize `veil_validate_bip39_phrase` /
// `veil_restore_identity_from_phrase` were removed — these zeroize variants
// (caller-writable buffer wiped in place before return, success and error
// paths both) are the only entry points.
// Fresh 24-word master phrase (onboarding). Out-string is malloc'd by the
// native side — copy immediately, then scrub + free with [veilFreeString].
final int Function(Pointer<Pointer<Utf8>>, Pointer<Pointer<Utf8>>)
    veilGenerateMasterPhrase = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<Pointer<Utf8>>,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_generate_master_phrase')
        .asFunction();

final int Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)
    _validateBip39PhraseZeroizeNative = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<Uint8>,
                  IntPtr,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_validate_bip39_phrase_zeroize')
        .asFunction();

int veilValidateBip39PhraseZeroize(
  Pointer<Utf8> phrase,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _validateBip39PhraseZeroizeNative(
        phrase.cast<Uint8>(), phrase.length, errOut);

final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) _restoreIdentityFromPhraseZeroizeNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_restore_identity_from_phrase_zeroize')
    .asFunction();

int veilRestoreIdentityFromPhraseZeroize(
  Pointer<Utf8> phrase,
  Pointer<Utf8> veilDir,
  Pointer<Utf8> instanceLabel,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _restoreIdentityFromPhraseZeroizeNative(
        phrase.cast<Uint8>(),
        phrase.length,
        veilDir.cast<Uint8>(),
        veilDir.length,
        instanceLabel.cast<Uint8>(),
        instanceLabel.length,
        errOut);

/// `_zeroize_with_password` variant — same contract as
/// [veilRestoreIdentityFromPhraseZeroize] plus an optional
/// passphrase that, if non-NULL, makes the daemon write a
/// passphrase-encrypted `master.enc` backup alongside the identity
/// document.  Both phrase AND password buffers are zeroed in place
/// before return (Argon2id 64 MiB defaults — production tier). Pass
/// `nullptr` for `password` to skip the encrypted backup.
final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) _restoreIdentityFromPhraseZeroizeWithPasswordNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_restore_identity_from_phrase_zeroize_with_password')
    .asFunction();

int veilRestoreIdentityFromPhraseZeroizeWithPassword(
  Pointer<Utf8> phrase,
  Pointer<Utf8> veilDir,
  Pointer<Utf8> instanceLabel,
  Pointer<Utf8> password, // nullable
  Pointer<Pointer<Utf8>> errOut,
) =>
    _restoreIdentityFromPhraseZeroizeWithPasswordNative(
        phrase.cast<Uint8>(),
        phrase.length,
        veilDir.cast<Uint8>(),
        veilDir.length,
        instanceLabel.cast<Uint8>(),
        instanceLabel.length,
        password == nullptr ? nullptr : password.cast<Uint8>(),
        password == nullptr ? 0 : password.length,
        errOut);

// ── Short-lived sovereign signer ───────────────────────────────────────────

final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Pointer<VeilSovereignSigner>>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) _sovereignSignerOpenFromPhraseZeroizeNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<VeilSovereignSigner>>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_signer_open_from_phrase_zeroize')
    .asFunction();

int veilSovereignSignerOpenFromPhraseZeroize(
  Pointer<Utf8> phrase,
  Pointer<Pointer<VeilSovereignSigner>> outSigner,
  Pointer<Uint8> outNodeId,
  Pointer<Uint8> outPublicKey,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _sovereignSignerOpenFromPhraseZeroizeNative(
      phrase.cast<Uint8>(),
      phrase.length,
      outSigner,
      outNodeId,
      32,
      outPublicKey,
      32,
      errOut,
    );

final int Function(
  Pointer<VeilSovereignSigner>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilSovereignSignerSign = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilSovereignSigner>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_signer_sign')
    .asFunction();

final Pointer<NativeFunction<Void Function(Pointer<Void>)>>
    veilSovereignSignerClosePointer =
    nativeLib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
  'veil_sovereign_signer_close',
);

final void Function(Pointer<Void>) veilSovereignSignerClose =
    veilSovereignSignerClosePointer.asFunction();

final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Uint8>>,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilSovereignBundleCreateHybrid512Zeroize = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_bundle_create_hybrid512_zeroize')
    .asFunction();

final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Uint8>>,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilSovereignRecoveryCertificateExportZeroize = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_recovery_certificate_export_zeroize')
    .asFunction();

final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<VeilSovereignSigner>>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilSovereignSignerOpenBundleZeroize = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<VeilSovereignSigner>>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_signer_open_bundle_zeroize')
    .asFunction();

final int Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<VeilSovereignSigner>>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilSovereignSignerOpenRecoveryCertificateZeroize = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<VeilSovereignSigner>>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_signer_open_recovery_certificate_zeroize')
    .asFunction();

final int Function(
  Pointer<VeilSovereignSigner>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilSovereignSignerSignInto = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilSovereignSigner>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_signer_sign_into')
    .asFunction();

final int Function(
  int,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Bool>,
  Pointer<Pointer<Utf8>>,
) veilSovereignVerify = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Uint8,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Bool>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_sovereign_verify')
    .asFunction();

// ── Native SHA-256 (content-manifest hashing) ───────────────────────────────

final int Function(
  Pointer<Uint8>, // data
  int, // len
  Pointer<Uint8>, // out32
) veilSha256Raw = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
            )>>('veil_sha256')
    .asFunction();

// ── Push-envelope sealing (Epic 489.10) ─────────────────────────────────────

/// Per-envelope wire overhead (eph_pk + nonce + tag).  Mirrors
/// `VEIL_PUSH_ENVELOPE_OVERHEAD` in `crates/veilclient-ffi`.
const int veilPushEnvelopeOverhead = 60;

/// Hard cap on inner token length.
const int veilMaxPushTokenLen = 384;

/// Hard cap on sealed envelope length.
const int veilMaxPushEnvelopeLen = 512;

/// Push-envelope status codes (veilclient-ffi VEIL_PUSH_*).
const int veilPushOk = 0;
const int veilPushNoRendezvous = 1;
const int veilPushTooLarge = 2;

final int Function(
  Pointer<Uint8>, // token
  int, // token_len
  Pointer<Uint8>, // relay_pk_32
  Pointer<Uint8>, // out_buf
  int, // out_buf_cap
  Pointer<IntPtr>, // out_len
  Pointer<Pointer<Utf8>>,
) veilSealPushEnvelope = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_seal_push_envelope')
    .asFunction();

// ── Wake-HMAC FFI (Epic 489.10 slice 4.3.3) ──────────────────────────────────

final int Function(
  Pointer<Uint8>, // out_key_32
  Pointer<Pointer<Utf8>>,
) veilGenerateWakeHmacKey = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_generate_wake_hmac_key')
    .asFunction();

final int Function(
  Pointer<Uint8>, // key_32
  Pointer<Uint8>, // payload
  int, // payload_len
  Pointer<Uint8>, // receiver_id_32
  int, // now_secs
  Pointer<Int32>, // out_verdict
  Pointer<Pointer<Utf8>>,
) veilVerifyWakeHmac = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Uint64,
              Pointer<Int32>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_verify_wake_hmac')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // rendezvous_node_id (32 B)
  Pointer<Uint8>, // auth_cookie (16 B)
  Pointer<Uint8>, // envelope (nullable)
  int, // envelope_len
  Pointer<Pointer<Utf8>>,
) veilSetPushEnvelope = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_set_push_envelope')
    .asFunction();

/// Wake-HMAC envelope cap (Epic 489.10 slice 4.3.4) — mirrors
/// `veil_proto::MAX_WAKE_HMAC_ENVELOPE_BYTES`.
const int veilMaxWakeHmacEnvelopeLen = 128;

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // rendezvous_node_id (32 B)
  Pointer<Uint8>, // auth_cookie (16 B)
  Pointer<Uint8>, // envelope (nullable)
  int, // envelope_len
  Pointer<Pointer<Utf8>>,
) veilSetWakeHmacEnvelope = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_set_wake_hmac_envelope')
    .asFunction();

// ── Pairing / bootstrap-invite consume (Epic 489.7) ─────────────────────────

// JoinBootstrap status wire bytes (veil_proto::JoinBootstrapStatus).
const int veilJoinOk = 0;
const int veilJoinInvalidUri = 1;
const int veilJoinPasswordRequired = 2;
const int veilJoinPasswordWrong = 3;
const int veilJoinSignatureInvalid = 4;
const int veilJoinInternalError = 5;
const int veilJoinAlreadyRegistered = 6;

// CreateBootstrapInvite status wire bytes
// (veil_proto::create_invite_status, mirrors veilclient-ffi's
// VEIL_CREATE_INVITE_*).
const int veilCreateInviteOk = 0;
const int veilCreateInviteNotConfigured = 1;
const int veilCreateInviteBadPassword = 2;
const int veilCreateInviteInternalError = 3;

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // password ptr (nullable)
  int, // password_len
  Pointer<Uint8>, // out_status
  Pointer<
      Pointer<
          Utf8>>, // out_uri (malloc'd UTF-8 — caller frees with veil_free_string)
  Pointer<Pointer<Utf8>>, // err_out
) _createBootstrapInviteNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_create_bootstrap_invite')
    .asFunction();

int veilCreateBootstrapInvite(
  Pointer<VeilHandle> handle,
  Pointer<Utf8> password, // nullable
  Pointer<Uint8> outStatus,
  Pointer<Pointer<Utf8>> outUri,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _createBootstrapInviteNative(
        handle,
        password == nullptr ? nullptr : password.cast<Uint8>(),
        password == nullptr ? 0 : password.length,
        outStatus,
        outUri,
        errOut);

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // uri
  int, // uri_len
  Pointer<Uint8>, // password (nullable)
  int, // password_len
  Pointer<Uint8>, // expected_issuer_pk (nullable)
  int, // expected_issuer_pk_len
  Pointer<Uint8>, // out_node_id_32
  Pointer<Uint8>, // out_status
  Pointer<Pointer<Utf8>>,
) _joinBootstrapUriNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_join_bootstrap_uri')
    .asFunction();

int veilJoinBootstrapUri(
  Pointer<VeilHandle> handle,
  Pointer<Utf8> uri,
  Pointer<Utf8> password, // nullable
  Pointer<Utf8> expectedIssuerPk, // nullable
  Pointer<Uint8> outNodeId32,
  Pointer<Uint8> outStatus,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _joinBootstrapUriNative(
        handle,
        uri.cast<Uint8>(),
        uri.length,
        password == nullptr ? nullptr : password.cast<Uint8>(),
        password == nullptr ? 0 : password.length,
        expectedIssuerPk == nullptr ? nullptr : expectedIssuerPk.cast<Uint8>(),
        expectedIssuerPk == nullptr ? 0 : expectedIssuerPk.length,
        outNodeId32,
        outStatus,
        errOut);

// ── Mailbox (Epic 489.3) ────────────────────────────────────────────────────

// MailboxPutStatus wire bytes (veil_proto::MailboxPutStatus).
const int veilMailboxPutStored = 0;
const int veilMailboxPutDuplicate = 1;
const int veilMailboxPutQuotaPerReceiver = 2;
const int veilMailboxPutQuotaGlobal = 3;
const int veilMailboxPutRateLimited = 4;
const int veilMailboxPutNotRelay = 5;
const int veilMailboxPutCapabilityRequired = 6;
const int veilMailboxPutCapabilityInvalid = 7;
const int veilMailboxPutQuotaPerSender = 8;

/// Mirror of C `VeilMailboxBlob` (repr(C)).  Mirrors
/// `crates/veilclient-ffi/src/lib.rs::VeilMailboxBlob`.
///
/// Layout (88 B on 64-bit ABIs):
///   * [0..32]   sender_id: [u8; 32]
///   * [32..64]  content_id: [u8; 32]
///   * [64..72]  deposited_at: u64
///   * [72..80]  blob: *const u8 (pointer into caller-provided buffer)
///   * [80..84]  blob_len: u32
///   * [84..88]  _reserved: u32
final class VeilMailboxBlobStruct extends Struct {
  @Array(32)
  external Array<Uint8> senderId;
  @Array(32)
  external Array<Uint8> contentId;
  @Uint64()
  external int depositedAt;
  external Pointer<Uint8> blob;
  @Uint32()
  external int blobLen;
  @Uint32()
  external int reserved;
}

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // receiver_id (32 B)
  Pointer<Uint8>, // content_id (32 B)
  Pointer<Uint8>, // sender_id (32 B)
  Pointer<Uint8>, // blob
  int, // blob_len
  Pointer<Uint8>, // push_envelope (nullable)
  int, // push_envelope_len
  Pointer<Uint32>, // out_evicted
  Pointer<Pointer<Utf8>>,
) veilMailboxPut = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint32>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_put')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>, // capability_token
  int, // capability_token_len
  Pointer<Uint32>,
  Pointer<Pointer<Utf8>>,
) veilMailboxPutWithCapability = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint32>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_put_with_capability')
    .asFunction();

// PUT variant carrying a sealed wake-HMAC envelope alongside the push
// envelope + capability token (push wake-HMAC end-to-end).  The relay
// stamps the wake_hmac_envelope into the wake-push it fires to the
// receiver so the device can authenticate the wake before doing any
// observable work.  Same status/`out_evicted`/err contract as the other
// PUT variants; returns ≥0 status byte or <0 VEIL_ERR.
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // receiver_id (32 B)
  Pointer<Uint8>, // content_id (32 B)
  Pointer<Uint8>, // sender_id (32 B)
  Pointer<Uint8>, // blob
  int, // blob_len
  Pointer<Uint8>, // push_envelope (nullable)
  int, // push_envelope_len
  Pointer<Uint8>, // capability_token (nullable)
  int, // capability_token_len
  Pointer<Uint8>, // wake_hmac_envelope (nullable)
  int, // wake_hmac_envelope_len
  Pointer<Uint32>, // out_evicted
  Pointer<Pointer<Utf8>>,
) veilMailboxPutWithWakeHmac = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint32>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_put_with_wake_hmac')
    .asFunction();

// Look up the rendezvous replicas advertised for a receiver.  Daemon
// allocates `*out_buf` (length-prefixed; layout documented in
// `mailbox.dart::lookupRendezvousReplicas`) — caller MUST release it via
// [veilFreeReplicaBuf].  Returns 0 on OK; <0 VEIL_ERR otherwise.
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // receiver_id (32 B)
  int, // max_replicas (u8; 0 = daemon default)
  Pointer<Pointer<Uint8>>, // out_buf (daemon-allocated; caller frees)
  Pointer<IntPtr>, // out_len
  Pointer<Pointer<Utf8>>,
) veilLookupRendezvousReplicas = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Uint8,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_lookup_rendezvous_replicas')
    .asFunction();

/// Release a replica buffer returned by [veilLookupRendezvousReplicas].
/// Both `ptr` AND `len` are required (matches the C ABI — daemon needs the
/// length to reconstruct the boxed slice for deallocation).
final void Function(Pointer<Uint8>, int) veilFreeReplicaBuf = nativeLib
    .lookup<
        NativeFunction<
            Void Function(
              Pointer<Uint8>,
              IntPtr,
            )>>('veil_free_replica_buf')
    .asFunction();

/// Release a callback buffer handed to a recv-/event-handler callback
/// (cycle-7 H6). For recv, `ptr` is the `srcNodeId` base pointer and `len` is
/// `64 + dataLen` (layout `[nodeId(32) | appId(32) | data]`); for events, `ptr`
/// is the `payload` pointer and `len` is `payloadLen`. Must be called exactly
/// once per callback that received a non-null pointer, after copying the bytes.
final void Function(Pointer<Uint8>, int) veilFreeBuf = nativeLib
    .lookup<
        NativeFunction<
            Void Function(
              Pointer<Uint8>,
              IntPtr,
            )>>('veil_free_buf')
    .asFunction();

// Offline-mailbox seal: node signs an auth-deliver, DHT-resolves the recipient
// cert, fan-out-encrypts, and returns the blob via `*out_buf` (caller frees with
// [veilFreeBuf]). Returns 0 on OK; <0 VEIL_ERR otherwise.
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // recipient (32 B)
  Pointer<Uint8>, // app_id (32 B)
  int, // endpoint_id (u32)
  Pointer<Uint8>, // data
  int, // data_len
  Pointer<Pointer<Uint8>>, // out_buf (node-allocated; caller frees)
  Pointer<IntPtr>, // out_len
  Pointer<Pointer<Utf8>>,
) veilMailboxSeal = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_seal')
    .asFunction();

// Offline-mailbox open: node decrypts under our dk_seed, RECOVERS the sender
// from the blob's sidecar + verifies its auth-deliver, writing the verified
// sender (32 B) + app_id (32 B) + endpoint_id + the data buffer (via `*out_data`,
// caller frees with [veilFreeBuf]). Returns 0 on OK.
final int Function(
  Pointer<VeilHandle>,
  int, // our_cert_version (u64)
  Pointer<Uint8>, // blob
  int, // blob_len
  Pointer<Uint8>, // out_sender (32 B, caller-provided)
  Pointer<Uint8>, // out_app_id (32 B, caller-provided)
  Pointer<Uint32>, // out_endpoint_id
  Pointer<Pointer<Uint8>>, // out_data (node-allocated; caller frees)
  Pointer<IntPtr>, // out_data_len
  Pointer<Pointer<Utf8>>,
) veilMailboxOpen = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Uint64,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint32>,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_open')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // receiver_id
  Pointer<Uint8>, // auth_cookie (16 B)
  Pointer<Uint32>, // out_count
  Pointer<Pointer<Utf8>>,
) veilMailboxFetchCount = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint32>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_fetch_count')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<VeilMailboxBlobStruct>,
  int, // max_descriptors
  Pointer<Uint8>, // blob_buf
  int, // blob_buf_len
  Pointer<Pointer<Utf8>>,
) veilMailboxFetchInto = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<VeilMailboxBlobStruct>,
              Uint32,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_fetch_into')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // receiver_id
  Pointer<Uint8>, // content_id
  Pointer<Uint8>, // auth_cookie
  Pointer<Pointer<Utf8>>,
) veilMailboxAck = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_mailbox_ack')
    .asFunction();

// ── Streams (Epic 489.3) ────────────────────────────────────────────────────

final Pointer<VeilStreamFfi> Function(
  Pointer<VeilApp>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  int,
  Pointer<Pointer<Utf8>>,
) veilStreamOpen = nativeLib
    .lookup<
        NativeFunction<
            Pointer<VeilStreamFfi> Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Uint32,
              Pointer<Pointer<Utf8>>,
            )>>('veil_stream_open')
    .asFunction();

final int Function(
  Pointer<VeilStreamFfi>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilStreamWrite = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilStreamFfi>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_stream_write')
    .asFunction();

// stream_read returns ssize_t — signed pointer-sized integer.  Dart-side
// surface uses plain `int`; native returns IntPtr (matches ssize_t on
// 64-bit Windows + Linux + macOS / iOS).
final int Function(
  Pointer<VeilStreamFfi>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilStreamRead = nativeLib
    .lookup<
        NativeFunction<
            IntPtr Function(
              Pointer<VeilStreamFfi>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_stream_read')
    .asFunction();

final void Function(Pointer<VeilStreamFfi>) veilStreamClose = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<VeilStreamFfi>)>>(
      'veil_stream_close',
    )
    .asFunction();

// Block up to `timeout_ms` for a remote peer to open an inbound stream to a
// bound endpoint. Returns a stream handle + writes the initiator's node_id to
// `out_src_node_id` (32 B). NULL on timeout (no err) so the caller polls; NULL
// with err on a fatal condition.
final Pointer<VeilStreamFfi> Function(
  Pointer<VeilApp>,
  int,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilStreamAccept = nativeLib
    .lookup<
        NativeFunction<
            Pointer<VeilStreamFfi> Function(
              Pointer<VeilApp>,
              Uint64,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_stream_accept')
    .asFunction();

// ── Anonymous reliable streams (onion-routed + congestion-controlled) ────────
// Same byte-stream surface as veil_stream_*, but the cells ride the anonymous
// rendezvous transport with the app-layer ARQ + congestion control of
// `veil-onion-stream` — the fix for the bulk-transfer throughput wall. Keyed off
// the client handle (a node-wide hub, lazily bound).
final class VeilAnonStreamFfi extends Opaque {}

// open(handle, dst_node32*, dst_app32*, err) -> stream* (NULL on err).
final Pointer<VeilAnonStreamFfi> Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilAnonStreamOpen = nativeLib
    .lookup<
        NativeFunction<
            Pointer<VeilAnonStreamFfi> Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_anon_stream_open')
    .asFunction();

// warm_peer(handle, dst_node32*, err) -> 0 ok / -1 err. Fire-and-forget
// pre-warm of the outbound circuit pool toward a peer (background open).
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilAnonStreamWarmPeer = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_anon_stream_warm_peer')
    .asFunction();

// ── Media datagram channel (calls: lossy RTP/RTCP over the anon circuit) ─────
// Shares the anon-stream circuit pool but skips ARQ/pacing (drop-late, no
// retransmit). Per-packet flow is native↔native in production; these bindings
// drive control + a diagnostic recv counter for the Phase 2 two-node probe.
// See veil_media_abi.h.

// open_channel(handle, peer_node32*, err) -> chan id (u64; 0 on error).
final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilMediaOpenChannel = nativeLib
    .lookup<
        NativeFunction<
            Uint64 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_media_open_channel')
    .asFunction();

// open_direct_channel(app, peer_node32*, peer_app32*, peer_endpoint, err)
// -> chan id (u64; 0 on error).
final int Function(
  Pointer<VeilApp>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilMediaOpenDirectChannel = nativeLib
    .lookup<
        NativeFunction<
            Uint64 Function(
              Pointer<VeilApp>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Uint32,
              Pointer<Pointer<Utf8>>,
            )>>('veil_media_open_direct_channel')
    .asFunction();

// send_datagram(chan, ptr, len) -> 0 queued / 1 dropped / -1 invalid.
final int Function(int, Pointer<Uint8>, int) veilMediaSendDatagram = nativeLib
    .lookup<NativeFunction<Int32 Function(Uint64, Pointer<Uint8>, IntPtr)>>(
        'veil_media_send_datagram')
    .asFunction();

// dispatch_direct(peer_node32*, ptr, len) -> 0 delivered/accepted, -1 invalid.
final int Function(Pointer<Uint8>, Pointer<Uint8>, int)
    veilMediaDispatchDirectDatagram = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Pointer<Uint8>,
                    IntPtr)>>('veil_media_dispatch_direct_datagram')
        .asFunction();

// close_channel(chan).
final void Function(int) veilMediaCloseChannel = nativeLib
    .lookup<NativeFunction<Void Function(Uint64)>>('veil_media_close_channel')
    .asFunction();

// recv_count(peer_node32*) -> inbound datagram count from that peer.
final int Function(Pointer<Uint8>) veilMediaRecvCount = nativeLib
    .lookup<NativeFunction<Uint64 Function(Pointer<Uint8>)>>(
        'veil_media_recv_count')
    .asFunction();

// accept(handle, timeout_ms, out_src_node32*, out_src_app32*, err) -> stream*
// (NULL on timeout with no err, so the caller polls; NULL+err on fatal).
final Pointer<VeilAnonStreamFfi> Function(
  Pointer<VeilHandle>,
  int,
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Pointer<Utf8>>,
) veilAnonStreamAccept = nativeLib
    .lookup<
        NativeFunction<
            Pointer<VeilAnonStreamFfi> Function(
              Pointer<VeilHandle>,
              Uint64,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_anon_stream_accept')
    .asFunction();

// read -> ssize_t (IntPtr): n>0 bytes, 0 = clean EOF, <0 = reset (resume).
final int Function(
  Pointer<VeilAnonStreamFfi>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilAnonStreamRead = nativeLib
    .lookup<
        NativeFunction<
            IntPtr Function(
              Pointer<VeilAnonStreamFfi>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_anon_stream_read')
    .asFunction();

final int Function(
  Pointer<VeilAnonStreamFfi>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Utf8>>,
) veilAnonStreamWrite = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilAnonStreamFfi>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_anon_stream_write')
    .asFunction();

final int Function(Pointer<VeilAnonStreamFfi>, Pointer<Pointer<Utf8>>)
    veilAnonStreamFinish = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                  Pointer<VeilAnonStreamFfi>,
                  Pointer<Pointer<Utf8>>,
                )>>('veil_anon_stream_finish')
        .asFunction();

final void Function(Pointer<VeilAnonStreamFfi>) veilAnonStreamClose = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<VeilAnonStreamFfi>)>>(
      'veil_anon_stream_close',
    )
    .asFunction();

final void Function(Pointer<VeilAnonStreamFfi>) veilAnonStreamAbort = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<VeilAnonStreamFfi>)>>(
      'veil_anon_stream_abort',
    )
    .asFunction();

// ── Blob AEAD (XChaCha20-Poly1305) for the out-of-container file store ───────
// seal/unseal(key32, nonce24, input, len, *out_buf, *out_len, err) -> 0 OK / <0.
// Output buffer freed with [veilFreeBuf].
final int Function(
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Uint8>>,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilSeal = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_seal')
    .asFunction();

final int Function(
  Pointer<Uint8>,
  Pointer<Uint8>,
  Pointer<Uint8>,
  int,
  Pointer<Pointer<Uint8>>,
  Pointer<IntPtr>,
  Pointer<Pointer<Utf8>>,
) veilUnseal = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_unseal')
    .asFunction();

// ── NativeFinalizer pointers ─────────────────────────────────────────────────
//
// NativeFinalizer attaches a C-callable cleanup function to a Dart object;
// the function fires once the Dart object becomes garbage-collected
// WITHOUT a prior explicit `close()` call.  Acts as a safety-net against
// forgotten-close leaks (every leaked handle keeps a tokio runtime + an
// Arc-counted bundle alive).
//
// NativeFinalizer wants a `Pointer<NativeFunction<Void Function(Pointer<Void>)>>`
// — a type-erased pointer-to-function-of-pointer.  The C functions
// `veil_close`, `veil_app_close`, `veil_stream_close` all match
// this calling convention (one opaque-pointer arg, void return) so we
// can look them up under the generic signature.  C-side double-free
// guards mean a concurrent explicit close + GC finalizer is safe.

final Pointer<NativeFunction<Void Function(Pointer<Void>)>>
    veilCloseFinalizerPtr = nativeLib
        .lookup<NativeFunction<Void Function(Pointer<Void>)>>('veil_close');

final Pointer<NativeFunction<Void Function(Pointer<Void>)>>
    veilAppCloseFinalizerPtr =
    nativeLib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
  'veil_app_close',
);

final Pointer<NativeFunction<Void Function(Pointer<Void>)>>
    veilStreamCloseFinalizerPtr =
    nativeLib.lookup<NativeFunction<Void Function(Pointer<Void>)>>(
  'veil_stream_close',
);

// ── Multi-device pairing (Epic 489.8) ───────────────────────────────────────

// Source-side status codes (mirror VEIL_PAIR_SOURCE_* in veilclient-ffi).
const int veilPairSourceOk = 0;
const int veilPairSourceNotConfigured = 1;
const int veilPairSourceAlreadyInProgress = 2;
const int veilPairSourceInternalError = 3;
const int veilPairSourceWrongState = 4;
const int veilPairSourceBadHello = 5;
const int veilPairSourceUserAborted = 6;
const int veilPairSourceBadConfirm = 7;

// Target-side status codes (mirror VEIL_PAIR_TARGET_*).
const int veilPairTargetOk = 0;
const int veilPairTargetBadUri = 1;
const int veilPairTargetExpired = 2;
const int veilPairTargetAlreadyInProgress = 3;
const int veilPairTargetBadCert = 4;
const int veilPairTargetWrongState = 5;
const int veilPairTargetInternalError = 6;

/// Max ceremony frame size (64 KiB) — recommended caller buffer size
/// for Hello / Cert / Confirm byte transfers.
const int veilMaxPairCeremonyBytes = 64 * 1024;

/// OOB code length (6 ASCII digits).
const int veilPairOobCodeLen = 6;

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // password ptr (nullable)
  int, // password_len
  Pointer<Uint8>, // out_status
  Pointer<Pointer<Utf8>>, // out_uri (malloc'd; caller frees)
  Pointer<Pointer<Utf8>>, // err_out
) _pairSourceCreateInviteNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_pair_source_create_invite')
    .asFunction();

int veilPairSourceCreateInvite(
  Pointer<VeilHandle> handle,
  Pointer<Utf8> password, // nullable
  Pointer<Uint8> outStatus,
  Pointer<Pointer<Utf8>> outUri,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _pairSourceCreateInviteNative(
        handle,
        password == nullptr ? nullptr : password.cast<Uint8>(),
        password == nullptr ? 0 : password.length,
        outStatus,
        outUri,
        errOut);

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // hello_bytes
  int, // hello_len
  Pointer<Uint8>, // out_status
  Pointer<Uint8>, // out_oob_6
  Pointer<Uint8>, // out_cert_buf
  int, // out_cert_buf_cap
  Pointer<IntPtr>, // out_cert_len
  Pointer<Pointer<Utf8>>, // err_out
) veilPairSourceHandleHello = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_pair_source_handle_hello')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // confirm_bytes
  int, // confirm_len
  Pointer<Uint8>, // out_status
  Pointer<Pointer<Utf8>>, // err_out
) veilPairSourceHandleConfirm = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_pair_source_handle_confirm')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // uri
  int, // uri_len
  Pointer<Uint8>, // out_status
  Pointer<Uint8>, // out_hello_buf
  int, // out_hello_buf_cap
  Pointer<IntPtr>, // out_hello_len
  Pointer<Pointer<Utf8>>, // err_out
) _pairTargetConsumeUriNative = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_pair_target_consume_uri')
    .asFunction();

int veilPairTargetConsumeUri(
  Pointer<VeilHandle> handle,
  Pointer<Utf8> uri,
  Pointer<Uint8> outStatus,
  Pointer<Uint8> outHelloBuf,
  int outHelloBufCap,
  Pointer<IntPtr> outHelloLen,
  Pointer<Pointer<Utf8>> errOut,
) =>
    _pairTargetConsumeUriNative(handle, uri.cast<Uint8>(), uri.length,
        outStatus, outHelloBuf, outHelloBufCap, outHelloLen, errOut);

final int Function(
  Pointer<VeilHandle>,
  Pointer<Uint8>, // cert_bytes
  int, // cert_len
  Pointer<Uint8>, // out_status
  Pointer<Uint8>, // out_oob_6
  Pointer<Pointer<Utf8>>, // err_out
) veilPairTargetHandleCert = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_pair_target_handle_cert')
    .asFunction();

final int Function(
  Pointer<VeilHandle>,
  int, // confirmed (0 or 1)
  Pointer<Uint8>, // out_status
  Pointer<Uint8>, // out_confirm_buf
  int, // out_confirm_buf_cap
  Pointer<IntPtr>, // out_confirm_len
  Pointer<Pointer<Utf8>>, // err_out
) veilPairTargetBuildConfirm = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<VeilHandle>,
              Uint8,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_pair_target_build_confirm')
    .asFunction();

// ── Nicknames (human-readable names over veil) ───────────────────────────────
//
// Pure helpers (normalize / floor / mine / verify) are network-free; claim +
// resolve talk to the in-process embedded node (node-embedded builds only).
// Mining is chunked: each `veilNicknameMine` call is bounded by `maxHashes`;
// the caller loops off the UI isolate, threading the returned seed set back
// in as `priorSeeds`, and cancels by simply not calling again.

/// `veil_nickname_resolve` verdict: the name has no valid owner (available).
const int veilNicknameFree = 1;

// Normalize a candidate nickname. Writes normalized ASCII bytes to *out_buf
// (free with [veilFreeBuf]). VEIL_OK, or VEIL_ERR_INVALID_ARG on a bad name.
final int Function(
  Pointer<Uint8>, // name (UTF-8)
  int, // name_len
  Pointer<Pointer<Uint8>>, // out_buf
  Pointer<IntPtr>, // out_len
  Pointer<Pointer<Utf8>>, // err_out
) veilNicknameNormalize = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_nickname_normalize')
    .asFunction();

// The cumulative PoW weight floor for a name of this length (0 on bad name).
final int Function(
  Pointer<Uint8>, // name (UTF-8)
  int, // name_len
) veilNicknameLengthFloor = nativeLib
    .lookup<
        NativeFunction<
            Uint64 Function(
              Pointer<Uint8>,
              IntPtr,
            )>>('veil_nickname_length_floor')
    .asFunction();

// Mine PoW seeds (one bounded chunk). On VEIL_OK, *out_buf holds a serialized
// outcome (free with [veilFreeBuf]):
//   hit_target:u8 | weight:u64 LE | hashes:u64 LE | seed_count:u32 LE | seeds.
final int Function(
  Pointer<Uint8>, // name (UTF-8)
  int, // name_len
  Pointer<Uint8>, // owner_node_id (32 B)
  Pointer<Uint8>, // prior_seeds (count*32 B, may be nullptr)
  int, // prior_seeds_len
  int, // target_weight (u64)
  int, // max_hashes (u64)
  Pointer<Pointer<Uint8>>, // out_buf
  Pointer<IntPtr>, // out_len
  Pointer<Pointer<Utf8>>, // err_out
) veilNicknameMine = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Uint64,
              Uint64,
              Pointer<Pointer<Uint8>>,
              Pointer<IntPtr>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_nickname_mine')
    .asFunction();

// Verify a serialized NicknameRecord (owner binding + sig + PoW + floor).
final int Function(
  Pointer<Uint8>, // record bytes
  int, // record_len
  Pointer<Pointer<Utf8>>, // err_out
) veilNicknameVerify = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              IntPtr,
              Pointer<Pointer<Utf8>>,
            )>>('veil_nickname_verify')
    .asFunction();

// Sign an already-mined seed set with the sovereign key of the embedded node
// running as owner_node_id and publish to the DHT. On VEIL_OK writes the
// published record's cumulative weight to *out_weight. Errors carry the
// node-side reason (under-floor / taken-with-weight-W / multi-device subkey /
// no embedded node) in *err_out.
final int Function(
  Pointer<Uint8>, // owner_node_id (32 B)
  Pointer<Uint8>, // name (UTF-8)
  int, // name_len
  Pointer<Uint8>, // seeds (count*32 B, may be nullptr)
  int, // seeds_len
  int, // timeout_ms (u64; 0 = default)
  Pointer<Uint64>, // out_weight
  Pointer<Pointer<Utf8>>, // err_out
) veilNicknameClaim = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Pointer<Uint8>,
              IntPtr,
              Uint64,
              Pointer<Uint64>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_nickname_claim')
    .asFunction();

// Resolve the current owner of a nickname via the embedded node running as
// self_node_id. VEIL_OK = owner found (out_owner/out_weight/out_issued_at
// filled); [veilNicknameFree] = name is available; negative = error.
final int Function(
  Pointer<Uint8>, // self_node_id (32 B)
  Pointer<Uint8>, // name (UTF-8)
  int, // name_len
  int, // timeout_ms (u64; 0 = default)
  Pointer<Uint8>, // out_owner (32 B, caller-provided)
  Pointer<Uint64>, // out_weight
  Pointer<Uint64>, // out_issued_at
  Pointer<Pointer<Utf8>>, // err_out
) veilNicknameResolve = nativeLib
    .lookup<
        NativeFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              IntPtr,
              Uint64,
              Pointer<Uint8>,
              Pointer<Uint64>,
              Pointer<Uint64>,
              Pointer<Pointer<Utf8>>,
            )>>('veil_nickname_resolve')
    .asFunction();
