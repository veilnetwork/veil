/* SPDX-License-Identifier: MIT
 *
 * veil_ffi.h — C ABI for the veil client SDK.
 *
 * AUTO-GENERATED from `crates/veilclient-ffi/src/lib.rs`.
 * DO NOT EDIT BY HAND — regenerate via:
 *
 *     cbindgen --config crates/veilclient-ffi/cbindgen.toml \
 *              --crate veilclient-ffi \
 *              --output crates/veilclient-ffi/include/veil_ffi.h
 *
 * CI gate in `.github/workflows/ci.yml::hygiene` runs the same command
 * and diffs against committed header; PRs that touch FFI signatures must
 * also commit the regenerated header.
 *
 * Memory ownership / lifetime / safety contracts:
 *   * Opaque handles are caller-owned; free via the matching `_close()`
 *     or `_free()` function (e.g. `veil_close`, `veil_stream_close`).
 *   * `err_out` are caller-allocated `*mut *mut c_char`; library writes
 *     a heap-owned C string on error.  Caller frees via `veil_free_string`.
 *   * Buffer pointers + length pairs are caller-allocated; callee never
 *     reallocates them.
 *   * Callbacks may be invoked from arbitrary tokio worker threads; caller
 *     must synchronise by own state.  Callbacks are wrapped in `catch_unwind`;
 *     panics in callback bodies will NOT cross the ABI boundary.
 */


#ifndef VEIL_FFI_H
#define VEIL_FFI_H

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/**
 * Operation succeeded.
 */
#define VEIL_OK 0

/**
 * Generic error (see `err_out` for detail).
 */
#define VEIL_ERR -1

/**
 * A required pointer parameter was NULL or invalid UTF-8.
 */
#define VEIL_ERR_INVALID_ARG -2

/**
 * The handle / app / stream has already been closed.
 */
#define VEIL_ERR_CLOSED -3

/**
 * the FFI call was made from inside a Tokio
 * runtime worker thread (e.g. from a recv-handler callback). Calling
 * a `block_on` or `blocking_lock` FFI entry point from such a context
 * would deadlock the worker. Hosts that need to perform another FFI
 * operation from a callback must dispatch it to a different thread
 * (e.g. main UI thread, dedicated worker pool).
 */
#define VEIL_ERR_REENTRANT -4

/**
 * hard cap on `data` byte length accepted by
 * FFI calls that allocate from caller-supplied len. Sits BELOW the daemon's
 * `MAX_FRAME_BODY` (16 MiB) by enough headroom for the largest IPC send-payload
 * fixed prefix, so the framed `body_len = FIXED_SIZE + data_len` can never
 * exceed `MAX_FRAME_BODY`. Without this margin a max-size send produced
 * `body_len > MAX_FRAME_BODY`, which `decode_header` rejects → the daemon's
 * read task `return`s and tears down the WHOLE IPC connection (all multiplexed
 * apps/streams), not just the offending send (diff-audit 2026-06-12, defect
 * M25). The largest send prefix is `SendAnonymousDirectPayload::FIXED_SIZE`
 * (136 B); 256 B of headroom covers it plus any reply-aware trailer. Also
 * keeps a huge `len` to [`veil_send`] a clean `VEIL_ERR_INVALID_ARG` rather
 * than an OOM-sized allocation.
 */
#define VEIL_MAX_DATA_LEN (((16 * 1024) * 1024) - 256)

/**
 * Background-mode tier values [`veil_set_background_mode`].
 * Mirrors `MobileBackgroundMode` on the wire (0/1/2 byte).
 */
#define VEIL_BG_FOREGROUND 0

#define VEIL_BG_ACTIVE 1

#define VEIL_BG_LOWPOWER 2

/**
 * Network-kind values [`veil_notify_network_changed`].
 */
#define VEIL_NET_OFFLINE 0

#define VEIL_NET_WIFI 1

#define VEIL_NET_CELLULAR 2

#define VEIL_NET_ETHERNET 3

#define VEIL_NET_UNKNOWN 255

/**
 * Push-envelope status return codes [`veil_set_push_envelope`].
 * Mirrors `SetPushEnvelopeStatus` on the wire (0/1/2 byte).
 */
#define VEIL_PUSH_OK 0

#define VEIL_PUSH_NO_RENDEZVOUS 1

#define VEIL_PUSH_TOO_LARGE 2

/**
 * Wake-HMAC verdict codes returned by [`veil_verify_wake_hmac`].
 * Mirrors `veil_crypto::wake_hmac::WakePayloadVerdict` so receiver
 * plugins can branch on each failure mode separately (operators care
 * about clock-skew rate as a distinct signal from active forging).
 *
 * Slice 4.3.3 of Epic 489.10.
 */
#define VEIL_WAKE_VERDICT_VALID 0

#define VEIL_WAKE_VERDICT_TAMPERED 1

#define VEIL_WAKE_VERDICT_EXPIRED 2

#define VEIL_WAKE_VERDICT_MALFORMED 3

/**
 * Wake-HMAC key length (32 bytes).  Pinned to
 * `veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN`.
 */
#define VEIL_WAKE_HMAC_KEY_LEN 32

/**
 * Wake payload total wire size (72 bytes — `ts u64 BE || content_id 32
 * || hmac_tag 32`).  Pinned to `veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN`.
 */
#define VEIL_WAKE_PAYLOAD_LEN 72

/**
 *.4 P0: outcome [`veil_get_relay_x25519_pubkey`].
 * `VEIL_OK` means the daemon is relay-capable and `out_pubkey_32`
 * was populated. `VEIL_RELAY_X25519_UNAVAILABLE` means the daemon
 * is not relay-capable (operator did not opt into
 * `anonymity.relay_capable`) — apps must pick a different relay for
 * push-envelope sealing. Other negative codes are protocol errors.
 */
#define VEIL_RELAY_X25519_UNAVAILABLE -10

/**
 * Status return codes [`veil_mailbox_put`]. Mirrors
 * `MailboxPutStatus` on the wire (0..8 byte).
 */
#define VEIL_MAILBOX_PUT_STORED 0

#define VEIL_MAILBOX_PUT_DUPLICATE 1

#define VEIL_MAILBOX_PUT_QUOTA_PER_RECEIVER 2

#define VEIL_MAILBOX_PUT_QUOTA_GLOBAL 3

#define VEIL_MAILBOX_PUT_RATE_LIMITED 4

#define VEIL_MAILBOX_PUT_NOT_RELAY 5

/**
 * relay configured with
 * `require_capability_token = true` rejected a PUT that arrived
 * without a capability token.
 */
#define VEIL_MAILBOX_PUT_CAPABILITY_REQUIRED 6

/**
 * capability token decode or verify
 * failed (expired, wrong receiver, or bad signature).
 */
#define VEIL_MAILBOX_PUT_CAPABILITY_INVALID 7

/**
 * per-sender byte cap exceeded.
 */
#define VEIL_MAILBOX_PUT_QUOTA_PER_SENDER 8

/**
 * Status codes returned by `veil_join_bootstrap_uri` via `out_status`.
 * Mirror `veil_proto::join_status` constants exactly.
 */
#define VEIL_JOIN_OK 0

#define VEIL_JOIN_INVALID_URI 1

#define VEIL_JOIN_PASSWORD_REQUIRED 2

#define VEIL_JOIN_PASSWORD_WRONG 3

#define VEIL_JOIN_SIGNATURE_INVALID 4

#define VEIL_JOIN_INTERNAL_ERROR 5

#define VEIL_JOIN_ALREADY_REGISTERED 6

/**
 * Create-bootstrap-invite status codes (Epic 489.7 generator side).
 * Mirror `veil_proto::create_invite_status`.
 */
#define VEIL_CREATE_INVITE_OK 0

#define VEIL_CREATE_INVITE_NOT_CONFIGURED 1

#define VEIL_CREATE_INVITE_BAD_PASSWORD 2

#define VEIL_CREATE_INVITE_INTERNAL_ERROR 3

/**
 * Wire-byte session-state values for `VeilPeerCb::state`.
 */
#define VEIL_PEER_STATE_CONNECTING 0

#define VEIL_PEER_STATE_ACTIVE 1

#define VEIL_PEER_STATE_CLOSED 2

#define VEIL_PEER_STATE_UNKNOWN 255

/**
 * Wire-byte direction values for `VeilPeerCb::direction`.
 */
#define VEIL_PEER_DIR_INBOUND 0

#define VEIL_PEER_DIR_OUTBOUND 1

/**
 * Per-envelope wire overhead (`eph_pk + nonce + tag`).  Pre-allocate
 * `token_len + VEIL_PUSH_ENVELOPE_OVERHEAD` bytes on the caller
 * side to receive the sealed bytes.  Mirrors
 * `veil_anonymity::push_envelope::PUSH_ENVELOPE_OVERHEAD`.
 */
#define VEIL_PUSH_ENVELOPE_OVERHEAD 60

/**
 * Hard cap on inner token length (mirrors MAX_PUSH_TOKEN_LEN).
 */
#define VEIL_MAX_PUSH_TOKEN_LEN 384

/**
 * Hard cap on sealed envelope length (mirrors MAX_PUSH_ENVELOPE_LEN).
 */
#define VEIL_MAX_PUSH_ENVELOPE_LEN 512

/**
 * Event-kind wire bytes mirroring `veil_proto::event_kind::*`.
 * Hosts dispatch on `kind` to know how to interpret `payload`. Keep
 * in lockstep with the server-side constants — adding new kinds is
 * forward-compatible (older C consumers see an unknown kind and
 * fall back to a noop handler).
 */
#define VEIL_EVENT_SESSIONS_CHANGED 0

#define VEIL_EVENT_MOBILE_TIER_CHANGED 1

#define VEIL_EVENT_IDENTITY_ROTATED 2

/**
 * Mailbox drain (fetch) completed.  Payload: `[u32 BE drained_count]`.
 * BG-handler consumers (iOS BGProcessingTask, Android background workers)
 * subscribe so they can complete precisely at drain completion instead of
 * padding to a hardcoded fallback timeout.
 */
#define VEIL_EVENT_MAILBOX_DRAINED 3

/**
 * A mailbox relay signalled over our live session that it just stored a
 * deposit for us (in-network wake — no third-party push). Empty payload;
 * the client should drain its mailbox promptly. Best-effort hint.
 */
#define VEIL_EVENT_MAILBOX_WAKE 5

/**
 * Maximum freshness window for a restored IdentityDocument — 30 days.
 * Mirrors `veil_identity::MAX_FRESHNESS_WINDOW_SECS`. Restored
 * devices typically request the full window so the doc lives through
 * the next routine document republish (default ~half-life).
 */
#define VEIL_DEFAULT_RESTORE_VALIDITY_SECS ((30 * 24) * 3600)

/**
 * Wire-byte status codes for Source-side pairing ops.  Mirror
 * `veil_proto::pair_source_status`.
 */
#define VEIL_PAIR_SOURCE_OK 0

#define VEIL_PAIR_SOURCE_NOT_CONFIGURED 1

#define VEIL_PAIR_SOURCE_ALREADY_IN_PROGRESS 2

#define VEIL_PAIR_SOURCE_INTERNAL_ERROR 3

#define VEIL_PAIR_SOURCE_WRONG_STATE 4

#define VEIL_PAIR_SOURCE_BAD_HELLO 5

#define VEIL_PAIR_SOURCE_USER_ABORTED 6

#define VEIL_PAIR_SOURCE_BAD_CONFIRM 7

/**
 * Wire-byte status codes for Target-side pairing ops.  Mirror
 * `veil_proto::pair_target_status`.
 */
#define VEIL_PAIR_TARGET_OK 0

#define VEIL_PAIR_TARGET_BAD_URI 1

#define VEIL_PAIR_TARGET_EXPIRED 2

#define VEIL_PAIR_TARGET_ALREADY_IN_PROGRESS 3

#define VEIL_PAIR_TARGET_BAD_CERT 4

#define VEIL_PAIR_TARGET_WRONG_STATE 5

#define VEIL_PAIR_TARGET_INTERNAL_ERROR 6

/**
 * Hard cap on ceremony frame size (mirrors
 * `veil_proto::MAX_PAIR_CEREMONY_BYTES`).  Callers can pre-
 * allocate a buffer of this size to safely receive Hello / Cert /
 * Confirm bytes without two-call sizing.
 */
#define VEIL_MAX_PAIR_CEREMONY_BYTES (64 * 1024)

/**
 * OOB code length (always 6 ASCII digits).
 */
#define VEIL_PAIR_OOB_CODE_LEN 6

#if defined(VEIL_FFI_NODE_EMBEDDED)
#define STREAM_ENDPOINT_ID 12
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * First byte of every media cell. Distinct from
 * `veil_onion_stream::wire::PROTO_VER` (= 1), so a media cell is already an
 * invalid stream frame (`Frame::decode` → `None`) and the reliable demux would
 * reject it outright — media and stream coexist on one circuit with zero
 * collision, separated only by this byte.
 */
#define MEDIA_MAGIC 77
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * First byte of a media cell containing several RTP/RTCP datagrams. Keeping a
 * distinct top-level magic makes old receivers drop the unknown cell instead
 * of passing a batch envelope to WebRTC as if it were RTP.
 */
#define MEDIA_BATCH_MAGIC 66
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * `veil_nickname_resolve`: positive verdict for "the name is free" (no valid
 * owner record found) — not an error.
 */
#define NICKNAME_FREE 1
#endif

typedef struct Option_MediaRecvFn Option_MediaRecvFn;

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Handle to one ANONYMOUS reliable byte-stream (onion-routed, congestion-
 * controlled — see [`anon_stream`]). Split read/write halves so a caller can
 * read + write concurrently without one mutex deadlocking a blocking read
 * against a write.
 */
typedef struct VeilAnonStreamFfi VeilAnonStreamFfi;
#endif

/**
 * Opaque app endpoint.
 *
 * split into a `AppSender` (always present
 * while the app is bound) and an optional `AppReceiver` (moved out
 * when `set_recv_handler` installs the recv loop). Previously we
 * stored a single `Option<AppHandle>` and `set_recv_handler` did a
 * `take`, which left `veil_send` permanently returning
 * `VEIL_ERR_CLOSED` despite the daemon-side binding still being
 * alive — directly contradicting the documented contract. Now
 * `veil_send` always works through the still-resident `AppSender`
 * regardless of whether a recv handler is installed.
 */
typedef struct VeilApp VeilApp;

/**
 * Opaque connection handle returned by [`veil_connect`].
 *
 * Wraps a strong `Arc` over [`RuntimeBundle`]; cloning an internal `Arc`
 * from this is what allows apps and streams to outlive the caller's
 * own `VeilHandle*` if they so choose (although the typical pattern
 * is to keep the handle alive for the whole session).
 */
typedef struct VeilHandle VeilHandle;

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Opaque handle to a running embedded node.
 */
typedef struct VeilNode VeilNode;
#endif

/**
 * Short-lived sovereign signing burst opened from a recovery phrase. The
 * derived seed never crosses the FFI boundary and is zeroized when the last
 * in-flight operation releases this handle.
 */
typedef struct VeilSovereignSigner VeilSovereignSigner;

/**
 * Opaque veil stream — reliable ordered byte channel.
 *
 * The SDK stream is split into independent read/write halves under SEPARATE
 * mutexes (diff-audit H4): the old single `Mutex<Option<SdkStream>>` meant a
 * thread parked in `veil_stream_read` (which holds the lock across a blocking,
 * timeout-less read) blocked any concurrent `veil_stream_write` forever — a
 * half-duplex deadlock for request/response protocols. `tokio::io::split`
 * lets read and write lock disjoint halves. Dropping the struct drops both
 * halves → the underlying stream → its `Drop` sends STREAM_CLOSE.
 */
typedef struct VeilStreamFfi VeilStreamFfi;

/**
 * Recv callback signature — invoked from a tokio worker thread.
 *
 * BUFFER OWNERSHIP (cycle-7 H6): the three pointers (`src_node_id`,
 * `src_app_id`, `data`) are offsets into ONE heap buffer the callee now OWNS:
 * `src_node_id` is the base, laid out `[node_id(32) | app_id(32) | data]`. The
 * host MAY retain the pointers past this synchronous call (e.g. marshal them to
 * another thread/isolate and copy later) and MUST, exactly once per non-NULL
 * invocation, call `veil_free_buf(src_node_id, 64 + data_len)` after copying.
 * This replaces the old "valid for the call only; copy synchronously" contract
 * that a deferred host (Dart `NativeCallable.listener`) could not honour
 * without a use-after-free.
 *
 * `reply_id` is a by-value scalar (NOT part of the owned buffer — it has no
 * lifetime to manage): non-zero when this message arrived over the
 * authenticated anonymous transport WITH a one-time reply block. Pass it to
 * [`veil_send_reply`] to answer without either side publishing a public
 * rendezvous ad. `0` means "not repliable".
 *
 * wrapped in `Option<...>` so a NULL
 * function pointer passed from C/Swift/Kotlin is a valid `None`
 * representation that Rust matches and rejects gracefully — instead
 * of being silently treated as a valid `unsafe extern "C" fn(...)`
 * (which Rust assumes non-nullable, leading to UB on dereference
 * before `catch_unwind` could intervene).
 */
typedef void (*VeilRecvCb)(void *user,
                           const uint8_t *src_node_id,
                           const uint8_t *src_app_id,
                           uint64_t reply_id,
                           const uint8_t *data,
                           size_t len);

/**
 * Mailbox blob descriptor returned by [`veil_mailbox_fetch_into`].
 * `blob` is a borrow into a buffer the caller provided to the fetch
 * call; valid until the caller frees that buffer.
 */
typedef struct {
  uint8_t sender_id[32];
  uint8_t content_id[32];
  uint64_t deposited_at;
  /**
   * Pointer into caller-provided `blob_buf` (NOT separately allocated).
   */
  const uint8_t *blob;
  uint32_t blob_len;
  uint32_t _reserved;
} VeilMailboxBlob;

/**
 * Snapshot of the daemon's mobile/battery state, populated by
 * `veil_get_mobile_status`. All fields are scalar wire bytes;
 * apps interpret sentinels themselves (`battery_level_pct == 100`
 * could mean "literal 100%" or "AC / unknown").
 */
typedef struct {
  /**
   * 0 = Foreground / 1 = Active / 2 = LowPower.
   */
  uint8_t background_tier;
  uint8_t _pad1[3];
  /**
   * Configured `mobile.background_keepalive_multiplier`.
   */
  uint32_t background_keepalive_multiplier;
  /**
   * Effective background-keepalive factor RIGHT NOW.
   */
  uint32_t background_keepalive_factor;
  /**
   * Battery reading 0-100 (100 = AC / unknown).
   */
  uint8_t battery_level_pct;
  /**
   * Configured threshold for route-probe throttling (255 = disabled).
   */
  uint8_t low_battery_threshold_pct;
  uint8_t _pad2[2];
  /**
   * Configured route-probe multiplier on low-battery.
   */
  uint32_t low_battery_multiplier;
  /**
   * Effective route-probe factor RIGHT NOW.
   */
  uint32_t battery_route_probe_factor;
} VeilMobileStatus;

/**
 * Peer-list iteration callback.
 *
 * Invoked once per peer entry from `veil_peers_list`. All buffer
 * pointers are valid only for the duration of the call — copy out
 * anything you need to keep.
 *
 * user — the opaque pointer passed to `veil_peers_list`.
 * node_id — pointer to 32 bytes; peer's identity.
 * state — wire-byte session state (see VEIL_PEER_STATE_*).
 * direction — wire-byte direction (see VEIL_PEER_DIR_*).
 * transport — UTF-8 transport URI (NOT null-terminated; use len).
 * transport_len — byte length of `transport`.
 * wrapped in `Option<...>` for safe
 * NULL-pointer rejection at the FFI boundary. See [`VeilRecvCb`]
 * docs.
 */
typedef void (*VeilPeerCb)(void *user,
                           const uint8_t *node_id,
                           uint8_t state,
                           uint8_t direction,
                           const uint8_t *transport,
                           size_t transport_len);

/**
 * Push-event callback. Invoked from a tokio worker thread for every
 * `LocalAppMsg::Event` frame the daemon emits while this handler is
 * installed. `payload`+`payload_len` describe the per-kind opaque
 * bytes (see. `veil_proto::event_kind` for wire format per kind).
 *
 * BUFFER OWNERSHIP (cycle-7 H6): for a non-empty payload the pointer is an
 * OWNED heap buffer the callee must free via `veil_free_buf(payload,
 * payload_len)` after copying — it MAY be retained past this synchronous call
 * (Dart `NativeCallable.listener`). An empty payload passes a NULL pointer with
 * `payload_len == 0` (nothing to free).
 *
 * wrapped in `Option<...>` for safe
 * NULL-pointer rejection at the FFI boundary. See [`VeilRecvCb`]
 * docs.
 */
typedef void (*VeilEventCb)(void *user, uint8_t kind, const uint8_t *payload, size_t payload_len);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Open an anonymous reliable byte-stream to a peer. `dst_app_id` is the peer's
 * onion-stream endpoint app id (`deriveAppId(peer_node, "xveil",
 * "onion-stream")` — the Dart caller derives it, mirroring `veil_stream_open`).
 * Returns NULL on error.
 */

VeilAnonStreamFfi *veil_anon_stream_open(VeilHandle *handle,
                                         const uint8_t *dst_node_id,
                                         const uint8_t *dst_app_id,
                                         char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Accept the next inbound anonymous stream, or NULL on timeout (no error) /
 * error. On success writes the initiator's 32-byte node id + onion-stream app
 * id into the out params (caller-allocated, 32 B each).
 */

VeilAnonStreamFfi *veil_anon_stream_accept(VeilHandle *handle,
                                           uint64_t timeout_ms,
                                           uint8_t *out_src_node_id,
                                           uint8_t *out_src_app_id,
                                           char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Pre-warm the anonymous-stream outbound circuit pool toward a peer.
 * Fire-and-forget: kicks the background pool open (resolve ads + open +
 * confirm) and returns immediately, so a freshly-restarted node's first
 * serve/pull does not pay the cold-pool price inside the peer's manifest
 * window. Idempotent; cheap when the pool is already up. Returns 0 on
 * dispatch, -1 on error (NULL args / dead handle / hub bind failure).
 */

int32_t veil_anon_stream_warm_peer(VeilHandle *handle,
                                   const uint8_t *dst_node_id,
                                   char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Open a lossy MEDIA datagram channel to `peer` over the anonymous circuit
 * (reuses the reliable stream's rendezvous/pool and warms the circuit in the
 * background). Per-packet RTP/RTCP then flows native↔native via
 * [`veil_media_send_datagram`] / [`veil_media_set_recv_callback`]. Returns an
 * opaque channel id (> 0), or 0 on error.
 */
 uint64_t veil_media_open_channel(VeilHandle *handle, const uint8_t *peer_node_id, char **err_out) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Open a lossy MEDIA datagram channel to `peer` over a direct app endpoint.
 * Outbound RTP/RTCP is sent from `app` to `(peer_node_id, peer_app_id,
 * peer_endpoint_id)`. Inbound direct media datagrams must be received by the
 * host on the same app endpoint and fed to
 * [`veil_media_dispatch_direct_datagram`].
 */

uint64_t veil_media_open_direct_channel(VeilApp *app,
                                        const uint8_t *peer_node_id,
                                        const uint8_t *peer_app_id,
                                        uint32_t peer_endpoint_id,
                                        char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Open a lossy MEDIA channel forced through the ordinary Delivery relay path
 * (no onion circuit). The daemon E2E-encrypts each datagram for `peer`; relay
 * nodes see addressing metadata but never RTP/RTCP bytes. Intended only for
 * direct-identity calls when the preferred P2P route is unavailable.
 */

uint64_t veil_media_open_relay_channel(VeilApp *app,
                                       const uint8_t *peer_node_id,
                                       const uint8_t *peer_app_id,
                                       uint32_t peer_endpoint_id,
                                       char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Enqueue one media datagram (RTP/RTCP) on `chan`. NON-BLOCKING: returns 0 if
 * queued, 1 if dropped (queue full / channel closing) — the caller's real-time
 * media thread must never block. Returns -1 on a NULL/zero-length payload or an
 * unknown `chan`.
 */
 int veil_media_send_datagram(uint64_t chan, const uint8_t *ptr, size_t len) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Request a make-before-break anonymous route refresh for an open media
 * channel. This is deliberately separate from send success: an onion packet
 * can enter the first-hop queue successfully and still be black-holed farther
 * along the circuit. The peer reports that end-to-end silence over the live
 * call heartbeat, and the host forwards it here. Returns 0 when queued, 1 when
 * an equivalent repair is already pending, and -1 for an unknown/direct
 * channel.
 */
 int veil_media_repair_channel(uint64_t chan) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Feed one direct-P2P media datagram received by the host on the media app
 * endpoint into the shared native media callback registry. The host is
 * responsible for authenticating/filtering the source app id before calling.
 */

int veil_media_dispatch_direct_datagram(const uint8_t *peer_node_id,
                                        const uint8_t *ptr,
                                        size_t len)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Drain one bound app endpoint directly into the native media callback
 * registry, bypassing the host language's event loop entirely.
 *
 * `source_namespace` + `source_name` identify the well-known named app that a
 * remote media sender must use. The authenticated session `src_node_id` is
 * combined with those names to derive the only accepted `src_app_id`; frames
 * from another app on the same peer are silently dropped. This preserves the
 * source-app check previously performed in Dart without copying every RTP
 * packet through the UI isolate.
 *
 * This function takes exclusive ownership of the app's datagram receiver. It
 * must be called before [`veil_app_set_recv_handler`].
 */

int veil_media_start_direct_receiver(VeilApp *app,
                                     const uint8_t *source_namespace,
                                     size_t source_namespace_len,
                                     const uint8_t *source_name,
                                     size_t source_name_len,
                                     char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Install the C recv callback invoked (native↔native, from a tokio worker)
 * once per inbound media datagram from `chan`'s peer, with the wire magic
 * already stripped. Replaces any prior callback; `cb == NULL` clears it.
 * Returns 0, or -1 on an unknown `chan`.
 */
 int veil_media_set_recv_callback(uint64_t chan, Option_MediaRecvFn cb, void *ctx) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Close a media channel: stops the drain task, drops the outbound queue, and
 * clears the peer's recv callback. Idempotent (unknown `chan` is a no-op).
 */
 void veil_media_close_channel(uint64_t chan) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Diagnostic: number of inbound media datagrams received from `peer_node_id`
 * (32 bytes) since process start. Lets a host confirm receipt without wiring a
 * cross-thread recv callback (used by the Phase 2 two-node datagram probe).
 * Returns 0 on a NULL pointer.
 */
 uint64_t veil_media_recv_count(const uint8_t *peer_node_id) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Read up to `cap` bytes. Returns the count (0 = clean EOF), or a negative
 * error code (the stream was reset → the app should resume).
 */

ssize_t veil_anon_stream_read(VeilAnonStreamFfi *stream,
                              uint8_t *buf,
                              size_t cap,
                              char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Queue `len` bytes for reliable delivery. Returns `VEIL_OK` / a negative code.
 */

int veil_anon_stream_write(VeilAnonStreamFfi *stream,
                           const uint8_t *data,
                           size_t len,
                           char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Half-close the send direction (a FIN follows the last queued byte). The peer
 * reads EOF. Returns `VEIL_OK` / a negative code.
 */
 int veil_anon_stream_finish(VeilAnonStreamFfi *stream, char **err_out) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Close + free the stream handle (idempotent, NULL-safe). This is the graceful
 * resource-release path: dropping the write half closes the command channel, so
 * the driver finishes the send direction rather than resetting normal EOF.
 */
 void veil_anon_stream_close(VeilAnonStreamFfi *stream) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Abort + free the stream handle (idempotent, NULL-safe). Use for timeout /
 * retry cancellation. A Dart timeout may call this while another FFI worker is
 * blocked inside `read()`, and removing the generational handle alone does not
 * wake that already-cloned Arc. First signal the local read half, then send a
 * best-effort RST through the driver so the peer/route settle too.
 */
 void veil_anon_stream_abort(VeilAnonStreamFfi *stream) ;
#endif

/**
 * Free a C string returned by this library (error messages, etc.).
 * Safe to call on NULL.
 */
 void veil_free_string(char *s) ;

/**
 * Connect to an veil daemon's IPC socket and perform the APP_HELLO
 * handshake. Returns an opaque [`VeilHandle`] on success, NULL on
 * failure (with `*err_out` set).
 *
 * `socket_path` is treated as an anchor — see
 * [`veilclient::VeilClient::connect`] for backend discovery rules.
 */
 VeilHandle *veil_connect(const uint8_t *socket_path, uintptr_t socket_path_len, char **err_out) ;

/**
 * Release the handle. Outstanding apps / streams keep the runtime
 * alive via their own `Arc`; the runtime is dropped only when the last
 * reference goes away. Safe to call on NULL.
 *
 * Defends against double-free. A NULL / already-freed / garbage / wrong-type
 * token is absent from the generational handle table → safe no-op; the
 * (opaque, non-pointer) token is never dereferenced (see [`HandleTable`]).
 */
 void veil_close(VeilHandle *handle) ;

/**
 * Bind an ephemeral application endpoint. Returns NULL on failure
 * (see `*err_out`).
 */

VeilApp *veil_bind(VeilHandle *handle,
                   const uint8_t *namespace_,
                   uintptr_t namespace_len,
                   const uint8_t *name,
                   uintptr_t name_len,
                   uint32_t endpoint_id,
                   char **err_out)
;

/**
 * Bind a well-known persistent application endpoint. Returns NULL on
 * failure (see `*err_out`).
 */

VeilApp *veil_bind_named(VeilHandle *handle,
                         const uint8_t *namespace_,
                         uintptr_t namespace_len,
                         const uint8_t *name,
                         uintptr_t name_len,
                         uint32_t endpoint_id,
                         char **err_out)
;

/**
 * Bind a stable high-entropy capability alias whose app id is independent of
 * the local sovereign node id. Returns NULL on failure.
 */

VeilApp *veil_bind_capability(VeilHandle *handle,
                              const uint8_t *namespace_,
                              uintptr_t namespace_len,
                              const uint8_t *name,
                              uintptr_t name_len,
                              uint32_t endpoint_id,
                              char **err_out)
;

/**
 * Copy the bound `app_id` (32 bytes) into `out`.
 */
 int veil_app_get_app_id(const VeilApp *app, uint8_t *out) ;

/**
 * Return the bound endpoint id.
 */
 uint32_t veil_app_get_endpoint_id(const VeilApp *app) ;

/**
 * Close an app endpoint. Aborts any active recv loop and releases
 * resources. Safe to call on NULL.
 */
 void veil_app_close(VeilApp *app) ;

/**
 * Send a datagram from `app` to `(dst_node_id, dst_app_id, dst_endpoint_id)`.
 */

int veil_send(VeilApp *app,
              const uint8_t *dst_node_id,
              const uint8_t *dst_app_id,
              uint32_t dst_endpoint_id,
              const uint8_t *data,
              size_t len,
              char **err_out)
;

/**
 * Send an AUTHENTICATED anonymous datagram from `app` to
 * `(dst_node_id, dst_app_id, dst_endpoint_id)`.
 *
 * Like [`veil_send`], but routed over the onion/rendezvous transport: no
 * relay learns the sender's network location, while the recipient
 * cryptographically verifies WHO sent it. v1: one-way; fire-and-forget
 * (`VEIL_OK` means accepted + handed to the first hop, NOT delivery-
 * confirmed); the recipient must have opted in to receiving
 * (`[anonymity].receive_anonymous`). The sender node needs a sovereign
 * identity. Large messages are fragmented up to a fixed ceiling.
 *
 * Because the return value reports only local acceptance, an asynchronous
 * send failure (no route, terminal NACK) surfaces LATER as an
 * `ANON_SEND_FAILED` event (diff-audit L7), not as an error return here.
 * There is no end-to-end ACK, so absence of that event is not proof of
 * delivery.
 */

int veil_send_anonymous_authenticated(VeilApp *app,
                                      const uint8_t *dst_node_id,
                                      const uint8_t *dst_app_id,
                                      uint32_t dst_endpoint_id,
                                      const uint8_t *data,
                                      size_t len,
                                      char **err_out)
;

/**
 * Like [`veil_send_anonymous_authenticated`], but additionally attach a
 * one-time reply block so the recipient can answer WITHOUT either side
 * publishing a public rendezvous ad (no presence leak). The reply is delivered
 * back to `(this app, reply_endpoint_id)` and surfaces to the recipient as a
 * non-zero `reply_id` in the recv callback. Pass the endpoint you receive on
 * for `reply_endpoint_id`. Same fire-and-forget semantics as the plain
 * authenticated send.
 */

int veil_send_anonymous_authenticated_with_reply(VeilApp *app,
                                                 const uint8_t *dst_node_id,
                                                 const uint8_t *dst_app_id,
                                                 uint32_t dst_endpoint_id,
                                                 uint32_t reply_endpoint_id,
                                                 const uint8_t *data,
                                                 size_t len,
                                                 char **err_out)
;

/**
 * Like [`veil_send_anonymous_authenticated_with_reply`], but the caller GIVES
 * the relay's KEM key (`dst_x25519_pk`, 32 bytes) directly — so the daemon
 * routes the source-routed onion straight to `(dst_node_id, dst_x25519_pk)`
 * with NO rendezvous-ad self-resolve (the flaky lookup that returned
 * `NoRendezvous`). Still authenticated (the relay verifies the sender) and
 * still attaches a one-time reply block delivered back to
 * `(this app, reply_endpoint_id)`. This is the KEM-key-given mailbox FETCH;
 * `dst_x25519_pk` is a PUBLIC key (the relay's published KEM key). All three
 * `dst_*` arrays are 32 bytes.
 */

int veil_send_anonymous_authenticated_direct_with_reply(VeilApp *app,
                                                        const uint8_t *dst_node_id,
                                                        const uint8_t *dst_x25519_pk,
                                                        const uint8_t *dst_app_id,
                                                        uint32_t dst_endpoint_id,
                                                        uint32_t reply_endpoint_id,
                                                        const uint8_t *data,
                                                        size_t len,
                                                        char **err_out)
;

/**
 * Reply to a message received over the authenticated anonymous transport,
 * addressing it by the opaque `reply_id` from the recv callback. The daemon
 * routes the reply back over the original sender's rendezvous path — no public
 * ad on either side. `reply_id` is TTL-bounded daemon-side and may be replied
 * to MORE THAN ONCE until it expires (the daemon peeks the reply block, it does
 * not consume it) — deduplicate at the app layer if needed; a stale/unknown id
 * returns `VEIL_ERR` with a "reply unknown" detail. Same fire-and-forget
 * semantics as the other authenticated sends.
 */

int veil_send_reply(VeilApp *app,
                    uint64_t reply_id,
                    const uint8_t *data,
                    size_t len,
                    char **err_out)
;

/**
 * Install a recv handler that calls `cb` for every incoming datagram on this
 * app. Returns [`VEIL_OK`] once the handler is installed.
 *
 * A single persistent recv loop runs on the runtime and dispatches to the
 * currently-installed callback. Calling `set_recv_handler` again REPLACES the
 * handler (the callback is swapped atomically; no in-flight messages are
 * lost, and the call succeeds on every invocation). [`veil_send`] continues
 * to work throughout via the bundle reference.
 *
 * `user` is an opaque pointer passed to every callback invocation. The caller
 * MUST keep EVERY `user` it ever passes to `set_recv_handler` valid until
 * [`veil_app_close`] — NOT merely until the next `set_recv_handler` call.
 * Replacing the handler swaps the slot, but a message dispatch that already
 * copied the *previous* `(cb, user)` may still be running on a runtime thread
 * when the replacing call returns; that in-flight callback dereferences the
 * old `user`. There is no signal back to the caller for when such a dispatch
 * completes, so the only safe contract is "valid until close". (This is the
 * same exposure the pre-swap design had — `abort()` was never synchronous —
 * now stated precisely.)
 */
 int veil_app_set_recv_handler(VeilApp *app, VeilRecvCb cb, void *user, char **err_out) ;

/**
 * Open a reliable byte-stream to a remote endpoint.
 */

VeilStreamFfi *veil_stream_open(VeilApp *app,
                                const uint8_t *dst_node_id,
                                const uint8_t *dst_app_id,
                                uint32_t dst_endpoint_id,
                                uint32_t initial_window,
                                char **err_out)
;

/**
 * Block up to `timeout_ms` for a remote peer to open an inbound byte-stream to
 * a bound endpoint. On success returns an owned stream handle (drive it with
 * `veil_stream_read`/`veil_stream_write`/`veil_stream_close`) and writes the
 * initiator's 32-byte node_id into `out_src_node_id` (caller-allocated, 32 B).
 * Returns NULL on TIMEOUT with NO error written, so the caller can poll in a
 * loop; returns NULL WITH an error on a fatal condition (app closed / the
 * inbound-stream channel went away). This is the receive-side counterpart to
 * `veil_stream_open` — without it an inbound stream is stranded in the SDK.
 */

VeilStreamFfi *veil_stream_accept(VeilApp *app,
                                  uint64_t timeout_ms,
                                  uint8_t *out_src_node_id,
                                  char **err_out)
;

/**
 * XChaCha20-Poly1305 AEAD seal of `plaintext` under a 32-byte `key` + 24-byte
 * `nonce` (no associated data). Writes the ciphertext+tag to a freshly
 * allocated buffer (`*out_buf`/`*out_len`); free it with `veil_free_buf`. Used
 * by the host to encrypt large file blobs stored OUTSIDE the deniable container
 * under a key derived from the unlocked container — the blob is opaque
 * ciphertext at rest. Crypto stays in audited Rust; the key never persists.
 */

int veil_seal(const uint8_t *key,
              const uint8_t *nonce,
              const uint8_t *plaintext,
              size_t plaintext_len,
              uint8_t **out_buf,
              size_t *out_len,
              char **err_out)
;

/**
 * Inverse of [`veil_seal`]: XChaCha20-Poly1305 open. Fails (VEIL_ERR) on a bad
 * key/nonce/tag. Output (plaintext) buffer freed via `veil_free_buf`.
 */

int veil_unseal(const uint8_t *key,
                const uint8_t *nonce,
                const uint8_t *ciphertext,
                size_t ciphertext_len,
                uint8_t **out_buf,
                size_t *out_len,
                char **err_out)
;

/**
 * Write `len` bytes to the stream.
 */
 int veil_stream_write(VeilStreamFfi *stream, const uint8_t *data, size_t len, char **err_out) ;

/**
 * Read up to `cap` bytes from the stream into `buf`. Returns the
 * number of bytes read, 0 on EOF, or a negative error code.
 */
 ssize_t veil_stream_read(VeilStreamFfi *stream, uint8_t *buf, size_t cap, char **err_out) ;

/**
 * Close the stream and free its resources. Safe to call on NULL.
 */
 void veil_stream_close(VeilStreamFfi *stream) ;

/**
 * Read the daemon's relay-side X25519 public key into `out_pubkey_32`.
 * This is the seal-target for push-envelopes — apps that want to
 * register a sealed FCM/APNs token [`veil_set_push_envelope`]
 * must seal it against THIS exact key.
 *
 * Returns:
 * [`VEIL_OK`] — `out_pubkey_32` populated with 32 bytes.
 * [`VEIL_RELAY_X25519_UNAVAILABLE`] — daemon is not relay-
 * capable; pick a different relay or skip push-wake.
 * other negative codes — connection/protocol errors.
 *
 * Stable for the lifetime of the daemon process: the relay X25519 key
 * is persisted on disk (`<veil_dir>/device_anonymity_x25519_sk.bin`)
 * and survives restarts. Apps can cache the result.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*` from `veil_connect`.
 * `out_pubkey_32` must point to writable storage for at least 32 bytes.
 */
 int veil_get_relay_x25519_pubkey(VeilHandle *handle, uint8_t *out_pubkey_32, char **err_out) ;

/**
 * Resolve ANOTHER node's relay X25519 KEM public key by its `node_id`, over the
 * DHT. Unlike [`veil_get_relay_x25519_pubkey`] (which returns the LOCAL node's
 * own key), this asks the daemon to fetch + verify the target's signed
 * `RelayKeyRecord` against its identity document. Lets a receiver advertise an
 * always-on third-party relay as its mailbox host knowing only its node_id.
 *
 * Returns:
 * [`VEIL_OK`] — `out_pubkey_32` populated with the verified 32-byte key.
 * [`VEIL_RELAY_X25519_UNAVAILABLE`] — unresolved (DHT miss / no record /
 *   verification failed); the node advertises no relay key.
 * other negative codes — connection/protocol errors.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*` from `veil_connect`.
 * `node_id_32` must point to 32 readable bytes; `out_pubkey_32` to 32 writable.
 */

int veil_lookup_relay_x25519(VeilHandle *handle,
                             const uint8_t *node_id_32,
                             uint8_t *out_pubkey_32,
                             char **err_out)
;

/**
 * Register this node as a LOCATION-anonymous (onion) service: the daemon picks
 * relays, builds an onion circuit to a rendezvous relay (which never learns
 * this node's location), and publishes the ad so clients can reach this node by
 * its identity. `hop_count` is clamped to ≥ 2 by the daemon (2 = node→mid→relay).
 *
 * `VEIL_OK` once the daemon accepts; `VEIL_ERR` with a detail otherwise (e.g.
 * no relays available yet — retry after a short back-off). Connection-level:
 * hosts the whole node as a service; any bound endpoint can then receive.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*` from `veil_connect`.
 */
 int veil_register_onion_service(VeilHandle *handle, uint32_t hop_count, char **err_out) ;

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Register a location-anonymous service under a caller-owned random Ed25519
 * seed rather than the node's sovereign key. The seed buffer is writable and
 * is ZEROED immediately on every post-validation path. On success writes the
 * corresponding 32-byte public service identity to `out_identity_vk`; this is
 * the only address that belongs in a public capability link. The blinded DHT
 * descriptor and rendezvous advert contain no sovereign public key/node id.
 *
 * Embedded-node only: the service circuit lives in this process's node
 * runtime. Re-register the same seed after restart; registration is idempotent
 * within a descriptor period. At most the runtime's bounded hosted-service cap
 * may be active.
 *
 * # Safety
 * `identity_seed_32` must point to 32 WRITABLE bytes; they are zeroized.
 * `out_identity_vk_32` must point to 32 writable bytes.
 */

int veil_register_ephemeral_onion_service_zeroize(VeilHandle *handle,
                                                  uint8_t *identity_seed_32,
                                                  uint32_t hop_count,
                                                  uint8_t *out_identity_vk_32,
                                                  char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Provider-slotted form of
 * [`veil_register_ephemeral_onion_service_zeroize`]. Linked devices hosting
 * the same capability seed must use distinct slots in `0..8`; the runtime
 * publishes a collision-free descriptor for that slot while retaining the
 * legacy descriptor for old resolvers.
 */

int veil_register_ephemeral_onion_service_zeroize_v2(VeilHandle *handle,
                                                     uint8_t *identity_seed_32,
                                                     uint32_t hop_count,
                                                     uint8_t provider_slot,
                                                     uint8_t *out_identity_vk_32,
                                                     char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Stop maintaining one caller-owned ephemeral onion service. Idempotent:
 * unknown/already-withdrawn public keys return `VEIL_OK` too, so this local
 * lifecycle API never becomes a remote existence oracle. DHT ciphertext and
 * the circuit age out naturally; the host must reject capability requests as
 * soon as its encrypted registry marks the share revoked.
 */

int veil_withdraw_ephemeral_onion_service(VeilHandle *handle,
                                          const uint8_t *identity_vk_32,
                                          char **err_out)
;
#endif

/**
 * Register a PLAIN rendezvous-publisher entry (mailbox-by-discovery): the
 * daemon's maintenance tick signs + publishes a v5 `RendezvousAd` under THIS
 * node's real id at `rendezvous_node_id`'s rendezvous slot, advertising the
 * relay's KEM key so a sender resolving the ad (`veil_lookup_rendezvous_replicas`)
 * can anonymously deposit a mailbox PUT at the relay. Replaces any existing
 * entry with the same `(rendezvous_node_id, auth_cookie)`.
 *
 * `relay_kem_algo` is the KEM tag (`0` = X25519); `relay_kem_pk` / `kem_len`
 * the relay's KEM pubkey (32-byte X25519 for algo 0; obtain a self-relay key
 * via `veil_get_relay_x25519_pubkey`). Pass `kem_len = 0` to advertise no key.
 *
 * `VEIL_OK` once the daemon records the entry; `VEIL_ERR` otherwise.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*`. `rendezvous_node_id` must be readable
 * for 32 bytes, `auth_cookie` for 16. `relay_kem_pk` must be readable for
 * `kem_len` bytes (or NULL iff `kem_len == 0`).
 */

int veil_register_rendezvous_publisher(VeilHandle *handle,
                                       const uint8_t *rendezvous_node_id,
                                       const uint8_t *auth_cookie,
                                       uint64_t validity_window_secs,
                                       uint8_t relay_kem_algo,
                                       const uint8_t *relay_kem_pk,
                                       size_t kem_len,
                                       char **err_out)
;

/**
 * Send `data` to a LOCATION-anonymous (onion) service addressed by its Ed25519
 * IDENTITY key (`service_identity_vk`, 32 bytes — a `.onion`-like handle), NOT
 * its node_id. The daemon resolves the service's unlinkable per-period blinded
 * descriptor, decrypts it (the caller knows the identity), and routes the
 * message over an onion circuit. `hop_count` is clamped to ≥ 2 by the daemon.
 *
 * `VEIL_OK` once the daemon hands the cell to the first hop (fire-and-forget —
 * NOT delivery-confirmed); `VEIL_ERR` with a detail otherwise (e.g. no
 * resolvable descriptor — the service is offline or hasn't published).
 *
 * # Safety
 * `handle` must be a live `VeilHandle*`; `service_identity_vk` and
 * `target_app_id` must each be readable for 32 bytes; `data` must be readable
 * for `len` bytes (or NULL iff `len == 0`).
 */

int veil_send_to_onion_service(VeilHandle *handle,
                               const uint8_t *service_identity_vk,
                               const uint8_t *target_app_id,
                               uint32_t target_endpoint_id,
                               uint32_t hop_count,
                               const uint8_t *data,
                               size_t len,
                               char **err_out)
;

/**
 * Like [`veil_send_to_onion_service`], but UNAUTHENTICATED: the service receives
 * `src_node_id = [0;32]` and never learns who sent the message. Combined with the
 * unlinkable descriptor, neither the relays, the rendezvous relay, nor the
 * service learn the sender's location or identity. `src_app_id` (32 bytes) rides
 * inside the sealed payload for the service's app-level routing only.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*`; `service_identity_vk`, `target_app_id`,
 * and `src_app_id` must each be readable for 32 bytes; `data` must be readable
 * for `len` bytes (or NULL iff `len == 0`).
 */

int veil_send_to_onion_service_anonymous(VeilHandle *handle,
                                         const uint8_t *service_identity_vk,
                                         const uint8_t *target_app_id,
                                         uint32_t target_endpoint_id,
                                         const uint8_t *src_app_id,
                                         uint32_t hop_count,
                                         const uint8_t *data,
                                         size_t len,
                                         char **err_out)
;

/**
 * DIRECT (non-rendezvous) sender-anonymous send to a KNOWN peer addressed by its
 * `(target_node_id, target_x25519_pk)` (each 32 bytes). The source-routed onion
 * hides the sender's location from every relay; the receiver sees
 * `src_node_id = [0;32]` and never learns who sent it. For reaching a peer whose
 * transport node_id + anonymity x25519 the caller already knows — NOT a
 * location-anonymous service (use `veil_send_to_onion_service` for those).
 * `hop_count` is clamped to ≥ 1 by the daemon.
 *
 * `VEIL_OK` once handed to the first hop (fire-and-forget, NOT delivery-
 * confirmed); `VEIL_ERR` with a detail otherwise.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*`; `target_node_id`, `target_x25519_pk`,
 * `target_app_id`, and `src_app_id` must each be readable for 32 bytes; `data`
 * must be readable for `len` bytes (or NULL iff `len == 0`).
 */

int veil_send_anonymous_direct(VeilHandle *handle,
                               const uint8_t *target_node_id,
                               const uint8_t *target_x25519_pk,
                               const uint8_t *target_app_id,
                               uint32_t target_endpoint_id,
                               const uint8_t *src_app_id,
                               uint32_t hop_count,
                               const uint8_t *data,
                               size_t len,
                               char **err_out)
;

/**
 * Deposit `blob` for an offline `receiver_id` at the daemon's mailbox
 *. No `auth_cookie` required.
 *
 * `push_envelope` / `push_envelope_len` are optional (pass NULL / 0
 * to skip). When supplied and storage succeeds, the relay fires a
 * wake-push to the receiver after this call returns.
 *
 * Returns one of `VEIL_MAILBOX_PUT_*` (≥0) on a structured outcome
 * or a negative `VEIL_ERR_*` on transport / argument errors.
 * `out_evicted` (may be NULL) receives the count of older blobs the
 * relay had to evict to fit (only nonzero on `VEIL_MAILBOX_PUT_STORED`).
 *
 * # Safety
 * `handle` must be a live `VeilHandle*` from `veil_connect`.
 * `receiver_id`, `content_id`, `sender_id` must each point to ≥32
 * readable bytes. `blob` must point to ≥`blob_len` readable bytes
 * (or NULL if `blob_len == 0`). `push_envelope` must point to
 * ≥`push_envelope_len` readable bytes (or NULL if 0).
 */

int veil_mailbox_put(VeilHandle *handle,
                     const uint8_t *receiver_id,
                     const uint8_t *content_id,
                     const uint8_t *sender_id,
                     const uint8_t *blob,
                     size_t blob_len,
                     const uint8_t *push_envelope,
                     size_t push_envelope_len,
                     uint32_t *out_evicted,
                     char **err_out)
;

/**
 * `veil_mailbox_put` variant that forwards
 * a receiver-signed capability token. Required when targeting a
 * relay running with `MailboxConfig::require_capability_token = true`.
 *
 * `capability_token` / `capability_token_len` are the bytes obtained
 * from the receiver's `RendezvousAd` (surfaced on the SDK side as
 * `RendezvousReplicaInfo::capability_token`). Pass `NULL` / `0` to
 * fall back to the no-token path (equivalent to calling the original
 * `veil_mailbox_put`). Maximum length is
 * [`veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES`].
 *
 * All other parameters and safety contracts are identical to
 * [`veil_mailbox_put`].
 */

int veil_mailbox_put_with_capability(VeilHandle *handle,
                                     const uint8_t *receiver_id,
                                     const uint8_t *content_id,
                                     const uint8_t *sender_id,
                                     const uint8_t *blob,
                                     size_t blob_len,
                                     const uint8_t *push_envelope,
                                     size_t push_envelope_len,
                                     const uint8_t *capability_token,
                                     size_t capability_token_len,
                                     uint32_t *out_evicted,
                                     char **err_out)
;

/**
 * `veil_mailbox_put` variant that forwards BOTH a receiver-signed
 * capability token AND the receiver's sealed wake-HMAC envelope (Epic
 * 489.10 slice 4.3.4).  This is the export a mobile sender uses to
 * forward the wake-HMAC envelope so the relay can mint a receiver-
 * verifiable wake-HMAC tag on the push.
 *
 * `capability_token` / `capability_token_len` are as in
 * [`veil_mailbox_put_with_capability`] (pass `NULL` / `0` to skip).
 *
 * `wake_hmac_envelope` / `wake_hmac_envelope_len` are the bytes the
 * receiver published in its `RendezvousAd` (surfaced SDK-side as
 * `RendezvousReplicaInfo::wake_hmac_envelope` and returned over the C
 * ABI by [`veil_lookup_rendezvous_replicas`]).  Pass `NULL` / `0`
 * to fall back to an unauthenticated wake (equivalent to
 * [`veil_mailbox_put_with_capability`]).  Maximum length is
 * [`veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES`]; overflow returns
 * `VEIL_ERR_INVALID_ARG`.
 *
 * All other parameters and safety contracts are identical to
 * [`veil_mailbox_put`].  `wake_hmac_envelope` MUST point to
 * ≥`wake_hmac_envelope_len` readable bytes (or NULL if 0).
 */

int veil_mailbox_put_with_wake_hmac(VeilHandle *handle,
                                    const uint8_t *receiver_id,
                                    const uint8_t *content_id,
                                    const uint8_t *sender_id,
                                    const uint8_t *blob,
                                    size_t blob_len,
                                    const uint8_t *push_envelope,
                                    size_t push_envelope_len,
                                    const uint8_t *capability_token,
                                    size_t capability_token_len,
                                    const uint8_t *wake_hmac_envelope,
                                    size_t wake_hmac_envelope_len,
                                    uint32_t *out_evicted,
                                    char **err_out)
;

/**
 * Look up candidate mailbox-relays for `receiver_id` and return each
 * verified replica's relay id, ad-expiry, and the three sealed blobs a
 * sender forwards on the put: `push_envelope`, `capability_token`, and
 * (Epic 489.10 slice 4.3.4 — the whole point of this export) the
 * `wake_hmac_envelope`.  Round-trips to the daemon via IPC; resolves
 * the receiver's `RendezvousAd` from the local DHT cache.
 *
 * `max_replicas == 0` means "all up to the daemon's cap"
 * (`MAX_RENDEZVOUS_REPLICAS = 8`; single-key publication returns ≤ 1).
 *
 * On success returns [`VEIL_OK`] (0) and writes a heap-allocated,
 * length-prefixed buffer to `*out_buf` (its length to `*out_len`).  The
 * caller OWNS that buffer and MUST free it with
 * [`veil_free_replica_buf`] (NOT `free` / `veil_free_string`).
 * An empty result (no cached ad / no replicas) still returns
 * [`VEIL_OK`] with `*out_len == 4` (just the `count = 0` header) and
 * a non-NULL `*out_buf` the caller must still free.  On error returns a
 * negative `VEIL_ERR_*`, sets `*err_out`, and leaves `*out_buf =
 * NULL` / `*out_len = 0`.
 *
 * Wire layout (all integers little-endian) — hand this to the Dart side:
 *   count: u32
 *   then `count` entries, each:
 *     relay_node_id:          [u8; 32]
 *     valid_until_unix:       u64
 *     push_envelope_len:      u16, push_envelope:      [u8; len]
 *     capability_token_len:   u16, capability_token:   [u8; len]
 *     wake_hmac_envelope_len: u16, wake_hmac_envelope: [u8; len]
 *     rendezvous_kem_algo:    u8
 *     rendezvous_kem_pk_len:  u16, rendezvous_kem_pk:  [u8; len]
 * (Per-blob length is u16; every blob is backend-capped well under
 * 64 KiB — push ≤ 512 B, cap-token / wake-HMAC / relay-KEM-pk likewise.)
 *
 * # Safety
 * `handle` MUST be a live `VeilHandle*` from `veil_connect`.
 * `receiver_id` MUST point to ≥32 readable bytes.  `out_buf` and
 * `out_len` MUST be valid, writable pointers.
 */

int veil_lookup_rendezvous_replicas(VeilHandle *handle,
                                    const uint8_t *receiver_id,
                                    uint8_t max_replicas,
                                    uint8_t **out_buf,
                                    size_t *out_len,
                                    char **err_out)
;

/**
 * Free a replica buffer returned by
 * [`veil_lookup_rendezvous_replicas`].  `ptr` / `len` MUST be the
 * exact `*out_buf` / `*out_len` pair that call produced — passing any
 * other pointer, or a mismatched length, is undefined behaviour.  Safe
 * to call on `ptr == NULL` (no-op).
 *
 * # Safety
 * `ptr` MUST be either NULL or a pointer previously returned by
 * `veil_lookup_rendezvous_replicas` that has NOT already been freed,
 * and `len` MUST equal the length that call wrote.
 */
 void veil_free_replica_buf(uint8_t *ptr, size_t len) ;

/**
 * Normalize a candidate nickname. On VEIL_OK, `*out_buf`/`*out_len` hold the
 * normalized ASCII bytes (free with `veil_free_buf`); returns
 * VEIL_ERR_INVALID_ARG if the name cannot be normalized (bad charset/length).
 */

int veil_nickname_normalize(const uint8_t *name,
                            size_t name_len,
                            uint8_t **out_buf,
                            size_t *out_len,
                            char **err_out)
;

/**
 * The cumulative PoW weight a name of this length must carry (the anti-squat
 * floor) — the host mines until it reaches this. 0 on a bad name.
 */
 uint64_t veil_nickname_length_floor(const uint8_t *name, size_t name_len) ;

/**
 * Mine PoW seeds for `name` under `owner_node_id`, continuing from
 * `prior_seeds` (a concatenation of 32-byte seeds; may be NULL/0), until the
 * cumulative weight reaches `target_weight` or `max_hashes` is spent. The
 * call is bounded by `max_hashes` — the host loops (fresh call = fresh random
 * salt) and cancels by simply not calling again, threading the returned seed
 * set back in as `prior_seeds`.
 *
 * On VEIL_OK, `*out_buf`/`*out_len` hold a serialized outcome (free with
 * `veil_free_buf`): `hit_target:u8 | weight:u64 LE | hashes:u64 LE |
 * seed_count:u32 LE | seeds (count*32)`.
 */

int veil_nickname_mine(const uint8_t *name,
                       size_t name_len,
                       const uint8_t *owner_node_id,
                       const uint8_t *prior_seeds,
                       size_t prior_seeds_len,
                       uint64_t target_weight,
                       uint64_t max_hashes,
                       uint8_t **out_buf,
                       size_t *out_len,
                       char **err_out)
;

/**
 * Verify a serialized nickname record (from `NicknameRecord::to_bytes`).
 * Returns VEIL_OK if valid; VEIL_ERR with a reason in `err_out` otherwise.
 */
 int veil_nickname_verify(const uint8_t *record, size_t record_len, char **err_out) ;

/**
 * Free a callback buffer handed to a recv- or event-handler callback.
 * `ptr` MUST be the base pointer the callback received — for recv that is the
 * `src_node_id` pointer (layout `[node_id(32) | app_id(32) | data]`); for
 * events it is the `payload` pointer. `len` MUST be the total buffer length.
 * Safe to call on `ptr == NULL` (no-op).
 *
 * The host must call this exactly once per callback invocation that received a
 * non-NULL pointer, after copying the bytes it needs.
 *
 * # Safety
 * `ptr` MUST be NULL or the exact base pointer a recv/event callback received
 * and has NOT already freed, and `len` MUST equal that buffer's total length.
 */
 void veil_free_buf(uint8_t *ptr, size_t len) ;

/**
 * Seal `data` for `recipient`'s `(app_id, endpoint_id)` into an offline-mailbox
 * blob (node-side E2E crypto: sign + DHT-resolve the recipient cert +
 * fan-out-encrypt). On success returns [`VEIL_OK`] and writes a heap-allocated
 * buffer to `*out_buf` (its length to `*out_len`); free it with
 * [`veil_free_buf`]. On error returns a negative `VEIL_ERR_*`, sets `*err_out`,
 * and leaves `*out_buf = NULL` / `*out_len = 0`.
 *
 * `recipient` and `app_id` MUST point to ≥32 readable bytes; `data` to
 * ≥`data_len` (may be NULL iff `data_len == 0`). `out_buf` / `out_len` MUST be
 * valid writable pointers.
 */

int veil_mailbox_seal(VeilHandle *handle,
                      const uint8_t *recipient,
                      const uint8_t *app_id,
                      uint32_t endpoint_id,
                      const uint8_t *data,
                      size_t data_len,
                      uint8_t **out_buf,
                      size_t *out_len,
                      char **err_out)
;

/**
 * Open + verify a fetched offline-mailbox `blob`, decrypting under our current
 * cert version `our_cert_version`. The sender is RECOVERED from the blob's
 * sidecar (the anonymous mailbox deposit carries no usable wire sender) and,
 * once crypto-verified, written to `out_sender` (32 bytes). On success returns
 * [`VEIL_OK`], writes the verified destination app id to `out_app_id` (32 bytes)
 * and the endpoint id to `*out_endpoint_id`. A heap-allocated data buffer is written
 * to `*out_data` (length to `*out_data_len`); free with [`veil_free_buf`].
 *
 * `blob` MUST point to ≥`blob_len`. `out_sender` / `out_app_id` MUST each point
 * to ≥32 writable bytes; the other out-pointers MUST be writable.
 */

int veil_mailbox_open(VeilHandle *handle,
                      uint64_t our_cert_version,
                      const uint8_t *blob,
                      size_t blob_len,
                      uint8_t *out_sender,
                      uint8_t *out_app_id,
                      uint32_t *out_endpoint_id,
                      uint8_t **out_data,
                      size_t *out_data_len,
                      char **err_out)
;

/**
 * Fetch all blobs currently stored for `receiver_id`. `auth_cookie`
 * must match a previously-registered rendezvous-publisher entry.
 *
 * On success returns ≥0 (the count of blobs returned) and populates
 * `out_blobs` (allocated via `veil_mailbox_blobs_alloc`-style
 * caller-managed buffer). Apps fetch blobs into a length-aware
 * container by calling [`veil_mailbox_fetch_count`] first to size
 * their array, then [`veil_mailbox_fetch_into`] to copy.
 *
 * Two-call API avoids hidden allocations through the FFI boundary —
 * callers control all memory lifetimes.
 *
 * # Safety
 * `handle`, `receiver_id` (32 B), `auth_cookie` (16 B), `out_count`
 * must all be valid pointers. `out_count` receives the count.
 */

int veil_mailbox_fetch_count(VeilHandle *handle,
                             const uint8_t *receiver_id,
                             const uint8_t *auth_cookie,
                             uint32_t *out_count,
                             char **err_out)
;

/**
 * Copy the most-recently-fetched blob list (cached by
 * [`veil_mailbox_fetch_count`]) into caller-provided buffers.
 *
 * `descriptors_out` must point to ≥`max_descriptors` `VeilMailboxBlob`
 * slots. `blob_buf` is a contiguous byte buffer where blob payloads
 * are concatenated; descriptors' `blob` pointers index into it.
 * `blob_buf_len` must be ≥ sum of all blob_len; if too small, returns
 * `VEIL_ERR_INVALID_ARG` and the cached fetch list is kept (caller
 * can re-call with a larger buffer without re-fetching).
 *
 * On success returns the count of descriptors written and clears the
 * cache.
 *
 * # Safety
 * All output pointers must be writable for at least the documented
 * extents. After this call, the descriptor `blob` pointers are valid
 * only as long as `blob_buf` is alive and unmodified.
 */

int veil_mailbox_fetch_into(VeilHandle *handle,
                            VeilMailboxBlob *descriptors_out,
                            uint32_t max_descriptors,
                            uint8_t *blob_buf,
                            size_t blob_buf_len,
                            char **err_out)
;

/**
 * Acknowledge end-to-end receipt of a mailbox blob. Daemon deletes
 * the blob and frees its quota slice. Idempotent.
 *
 * Returns 1 if the blob was removed, 0 if no-op (already acked /
 * not present / wrong cookie), or negative on transport error.
 *
 * # Safety
 * `handle` must be a live `VeilHandle*`; `receiver_id` (32 B)
 * `content_id` (32 B), `auth_cookie` (16 B) must point to readable
 * storage of at least the documented length.
 */

int veil_mailbox_ack(VeilHandle *handle,
                     const uint8_t *receiver_id,
                     const uint8_t *content_id,
                     const uint8_t *auth_cookie,
                     char **err_out)
;

/**
 * Read the daemon's own `node_id` (32 bytes) into `out`. Returns
 * [`VEIL_OK`] or a negative error code. Round-trips to the daemon
 * via the IPC `GetNodeIdentity` request — call once at app startup
 * and cache; the value never changes for the lifetime of the daemon
 * process.
 *
 * Useful for displaying the user's identity in UI ("you are: 0xABC…")
 * without scraping `VEIL_LOCAL_NODE_ID` env or shelling out to
 * `veil-cli node show`.
 */
 int veil_get_node_id(VeilHandle *handle, uint8_t *out_node_id_32, char **err_out) ;

/**
 * Snapshot the daemon's current mobile/battery state into `out`.
 * Returns [`VEIL_OK`] or a negative error code. Round-trips to the
 * daemon via IPC `GetMobileStatus`; cheap (~1 ms) so apps can call
 * this every few seconds for live UI updates.
 */
 int veil_get_mobile_status(VeilHandle *handle, VeilMobileStatus *out, char **err_out) ;

/**
 * Decode a bootstrap-invite URI and register the peer for outbound dial
 *. Forwards the URI bytes to the daemon, which decodes
 * them through the standard plain / encrypted / signed-invite paths.
 *
 * `uri` is `(ptr, len)` UTF-8 (no NUL terminator). `password` and
 * `expected_issuer_pk` may be NULL (for plain URIs / unsigned) — pass a NULL
 * pointer (length ignored) — or `(ptr, len)` UTF-8.
 *
 * On success / `VEIL_JOIN_ALREADY_REGISTERED`, `out_node_id_32` is
 * populated with the decoded peer's node_id. On any error status it is
 * zero-filled. `out_status` always carries the wire-byte status code
 * (one of `VEIL_JOIN_*`). Returns [`VEIL_OK`] iff the IPC
 * round-trip itself succeeded; the actual decode/verify outcome lives
 * in `out_status`.
 *
 * Because the outcome is in `out_status`, this call returns `VEIL_OK`
 * for *every* completed round-trip — including failure statuses
 * (`VEIL_JOIN_PASSWORD_WRONG`, …) and successes that carry an
 * informational note. In all of those cases `*err_out` is set to the
 * detail string for `out_status`, so `*err_out` may be non-NULL even
 * on `VEIL_OK`. Callers MUST free `*err_out` with `veil_free_string`
 * whenever it is non-NULL — see the crate-level "Error model".
 */

int veil_join_bootstrap_uri(VeilHandle *handle,
                            const uint8_t *uri,
                            uintptr_t uri_len,
                            const uint8_t *password,
                            uintptr_t password_len,
                            const uint8_t *expected_issuer_pk,
                            uintptr_t expected_issuer_pk_len,
                            uint8_t *out_node_id_32,
                            uint8_t *out_status,
                            char **err_out)
;

/**
 * Build a bootstrap-invite URI from the daemon's own identity and
 * listen-address config (Epic 489.7 generator side, "share my invite"
 * flow).  Output goes to a caller-owned heap-allocated UTF-8 string
 * the FFI returns through `out_uri` — caller MUST free it via
 * [`veil_free_string`] after consuming.
 *
 * `password` may be `NULL` (plain `veil:bootstrap?…` URI) — pass a NULL
 * pointer (length ignored) — or `(ptr, len)` UTF-8 (encrypted `veil:pair?…`
 * envelope). Empty / whitespace-only passwords are rejected with status
 * `VEIL_CREATE_INVITE_BAD_PASSWORD` so callers can re-prompt rather
 * than emitting an envelope encrypted under a trivial key.
 *
 * On non-OK status, `out_uri` is set to NULL and `err_out` (if non-NULL)
 * carries a human-readable detail message.
 *
 * Returns [`VEIL_OK`] iff the IPC round-trip itself succeeded; the
 * actual outcome lives in `out_status` (one of `VEIL_CREATE_INVITE_*`).
 *
 * # Safety
 * `handle` must be a live `VeilHandle*` from `veil_connect`.
 * `out_status` must be writable.  `out_uri` must be writable; on
 * success it receives a pointer to a malloc'd NUL-terminated UTF-8
 * string — caller frees with [`veil_free_string`].
 */

int veil_create_bootstrap_invite(VeilHandle *handle,
                                 const uint8_t *password,
                                 uintptr_t password_len,
                                 uint8_t *out_status,
                                 char **out_uri,
                                 char **err_out)
;

/**
 * Snapshot the daemon's currently-active peer sessions. Calls `cb`
 * once per peer, passing `user` through unchanged. Returns
 * [`VEIL_OK`] on success or a negative error code.
 *
 * The list is bounded at 256 entries server-side — apps with thousands
 * of active sessions on a relay should treat the result as a snapshot
 * (not exhaustive).
 */
 int veil_peers_list(VeilHandle *handle, VeilPeerCb cb, void *user, char **err_out) ;

/**
 * Tell the daemon what background-mode tier the app is currently in.
 * Daemon scales keepalive cadence (and, in a future revision, suspends
 * route probes on `LowPower`) so sessions survive OS-level Doze / iOS
 * background-task suspension.
 *
 * `mode` must be one of `VEIL_BG_FOREGROUND`, `VEIL_BG_ACTIVE`
 * `VEIL_BG_LOWPOWER`. Returns [`VEIL_OK`] or a negative error.
 */
 int veil_set_background_mode(VeilHandle *handle, int mode, char **err_out) ;

/**
 * Tell the daemon that the local network attachment changed. Triggers
 * an eager gateway-reconnect attempt so the app doesn't have to wait
 * for the keepalive timeout to detect that warm sessions are doomed.
 *
 * `kind` must be one of `VEIL_NET_*`. `mtu_hint = 0` means "use
 * default" (advisory only).
 */
 int veil_notify_network_changed(VeilHandle *handle, int kind, uint16_t mtu_hint, char **err_out) ;

/**
 * Register a sealed FCM/APNs push-token envelope on a rendezvous-publisher
 * entry.
 *
 * `rendezvous_node_id` (32 bytes) and `auth_cookie` (16 bytes) must match an
 * entry the daemon has already registered via
 * `register_rendezvous_publisher_with_push`. `envelope` carries opaque
 * sealed bytes (use `veil_anonymity::push_envelope::seal_push_envelope`
 * client-side BEFORE calling this — daemon never sees raw token).
 * `envelope_len = 0` clears the registration.
 *
 * Returns one of:
 * * [`VEIL_PUSH_OK`] — envelope set / cleared successfully.
 * * [`VEIL_PUSH_NO_RENDEZVOUS`] — no matching entry registered (caller
 *   should call register_rendezvous_publisher_with_push first OR ignore
 *   if the daemon isn't running rendezvous).
 * * [`VEIL_PUSH_TOO_LARGE`] — envelope exceeds 512 B cap.
 * * [`VEIL_ERR`] / [`VEIL_ERR_INVALID_ARG`] / [`VEIL_ERR_REENTRANT`]
 *   per the standard FFI error model.
 *
 * # Safety
 *
 * `rendezvous_node_id` MUST point to an exactly 32-byte buffer. `auth_cookie`
 * to exactly 16. `envelope` to a buffer of length `envelope_len`. All
 * pointers may be NULL only when their corresponding length is 0. Caller
 * retains ownership of all input buffers; the function copies the envelope
 * internally (returning before write completes to the daemon's state).
 */

int veil_set_push_envelope(VeilHandle *handle,
                           const uint8_t *rendezvous_node_id,
                           const uint8_t *auth_cookie,
                           const uint8_t *envelope,
                           size_t envelope_len,
                           char **err_out)
;

/**
 * SHA-256 of `data` (`len` bytes) written to the caller-owned 32-byte
 * buffer `out32`.  Stateless — does not need a `VeilHandle`.  Exposed for
 * the app's content-manifest hashing: Dart's pure `package:crypto` digest
 * runs at ~35 MB/s on a phone, so hashing a large file before its offer
 * dominated the send latency; the native digest is ~30-50x faster.
 * Returns [`VEIL_OK`] or [`VEIL_ERR_INVALID_ARG`].
 *
 * # Safety
 *
 * `data` must point to `len` readable bytes (or be NULL only when `len`
 * is 0).  `out32` MUST point to at least 32 writable bytes.
 */
 int veil_sha256(const uint8_t *data, size_t len, uint8_t *out32) ;

/**
 * Seal a raw FCM/APNs token to the push-relay identified by a 32-byte
 * X25519 public key.  Stateless — does not need an `VeilHandle`.
 * The relay pubkey is typically obtained from `veil_get_node_id` of
 * the relay daemon (which surfaces it as
 * [`veil_get_relay_x25519_pubkey`]), then transferred OOB to the
 * sender (typically baked into the app via a build-time constant
 * per push-relay deployment).
 *
 * Output goes to caller-owned buffer `out_buf` of length `out_buf_cap`.
 * On success `*out_len` receives the actual sealed length (always
 * `token_len + VEIL_PUSH_ENVELOPE_OVERHEAD`).  Returns
 * [`VEIL_OK`] / [`VEIL_PUSH_TOO_LARGE`] / [`VEIL_ERR_INVALID_ARG`]
 * / [`VEIL_ERR`].
 *
 * # Safety
 *
 * `token` must point to `token_len` readable bytes (or NULL if 0).
 * `relay_pk_32` MUST point to exactly 32 readable bytes.  `out_buf`
 * MUST be writable for at least `out_buf_cap` bytes.  `out_len` MUST
 * be a writable pointer.
 */

int veil_seal_push_envelope(const uint8_t *token,
                            size_t token_len,
                            const uint8_t *relay_pk_32,
                            uint8_t *out_buf,
                            size_t out_buf_cap,
                            size_t *out_len,
                            char **err_out)
;

/**
 * Upload a sealed wake-HMAC envelope to the daemon's rendezvous-publisher
 * entry matched by `(rendezvous_node_id, auth_cookie)` (Epic 489.10
 * slice 4.3.4 — analog to [`veil_set_push_envelope`]).
 *
 * Empty `envelope` (`envelope_len == 0`) clears the registration —
 * the receiver falls back to the legacy rate-limited wake path.  Use
 * when toggling HMAC authentication on/off.
 *
 * Returns:
 * * [`VEIL_PUSH_OK`] — envelope set / cleared successfully.
 * * [`VEIL_PUSH_NO_RENDEZVOUS`] — no matching publisher entry
 *   (caller should `register_rendezvous_publisher` first).
 * * [`VEIL_PUSH_TOO_LARGE`] — `envelope_len` exceeds
 *   `MAX_WAKE_HMAC_ENVELOPE_BYTES`.
 * * Other negative codes — connection / protocol errors.
 *
 * # Safety
 *
 * `handle` MUST be a live `VeilHandle*`.  `rendezvous_node_id`
 * MUST point to 32 readable bytes.  `auth_cookie` MUST point to 16
 * readable bytes.  `envelope` MUST point to `envelope_len` readable
 * bytes (or NULL if 0).
 */

int veil_set_wake_hmac_envelope(VeilHandle *handle,
                                const uint8_t *rendezvous_node_id,
                                const uint8_t *auth_cookie,
                                const uint8_t *envelope,
                                size_t envelope_len,
                                char **err_out)
;

/**
 * Fill `out_key_32` with a fresh 32-byte wake-HMAC key from the OS CSPRNG.
 *
 * Receivers generate one key per identity rotation epoch and persist it
 * platform-side (iOS Keychain / Android Keystore — sibling slice).
 * The key is sealed to the chosen push-relay via [`veil_seal_push_envelope`]
 * — same envelope shape as a push token — and embedded in the receiver's
 * rendezvous ad as `wake_hmac_envelope` (slice 4.3.2 wire bump).
 *
 * # Safety
 *
 * `out_key_32` MUST point to exactly 32 writable bytes.
 */
 int veil_generate_wake_hmac_key(uint8_t *out_key_32, char **err_out) ;

/**
 * Verify a wake-up payload delivered via OS push (FCM / APNs body).
 * Receiver's plugin calls this inside `handleWakeup` BEFORE doing any
 * expensive veil work (daemon reconnect, mailbox drain).
 *
 * Returns one of [`VEIL_WAKE_VERDICT_*`] codes via `out_verdict`:
 *
 * * `VALID` — payload matches; proceed to drain.
 * * `TAMPERED` — HMAC mismatch.  Silent no-op; no observable network
 *   reaction (defeats presence oracle).
 * * `EXPIRED` — `ts` outside ±5-min freshness window.  Silent no-op;
 *   distinguish from tampering so operators can track clock-skew
 *   rate separately.
 * * `MALFORMED` — `payload_len != 72`.  Silent no-op; logs locally.
 *
 * On any [`VEIL_OK`] return the verdict byte is meaningful (≤ 3).
 * Other return codes indicate input-validation errors.
 *
 * # Safety
 *
 * `key_32` and `receiver_id_32` MUST each point to exactly 32 readable
 * bytes.  `payload` MUST point to `payload_len` readable bytes (or
 * NULL if 0).  `out_verdict` MUST be a writable pointer.
 */

int veil_verify_wake_hmac(const uint8_t *key_32,
                          const uint8_t *payload,
                          size_t payload_len,
                          const uint8_t *receiver_id_32,
                          uint64_t now_secs,
                          int *out_verdict,
                          char **err_out)
;

/**
 * Install a push-event handler on this veil connection
 *. The handler runs on a private tokio task and is
 * torn down when the handle is closed or `set_event_handler` is
 * called again. Returns [`VEIL_OK`] iff a fresh handler was
 * installed; [`VEIL_ERR_INVALID_ARG`] if `handle` is NULL.
 *
 * Single-subscriber semantics — calling this twice replaces the
 * previous handler (the prior task is aborted). Pass NULL `user`
 * if the C side does not need the opaque pointer; otherwise the
 * caller must keep `user` valid until the handler is replaced or
 * the handle is closed.
 *
 * Threading note: the callback fires on a tokio worker thread.
 * Hosts that marshal to a single-threaded UI loop (Flutter
 * dart:ffi, Swift, Kotlin) should wrap their callback in a
 * listener-style trampoline that wakes the UI isolate/queue.
 */
 int veil_set_event_handler(VeilHandle *handle, VeilEventCb cb, void *user, char **err_out) ;

/**
 * Generate a FRESH master identity phrase: a new random 32-byte master seed
 * encoded as the 24-word English mnemonic (veil master-phrase checksum). The
 * seed material lives only inside this call and zeroizes on drop — the
 * returned phrase is its ONLY representation. Flow: show it to the user for
 * the paper backup, confirm, then create the identity DETERMINISTICALLY via
 * `veil_restore_identity_from_phrase_zeroize` with this same phrase, so a
 * fresh onboarding and a later disaster-recovery restore agree on node_id.
 *
 * On success writes a NUL-terminated UTF-8 phrase into `*phrase_out`; the
 * caller MUST free it with `veil_free_string`, and should zero the buffer
 * first (the Dart wrapper copies into an immutable String and scrubs the
 * native bytes — same posture as the validate/restore zeroize variants).
 */
 int veil_generate_master_phrase(char **phrase_out, char **err_out) ;

/**
 * Validate a BIP-39 master phrase, zeroizing the caller's buffer on consume.
 *
 * Returns `VEIL_OK` iff the phrase is exactly 24 words from the English BIP-39
 * wordlist AND the checksum verifies. The `(phrase, phrase_len)` buffer is
 * overwritten with `0` before returning, on every path. UI uses this for live
 * feedback as the user types.
 *
 * Reads the phrase, runs the same validation, and unconditionally
 * overwrites the buffer bytes with `0` before returning — regardless
 * of success or failure. Caller MUST guarantee `phrase` points to a
 * writable, NUL-terminated UTF-8 buffer (typical: malloc'd from C, or
 * `String.toNativeUtf8` in Dart).
 */
 int veil_validate_bip39_phrase_zeroize(uint8_t *phrase, uintptr_t phrase_len, char **err_out) ;

/**
 * Restore an identity from a BIP-39 master phrase, zeroizing the phrase on
 * consume.
 *
 * Decodes `phrase` → master_seed → derives identity_sk → builds a fresh signed
 * `IdentityDocument` and writes `identity_document.bin`, `instance.toml`, and
 * `identity_sk.bin` to `veil_dir`. `instance_label` is the human-readable
 * device name (capped at 64 chars). Idempotent: same phrase + same `veil_dir`
 * regenerates the per-device key; the `node_id` (= BLAKE3(master_pk)) is stable.
 *
 * `phrase` is a SECRET, passed as a writable `(*mut u8, len)` buffer that is
 * overwritten with `0` before return on EVERY path. `veil_dir` and
 * `instance_label` are non-secret `(*const u8, len)` UTF-8. Returns `VEIL_OK`
 * on success; on failure sets `*err_out` and returns `VEIL_ERR`.
 */

int veil_restore_identity_from_phrase_zeroize(uint8_t *phrase,
                                              uintptr_t phrase_len,
                                              const uint8_t *veil_dir,
                                              uintptr_t veil_dir_len,
                                              const uint8_t *instance_label,
                                              uintptr_t instance_label_len,
                                              char **err_out)
;

/**
 * Restore identity AND write an encrypted master-seed backup
 * ([`veil_restore_identity_from_phrase_zeroize`] + passphrase-protected
 * `master.enc` file in `veil_dir`).
 *
 * Both `phrase` AND `password` buffers are zeroed in place before this
 * function returns (on every code path — success, validation error,
 * I/O error, or panic).  Caller still owns the allocations and frees
 * them after this call.
 *
 * `password` may be NULL — equivalent to calling
 * [`veil_restore_identity_from_phrase_zeroize`] without the encrypted-
 * master file.  This is provided as a convenience so consumer Flutter
 * apps can branch on "user-supplied passphrase or not" without
 * switching FFI symbols.
 *
 * The Argon2id parameters are the spec-production default (64 MiB,
 * t=3, p=4).  Test code wanting cheaper KDF must use the lower-level
 * `veil_identity::sovereign_flow::restore_identity` directly with
 * `argon2_params_override`.
 *
 * # Safety
 * `phrase` and (if non-NULL) `password` must each point to a writable buffer
 * of at least the given length.  `veil_dir` and `instance_label` are read-only
 * `(*const u8, len)` UTF-8.  `err_out` must be writable; on non-OK returns it
 * receives a pointer to a malloc'd UTF-8 string — caller frees with
 * [`veil_free_string`].
 */

int veil_restore_identity_from_phrase_zeroize_with_password(uint8_t *phrase,
                                                            uintptr_t phrase_len,
                                                            const uint8_t *veil_dir,
                                                            uintptr_t veil_dir_len,
                                                            const uint8_t *instance_label,
                                                            uintptr_t instance_label_len,
                                                            uint8_t *password,
                                                            uintptr_t password_len,
                                                            char **err_out)
;

/**
 * Open a short-lived sovereign signer from a recovery phrase.
 *
 * The writable phrase buffer is wiped on every path. Only an opaque handle,
 * the public key, and its node id cross back to the caller; the decoded master
 * seed and derived signing seed remain in native memory and zeroize on drop.
 * Call [`veil_sovereign_signer_close`] immediately after the membership-signing
 * burst.
 */

int veil_sovereign_signer_open_from_phrase_zeroize(uint8_t *phrase,
                                                   size_t phrase_len,
                                                   VeilSovereignSigner **out_signer,
                                                   uint8_t *out_node_id,
                                                   size_t out_node_id_cap,
                                                   uint8_t *out_public_key,
                                                   size_t out_public_key_cap,
                                                   char **err_out)
;

/**
 * Sign one message during an open sovereign burst. The output is a raw
 * 64-byte Ed25519 signature.
 */

int veil_sovereign_signer_sign(VeilSovereignSigner *signer,
                               const uint8_t *message,
                               size_t message_len,
                               uint8_t *out_signature,
                               size_t out_signature_cap,
                               char **err_out)
;

/**
 * Create a portable Ed25519+Falcon512 sovereign bundle encrypted with the
 * recovery phrase. The mutable phrase is wiped on every path. The returned
 * ciphertext buffer is freed with [`veil_free_buf`].
 */

int veil_sovereign_bundle_create_hybrid512_zeroize(uint8_t *phrase,
                                                   size_t phrase_len,
                                                   uint8_t **out_bundle,
                                                   size_t *out_bundle_len,
                                                   char **err_out)
;

/**
 * Re-wrap an existing XVSB or XVRC credential into a fresh XVRC recovery
 * certificate while preserving the exact full public key and derived node id.
 * Current-secret and new-code buffers are wiped on every path; only encrypted
 * certificate bytes return.
 */

int veil_sovereign_recovery_certificate_export_zeroize(const uint8_t *bundle,
                                                       size_t bundle_len,
                                                       uint8_t *phrase,
                                                       size_t phrase_len,
                                                       uint8_t *recovery_code,
                                                       size_t recovery_code_len,
                                                       uint8_t **out_certificate,
                                                       size_t *out_certificate_len,
                                                       char **err_out)
;

/**
 * Open an XVRC with its independent recovery code as a short-lived hybrid
 * signer. The code is wiped before return and plaintext material stays native.
 */

int veil_sovereign_signer_open_recovery_certificate_zeroize(const uint8_t *certificate,
                                                            size_t certificate_len,
                                                            uint8_t *recovery_code,
                                                            size_t recovery_code_len,
                                                            VeilSovereignSigner **out_signer,
                                                            uint8_t *out_algorithm,
                                                            uint8_t *out_node_id,
                                                            size_t out_node_id_cap,
                                                            uint8_t *out_public_key,
                                                            size_t out_public_key_cap,
                                                            size_t *out_public_key_len,
                                                            char **err_out)
;

/**
 * Decrypt a local sovereign bundle and open a short-lived variable-algorithm
 * signer. Neither phrase nor plaintext key material crosses back to the host.
 */

int veil_sovereign_signer_open_bundle_zeroize(const uint8_t *bundle,
                                              size_t bundle_len,
                                              uint8_t *phrase,
                                              size_t phrase_len,
                                              VeilSovereignSigner **out_signer,
                                              uint8_t *out_algorithm,
                                              uint8_t *out_node_id,
                                              size_t out_node_id_cap,
                                              uint8_t *out_public_key,
                                              size_t out_public_key_cap,
                                              size_t *out_public_key_len,
                                              char **err_out)
;

/**
 * Variable-length sovereign signature API. `out_signature_len` receives the
 * exact number of bytes written (64 for Ed25519, ~700-830 for hybrid-512).
 */

int veil_sovereign_signer_sign_into(VeilSovereignSigner *signer,
                                    const uint8_t *message,
                                    size_t message_len,
                                    uint8_t *out_signature,
                                    size_t out_signature_cap,
                                    size_t *out_signature_len,
                                    char **err_out)
;

/**
 * Verify an algorithm-tagged sovereign signature and bind the supplied node
 * id to the full public key. Invalid signatures return VEIL_OK + false.
 */

int veil_sovereign_verify(uint8_t algorithm,
                          const uint8_t *node_id,
                          const uint8_t *public_key,
                          size_t public_key_len,
                          const uint8_t *message,
                          size_t message_len,
                          const uint8_t *signature,
                          size_t signature_len,
                          bool *out_valid,
                          char **err_out)
;

/**
 * Close a sovereign signing burst. Double-close and stale handles are safe
 * no-ops; the generational table prevents ABA reuse.
 */
 void veil_sovereign_signer_close(VeilSovereignSigner *signer) ;

/**
 * Source-side: generate a pair-invite URI + initialize ceremony.
 * On success, `*out_uri` receives a malloc'd NUL-terminated UTF-8
 * string — caller frees with [`veil_free_string`].  `password` is the
 * master_sk decryption passphrase as `(ptr, len)` UTF-8; pass a NULL pointer
 * (length ignored) for a standalone identity with no encrypted master.
 */

int veil_pair_source_create_invite(VeilHandle *handle,
                                   const uint8_t *password,
                                   uintptr_t password_len,
                                   uint8_t *out_status,
                                   char **out_uri,
                                   char **err_out)
;

/**
 * Source-side: process Hello bytes from Target.  Returns Cert bytes
 * (via caller buffer) + 6-digit OOB code.  `out_cert_buf` must be
 * writable for ≥ `out_cert_buf_cap` bytes (recommend
 * `VEIL_MAX_PAIR_CEREMONY_BYTES` = 64 KiB so a fixed-size buffer
 * always fits the Cert).  `out_oob_6` MUST point to a 6-byte buffer.
 */

int veil_pair_source_handle_hello(VeilHandle *handle,
                                  const uint8_t *hello_bytes,
                                  size_t hello_len,
                                  uint8_t *out_status,
                                  uint8_t *out_oob_6,
                                  uint8_t *out_cert_buf,
                                  size_t out_cert_buf_cap,
                                  size_t *out_cert_len,
                                  char **err_out)
;

/**
 * Source-side: process Confirm bytes — finalizes the ceremony.
 *
 * Phase 6.49 exemplar: uses [`guard::ffi_prelude`] + [`null_check!`]
 * for the boundary checks so that the consistent error messages
 * land on every FFI fn after incremental migration.
 */

int veil_pair_source_handle_confirm(VeilHandle *handle,
                                    const uint8_t *confirm_bytes,
                                    size_t confirm_len,
                                    uint8_t *out_status,
                                    char **err_out)
;

/**
 * Target-side: consume scanned URI, build Hello bytes.
 */

int veil_pair_target_consume_uri(VeilHandle *handle,
                                 const uint8_t *uri,
                                 uintptr_t uri_len,
                                 uint8_t *out_status,
                                 uint8_t *out_hello_buf,
                                 size_t out_hello_buf_cap,
                                 size_t *out_hello_len,
                                 char **err_out)
;

/**
 * Target-side: process Cert bytes, return OOB code.
 *
 * Phase 6.49 exemplar (second after `veil_pair_source_handle_confirm`).
 */

int veil_pair_target_handle_cert(VeilHandle *handle,
                                 const uint8_t *cert_bytes,
                                 size_t cert_len,
                                 uint8_t *out_status,
                                 uint8_t *out_oob_6,
                                 char **err_out)
;

/**
 * Target-side: emit Confirm bytes based on user's OOB-compare
 * decision.  `confirmed = 1` triggers identity persistence.
 */

int veil_pair_target_build_confirm(VeilHandle *handle,
                                   uint8_t confirmed,
                                   uint8_t *out_status,
                                   uint8_t *out_confirm_buf,
                                   size_t out_confirm_buf_cap,
                                   size_t *out_confirm_len,
                                   char **err_out)
;

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Sign `message` with the Ed25519 identity in `identity_toml` (the config the
 * host stores in its deniable container). Writes the 64-byte signature to
 * `out_sig_64` and the 32-byte public key to `out_pubkey_32` (so the verifier
 * can bind it to the author's node_id). Returns 0 on success, -1 on error with
 * `*err_out` set (free with `veil_free_string`).
 *
 * # Safety
 * `identity_toml_ptr`/`msg_ptr` must point to their respective readable byte
 * lengths; `out_sig_64` must be writable for 64 bytes and `out_pubkey_32` for
 * 32; `err_out` (if non-null) must be a writable `*mut c_char` slot.
 */

int veil_identity_sign(const uint8_t *identity_toml_ptr,
                       size_t identity_toml_len,
                       const uint8_t *msg_ptr,
                       size_t msg_len,
                       uint8_t *out_sig_64,
                       uint8_t *out_pubkey_32,
                       char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Verify a message-authorship signature. Checks BOTH that `pubkey_32` really
 * belongs to `node_id_32` (`node_id = BLAKE3(pubkey)` — so a forged pubkey for
 * a claimed author is rejected) AND that `sig_64` is a valid Ed25519 signature
 * over `message` by that key.
 *
 * Returns 0 (`VERIFY_VALID`) if authentic, 1 (`VERIFY_INVALID`) if the node_id
 * binding or the signature fails, -1 on a bad argument (null pointer).
 *
 * # Safety
 * `node_id_32`/`pubkey_32` must be readable for 32 bytes, `sig_64` for 64, and
 * `msg_ptr` for `msg_len` bytes.
 */

int veil_identity_verify(const uint8_t *node_id_32,
                         const uint8_t *pubkey_32,
                         const uint8_t *msg_ptr,
                         size_t msg_len,
                         const uint8_t *sig_64)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Sign an already-mined seed set with the sovereign key of the embedded node
 * running as `owner_node_id`, and publish the nickname record to the DHT
 * (store-local + K-closest fan-out; auto-renewal rides the periodic
 * republish). `seeds` is a concatenation of 32-byte seeds from
 * `veil_nickname_mine`. On VEIL_OK writes the published record's cumulative
 * weight to `*out_weight`.
 *
 * Errors (VEIL_ERR, reason in `*err_out` — free with `veil_free_string`):
 * invalid name/seed set, weight under the per-length floor, no embedded node
 * for this identity, non-sovereign/multi-device key, or the name is owned by
 * a heavier foreign record (the message carries the weight to beat).
 *
 * # Safety
 * `owner_node_id` must point to 32 readable bytes; `name` to `name_len`
 * readable bytes; `seeds` to `seeds_len` readable bytes (multiple of 32, may
 * be NULL iff `seeds_len == 0` — though an empty set never clears the
 * floor); `out_weight` must be a writable `u64` slot; `err_out` (if
 * non-null) a writable `*mut c_char` slot.
 */

int veil_nickname_claim(const uint8_t *owner_node_id,
                        const uint8_t *name,
                        size_t name_len,
                        const uint8_t *seeds,
                        size_t seeds_len,
                        uint64_t timeout_ms,
                        uint64_t *out_weight,
                        char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Resolve the current owner of a nickname via the embedded node running as
 * `self_node_id`. Verifies every replica (owner binding + signature +
 * recomputed cumulative PoW + length floor) and picks the record that
 * displaces all others.
 *
 * Returns VEIL_OK with `*out_owner` (32 bytes), `*out_weight` and
 * `*out_issued_at` filled when an owner exists; [`NICKNAME_FREE`] (=1) when
 * the name has no valid owner record (available); negative on error
 * (`*err_out` set — free with `veil_free_string`).
 *
 * # Safety
 * `self_node_id` must point to 32 readable bytes; `name` to `name_len`
 * readable bytes; `out_owner` must be writable for 32 bytes; `out_weight` /
 * `out_issued_at` writable `u64` slots; `err_out` (if non-null) a writable
 * `*mut c_char` slot.
 */

int veil_nickname_resolve(const uint8_t *self_node_id,
                          const uint8_t *name,
                          size_t name_len,
                          uint64_t timeout_ms,
                          uint8_t *out_owner,
                          uint64_t *out_weight,
                          uint64_t *out_issued_at,
                          char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Provision a fresh node identity IN-PROCESS — generate an Ed25519 keypair and
 * mine its proof-of-work nonce — and return a ready-to-use config (TOML)
 * carrying that identity, WITHOUT writing anything to disk. The host stores the
 * returned bytes inside its own (deniable) container, so nothing
 * identity-bearing (private key, node_id) ever touches the filesystem. This is
 * the in-process replacement for `veil-cli config init` on mobile / sandboxed
 * hosts.
 *
 * `difficulty` is the PoW difficulty in leading zero bits; pass `0` for the
 * canonical default. Mining runs synchronously on the calling thread (it can
 * take a while), so call this off the host's UI thread.
 *
 * Returns a newly allocated C string (free it with `veil_free_string`) on
 * success, or NULL with `*err_out` set on failure.
 *
 * # Safety
 * `err_out` (if non-null) must be a writable `*mut c_char` slot.
 */
 char *veil_config_init(uint32_t difficulty, char **err_out) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Like `veil_config_init`, but the Ed25519 identity is DERIVED FROM A MASTER
 * PHRASE instead of random (onboarding-phrase epic P2): phrase → master seed
 * (checksum verified) → the SAME HKDF the sovereign restore uses
 * (`veil_crypto::identity::derive_master_sk_ed25519`) → keypair; only the
 * anti-sybil nonce is searched. `node_id` depends only on the public key, so
 * the identity is deterministic in the phrase — a later disaster-recovery
 * restore lands on the SAME node_id — while the nonce is simply re-mined.
 *
 * The caller's `(phrase, phrase_len)` buffer is overwritten with `0` before
 * returning on EVERY path (same contract as the validate/restore zeroize
 * variants); the decoded seed and derived secret zeroize on drop. Returns
 * the rendered config TOML (free with `veil_free_string`), or NULL with
 * `err_out` set. `difficulty` 0 = canonical.
 */

char *veil_config_init_from_phrase_zeroize(uint8_t *phrase,
                                           size_t phrase_len,
                                           uint32_t difficulty,
                                           char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Compose a full, bootable node config by combining a stored identity (the
 * config TOML from `veil_config_init`, kept in the host's deniable container)
 * with EPHEMERAL runtime endpoints chosen per launch: `listen_transport` (e.g.
 * `tcp://127.0.0.1:9931`), `ipc_socket`, and `admin_socket` (filesystem paths,
 * wrapped as `unix://`). None of these endpoints are identity-bearing, so they
 * are not stored — only the identity is. Returns the merged config as TOML
 * (free with `veil_free_string`), or NULL with `*err_out` set.
 *
 * # Safety
 * Each `*_ptr` must point to its `*_len` readable bytes; `err_out` (if non-null)
 * must be a writable `*mut c_char` slot.
 */

char *veil_config_compose(const uint8_t *identity_toml_ptr,
                          size_t identity_toml_len,
                          const uint8_t *listen_transport_ptr,
                          size_t listen_transport_len,
                          const uint8_t *ipc_socket_ptr,
                          size_t ipc_socket_len,
                          const uint8_t *admin_socket_ptr,
                          size_t admin_socket_len,
                          char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Start an embedded node from a config file at `config_path` (`(ptr,len)`,
 * UTF-8). Non-blocking. Returns an opaque handle, or null with `*err_out` set
 * (free it with `veil_free_string`).
 *
 * # Safety
 * `config_path_ptr` must point to `config_path_len` readable bytes; `err_out`
 * (if non-null) must be a writable `*mut c_char` slot.
 */
 VeilNode *veil_node_start(const uint8_t *config_path_ptr, size_t config_path_len, char **err_out) ;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Start an embedded node in deferred-init mode: it boots under an ephemeral
 * throwaway identity, binds ONLY the admin endpoint at `admin_socket` (`(ptr,
 * len)`, UTF-8 Unix path or authenticated loopback-TCP URI), and waits. Promote it to its real identity by
 * pushing a config with `veil_node_apply_config` — so the real private key
 * never has to be written to a config file on disk.
 *
 * Pick an ephemeral, identity-free endpoint for `admin_socket` (e.g. a path
 * under a per-launch temp dir, or `tcp://127.0.0.1:0?runtime_dir=...`).
 * Non-blocking; returns an opaque handle or null + err.
 *
 * `anonymous` arms `[anonymity]` in the stub boot config so the node is
 * actually onion-reachable once its real identity is applied. It MUST be set
 * here (at boot) rather than via `veil_node_apply_config`: anonymity is pinned
 * at startup and the later apply-config (a reload) does not re-apply it. The
 * published onion descriptor is sealed against the live identity, so it
 * resolves to the real identity once `veil_node_apply_config` promotes it.
 *
 * # Safety
 * `admin_socket_ptr` must point to `admin_socket_len` readable bytes; `err_out`
 * (if non-null) must be a writable `*mut c_char` slot.
 */

VeilNode *veil_node_start_deferred(const uint8_t *admin_socket_ptr,
                                   size_t admin_socket_len,
                                   bool anonymous,
                                   char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Promote a deferred-init node to its real identity by applying `config_toml`
 * (`(ptr, len)`, UTF-8 — e.g. the bytes returned by `veil_config_init` and
 * kept in the host's deniable storage) over the node's admin socket, IN MEMORY
 * (`persist = false`, so nothing is written to disk). Retries briefly while the
 * deferred node finishes binding its admin socket.
 *
 * The node must have been started with `veil_node_start_deferred`. Returns 0 on
 * success, -1 on failure with `*err_out` set (free it with `veil_free_string`).
 *
 * # Safety
 * `node` must be a live handle from `veil_node_start_deferred`; `config_ptr`
 * must point to `config_len` readable bytes; `err_out` (if non-null) must be a
 * writable `*mut c_char` slot.
 */

int veil_node_apply_config(const VeilNode *node,
                           const uint8_t *config_ptr,
                           size_t config_len,
                           char **err_out)
;
#endif

#if defined(VEIL_FFI_NODE_EMBEDDED)
/**
 * Stop the embedded node: trigger graceful shutdown and join its thread.
 * Consumes the handle.
 *
 * # Safety
 * `node` must be a handle returned by `veil_node_start*` and not yet stopped.
 */
 void veil_node_stop(VeilNode *node) ;
#endif

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* VEIL_FFI_H */
