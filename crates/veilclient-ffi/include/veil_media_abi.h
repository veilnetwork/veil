/* SPDX-License-Identifier: MIT
 *
 * veil_media_abi.h — lossy MEDIA datagram ABI for calls (Phase 2).
 *
 * A hand-authored SUBSET of the veilclient-ffi C ABI, carved out for the
 * `veil_media` Flutter plugin's native `webrtc::Transport` shim (Phase 3+),
 * which drives RTP/RTCP native↔native and must NOT depend on the full
 * (cbindgen-generated) `veil_ffi.h`. The canonical, authoritative declarations
 * still live in `veil_ffi.h`; keep the two in sync if a signature changes.
 *
 * Model
 * -----
 * Media rides one of three transports — the anonymous 2-hop onion circuit, a
 * direct P2P app datagram, or the ordinary Delivery relay — always through a
 * lossy path: each datagram is one cell, dropped (never retransmitted) on loss.
 * Ordering is best-effort; the media codec's PLC/FEC absorbs gaps. There is no
 * ARQ, no ACKs, and no pacing.
 *
 * End-to-end seal
 * ---------------
 * EVERY channel is opened with two 32-byte directional call-media keys, and
 * every cell on every transport is sealed with them (ChaCha20-Poly1305, with a
 * per-epoch salt and a sequence number bound in as AAD and checked against a
 * replay window). There is no unsealed mode and no way to add keys later: a
 * channel that cannot be keyed does not open. None of the three transports is
 * end-to-end on its own — the onion path's splice relay reads the cell to route
 * it and its receive cookie is derived from a PUBLIC node id, a "direct"
 * session is encrypted only hop-to-hop, and an ML-KEM relay envelope proves
 * confidentiality but never origin.
 *
 * Threading / safety
 * ------------------
 *   * `veil_media_send_datagram` is non-blocking and may be called from the
 *     media engine's real-time send thread. It enqueues onto a bounded queue
 *     and returns immediately (dropping on overflow).
 *   * The recv callback is invoked from a tokio worker thread, once per inbound
 *     datagram, with the wire magic already stripped. It must not block; hand
 *     the bytes straight to the RTP receiver. The `ptr` is only valid for the
 *     duration of the call — copy if you need to retain it.
 *   * The channel id is an opaque handle; free it with
 *     `veil_media_close_channel`. `0` is reserved for "error / invalid".
 */

#ifndef VEIL_MEDIA_ABI_H
#define VEIL_MEDIA_ABI_H

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque connection handle (same type as `veil_ffi.h`'s `VeilHandle`). */
typedef struct VeilHandle VeilHandle;
/* Opaque app endpoint (same type as `veil_ffi.h`'s `VeilApp`). */
typedef struct VeilApp VeilApp;

/*
 * Recv callback: (ctx, ptr, len). Invoked once per inbound media datagram from
 * the channel's peer, magic stripped. Must not block. `ptr` is borrowed for the
 * call only.
 */
typedef void (*VeilMediaRecvFn)(void *ctx, const uint8_t *ptr, size_t len);

/* Relay drain timing snapshot; all fields are u64 for a stable cross-ABI
 * layout. Values are cumulative/maxima except `video_queue_depth`. */
typedef struct VeilMediaChannelStats {
    uint64_t video_frames_enqueued;
    uint64_t video_frames_started;
    uint64_t video_queue_depth;
    uint64_t video_queue_max_depth;
    uint64_t video_queue_age_max_ms;
    uint64_t video_queue_holds_75ms;
    uint64_t sender_lock_max_ms;
    uint64_t sender_lock_holds_16ms;
    uint64_t video_frame_ipc_max_ms;
    uint64_t video_frame_ipc_holds_33ms;
    uint64_t ipc_cell_max_ms;
    uint64_t ipc_cell_holds_16ms;
    uint64_t ipc_send_failures;
} VeilMediaChannelStats;

/*
 * Open a lossy MEDIA datagram channel to `peer_node_id` (32 bytes) over the
 * anonymous circuit. Reuses the reliable stream's rendezvous/pool and warms the
 * circuit in the background. Returns an opaque channel id (> 0), or 0 on error
 * (`*err_out` set to a heap C string — free with `veil_free_string`).
 */
uint64_t veil_media_open_channel(VeilHandle *handle,
                                 const uint8_t *peer_node_id,
                                 const uint8_t *tx_key,
                                 const uint8_t *rx_key,
                                 char **err_out);

/*
 * Open a lossy MEDIA datagram channel to `peer_node_id` over a direct app
 * endpoint. Outbound datagrams are sent from `app` to
 * (`peer_node_id`, `peer_app_id`, `peer_endpoint_id`). Inbound datagrams must be
 * received by the host on `app`, source-filtered, then fed to
 * `veil_media_dispatch_direct_datagram`.
 */
uint64_t veil_media_open_direct_channel(VeilApp *app,
                                        const uint8_t *peer_node_id,
                                        const uint8_t *peer_app_id,
                                        uint32_t peer_endpoint_id,
                                        const uint8_t *tx_key,
                                        const uint8_t *rx_key,
                                        char **err_out);

/* Open a non-onion Delivery-relay media channel for direct identities. */
uint64_t veil_media_open_relay_channel(VeilApp *app,
                                       const uint8_t *peer_node_id,
                                       const uint8_t *peer_app_id,
                                       uint32_t peer_endpoint_id,
                                       const uint8_t *tx_key,
                                       const uint8_t *rx_key,
                                       char **err_out);

/*
 * Drain inbound datagrams from `app` directly into the native media registry.
 * The claimed source node plus (`source_namespace`, `source_name`) must derive
 * the frame's source app_id; mismatches are silently dropped. That is a demux,
 * not a sender gate — the seal is what authenticates a sender. This takes
 * exclusive ownership of the app receiver and must precede any generic handler.
 */
int veil_media_start_direct_receiver(VeilApp *app,
                                     const uint8_t *source_namespace,
                                     size_t source_namespace_len,
                                     const uint8_t *source_name,
                                     size_t source_name_len,
                                     char **err_out);

/*
 * Enqueue one media datagram (RTP/RTCP) on `chan`. NON-BLOCKING. Returns:
 *    0  queued
 *    1  dropped (queue full / channel closing)
 *   -1  invalid argument (NULL/zero-length payload, or unknown `chan`)
 */
int veil_media_send_datagram(uint64_t chan, const uint8_t *ptr, size_t len);

/* Select the batching wire format: 0 off, 1 legacy audio+video, 2 compact
 * relay audio-only (relay channels only). Not a security switch — every mode
 * seals identically, and the batch envelope travels inside the seal. */
int veil_media_channel_set_batching(uint64_t chan, int mode);

/* Snapshot local relay queue/IPC timing. Direct/onion channels return zeros.
 * Returns 0 on success or -1 for an invalid channel/output pointer. */
int veil_media_channel_get_stats(uint64_t chan,
                                 VeilMediaChannelStats *out);

/*
 * Request a make-before-break refresh of an anonymous channel's outbound
 * rendezvous/circuit pool after the peer reports end-to-end media silence.
 * Returns 0 when queued, 1 when already pending, -1 for invalid/direct.
 */
int veil_media_repair_channel(uint64_t chan);

/*
 * Feed one direct-P2P media datagram from `peer_node_id` into the native media
 * ingress. Whatever the host believes about the source, the cell is opened with
 * the channel's own key before a byte of it reaches the engine.
 */
int veil_media_dispatch_direct_datagram(const uint8_t *peer_node_id,
                                        const uint8_t *ptr,
                                        size_t len);

/*
 * Install (or, with `cb == NULL`, clear) the recv callback for inbound media
 * datagrams from `chan`'s peer. Replaces any prior callback. Returns 0, or -1
 * on an unknown `chan`.
 */
int veil_media_set_recv_callback(uint64_t chan, VeilMediaRecvFn cb, void *ctx);

/*
 * Close a media channel: stops the drain task, drops the outbound queue, and
 * clears the peer's recv callback. Idempotent.
 */
void veil_media_close_channel(uint64_t chan);

/*
 * Diagnostic: number of inbound media datagrams from `peer_node_id` (32 bytes)
 * that OPENED against the channel key since process start. Lets a host confirm
 * receipt without wiring a recv callback; a stranger cannot advance it.
 * Returns 0 on a NULL pointer.
 */
uint64_t veil_media_recv_count(const uint8_t *peer_node_id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VEIL_MEDIA_ABI_H */
