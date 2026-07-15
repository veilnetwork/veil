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
 * Media rides the SAME anonymous 2-hop onion circuit as the reliable byte
 * stream, but through a lossy path: each datagram is one circuit cell, dropped
 * (never retransmitted) on loss. Ordering is best-effort; the media codec's
 * PLC/FEC absorbs gaps. There is no ARQ, no ACKs, and no pacing.
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

/*
 * Open a lossy MEDIA datagram channel to `peer_node_id` (32 bytes) over the
 * anonymous circuit. Reuses the reliable stream's rendezvous/pool and warms the
 * circuit in the background. Returns an opaque channel id (> 0), or 0 on error
 * (`*err_out` set to a heap C string — free with `veil_free_string`).
 */
uint64_t veil_media_open_channel(VeilHandle *handle,
                                 const uint8_t *peer_node_id,
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
                                        char **err_out);

/* Open a non-onion Delivery-relay media channel for direct identities. */
uint64_t veil_media_open_relay_channel(VeilApp *app,
                                       const uint8_t *peer_node_id,
                                       const uint8_t *peer_app_id,
                                       uint32_t peer_endpoint_id,
                                       char **err_out);

/*
 * Drain inbound datagrams from `app` directly into the native media registry.
 * The authenticated source node plus (`source_namespace`, `source_name`) must
 * derive the frame's source app_id; mismatches are silently dropped. This takes
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

/*
 * Request a make-before-break refresh of an anonymous channel's outbound
 * rendezvous/circuit pool after the peer reports end-to-end media silence.
 * Returns 0 when queued, 1 when already pending, -1 for invalid/direct.
 */
int veil_media_repair_channel(uint64_t chan);

/*
 * Feed one already-authenticated direct-P2P media datagram from `peer_node_id`
 * into the native media receive callback registry. The host is responsible for
 * checking that the datagram arrived from the expected media app_id.
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
 * Diagnostic: number of inbound media datagrams received from `peer_node_id`
 * (32 bytes) since process start. Lets a host confirm receipt without wiring a
 * recv callback. Returns 0 on a NULL pointer.
 */
uint64_t veil_media_recv_count(const uint8_t *peer_node_id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VEIL_MEDIA_ABI_H */
