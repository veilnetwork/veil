/* SPDX-License-Identifier: MIT
 *
 * veil_media_engine.h — control ABI for the veil call media engine.
 *
 * The engine wraps a codec-stripped libwebrtc (webrtc::Call + AudioState, no
 * ICE/PeerConnection) and drives it through a custom webrtc::Transport that
 * pipes RTP/RTCP over the veil media datagram channel (see veil_media_abi.h in
 * veilclient-ffi). Per-packet media never touches Dart; this ABI is CONTROL
 * ONLY — create/start/stop, mute, device enumerate/select, stats.
 *
 * Threading: create/destroy and start/stop are expected on one control thread
 * (the Dart FFI caller). The engine owns its own webrtc worker/network threads
 * internally. Callbacks (none yet in this control ABI) would be marshalled by
 * the caller.
 *
 * Lifetime: `veil_media_engine_create` returns an opaque handle; free it with
 * `veil_media_engine_destroy`. The caller owns the veil media channel (opened
 * via veil_media_open_channel) and passes its id in; the engine registers its
 * recv callback on that channel and sends via it, but does NOT close it.
 */

#ifndef VEIL_MEDIA_ENGINE_H
#define VEIL_MEDIA_ENGINE_H

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// The engine object is compiled with WebRTC's flags, which include
// -fvisibility=hidden. Force DEFAULT visibility on this whole control ABI so
// the symbols are exported from libveil_media.dylib (Dart resolves them via
// DynamicLibrary.process()).
#pragma GCC visibility push(default)

typedef struct VeilMediaEngine VeilMediaEngine;

/* Result codes. 0 == OK; negatives are errors. */
#define VEIL_MEDIA_OK 0
#define VEIL_MEDIA_ERR -1          /* generic failure */
#define VEIL_MEDIA_ERR_ARG -2      /* bad argument (null handle, etc.) */
#define VEIL_MEDIA_ERR_STATE -3    /* wrong state (e.g. audio already started) */
#define VEIL_MEDIA_ERR_DEVICE -4   /* device enumerate/select failed */

/*
 * Create a media engine bound to an already-open veil media channel.
 *   veil_chan   : channel id from veil_media_open_channel (RTP/RTCP transport).
 *   local_id    : 32-byte OUR node id — used to derive our send SSRC.
 *   peer_id     : 32-byte peer node id — used to derive the expected recv SSRC.
 * SSRCs are derived from the node ids so the two endpoints agree without an
 * extra negotiation: our send-ssrc = f(local_id) = peer's recv remote-ssrc, and
 * vice versa. The engine installs its inbound recv callback on `veil_chan` and
 * sends outbound RTP/RTCP through it. Returns NULL on failure.
 */
VeilMediaEngine *veil_media_engine_create(uint64_t veil_chan,
                                          const uint8_t *local_id,
                                          const uint8_t *peer_id);

/* Tear down: stops all streams, unregisters the recv callback, frees the
 * engine. Does NOT close the veil media channel (caller owns it). */
void veil_media_engine_destroy(VeilMediaEngine *engine);

/* ---- Audio ---------------------------------------------------------------
 * Start/stop a bidirectional (or one-way) Opus audio session. `send` mounts
 * mic capture -> Opus encode -> RTP -> Transport; `recv` mounts RTP ->
 * Opus/NetEQ -> speaker. Idempotent per direction. */
int veil_media_engine_start_audio(VeilMediaEngine *engine, int send, int recv);
int veil_media_engine_stop_audio(VeilMediaEngine *engine);

/* Local mic mute (stop transmitting) / remote playout mute. */
int veil_media_engine_set_mic_muted(VeilMediaEngine *engine, int muted);
int veil_media_engine_set_speaker_muted(VeilMediaEngine *engine, int muted);

/* ---- Video (Phase 4) -----------------------------------------------------
 * A VP8 video session over the SAME veil media channel as audio, on a distinct
 * SSRC. `send` mounts a video source -> VP8 encode -> RTP -> Transport; `recv`
 * mounts RTP -> VP8 decode -> the frame callback. Idempotent per direction.
 * Frames are I420. Set VEIL_MEDIA_TEST_VIDEO=1 in the environment to drive the
 * send stream from a built-in synthetic frame generator (pipeline bring-up)
 * instead of pushed frames. */
int veil_media_engine_start_video(VeilMediaEngine *engine, int send, int recv);
int veil_media_engine_stop_video(VeilMediaEngine *engine);

/* Open the platform camera and drive the video send stream from it (near
 * width x height at fps; the camera picks the closest supported format). Video
 * send must already be started (veil_media_engine_start_video send=1). Returns
 * VEIL_MEDIA_OK, or VEIL_MEDIA_ERR_STATE if this platform has no camera backend
 * or the device can't be opened. Idempotent. */
int veil_media_engine_start_camera(VeilMediaEngine *engine, int width,
                                   int height, int fps);
int veil_media_engine_stop_camera(VeilMediaEngine *engine);

/* Push one captured I420 frame into the video send stream (platform camera /
 * screen capturer, or Dart). Planes may be strided; pass ts_us=0 to stamp now.
 * No-op if video send isn't started. */
int veil_media_engine_push_video_frame(VeilMediaEngine *engine,
                                       const uint8_t *y, const uint8_t *u,
                                       const uint8_t *v, int width, int height,
                                       int stride_y, int stride_u, int stride_v,
                                       int64_t ts_us);

/* Pull the latest decoded remote frame as tightly-packed RGBA (width*height*4
 * bytes, row stride width*4). Copies into `dst` (capacity `dst_cap`) and sets
 * *out_w / *out_h. Returns a monotonic frame sequence (>0) when a frame was
 * copied, 0 if none decoded yet, or -1 if `dst_cap` is too small (the output
 * width/height pointers are still set so the caller can resize + retry). Poll
 * at the display rate and repaint only when the returned sequence changes.
 * Thread-safe. */
int veil_media_engine_get_video_frame(VeilMediaEngine *engine, uint8_t *dst,
                                      int dst_cap, int *out_w, int *out_h);

/* Pull the latest local camera frame as tightly-packed RGBA for self-preview.
 * Same return contract as veil_media_engine_get_video_frame. */
int veil_media_engine_get_local_video_frame(VeilMediaEngine *engine,
                                            uint8_t *dst, int dst_cap,
                                            int *out_w, int *out_h);

/* ---- Device selection ----------------------------------------------------
 * Enumerate returns a heap-allocated JSON C string
 * [{"id":"...","label":"...","kind":"input|output"}], or NULL on failure.
 * Free it with veil_media_free_string. Select by the opaque "id". Switchable
 * mid-call. (iOS routes via AVAudioSession, not indices — the engine hides
 * that behind the same API.) */
char *veil_media_engine_list_audio_inputs(VeilMediaEngine *engine);
char *veil_media_engine_list_audio_outputs(VeilMediaEngine *engine);
int veil_media_engine_select_audio_input(VeilMediaEngine *engine,
                                         const char *id);
int veil_media_engine_select_audio_output(VeilMediaEngine *engine,
                                          const char *id);

/* ---- Stats ---------------------------------------------------------------
 * Heap JSON snapshot {"tx_pkts","rx_pkts","tx_bytes","rx_bytes",
 * "rtt_ms","jitter_ms","loss_pct","target_bitrate_bps",...} or NULL.
 * Free with veil_media_free_string. */
char *veil_media_engine_get_stats(VeilMediaEngine *engine);

/* Free any char* returned by this ABI. */
void veil_media_free_string(char *s);

/* ABI/build probe: returns a static version string (no free). */
const char *veil_media_version(void);

#pragma GCC visibility pop

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VEIL_MEDIA_ENGINE_H */
