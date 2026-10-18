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
typedef struct VeilGroupMediaEngine VeilGroupMediaEngine;

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

/* Rebind an already-running engine to a caller-owned, authenticated channel
 * for the SAME logical call/peer/key material. The old channel stays caller-
 * owned. On failure it remains active; on success its callback is unregistered.
 * Does not recreate audio/video streams, reset RTP or stop capture/playout. */
/* A committed new channel also advances each local congestion controller's
 * opaque path identity, preserving streams/SSRCs and receive buffers. Failed
 * and idempotent candidates do not. Estimator work has independent audio/video
 * scheduling bounds (50/20 ms); a busy worker retries on get_stats. Stats expose
 * media_route_generation and audio/video_bwe_route_generation locally only. */
int veil_media_engine_rebind_channel(VeilMediaEngine *engine, uint64_t veil_chan);

/* Same call/key contract as rebind_channel, retaining the previous inbound
 * binding so independent peer route changes do not interrupt receive audio.
 * Caller retains ownership of both handles and releases superseded bindings.
 * Destroy unregisters and fences all remaining bindings. */
int veil_media_engine_rebind_channel_keep_receiver(VeilMediaEngine *engine, uint64_t veil_chan);
/* Unregister/fence an older inbound binding. Refuses the active outbound
 * channel; repeated release of an already-released binding is harmless. */
int veil_media_engine_release_receive_channel(VeilMediaEngine *engine, uint64_t veil_chan);

/* Optional endpoint-only audio redundancy. The caller must first qualify an
 * alternate channel with the same peer/call keys and retain its ownership.
 * Zero disables it. No receive registration, video, RTCP or padding is copied.
 * Rebind/stop clears it; clear before closing the caller-owned alternate.
 * Default off. Additional traffic must be measured before production use. */
int veil_media_engine_set_audio_mirror_channel(VeilMediaEngine *engine, uint64_t veil_chan);

/* ---- Audio ---------------------------------------------------------------
 * Start/stop a bidirectional (or one-way) Opus audio session. `send` mounts
 * mic capture -> Opus encode -> RTP -> Transport; `recv` mounts RTP ->
 * Opus/NetEQ -> speaker. Idempotent per direction. */
int veil_media_engine_start_audio(VeilMediaEngine *engine, int send, int recv);
int veil_media_engine_stop_audio(VeilMediaEngine *engine);

/* Local mic mute (stop transmitting) / remote playout mute. */
int veil_media_engine_set_mic_muted(VeilMediaEngine *engine, int muted);
int veil_media_engine_set_speaker_muted(VeilMediaEngine *engine, int muted);

/* ---- N-party audio ------------------------------------------------------
 * One group engine owns exactly one ADM, AudioState/AudioMixer and Opus send
 * stream. Each peer contributes one veil datagram channel and one receive
 * stream. The single encoded mic stream is fanned out natively; decoded peer
 * streams are mixed by WebRTC before the ADM speaker callback. Packet bytes
 * never cross Dart. Channels remain caller-owned. */
VeilGroupMediaEngine *veil_media_group_engine_create(
    const uint8_t *local_id);
void veil_media_group_engine_destroy(VeilGroupMediaEngine *engine);
int veil_media_group_engine_add_peer(VeilGroupMediaEngine *engine,
                                     uint64_t veil_chan,
                                     const uint8_t *peer_id);
int veil_media_group_engine_remove_peer(VeilGroupMediaEngine *engine,
                                        const uint8_t *peer_id);
int veil_media_group_engine_start_audio(VeilGroupMediaEngine *engine);
int veil_media_group_engine_stop_audio(VeilGroupMediaEngine *engine);
int veil_media_group_engine_set_mic_muted(VeilGroupMediaEngine *engine,
                                          int muted);
/* Monotonic inbound datagram count for one peer, or 0 if absent. */
uint64_t veil_media_group_engine_peer_rx_packets(
    VeilGroupMediaEngine *engine, const uint8_t *peer_id);

/* ---- N-party video ------------------------------------------------------
 * One shared VP8 send stream/source is fanned out to every current peer. Each
 * peer owns an independent receive stream + latest-frame sink on a separate
 * WebRTC video Call. Video SSRCs are derived from the full node id in
 * a domain distinct from group audio; collisions reject the peer fail-closed.
 * RTP never crosses Dart. */
int veil_media_group_engine_start_video(VeilGroupMediaEngine *engine);
int veil_media_group_engine_stop_video(VeilGroupMediaEngine *engine);
/* Local group video adaptation, 30..2500 kbit/s and 1..60 fps. No signaling
 * or relay priority is added. The video-worker scheduling wait is 20 ms. */
int veil_media_group_engine_set_video_bitrate(VeilGroupMediaEngine *engine,
                                              int max_bitrate_kbps, int max_fps);
/* Low-rate adaptation: 1..2500 kbit/s and 0.02..60 fps. Encoder handoff
 * uses the fractional cadence; local preview/capture remain live. Zero,
 * negative and non-finite budgets are errors, never legacy defaults.
 * May be prepared before start, so encoder/estimator begin at that budget.
 * A prepared budget is consumed by one start; legacy defaults remain 30/1.
 * Existing 20 ms video-worker scheduling wait and debug pin apply. */
int veil_media_group_engine_set_video_budget(VeilGroupMediaEngine *engine,
                                        int max_bitrate_kbps, double max_fps);
/* Endpoint-local Opus control, before or during audio: 20/40/60 ms packets
 * and 16000..32000 bit/s payload. Reconfigures the existing sender, preserving
 * RTP state, microphone and receive streams. Only waits on the audio worker
 * (20 ms scheduling bound); ERR_STATE means the requested budget was not
 * confirmed. No network role, priority or synthetic bandwidth report is sent. */
int veil_media_group_engine_set_audio_budget(VeilGroupMediaEngine *engine,
                                            int packet_ms, int payload_bps);
/* Optional endpoint-local send pause (0/1). Camera/screen capture, preview,
 * audio, RTCP and receiving video remain live. Already queued Veil packets
 * cannot be recalled. Pausing never waits on the video worker; resuming
 * requests a keyframe with a 20 ms scheduling wait, retry on ERR_STATE.
 * The pause persists across video source/stream changes on this engine. */
int veil_media_group_engine_set_video_send_paused(VeilGroupMediaEngine *engine, int paused);
/* Group audio quality: maxima over fresh RTCP audio report blocks (15 s).
 * `audio_receivers` maps peer-id hex to accepted `audio_rx_pkts` and the
 * native `audio_delay_ms` (current queued samples + reported ADM delay).
 * `audio_filtered_delay_ms` retains WebRTC's RTP-span estimate for diagnostics;
 * sender timestamp resets can invalidate it without delaying actual PCM.
 * `audio_rx_supported` stays 1 even when
 * `worker_stalled` is 1 and the receiver map is empty (unknown, not healthy).
 * Audio and video telemetry have separate 20 ms scheduling waits.
 * `audio_playout_peers` counts active peers that advertised encrypted RTCP APP
 * playout feedback; `audio_playout_reports` counts fresh measured estimates
 * (12 s), and `audio_playout_ms` is their maximum or -1 when unknown. Receiver
 * samples are appended to existing RTCP only, with no relay-visible role.
 * `audio_latency_recovery_count`, `audio_latency_discarded_ms` and
 * `audio_latency_fallback_frames` aggregate local decoded-audio catch-up over
 * all receivers in this engine. Consume fresh counter deltas, not cached
 * totals; a new engine establishes a new baseline. These fields stay local.
 * Free this JSON with veil_media_free_string. */
char *veil_media_group_engine_get_stats(VeilGroupMediaEngine *engine);
int veil_media_group_engine_start_camera(VeilGroupMediaEngine *engine,
                                         int width, int height, int fps);
int veil_media_group_engine_stop_camera(VeilGroupMediaEngine *engine);
int veil_media_group_engine_start_screen(VeilGroupMediaEngine *engine,
                                         int width, int fps);
/* Source-aware additive variant. `source_id` comes from
 * veil_media_list_screen_inputs; NULL/empty selects the default display. */
int veil_media_group_engine_start_screen_source(VeilGroupMediaEngine *engine,
                                                const char *source_id,
                                                int width, int fps);
int veil_media_group_engine_stop_screen(VeilGroupMediaEngine *engine);
int veil_media_group_engine_push_video_frame(
    VeilGroupMediaEngine *engine, const uint8_t *y, const uint8_t *u,
    const uint8_t *v, int width, int height, int stride_y, int stride_u,
    int stride_v, int64_t ts_us);
/* Per-peer remote frame pull; same return contract as the 1:1 getter below. */
int veil_media_group_engine_get_peer_video_frame(
    VeilGroupMediaEngine *engine, const uint8_t *peer_id, uint8_t *dst,
    int dst_cap, int *out_w, int *out_h);
int veil_media_group_engine_get_local_video_frame(
    VeilGroupMediaEngine *engine, uint8_t *dst, int dst_cap, int *out_w,
    int *out_h);

/* ---- Video (Phase 4) -----------------------------------------------------
 * A VP8 video session over the SAME veil media channel as audio, on a distinct
 * SSRC. `send` mounts a video source -> VP8 encode -> RTP -> Transport; `recv`
 * mounts RTP -> VP8 decode -> the frame callback. Idempotent per direction.
 * Frames are I420. Set VEIL_MEDIA_TEST_VIDEO=1 in the environment to drive the
 * send stream from a built-in synthetic frame generator (pipeline bring-up)
 * instead of pushed frames. `max_bitrate_kbps` and `max_fps` are explicit so
 * direct P2P can use a quality profile while padded onion media stays
 * conservative. Values <= 0 select the 150 kbps / 15 fps privacy-path defaults. */
int veil_media_engine_start_video(VeilMediaEngine *engine, int send, int recv,
                                  int max_bitrate_kbps, int max_fps);
int veil_media_engine_stop_video(VeilMediaEngine *engine);

/* Configure before the first audio/video start. Both peers must advertise
 * independent media transport feedback (xVeil call protocol v4). The default
 * is disabled for peers with a shared audio/video transport sequence space. */
int veil_media_engine_set_independent_transport_feedback(VeilMediaEngine *engine,
                                                        int enabled);

/* Before the first audio/video start, account for bytes below RTP and enable
 * state-preserving Opus packet-duration adaptation (20..60 ms). Requires
 * independent feedback and the bundled local ANA factory. Zero disables
 * this option; unsupported builds return ERR_STATE for a positive hint.
 * After starting, an already enabled positive hint can be updated for route
 * framing changes without recreating streams. Enabling/disabling stays frozen.
 * RTP overhead is added separately by WebRTC. A hint does not measure actual
 * wire delivery or give relays any scheduling information. */
int veil_media_engine_set_audio_packet_overhead(VeilMediaEngine *engine, int bytes);

/* Set a route-specific RTP packet ceiling before starting video send. Zero
 * restores libwebrtc's default; nonzero values are clamped to 576..1460.
 * Compact relay mode uses 1000 so one sealed Delivery frame fits one QUIC
 * DATAGRAM. Returns VEIL_MEDIA_ERR_STATE after video send has started. */
int veil_media_engine_set_max_rtp_packet_size(VeilMediaEngine *engine,
                                              int max_packet_size);

/* Retune the running video send stream to a new bitrate/fps budget without
 * restarting it (encoder reconfigure; the route stays untouched). Used by the
 * app-side link-quality adaptation. Same clamps and VEIL_MEDIA_VIDEO_KBPS
 * override as veil_media_engine_start_video. Returns VEIL_MEDIA_ERR_STATE if
 * video send isn't running. */
int veil_media_engine_set_video_bitrate(VeilMediaEngine *engine,
                                        int max_bitrate_kbps, int max_fps);
/* Low-rate adaptation: 1..2500 kbit/s and 0.02..60 fps. Encoder handoff
 * uses the fractional cadence; local preview/capture remain live. Zero,
 * negative and non-finite budgets are errors, never legacy defaults.
 * Existing 20 ms video-worker scheduling wait and debug pin apply. */
int veil_media_engine_set_video_budget(VeilMediaEngine *engine,
                                        int max_bitrate_kbps, double max_fps);
/* Optional endpoint-local send pause (0/1). Camera/screen capture, preview,
 * audio, RTCP and receiving video remain live. Already queued Veil packets
 * cannot be recalled. Pausing never waits on the video worker; resuming
 * requests a keyframe with a 20 ms scheduling wait, retry on ERR_STATE.
 * The pause persists across video source/stream changes on this engine. */
int veil_media_engine_set_video_send_paused(VeilMediaEngine *engine, int paused);

/* Open the platform camera and drive the video send stream from it (near
 * width x height at fps; the camera picks the closest supported format). Video
 * send must already be started (veil_media_engine_start_video send=1). Returns
 * VEIL_MEDIA_OK, or VEIL_MEDIA_ERR_STATE if this platform has no camera backend
 * or the device can't be opened. Idempotent. */
int veil_media_engine_start_camera(VeilMediaEngine *engine, int width,
                                   int height, int fps);
/* Device-aware variant. `device_id` is an opaque id returned by
 * veil_media_engine_list_video_inputs; NULL/empty selects the platform
 * default. Kept separate so existing native consumers retain ABI. */
int veil_media_engine_start_camera_device(VeilMediaEngine *engine,
                                          const char *device_id, int width,
                                          int height, int fps);
int veil_media_engine_stop_camera(VeilMediaEngine *engine);

/* Screen share: capture a display into the SAME VP8 send source the camera
 * uses (frames downscaled to <= width, at fps) — a source switch, not a new
 * track, so the peer renders it with no changes. Starting the screen stops a
 * running camera (one source at a time); the app layer restores the camera
 * when the share ends. macOS backend only for now; other platforms return
 * VEIL_MEDIA_ERR_STATE. Capture fails until OS Screen Recording permission is
 * granted. Idempotent. */
int veil_media_engine_start_screen(VeilMediaEngine *engine, int width,
                                   int fps);
/* Source-aware additive variant. `source_id` comes from
 * veil_media_list_screen_inputs; NULL/empty selects the default display. */
int veil_media_engine_start_screen_source(VeilMediaEngine *engine,
                                          const char *source_id, int width,
                                          int fps);
int veil_media_engine_stop_screen(VeilMediaEngine *engine);

/* Push one captured I420 frame into the video send stream (platform camera /
 * screen capturer, or Dart). Planes may be strided; pass ts_us=0 to stamp now.
 * No-op if video send isn't started. */
int veil_media_engine_push_video_frame(VeilMediaEngine *engine,
                                       const uint8_t *y, const uint8_t *u,
                                       const uint8_t *v, int width, int height,
                                       int stride_y, int stride_u, int stride_v,
                                       int64_t ts_us);

/* Android Camera2 fast path: convert a strided YUV_420_888 frame (shared U/V
 * pixel stride) to upright I420 with libyuv, then enqueue it directly. This
 * keeps per-pixel de-striding/rotation out of Dart's capture isolate. Rotation
 * is clockwise and must be 0/90/180/270. */
int veil_media_engine_push_android420_frame(
    VeilMediaEngine *engine, const uint8_t *y, const uint8_t *u,
    const uint8_t *v, int width, int height, int stride_y, int stride_u,
    int stride_v, int pixel_stride_uv, int rotation, int64_t ts_us);

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
char *veil_media_engine_list_video_inputs(VeilMediaEngine *engine);
/* Platform screen sources. This list is process-global rather than tied to an
 * engine so 1:1 and group call UIs share the same IDs. */
char *veil_media_list_screen_inputs(void);
/* 1 = granted, 0 = denied/not-yet-granted, -1 = unsupported platform. */
int veil_media_screen_capture_access(void);
/* Requests OS consent after an explicit user action; same return contract. */
int veil_media_request_screen_capture_access(void);
int veil_media_engine_select_audio_input(VeilMediaEngine *engine,
                                         const char *id);
int veil_media_engine_select_audio_output(VeilMediaEngine *engine,
                                          const char *id);

/* ---- Stats ---------------------------------------------------------------
 * Additive `audio_rx_pkts` counts RTP packets accepted by the audio receive
 * stream, excluding video and RTCP. It is valid only with worker_stalled=0;
 * it does not measure decoded/played audio. Worker scheduling waits are 20 ms
 * `audio_rx_native_age_ms` is elapsed local native time since the receive
 * stream's last accepted RTP packet (-1 before audio or on worker timeout).
 * It excludes host timer lag. `audio_concealed_samples`,
 * `audio_concealment_events`, `audio_interruption_count` and
 * `audio_interruption_duration_ms` expose cumulative receive-stream playout
 * statistics, valid only with worker_stalled=0.
 * An operation already started is waited out for lifetime safety.
 * `audio_tx_pkts` counts audio RTP emitted by the send stream, with the same
 * sample-validity rule. `mic_muted` is the native mute intent, not device state.
 * `audio_tx_rtp_*` report endpoint-local Opus RTP generation and local queue
 * admission independently of video/RTCP and the audio worker stats timeout.
 * Source/queue ages are -1 before a matching packet, never a zero-delay pass.
 * Gaps include legitimate DTX silence; successful admission is not delivery.
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
