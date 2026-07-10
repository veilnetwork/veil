/* SPDX-License-Identifier: MIT
 *
 * veil_video_note.h — video-note ("кружочек") recorder ABI.
 *
 * Records the camera + microphone ENTIRELY INTO RAM as the VNOTE1 container:
 * VP8 video frames + an embedded VOICE_OPUS audio block, both produced by the
 * SAME vendored libwebrtc the call engine uses. No platform recorder is
 * involved on purpose — MediaRecorder/AVAssetWriter write plaintext FILES
 * (canon violation), and no standard container plays from RAM on both
 * platforms anyway (AVPlayer cannot decode WebM/VP8, the same trap as
 * Opus/AVFoundation for voice). Playback is the in-app twin brick: VP8 decode
 * -> frame pull (like remote call video), audio via the voice WAV path.
 *
 * VNOTE1 container (self-describing, little-endian):
 *   offset 0 : "VN01" magic (4 bytes)
 *   offset 4 : u8  version = 1
 *   offset 5 : u8  flags (bit0 = has audio, bit1 = has video)
 *   offset 6 : u16 width   (encoded, square after center-crop)
 *   offset 8 : u16 height
 *   offset 10: u8  fps (target)
 *   offset 11: u8  reserved = 0
 *   offset 12: u32 duration_ms
 *   offset 16: u32 audio_len — byte length of the embedded audio block
 *   offset 20: u32 video_frame_count
 *   offset 24: audio_len bytes — a complete VOICE_OPUS ("VOP1") block, decoded
 *              by the existing voice bricks (decode-to-WAV works unchanged)
 *   then     : video_frame_count x [ u32 ts_ms ][ u8 flags(bit0=keyframe) ]
 *                                  [ u32 len ][ len VP8 bytes ]
 *
 * Capture sources: macOS/Linux use the platform camera capturer the calls use
 * (veil_camera.h) — start() opens it. Android has NO native camera backend:
 * the Dart-side capturer (same as calls) feeds frames through
 * veil_media_vnote_recorder_push_frame instead, and start() only starts the
 * microphone there.
 *
 * Threading: create/start/stop/destroy on one control thread. Camera frames
 * arrive on the capture queue, mic PCM on the audio thread; level/elapsed are
 * safe to poll from the UI.
 *
 * The recorder builds its own ADM (mic) exactly like the voice recorder — the
 * app layer must not run a call and a video-note recording at the same time
 * (one AudioTransport per ADM; two live ADMs would double-tap the mic HW).
 */

#ifndef VEIL_VIDEO_NOTE_H
#define VEIL_VIDEO_NOTE_H

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

typedef struct VeilVnoteRecorder VeilVnoteRecorder;

#define VEIL_VNOTE_OK 0
#define VEIL_VNOTE_ERR -1
#define VEIL_VNOTE_ERR_ARG -2
#define VEIL_VNOTE_ERR_DEVICE -3

/* Create a recorder targeting a [width]x[width] square at [fps] (camera
 * frames are center-cropped square and downscaled; <=0 picks the defaults
 * 480 @ 24). [native_camera] != 0 makes start() open the platform camera
 * where a backend exists; 0 = frames come ONLY through push_frame (the
 * Android path, and tests that must not mix in a real camera). Builds the
 * platform ADM + Opus encoder + VP8 encoder. Returns NULL when the native
 * layer is unavailable. Does NOT start capture. */
VeilVnoteRecorder* veil_media_vnote_recorder_create(int width, int fps,
                                                    int native_camera);

/* Begin capturing: microphone always; the platform camera where a native
 * backend exists (macOS/Linux — Android pushes frames from Dart instead).
 * Returns VEIL_VNOTE_ERR_DEVICE if the mic can't be opened. Idempotent. */
int veil_media_vnote_recorder_start(VeilVnoteRecorder* rec);

/* Feed one strided I420 frame (the Dart camera capturer on Android; also the
 * synthetic-frame path in tests). Same plane/stride contract as
 * veil_media_engine_push_video_frame. ts_us <= 0 stamps "now". */
int veil_media_vnote_recorder_push_frame(VeilVnoteRecorder* rec,
                                         const uint8_t* y, const uint8_t* u,
                                         const uint8_t* v, int width,
                                         int height, int stride_y,
                                         int stride_u, int stride_v,
                                         int64_t ts_us);

/* Most-recent smoothed mic level in 0..1 (live meter). */
float veil_media_vnote_recorder_level(VeilVnoteRecorder* rec);

/* Copy the latest CAPTURED frame (post crop/scale — exactly what is being
 * encoded) as tightly packed RGBA into dst: the live round self-preview.
 * Returns seq (>0) when copied, 0 when none yet, -1 when dst_cap is too
 * small (out_w/out_h still set). */
int veil_media_vnote_recorder_frame(VeilVnoteRecorder* rec, uint8_t* dst,
                                    int dst_cap, int* out_w, int* out_h);

/* Elapsed recording time so far, in ms (wall clock since start). */
int veil_media_vnote_recorder_elapsed_ms(VeilVnoteRecorder* rec);

/* Stop capture and finalize the VNOTE1 stream. On success *out_bytes is a
 * malloc'd buffer (free with veil_media_vnote_free_bytes), *out_len its
 * size, *out_duration_ms the clip length. An empty clip (no frames AND no
 * audio) yields out_len 0. */
int veil_media_vnote_recorder_stop(VeilVnoteRecorder* rec, uint8_t** out_bytes,
                                   size_t* out_len, int* out_duration_ms);

/* Free a buffer returned by veil_media_vnote_recorder_stop. */
void veil_media_vnote_free_bytes(uint8_t* bytes);

/* Free the recorder (stops capture if still running). Idempotent. */
void veil_media_vnote_recorder_destroy(VeilVnoteRecorder* rec);

/* ── Playback ───────────────────────────────────────────────────────────────
 *
 * Pull-driven decode: the app plays the AUDIO section through the existing
 * voice path (decode-to-WAV -> loopback -> platform player — exact position,
 * pause, speed for free) and polls veil_media_vnote_player_frame_at with that
 * position; the player decodes forward on demand (VP8 decode of a small
 * square is sub-millisecond) and rewinds via the nearest preceding keyframe.
 * No decode thread, no A/V clock of its own. */

typedef struct VeilVnotePlayer VeilVnotePlayer;

/* Parse a VNOTE1 byte stream (copies it; strict bounds checks — the clip is
 * network-received). Returns NULL on a malformed container. */
VeilVnotePlayer* veil_media_vnote_player_create(const uint8_t* vnote,
                                                size_t len);

int veil_media_vnote_player_duration_ms(VeilVnotePlayer* p);
int veil_media_vnote_player_width(VeilVnotePlayer* p);
int veil_media_vnote_player_height(VeilVnotePlayer* p);
int veil_media_vnote_player_has_audio(VeilVnotePlayer* p);

/* Copy out the embedded VOICE_OPUS audio block (malloc'd; free with
 * veil_media_vnote_free_bytes). VEIL_VNOTE_ERR when the note is silent. */
int veil_media_vnote_player_audio(VeilVnotePlayer* p, uint8_t** out_bytes,
                                  size_t* out_len);

/* Decode up to the frame at [ms] and copy the latest decoded frame as tightly
 * packed RGBA into dst. Returns a monotonically increasing seq (>0) when a
 * frame is available, 0 when none decoded yet, -1 when dst_cap is too small
 * (out_w/out_h are still set — resize and retry). Rewinding restarts from the
 * nearest preceding keyframe. */
int veil_media_vnote_player_frame_at(VeilVnotePlayer* p, int ms, uint8_t* dst,
                                     int dst_cap, int* out_w, int* out_h);

void veil_media_vnote_player_destroy(VeilVnotePlayer* p);

#pragma GCC visibility pop

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VEIL_VIDEO_NOTE_H */
