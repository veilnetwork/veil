/* SPDX-License-Identifier: MIT
 *
 * veil_audio_record.h — standalone voice-message recorder ABI.
 *
 * Records the microphone to an Opus byte stream ENTIRELY IN RAM: it reuses the
 * same platform AudioDeviceModule the call engine uses (AVAudioEngine on macOS,
 * AAudio on Android, webrtc's default ADM on Linux/Windows) and the same
 * bundled Opus encoder, but drives NO webrtc::Call / AudioState / RTP — it just
 * taps captured PCM through a custom AudioTransport, Opus-encodes each 10 ms
 * frame, and appends it to a heap buffer. Nothing is ever written to disk (the
 * xVeil deniability canon: decrypted/plaintext bytes never touch the FS).
 *
 * On stop it returns the finished stream in a small self-describing container
 * (see VOICE_OPUS framing in veil_audio_record.cc), the clip duration, and a
 * downsampled amplitude waveform for the UI. The caller stores the returned
 * bytes in the encrypted container and frees them with
 * veil_media_recorder_free_bytes.
 *
 * Threading: create/start/stop/destroy on one control thread (the Dart FFI
 * caller). Capture callbacks run on the platform audio thread; the recorder
 * serializes buffer access internally. level() is lock-free (atomic) so the UI
 * can poll it at frame rate for a live meter.
 */

#ifndef VEIL_AUDIO_RECORD_H
#define VEIL_AUDIO_RECORD_H

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

typedef struct VeilAudioRecorder VeilAudioRecorder;

/* Result codes mirror veil_media_engine.h. */
#define VEIL_REC_OK 0
#define VEIL_REC_ERR -1        /* generic failure */
#define VEIL_REC_ERR_ARG -2    /* bad argument */
#define VEIL_REC_ERR_STATE -3  /* wrong state (already/never started) */
#define VEIL_REC_ERR_DEVICE -4 /* mic unavailable / permission denied */

/* Create a recorder: builds the platform ADM + an Opus encoder. Does NOT start
 * capture (call veil_media_recorder_start). Returns NULL on failure. */
VeilAudioRecorder* veil_media_recorder_create(void);

/* Begin capturing the microphone. Idempotent while recording. Returns
 * VEIL_REC_OK, or VEIL_REC_ERR_DEVICE if the mic can't be opened (e.g. the OS
 * permission was denied). */
int veil_media_recorder_start(VeilAudioRecorder* rec);

/* Most-recent capture level in 0..1 (a smoothed peak), for a live UI meter.
 * Lock-free; returns 0 before the first frame or after stop. */
float veil_media_recorder_level(VeilAudioRecorder* rec);

/* Elapsed captured milliseconds so far (for a live duration counter). */
int veil_media_recorder_elapsed_ms(VeilAudioRecorder* rec);

/* Stop capture and finalize the clip.
 *   out_bytes    : receives a heap pointer to the VOICE_OPUS byte stream (free
 *                  with veil_media_recorder_free_bytes). NULL/len 0 if nothing
 *                  was captured.
 *   out_len      : receives the byte length.
 *   out_duration_ms : receives the clip duration in ms.
 *   waveform_out : caller buffer that receives `waveform_bars` amplitude bytes
 *                  (0..255), the clip downsampled + peak-normalized. May be NULL
 *                  to skip the waveform.
 *   waveform_bars: number of bars to write into waveform_out.
 * Returns VEIL_REC_OK on success (even for an empty clip), or an error code. */
int veil_media_recorder_stop(VeilAudioRecorder* rec, uint8_t** out_bytes,
                             size_t* out_len, int* out_duration_ms,
                             uint8_t* waveform_out, int waveform_bars);

/* Free a buffer returned by veil_media_recorder_stop. */
void veil_media_recorder_free_bytes(uint8_t* bytes);

/* Destroy the recorder (stops capture if still running). */
void veil_media_recorder_destroy(VeilAudioRecorder* rec);

#pragma GCC visibility pop

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VEIL_AUDIO_RECORD_H */
