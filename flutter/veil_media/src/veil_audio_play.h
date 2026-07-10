/* SPDX-License-Identifier: MIT
 *
 * veil_audio_play.h — voice-message playback ABI.
 *
 * Plays a VOICE_OPUS clip (see veil_audio_record.cc) ENTIRELY FROM RAM: the
 * Opus is decoded to PCM in memory and pushed to the platform speaker via the
 * same AudioDeviceModule the call engine uses (AVAudioEngine / AAudio / the
 * webrtc default) through a custom AudioTransport's NeedMorePlayData. Nothing
 * decrypted is written to disk, and playback does NOT depend on the OS media
 * frameworks (AVFoundation cannot decode Opus at all).
 *
 * Supports variable-speed playback (1.0 / 1.5 / 2.0) by consuming the decoded
 * PCM faster — a naive time-compression (pitch rises slightly; a WSOLA
 * pitch-preserving pass is a possible follow-up), which is the common v1 for
 * voice notes.
 *
 * Threading: create/start/pause/resume/seek/set_speed/destroy on one control
 * thread. Playout pulls run on the platform audio thread; position/state are
 * atomic so the UI can poll them for a progress bar.
 */

#ifndef VEIL_AUDIO_PLAY_H
#define VEIL_AUDIO_PLAY_H

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

typedef struct VeilAudioPlayer VeilAudioPlayer;

#define VEIL_PLAY_OK 0
#define VEIL_PLAY_ERR -1
#define VEIL_PLAY_ERR_ARG -2

/* Create a player over a VOICE_OPUS byte stream (decodes it to PCM in RAM).
 * Returns NULL on a bad container / decoder failure. Does NOT start playout. */
VeilAudioPlayer* veil_media_player_create(const uint8_t* voice_opus,
                                          size_t len);

/* Begin playout from the current position. Idempotent while playing. */
int veil_media_player_start(VeilAudioPlayer* p);

/* Pause / resume playout without losing position. */
int veil_media_player_pause(VeilAudioPlayer* p);
int veil_media_player_resume(VeilAudioPlayer* p);

/* Jump to [ms] into the clip (clamped). */
int veil_media_player_seek(VeilAudioPlayer* p, int ms);

/* Playback speed multiplier (e.g. 1.0, 1.5, 2.0). Clamped to a sane range. */
int veil_media_player_set_speed(VeilAudioPlayer* p, float speed);

/* Current playback position + total duration, in ms (for a progress bar). */
int veil_media_player_position_ms(VeilAudioPlayer* p);
int veil_media_player_duration_ms(VeilAudioPlayer* p);

/* 1 while actively playing (not paused, not finished); 0 otherwise. Poll this
 * to drive the play/pause icon + reset at end-of-clip. */
int veil_media_player_is_playing(VeilAudioPlayer* p);

/* Stop playout and free the player. */
void veil_media_player_destroy(VeilAudioPlayer* p);

/* Decode a VOICE_OPUS clip to 16 kHz mono float32 PCM (the input on-device
 * speech-to-text/whisper expects). On success returns VEIL_PLAY_OK and sets
 * *out_pcm to a malloc'd float buffer (free with veil_media_free_pcm) and
 * *out_samples to the sample count. Returns an error on a bad container. */
int veil_media_decode_pcm16k(const uint8_t* voice_opus, size_t len,
                             float** out_pcm, int* out_samples);

/* Free a buffer returned by veil_media_decode_pcm16k. */
void veil_media_free_pcm(float* pcm);

/* Decode a VOICE_OPUS clip to a complete RIFF/WAV byte stream (mono int16 PCM
 * at the clip's rate) held in RAM, so the OS media frameworks — which cannot
 * decode Opus (AVFoundation) — can play it from a loopback URL with seeking.
 * On success returns VEIL_PLAY_OK and sets *out_wav to a malloc'd buffer
 * (free with veil_media_free_wav) and *out_len to its size. */
int veil_media_decode_wav(const uint8_t* voice_opus, size_t len,
                          uint8_t** out_wav, size_t* out_len);

/* Free a buffer returned by veil_media_decode_wav. */
void veil_media_free_wav(uint8_t* wav);

#pragma GCC visibility pop

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VEIL_AUDIO_PLAY_H */
