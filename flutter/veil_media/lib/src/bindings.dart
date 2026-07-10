import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'native.dart';

/// Opaque engine handle (VeilMediaEngine*).
final class VeilMediaEngineHandle extends Opaque {}

// create(veil_chan u64, local_id u8[32], peer_id u8[32]) -> engine*
final Pointer<VeilMediaEngineHandle> Function(
        int, Pointer<Uint8>, Pointer<Uint8>) veilMediaEngineCreate =
    nativeLib
        .lookup<
            NativeFunction<
                Pointer<VeilMediaEngineHandle> Function(Uint64, Pointer<Uint8>,
                    Pointer<Uint8>)>>('veil_media_engine_create')
        .asFunction();

// destroy(engine*)
final void Function(Pointer<VeilMediaEngineHandle>) veilMediaEngineDestroy =
    nativeLib
        .lookup<NativeFunction<Void Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_destroy')
        .asFunction();

// start_audio(engine*, send int, recv int) -> int
final int Function(Pointer<VeilMediaEngineHandle>, int, int)
    veilMediaEngineStartAudio = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>, Int32,
                    Int32)>>('veil_media_engine_start_audio')
        .asFunction();

// stop_audio(engine*) -> int
final int Function(Pointer<VeilMediaEngineHandle>) veilMediaEngineStopAudio =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_stop_audio')
        .asFunction();

// start_video(engine*, send int, recv int) -> int
final int Function(Pointer<VeilMediaEngineHandle>, int, int)
    veilMediaEngineStartVideo = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>, Int32,
                    Int32)>>('veil_media_engine_start_video')
        .asFunction();

// stop_video(engine*) -> int
final int Function(Pointer<VeilMediaEngineHandle>) veilMediaEngineStopVideo =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_stop_video')
        .asFunction();

// push_video_frame(engine*, y, u, v, w, h, stride_y, stride_u, stride_v, ts_us) -> int
final int Function(Pointer<VeilMediaEngineHandle>, Pointer<Uint8>,
        Pointer<Uint8>, Pointer<Uint8>, int, int, int, int, int, int)
    veilMediaEnginePushVideoFrame = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<VeilMediaEngineHandle>,
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Pointer<Uint8>,
                    Int32,
                    Int32,
                    Int32,
                    Int32,
                    Int32,
                    Int64)>>('veil_media_engine_push_video_frame')
        .asFunction();

// start_camera(engine*, width int, height int, fps int) -> int
final int Function(Pointer<VeilMediaEngineHandle>, int, int, int)
    veilMediaEngineStartCamera = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>, Int32, Int32,
                    Int32)>>('veil_media_engine_start_camera')
        .asFunction();

// stop_camera(engine*) -> int
final int Function(Pointer<VeilMediaEngineHandle>) veilMediaEngineStopCamera =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_stop_camera')
        .asFunction();

// start_screen(engine*, width int, fps int) -> int
final int Function(Pointer<VeilMediaEngineHandle>, int, int)
    veilMediaEngineStartScreen = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>, Int32,
                    Int32)>>('veil_media_engine_start_screen')
        .asFunction();

// stop_screen(engine*) -> int
final int Function(Pointer<VeilMediaEngineHandle>) veilMediaEngineStopScreen =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_stop_screen')
        .asFunction();

// get_video_frame(engine*, dst, dst_cap, out_w, out_h) -> int seq
final int Function(Pointer<VeilMediaEngineHandle>, Pointer<Uint8>, int,
        Pointer<Int32>, Pointer<Int32>) veilMediaEngineGetVideoFrame =
    nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<VeilMediaEngineHandle>,
                    Pointer<Uint8>,
                    Int32,
                    Pointer<Int32>,
                    Pointer<Int32>)>>('veil_media_engine_get_video_frame')
        .asFunction();

// get_local_video_frame(engine*, dst, dst_cap, out_w, out_h) -> int seq
final int Function(Pointer<VeilMediaEngineHandle>, Pointer<Uint8>, int,
        Pointer<Int32>, Pointer<Int32>) veilMediaEngineGetLocalVideoFrame =
    nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<VeilMediaEngineHandle>,
                    Pointer<Uint8>,
                    Int32,
                    Pointer<Int32>,
                    Pointer<Int32>)>>('veil_media_engine_get_local_video_frame')
        .asFunction();

// set_mic_muted(engine*, muted int) -> int
final int Function(Pointer<VeilMediaEngineHandle>, int)
    veilMediaEngineSetMicMuted = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>,
                    Int32)>>('veil_media_engine_set_mic_muted')
        .asFunction();

// set_speaker_muted(engine*, muted int) -> int
final int Function(Pointer<VeilMediaEngineHandle>, int)
    veilMediaEngineSetSpeakerMuted = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>,
                    Int32)>>('veil_media_engine_set_speaker_muted')
        .asFunction();

// list_audio_inputs(engine*) -> char* (heap JSON, free with veil_media_free_string)
final Pointer<Utf8> Function(Pointer<VeilMediaEngineHandle>)
    veilMediaEngineListAudioInputs = nativeLib
        .lookup<
                NativeFunction<
                    Pointer<Utf8> Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_list_audio_inputs')
        .asFunction();

final Pointer<Utf8> Function(Pointer<VeilMediaEngineHandle>)
    veilMediaEngineListAudioOutputs = nativeLib
        .lookup<
                NativeFunction<
                    Pointer<Utf8> Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_list_audio_outputs')
        .asFunction();

// select_audio_input(engine*, id char*) -> int
final int Function(Pointer<VeilMediaEngineHandle>, Pointer<Utf8>)
    veilMediaEngineSelectAudioInput = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>,
                    Pointer<Utf8>)>>('veil_media_engine_select_audio_input')
        .asFunction();

final int Function(Pointer<VeilMediaEngineHandle>, Pointer<Utf8>)
    veilMediaEngineSelectAudioOutput = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilMediaEngineHandle>,
                    Pointer<Utf8>)>>('veil_media_engine_select_audio_output')
        .asFunction();

// get_stats(engine*) -> char* (heap JSON, free with veil_media_free_string)
final Pointer<Utf8> Function(Pointer<VeilMediaEngineHandle>)
    veilMediaEngineGetStats = nativeLib
        .lookup<
                NativeFunction<
                    Pointer<Utf8> Function(Pointer<VeilMediaEngineHandle>)>>(
            'veil_media_engine_get_stats')
        .asFunction();

// free_string(char*)
final void Function(Pointer<Utf8>) veilMediaFreeString = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>(
        'veil_media_free_string')
    .asFunction();

// version() -> const char* (static; do NOT free)
final Pointer<Utf8> Function() veilMediaVersion = nativeLib
    .lookup<NativeFunction<Pointer<Utf8> Function()>>('veil_media_version')
    .asFunction();

// ---- Voice-message recorder (mic -> Opus -> RAM) --------------------------

/// Opaque recorder handle (VeilAudioRecorder*).
final class VeilAudioRecorderHandle extends Opaque {}

// recorder_create() -> recorder* (NULL on failure)
final Pointer<VeilAudioRecorderHandle> Function() veilMediaRecorderCreate =
    nativeLib
        .lookup<NativeFunction<Pointer<VeilAudioRecorderHandle> Function()>>(
            'veil_media_recorder_create')
        .asFunction();

// recorder_start(recorder*) -> int
final int Function(Pointer<VeilAudioRecorderHandle>) veilMediaRecorderStart =
    nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilAudioRecorderHandle>)>>(
            'veil_media_recorder_start')
        .asFunction();

// recorder_level(recorder*) -> float 0..1
final double Function(Pointer<VeilAudioRecorderHandle>) veilMediaRecorderLevel =
    nativeLib
        .lookup<
            NativeFunction<
                Float Function(Pointer<VeilAudioRecorderHandle>)>>(
            'veil_media_recorder_level')
        .asFunction();

// recorder_elapsed_ms(recorder*) -> int
final int Function(Pointer<VeilAudioRecorderHandle>)
    veilMediaRecorderElapsedMs = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<VeilAudioRecorderHandle>)>>(
            'veil_media_recorder_elapsed_ms')
        .asFunction();

// recorder_stop(recorder*, out_bytes**, out_len*, out_duration_ms*,
//               waveform_out*, waveform_bars) -> int
final int Function(Pointer<VeilAudioRecorderHandle>, Pointer<Pointer<Uint8>>,
        Pointer<Size>, Pointer<Int32>, Pointer<Uint8>, int)
    veilMediaRecorderStop = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<VeilAudioRecorderHandle>,
                    Pointer<Pointer<Uint8>>,
                    Pointer<Size>,
                    Pointer<Int32>,
                    Pointer<Uint8>,
                    Int32)>>('veil_media_recorder_stop')
        .asFunction();

// recorder_free_bytes(bytes*)
final void Function(Pointer<Uint8>) veilMediaRecorderFreeBytes = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>(
        'veil_media_recorder_free_bytes')
    .asFunction();

// recorder_destroy(recorder*)
final void Function(Pointer<VeilAudioRecorderHandle>) veilMediaRecorderDestroy =
    nativeLib
        .lookup<
            NativeFunction<
                Void Function(Pointer<VeilAudioRecorderHandle>)>>(
            'veil_media_recorder_destroy')
        .asFunction();

// ---- Voice-message player (VOICE_OPUS -> PCM -> ADM speaker) ---------------

/// Opaque player handle (VeilAudioPlayer*).
final class VeilAudioPlayerHandle extends Opaque {}

// player_create(voice_opus*, len) -> player* (NULL on failure)
final Pointer<VeilAudioPlayerHandle> Function(Pointer<Uint8>, int)
    veilMediaPlayerCreate = nativeLib
        .lookup<
            NativeFunction<
                Pointer<VeilAudioPlayerHandle> Function(
                    Pointer<Uint8>, Size)>>('veil_media_player_create')
        .asFunction();

// player_start(player*) -> int
final int Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerStart =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_start')
        .asFunction();

final int Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerPause =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_pause')
        .asFunction();

final int Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerResume =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_resume')
        .asFunction();

// player_seek(player*, ms) -> int
final int Function(Pointer<VeilAudioPlayerHandle>, int) veilMediaPlayerSeek =
    nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<VeilAudioPlayerHandle>, Int32)>>(
            'veil_media_player_seek')
        .asFunction();

// player_set_speed(player*, speed) -> int
final int Function(Pointer<VeilAudioPlayerHandle>, double)
    veilMediaPlayerSetSpeed = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(
                    Pointer<VeilAudioPlayerHandle>, Float)>>(
            'veil_media_player_set_speed')
        .asFunction();

final int Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerPositionMs =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_position_ms')
        .asFunction();

final int Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerDurationMs =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_duration_ms')
        .asFunction();

final int Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerIsPlaying =
    nativeLib
        .lookup<NativeFunction<Int32 Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_is_playing')
        .asFunction();

// player_destroy(player*)
final void Function(Pointer<VeilAudioPlayerHandle>) veilMediaPlayerDestroy =
    nativeLib
        .lookup<NativeFunction<Void Function(Pointer<VeilAudioPlayerHandle>)>>(
            'veil_media_player_destroy')
        .asFunction();

// decode_wav(voice_opus*, len, out_wav**, out_len*) -> int
final int Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>)
    veilMediaDecodeWav = nativeLib
        .lookup<
            NativeFunction<
                Int32 Function(Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>,
                    Pointer<Size>)>>('veil_media_decode_wav')
        .asFunction();

// free_wav(wav*)
final void Function(Pointer<Uint8>) veilMediaFreeWav = nativeLib
    .lookup<NativeFunction<Void Function(Pointer<Uint8>)>>(
        'veil_media_free_wav')
    .asFunction();
