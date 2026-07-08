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
