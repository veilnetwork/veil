#ifndef VEIL_AUDIO_ADAPTOR_CONFIG_H_
#define VEIL_AUDIO_ADAPTOR_CONFIG_H_

namespace veil_media {
// Local encoder configuration, never transmitted. The linked factory must
// recognize this exact version before delegating to the protobuf parser.
inline constexpr char kFramingAudioAdaptorConfig[] = "veil.opus.framing.v1";
// Keep useful signal under pressure before sacrificing more video. This is
// payload only; the framing allocator accounts for actual packet overhead.
inline constexpr int kFramingAudioMinPayloadBps = 24'000;
}  // namespace veil_media

#endif
