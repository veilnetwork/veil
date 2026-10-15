#ifndef VEIL_AUDIO_ADAPTOR_CONFIG_H_
#define VEIL_AUDIO_ADAPTOR_CONFIG_H_

namespace veil_media {
// Local encoder configuration, never transmitted. The linked factory must
// recognize this exact version before delegating to the protobuf parser.
inline constexpr char kFramingAudioAdaptorConfig[] = "veil.opus.framing.v1";
}  // namespace veil_media

#endif
