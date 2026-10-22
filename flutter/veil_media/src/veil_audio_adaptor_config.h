#ifndef VEIL_AUDIO_ADAPTOR_CONFIG_H_
#define VEIL_AUDIO_ADAPTOR_CONFIG_H_

#include <algorithm>

namespace veil_media {
// Local encoder configuration, never transmitted. The linked factory must
// recognize this exact version before delegating to the protobuf parser.
inline constexpr char kFramingAudioAdaptorConfig[] = "veil.opus.framing.v1";
// Keep useful signal under pressure before sacrificing more video. This is
// payload only; the framing allocator accounts for actual packet overhead.
inline constexpr int kFramingAudioMinPayloadBps = 24'000;

// The audio-only GCC ceiling must permit a funded 40-ms packet; otherwise
// ANA can remain at 60 ms forever and video cannot leave its packetization
// hold, even after the endpoint has released its measured audio pause. Include
// the negotiated RTP/TWCC header (20 bytes) and the encoder's 20% reserve.
// This is a ceiling for real congestion control, never an allocation floor.
// Routes without framing retain the small audio-only probe ceiling.
inline constexpr int framing_audio_transport_ceiling_bps(int route_overhead) {
  if (route_overhead <= 0) return 96'000;
  const int short_cost = kFramingAudioMinPayloadBps +
      (route_overhead + 20) * 8 * 1000 / 40;
  // ANA's duration comparison is strict; retain a whole bit/s after integer
  // rounding of raw_allocation / 5 * 4 in BoundedAudioEncoder.
  return std::max(96'000, (short_cost / 4 + 1) * 5);
}
}  // namespace veil_media

#endif
