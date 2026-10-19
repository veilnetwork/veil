#include "bounded_audio_encoder.h"
#include "api/environment/environment_factory.h"
#include "system_wrappers/include/clock.h"
#include "third_party/opus/src/include/opus.h"
#include <array>
#include <cstdio>
#include <cstdlib>

static void require(bool good, const char* message) {
  if (!good) { std::fprintf(stderr, "%s\n", message); std::abort(); }
}

int main() {
  webrtc::SimulatedClock clock(0);
  auto priority = std::make_shared<veil_media::AudioPacketPriority>();
  priority->ExpectVideo(true, 0);
  const auto env = webrtc::CreateEnvironment(&clock);
  auto factory = webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>(
      nullptr, 0, priority);
  auto encoder = factory->Create(env, webrtc::SdpAudioFormat("opus", 48000, 2,
      {{"minptime", "20"}, {"maxptime", "60"}, {"stereo", "0"},
       {"useinbandfec", "1"}, {"usedtx", "0"}}), {.payload_type = 111});
  require(encoder != nullptr, "Opus unavailable");
  encoder->SetReceiverFrameLengthRange(20, 60);
  require(encoder->EnableAudioNetworkAdaptor(veil_media::kFramingAudioAdaptorConfig), "ANA unavailable");
  encoder->OnReceivedOverhead(380);
  auto allocation = [&](int bps) {
    webrtc::BitrateAllocationUpdate update;
    update.target_bitrate = webrtc::DataRate::BitsPerSec(bps);
    encoder->OnReceivedUplinkAllocation(update);
  };
  int error = 0;
  OpusDecoder* decoder = opus_decoder_create(48000, 1, &error);
  require(decoder && error == OPUS_OK, "decoder unavailable");
  std::array<int16_t, 480> input{};
  std::array<int16_t, 5760> decoded{};
  uint32_t timestamp = 0, previous = 0;
  int previous_ms = 0, packets = 0, video = 0, long_packets = 0;
  int64_t long_not_before = 0;
  auto feed = [&](int blocks, bool sending_video, int maximum_ms,
                  int settled_ms = 0) {
    const int64_t start = clock.TimeInMicroseconds();
    for (int b = 0; b < blocks; ++b) {
      const int64_t now = clock.TimeInMicroseconds();
      if (sending_video && now % 1'000'000 == 0 && priority->BeginVideo()) {
        ++video; priority->EndVideo(true, now);
      }
      for (size_t i = 0; i < input.size(); ++i)
        input[i] = (timestamp + i) % 48 < 24 ? 2000 : -2000;
      webrtc::Buffer packet;
      const auto info = encoder->Encode(timestamp, input, &packet);
      if (info.encoded_bytes) {
        const int samples = opus_packet_get_nb_samples(packet.data(), packet.size(), 48000);
        require(samples > 0 && samples / 48 <= maximum_ms, "long packet preceded secondary yield");
        require(opus_decode(decoder, packet.data(), packet.size(), decoded.data(), decoded.size(), 0) == samples,
                "actual Opus decode failed across limit change");
        if (packets) require(info.encoded_timestamp - previous == uint32_t(previous_ms * 48),
                             "RTP timestamp discontinuity");
        previous = info.encoded_timestamp; previous_ms = samples / 48; ++packets;
        if (previous_ms == 60) {
          ++long_packets; require(now >= long_not_before, "60 ms before real video quiet interval");
        }
        if (settled_ms && now - start > 1'000'000 && previous_ms != settled_ms) {
          std::fprintf(stderr, "phase_start_us=%lld now_us=%lld expected=%d actual=%d blocked=%d wanted_long=%d next_blocks=%zu\n",
              static_cast<long long>(start), static_cast<long long>(now), settled_ms,
              previous_ms, priority->VideoBlocked(), priority->WantsLongPackets(),
              encoder->Num10MsFramesInNextPacket());
          require(false, "legitimate codec duration failed to settle");
        }
      }
      require(encoder->GetTargetBitrate() >= 24000 && encoder->GetTargetBitrate() <= 32000,
              "payload target outside existing speech rails");
      timestamp += 480; clock.AdvanceTimeMilliseconds(10);
    }
  };
  allocation(160000);
  feed(2, true, 40);
  // Encode establishes Opus's uplink smoother; a real control callback then
  // evaluates ANA with that metric, as in the production send stream.
  encoder->OnReceivedRtt(20);
  feed(500, true, 40, 40);
  const int before_video = video;
  allocation(64000); feed(300, true, 40, 40);
  require(video > before_video && !priority->VideoBlocked(), "BWE alone paused healthy video");
  require(long_packets == 0, "premature 60-ms allocation");
  const int64_t pause_at = clock.TimeInMicroseconds();
  priority->PauseVideo(true, pause_at);
  long_not_before = pause_at + veil_media::AudioPacketPriority::kQuietUs;
  feed(200, false, 40);
  // No fresh allocation callback: the cached real estimate must be applied
  // once quiet is proved, without requiring a new transport estimate.
  feed(200, false, 60, 60);
  require(long_packets > 0, "fully yielded narrow path lost 60-ms support");
  priority->PauseVideo(false, clock.TimeInMicroseconds());
  require(priority->VideoBlocked(), "resume ignored current long packet mode");
  feed(200, true, 60, 60);
  require(priority->VideoBlocked(), "unfunded short packets reopened video");
  allocation(160000);
  require(priority->VideoBlocked(), "requested short allocation was treated as emitted ACK");
  const int resumed_before = video;
  feed(200, true, 60, 40);
  require(!priority->VideoBlocked() && video > resumed_before, "video did not resume after real short packet");
  opus_decoder_destroy(decoder);
  std::printf("ok: %d real Opus packets decode; low BWE keeps video live with <=40ms; quiet permits60; short ACK resumes video\n", packets);
}
