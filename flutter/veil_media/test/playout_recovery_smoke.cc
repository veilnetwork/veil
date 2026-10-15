#undef NDEBUG  // The WebRTC release flags must not disable this regression.
#include "veil_playout_recovery.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>

class Decoder final : public webrtc::NetEq {
 public:
  int pulls = 0;
  int mode = 0;
  int GetAudio(webrtc::AudioFrame* f, bool* muted, int* rate,
               std::optional<Operation>) override {
    ++pulls;
    f->UpdateFrame(0, nullptr, 480, 48000,
        pulls > 1 && mode == 1 ? webrtc::AudioFrame::kPLC : webrtc::AudioFrame::kNormalSpeech,
        webrtc::AudioFrame::kVadActive, 1);
    f->mutable_data()[0] = pulls == 1 ? 1000 : 2000;
    if (muted) *muted = pulls > 1 && mode == 2;
    if (rate) *rate = 48000;
    return pulls > 1 && mode == 3 ? kFail : kOK;
  }
  int InsertPacket(const webrtc::RTPHeader&, std::span<const uint8_t>, const webrtc::RtpPacketInfo&) override { return 0; }
  void SetCodecs(const std::map<int, webrtc::SdpAudioFormat>&) override {}
  bool RegisterPayloadType(int, const webrtc::SdpAudioFormat&) override { return true; }
  int RemovePayloadType(uint8_t) override { return 0; }
  void SetMaximumBufferPackets(size_t) override {}
  void SetFastAccelerate(bool) override {}
  void RemoveAllPayloadTypes() override {}
  bool SetMinimumDelay(int) override { return true; }
  bool SetMaximumDelay(int) override { return true; }
  bool SetBaseMinimumDelayMs(int) override { return true; }
  int GetBaseMinimumDelayMs() const override { return 0; }
  int TargetDelayMs() const override { return 0; }
  int FilteredCurrentDelayMs() const override { return 0; }
  int NetworkStatistics(webrtc::NetEqNetworkStatistics*) override { return 0; }
  webrtc::NetEqNetworkStatistics CurrentNetworkStatistics() const override { return {}; }
  webrtc::NetEqLifetimeStatistics GetLifetimeStatistics() const override { return {}; }
  webrtc::NetEqOperationsAndState GetOperationsAndState() const override {
    webrtc::NetEqOperationsAndState s;
    s.current_buffer_size_ms = mode == 5 ? 100 : mode == 4 ? 500 : pulls < 2 ? 200 : 100;
    s.next_packet_available = mode != 6;
    return s;
  }
  std::optional<uint32_t> GetPlayoutTimestamp() const override { return std::nullopt; }
  int last_output_sample_rate_hz() const override { return 48000; }
  void FlushBuffers() override { std::abort(); }
  int SyncBufferSizeMs() const override { return mode == 6 ? 10 : 40; }
};
int main() {
  for (int mode = 0; mode <= 7; ++mode) {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = mode;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats);
    webrtc::AudioFrame frame;
    bool muted = false;
    int rate = 0;
    const auto action = mode == 7 ? std::optional<webrtc::NetEq::Operation>(
        webrtc::NetEq::Operation::kNormal) : std::nullopt;
    assert(recovering.GetAudio(&frame, &muted, &rate, action) == 0);
    assert(!muted && rate == 48000);
    assert(frame.speech_type_ == webrtc::AudioFrame::kNormalSpeech);
    assert(frame.data()[0] == (mode == 0 || mode == 4 ? 2000 : 1000));
    assert(observed->pulls == (mode >= 5 ? 1 : mode == 4 ? 17 : 2));
    assert(stats->discarded_ms == (mode == 4 ? 160u : mode == 0 ? 10u : 0u));
    assert(stats->fallback_frames == (mode == 1 || mode == 2 ? 1u : 0u));
  }
  std::puts("catch-up preserves usable speech on PLC/mute/error; work bounded to 16 pulls");
}
