#undef NDEBUG  // The WebRTC release flags must not disable this regression.
#include "veil_playout_recovery.h"
#include "rtc_base/time_utils.h"
#include "api/audio_codecs/builtin_audio_decoder_factory.h"
#include "api/environment/environment_factory.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>

class Decoder final : public webrtc::NetEq {
 public:
  int pulls = 0;
  int mode = 0;
  int frame_ms = 0;
  int buffer_ms_override = 0;
  int target_ms = 0;
  int maximum_delay = 0;
  int maximum_delay_calls = 0;
  int insert_result = 0;
  int fault_after = 1;
  bool clocked_output = false;
  bool packet_witness = false;
  webrtc::RTPHeader clock_header{};
  uint32_t clock_origin = 0;
  int GetAudio(webrtc::AudioFrame* f, bool* muted, int* rate,
               std::optional<Operation>) override {
    ++pulls;
    f->UpdateFrame((clocked_output ? clock_origin : 10000) + pulls * 480, nullptr, 480, 48000,
        pulls > fault_after && mode == 1 ? webrtc::AudioFrame::kPLC : webrtc::AudioFrame::kNormalSpeech,
        webrtc::AudioFrame::kVadActive, 1);
    f->packet_infos_ = webrtc::RtpPacketInfos();
    if (clocked_output && packet_witness && pulls == 1)
      f->packet_infos_ = webrtc::RtpPacketInfos(webrtc::RtpPacketInfos::vector_type{
          webrtc::RtpPacketInfo(clock_header, webrtc::Timestamp::Micros(1000000))});
    f->mutable_data()[0] = clocked_output ? pulls * 1000 : pulls == 1 ? 1000 : 2000;
    if (muted) *muted = pulls > fault_after && mode == 2;
    if (rate) *rate = 48000;
    return pulls > fault_after && mode == 3 ? kFail : kOK;
  }
  int InsertPacket(const webrtc::RTPHeader&, std::span<const uint8_t>, const webrtc::RtpPacketInfo&) override { return insert_result; }
  void SetCodecs(const std::map<int, webrtc::SdpAudioFormat>&) override {}
  bool RegisterPayloadType(int, const webrtc::SdpAudioFormat&) override { return true; }
  int RemovePayloadType(uint8_t) override { return 0; }
  void SetMaximumBufferPackets(size_t) override {}
  void SetFastAccelerate(bool) override {}
  void RemoveAllPayloadTypes() override {}
  bool SetMinimumDelay(int) override { return true; }
  bool SetMaximumDelay(int n) override {
    ++maximum_delay_calls;
    if (n < 0) return false;
    maximum_delay = n;
    return true;
  }
  bool SetBaseMinimumDelayMs(int) override { return true; }
  int GetBaseMinimumDelayMs() const override { return 0; }
  int TargetDelayMs() const override { return target_ms; }
  int FilteredCurrentDelayMs() const override { return 0; }
  int NetworkStatistics(webrtc::NetEqNetworkStatistics*) override { return 0; }
  webrtc::NetEqNetworkStatistics CurrentNetworkStatistics() const override { return {}; }
  webrtc::NetEqLifetimeStatistics GetLifetimeStatistics() const override { return {}; }
  webrtc::NetEqOperationsAndState GetOperationsAndState() const override {
    webrtc::NetEqOperationsAndState s;
    s.current_buffer_size_ms = buffer_ms_override ? buffer_ms_override : mode == 8 ? 100 : mode == 9 ? 120 :
        mode == 5 ? 100 : mode == 4 ? 500 : pulls < 2 ? 280 : 100;
    s.next_packet_available = mode != 6;
    s.current_frame_size_ms = frame_ms;
    return s;
  }
  std::optional<uint32_t> GetPlayoutTimestamp() const override { return std::nullopt; }
  int last_output_sample_rate_hz() const override { return 48000; }
  void FlushBuffers() override { std::abort(); }
  int SyncBufferSizeMs() const override { return mode == 6 ? 10 : 40; }
};

class RenderClock : public webrtc::ClockInterface {
 public:
  int64_t us = 1000000;
  int64_t TimeNanos() const override { return us * 1000; }
};

void DecodedAgeRegression(int mode = 0, int queued_ms = 90,
                          bool witness = true, bool aligned = true,
                          bool explicit_action = false, int target_ms = 0) {
  RenderClock wall;
  auto* previous = webrtc::SetClockForTesting(&wall);
  {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = mode;
    observed->fault_after = 2;
    observed->frame_ms = 40;
    observed->buffer_ms_override = queued_ms;
    observed->target_ms = target_ms;
    observed->clocked_output = true;
    observed->packet_witness = witness;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats);
    assert(recovering.RegisterPayloadType(111, webrtc::SdpAudioFormat("opus", 48000, 2)));
    webrtc::RTPHeader header{};
    header.ssrc = 11;
    header.payloadType = 111;
    const uint8_t payload[] = {1}; // The fake decoder accepts every payload.
    for (int i = 0; i < 4; ++i) {
      wall.us = 1000000 + i * 40000;
      header.timestamp = i * 1920;
      header.sequenceNumber = 20 + i;
      assert(recovering.InsertPacket(header, payload,
          webrtc::RtpPacketInfo(header, webrtc::Timestamp::Micros(wall.us))) == 0);
    }
    observed->clock_header = header;
    observed->clock_origin = header.timestamp - 480 + (aligned ? 0 : 9600);
    webrtc::AudioFrame frame;
    wall.us = 1250000;
    // Establish an actual decoded-packet witness without trimming. The next
    // 10-ms block has no packet metadata of its own, as real NetEq can emit.
    assert(recovering.GetAudio(&frame, nullptr, nullptr,
        webrtc::NetEq::Operation::kNormal) == 0);
    assert(observed->pulls == 1 && stats->discarded_ms == 0);
    wall.us = 1280000;
    auto action = explicit_action ? std::optional<webrtc::NetEq::Operation>(
        webrtc::NetEq::Operation::kNormal) : std::nullopt;
    assert(recovering.GetAudio(&frame, nullptr, nullptr, action) == 0);
    const bool attempt = queued_ms >= std::max(70, target_ms + 40) && witness && aligned &&
        !explicit_action && mode != 6;
    const bool skipped = attempt && mode == 0;
    assert(observed->pulls == (attempt ? 3 : 2));
    assert(stats->discarded_ms == (skipped ? 10u : 0u));
    assert(frame.data()[0] == (skipped ? 3000 : 2000));
    assert(frame.speech_type_ == webrtc::AudioFrame::kNormalSpeech);
    assert(frame.packet_infos_.empty());
    assert(stats->fallback_frames == (attempt && (mode == 1 || mode == 2) ? 1u : 0u));
  }
  webrtc::SetClockForTesting(previous);
}

int main() {
  // Exercise the production factory with real NetEq/PCMU. Draining stale
  // audio within one render callback must not age packets by those discarded
  // blocks: no additional wall/render time has elapsed.
  {
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEqFactory factory(stats);
    webrtc::NetEq::Config config;
    config.sample_rate_hz = 8000;
    auto neteq = factory.Create(webrtc::CreateEnvironment(), config,
                                webrtc::CreateBuiltinAudioDecoderFactory());
    assert(neteq->RegisterPayloadType(0, webrtc::SdpAudioFormat("PCMU", 8000, 1)));
    webrtc::RTPHeader header{};
    header.ssrc = 99;
    header.payloadType = 0;
    const std::vector<uint8_t> payload(160, 0x7f); // 20-ms G.711 packet.
    for (int i = 0; i < 25; ++i) {
      header.sequenceNumber = i;
      header.timestamp = i * 160;
      assert(neteq->InsertPacket(header, payload,
          webrtc::RtpPacketInfo(header, webrtc::Timestamp::Micros(1000000))) == 0);
    }
    webrtc::AudioFrame frame;
    assert(neteq->GetAudio(&frame) == 0);
    const auto state = neteq->GetOperationsAndState();
    std::printf("one render: discarded=%llu ms, packet waited=%llu ms\n",
        static_cast<unsigned long long>(stats->discarded_ms.load()),
        static_cast<unsigned long long>(state.last_waiting_time_ms));
    assert(stats->discarded_ms > 0); // Ensure this actually exercises catch-up.
    assert(state.last_waiting_time_ms == 10);
    for (int renders = 2; renders <= 3; ++renders) {
      assert(neteq->GetAudio(&frame) == 0);
      assert(neteq->GetOperationsAndState().last_waiting_time_ms == renders * 10);
    }
  }
  DecodedAgeRegression();
  // Physical render trace: RTP age initiated a trim with only 84 ms stored,
  // below the adaptive 120-ms target. The decoder then refilled that target,
  // causing repeated speech discards and keeping video permanently paused.
  DecodedAgeRegression(0, 90, true, true, false, 120);
  DecodedAgeRegression(0, 150, true, true, false, 120);
  DecodedAgeRegression(0, 160, true, true, false, 120);
  DecodedAgeRegression(0, 60); // Leave a complete packet plus 20 ms.
  DecodedAgeRegression(0, 90, false); // Never infer an output clock.
  DecodedAgeRegression(0, 90, true, false); // A stale decoder origin.
  DecodedAgeRegression(0, 90, true, true, true); // Caller-directed operation.
  for (int mode : {1, 2, 3, 6}) DecodedAgeRegression(mode);
  for (int mode = 0; mode <= 9; ++mode) {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = mode;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    auto clock = std::make_unique<webrtc::TickTimer>();
    auto* observed_clock = clock.get();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats, std::move(clock));
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
    assert(observed_clock->ticks() == 1); // up to 17 decoder pulls, one render tick
    assert(recovering.GetAudio(&frame, &muted, &rate,
        webrtc::NetEq::Operation::kNormal) == (mode == 3 ? webrtc::NetEq::kFail : 0));
    assert(observed_clock->ticks() == 2);
  }
  // The same call has two real NetEq wrappers, but only one is catching up.
  // Its event must be attributed to the actual accepted RTP source.
  {
    auto totals = std::make_shared<veil_media::PlayoutRecoveryStats>();
    auto first = std::make_unique<Decoder>();
    auto second = std::make_unique<Decoder>();
    second->mode = 5; // 100 ms, no decoded speech is dropped
    veil_media::RecoveringNetEq a(std::move(first), totals);
    veil_media::RecoveringNetEq b(std::move(second), totals);
    webrtc::RTPHeader header;
    const webrtc::RtpPacketInfo info;
    header.ssrc = 11;
    a.InsertPacket(header, {}, info);
    header.ssrc = 22;
    b.InsertPacket(header, {}, info);
    webrtc::AudioFrame frame;
    a.GetAudio(&frame, nullptr, nullptr, std::nullopt);
    b.GetAudio(&frame, nullptr, nullptr, std::nullopt);
    const auto one = totals->receivers.Snapshot(11);
    const auto two = totals->receivers.Snapshot(22);
    assert(one.known && two.known && one.origin != two.origin);
    assert(one.discarded_ms == 10 && one.last_discard_us > 0);
    assert(two.discarded_ms == 0 && two.last_discard_us == 0);
    assert(!totals->receivers.Snapshot(33).known);
  }
  // The decoder must not refill toward a target above the catch-up budget.
  // Reserve one decoded packet's headroom for ordinary packet-sized arrivals.
  {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = 5; // quiet, no catch-up needed
    observed->frame_ms = 40;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats);
    assert(observed->maximum_delay == 100); // unknown initial packet: 20 ms
    webrtc::AudioFrame frame;
    bool muted = false;
    int rate = 0;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 120); // 160 - actual 40-ms packet
    const int calls = observed->maximum_delay_calls;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay_calls == calls);
    assert(recovering.SetMaximumDelay(50));
    assert(observed->maximum_delay == 50);
    observed->frame_ms = 60;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 50); // retain a stricter caller bound
    observed->frame_ms = 20;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 50);
    assert(recovering.SetMaximumDelay(0));
    assert(observed->maximum_delay == 100);
    assert(recovering.SetMaximumDelay(500));
    assert(observed->maximum_delay == 100);
    assert(!recovering.SetMaximumDelay(-1));
    observed->frame_ms = 40;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 120);
    observed->frame_ms = 0; // silence/unknown must not invent a smaller packet
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 120);
    observed->mode = 1; // PLC is generated output, not a new packet duration
    observed->frame_ms = 20;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 120);
    observed->mode = 2; // muted output cannot change the known duration either
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 120);
    observed->mode = 5;
    recovering.GetAudio(&frame, &muted, &rate, std::nullopt);
    assert(observed->maximum_delay == 100); // a real shorter decoded packet
    assert(stats->count == 0 && stats->discarded_ms == 0);
  }
  // Packet-sized headroom increases only as normal speech establishes the
  // packet duration. Short-packet group recovery keeps its original budget.
  for (const int packet_ms : {10, 20, 40, 60, 100}) {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = 5;
    observed->frame_ms = packet_ms;
    const int budget_ms = std::clamp(80 + 2 * packet_ms, 120, 200);
    observed->buffer_ms_override = budget_ms;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats);
    webrtc::AudioFrame frame;
    recovering.GetAudio(&frame, nullptr, nullptr, std::nullopt);
    assert(observed->maximum_delay == budget_ms - packet_ms);
    assert(stats->discarded_ms == 0 && observed->pulls == 1);
    // Just above that packet duration's budget, bounded catch-up still runs.
    observed->buffer_ms_override += 10;
    recovering.GetAudio(&frame, nullptr, nullptr, std::nullopt);
    assert(observed->pulls == 18 && stats->discarded_ms == 160);
  }
  // A bound supplied by the real NetEq factory config predates the wrapper.
  {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = 5;
    observed->frame_ms = 40;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats, nullptr, 40);
    assert(observed->maximum_delay == 40);
    webrtc::AudioFrame frame;
    recovering.GetAudio(&frame, nullptr, nullptr, std::nullopt);
    assert(observed->maximum_delay == 40);
  }
  // Diagnostic capture must require both switches, remain bounded and defer
  // every file operation until the renderer has stopped and the owner dies.
  std::string path = std::string(std::getenv("TMPDIR") ? std::getenv("TMPDIR")
                                                     : "/tmp/") +
                     "/veil-playout-trace-XXXXXX";
  const int fd = mkstemp(path.data());
  assert(fd >= 0);
  close(fd);
  unlink(path.c_str());
  setenv("VEIL_MEDIA_PLAYOUT_TRACE", "1", 1);
  unsetenv("VEIL_MEDIA_DIAG_PATH");
  { veil_media::PlayoutTrace off; assert(!off.enabled()); }
  setenv("VEIL_MEDIA_DIAG_PATH", path.c_str(), 1);
  unsetenv("VEIL_MEDIA_PLAYOUT_TRACE");
  { veil_media::PlayoutTrace off; assert(!off.enabled()); }
  setenv("VEIL_MEDIA_PLAYOUT_TRACE", "1", 1);
  {
    veil_media::PlayoutTrace trace;
    assert(trace.enabled());
    for (size_t i = 0; i < veil_media::PlayoutTrace::kLimit + 3; ++i) {
      trace.Record(1000, 200, 100, 40, 10, false, 40, 80, 9000, 0, false);
      trace.RecordPacket(900, 11, 65535, 8500);
    }
    assert(access(path.c_str(), F_OK) != 0);
    // Teardown uses the explicitly selected original file, not later env.
    unsetenv("VEIL_MEDIA_DIAG_PATH");
  }
  std::ifstream file(path);
  std::string line;
  assert(std::getline(file, line));
  assert(line == "audio.playout.begin count=65536 observed=65539 limit=65536");
  size_t rows = 0;
  while (rows < veil_media::PlayoutTrace::kLimit && std::getline(file, line)) {
    assert(line.find("before_ms=200 after_ms=100 target_ms=40 skipped=10 fallback=0")
           != std::string::npos);
    assert(line.find("rtp_timestamp=9000 speech_type=0 muted=0")
           != std::string::npos);
    ++rows;
  }
  assert(rows == veil_media::PlayoutTrace::kLimit);
  assert(std::getline(file, line));
  assert(line == "audio.rtp.begin count=65536 observed=65539 limit=65536");
  rows = 0;
  while (std::getline(file, line)) {
    assert(line == "audio.rtp received_us=900 ssrc=11 sequence=65535 rtp_timestamp=8500");
    ++rows;
  }
  assert(rows == veil_media::PlayoutTrace::kLimit);
  file.close();
  unlink(path.c_str());
  // Real wrapper wiring: retain the actual decoded RTP timestamp, and only
  // record accepted packets. No packet body is passed to the trace.
  setenv("VEIL_MEDIA_DIAG_PATH", path.c_str(), 1);
  {
    auto decoder = std::make_unique<Decoder>();
    auto* observed = decoder.get();
    observed->mode = 5;
    auto stats = std::make_shared<veil_media::PlayoutRecoveryStats>();
    veil_media::RecoveringNetEq recovering(std::move(decoder), stats);
    webrtc::RTPHeader header;
    header.ssrc = 11;
    header.sequenceNumber = 42;
    header.timestamp = 8500;
    assert(recovering.InsertPacket(header, {}, webrtc::RtpPacketInfo{}) == 0);
    observed->insert_result = webrtc::NetEq::kFail;
    header.sequenceNumber = 43;
    assert(recovering.InsertPacket(header, {}, webrtc::RtpPacketInfo{}) != 0);
    webrtc::AudioFrame frame;
    recovering.GetAudio(&frame, nullptr, nullptr, std::nullopt);
    assert(frame.timestamp_ == 10480);
    assert(access(path.c_str(), F_OK) != 0);
  }
  file.open(path);
  const std::string traced((std::istreambuf_iterator<char>(file)), {});
  assert(traced.find("rtp_timestamp=10480 speech_type=0 muted=0") != std::string::npos);
  assert(traced.find("audio.rtp.begin count=1 observed=1 limit=65536") != std::string::npos);
  assert(traced.find("ssrc=11 sequence=42 rtp_timestamp=8500") != std::string::npos);
  assert(traced.find("sequence=43") == std::string::npos);
  file.close();
  unlink(path.c_str());
  unsetenv("VEIL_MEDIA_DIAG_PATH");
  unsetenv("VEIL_MEDIA_PLAYOUT_TRACE");
  std::puts("catch-up preserves usable speech on PLC/mute/error; work bounded to 16 pulls");
  std::puts("playout timing trace is opt-in, bounded, and writes only at teardown");
}
