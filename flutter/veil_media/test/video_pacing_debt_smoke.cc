#undef NDEBUG
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <map>
#include <string>
#include <vector>
#include "api/field_trials_view.h"
#include "modules/pacing/pacing_controller.h"
#include "system_wrappers/include/clock.h"
#include "video/video_send_stream_impl.h"

class Trials final : public webrtc::FieldTrialsView {
 public:
  explicit Trials(std::string value) : value_(std::move(value)) {}
  std::string Lookup(absl::string_view key) const override {
    return key == "WebRTC-Video-Pacing" ? value_ : "";
  }
  std::unique_ptr<webrtc::FieldTrialsView> CreateCopy() const override {
    return std::make_unique<Trials>(value_);
  }
 private:
  std::string value_;
};

class Sender final : public webrtc::PacingController::PacketSender {
 public:
  explicit Sender(webrtc::SimulatedClock& clock) : clock_(clock) {}
  void SendPacket(std::unique_ptr<webrtc::RtpPacketToSend> packet,
                  const webrtc::PacedPacketInfo& info) override {
    bytes_at_ms[clock_.TimeInMilliseconds() - 1000] += packet->size();
    sequences.push_back(packet->SequenceNumber());
    probe_ids.push_back(info.probe_cluster_id);
    const auto sequence = packet->SequenceNumber();
    assert(std::all_of(packet->payload().begin(), packet->payload().end(),
        [&](uint8_t value) { return value == uint8_t(sequence % 251); }));
  }
  std::vector<std::unique_ptr<webrtc::RtpPacketToSend>> FetchFec() override { return {}; }
  std::vector<std::unique_ptr<webrtc::RtpPacketToSend>> GeneratePadding(webrtc::DataSize) override { return {}; }
  std::map<int64_t, size_t> bytes_at_ms;
  std::vector<uint16_t> sequences;
  std::vector<int> probe_ids;
 private:
  webrtc::SimulatedClock& clock_;
};


void SendAudioBetweenProbeBursts() {
  using namespace webrtc;
  constexpr int kProbeId = 42;
  SimulatedClock clock(1'000'000);
  Sender sender(clock);
  Trials trials("");
  PacingController pacer(&clock, &sender, trials);
  pacer.SetPacerConfig(PacerConfig::Create(clock.CurrentTime(),
      DataRate::BitsPerSec(48'000), DataRate::Zero()));
  ProbeClusterConfig cluster;
  cluster.at_time = clock.CurrentTime();
  cluster.target_data_rate = DataRate::BitsPerSec(24'000);
  cluster.target_duration = TimeDelta::Millis(300);
  cluster.min_probe_delta = TimeDelta::Millis(1);
  cluster.target_probe_count = 3;
  cluster.id = kProbeId;
  const std::array clusters{cluster};
  pacer.CreateProbeClusters(clusters);

  const auto enqueue_audio = [&](uint16_t sequence, size_t size) {
    auto packet = std::make_unique<RtpPacketToSend>(nullptr);
    packet->set_packet_type(RtpPacketMediaType::kAudio);
    packet->SetSsrc(11);
    packet->SetSequenceNumber(sequence);
    packet->set_capture_time(clock.CurrentTime());
    std::fill_n(packet->AllocatePayload(size), size, uint8_t(sequence % 251));
    pacer.EnqueuePacket(std::move(packet));
  };
  enqueue_audio(0, 240);
  pacer.ProcessPackets();
  assert(sender.sequences == std::vector<uint16_t>{0});
  assert(sender.probe_ids == std::vector<int>{kProbeId});
  const Timestamp next_probe = pacer.NextSendTime();
  assert(next_probe - clock.CurrentTime() >= TimeDelta::Millis(80));

  clock.AdvanceTimeMilliseconds(10);
  enqueue_audio(1, 80);
  assert(pacer.NextSendTime() <= clock.CurrentTime());
  pacer.ProcessPackets();
  assert((sender.sequences == std::vector<uint16_t>{0, 1}));
  assert(sender.probe_ids.back() == PacedPacketInfo::kNotAProbe);
  assert(pacer.NextSendTime() == next_probe);

  clock.AdvanceTimeMicroseconds((next_probe - clock.CurrentTime()).us());
  enqueue_audio(2, 120);
  pacer.ProcessPackets();
  assert((sender.sequences == std::vector<uint16_t>{0, 1, 2}));
  assert(sender.probe_ids.back() == kProbeId);
}

struct Case { const char* name; int before; int after; int initial; int queued; bool audio; bool account; };
int main() {
  SendAudioBetweenProbeBursts();
  bool bounded = true;
  for (const auto& c : std::vector<Case>{
      {"steady",900000,900000,14,0,false,false},
      {"increase",15000,900000,1,0,false,false},
      {"decrease",900000,15000,14,0,false,false},
      {"moderate_decrease",90000,15000,1,0,false,false},
      {"queued_decrease",900000,15000,14,5,false,false},
      {"audio",900000,15000,14,0,true,false},
      {"accounted_audio",900000,15000,14,0,true,true}}) {
    Trials trials("factor:4.0,max_delay:25ms");
    webrtc::internal::PacingConfig profile(trials);
    webrtc::SimulatedClock clock(1000000); Sender sender(clock);
    webrtc::PacingController pacer(&clock,&sender,trials);
    if (!c.audio) pacer.SetQueueTimeLimit(profile.max_pacing_delay.Get());
    pacer.SetAccountForAudioPackets(c.account);
    pacer.SetPacerConfig(webrtc::PacerConfig::Create(clock.CurrentTime(),
        webrtc::DataRate::BitsPerSec(c.before*4),webrtc::DataRate::Zero()));
    auto add = [&](int sequence,int payload) {
      auto p=std::make_unique<webrtc::RtpPacketToSend>(nullptr);
      p->set_packet_type(c.audio?webrtc::RtpPacketMediaType::kAudio:webrtc::RtpPacketMediaType::kVideo);
      p->SetSsrc(11);p->SetSequenceNumber(sequence);p->set_capture_time(clock.CurrentTime());
      auto* bytes=p->AllocatePayload(payload); assert(bytes);
      std::fill(bytes,bytes+payload,uint8_t(sequence%251));pacer.EnqueuePacket(std::move(p));
    };
    for(int i=0;i<c.initial;++i)add(i,1000);
    pacer.ProcessPackets();assert(sender.sequences.size()==size_t(c.initial));
    if(c.queued) {pacer.SetCongested(true);for(int i=0;i<c.queued;++i)add(c.initial+i,1000);assert(pacer.QueueSizePackets()==size_t(c.queued));}
    pacer.SetPacerConfig(webrtc::PacerConfig::Create(clock.CurrentTime(),
        webrtc::DataRate::BitsPerSec(c.after*4),webrtc::DataRate::Zero()));
    clock.AdvanceTimeMilliseconds(1);pacer.SetCongested(false);add(c.initial+c.queued,400);
    for(int ms=0;ms<3000;++ms){pacer.ProcessPackets();clock.AdvanceTimeMilliseconds(1);}
    const auto count=c.initial+c.queued+1; assert(sender.sequences.size()==size_t(count));
    for(int i=0;i<count;++i)assert(sender.sequences[i]==i);
    size_t sent_bytes=0;for(const auto& [at,bytes]:sender.bytes_at_ms)sent_bytes+=bytes;
    assert(sent_bytes==size_t((count-1)*1012+412));
    const auto delay=sender.bytes_at_ms.rbegin()->first-1;
    std::printf("{\"case\":\"%s\",\"fresh_delay_ms\":%lld,\"packets\":%d,\"wire_bytes\":%zu}\n",c.name,(long long)delay,count,sent_bytes);
    if(c.audio||c.after>=c.before)assert(delay==0);
    else bounded=bounded&&delay<=50;
  }
  std::fflush(stdout);assert(bounded);
}
