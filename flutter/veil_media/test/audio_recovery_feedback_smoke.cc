// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>

#include "modules/rtp_rtcp/source/rtcp_packet/common_header.h"
#include "veil_audio_recovery_feedback.h"
#include "veil_audio_concealment_feedback.h"
#include "veil_audio_soft_loss.h"
static void require(bool ok, const char* message) {
  if (!ok) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
  }
}
int main() {
  using namespace veil_media;
  {
    using Kind = AudioSoftLossWindow::Kind;
    AudioSoftLossWindow damage;
    damage.Observe(Kind::Concealment, 1, 1, 100000, true, true, 1'000'000);
    require(damage.Samples(1'000'000) == 0, "startup damage became current");
    damage.Observe(Kind::Concealment, 1, 2, 100000 + 11*48, true, true, 2'000'000);
    damage.Observe(Kind::Concealment, 1, 3, 100000 + 38*48, true, true, 3'000'000);
    require(damage.Samples(3'000'000) == 38*48 && damage.FreshReportUs(3'000'000) == 0,
            "two short events became significant damage");
    damage.Observe(Kind::Catchup, 1, 1, 0, true, false, 3'000'000);
    damage.Observe(Kind::Catchup, 1, 2, 85*48, true, true, 4'000'000);
    require(damage.Samples(4'000'000) == 123*48 &&
                damage.FreshReportUs(4'000'321) == 4'000'000,
            "combined discarded speech and concealment did not qualify");
    damage.Observe(Kind::Catchup, 1, 2, 5000*48, true, true, 4'100'000);
    damage.Observe(Kind::Catchup, 1, 3, 1, true, true, 4'200'000);
    damage.Observe(Kind::Catchup, 1, 4, 85*48, true, true, 4'300'000);
    require(damage.Samples(4'300'000) == 123*48 &&
                damage.FreshReportUs(4'300'000) == 4'000'000,
            "replay/rollback/cached counters renewed damage");
    require(damage.Samples(8'000'000) == 112*48 && damage.FreshReportUs(8'000'000) == 0,
            "expired contributions kept qualifying pressure");
    damage.Observe(Kind::Concealment, 2, 1, 900000, true, true, 8'100'000);
    require(damage.Samples(8'100'000) == 0, "new origin inherited damage history");
    damage.Observe(Kind::Concealment, 1, 999, 990000, true, true, 8'200'000);
    damage.Observe(Kind::Concealment, 2, 999, 0, false, true, 8'300'000);
    damage.Observe(Kind::Concealment, 2, 2, 900000 + 119*48, true, true, 8'400'000);
    require(damage.FreshReportUs(8'400'000) == 0, "old/unknown report poisoned a new origin");
    damage.Observe(Kind::Concealment, 2, 3, 900000 + 120*48, true, true, 8'500'000);
    require(damage.FreshReportUs(8'500'000) == 8'500'000, "120ms boundary missed");
    damage.Observe(Kind::Concealment, 2, 4, 9999999, true, true, 15'000'000);
    require(damage.Samples(15'000'000) == 0, "observation gap became fresh damage");
    damage.Observe(Kind::Concealment, 2, 5, 10000099, true, false, 16'000'000);
    require(damage.Samples(16'000'000) == 0, "stale newly observed counter became damage");
    require(!damage.FreshAt(22'000'000), "cached duration counters stayed fresh forever");
    require(AudioSoftLossWindow::CatchupSamples(7000) == 7000*48,
            "cumulative catchup saturated at the rolling window");
  }
  AudioRecoveryRegistry registry_a, registry_b;
  const auto decoder_a = registry_a.NewStream();
  const auto decoder_b = registry_b.NewStream();
  require(decoder_b->Snapshot().origin > decoder_a->Snapshot().origin,
          "recreated engine registry reused a decoder identity");
  AudioRecoveryCursor cursor;
  auto packet = EncodeAudioRecovery(7, 11, 1, {true, 1, 20, 1'000'000},
                                    1'000'000, 1'100'000);
  webrtc::rtcp::CommonHeader header;
  require(header.Parse(packet.data(), packet.size()),
          "invalid real RTCP APP framing");
  auto report = DecodeAudioRecovery(
      {header.payload(), header.payload_size_bytes()}, header.count());
  require(report.has_value() && report->age_ms == 100,
          "event age did not round trip");
  cursor.Observe(*report, 22, 2'000'000);
  require(cursor.FreshReportUs(2'000'000) == 0, "foreign SSRC affected sender");
  cursor.Observe(*report, 11, 2'000'000);
  require(cursor.FreshReportUs(2'000'000) == 2'000'000,
          "fresh decoded loss disappeared");
  cursor.Observe(*report, 11, 3'000'000);
  require(cursor.FreshReportUs(3'000'000) == 2'000'000, "replay renewed loss");
  report->sequence = 2;
  cursor.Observe(*report, 11, 4'000'000);
  require(cursor.FreshReportUs(4'000'000) == 2'000'000,
          "new report of old event renewed loss");
  report->sequence = 3;
  report->discarded_ms = 40;
  report->age_ms = kUnknownRecoveryAge;
  cursor.Observe(*report, 11, 5'000'000);
  report->sequence = 4;
  report->age_ms = 0;
  cursor.Observe(*report, 11, 6'000'000);
  require(cursor.FreshReportUs(6'000'000) == 2'000'000,
          "stale counter became fresh later");
  report->sequence = 1;  // Recreated engine restarts its report sequence too.
  report->origin = 2;
  report->discarded_ms = 10;
  cursor.Observe(*report, 11, 7'000'000);
  require(cursor.FreshReportUs(7'000'000) == 7'000'000,
          "new receiver inherited an older counter");
  require(cursor.Sample().known && cursor.Sample().origin == 2 &&
          cursor.Sample().discarded_ms == 10,
          "canonical peer event identity differs from the RTCP report");
  auto old_unknown = *report;
  old_unknown.known = false;
  old_unknown.origin = 0;
  old_unknown.discarded_ms = 0;
  old_unknown.age_ms = kUnknownRecoveryAge;
  old_unknown.sequence = 1000;
  cursor.Observe(old_unknown, 11, 7'100'000);
  report->sequence = 2;
  report->discarded_ms = 20;
  cursor.Observe(*report, 11, 7'200'000);
  require(cursor.Sample().discarded_ms == 20 &&
          cursor.FreshReportUs(7'200'000) == 7'200'000,
          "old unknown sample poisoned the recreated decoder's sequence");
  report->sequence = 6;
  report->origin = 1;
  report->discarded_ms = 100;
  cursor.Observe(*report, 11, 8'000'000);
  require(cursor.FreshReportUs(8'000'000) == 7'200'000,
          "retired receiver renewed loss");
  require(cursor.FreshReportUs(23'000'001) == 0, "old witness did not expire");
  for (int index : {3, 8, 44}) {
    auto corrupt = packet;
    corrupt[index] ^= 1;
    webrtc::rtcp::CommonHeader h;
    if (h.Parse(corrupt.data(), corrupt.size()))
      require(!DecodeAudioRecovery({h.payload(), h.payload_size_bytes()},
                                   h.count()),
              "malformed recognized report accepted");
  }
  require(!DecodeAudioRecovery({packet.data() + 4, 43}, 0),
          "truncated report accepted");
  auto unknown = EncodeAudioRecovery(7, 11, 1, {true, 1, 20, 1'000'000},
                                     1'000'000, 5'000'000);
  require(header.Parse(unknown.data(), unknown.size()),
          "unknown report malformed");
  auto decoded = DecodeAudioRecovery(
      {header.payload(), header.payload_size_bytes()}, header.count());
  require(decoded && !decoded->known, "stale sampling claimed healthy source");
  LocalAudioConcealment local;
  AudioConcealmentCursor concealment;
  auto observe = [&](int64_t at) {
    const auto wire = EncodeAudioConcealment(7, local.Report(at));
    require(header.Parse(wire.data(), wire.size()), "VAP3 RTCP framing");
    const auto r = DecodeAudioConcealment(
        {header.payload(), header.payload_size_bytes()}, header.count());
    require(r.has_value(), "VAP3 roundtrip");
    const auto before_foreign = concealment.FreshReportUs(at);
    concealment.Observe(*r, 22, at);
    require(concealment.FreshReportUs(at) == before_foreign, "foreign concealment SSRC");
    concealment.Observe(*r, 11, at);
    return *r;
  };
  require(!local.Observe(11, 1, 3, 1000, 100, 1'000'000), "startup event");
  require(local.FreshReportUs(1'100'000) == 0, "local history became pressure");
  auto r = observe(1'100'000);
  require(concealment.FreshReportUs(1'100'000) == 0 && r.concealed_samples == 900,
          "historical concealment became fresh");
  require(!local.Observe(11, 2, 3, 1480, 580, 2'000'000), "silent concealment event");
  require(local.FreshReportUs(2'100'000) == 0, "local DTX became pressure");
  observe(2'100'000);
  require(concealment.FreshReportUs(2'100'000) == 0, "DTX yielded false pressure");
  require(local.Observe(11, 3, 3, 1960, 580, 3'000'000), "speech event missed");
  require(local.FreshReportUs(3'000'789) == 3'000'000 &&
              local.FreshReportUs(3'100'321) == 3'000'000,
          "rounded age manufactured another local identity");
  r = observe(3'100'000);
  require(r.age_ms == 100 && concealment.FreshReportUs(3'100'000) == 3'100'000,
          "fresh concealment missing");
  concealment.Observe(r, 11, 3'200'000);
  require(!local.Observe(11, 3, 3, 2440, 580, 3'300'000), "cached sequence event");
  require(!local.Observe(11, 4, 3, 2440, 580, 2'900'000), "clock rollback event");
  require(!local.Observe(11, 4, 3, 1960, 580, 4'000'000), "cached count event");
  require(local.FreshReportUs(4'100'000) == 3'000'000 &&
              local.FreshReportUs(6'000'001) == 0,
          "local poll extended event lifetime");
  observe(4'100'000);
  require(concealment.FreshReportUs(4'100'000) == 3'100'000,
          "cached concealment renewed event");
  require(!local.Observe(11, 5, 0, 0, 0, 5'000'000), "unknown produced event");
  require(local.FreshReportUs(5'000'001) == 0, "unknown local sample retained pressure");
  observe(5'100'000);
  require(!local.Observe(11, 6, 2, 99999, 0, 5'200'000), "retired decoder event");
  require(!local.Observe(11, 6, 3, 2440, 580, 6'000'000), "resume replayed gap");
  observe(6'100'000);
  require(!local.Observe(11, 7, 3, 2920, 580, 10'000'000), "sampling gap event");
  observe(10'100'000);
  require(!local.Observe(11, 8, 3, 100, 0, 11'000'000), "counter rollback event");
  require(!local.Observe(11, 1, 4, 9999, 0, 12'000'000), "new decoder history event");
  observe(12'100'000);
  require(local.Observe(11, 2, 4, 10479, 0, 13'000'000), "new decoder event missed");
  const auto stale = local.Report(17'000'000);
  require(!stale.known && stale.age_ms == kUnknownRecoveryAge,
          "stale native sample remained known");
  observe(13'100'000);
  auto old = r;
  old.sequence = 999;
  old.concealed_samples = 99999;
  concealment.Observe(old, 11, 14'000'000);
  require(concealment.FreshReportUs(14'000'000) == 13'100'000 &&
              concealment.FreshReportUs(29'000'000) == 0,
          "retired decoder/expiry refreshed concealment");
  auto malformed_concealment = EncodeAudioConcealment(7, r);
  malformed_concealment[47] = 2;
  require(!DecodeAudioConcealment({malformed_concealment.data() + 4, 44}, 0) &&
              !DecodeAudioConcealment({malformed_concealment.data() + 4, 43}, 0),
          "malformed concealment accepted");
  std::puts(
      "ok real RTCP recovery framing, SSRC binding, replay, freshness, "
      "retirement and expiry");
}
