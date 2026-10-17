// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>

#include "modules/rtp_rtcp/source/rtcp_packet/common_header.h"
#include "veil_audio_recovery_feedback.h"
static void require(bool ok, const char* message) {
  if (!ok) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
  }
}
int main() {
  using namespace veil_media;
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
  report->sequence = 6;
  report->origin = 1;
  report->discarded_ms = 100;
  cursor.Observe(*report, 11, 8'000'000);
  require(cursor.FreshReportUs(8'000'000) == 7'000'000,
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
  std::puts(
      "ok real RTCP recovery framing, SSRC binding, replay, freshness, "
      "retirement and expiry");
}
