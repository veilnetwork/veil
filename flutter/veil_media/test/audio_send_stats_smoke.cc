#include "veil_audio_send_stats.h"
#include <array>
#include <cassert>
#include <vector>

int main() {
  constexpr int64_t ms = 1'000'000;
  constexpr uint32_t ssrc = 0x01020304;
  std::array<uint8_t, 13> packet{0x80, 111, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0};
  veil_media::AudioSendStats stats;
  assert(stats.snapshot(1000 * ms).age_ms == -1);
  assert(stats.snapshot(1000 * ms).queue_age_ms == -1);

  assert(stats.mark_attempt(packet, ssrc, 1000 * ms));
  stats.mark_result(1000 * ms, 1002 * ms, true);
  auto s = stats.snapshot(1010 * ms);
  assert(s.attempts == 1 && s.queued == 1 && s.age_ms == 10 && s.queue_age_ms == 8);
  assert(s.dropped == 0);

  // Video, RTCP, another audio SSRC and malformed RTP must not make audio
  // look alive. These are the confusing traffic sources in a live AV call.
  packet[1] = 96;
  assert(!stats.mark_attempt(packet, ssrc, 1100 * ms));
  packet[1] = 200;
  assert(!stats.mark_attempt(packet, ssrc, 1100 * ms));
  packet[1] = 111;
  assert(!stats.mark_attempt(packet, ssrc + 1, 1100 * ms));
  assert(!stats.mark_attempt(std::span(packet).first(8), ssrc, 1100 * ms));
  assert(!stats.mark_attempt(packet, 0, 1100 * ms));
  assert(stats.snapshot(1100 * ms).attempts == 1);

  // Local admission failure is distinct from a source that stopped producing.
  assert(stats.mark_attempt(packet, ssrc, 2000 * ms));
  assert(stats.snapshot(2000 * ms).dropped == 0); // pending is not failed
  stats.mark_result(2000 * ms, 2005 * ms, false);
  s = stats.snapshot(2010 * ms);
  assert(s.attempts == 2 && s.queued == 1 && s.age_ms == 10 && s.queue_age_ms == 1008);
  assert(s.max_gap_ms == 1000 && s.max_admission_ms == 5);
  assert(s.dropped == 1);
  assert(stats.snapshot(100 * ms).age_ms == -1);  // no fresh-looking clock reversal

  // Padding probes must not renew the encoded-audio clock. Include a CSRC,
  // an RTP extension and actual audio with trailing padding in the fixture.
  veil_media::AudioSendStats diagnostic;
  std::vector<uint8_t> extended(28);
  extended[0] = 0xb1; extended[1] = 111;
  extended[8] = 1; extended[9] = 2; extended[10] = 3; extended[11] = 4;
  extended[16] = 0xbe; extended[17] = 0xde; extended[19] = 1;
  extended[24] = 0xf8; extended[25] = 0xaa; extended[27] = 2;
  assert(diagnostic.mark_attempt(extended, ssrc, 1000 * ms));
  s = diagnostic.snapshot(1010 * ms);
  assert(s.payload_packets == 1 && s.padding_packets == 0);
  assert(s.payload_bytes == 2 && s.padding_bytes == 2);
  assert(s.payload_age_ms == 10 && s.max_payload_gap_ms == 0);
  extended[27] = 4;  // All bytes after the RTP/extension header are padding.
  assert(diagnostic.mark_attempt(extended, ssrc, 1100 * ms));
  s = diagnostic.snapshot(1110 * ms);
  assert(s.attempts == 2 && s.age_ms == 10 && s.payload_age_ms == 110);
  assert(s.payload_packets == 1 && s.padding_packets == 1 && s.padding_bytes == 6);
  extended[27] = 2;
  assert(diagnostic.mark_attempt(extended, ssrc, 2000 * ms));
  assert(diagnostic.snapshot(2010 * ms).max_payload_gap_ms == 1000);

  // Malformed lengths must not underflow the accounting or claim a payload.
  extended[27] = 0;  // P set with a zero padding length.
  assert(diagnostic.mark_attempt(extended, ssrc, 2100 * ms));
  extended[27] = 5;  // Padding exceeds the bytes after the header.
  assert(diagnostic.mark_attempt(extended, ssrc, 2200 * ms));
  extended[27] = 2; extended[18] = 0xff; extended[19] = 0xff;
  assert(diagnostic.mark_attempt(extended, ssrc, 2300 * ms));
  extended.resize(15); extended[0] = 0x81;  // Truncated CSRC.
  assert(diagnostic.mark_attempt(extended, ssrc, 2400 * ms));
  s = diagnostic.snapshot(2410 * ms);
  assert(s.unclassified_packets == 4 && s.payload_packets == 2);
  assert(s.payload_age_ms == 410 && s.payload_bytes == 4);

  // A video's padding probe must not count as an encoded frame or audio.
  // Use the same SSRC deliberately: payload type also isolates the counters.
  veil_media::RtpSendStats video;
  packet[0] = 0x80; packet[1] = 96;
  assert(!stats.mark_attempt(packet, ssrc, 3000 * ms));
  assert(video.mark_attempt(packet, ssrc, 3000 * ms, 96));
  video.mark_result(3000 * ms, 3001 * ms, true);
  std::vector<uint8_t> probe(packet.begin(), packet.end());
  probe[0] = 0xa0; probe.back() = 1;
  assert(video.mark_attempt(probe, ssrc, 3100 * ms, 96));
  video.mark_result(3100 * ms, 3102 * ms, false);
  auto v = video.snapshot(3110 * ms);
  assert(v.attempts == 2 && v.queued == 1 && v.dropped == 1);
  assert(v.payload_packets == 1 && v.padding_packets == 1);
  assert(v.payload_bytes == 1 && v.padding_bytes == 1);
  assert(v.payload_age_ms == 110 && v.age_ms == 10);
  assert(v.max_admission_ms == 2);
  packet[1] = 111;
  assert(!video.mark_attempt(packet, ssrc, 3200 * ms, 96));
  packet[1] = 96;
  assert(!video.mark_attempt(packet, ssrc + 1, 3200 * ms, 96));
  assert(video.snapshot(3200 * ms).attempts == 2);
  assert(stats.snapshot(3200 * ms).attempts == 2);
}
