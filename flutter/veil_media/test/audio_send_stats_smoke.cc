#include "veil_audio_send_stats.h"
#include <array>
#include <cassert>

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
  stats.mark_result(2000 * ms, 2005 * ms, false);
  s = stats.snapshot(2010 * ms);
  assert(s.attempts == 2 && s.queued == 1 && s.age_ms == 10 && s.queue_age_ms == 1008);
  assert(s.max_gap_ms == 1000 && s.max_admission_ms == 5);
  assert(stats.snapshot(100 * ms).age_ms == -1);  // no fresh-looking clock reversal
}
