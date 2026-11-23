#undef NDEBUG
#include "veil_audio_rtp_lag.h"
#include "veil_audio_recovery.h"
#include <cassert>
#include <cstdio>

using veil_media::AudioRtpLag;
constexpr uint32_t kOrigin = 0xffff0000;
static uint32_t stamp(int64_t ms) { return kOrigin + static_cast<uint32_t>(ms * 48); }

int main() {
  // Sender wall clocks are never supplied. Offset and fixed path latency,
  // including a slow path, cannot masquerade as new queue growth.
  for (int delay : {18, 120, 800}) {
    AudioRtpLag lag;
    for (int ms = 0; ms <= 2000; ms += 20) {
      const int64_t now = 1'000'000 + (ms + delay) * 1000;
      lag.Packet(7, stamp(ms), now);
      if (ms >= 100) assert(lag.Output(stamp(ms - 80), now) == 80);
    }
    // RTP wrap and bounded reorder retain the same baseline.
    lag.Packet(7, stamp(1900), 1'000'000 + (2005 + delay)*1000);
    assert(lag.Output(stamp(1925), 1'000'000 + (2005 + delay)*1000) == 80);
    // A new RTP clock/SSRC is unknown, never the previous stream's delay.
    lag.Packet(8, 123, 1'000'000 + (2020 + delay)*1000);
    assert(!lag.Output(123, 1'000'000 + (2020 + delay)*1000));
  }
  {
    AudioRtpLag lag;
    for (int ms = 0; ms <= 1000; ms += 20) lag.Packet(7, stamp(ms), 1'000'000 + ms*1000);
    // The network now holds 190 ms before insertion. A 90-ms local queue
    // alone misses it: relative RTP age accounts for both stages.
    lag.Packet(7, stamp(1020), 2'210'000);
    assert(lag.Output(stamp(930), 2'210'000) == 280);
    // A permanent route change is eventually a new floor, not endless loss.
    for (int ms = 1040; ms <= 33000; ms += 20) lag.Packet(7, stamp(ms), 1'190'000 + ms*1000);
    assert(lag.Output(stamp(32910), 34'190'000) == 90);
    // Long silence/outage is unknown; the first resumed packet cannot grant
    // an old baseline. Repeated duplicate packets cannot warm it either.
    assert(!lag.Output(stamp(32910), 38'190'000));
    lag.Packet(7, stamp(65000), 66'190'000);
    for (int i = 1; i < 10; ++i) lag.Packet(7, stamp(65000), 66'190'000+i*20000);
    assert(!lag.Output(stamp(65000), 66'390'000));
    lag.Reset();
    assert(!lag.Output(stamp(65000), 66'390'000));
  }
  for (int direction : {-1, 1}) {
    AudioRtpLag lag;
    for (int ms = 0; ms <= 1000; ms += 20) lag.Packet(7, stamp(ms), 2'000'000+ms*1000);
    lag.Packet(7, stamp(1020 + direction*30000), 3'020'000);
    assert(!lag.Output(stamp(1020 + direction*30000), 3'020'000));
  }
  {
    AudioRtpLag lag;
    for (int ms = 0; ms <= 1000; ms += 20)
      lag.Packet(7, stamp(ms), 2'000'000+ms*1000, static_cast<uint16_t>(65520+ms/20));
    assert(lag.Output(stamp(920), 3'000'000) == 80);
    // Sequence wrap and bounded reorder do not reset; a new random sequence
    // origin invalidates the floor even with a small timestamp discontinuity.
    assert(!lag.Packet(7, stamp(980), 3'005'000, uint16_t(65520+49)));
    assert(lag.Packet(7, stamp(1400), 3'020'000, uint16_t(9000)));
    assert(!lag.Output(stamp(1020), 3'020'000));
    assert(!lag.MatchesPacket(7, stamp(1000), uint16_t(65520+50)));
    assert(lag.MatchesPacket(7, stamp(1400), uint16_t(9000)));
    assert(!lag.MatchesPacket(8, stamp(1400), uint16_t(9000)));
  }
  {
    AudioRtpLag lag;
    for (int ms = 0; ms <= 1000; ms += 20)
      lag.Packet(7, stamp(ms), 2'000'000 + ms * 1000, uint16_t(100 + ms / 20));
    assert(lag.Output(stamp(920), 3'000'000) == 80);
    // A restart can preserve packet sequence while resetting the RTP clock.
    // A 1.2-s backwards step is inside the timestamp-only reorder window.
    assert(lag.Packet(7, stamp(-200), 3'020'000, uint16_t(151)));
    assert(!lag.Output(stamp(-200), 3'020'000));
    assert(!lag.Packet(7, stamp(1000), 3'030'000, uint16_t(150)));
    for (int i = 1; i <= 5; ++i)
      assert(!lag.Packet(7, stamp(-200 + i * 20), 3'020'000 + i * 20'000,
                         uint16_t(151 + i)));
    assert(lag.Output(stamp(-140), 3'120'000) == 40);
  }
  {
    AudioRtpLag lag;
    for (uint16_t index = 0; index < 3; ++index)
      lag.Packet(7, stamp(index * 20), 1'000'000 + index * 20'000, index);
    assert(lag.RecentArrivalVariationMs(1'040'000) == 0);
    lag.Packet(7, stamp(60), 1'610'000, 3);
    assert(lag.RecentArrivalVariationMs(1'610'000) == 550);
    // A replay and a reordered packet do not raise or renew the late bound.
    lag.Packet(7, stamp(60), 1'700'000, 3);
    lag.Packet(7, stamp(20), 1'800'000, 1);
    assert(lag.RecentArrivalVariationMs(1'800'000) == 550);
    assert(lag.RecentArrivalVariationMs(3'500'000) == 0);
    lag.Packet(8, stamp(80), 1'820'000, 4);
    assert(lag.RecentArrivalVariationMs(1'820'000) == 0);
  }
  {
    AudioRtpLag lag;
    for (uint16_t index = 0; index < 3; ++index)
      lag.Packet(7, stamp(index * 20), 1'000'000 + index * 20'000,
                 static_cast<uint16_t>(65532 + index));
    lag.Packet(7, stamp(100), 1'100'000, 1);
    assert(lag.RecentArrivalVariationMs(1'100'000) == 0);
    // A genuinely missing packet can arrive late within the same stream,
    // even if the sequence has already wrapped and advanced past it.
    lag.Packet(7, stamp(60), 1'310'000, 65535);
    assert(lag.RecentArrivalVariationMs(1'310'000) == 250);
    lag.Packet(7, stamp(60), 1'500'000, 65535);
    // Earlier than the first observed sequence: no known receive hole.
    lag.Packet(7, stamp(-20), 1'510'000, 65531);
    assert(lag.RecentArrivalVariationMs(1'510'000) == 250);
    lag.Packet(7, stamp(80), 1'610'000, 0);
    assert(lag.RecentArrivalVariationMs(1'610'000) == 250);
    assert(lag.RecentArrivalVariationMs(3'000'000) == 0);
  }
  {
    veil_media::AudioRecoveryRegistry registry;
    auto stream = registry.NewStream(); registry.Attach(7, stream);
    stream->SetLag(269, 1'234'567);
    assert(registry.LagMs(7, 1'235'000) == 269);
    assert(registry.LagMs(8, 1'235'000) == -1);
    assert(registry.LagMs(7, 1'233'000) == -1);
    assert(registry.LagMs(7, 4'235'000) == -1);
    stream->SetLag(std::nullopt, 1'240'000);
    assert(registry.LagMs(7, 1'241'000) == -1);
    stream->SetLag(60, 1'250'000); stream.reset();
    assert(registry.LagMs(7, 1'251'000) == -1);
  }
  std::puts("RTP lag: constant high delay, wrap, reorder, upstream queue, floor expiry, silence, reset and fresh publication verified");
}
