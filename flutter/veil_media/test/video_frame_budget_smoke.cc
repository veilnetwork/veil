#include "veil_video_frame_budget.h"
#include <cassert>
#include <thread>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>

int main(int argc, char** argv) {
  veil_media::VideoFrameBudget budget;
  budget.SetPacketPayload(964);
  budget.SetProfile(15000);
  budget.SetRate(7200);
  assert(budget.snapshot().bytes == 900);  // One RTP payload remains possible.
  budget.Observe(2296, 320, 240);
  const auto first = budget.snapshot();
  assert(first.max_pixels > 6144 && first.max_pixels < 320 * 240);
  assert(first.oversize_frames == 1);
  // Queued results at an old resolution must not compound the reduction.
  for (int i = 0; i < 10; ++i) budget.Observe(2296, 320, 240);
  assert(budget.snapshot().max_pixels == first.max_pixels);
  budget.Observe(500, 160, 120);
  assert(budget.snapshot().max_pixels == first.max_pixels);
  assert(budget.snapshot().last_pixels == 160 * 120);
  // Smaller actual encodes can lower the bound further, but never force
  // upscaling or a zero-size source at the existing coarse-frame floor.
  budget.Observe(4000, 160, 120);
  assert(budget.snapshot().max_pixels == 6144);
  budget.Observe(4000, 64, 48);
  assert(budget.snapshot().max_pixels == 6144);
  budget.Observe(5000, 0, 240);
  budget.Observe(5000, 4097, 240);
  assert(budget.snapshot().last_pixels == 64 * 48);
  // Only the host's larger profile releases this extra source bound. Native
  // rate fluctuations while the low profile stays selected cannot grow it.
  budget.SetRate(2000000);
  assert(budget.snapshot().max_pixels == 6144);
  budget.SetProfile(90000);
  assert(budget.snapshot().max_pixels == 0 && budget.snapshot().bytes == 0);
  budget.Observe(100000, 640, 360);
  assert(budget.snapshot().max_pixels == 0);
  budget.SetProfile(30000);
  assert(budget.snapshot().bytes == 1500);
  budget.SetRate(0);
  assert(budget.snapshot().bytes == 1500);
  // A requested high profile with a low actual BWE allocation must not leave
  // the image size unbounded. This was observed at selected45k/actual29k with
  // multi-packet frames and no pixel cap. Raising only the request cannot
  // remove protection while the encoder still has the same small allocation.
  veil_media::VideoFrameBudget allocated;
  allocated.SetPacketPayload(980);
  allocated.SetProfile(45000);
  assert(allocated.snapshot().bytes == 0);
  allocated.SetRate(24000);
  assert(allocated.snapshot().bytes == 1200);
  allocated.Observe(3161, 320, 240);
  const auto low = allocated.snapshot();
  assert(low.max_pixels > 0 && low.max_pixels < 76800);
  allocated.SetProfile(150000);
  assert(allocated.snapshot().max_pixels == low.max_pixels);
  allocated.SetRate(0);
  assert(allocated.snapshot().bytes == 1200);
  assert(allocated.snapshot().max_pixels == low.max_pixels);
  allocated.SetRate(40000);
  assert(allocated.snapshot().bytes == 0);
  assert(allocated.snapshot().max_pixels == low.max_pixels);
  allocated.SetRate(60000); // Actual recovery, even without a host profile change.
  assert(allocated.snapshot().max_pixels == 0);
  allocated.SetProfile(225000);
  assert(allocated.snapshot().max_pixels == 0);
  // Explicit audio feedback must control pixels even when encoded frames
  // fit and the host bitrate stays at its floor.
  veil_media::VideoFrameBudget audio;
  audio.SetPacketPayload(1440);
  audio.SetProfile(15000);
  audio.SetRate(12000);
  audio.SetAudioPressure(0, 1'000'000);
  audio.Observe(1513, 320, 240, 1, 1'100'000);
  assert(audio.snapshot().max_pixels == 0); // One healthy overshoot.
  audio.Observe(500, 320, 240, 2, 1'200'000);
  audio.SetAudioPressure(1, 2'000'000);
  const int protected_pixels = audio.snapshot().max_pixels;
  assert(protected_pixels > 0 && protected_pixels < 320 * 240);
  audio.SetAudioPressure(1, 2'500'000);
  assert(audio.snapshot().max_pixels == protected_pixels);
  audio.Observe(500, 160, 120, 3, 2'600'000);
  audio.SetAudioPressure(1, 5'000'000);
  const int second_cut = audio.snapshot().max_pixels;
  assert(second_cut < protected_pixels);
  audio.SetRate(90000);
  audio.SetProfile(150000);
  assert(audio.snapshot().max_pixels == second_cut); // No allocation bypass.
  for (int i = 6; i <= 9; ++i) {
    audio.Observe(500, 160, 120, i, i * 1'000'000);
    audio.SetAudioPressure(0, i * 1'000'000);
  }
  assert(audio.snapshot().max_pixels > second_cut);
  const int recovered_step = audio.snapshot().max_pixels;
  audio.SetAudioPressure(-1, 9'500'000);
  audio.Observe(500, 80, 60, 10, 10'000'000);
  audio.SetAudioPressure(0, 10'000'000);
  for (int i = 0; i < 20; ++i) audio.SetAudioPressure(0, 10'000'000);
  audio.Observe(500, 80, 60, 11, 11'000'000);
  audio.SetAudioPressure(0, 11'000'000);
  audio.Observe(500, 80, 60, 12, 12'000'000);
  audio.SetAudioPressure(0, 12'000'000);
  assert(audio.snapshot().max_pixels == recovered_step);
  audio.Observe(500, 80, 60, 13, 13'000'000);
  audio.SetAudioPressure(0, 13'000'000);
  assert(audio.snapshot().max_pixels > recovered_step);
  // Feedback can precede the first encode. A small encoded frame is no
  // exemption from the caller's measured audio pressure.
  veil_media::VideoFrameBudget before_encode;
  before_encode.SetProfile(15000);
  before_encode.SetPacketPayload(1440);
  before_encode.SetAudioPressure(1, 1'000'000);
  before_encode.Observe(500, 320, 240, 1, 1'100'000);
  assert(before_encode.snapshot().max_pixels > 0);
  assert(before_encode.snapshot().oversize_frames == 0);
  const int paused_cap = before_encode.snapshot().max_pixels;
  for (int i = 2; i <= 8; ++i)
    before_encode.SetAudioPressure(0, i * 1'000'000);
  assert(before_encode.snapshot().max_pixels == paused_cap);
  assert(before_encode.snapshot().audio_recoveries == 0);
  // A stale healthy hint cannot exempt a later overshoot or grant recovery.
  veil_media::VideoFrameBudget stale;
  stale.SetProfile(15000);
  stale.SetPacketPayload(1440);
  stale.SetAudioPressure(0, 1'000'000);
  stale.Observe(1513, 320, 240, 1, 5'000'000);
  const int stale_cap = stale.snapshot().max_pixels;
  assert(stale_cap > 0);
  stale.Observe(500, 80, 60, 10, 10'000'000);
  stale.SetAudioPressure(0, 10'000'000);
  stale.Observe(500, 80, 60, 11, 11'000'000);
  stale.SetAudioPressure(0, 11'000'000);
  stale.Observe(500, 80, 60, 12, 12'000'000);
  stale.SetAudioPressure(0, 12'000'000);
  assert(stale.snapshot().max_pixels == stale_cap);
  stale.Observe(500, 80, 60, 13, 13'000'000);
  stale.SetAudioPressure(0, 13'000'000);
  assert(stale.snapshot().max_pixels > stale_cap);
  // A transport-sized image can still spend multiple low-cadence frames'
  // codec allocation. Reproduce the observed 1477-byte image at 5833 bit/s
  // and 1 fps: healthy audio cannot make the missing next frame affordable.
  veil_media::VideoFrameBudget cadence;
  cadence.SetPacketPayload(1440);
  cadence.SetProfile(8000);
  cadence.SetRate(5833, 1.0);
  cadence.SetAudioPressure(0, 1'000'000);
  cadence.Observe(1477, 320, 240, 1, 1'100'000);
  const int cadence_cap = cadence.snapshot().max_pixels;
  assert(cadence_cap > 6144 && cadence_cap < 320 * 240);
  for (int i = 2; i <= 10; ++i) {
    cadence.Observe(500, 160, 120, i, i * 1'000'000);
    cadence.SetAudioPressure(0, i * 1'000'000);
  }
  assert(cadence.snapshot().max_pixels == cadence_cap);
  cadence.SetAudioPressure(1, 11'000'000);
  assert(cadence.snapshot().max_pixels < cadence_cap);
  for (int i = 12; i <= 40; ++i) {
    cadence.Observe(500, 160, 120, i, i * 1'000'000);
    cadence.SetAudioPressure(0, i * 1'000'000);
    assert(cadence.snapshot().max_pixels <= cadence_cap);
  }
  assert(cadence.snapshot().max_pixels == cadence_cap);
  // Rate jitter and encoder suspension cannot refund a source-size limit.
  cadence.SetRate(6000, 1.0);
  cadence.SetRate(0, 15.0);
  for (int i = 41; i <= 45; ++i) {
    cadence.Observe(500, 160, 120, i, i * 1'000'000);
    cadence.SetAudioPressure(0, i * 1'000'000);
  }
  assert(cadence.snapshot().max_pixels == cadence_cap);
  // Actual per-frame funding growth permits gradual recovery again.
  cadence.SetProfile(16000);
  cadence.SetRate(12000, 1.0);
  for (int i = 46; i <= 50; ++i) {
    cadence.Observe(500, 160, 120, i, i * 1'000'000);
    cadence.SetAudioPressure(0, i * 1'000'000);
  }
  assert(cadence.snapshot().max_pixels > cadence_cap);
  // Unknown/nonfinite FPS and the usual fast-camera cadence keep the existing
  // healthy overshoot behavior. No fabricated frame rate is supplied.
  for (double fps : {0.0, std::numeric_limits<double>::quiet_NaN(), 15.0}) {
    veil_media::VideoFrameBudget ordinary;
    ordinary.SetPacketPayload(1440);
    ordinary.SetProfile(8000);
    ordinary.SetRate(5833, fps);
    ordinary.SetAudioPressure(0, 1'000'000);
    ordinary.Observe(1477, 320, 240, 1, 1'100'000);
    assert(ordinary.snapshot().max_pixels == 0);
  }
  veil_media::VideoFrameBudget fractional;
  fractional.SetPacketPayload(1440);
  fractional.SetProfile(15000);
  fractional.SetRate(12000, 1.5);
  fractional.SetAudioPressure(0, 1'000'000);
  fractional.Observe(1900, 320, 240, 1, 1'100'000);
  assert(fractional.snapshot().max_pixels > 0);
  // Packetizer setup, codec output and source requests have different queues.
  // A growth hold preserves the current cap and earned active recovery,
  // without banking time or frames from the hold itself.
  veil_media::VideoFrameBudget held;
  held.SetPacketPayload(1440);
  held.SetProfile(15000);
  held.SetRate(12000);
  held.Observe(500, 320, 240, 1, 1'000'000);
  held.SetAudioPressure(1, 1'100'000);
  const int held_cap = held.snapshot().max_pixels;
  for (int i = 2; i <= 3; ++i) {
    held.Observe(500, 160, 120, i, i * 1'000'000);
    held.SetAudioPressure(0, i * 1'000'000);
  }
  for (int i = 4; i <= 6; ++i) {
    held.Observe(500, 160, 120, i, i * 1'000'000);
    held.HoldGrowth(i * 1'000'000, 7'000'000, i * 1'000'000);
    assert(held.snapshot().max_pixels == held_cap);
    assert(held.snapshot().audio_recoveries == 0);
  }
  held.HoldGrowth(6'000'000, 7'000'000, 6'500'000); // Replay: same deadline.
  held.Observe(500, 160, 120, 7, 7'000'000);
  held.SetAudioPressure(0, 7'000'000);
  assert(held.snapshot().max_pixels == held_cap); // No time bank from the hold.
  held.Observe(500, 160, 120, 8, 8'000'000);
  held.SetAudioPressure(0, 8'000'000);
  assert(held.snapshot().max_pixels > held_cap); // Earned recovery was preserved.
  assert(held.snapshot().audio_recoveries == 1);
  assert(held.snapshot().growth_holds == 1);
  held.SetAudioPressure(1, 8'500'000);
  const int genuine_cut = held.snapshot().max_pixels;
  held.HoldGrowth(8'000'000, 10'000'000, 9'000'000);
  assert(held.snapshot().audio_state == 1); // Cannot erase a newer pressure report.
  assert(held.snapshot().max_pixels == genuine_cut);
  // The low-rate startup sizing cap follows actual allocated rate, not just
  // a larger request. One fresh healthy sample permits one bounded area probe.
  auto low_rate_start = [](veil_media::VideoFrameBudget& b) {
    b.SetPacketPayload(1000);
    b.SetProfile(900000);
    b.SetRate(15000, 1);
    b.SetAudioPressure(0, 1'000'000);
    b.Observe(5000, 640, 480, 1, 1'100'000);
    assert(b.snapshot().max_pixels > 0 && b.snapshot().max_pixels < 640 * 480);
  };
  veil_media::VideoFrameBudget funded;
  low_rate_start(funded);
  const int funded_cap = funded.snapshot().max_pixels;
  funded.SetProfile(2500000); // Request alone earns nothing.
  funded.Observe(300, 160, 120, 2, 1'200'000);
  assert(funded.snapshot().max_pixels == funded_cap);
  funded.SetRate(60000, 8);
  funded.Observe(300, 160, 120, 3, 1'300'000);
  const int funded_probe = funded.snapshot().max_pixels;
  assert(funded_probe > funded_cap && funded_probe <= funded_cap * 4);
  funded.SetRate(240000, 16);
  funded.Observe(300, 160, 120, 4, 1'400'000);
  assert(funded.snapshot().max_pixels == funded_probe); // Same audio sample.
  funded.SetAudioPressure(0, 2'000'000);
  funded.Observe(1000, 320, 240, 5, 2'100'000);
  assert(funded.snapshot().max_pixels == 0); // Original source ceiling, not beyond.
  assert(funded.snapshot().audio_cuts == 0);
  for (int state : {-1, 1}) {
    veil_media::VideoFrameBudget blocked;
    low_rate_start(blocked);
    const int cap = blocked.snapshot().max_pixels;
    blocked.SetAudioPressure(state, 1'200'000);
    blocked.SetRate(240000, 16);
    blocked.Observe(300, 160, 120, 2, 1'300'000);
    const int protected_cap = blocked.snapshot().max_pixels;
    assert(protected_cap > 0 && protected_cap <= cap);
    blocked.SetAudioPressure(0, 1'400'000);
    blocked.Observe(300, 160, 120, 3, 1'500'000);
    assert(blocked.snapshot().max_pixels == protected_cap); // No banked unknown/pressure credit.
  }
  for (bool pause : {false, true}) {
    veil_media::VideoFrameBudget stopped_growth;
    low_rate_start(stopped_growth);
    const int cap = stopped_growth.snapshot().max_pixels;
    stopped_growth.SetRate(240000, 16);
    if (pause) {
      stopped_growth.SetAudioPressure(0, 5'000'000); // No recent encoded work.
    } else {
      stopped_growth.HoldGrowth(1'000'000, 3'000'000, 1'200'000);
      stopped_growth.Observe(300, 160, 120, 2, 2'000'000);
      stopped_growth.SetAudioPressure(0, 2'100'000);
    }
    const int64_t resume = pause ? 5'100'000 : 3'100'000;
    stopped_growth.Observe(300, 160, 120, 3, resume);
    assert(stopped_growth.snapshot().max_pixels == cap);
  }
  veil_media::VideoFrameBudget stale_funding;
  low_rate_start(stale_funding);
  const int stale_funding_cap = stale_funding.snapshot().max_pixels;
  stale_funding.SetRate(240000, 16);
  stale_funding.Observe(300, 160, 120, 2, 5'000'000);
  stale_funding.SetAudioPressure(0, 5'100'000);
  stale_funding.Observe(300, 160, 120, 3, 5'200'000);
  assert(stale_funding.snapshot().max_pixels == stale_funding_cap);
  std::thread encoder([&] {
    for (int i = 0; i < 1000; ++i) {
      budget.SetRate(8000);
      budget.Observe(2000, 320, 240);
    }
  });
  std::thread source([&] {
    for (int i = 0; i < 1000; ++i) {
      const auto s = budget.snapshot();
      assert(s.bytes >= 900);
      assert(s.max_pixels == 0 || s.max_pixels >= 6144);
    }
  });
  encoder.join();
  source.join();
  if (argc == 2) {
    { std::ofstream empty(argv[1]); assert(empty.good()); }
    setenv("VEIL_MEDIA_DIAG_PATH", argv[1], 1);
    {
      veil_media::VideoFrameBudget traced;
      traced.SetPacketPayload(964);
      traced.SetProfile(15000);
      traced.SetRate(7200);
      traced.Observe(2296, 320, 240, 17, 19000);
      traced.Observe(500, 160, 120, 18, 20000);
    }
    std::ifstream input(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(input)), {});
    assert(text.find("count=2 seen=2") != std::string::npos);
    assert(text.find("timestamp=17 at_us=19000 bytes=2296 width=320 height=240 budget=900 cap_before=0 cap_after=") != std::string::npos);
    assert(text.find("timestamp=18 at_us=20000 bytes=500 width=160 height=120") != std::string::npos);
    assert(text.find("write_ok=1") != std::string::npos);
    unsetenv("VEIL_MEDIA_DIAG_PATH");
    std::remove(argv[1]);
  }
}
