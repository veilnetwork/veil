#include "veil_video_frame_budget.h"
#include <cassert>
#include <thread>
#include <fstream>
#include <iterator>
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
  // Packetizer setup, codec output and source requests have different queues.
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
