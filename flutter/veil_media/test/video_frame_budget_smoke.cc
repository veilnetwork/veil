#include "veil_video_frame_budget.h"
#include <cassert>
#include <thread>

int main() {
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
}
