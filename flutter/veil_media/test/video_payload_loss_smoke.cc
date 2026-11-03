#include "veil_video_payload_loss.h"
#include <cassert>
#include <cstdio>
using namespace veil_media;
int main() {
  VideoPacketHistory h;
  h.Record(65535, 90, 100, true, 1);
  h.Record(0, 91, 100, false, 2);
  h.Record(1, 92, 100, true, 3);
  assert(h.Find(65535, 3)->payload);
  assert(!h.Find(0, 3)->payload);
  assert(!h.Find(1, 2)); // future/rollback
  assert(!h.Find(1, 15'000'004));
  VideoPayloadLoss a, b;
  auto first = *h.Find(65535, 3), padding = *h.Find(0, 3), last = *h.Find(1, 3);
  // Per-peer losses remain separate despite sharing source metadata.
  a.Observe({{first, false}, {padding, false}, {last, true}}, true, 100);
  b.Observe({{first, true}, {padding, false}, {last, true}}, true, 100);
  assert(a.FreshAt(100) && b.FreshAt(100));
  a.Observe({{first, false}, {padding, false}, {last, true}}, true, 3'000'200);
  assert(a.event_us() == 0 && !a.FreshAt(3'000'200)); // replay can't confirm
  h.Record(2, 93, 100, true, 4);
  auto next = *h.Find(2, 4);
  a.Observe({{next, true}}, true, 3'000'201);
  b.Observe({{next, true}}, true, 3'000'201);
  assert(a.event_us() == 3'000'201 && b.event_us() == 0);
  // Late receipt is sticky even if an older missing report arrives later.
  a.Reset();
  a.Observe({{first, false}, {last, true}}, true, 100);
  a.Observe({{first, true}}, true, 200);
  a.Observe({{first, false}, {next, true}}, true, 3'000'201);
  assert(a.event_us() == 0);
  // Ring alias/expiry is unknown, never proof that the lost packet was padding.
  h.Record(4097, 94, 100, false, 5);
  assert(!h.Find(1, 5));
  a.Observe({}, false, 3'000'202);
  assert(!a.FreshAt(3'000'202));
  h.Record(4098, 95, 100, true, 6);
  a.Observe({{*h.Find(4098, 6), true}}, true, 3'000'203);
  assert(!a.FreshAt(3'000'203)); // healthy short report can't restore unknown continuity
  a.Reset(5);
  a.Observe({{first, false}, {last, true}}, true, 100);
  assert(!a.FreshAt(100)); // superseded-route records cannot renew evidence
  a.Observe({{*h.Find(4098, 6), true}}, true, 101);
  assert(a.FreshAt(101) && a.event_us() == 0);
  assert(!a.FreshAt(3'000'102));
  a.Observe({{*h.Find(4098, 6), true}}, true, 90);
  assert(!a.FreshAt(90));
  std::puts("video payload loss: exact packet classes, real gap, late fill, replay, per-peer, bounds, wrap and epochs PASS");
}
