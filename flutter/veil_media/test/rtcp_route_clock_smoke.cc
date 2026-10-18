#include "../src/veil_rtcp_route_clock.h"

#include <cassert>

int main() {
  veil_media::RtcpRouteClock route;
  assert(route.epoch() == 0);
  assert(!route.Accepts(0));
  assert(route.Accepts(1));
  assert(route.Accepts(0xffffffff));
  route.Reset(0xfffffff0);
  assert(route.epoch() == 1);
  assert(!route.Accepts(0xffffffef));
  assert(!route.Accepts(0xfffffff0));
  assert(route.Accepts(0xfffffff1));
  assert(route.Accepts(0x10));  // Compact NTP wrapped after the switch.
  assert(!route.Accepts(0));
  route.Reset(0x100);
  assert(route.epoch() == 2);
  assert(!route.Accepts(0xfffffff1));
  assert(!route.Accepts(0x10));
  assert(!route.Accepts(0x100));
  assert(route.Accepts(0x101));
  // A genuine zero floor at a wrap remains a changed route, not a sentinel.
  route.Reset(0);
  assert(route.epoch() == 3);
  assert(!route.Accepts(0xffffffff));
  assert(route.Accepts(1));
}
