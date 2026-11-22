#include "veil_video_loss_persistence.h"
#include <cassert>
#include <cstdio>

using veil_media::VideoLossPersistence;
int main() {
  VideoLossPersistence p;
  // Recorded temporary RR gap: four missing packets drain to zero in1.6s.
  assert(p.Observe(0, 373, 125'169'862) == 0);
  assert(p.Observe(4, 387, 126'901'235) == 0);
  assert(p.Observe(3, 387, 127'020'767) == 0);
  assert(p.Observe(2, 387, 127'158'668) == 0);
  assert(p.Observe(1, 387, 127'222'659) == 0);
  assert(p.Observe(0, 387, 128'507'467) == 0);
  assert(p.Observe(0, 397, 133'454'256) == 0);
  p.Reset();
  assert(p.Observe(0, 100, 1'000'000) == 0);
  assert(p.Observe(4, 110, 2'000'000) == 0);
  assert(p.Observe(4, 111, 4'999'999) == 0);
  assert(p.Observe(4, 111, 5'000'000) == 0); // duplicate cannot confirm
  assert(p.Observe(4, 112, 5'010'000) == 5'010'000);
  assert(p.Observe(4, 120, 6'000'000) == 0); // consumed historical gap
  assert(p.Observe(5, 121, 7'000'000) == 0);
  assert(p.Observe(4, 122, 8'000'000) == 0); // recovered new gap
  assert(p.Observe(4, 130, 12'000'000) == 0);
  // An identical report, even polled much later, cannot confirm a gap.
  p.Reset();
  assert(p.Observe(0, 100, 1'000'000) == 0);
  assert(p.Observe(1, 101, 2'000'000) == 0);
  assert(p.Observe(1, 101, 9'000'000) == 0);
  assert(p.Observe(8, 100, 10'000'000) == 0); // reordered old report
  assert(p.Observe(1, 102, 11'000'000) == 11'000'000);
  // Historical first loss and signed negative cumulative counters are valid.
  p.Reset();
  assert(p.Observe(40, 200, 1'000'000) == 0);
  assert(p.Observe(40, 210, 5'000'000) == 0);
  p.Reset();
  assert(p.Observe(-4, 100, 1'000'000) == 0);
  assert(p.Observe(-3, 101, 2'000'000) == 0);
  assert(p.Observe(-3, 110, 5'000'000) == 5'000'000);
  // Serial arithmetic accepts sequence wrap without accepting old reports.
  p.Reset();
  assert(p.Observe(0, 0xfffffff0u, 1'000'000) == 0);
  assert(p.Observe(1, 0xfffffff9u, 2'000'000) == 0);
  assert(p.Observe(1, 1, 5'000'000) == 5'000'000);
  // New route, stream, expired report and clock rollback start fresh evidence.
  p.Reset();
  assert(p.Observe(0, 100, 1'000'000) == 0);
  assert(p.Observe(1, 101, 2'000'000) == 0);
  p.RouteChanged();
  assert(p.Observe(1, 110, 6'000'000) == 0);
  assert(p.Observe(2, 111, 7'000'000) == 0);
  assert(p.Observe(2, 120, 10'000'000) == 10'000'000);
  p.Reset();
  assert(p.Observe(0, 1, 1'000'000) == 0);
  assert(p.Observe(1, 2, 2'000'000) == 0);
  assert(p.Observe(1, 3, 20'000'000) == 0);
  assert(p.Observe(1, 4, 19'000'000) == 0);
  assert(p.Observe(1, 5, 22'000'000) == 0); // unknown history after rollback
  assert(p.Observe(2, 6, 23'000'000) == 0);
  assert(p.Observe(2, 7, 26'000'000) == 26'000'000);
  // In the relay capture, the receiver could report the three missing
  // packets only once a newly resumed frame advanced its highest sequence.
  p.Reset();
  assert(p.Observe(0, 25506, 30'776'000) == 0);
  p.ResumeAfter(25509, 43'000'000);
  assert(p.Observe(0, 25506, 43'300'000) == 0);  // Queued before the pause.
  assert(p.Observe(3, 25510, 44'615'000) == 0);
  assert(p.Observe(3, 25517, 47'645'000) == 0);  // Same old gap.
  assert(p.Observe(5, 25521, 48'600'000) == 0);
  assert(p.Observe(5, 25527, 51'638'000) == 51'638'000);
  // A report within the old source's range must not set the resume baseline.
  // Test both RTP's low-16-bit wrap and RR's extended sequence wrap.
  p.Reset();
  assert(p.Observe(0, 0xfffffffcu, 1'000'000) == 0);
  p.ResumeAfter(0xffffu, 1'500'000);
  assert(p.Observe(1, 0xfffffffeu, 2'000'000) == 0);
  assert(p.Observe(3, 0, 3'000'000) == 0);
  assert(p.Observe(3, 1, 6'100'000) == 0);
  assert(p.Observe(4, 2, 7'000'000) == 0);
  assert(p.Observe(4, 3, 10'000'000) == 10'000'000);
  p.Reset();
  assert(p.Observe(0, 100, 1'000'000) == 0);
  p.ResumeAfter(100, 2'000'000);
  assert(p.Observe(9, 100, 1'900'000) == 0);  // Older ingress processed later.
  assert(p.Observe(1, 102, 3'000'000) == 0);  // One sequence withheld by the pause.
  assert(p.Observe(1, 103, 6'000'000) == 0);
  // After a long absence, the low-16-bit comparison alone is ambiguous.
  p.ResumeAfter(100, 7'000'000);
  assert(p.Observe(1, 40100, 23'000'000) == 0);
  assert(p.Observe(2, 40102, 24'000'000) == 0);
  assert(p.Observe(2, 40103, 27'000'000) == 27'000'000);
  std::puts("video loss persistence: late fill, sustained loss, replay, signed counters, wrap and lifecycle PASS");
}
