#include "veil_rtcp_send_stats.h"
#include <cassert>
#include <vector>

std::vector<uint8_t> Block(uint8_t type, uint8_t fmt, size_t bytes = 8) {
  std::vector<uint8_t> b(bytes);
  b[0] = 0x80 | fmt; b[1] = type;
  b[2] = ((bytes / 4 - 1) >> 8) & 255;
  b[3] = (bytes / 4 - 1) & 255;
  return b;
}

int main() {
  veil_media::RtcpSendStats stats;
  auto sr = Block(200, 0), sdes = Block(202, 1);
  auto compound = sr; compound.insert(compound.end(), sdes.begin(), sdes.end());
  stats.Record(compound, false);
  auto s = stats.Snapshot();
  assert(s.audio_packets == 1 && s.audio_bytes == 16);
  assert(s.blocks[0][0] == 1 && s.blocks[0][2] == 1 && s.video_packets == 0);
  // A damaged compound cannot partially publish its valid first SR.
  auto bad = compound; bad.back() = 0;
  bad.pop_back(); stats.Record(bad, false);
  s = stats.Snapshot();
  assert(s.audio_packets == 2 && s.malformed[0] == 1 && s.blocks[0][0] == 1);
  for (auto [type, fmt, kind] : {std::array<int,3>{201,0,1}, {203,0,3},
      {204,0,4}, {205,1,5}, {206,1,6}, {206,4,7}, {205,15,8}, {207,0,10}, {210,0,11}}) {
    auto b = Block(type, fmt); stats.Record(b, true);
    assert(stats.Snapshot().blocks[1][kind] == 1);
  }
  auto remb = Block(206, 15, 20);
  remb[12]='R'; remb[13]='E'; remb[14]='M'; remb[15]='B';
  stats.Record(remb, true); assert(stats.Snapshot().blocks[1][9] == 1);
  remb[12] ^= 1; stats.Record(remb, true);
  assert(stats.Snapshot().blocks[1][9] == 1 && stats.Snapshot().blocks[1][11] == 2);
  auto padded = Block(201, 0, 12); padded[0] |= 0x20; padded.back() = 4;
  stats.Record(padded, true); assert(stats.Snapshot().blocks[1][1] == 2);
  padded.back() = 0; stats.Record(padded, true);
  assert(stats.Snapshot().malformed[1] == 1);
  auto invalid = Block(200, 0); invalid[0] = 0;
  stats.Record(invalid, true); stats.Record(std::span<const uint8_t>{}, true);
  std::vector<uint8_t> many;
  for (int i=0; i<65; ++i) many.insert(many.end(), sr.begin(), sr.end());
  stats.Record(many, true);
  assert(stats.Snapshot().malformed[1] == 4);
  assert(stats.Snapshot().blocks[1][0] == 0);
}
