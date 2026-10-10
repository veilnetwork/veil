#include "veil_audio_redundancy.h"
#include <cassert>
#include <vector>

int main() {
  constexpr uint32_t ssrc = 0x01020304;
  std::vector<uint8_t> p{0x80, 111, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         1, 2, 3, 4, 0xf8, 0xff, 0xfe};
  auto key = veil_media::AudioPayloadKey(p, ssrc);
  assert(key && *key == 0xffffffffffffULL);
  veil_media::AudioPacketHistory history;
  assert(history.accept(*key));
  assert(!history.accept(*key));
  // Sequence and timestamp wrap do not alias a previous packet; a first
  // arrival may come from either route, including out of order.
  p[2] = p[3] = p[4] = p[5] = p[6] = p[7] = 0;
  key = veil_media::AudioPayloadKey(p, ssrc);
  assert(key && *key == 0 && history.accept(*key));
  assert(history.accept(960ULL << 16 | 1));
  assert(!history.accept(0));
  assert(!veil_media::AudioPayloadKey(p, 0));
  assert(!veil_media::AudioPayloadKey(p, ssrc + 1));
  p[1] = 96; assert(!veil_media::AudioPayloadKey(p, ssrc)); p[1] = 111;
  p[0] = 0xa0; p.back() = 3;  // Padding-only audio is not mirrored.
  assert(!veil_media::AudioPayloadKey(p, ssrc));
  p.back() = 0; assert(!veil_media::AudioPayloadKey(p, ssrc));
  p.back() = 4; assert(!veil_media::AudioPayloadKey(p, ssrc));
  p[0] = 0x81; assert(!veil_media::AudioPayloadKey(p, ssrc)); // CSRC truncated.
  p[0] = 0x90; assert(!veil_media::AudioPayloadKey(p, ssrc)); // Extension truncated.
  p.resize(23); p[12] = 0xbe; p[13] = 0xde; p[14] = 0; p[15] = 1;
  p[20] = 0xf8; p[21] = 0xff; p[22] = 0xfe;
  assert(veil_media::AudioPayloadKey(p, ssrc));
  p[14] = 0xff; assert(!veil_media::AudioPayloadKey(p, ssrc));
  // Duplicates do not evict useful history. Memory is fixed, with an explicit
  // packet-count boundary rather than an unbounded session replay cache.
  veil_media::AudioPacketHistory bounded;
  for (size_t i = 0; i < bounded.capacity; ++i) {
    assert(bounded.accept(i)); assert(!bounded.accept(i));
  }
  assert(!bounded.accept(0));
  assert(bounded.accept(bounded.capacity));
  assert(bounded.accept(0));
}
