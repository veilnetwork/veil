#include "../src/veil_audio_encode_timing.h"

#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>

int main() {
  char path[] = "/private/tmp/veil-encode-timing-XXXXXX";
  const int fd = mkstemp(path);
  assert(fd >= 0);
  close(fd);
  setenv("VEIL_MEDIA_DIAG_PATH", path, 1);
  setenv("VEIL_MEDIA_RTP_TRACE_LIMIT", "2", 1);
  {
    veil_media::AudioEncodeTiming trace(7);
    trace.Input(0xffffff00u, 1000);
    trace.Input(0x000000e0u, 2000);
    trace.Allocation(2500, 160000, 120000, 245);
    trace.Encoded(0xffffff00u, 3000, 2, 20);
    trace.Encoded(0x000000e0u, 4000, 2, 0); // DTX is not an emitted packet.
    for (uint32_t i = 0; i < 32; ++i) trace.Input(10000 + i * 480, 4100 + i);
    trace.Allocation(4500, 64000, 48000, 245);
    trace.Encoded(0xffffff00u, 5000, 6, 20); // The input is no longer retained.
    trace.Encoded(10000, 6000, 6, 20); // Capacity cannot be exceeded.
  }
  std::ifstream file(path);
  const std::string text((std::istreambuf_iterator<char>(file)), {});
  assert(text.find("ssrc=7 count=2 limit=2 inputs=34 seen=3") != std::string::npos);
  assert(text.find("first_us=1000 first_index=0 encoded_us=3000") != std::string::npos);
  assert(text.find("first_us=-1 first_index=-1 encoded_us=5000") != std::string::npos);
  assert(text.find("allocation_us=2500 allocation_raw_bps=160000 allocation_ana_bps=120000 allocation_overhead_bytes=245") != std::string::npos);
  assert(text.find("allocation_us=4500 allocation_raw_bps=64000 allocation_ana_bps=48000 allocation_overhead_bytes=245") != std::string::npos);
  assert(text.find("encoded_us=4000") == std::string::npos);
  assert(text.find("encoded_us=6000") == std::string::npos);
  unlink(path);
  unsetenv("VEIL_MEDIA_DIAG_PATH");
  unsetenv("VEIL_MEDIA_RTP_TRACE_LIMIT");
}
