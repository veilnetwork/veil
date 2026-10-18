#include "../src/veil_group_audio_send_trace.h"

#include <array>
#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>

std::string Read(const char* path) {
  std::ifstream file(path);
  return {(std::istreambuf_iterator<char>(file)), {}};
}

int main() {
  char path[] = "/private/tmp/veil-group-send-trace-XXXXXX";
  const int fd = mkstemp(path);
  assert(fd >= 0);
  close(fd);
  // Version 2, Opus PT, wrapped timestamp/sequence, SSRC 7, one payload byte.
  const std::array<uint8_t, 13> audio = {
      0x80, 111, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 7, 1};
  unsetenv("VEIL_MEDIA_DIAG_PATH");
  {
    veil_media::GroupAudioSendTrace disabled(7);
    setenv("VEIL_MEDIA_DIAG_PATH", path, 1);
    disabled.Record(100, audio, 1, 2, true);
  }
  assert(Read(path).empty());
  setenv("VEIL_MEDIA_RTP_TRACE_LIMIT", "2", 1);
  {
    veil_media::GroupAudioSendTrace trace(7);
    auto other = audio;
    other[11] = 8;
    trace.Record(100, other, 1, 2, true);  // Wrong audio SSRC.
    other = audio;
    other[1] = 96;
    trace.Record(100, other, 1, 2, true);  // Video cannot occupy the recorder.
    other = audio;
    other[0] |= 0x20;
    trace.Record(100, other, 1, 2, true);  // All padding, no audio payload.
    trace.Record(100, audio, 1000, 1001, true);
    trace.Record(200, audio, 1002, 1003, false);
    trace.Record(300, audio, 1004, 1005, true);  // Explicitly reported truncation.
    assert(Read(path).empty());  // Nothing writes on the media callback.
  }
  const auto text = Read(path);
  assert(text.find("ssrc=7 count=2 limit=2 seen=3") != std::string::npos);
  assert(text.find("channel=100 seq=65535 timestamp=4294967294 attempted_us=1000 admitted_us=1001 packet_bytes=13 accepted=1") != std::string::npos);
  assert(text.find("channel=200 seq=65535 timestamp=4294967294 attempted_us=1002 admitted_us=1003 packet_bytes=13 accepted=0") != std::string::npos);
  assert(text.find("channel=300") == std::string::npos);
  unlink(path);
  unsetenv("VEIL_MEDIA_DIAG_PATH");
  unsetenv("VEIL_MEDIA_RTP_TRACE_LIMIT");
}
