/* SPDX-License-Identifier: MIT
 *
 * parse_bombs_smoke.cc — the media containers, fed what an attacker sends.
 *
 * A voice message and a video note arrive as bytes from a peer and are parsed
 * by libveil_media the moment the recipient taps them. Both containers declare
 * their own sizes in fields the sender chose, and both parsers used to size
 * allocations from those fields before anything had been proved. This links
 * the real dylib and asserts the positive: each bomb is REFUSED — a null
 * handle back, the process still alive, and the resident set barely moved.
 *
 * Build/run: ../test/run_parse_bombs_smoke.sh
 */

#include <sys/resource.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#endif

extern "C" {
struct VeilAudioPlayer;
struct VeilVnotePlayer;
VeilAudioPlayer* veil_media_player_create(const uint8_t* voice_opus, size_t len);
void veil_media_player_destroy(VeilAudioPlayer* p);
int veil_media_player_duration_ms(VeilAudioPlayer* p);
VeilVnotePlayer* veil_media_vnote_player_create(const uint8_t* vnote,
                                                size_t len);
void veil_media_vnote_player_destroy(VeilVnotePlayer* p);
}

namespace {

int failures = 0;

// Peak resident set in MiB. Every ceiling below is stated against the peak,
// not the current size, so a buffer that was allocated and freed still counts.
long peak_rss_mib() {
  struct rusage ru {};
  getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
  return ru.ru_maxrss / (1024 * 1024);  // bytes on Darwin
#else
  return ru.ru_maxrss / 1024;  // kilobytes elsewhere
#endif
}

// Address space, in MiB.
//
// Resident size is not enough to see every bomb. A reserve() for a hundred
// gigabytes is one mmap, and on a 64-bit desktop the kernel hands back the
// range without committing a page: the resident set never moves, the parser
// carries on, and a probe that watches only RSS reports success. On a phone —
// where these messages are opened — the same request has nowhere to come from,
// and libc++ built with -fno-exceptions turns the failure into abort(). What
// is common to both is the size of the request, so that is what is measured.
long vsize_mib() {
#if defined(__APPLE__)
  mach_task_basic_info info{};
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS) {
    return -1;
  }
  return (long)(info.virtual_size / (1024 * 1024));
#else
  long pages = 0;
  FILE* f = std::fopen("/proc/self/statm", "r");
  if (f == nullptr) return -1;
  if (std::fscanf(f, "%ld", &pages) != 1) pages = 0;
  std::fclose(f);
  return pages * (long)(sysconf(_SC_PAGESIZE) / 1024) / 1024;
#endif
}

void check(bool ok, const char* what) {
  std::printf("%-58s %s\n", what, ok ? "REFUSED" : "*** ACCEPTED ***");
  if (!ok) failures++;
}

void check_rss(long before, long budget_mib, const char* what) {
  const long grew = peak_rss_mib() - before;
  const bool ok = grew <= budget_mib;
  std::printf("%-58s %+ld MiB rss (budget %ld) %s\n", what, grew, budget_mib,
              ok ? "ok" : "*** BLEW THE BUDGET ***");
  if (!ok) failures++;
}

void put_u16le(std::vector<uint8_t>& v, uint16_t x) {
  v.push_back((uint8_t)(x & 0xff));
  v.push_back((uint8_t)(x >> 8));
}
void put_u32le(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back((uint8_t)(x & 0xff));
  v.push_back((uint8_t)((x >> 8) & 0xff));
  v.push_back((uint8_t)((x >> 16) & 0xff));
  v.push_back((uint8_t)((x >> 24) & 0xff));
}

// VOICE_OPUS: "VOP1" | u8 version | u8 channels | u32 rate | u32 duration_ms |
//             u32 packet_count | packet_count x [u16 len][len bytes]
std::vector<uint8_t> voice(uint8_t version, uint8_t channels, uint32_t rate,
                          uint32_t duration_ms, uint32_t packet_count,
                          const std::vector<uint8_t>& body) {
  std::vector<uint8_t> v{'V', 'O', 'P', '1'};
  v.push_back(version);
  v.push_back(channels);
  put_u32le(v, rate);
  put_u32le(v, duration_ms);
  put_u32le(v, packet_count);
  v.insert(v.end(), body.begin(), body.end());
  return v;
}

// VNOTE1: "VN01" | u8 version | u8 flags | u16 w | u16 h | u8 fps | u8 pad |
//         u32 duration_ms | u32 audio_len | u32 frame_count | audio | frames
std::vector<uint8_t> vnote(uint32_t audio_len, uint32_t frame_count) {
  std::vector<uint8_t> v{'V', 'N', '0', '1'};
  v.push_back(1);  // version
  v.push_back(0);  // flags: no audio
  put_u16le(v, 480);
  put_u16le(v, 480);
  v.push_back(24);  // fps
  v.push_back(0);   // reserved
  put_u32le(v, 1000);
  put_u32le(v, audio_len);
  put_u32le(v, frame_count);
  return v;
}

}  // namespace

int main() {
  // ── Bomb 1: the sample rate ───────────────────────────────────────────────
  // Read from the header, checked only for "greater than zero", and used to
  // size the decode scratch — 120 ms of it, before a single packet is looked
  // at. At the top of the int range that is about a gigabyte.
  {
    const long before = peak_rss_mib();
    auto bomb = voice(1, 1, 0x7FFFFFFF, 0, 0, {});
    auto* p = veil_media_player_create(bomb.data(), bomb.size());
    check(p == nullptr, "voice: sample rate 0x7FFFFFFF");
    veil_media_player_destroy(p);
    check_rss(before, 64, "voice: sample rate 0x7FFFFFFF, peak growth");
  }

  // The fields the old parser never read at all.
  {
    auto bad_version = voice(2, 1, 48000, 0, 0, {});
    check(veil_media_player_create(bad_version.data(), bad_version.size()) ==
              nullptr,
          "voice: container version 2");
    auto bad_channels = voice(1, 9, 48000, 0, 0, {});
    check(veil_media_player_create(bad_channels.data(), bad_channels.size()) ==
              nullptr,
          "voice: channel count 9");
    auto bad_duration = voice(1, 1, 48000, 0xFFFFFFFF, 0, {});
    check(veil_media_player_create(bad_duration.data(), bad_duration.size()) ==
              nullptr,
          "voice: duration 0xFFFFFFFF ms");
    auto lying_count = voice(1, 1, 48000, 1000, 1000000, {1, 2, 3, 4});
    check(veil_media_player_create(lying_count.data(), lying_count.size()) ==
              nullptr,
          "voice: 1000000 packets in four bytes");
  }

  // ── Bomb 2: the decoded sample count ──────────────────────────────────────
  // Every packet decodes to as much as 120 ms whatever its size, and the PCM
  // buffer grew by push_back with no ceiling. A container well under a
  // megabyte inflates to hundreds of megabytes of int16.
  {
    const long before = peak_rss_mib();
    std::vector<uint8_t> body;
    const int kPackets = 200000;
    for (int i = 0; i < kPackets; i++) {
      // TOC 0x18: SILK narrowband, 60 ms, one frame — the longest single
      // frame a three-byte packet can ask the decoder for.
      put_u16le(body, 3);
      body.push_back(0x18);
      body.push_back((uint8_t)i);
      body.push_back((uint8_t)(i >> 8));
    }
    auto bomb = voice(1, 1, 48000, 1000, kPackets, body);
    std::printf("voice: %d minimal packets in %zu KiB\n", kPackets,
                bomb.size() / 1024);
    auto* p = veil_media_player_create(bomb.data(), bomb.size());
    // Either the ceiling refused the clip outright, or the decoder produced
    // nothing at all from the junk. Both are fine; unbounded growth is not.
    if (p != nullptr) {
      std::printf("  (opened, %d ms held)\n", veil_media_player_duration_ms(p));
      veil_media_player_destroy(p);
    }
    check_rss(before, 128, "voice: decoded-sample ceiling, peak growth");
  }

  // ── Bomb 3: the video-note frame count ────────────────────────────────────
  // A u32 read straight out of the header and handed to reserve() before one
  // frame header had been shown to exist. Tens of gigabytes asked for, a throw
  // out of a C entry point, and no handler above it.
  {
    // The reservation is freed on the way out of the parser, so it is only
    // visible while it is alive: a watcher samples the address space flat out
    // while the bomb is fed in repeatedly. Two hundred passes, each one a
    // chance to catch a hundred gigabytes being asked for.
    auto bomb = vnote(0, 0xFFFFFFFF);
    const long rss_before = peak_rss_mib();
    const long vsize_before = vsize_mib();
    std::atomic<long> seen{vsize_before};
    std::atomic<bool> stop{false};
    std::thread watcher([&] {
      while (!stop.load(std::memory_order_relaxed)) {
        const long v = vsize_mib();
        long best = seen.load(std::memory_order_relaxed);
        while (v > best && !seen.compare_exchange_weak(best, v)) {
        }
      }
    });
    bool all_refused = true;
    for (int i = 0; i < 200; i++) {
      auto* p = veil_media_vnote_player_create(bomb.data(), bomb.size());
      if (p != nullptr) all_refused = false;
      veil_media_vnote_player_destroy(p);
    }
    stop.store(true, std::memory_order_relaxed);
    watcher.join();

    check(all_refused, "vnote: frame count 0xFFFFFFFF");
    check_rss(rss_before, 64, "vnote: frame count 0xFFFFFFFF");
    const long asked = seen.load() - vsize_before;
    const bool bounded = asked <= 64;
    std::printf("%-58s %+ld MiB asked for (budget 64) %s\n",
                "vnote: frame count 0xFFFFFFFF", asked,
                bounded ? "ok" : "*** BLEW THE BUDGET ***");
    if (!bounded) failures++;

    auto near_miss = vnote(0, 100000);
    check(veil_media_vnote_player_create(near_miss.data(), near_miss.size()) ==
              nullptr,
          "vnote: 100000 frames with no frame bytes");
  }

  // ── And a container that is fine stays fine ───────────────────────────────
  {
    auto empty_but_valid = voice(1, 1, 48000, 0, 0, {});
    // No packets, so nothing decodes and the player is refused for being
    // empty — not for the header, which is exactly what a recorder writes.
    check(veil_media_player_create(empty_but_valid.data(),
                                   empty_but_valid.size()) == nullptr,
          "voice: well-formed but empty (expected refusal)");
    auto no_frames = vnote(0, 0);
    auto* p = veil_media_vnote_player_create(no_frames.data(),
                                             no_frames.size());
    std::printf("%-58s %s\n", "vnote: well-formed, zero frames",
                p != nullptr ? "ACCEPTED (correct)" : "*** REFUSED ***");
    if (p == nullptr) failures++;
    veil_media_vnote_player_destroy(p);
  }

  std::printf("\npeak rss %ld MiB, %d failure(s)\n", peak_rss_mib(), failures);
  return failures == 0 ? 0 : 1;
}
