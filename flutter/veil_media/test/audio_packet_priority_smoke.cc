#include "veil_audio_packet_priority.h"
#include <cassert>
#include <cstdio>
#include <thread>

int main() {
  using veil_media::AudioPacketPriority;
  {
    auto a = std::make_shared<AudioPacketPriority>();
    auto b = std::make_shared<AudioPacketPriority>();
    assert(veil_media::current_audio_packet_priority == nullptr);
    {
      veil_media::AudioPacketPriorityScope outer(a);
      assert(*veil_media::current_audio_packet_priority == a);
      {
        veil_media::AudioPacketPriorityScope inner(b);
        assert(*veil_media::current_audio_packet_priority == b);
      }
      assert(*veil_media::current_audio_packet_priority == a);
      std::thread other([&] {
        assert(veil_media::current_audio_packet_priority == nullptr);
        veil_media::AudioPacketPriorityScope isolated(b);
        assert(*veil_media::current_audio_packet_priority == b);
      });
      other.join();
      assert(*veil_media::current_audio_packet_priority == a);
    }
    assert(veil_media::current_audio_packet_priority == nullptr);
  }
  AudioPacketPriority p;
  {
    AudioPacketPriority starting;
    starting.Enable();
    starting.ExpectVideo(true, 0);
    starting.Encoded(20);
    starting.WantLongPackets(true, 1);
    assert(starting.TryGrantLongPackets(1));
    assert(starting.VideoBlocked());
    assert(!starting.BeginVideo());  // No video ever admitted: source is yielded.
    starting.WantLongPackets(false, 2);
    starting.Encoded(40);
    assert(starting.BeginVideo());
    starting.EndVideo(true, 3);
    starting.WantLongPackets(true, 4);
    assert(!starting.TryGrantLongPackets(3'000'000));
    assert(!starting.VideoBlocked());  // Idle elapsed time alone grants nothing.
  }
  assert(!p.VideoBlocked());  // Legacy encoder has no new dependency.
  p.Enable();
  p.WantLongPackets(true, 0);
  assert(p.TryGrantLongPackets(0));  // Audio-only is immediately supported.
  p.Encoded(60);
  p.ExpectVideo(true, 1);
  assert(p.VideoHeldForAudio());
  p.WantLongPackets(false, 2);
  assert(p.VideoHeldForAudio());  // Requested short is not an emitted short.
  p.Encoded(40);
  assert(!p.VideoBlocked());
  assert(p.BeginVideo());
  p.EndVideo(true, 10);

  p.WantLongPackets(true, 11);
  assert(!p.TryGrantLongPackets(10'000'000));
  assert(!p.VideoBlocked());  // BWE alone must not pause video.
  assert(p.BeginVideo());
  p.PauseVideo(true, 20);
  assert(!p.TryGrantLongPackets(20'000'000));  // Admission still in flight.
  p.EndVideo(true, 30'000'000);
  assert(!p.TryGrantLongPackets(31'999'999));
  assert(p.TryGrantLongPackets(32'000'000));
  p.Encoded(60);
  p.PauseVideo(false, 32'000'001);
  assert(p.VideoBlocked());
  assert(!p.BeginVideo());
  p.Encoded(40);  // An old pending short packet cannot acknowledge recovery.
  assert(p.VideoBlocked());
  p.WantLongPackets(false, 32'000'002);
  assert(p.VideoBlocked());
  p.Encoded(40);
  assert(!p.VideoBlocked());
  assert(p.BeginVideo());
  p.EndVideo(true, 33'000'000);
  p.ExpectVideo(false, 33'000'100);
  assert(!p.BeginVideo());  // No late packet may follow a completed stop.
  p.WantLongPackets(true, 33'000'101);
  assert(!p.TryGrantLongPackets(35'000'099));
  assert(p.TryGrantLongPackets(35'000'100));
  assert(!p.LongPacketsAllowed(32'000'000));  // Clock rollback is not quiet.

  p.ExpectVideo(true, 36'000'000);
  p.WantLongPackets(false, 36'000'000);
  p.Encoded(40);
  p.ResetAudio();
  assert(p.VideoBlocked());
  p.Encoded(20);
  assert(!p.VideoBlocked());
  p.Disable();
  assert(p.BeginVideo());
  p.EndVideo(false, 37'000'000);
  std::puts("ok: emitted short ACK, real video quiescence, in-flight admission, resume and clock bounds");
}
