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
    AudioPacketPriority muted;
    muted.Enable();
    muted.SetAudioSending(false);
    muted.ExpectVideo(true, 0);
    assert(!muted.VideoHeldForAudio() && muted.BeginVideo());
    muted.EndVideo(true, 1);
    muted.PauseVideo(true, 2);
    assert(muted.VideoBlocked() && !muted.BeginVideo()); // Explicit pressure remains binding.
    muted.PauseVideo(false, 3);
    assert(!muted.VideoBlocked());
    muted.SetAudioSending(true);
    assert(muted.VideoHeldForAudio()); // Resume needs a real packet, not a mute toggle.
    muted.Encoded(20);
    assert(!muted.VideoBlocked());
    muted.SetAudioSending(true);
    assert(!muted.VideoBlocked()); // Idempotent unmute cannot keep blanking video.
    muted.SetAudioSending(false);
    muted.Encoded(60); // An old queued encode cannot freeze a muted source.
    assert(!muted.VideoBlocked());
    muted.SetAudioSending(true);
    assert(muted.VideoBlocked());
    muted.WantLongPackets(false, 4);
    muted.Encoded(40);
    assert(!muted.VideoBlocked());
  }
  {
    AudioPacketPriority starting;
    starting.Enable();
    starting.ExpectVideo(true, 0);
    starting.Encoded(20);
    starting.WantLongPackets(true, 1);
    assert(starting.TryGrantLongPackets(1));
    assert(!starting.VideoBlocked()); // A codec request is not a video pause.
    assert(starting.BeginVideo());
    starting.EndVideo(true, 1);
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
  assert(!p.VideoHeldForAudio()); // Real long audio is a valid capture witness.
  p.WantLongPackets(false, 2);
  assert(!p.VideoHeldForAudio()); // Short-packet funding cannot latch the camera.
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
  assert(!p.VideoBlocked());
  assert(p.BeginVideo());
  p.EndVideo(true, 32'000'001);
  p.Encoded(40);
  assert(!p.VideoBlocked());
  p.WantLongPackets(false, 32'000'002);
  assert(!p.VideoBlocked());
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
  {
    // The app has already reduced its actual capture gate to <=1 fps. A
    // healthy sparse trial must not depend on first funding 40-ms Opus.
    AudioPacketPriority sparse;
    sparse.Enable();
    sparse.WantLongPackets(true, 0);
    assert(sparse.TryGrantLongPackets(0));
    sparse.Encoded(60);
    sparse.ExpectVideo(true, 0);
    assert(!sparse.VideoBlocked());
    sparse.AllowSparseVideo(true);
    assert(!sparse.VideoBlocked() && sparse.BeginVideo());
    assert(sparse.TryGrantLongPackets(1)); // Sparse RTP can coexist with 60 ms.
    sparse.EndVideo(true, 2);
    sparse.PauseVideo(true, 3); // Real measured trouble still stops the source.
    assert(sparse.VideoBlocked() && !sparse.BeginVideo());
    assert(!sparse.VideoHeldForAudio()); // Report the explicit pause accurately.
    sparse.PauseVideo(false, 4);
    assert(!sparse.VideoBlocked());
    sparse.AllowSparseVideo(false); // A probe cannot close an already live source.
    assert(!sparse.VideoBlocked() && sparse.BeginVideo());
    sparse.EndVideo(true, 4);
    sparse.WantLongPackets(false, 5);
    assert(!sparse.VideoBlocked());
    sparse.Encoded(40);
    assert(!sparse.VideoBlocked());
    sparse.AllowSparseVideo(true);
    sparse.ResetAudio();
    assert(sparse.VideoBlocked()); // No synthetic ACK for missing audio.
    sparse.Encoded(60);
    sparse.ExpectVideo(false, 6);
    assert(!sparse.BeginVideo());
  }
  std::puts("ok: capture witness, long Opus video continuity, explicit pause, quiescence, in-flight admission and clock bounds");
}
