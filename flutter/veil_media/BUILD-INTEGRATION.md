# veil_media — build & integration plan (Phase 3+)

Status: **scaffold in place; libwebrtc build in progress.** The Dart control
API, the extern-C engine ABI (`src/veil_media_engine.h`), and the
`webrtc::Transport` shim (`src/veil_transport_shim.*`) are written against
documented WebRTC APIs. The `webrtc::Call` engine impl and the per-platform
native builds are finalized against the built headers.

## What this plugin is

A codec-stripped libwebrtc (no ICE/STUN/TURN/SDP/PeerConnection/DTLS) driven by
`webrtc::Call` + a custom `webrtc::Transport` (the shim) that pipes RTP/RTCP
over the **veil media datagram channel** (Phase 2, `veilclient-ffi`
`veil_media_*` ABI). Per-packet media flows native↔native; Dart drives control
only (`lib/veil_media.dart`).

```
Dart (control)            veil_media_engine_*  (src/veil_media_engine.h)
   │  start/stop/mute/device/stats
   ▼
webrtc::Call ── AudioState(AEC3/AGC/NS + ADM) ── AudioSend/ReceiveStream(Opus/NetEQ)
   │  SendRtp/SendRtcp                    ▲ DeliverRtp/RtcpPacket
   ▼                                      │
VeilTransportShim ──► veil_media_send_datagram   veil_media recv cb ──┘
   (src/veil_transport_shim.cc)          (veilclient-ffi, Phase 2, already linked)
```

## libwebrtc checkout

- Location (OUTSIDE the xVeil git repo): `~/Projects/veilnetwork/webrtc-checkout/src`
- Fetched via depot_tools (`fetch --nohooks webrtc` + `gclient sync`).
- Pin the branch once it lands (record the `src` commit here) so the API
  version is reproducible — the VERSION-SENSITIVE spots in the shim/engine are
  keyed to it.

## GN args (codec-stripped; from the Phase 0 spike)

The size win is CODEC selection, not ICE removal. Drop the AV1 encoder (libaom)
+ H264; keep Opus. Sizes (arm64, stripped): full ~22–30 MB → audio-only ~4–6 MB.

```
is_debug=false
symbol_level=0
is_component_build=false
rtc_include_tests=false
rtc_build_examples=false
rtc_build_tools=false
rtc_enable_protobuf=false
use_thin_lto=true
rtc_use_h264=false
enable_libaom=false
rtc_include_ilbc=false
rtc_include_opus=true          # keep Opus
# Phase 4 (video): keep VP8/VP9 (default), add dav1d AV1-DECODE only if wanted.
```

Per platform:
- **macOS arm64**: `target_os="mac" target_cpu="arm64"` → static `.a` or
  `WebRTC.xcframework`.
- **iOS arm64**: `target_os="ios" target_cpu="arm64"` (+ `ios_enable_code_signing=false`).
- **Android arm64**: `target_os="android" target_cpu="arm64"` → per-ABI `.so`/`.aar`.

Build: `gn gen out/mac-arm64 --args='...'` then
`ninja -C out/mac-arm64 webrtc` (or the specific media targets).

## Native build wiring (per platform, TODO once the lib lands)

- **macos/ios**: `veil_media.podspec` vendors the trimmed `WebRTC.xcframework`
  (or `.a` + headers) and compiles `src/veil_transport_shim.cc` +
  `src/veil_media_engine.cc` (as `.mm` if ObjC++ is needed for ADM/AVAudioSession).
  Link: WebRTC + the host's `veilclient_ffi` (already in the process → the
  `veil_media_*` symbols resolve; Dart binds via `DynamicLibrary.process()`).
- **android**: `android/build.gradle` + `CMakeLists.txt` builds the shim/engine
  into `libveil_media.so`, linking the per-ABI WebRTC `.so` and `libveilclient_ffi.so`.
  Screen capture (Phase 5) adds a Kotlin MediaProjection foreground service.

## Engine construction sequence (src/veil_media_engine.cc)

1. `webrtc::Environment env = webrtc::CreateEnvironment();`
2. Build `AudioState` (holds `AudioProcessing`/AEC3 + `AudioDeviceModule`) with
   builtin audio encoder/decoder factories (Opus).
3. `webrtc::Call::Config` with the env; `Call::Create(config)`.
4. Construct `VeilTransportShim(veil_chan, call, network_queue)` and `Start()`.
5. `AudioSendStream::Config`: rtp.ssrc, Opus `SendCodecSpec`, `send_transport =
   shim`, add `RtpExtension::kTransportSequenceNumberUri` (TWCC). Create via
   `call->CreateAudioSendStream(config)`.
6. `AudioReceiveStreamInterface::Config`: rtp.remote_ssrc/local_ssrc, Opus
   decoder map, `rtcp_send_transport = shim`. `call->CreateAudioReceiveStream(config)`.
7. `Start()` the streams; ADM starts mic capture + speaker playout.

## Congestion control

TWCC over the same channel: add `kTransportSequenceNumberUri` both directions;
route ALL RTCP through the shim (`rtcp_send_transport` → `SendRtcp`; inbound
RTCP → `DeliverRtcpPacket`); the shim already calls `Call::OnSentPacket` after
each send to close the send-side GCC loop. Real TWCC beats synthetic REMB on a
lossy path. Tune in Phase 3–4.

## VERSION-SENSITIVE spots (finalize against built headers)

- `webrtc::Transport::SendRtp/SendRtcp` param types (ArrayView vs `std::span`).
- `PacketReceiver::DeliverRtpPacket` arity (MediaType, RtpPacketReceived,
  undemuxable handler) and `DeliverRtcpPacket(CopyOnWriteBuffer)`.
- `rtc::SentPacket` / `Call::OnSentPacket` signature.
- `CreateEnvironment` / `AudioState` / stream-config builders churn across branches.

## Milestone (Phase 3 deliverable)

First real **anon↔anon audio call**: desktop ↔ phone, mic→Opus→veil→speaker
both ways, with AEC3/NetEQ, over the 2-hop onion media channel. Drive from
`CallService`: on `active`, open a `veil_media` channel to the peer (Phase 2
`openMediaChannel`) and `VeilMediaEngine.create(...).startAudio()`.

## Not built yet / deferred

- Video (Phase 4): VP8/VP9 + camera enumerate/select; add `MediaType::VIDEO`
  to the shim's inbound demux and a `VideoSendStream`/`VideoReceiveStream`.
- Screen (Phase 5): macOS ScreenCaptureKit / Android MediaProjection.
- SRTP: media rides the already-E2E-sealed onion channel, so relays never see
  plaintext; SRTP (keys from the call offer) is defense-in-depth, add later.

## Native diagnostics

Native media diagnostics are disabled by default, including file output from
release builds. For an explicit stand run, set `VEIL_MEDIA_DIAG_PATH` to a
writable file before launching the process, for example
`VEIL_MEDIA_DIAG_PATH=/tmp/veil_media_diag.log`. The transport's periodic RTP
sampling is also inactive when the variable is unset, so ordinary calls do not
pay its counter or file-I/O cost.
