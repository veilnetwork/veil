# WebRTC audio adaptor factory

`controller_manager.cc` comes from WebRTC commit
`4ef980bc2c70834276c791e71e7834b8809f24ad`, path
`modules/audio_coding/audio_network_adaptor/controller_manager.cc`.
Unmodified source SHA-256: `8ed469936ff3abdd5318b9aa483c90c55a1f5cef9f6d1c107df327944c2eebf1`.

The only changes are the Veil config header include and a versioned-config
branch before the upstream protobuf parser. It constructs the existing
FrameLengthControllerV2 (24 kbit/s payload minimum, fast adaptation), followed by the
existing BitrateController (zero overhead offsets). The protected payload floor
also applies to the encoder after ANA callbacks: gross allocations for another
packet duration must not lower the current packet's useful signal. Fixed group
budgets keep their 16..32-kbit API; the group application policy already uses a
24-kbit floor. Supported durations and initial values come from Opus.
There is no new codec, allocation rule, packet format or relay metadata.

Compile this whole translation unit with the pinned SDK's flags and link it
before the normally extracted WebRTC archive. It supplies all symbols from
that archive member, so the upstream member is not extracted. Do not force
load the WebRTC archive or compile a second copy of this translation unit.
On iOS this object belongs in the force-loaded Veil archive, not WebRTC's.
The bundled SDK/header pin must stay aligned when updating this file.

LICENSE and PATENTS are retained from the same source tree.
