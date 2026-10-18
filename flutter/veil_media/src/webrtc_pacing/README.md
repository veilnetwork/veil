# WebRTC pacing debt correction

This is the upstream `modules/pacing/pacing_controller.cc` translation unit,
with the WebRTC BSD license and patent grant retained alongside it. `abi.json`
records the original/patched source and matching private header hashes.

The local change bounds pre-existing media debt when the **adjusted** pacing
rate falls, including the end of a temporary queue-rate boost. Its bound is the
smaller of the existing queue-time limit and 500-ms maximum debt interval.
Queued packets, FIFO, payloads, bitrate estimates, flow control, and source byte
credits are preserved. The endpoint's independent audio Call stays unpaced.

The earlier change only in `SetPacerConfig` is rejected: a queued-frame case
regressed from 24 to 574 ms. The current change passes the real-pacer matrix,
including steady/increasing rates, pending data and audio. See xVeil's
`doc/validation/video-pacer-debt-2026-10-18` for retained counterexamples.

Native builders use the SDK's pacing compile command when present, or its
common call compile flags in reduced SDK bundles after the private ABI check.
They link the replacement object **before** `libwebrtc.a`. The original archive is
not edited; its old pacing object is not extracted. iOS puts the object in the
already force-loaded native archive. Public media exports are unchanged.
The private header hashes are checked before compiling; a different SDK must
be reviewed and qualified before changing these hashes or this translation unit.
