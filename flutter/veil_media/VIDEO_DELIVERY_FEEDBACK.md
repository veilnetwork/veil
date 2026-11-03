# Receiver video delivery feedback

The optional RTCP APP report is carried inside the existing authenticated,
encrypted endpoint media channel. It describes receiver progress, not relay
admission or network capacity. No relay role, priority or routing field changes.
Frame delivery means the native sink callback, not screen presentation.

Both versions occupy 64 bytes. Offsets below start at the RTCP header; integers
use network byte order.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | RTCP v2, APP/PT 204, subtype 0, length 15 |
| 4 | 4 | Sender SSRC; the authenticated channel identifies the peer |
| 8 | 4 | `VVD1` (`0x56564431`) or `VVD2` (`0x56564432`) |
| 12 | 4 | Target video SSRC |
| 16 | 8 | Receiver origin |
| 24 | 8 | Receiver monotonic sample time, microseconds |
| 32 | 8 | Received RTP payload bytes |
| 40 | 8 | Delivered frame count |
| 48 | 4 | Last delivered frame's RTP timestamp |
| 52 | 4 | WebRTC `current_delay_ms` |
| 56 | 4 | VVD1: zero; VVD2: WebRTC `target_delay_ms` |
| 60 | 4 | Zero, reserved |

VVD1 reserves the final eight bytes as zero. VVD2 carries a known timing target,
including a valid zero. An absent target is distinct from zero in the local
JSON snapshot. The sample collects current and target delay from the same
receive-stream stats call, for both direct and group endpoints.

Both delay fields must be in 0..60000 ms. Origin must be nonzero and no later
than the sample time; sample time, byte and frame counters cannot exceed
`INT64_MAX`. Incorrect size, subtype, reserved bytes or bounds invalidate the
report. A compound containing two delivery reports, including mixed versions,
is rejected before publishing observations from that compound.

The cursor checks the target SSRC, receiver origin and monotonic sample/counter
progress. Replays do not refresh the three-second local arrival lease. The
existing 950-ms extra-RR trigger and ordinary RTCP scheduling are unchanged;
ordinary compounds may repeat a sample without earning new progress credit.

Current and target delays are timing estimates, not a measured network queue
or acoustic latency. The host bounds target allowance by reported current
delay, keeps raw RTP-time history, and independently checks continued lag growth
and the `current_delay_ms` ceiling. A target alone never proves decoder progress.
Producer growth still requires a fresh causal frame ACK after the acknowledged
native budget change. Unknown targets retain the unqualified timing path.

Older receivers may ignore VVD2. The current parser accepts both versions, but
mixed-version performance is not qualified here. The public C ABI is unchanged;
applications need a rebuilt media engine to produce the new report.
