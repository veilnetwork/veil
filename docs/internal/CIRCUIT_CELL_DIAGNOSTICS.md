# Scoped circuit-cell investigation

This is private operator evidence for diagnosing a selected circuit, not an
anonymous user report. Do not publish the raw records or the policy file.
Normal builds cannot activate this facility: `veil-anonymity/circuit-trace` is
off by default. For an embedded investigation build select
`veilclient-ffi/circuit-trace`; for a relay select
`veil-dispatcher/circuit-trace`. Neither option changes wire framing, replay
rules, retransmission timers, flow control, carrier selection or priorities.

On Unix, start the controlled process with `VEIL_CIRCUIT_TRACE_FILE` naming a
private regular file in an operator-owned directory. The parser accepts only:

```text
key <fresh random 32-byte key in hex>
local
prefix <16-byte keyed prefix token in hex>
peer <32-byte adjacent transport peer in hex>
```

Use one fresh key for one investigation, shared securely between its nodes.
`local` belongs only on the controlled sending endpoint. Start relay policies
with the key and explicitly selected adjacent test peer; add only prefix
tokens observed on the controlled endpoint. A key alone selects nothing.
At most 16 prefixes and 16 adjacent peers may be selected. No wildcard exists.
Unix group/world-accessible files, symlinks, malformed files and files over
4096 bytes fail closed. Windows file activation is disabled: this module does
not implement ACL validation.

The policy refresh interval is one second, so removing a filter is not an
instant revocation of diagnostic observation. Editing/replacing a policy does
not renew the process's lease: ten minutes after the first enabled check or
32768 selected observations, whichever comes first, observation stops. Stop
the investigation and remove its policy/key files after collecting evidence.
The frame path remains synchronous in an enabled investigation, including the
bounded policy-file refresh and logging; do not compare its timing directly
with uninstrumented runs. File I/O and trace logging never hold the TX registry.

## Joining observations

The sender's `onion-stream-cell` record contains a keyed token of the opaque
post-cookie envelope, its keyed prefix token, the local stream DATA range (only
interpreted at the endpoint), and the local enqueue result. That result is not
a delivery receipt. Bulk scalar and batched sends use the same instrumented
envelope sender. Heartbeats/other paths outside that sender are not covered.

At a selected splice, `anonymity.circuit.trace.splice` binds the same opaque
token to its outgoing return-cell circuit ID and sequence. It does not decode
the envelope as a stream, message or media. The final hop's
`anonymity.circuit.trace.return` binds incoming circuit ID to outgoing circuit
ID with the same sequence. `anonymity.circuit.trace.egress` reports the exact
TX admission result (`Ok`, `Missing`, `Full`, `Closed`) on the selected adjacent
link, not socket completion or remote receipt. `local_us` covers this local
return handler from before the layer transform through enqueue, not transport
queue residence or network latency.

For a two-relay receive circuit, the join is:

```text
endpoint DATA range -> keyed opaque token
splice token -> return CID/sequence on splice-to-middle link
middle input CID/sequence -> output CID/sequence on middle-to-endpoint link
middle egress output CID/sequence -> exact admission result
```

Join by wire fields on known adjacent links and process lifetimes, not by
nearby wall timestamps or by equal sequence alone. Circuit IDs are link-local;
the same ID can be reused in a different process/lifetime. A longer receive
circuit requires an explicitly selected neighbor scope at every intervening
relay and a return mapping for each hop; a missing intermediate mapping is an
unresolved attribution, not proof of delivery or loss. Token equality links
bytes, not a unique retransmission attempt: retransmissions can repeat the same
opaque bytes under fresh outer sequences. Relay records never contain the
stream classification/range, payload, cookie, raw prefix, key or raw peer ID.
All records are intentionally excluded from anonymous diagnostic exports.

The isolated dispatcher test exercises both circuit transports with real
CircuitTables and SessionTxRegistry queues: one exact last-hop `Missing`, then
peer registration, rejection of an identical replayed outer cell, and successful
delivery of the same opaque bytes under a fresh outer sequence on the same
circuit. It proves the diagnostic join and these protocol behaviors. It does
not reproduce the user's network pause or establish its cause.
