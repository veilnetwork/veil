# Durable publication for a host-owned ratchet

The embedded node keeps ratchet state in memory. A host that persists snapshots
must also reserve exclusive sending positions **before** publishing ciphertext.
A host-side check alone is insufficient: IPC send commands can consume keys
later, concurrently, after several commands checked the same remaining slot.

The journaling host attaches with `veil_ratchet_host_begin` before application
traffic. This creates a process-local attachment epoch and clears old volatile
permissions. A store that has never attached retains its memory-only behavior;
calling this API is not a replacement for persistent storage.

For every live sending chain, the host commits an exclusive end position in its
own encrypted storage. Only after that commit, and the host's rollback-anchor
update attempt, does it call `veil_ratchet_host_allow`. The native store checks
the chain, position and attachment under the same lock that consumes the key.
Permissions cannot be used on a different chain and are bounded by the existing
recovery skip limit. Permissions themselves are never exported in snapshots.

When a fresh PQXDH exchange creates a new chain, its initial ciphertext stays
unpublished. The host observes bounded reservation demand through
`veil_ratchet_host_state`, reserves that new chain, and the original command
retries. The retained prologue allows the first published frame to skip the
initial unpublished index. Repeated blocked retries do not consume more keys.

The IPC handler waits locally for a floor, within its existing control deadline
or a bounded ordinary-send wait. Exhausted reservations, closed attachments and
superseded owners cannot cause a plaintext/stateless fallback. A local
`RATCHET_NOT_DURABLE` send error (13) leaves retry to the application. No floor,
application priority, media classification or attachment epoch is sent to a
relay; this change introduces no wire-format or mailbox behavior.

At shutdown the host ends its attachment before its final snapshot and joins
in-flight reservation writes before closing storage. An old epoch cannot close
or authorize a successor. The FFI reports a superseded epoch separately so an
old host binder can avoid snapshotting the successor's store into its own
container.

Recovery remains the host's responsibility: restore snapshots, burn through
all committed exclusive positions, and only then resume sends. Rollback of the
entire container still depends on the host's rollback-anchor policy. The
publication gate prevents concurrent consumption beyond a committed floor; it
does not by itself detect restoration of an old container.

Regression coverage includes a real cryptographic crash/rollback witness,
parallel send admission, fresh chains and retained prologues, DH rotation,
stale owners, floor bounds, direct/relay IPC waiting and FFI buffer validation.
