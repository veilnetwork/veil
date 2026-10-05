# Local Quinn extension

This copy retains the locked upstream release and its license files.
The adjacent quinn-proto copy has the same provenance.

The only extension is an opt-in outgoing DATAGRAM expiration deadline.
No wire fields, advertised transport parameters, TLS policy, reliable stream
behavior or congestion-controller settings change. Existing send_datagram
calls have no deadline. The endpoint uses the extension only for its own
primary source on a prepared independent connection. Transit has no deadline.

Expired packets are removed on send-buffer queries and before packet creation.
They release outgoing capacity and unblock waiting producers. All fragments
of one application frame receive the same local monotonic deadline. The
extension bounds time in the local unsent queue, not propagation time, peer
queues, loss-probe recovery or end-to-end media quality.

When updating Quinn, compare these local changes against the locked registry
archive, preserve opt-in/default behavior, and rerun upstream protocol tests,
transport/session gates and the neutral loss characterization.

The local expiry counter is diagnostic only. It reports packets discarded
before transmission; it is separate from congestion losses and adds no wire
field. Preserve the original API's unbounded lifetime and exact FIFO handling
for packets without a deadline.

Standalone upstream tests use these commands from the Veil root (the workspace
patch applies to production builds, not to an excluded crate's own workspace):

```sh
cargo test --manifest-path third_party/quinn-proto/Cargo.toml --lib
cargo update --manifest-path third_party/quinn/Cargo.toml \
  --config 'patch.crates-io.quinn-proto.path="ABSOLUTE_PATH_TO/quinn-proto"' \
  -p quinn-proto --precise 0.11.15
cargo test --manifest-path third_party/quinn/Cargo.toml \
  --config 'patch.crates-io.quinn-proto.path="ABSOLUTE_PATH_TO/quinn-proto"' \
  --no-default-features --features runtime-tokio,rustls-aws-lc-rs --lib
```

Restore Quinn's upstream Cargo.lock after standalone checks; production uses
the root Cargo.lock with both path patches already selected.
