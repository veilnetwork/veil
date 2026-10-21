# Local Quinn extension

This copy retains the locked upstream release and its license files.
The adjacent quinn-proto and quinn-udp copies have the provenance recorded in
`UPSTREAM.json`. The manifest includes their registry archive SHA-256 digests.

The local patch set includes:

- opt-in outgoing DATAGRAM expiration deadlines;
- pacing fixes for small congestion windows, fractional credit and a
  controller's explicit pacing rate;
- local queue/expiry/receive diagnostics and opt-in kernel receive timestamps;
- opt-in Apple socket batching (`fast-apple-datapath`).

The wire format and TLS policy are unchanged. Pacing behavior is intentionally
patched; this is not a byte-identical upstream tree. Existing `send_datagram`
calls have no expiry deadline. Transit forwarding does not receive the
endpoint's expiration policy or an application/media priority label.

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
  -p quinn-proto --precise 0.11.18
cargo test --manifest-path third_party/quinn/Cargo.toml \
  --config 'patch.crates-io.quinn-proto.path="ABSOLUTE_PATH_TO/quinn-proto"' \
  --no-default-features --features runtime-tokio,rustls-aws-lc-rs --lib
```

Restore Quinn's upstream Cargo.lock after standalone checks; production uses
the root Cargo.lock with both path patches already selected.

Verify versions with `scripts/check-quinn-provenance.py`
before updating the manifest; compare the listed archive bytes before bumping a pin.
