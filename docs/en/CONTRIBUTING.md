# Contributing

## Build

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Code Style

- No `unwrap()` on user-controlled or network data in production code (use `?` or `match`)
- `lock!(mutex)` macro instead of `.lock().unwrap()` for Mutex
- Key material types: `Debug` must redact secrets (see `crypto/types.rs`)
- New fields on `FrameDispatcher`: add to `make_test_dispatcher()` and `make_gossip_dispatcher()`

## Testing

- Unit tests: `#[cfg(test)] mod tests` in each module
- Integration tests: `node/runtime.rs` tests with real TCP
- Simulator tests: `sim/` module with `SimNetwork`
- PoW difficulty is 16 bits in `#[cfg(test)]` (fast, see `identity_policy.rs`)

## Commit Format

```
Short summary of the change

Longer description if needed: motivation, design choice, edge cases.

Co-Authored-By: ...
```

## Architecture Decisions

- **No async in dispatcher**: `dispatch()` is synchronous — returns `DispatchResult` immediately
- **Single-lock convention**: never hold two `Mutex` locks simultaneously
- **Forward compatibility**: unknown frame families → `NotHandled` (not `Violation`)
- **TLV extension**: new payload fields as optional TLV suffix (existing nodes ignore unknown tags)
