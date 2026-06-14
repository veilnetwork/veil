# Contributing

Glad you're here. This guide gets you from a fresh checkout to a clean pull
request. Nothing here assumes you've worked on Veil before — if a step looks
unfamiliar, that's on us to explain, so read on.

## Build

You'll need a recent Rust toolchain. These three commands compile the project,
run its tests, and lint the code:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

Run them before you open a pull request. If all three pass locally, you're in
good shape.

## Code Style

A few house rules keep the codebase safe and readable. None of them are hard
once you've seen them:

- Don't call `unwrap()` on user-controlled or network data in production code —
  it panics on bad input. Use `?` or `match` instead.
- Use the `lock!(mutex)` macro rather than `.lock().unwrap()` for a Mutex.
- Types that hold key material (secret keys and the like) must redact their
  secrets in `Debug` output, so a stray log line never leaks them. See
  `crypto/types.rs` for the pattern.
- Adding a new field to `FrameDispatcher`? Wire it into `make_test_dispatcher()`
  and `make_gossip_dispatcher()` too, or the tests won't build.

## Testing

We lean on tests at three levels. New code should come with whichever fits:

- **Unit tests** live in a `#[cfg(test)] mod tests` block inside each module.
- **Integration tests** sit in `node/runtime.rs` and talk over real TCP.
- **Simulator tests** live in the `sim/` module and run against `SimNetwork`, an
  in-memory stand-in for the network.

One handy detail: Proof of Work difficulty drops to 16 bits under
`#[cfg(test)]`, so the tests stay fast. See `identity_policy.rs`.

## Commit Format

Write a short summary line, then a blank line, then the details. Here's the
shape:

```
Short summary of the change

Longer description if needed: motivation, design choice, edge cases.

Co-Authored-By: ...
```

The summary says *what* changed. The body says *why* — the reasoning, the design
choice you made, any tricky edge cases. Future readers (including you) will thank
you.

## Architecture Decisions

These are deliberate choices, not accidents. Please keep to them — and if you
think one is wrong, open an issue so we can talk it through:

- **No async in the dispatcher.** The `dispatch()` function is synchronous: it
  returns a `DispatchResult` right away, no `await`.
- **One lock at a time.** Never hold two `Mutex` locks at once. It's the simplest
  way to rule out deadlocks.
- **Stay forward-compatible.** When a node meets a frame family it doesn't
  recognize, it returns `NotHandled` (a polite "not mine"), never `Violation`
  (an error). That way old nodes and new nodes get along.
- **Extend with TLV.** Add new payload fields as an optional TLV suffix — TLV
  meaning tag-length-value, a self-describing format where each field is labeled.
  Nodes that don't know a tag simply skip it.
