# Wire-format kill-switch — design doc

Anti-censorship strategy P2 #6 — proactive resilience against a DPI adversary that surfaces an OVL1-specific fingerprint. (DPI is deep packet inspection: a censor's box that examines packet contents to identify a protocol.)

**Status: Phase 1 + Phase 2 shipped (2026-05-21).** Rotating a variant from V1 to V2 takes 30-60 minutes, from trigger to completion, via [`ansible/rotate-obfs4-variant.yml`](../../ansible/rotate-obfs4-variant.yml).

## Problem

We have layered DPI defences — obfs4 AEAD framing, tls-boring Chrome ClientHello, QUIC Chrome transport params, padding regression testing. Even so, an adversary determined enough to target OVL1 specifically could publish a fingerprint that matches our exact obfs4 variant. The likely vectors:

* **Length-distribution fingerprint** of the obfs4 padding — our current constants leak a small but measurable statistical signal compared to reference Tor obfs4 deployments, because of a different `MAX_PADDING` value.
* **Initial handshake byte-pattern fingerprint** — the elligator2 representative bytes have a specific Curve25519-affine structure that a pattern-matcher can detect.
* **Timing signature** of the handshake retransmission pattern.

Today these are individual, hard-to-spot weaknesses. Tomorrow they could be cataloged in a DPI signature database. When that happens, we need a **rotation mechanism** that:

* Doesn't require a binary rebuild and a global redeployment cycle.
* Lets the operator ship a new obfs4 variant without breaking existing client deployments.
* Supports staged migration — the server advertises both the old and new variants for a grace period.

## Architecture (this slice — Phase 1, "landing-pad")

The Phase 1 commit ships the **variant-registry surface** without changing any wire bytes:

* A new module, [`crates/veil-obfs4/src/wire_variant.rs`], holds the `WireFormatVariant` enum. There is currently one variant: `V1`.
* `WireFormatVariant::hkdf_auth_key_info()` and `auth_mac_context()` return the per-variant domain-separation labels. V1's labels match the legacy `b"obfs4-auth-key-v1"` / `b"obfs4-auth-v1:"` constants bit-for-bit, pinned by the anchor test [`v1_labels_match_legacy_constants`].
* `ntor.rs` now pulls its constants from the variant enum via a `const fn`, at no runtime cost.
* `WireFormatVariant::from_config_str(...)` parses operator config strings (`"v1"`, `"obfs4-v1"`, and so on).
* The enum is `#[non_exhaustive]`, so any caller that matches on it must include a `_` arm. That way, adding `V2` later doesn't force a downstream rebuild.

Total scope: ~150 LoC, 6 unit tests, and this doc. Zero behaviour change in production.

## Phase 2 — shipped 2026-05-21

The activation drill is below. The Phase 2 plumbing **landed without a real V2 trigger**, because the operator decided a block would take a couple of hours and the code had to be pre-shipped. Adding a **fresh** V2-style variant (say V3) follows the same pattern documented in Step 1.

Code shipped:
* `WireFormatVariant::V2` in `crates/veil-obfs4/src/wire_variant.rs`: distinct domain-separation labels (`obfs4-auth-key-v2`, `obfs4-auth-v2:`, first-frame MAC tag `obfs4-v2:`) and a tighter padding bound (0..=96 vs V1's 0..=128).
* `ClientHandshake::start_variant(...)` and `ServerHandshake::accept_full_multi(...)` — a variant-aware handshake API.
* `obfs4_client_connect_variant(...)` and `obfs4_server_accept_multi(...)` — stream-layer wrappers.
* `TransportContext.obfs4_accept_variants: Vec<WireFormatVariant>` and `obfs4_client_variant: WireFormatVariant` — wired through the `[transport] obfs4_accept_variants = ["v2", "v1"]` and `obfs4_client_variant = "v2"` config schema.
* 14 ntor tests (V1 roundtrip, V2 roundtrip, V1↔V2 silent-drop, multi-accept routing, and length-distribution distinguishability).
* [`ansible/rotate-obfs4-variant.yml`](../../ansible/rotate-obfs4-variant.yml) — a 5-stage rotation playbook (dual-accept → client-V2 → V2-only → rollback path).

### Operator activation playbook (real-world drill)

### Step 1: define V2 constants

Add to `wire_variant.rs`:

```rust
pub enum WireFormatVariant {
    V1,
    V2,  // ← new
}

impl WireFormatVariant {
    pub const fn hkdf_auth_key_info(&self) -> &'static [u8] {
        match self {
            Self::V1 => b"obfs4-auth-key-v1",
            Self::V2 => b"obfs4-auth-key-v2",
        }
    }
    // … same for auth_mac_context, name, etc.
}
```

V2 should also use **different padding constants** in `ntor.rs` (for example, `MAX_HANDSHAKE_PADDING_V2 = 96` vs V1's 128), so the length-distribution fingerprints diverge.

### Step 2: server multi-variant accept

A listener-side change in `crates/veil-transport/src/obfs4_tcp.rs`:

```rust
// Today (Phase 1):
let variant = WireFormatVariant::V1;  // hard-coded

// Phase 2:
let accepted_variants = config.obfs4_accept_variants(); // e.g., [V2, V1]
let variant = detect_variant_from_client(&buf, &accepted_variants)?;
```

Variant detection happens in the handshake's first flight: try MAC verification against each variant's `auth_mac_context`, in the operator-configured priority order. A wrong variant means a silent drop — the same as a wrong PSK today, which preserves the anti-probe property.

### Step 3: client preferred-variant config

A client-side change in the connect path:

```rust
[transport]
obfs4_variant_preferred = "v2"    # try v2 first
obfs4_variant_fallback  = ["v1"]  # drop to v1 if v2 server doesn't respond
```

Implementation: connect with V2 first; if the server silently drops it (a ~5 s timeout), reconnect with V1. This state is per-connection, so a mixed-deployment cluster heals without operator intervention.

### Step 4: rotation playbook

```yaml
# ansible/playbook-rotate-wire-variant.yml
- name: Rotate to obfs4 V2 across testnet
  hosts: all
  serial: 1
  tasks:
    - name: Stage V2 binary
      ansible.builtin.copy:
        src: target/release/veil-cli-v2
        dest: /usr/local/bin/veil-cli.new
    - name: Configure dual-variant accept
      ansible.builtin.lineinfile:
        path: /var/lib/veil/node.toml
        line: 'obfs4_accept_variants = ["v2", "v1"]'
    - name: Atomic swap + restart
      ansible.builtin.shell: |
        mv /usr/local/bin/veil-cli.new /usr/local/bin/veil-cli
        systemctl restart veil
    - name: Wait healthy
      # … same as deploy-binary-only.yml
```

The operator runs this one host at a time (`serial: 1`). The mixed-version cluster heals automatically via the client variant-fallback. Once **all** hosts are V2-capable:

```yaml
- name: Drop V1 accept (final stage)
  hosts: all
  serial: 1
  tasks:
    - name: V2-only accept
      ansible.builtin.lineinfile:
        path: /var/lib/veil/node.toml
        regexp: '^obfs4_accept_variants\s*='
        line: 'obfs4_accept_variants = ["v2"]'
```

## Phase 3 — future variants

Beyond V2:

* **V3 — pluggable transport adapters**: each variant can declare an adapter that substitutes a completely different wire shape (for example, HTTP/3 mimicry). The adapter trait lives in `crates/veil-transport/src/lib.rs`, with a new crate per variant.
* **V4 — runtime-loadable variants**: variants distributed as signed plug-in binaries. The operator pulls a new `.tar.gz` from a private S3 bucket, and the daemon hot-loads it on SIGHUP. This rotates the wire shape with no binary redeploy.

Both are major epics in their own right, and both are out of scope for the kill-switch slice.

## Triggers (when to activate Phase 2)

Open the new epic and start Phase 2 when ANY of these holds:

1. **Published DPI signature.** A security researcher, or a regulator-aligned vendor, publishes a pattern that specifically matches OVL1's obfs4 byte distribution.
2. **Production observation.** Per-host metrics show a statistically significant dip in connection-success rate tied to specific ASes or countries, which suggests fingerprint-based blocking.
3. **Operator threat-model upgrade.** A new deployment lands in a jurisdiction known to run a custom DPI-fingerprint database (Iran's PFM, Russia's TSPU, and the like).

Until one of these fires, **don't ship Phase 2 preemptively.** A second variant doubles the wire-format surface area, and the mixed-version handshake state grows the test matrix. Phase 1's landing pad strikes the right balance between "ready when needed" and "premature optimization."

## How this composes with other anti-censorship layers

| Layer | Closes | Status |
|---|---|---|
| obfs4 AEAD framing | #1, #20 (partial) | ✅ shipped (Phase 1b/c 2025) |
| tls-boring ClientHello | #2, #3, #5, #13 (partial) | ✅ shipped (Epic 488) |
| QUIC Chrome transport params | #19 | ✅ shipped (P1 #4, 2026-05-20) |
| Webtunnel + Let's Encrypt | #15 | ✅ shipped (P1 #3, 2026-05-20) |
| DoT/DoH bootstrap | #9, #10, #11, #12 | ✅ shipped (P0 #2, 2026-05-20) |
| PoW-Gated Rendezvous | #4, #6, #16, #17 | ✅ shipped (PoW-Rendezvous epic, 2026-05-20) |
| n-gram regression testing | validation of #33 | ✅ shipped (P2 #5, 2026-05-20) |
| **Wire-format kill-switch** | proactive #20 | 🧊 Phase 1 landing-pad shipped (P2 #6, 2026-05-20); Phase 2 activates when a trigger fires |

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) for the full DPI threat model and roadmap.
