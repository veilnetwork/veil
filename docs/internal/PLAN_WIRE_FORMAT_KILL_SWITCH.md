# Wire-format kill-switch — design doc

Anti-censorship strategy P2 #6 — proactive resilience against а DPI adversary що surfaces an OVL1-specific fingerprint.

**Status: Phase 1 + Phase 2 shipped (2026-05-21).**  Variant rotation от V1 к V2 takes 30-60 minutes от trigger к completion via [`ansible/rotate-obfs4-variant.yml`](../../ansible/rotate-obfs4-variant.yml).

## Problem

Despite layered DPI defences (obfs4 AEAD framing, tls-boring Chrome ClientHello, QUIC Chrome transport params, padding regression testing), а sufficiently determined adversary targeting OVL1 specifically может publish а targeted fingerprint что matches our exact obfs4 variant.  Possible vectors:

* **Length-distribution fingerprint** of obfs4 padding — current constants leak а small but measurable statistical signal vs reference Tor obfs4 deployments (different `MAX_PADDING` value).
* **Initial handshake byte-pattern fingerprint** — elligator2 representative bytes have а specific Curve25519-affine structure that pattern-matchers can detect.
* **Timing signature** of the handshake retransmission pattern.

Today these are individual hard-to-spot weaknesses; tomorrow they could be cataloged in а DPI signature database.  When that happens, we need а **rotation mechanism** что:

* Doesn't require а binary rebuild + global redeployment cycle.
* Allows the operator к ship а new obfs4 variant без breaking existing client deployments.
* Supports staged migration (server advertises both old + new for а grace period).

## Architecture (this slice — Phase 1, "landing-pad")

The Phase 1 commit ships the **variant-registry surface** без changing wire bytes:

* New module [`crates/veil-obfs4/src/wire_variant.rs`] с the `WireFormatVariant` enum.  Currently one variant: `V1`.
* `WireFormatVariant::hkdf_auth_key_info()` + `auth_mac_context()` return the per-variant domain-separation labels.  V1's labels match the legacy `b"obfs4-auth-key-v1"` / `b"obfs4-auth-v1:"` constants bit-for-bit — pinned by anchor test [`v1_labels_match_legacy_constants`].
* `ntor.rs` switched к pull constants от the variant enum via `const fn` (no runtime cost).
* `WireFormatVariant::from_config_str(...)` parses operator config strings (`"v1"`, `"obfs4-v1"`, etc.).
* `#[non_exhaustive]` on the enum — callers что match must include а `_` arm, so adding `V2` doesn't force downstream rebuild.

Total scope: ~150 LoC + 6 unit tests + this doc.  Zero behaviour change in production.

## Phase 2 — shipped 2026-05-21

Activation drill below.  Phase 2 plumbing **landed без а real V2-trigger** because operator decision was «блокировка займет пару часов, code must be pre-shipped».  Adding а **fresh** V2 variant (say V3) follows the same pattern documented в Step 1.

Code shipped:
* `WireFormatVariant::V2` в `crates/veil-obfs4/src/wire_variant.rs`: distinct domain-separation labels (`obfs4-auth-key-v2`, `obfs4-auth-v2:`, first-frame MAC tag `obfs4-v2:`), tighter padding bound (0..=96 vs V1's 0..=128).
* `ClientHandshake::start_variant(...)` + `ServerHandshake::accept_full_multi(...)` — variant-aware handshake API.
* `obfs4_client_connect_variant(...)` + `obfs4_server_accept_multi(...)` — stream-layer wrappers.
* `TransportContext.obfs4_accept_variants: Vec<WireFormatVariant>` + `obfs4_client_variant: WireFormatVariant` — wired through `[transport] obfs4_accept_variants = ["v2", "v1"]` и `obfs4_client_variant = "v2"` config schema.
* 14 ntor tests (V1 roundtrip + V2 roundtrip + V1↔V2 silent-drop + multi-accept routing + length-distribution distinguishability).
* [`ansible/rotate-obfs4-variant.yml`](../../ansible/rotate-obfs4-variant.yml) — 5-stage rotation playbook (dual-accept → client-V2 → V2-only → rollback path).

### Operator activation playbook (real-world drill)

### Step 1: define V2 constants

Add к `wire_variant.rs`:

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
    // … same для auth_mac_context, name, etc.
}
```

V2 should also have **different padding constants** в `ntor.rs` (e.g., `MAX_HANDSHAKE_PADDING_V2 = 96` vs V1's 128) so length-distribution fingerprints diverge.

### Step 2: server multi-variant accept

Listener-side change в `crates/veil-transport/src/obfs4_tcp.rs`:

```rust
// Today (Phase 1):
let variant = WireFormatVariant::V1;  // hard-coded

// Phase 2:
let accepted_variants = config.obfs4_accept_variants(); // e.g., [V2, V1]
let variant = detect_variant_от_client(&buf, &accepted_variants)?;
```

Variant detection в the handshake's first-flight: try MAC verification against each variant's `auth_mac_context` в the operator-configured priority order.  Wrong variant ⇒ silent drop (same as wrong PSK today — preserves anti-probe property).

### Step 3: client preferred-variant config

Client-side change в the connect path:

```rust
[transport]
obfs4_variant_preferred = "v2"    # try v2 first
obfs4_variant_fallback  = ["v1"]  # drop к v1 if v2 server doesn't respond
```

Implementation: connect с V2 first; if server silent-drops (timeout ~5 s), reconnect с V1.  Per-connection state, so а mixed-deployment cluster heals without operator intervention.

### Step 4: rotation playbook

```yaml
# ansible/playbook-rotate-wire-variant.yml
- name: Rotate к obfs4 V2 across testnet
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

Operator runs this в one host at а time (`serial: 1`).  Mixed-version cluster heals автоматически via client variant-fallback.  Once **all** hosts are V2-capable:

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

* **V3 — pluggable transport adapters**: each variant can declare an adapter что substitutes а completely different wire shape (e.g., HTTP/3 mimicry).  Adapter trait в `crates/veil-transport/src/lib.rs`; new crate per variant.
* **V4 — runtime-loadable variants**: variants distributed as signed plug-in binaries (operator pulls а new `.tar.gz` от а private S3 bucket, daemon hot-loads it на SIGHUP).  Wire shape rotation без binary redeploy.

Both are major epics in their own right — out of scope for the kill-switch slice.

## Triggers (when к activate Phase 2)

Open the new epic and start Phase 2 when ANY of:

1. **Published DPI signature**: а security researcher или а regulator-aligned vendor publishes а pattern that specifically matches OVL1's obfs4 byte distribution.
2. **Production observation**: per-host metrics show а statistically significant connection-success-rate dip correlated с specific ASes / countries — suggesting fingerprint-based blocking.
3. **Operator threat-model upgrade**: new deployment в а jurisdiction known к operate а custom DPI-fingerprint database (Iran's PFM, Russia's TSPU, etc.).

Until one of these fires, **don't preemptively ship Phase 2** — adding а second variant doubles the wire-format surface area, и mixed-version handshake state увеличит the test matrix.  Phase 1's landing pad is the right balance of "ready when needed" vs "premature optimization."

## Composition с other anti-censorship layers

| Layer | Closes | Status |
|---|---|---|
| obfs4 AEAD framing | #1, #20 (partial) | ✅ shipped (Phase 1b/c 2025) |
| tls-boring ClientHello | #2, #3, #5, #13 (partial) | ✅ shipped (Epic 488) |
| QUIC Chrome transport params | #19 | ✅ shipped (P1 #4, 2026-05-20) |
| Webtunnel + Let's Encrypt | #15 | ✅ shipped (P1 #3, 2026-05-20) |
| DoT/DoH bootstrap | #9, #10, #11, #12 | ✅ shipped (P0 #2, 2026-05-20) |
| PoW-Gated Rendezvous | #4, #6, #16, #17 | ✅ shipped (PoW-Rendezvous epic, 2026-05-20) |
| n-gram regression testing | validation of #33 | ✅ shipped (P2 #5, 2026-05-20) |
| **Wire-format kill-switch** | proactive #20 | 🧊 Phase 1 landing-pad shipped (P2 #6, 2026-05-20); Phase 2 activates когда trigger fires |

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) для the full DPI threat-model + roadmap.
