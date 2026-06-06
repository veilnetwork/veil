# Fingerprint regression testing

Anti-censorship strategy P2 #5 (Epic 488.2 carry-over) — closes the **validation** half of DPI method #33 (flow-cache state tracking + n-gram analysis). An n-gram here is a run of N consecutive bytes; counting how often each run appears gives a statistical fingerprint of the stream.

OVL1's on-the-wire work (obfs4 AEAD framing, tls-boring Chrome ClientHello, QUIC Chrome transport params) makes veil's bytes statistically indistinguishable от reference HTTPS/CDN traffic. The risk: without а regression suite, one feature addition — а new header field, а padding-pattern change, а protocol-version negotiation byte — could quietly break that property and nobody would notice.

The [`veil-fingerprint`](../../crates/veil-fingerprint/) crate ships the **analyzer engine** that guards against exactly that:

* **`NGramModel`** — counts byte n-grams (unigram / bigram / trigram / quadgram) и normalises к а probability distribution.
* **`kl_divergence`** + **`chi_squared`** — pairwise distance metrics.  Lower = "models look more alike".
* **`uniform_random_baseline`** — deterministic synthetic reference for "AEAD ciphertext should look like uniform random bytes".

## Quick start — assert veil ciphertext is random-shaped

```rust
use veil_fingerprint::{NGramModel, chi_squared, uniform_random_model};

// Capture а sample of veil traffic bytes (post-obfs4 framing).
// In а production regression test this would come от а fixture
// snapshot or а sim-network run.
let veil_bytes: Vec<u8> = capture_veil_ciphertext(/* … */);
let mut veil_model = NGramModel::new(1);
veil_model.observe(&veil_bytes);

// Compare к а uniform-random reference of similar size.
let reference = uniform_random_model(
    /*seed=*/ 0xDEADBEEF,
    veil_bytes.len(),
    /*n=*/ 1,
);
let chi = chi_squared(&veil_model, &reference);

// Empirical noise floor for 200 k unigram samples: chi² ≈ 0.002.
// А threshold of 0.01 trips well-above the noise floor while still
// being far below the "biased / random" regime (chi² > 0.3).
assert!(chi < 0.01, "wire-format regression: chi² = {chi}");
```

## Calibration table (empirical)

Run these once per ENV (CI machine + dev machine) before pinning thresholds.

| Setup | n-gram length | Sample size | Random/random chi² | Biased/random chi² |
|---|---|---|---|---|
| Unigram (256 buckets) | 1 | 100 k | ≈ 0.002 | ≥ 0.3 |
| Bigram (65 k buckets) | 2 | 100 k | ≈ 0.6 | ≥ 2.0 |
| Bigram (65 k buckets) | 2 | 1 M | ≈ 0.06 | ≥ 2.0 |
| Trigram (16 M buckets) | 3 | 1 M | ≈ 16 | ≥ 60 |

Rule of thumb: set the **threshold to 3× the random/random noise floor**. That trips on а real shift без firing on the natural seed-к-seed variance.

## What this crate does **not** ship (deliberately)

* **Real-world Tor / OpenVPN / WireGuard reference pcaps.** Held back over license and privacy concerns, и а meaningful comparison needs hand-curated fixtures от diverse clients. Future slice: ingest pcap-format files into the same `NGramModel` API.
* **Live capture against running veil nodes.** Out of scope for an in-process test crate. The operator-side capture procedure is below.
* **А static "Chrome HTTPS" reference fixture.** The `tls-boring` ClientHello fingerprint test уже covers ClientHello shape, and this crate stays deliberately domain-agnostic — point the same analyzer at any byte stream.

## Operator-side capture procedure (future fixtures)

When future slices want к compare veil traffic к real-world references:

```bash
# 1. Capture а 10-minute sample of veil traffic on one host.
ssh root@b1 'tcpdump -w /tmp/veil-sample.pcap -i any "port 5556 or port 8443" -G 600 -W 1 2>/dev/null &'

# 2. Capture matching reference traffic (your normal HTTPS browsing).
tcpdump -w /tmp/chrome-sample.pcap -i any "port 443" -G 600 -W 1

# 3. Extract application-layer bytes (post-TCP, post-TLS).
#    Use Wireshark's "follow-stream → raw" export, OR scapy + custom script,
#    OR `tshark -Y "tcp" -T fields -e tcp.payload`.

# 4. Hash-truncate samples к а fixed size (1 MB) для repeatable comparisons.
head -c 1048576 veil-sample.bytes > veil-1m.bin
head -c 1048576 chrome-sample.bytes > chrome-1m.bin

# 5. Run the analyzer.
cargo run --example fp-compare -- veil-1m.bin chrome-1m.bin
```

(The `fp-compare` example doesn't exist yet — Future-slice work: ship а CLI binary that takes two byte-files и prints chi²/KL divergence + а pass/fail indicator.)

## Composition с other anti-censorship layers

| Layer | What it does | Validation path |
|---|---|---|
| **obfs4 AEAD framing** | Wire bytes look random | `veil-fingerprint` chi² against uniform |
| **tls-boring ClientHello** | TLS handshake matches Chrome JA4 | Existing `epic480_6_chrome_client_hello_shape_regression` test |
| **QUIC Chrome transport params** | QUIC params match Chrome HTTP/3 | `chrome_mimic_constants_match_published_values` test |
| **PoW-Gated Rendezvous** | Listen surface invisible к scanners | Live testnet `enable-stealth-canary.yml` |
| **DoT/DoH bootstrap** | DNS resolution не on-path-readable | `dns::tests::all_pinned_upstreams_build_for_dot_and_doh` |
| **Webtunnel + Let's Encrypt** | TLS endpoint indistinguishable от small static site | `deploy-webtunnel-autotls.yml` post-deploy verification |

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) для the full DPI threat-model + roadmap.

## Re-open triggers

Re-open the (Epic 488.2 carry-over) row in TASKS.md if any of these happen:

* А new DPI tool publishes а fingerprinting model aimed at OVL1 specifically.
* Someone reviewing а wire-format change needs к verify "before / after" indistinguishability без relying on intuition.
* The operator-side capture procedure becomes routine и needs CLI automation.
