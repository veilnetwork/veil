//! Relay-directory entry encoding.
//!
//! Each anonymity-relay-capable node (— operator opted in
//! via `[anonymity].relay_capable = true`) periodically publishes a
//! signed [`RelayDirectoryEntry`] to a well-known DHT key. Senders
//! constructing onion circuits ([`super::circuit`] +
//! [`super::packet`]) query the directory to discover which peers
//! advertise `cap_flags::ANONYMITY_RELAY`, what X25519 pubkey to
//! encrypt for, and how much bandwidth they offer.
//!
//! # Why per-node DHT keys instead of one big directory blob
//!
//! A single "directory" record published by a directory-authority is
//! the Tor model. We deliberately don't replicate it — a directory
//! authority is a single point of takedown that an authoritarian
//! censor will target first. Instead, every relay self-publishes:
//!
//! ```text
//! relay_dht_key(node_id) = BLAKE3("veil:v1:anonymity-relay\0" || node_id)
//! ```
//!
//! Senders discover candidates from their own DHT routing table /
//! PEX, then `dht_get_local(relay_dht_key(candidate))` to fetch each
//! one's signed entry. Filtering happens at the sender side; no
//! central authority can revoke or censor a relay.
//!
//! # Wire format (binary, big-endian, fixed-prefix layout)
//!
//! ```text
//! [0..2] magic = "RD" (Relay-Directory)
//! [2] version = 1
//! [3] sig_algo u8 (0 = Ed25519, 1 = Falcon-512)
//! [4..36] node_id 32 B (BLAKE3 of identity pubkey)
//! [36..68] x25519_pk 32 B (anonymity hop key — distinct
//! from the OVL1 session ECDH key)
//! [68..72] advertised_bps u32 BE (relay's claimed forwarding
//! capacity; sender uses for
//! load-balancing — UNVERIFIED
//! relay can lie)
//! [72..80] last_published_unix u64 BE (sender uses for freshness;
//! entries older than ~24h
//! should be skipped)
//! [80..82] issuer_pk_len u16 BE
//! [82..] issuer_pk (base64 of identity pubkey — same
//! encoding as `IdentityConfig.public_key`
//! lets verifier decode without the DHT
//! key context)
//! [..] sig_len u16 BE
//! [..] signature (raw bytes; length matches sig_algo)
//! ```
//!
//! ## Why issuer_pk is in-band even though node_id is too
//!
//! `node_id = BLAKE3(issuer_pk)`, so technically the verifier could
//! brute-force it from a list of candidate pubkeys. We ship
//! `issuer_pk` in-band so verification is a single sig-check, not a
//! lookup-then-verify. The 32-44 extra bytes are negligible.
//!
//! # Canonical signed message
//!
//! ```text
//! "veil-relay-directory:v1\0"
//! + node_id
//! + x25519_pk
//! + advertised_bps.to_be_bytes
//! + last_published_unix.to_be_bytes
//! ```
//!
//! Domain prefix prevents cross-protocol signature reuse (an
//! identity_proof or signed_invite signature can't be replayed as a
//! relay-directory entry). Including all metadata in the signed
//! message means an attacker who captures a directory entry cannot:
//! * Substitute a different `x25519_pk` (would let attacker decrypt
//!   onion traffic intended for the legitimate relay).
//! * Inflate `advertised_bps` (would skew sender's load-balancing).
//! * Backdate `last_published_unix` (would extend the entry past
//!   its natural freshness window).
//!
//! All four anti-tamper modes have negative tests.
//!
//! # What this module does NOT do
//!
//! * **No DHT publish/query plumbing.** This module ships the
//!   wire format + crypto. Periodic-publish from the maintenance
//!   loop and sender-side relay-discovery query are separate slices
//!   (next commits).
//! * **No bandwidth-claim verification.** The `advertised_bps`
//!   field is operator-self-reported; relays can lie. A future
//!   reputation slice can downweight relays that consistently
//!   fail to deliver their claimed bandwidth — out of scope here.
//! * **No revocation.** Operators who want to stop being a relay
//!   just stop publishing; their entry naturally expires from the
//!   DHT after the value-store TTL.

use veil_crypto::{sign_message, verify_message};
use veil_types::SignatureAlgorithm;

const MAGIC: &[u8; 2] = b"RD";
const VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"veil-relay-directory:v1\0";
const NODE_ID_LEN: usize = 32;
const X25519_PK_LEN: usize = 32;

/// Maximum allowed wire size of a directory entry — bounds memory
/// for an attacker-published record. Generous enough for Falcon-512
/// (~660 B sig + ~900 B pubkey) plus envelope overhead.
pub const MAX_DIRECTORY_ENTRY_BYTES: usize = 4 * 1024;

/// Soft freshness ceiling — entries older than this should be
/// skipped by senders. 24 h is generous: a relay that's been
/// offline for a day might still come back, but using a stale
/// entry just wastes the sender's circuit-build attempt. Senders
/// can override per-deployment.
pub const DEFAULT_FRESHNESS_WINDOW_SECS: u64 = 24 * 3600;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DirectoryError {
    #[error("sign: {0}")]
    Sign(String),
    #[error("signature verification failed (wrong key, tampered fields, or wrong algo)")]
    Verify,
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported sig algo byte: {0}")]
    BadSigAlgo(u8),
    #[error("entry exceeds {MAX_DIRECTORY_ENTRY_BYTES} byte cap (got {got})")]
    TooLarge { got: usize },
    #[error("entry stale: now={now} > last_published+{window}={cutoff}")]
    Stale { now: u64, cutoff: u64, window: u64 },
}

/// Decoded relay-directory entry. Construct [`sign_entry`]
/// transmit as bytes via DHT publish, decode at the receiver via
/// [`decode_entry`], verify [`verify_entry`], optionally check
/// freshness [`is_fresh`].
#[derive(Debug, Clone, PartialEq)]
pub struct RelayDirectoryEntry {
    pub node_id: [u8; NODE_ID_LEN],
    pub x25519_pk: [u8; X25519_PK_LEN],
    pub advertised_bps: u32,
    pub last_published_unix: u64,
    pub issuer_pk: String, // base64 of identity pubkey
    pub issuer_algo: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

/// Derive the DHT key under which `node_id`'s relay-directory entry
/// is published. Domain-separated from other DHT-key derivations
/// in the codebase so a relay-directory query can't accidentally
/// hit (e.g.) a bootstrap-bundle slot.
pub fn relay_directory_dht_key(node_id: &[u8; NODE_ID_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil:v1:anonymity-relay\0");
    h.update(node_id);
    *h.finalize().as_bytes()
}

/// Build, sign, and encode a relay-directory entry. `issuer_pk` and
/// `issuer_sk` are base64-encoded as in `IdentityConfig`; `node_id`
/// is the BLAKE3 of the binary issuer pubkey (caller is responsible
/// for the consistency).
pub fn sign_entry(
    node_id: [u8; NODE_ID_LEN],
    x25519_pk: [u8; X25519_PK_LEN],
    advertised_bps: u32,
    last_published_unix: u64,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
) -> Result<Vec<u8>, DirectoryError> {
    let canonical = canonical_message(&node_id, &x25519_pk, advertised_bps, last_published_unix);
    let signature = sign_message(issuer_algo, issuer_pk, issuer_sk, &canonical)
        .map_err(|e| DirectoryError::Sign(format!("{e}")))?;
    let bytes = encode_body(
        &node_id,
        &x25519_pk,
        advertised_bps,
        last_published_unix,
        issuer_pk.as_bytes(),
        issuer_algo,
        &signature,
    )?;
    if bytes.len() > MAX_DIRECTORY_ENTRY_BYTES {
        return Err(DirectoryError::TooLarge { got: bytes.len() });
    }
    Ok(bytes)
}

/// Decode bytes from DHT into a [`RelayDirectoryEntry`]. Does NOT
/// verify the signature; callers MUST chain [`verify_entry`] before
/// trusting any field. Decoding-without-verifying is exposed
/// separately so a debug tool can pretty-print "what does this
/// entry claim" before deciding to trust it.
pub fn decode_entry(blob: &[u8]) -> Result<RelayDirectoryEntry, DirectoryError> {
    if blob.len() > MAX_DIRECTORY_ENTRY_BYTES {
        return Err(DirectoryError::TooLarge { got: blob.len() });
    }
    let mut p = 0usize;
    let magic = read(blob, &mut p, 2)?;
    if magic != MAGIC {
        return Err(DirectoryError::Malformed(format!("bad magic: {magic:?}")));
    }
    let version = read(blob, &mut p, 1)?[0];
    if version != VERSION {
        return Err(DirectoryError::Malformed(format!(
            "unsupported version {version}",
        )));
    }
    let sig_algo_byte = read(blob, &mut p, 1)?[0];
    let issuer_algo = match sig_algo_byte {
        0 => SignatureAlgorithm::Ed25519,
        1 => SignatureAlgorithm::Falcon512,
        2 => SignatureAlgorithm::Ed25519Falcon512Hybrid,
        3 => SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        b => return Err(DirectoryError::BadSigAlgo(b)),
    };
    let mut node_id = [0u8; NODE_ID_LEN];
    node_id.copy_from_slice(read(blob, &mut p, NODE_ID_LEN)?);
    let mut x25519_pk = [0u8; X25519_PK_LEN];
    x25519_pk.copy_from_slice(read(blob, &mut p, X25519_PK_LEN)?);
    // SAFETY — `read` returns slice of exactly N bytes
    // when Ok, so `try_into::<[u8; N]>` is provably-infallible. The
    // prior absence of a SAFETY comment was the lone audit complaint;
    // semantics were already correct.
    let advertised_bps =
        u32::from_be_bytes(read(blob, &mut p, 4)?.try_into().expect("4-byte slice"));
    let last_published_unix =
        u64::from_be_bytes(read(blob, &mut p, 8)?.try_into().expect("8-byte slice"));
    let pk_len =
        u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().expect("2-byte slice")) as usize;
    let issuer_pk_bytes = read(blob, &mut p, pk_len)?;
    let issuer_pk = std::str::from_utf8(issuer_pk_bytes)
        .map_err(|e| DirectoryError::Malformed(format!("issuer_pk utf8: {e}")))?
        .to_owned();
    let sig_len =
        u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().expect("2-byte slice")) as usize;
    let signature = read(blob, &mut p, sig_len)?.to_vec();
    if p != blob.len() {
        return Err(DirectoryError::Malformed(format!(
            "{} trailing byte(s)",
            blob.len() - p,
        )));
    }
    Ok(RelayDirectoryEntry {
        node_id,
        x25519_pk,
        advertised_bps,
        last_published_unix,
        issuer_pk,
        issuer_algo,
        signature,
    })
}

/// Verify the signature on a decoded entry. Returns Ok when
/// the signature is valid; Err(Verify) when it's not. Caller is
/// responsible for additionally checking freshness [`is_fresh`]
/// (kept separate so a debug tool can validate signature on a
/// stale entry without freshness rejection).
pub fn verify_entry(entry: &RelayDirectoryEntry) -> Result<(), DirectoryError> {
    // Bind node_id to the issuer key: node_id MUST equal BLAKE3(issuer_pk).
    // Without this, an attacker holding ANY valid identity key could sign an
    // entry naming a *victim's* node_id (with an attacker-chosen x25519_pk) and
    // the signature alone would pass — letting them occupy a victim's relay
    // slot. Enforcing the binding HERE (not only at the `discover_relay_hops`
    // caller, which matches node_id against the fetch key) keeps the invariant
    // intact for every caller, including any future network-wide directory
    // discovery. (audit: relay-pool poisoning / deanonymization.)
    let issuer_pk_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &entry.issuer_pk,
    )
    .map_err(|_| DirectoryError::Verify)?;
    if blake3::hash(&issuer_pk_bytes).as_bytes() != &entry.node_id {
        return Err(DirectoryError::Verify);
    }
    let canonical = canonical_message(
        &entry.node_id,
        &entry.x25519_pk,
        entry.advertised_bps,
        entry.last_published_unix,
    );
    verify_message(
        entry.issuer_algo,
        &entry.issuer_pk,
        &canonical,
        &entry.signature,
    )
    .map_err(|_| DirectoryError::Verify)
}

/// Check freshness against a wall-clock `now`. Returns Ok when
/// `now <= last_published + window`, Err(Stale) otherwise. `window`
/// defaults [`DEFAULT_FRESHNESS_WINDOW_SECS`] (24 h); senders
/// can pass a tighter value per-deployment (e.g. 1 h) to bias
/// toward more-recently-published relays at the cost of fewer
/// candidates.
pub fn is_fresh(
    entry: &RelayDirectoryEntry,
    now_unix: u64,
    window: u64,
) -> Result<(), DirectoryError> {
    let cutoff = entry.last_published_unix.saturating_add(window);
    if now_unix > cutoff {
        Err(DirectoryError::Stale {
            now: now_unix,
            cutoff,
            window,
        })
    } else {
        Ok(())
    }
}

/// A directory entry that survived all validation checks
/// (decoded, signature-verified, fresh) — ready to feed into
/// [`super::circuit::build_circuit`] / [`super::packet::build_anonymous_cell`]
/// as a hop.
///
/// Carries the bandwidth + last-seen timestamps alongside the
/// circuit-layer `Hop` so a downstream load-balancer / freshness-
/// preferer can sort candidates by something other than arrival
/// order.
#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveredRelay {
    pub hop: super::circuit::Hop,
    pub advertised_bps: u32,
    pub last_published_unix: u64,
}

/// Sender-side relay discovery: walk `candidate_node_ids`, fetch
/// each one's relay-directory entry via `fetch`, decode + verify +
/// freshness-check, return the surviving usable [`DiscoveredRelay`]s.
///
/// Designed around an injected `fetch` closure rather than a hard
/// dependency on `KademliaService` so this primitive can be:
/// * Unit-tested against an in-memory `HashMap` stub.
/// * Integrated at the runtime layer with the real
///   `dht.get_local(relay_directory_dht_key(node_id))`.
/// * Future: integrated against an iterative-find DHT lookup so
///   candidates can be discovered network-wide rather than only
///   from local routing-table-known peers.
///
/// Filters applied to each candidate (in order):
/// * `fetch` returned `Some(bytes)` — candidate has a published entry
/// * `decode_entry` succeeded — entry is well-formed
/// * `verify_entry` succeeded — signature checks out
/// * `is_fresh(entry, now, freshness_window)` succeeded — entry not stale
/// * Entry's `node_id` matches the candidate's node_id — not impersonating
///   a different relay (would otherwise let an attacker publish under
///   `node_id_A` an entry claiming to be `node_id_B`'s relay key)
///
/// Order of returned `DiscoveredRelay`s matches input order; caller
/// applies its own load-balancing / random-shuffle policy.
pub fn discover_relay_hops<F>(
    candidate_node_ids: &[[u8; NODE_ID_LEN]],
    fetch: F,
    now_unix: u64,
    freshness_window: u64,
) -> Vec<DiscoveredRelay>
where
    F: Fn(&[u8; NODE_ID_LEN]) -> Option<Vec<u8>>,
{
    candidate_node_ids
        .iter()
        .filter_map(|node_id| {
            let bytes = fetch(node_id)?;
            let entry = decode_entry(&bytes).ok()?;
            verify_entry(&entry).ok()?;
            is_fresh(&entry, now_unix, freshness_window).ok()?;
            // Anti-impersonation: the entry's claimed node_id must
            // match the candidate node_id under which we fetched it.
            // Without this check, an attacker could publish under
            // `relay_directory_dht_key(node_id_A)` an entry whose
            // body claims `node_id = node_id_B` — our caller would
            // think B's relay key is the attacker's x25519 pubkey.
            //
            // Note: the signature alone doesn't catch this — the
            // signature just proves "whoever holds this issuer_pk
            // signed this". An attacker who controls A's identity
            // could legitimately publish A's entry under A's DHT key
            // claiming any x25519_pk they like. But they cannot
            // publish under A's DHT key claiming to be B (because
            // B's signing key isn't theirs). This check enforces
            // the link.
            if entry.node_id != *node_id {
                return None;
            }
            Some(DiscoveredRelay {
                hop: super::circuit::Hop {
                    node_id: entry.node_id,
                    pubkey: entry.x25519_pk,
                },
                advertised_bps: entry.advertised_bps,
                last_published_unix: entry.last_published_unix,
            })
        })
        .collect()
}

fn canonical_message(
    node_id: &[u8; NODE_ID_LEN],
    x25519_pk: &[u8; X25519_PK_LEN],
    advertised_bps: u32,
    last_published_unix: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + NODE_ID_LEN + X25519_PK_LEN + 4 + 8);
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(node_id);
    out.extend_from_slice(x25519_pk);
    out.extend_from_slice(&advertised_bps.to_be_bytes());
    out.extend_from_slice(&last_published_unix.to_be_bytes());
    out
}

fn encode_body(
    node_id: &[u8; NODE_ID_LEN],
    x25519_pk: &[u8; X25519_PK_LEN],
    advertised_bps: u32,
    last_published_unix: u64,
    issuer_pk: &[u8],
    issuer_algo: SignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, DirectoryError> {
    if issuer_pk.len() > u16::MAX as usize {
        return Err(DirectoryError::Malformed("issuer_pk too long".into()));
    }
    if signature.len() > u16::MAX as usize {
        return Err(DirectoryError::Malformed("signature too long".into()));
    }
    let mut out = Vec::with_capacity(
        2 + 1 + 1 + NODE_ID_LEN + X25519_PK_LEN + 4 + 8 + 2 + issuer_pk.len() + 2 + signature.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(node_id);
    out.extend_from_slice(x25519_pk);
    out.extend_from_slice(&advertised_bps.to_be_bytes());
    out.extend_from_slice(&last_published_unix.to_be_bytes());
    out.extend_from_slice(&(issuer_pk.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

fn read<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], DirectoryError> {
    // checked_add — defends debug-build panic on 32-bit
    // wraparound when attacker-controlled `n` is huge.
    let end = pos
        .checked_add(n)
        .ok_or_else(|| DirectoryError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| DirectoryError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    fn fresh_relay() -> (String, String, [u8; NODE_ID_LEN], [u8; X25519_PK_LEN]) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        // node_id = BLAKE3(binary identity pubkey). We have base64 here
        // so decode + hash to match the codebase convention.
        let pk_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &kp.public_key)
                .unwrap();
        let mut node_id = [0u8; NODE_ID_LEN];
        node_id.copy_from_slice(blake3::hash(&pk_bytes).as_bytes());
        // X25519 pubkey is independent — generate a fresh one.
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk).to_bytes();
        (kp.public_key, kp.private_key, node_id, x25519_pk)
    }

    const T0: u64 = 1_700_000_000;
    const BPS: u32 = 1_000_000;

    #[test]
    fn epic482_4_sign_decode_verify_round_trip() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .expect("sign");
        let decoded = decode_entry(&bytes).expect("decode");
        verify_entry(&decoded).expect("verify");
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.x25519_pk, x25519_pk);
        assert_eq!(decoded.advertised_bps, BPS);
        assert_eq!(decoded.last_published_unix, T0);
        assert_eq!(decoded.issuer_pk, issuer_pk);
        assert_eq!(decoded.issuer_algo, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn epic482_4_relay_directory_dht_key_is_deterministic() {
        let n = [0xAAu8; NODE_ID_LEN];
        assert_eq!(
            relay_directory_dht_key(&n),
            relay_directory_dht_key(&n),
            "DHT key derivation must be deterministic"
        );
    }

    #[test]
    fn epic482_4_relay_directory_dht_key_distinct_per_node_id() {
        let mut a = [0u8; NODE_ID_LEN];
        let mut b = [0u8; NODE_ID_LEN];
        a[0] = 0x01;
        b[0] = 0x02;
        assert_ne!(
            relay_directory_dht_key(&a),
            relay_directory_dht_key(&b),
            "distinct node_ids must produce distinct DHT keys"
        );
    }

    // extraction: domain-separation cross-validation against
    // `bootstrap_bundle_dht_key` moved to
    // `veilcore/tests/dht_key_domain_separation.rs` because it requires
    // node::bootstrap which lives in veilcore.

    #[test]
    fn epic482_4_tampered_x25519_pk_fails_verify() {
        // Attacker substitutes their own X25519 pubkey while keeping the
        // legitimate node_id + signature → would let attacker decrypt
        // onion traffic intended for the real relay. Must fail verify.
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut entry = decode_entry(&bytes).unwrap();
        entry.x25519_pk[0] ^= 0x01;
        let err = verify_entry(&entry).unwrap_err();
        assert_eq!(
            err,
            DirectoryError::Verify,
            "tampered x25519_pk must fail signature verification"
        );
    }

    #[test]
    fn epic482_4_tampered_advertised_bps_fails_verify() {
        // Inflating bandwidth claim would skew sender's load-balancing.
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut entry = decode_entry(&bytes).unwrap();
        entry.advertised_bps = 100 * BPS;
        let err = verify_entry(&entry).unwrap_err();
        assert_eq!(err, DirectoryError::Verify);
    }

    #[test]
    fn epic482_4_tampered_last_published_fails_verify() {
        // Backdating last_published would extend the entry past its
        // natural freshness window.
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut entry = decode_entry(&bytes).unwrap();
        entry.last_published_unix = T0 + 30 * 24 * 3600; // forward-date 30 days
        let err = verify_entry(&entry).unwrap_err();
        assert_eq!(err, DirectoryError::Verify);
    }

    #[test]
    fn epic482_4_tampered_node_id_fails_verify() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut entry = decode_entry(&bytes).unwrap();
        entry.node_id[31] ^= 0x01;
        let err = verify_entry(&entry).unwrap_err();
        assert_eq!(err, DirectoryError::Verify);
    }

    #[test]
    fn epic482_4_tampered_signature_fails_verify() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut entry = decode_entry(&bytes).unwrap();
        entry.signature[0] ^= 0x01;
        let err = verify_entry(&entry).unwrap_err();
        assert_eq!(err, DirectoryError::Verify);
    }

    #[test]
    fn epic482_4_wrong_issuer_pk_fails_verify() {
        // Attacker captures a legitimate signed entry, then replaces
        // the embedded issuer_pk with their own pubkey but keeps the
        // original signature. Must fail because the captured
        // signature was created by the original issuer_sk, not the
        // attacker's sk.
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let (other_pk, _) = {
            let kp = generate_keypair(SignatureAlgorithm::Ed25519);
            (kp.public_key, kp.private_key)
        };
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut entry = decode_entry(&bytes).unwrap();
        entry.issuer_pk = other_pk;
        let err = verify_entry(&entry).unwrap_err();
        assert_eq!(err, DirectoryError::Verify);
    }

    #[test]
    fn epic482_4_freshness_check_accepts_within_window() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let entry = decode_entry(&bytes).unwrap();
        // 23 hours after publish — within default 24h window.
        is_fresh(&entry, T0 + 23 * 3600, DEFAULT_FRESHNESS_WINDOW_SECS).expect("within window");
    }

    #[test]
    fn epic482_4_freshness_check_rejects_stale_entry() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let entry = decode_entry(&bytes).unwrap();
        // 25 hours after publish — past default 24h window.
        let err = is_fresh(&entry, T0 + 25 * 3600, DEFAULT_FRESHNESS_WINDOW_SECS).unwrap_err();
        assert!(
            matches!(err, DirectoryError::Stale { .. }),
            "stale entry must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_4_freshness_window_is_configurable() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let entry = decode_entry(&bytes).unwrap();
        // With 1-hour window: 90 minutes after publish is stale.
        let err = is_fresh(&entry, T0 + 5400, 3600).unwrap_err();
        assert!(matches!(err, DirectoryError::Stale { .. }));
        // With 7-day window: 5 days after publish is fresh.
        is_fresh(&entry, T0 + 5 * 24 * 3600, 7 * 24 * 3600).expect("fresh under 7d window");
    }

    #[test]
    fn epic482_4_unsupported_version_rejected() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let mut bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        bytes[2] = 99; // version byte
        let err = decode_entry(&bytes).unwrap_err();
        assert!(
            matches!(err, DirectoryError::Malformed(_)),
            "unsupported version must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_4_bad_magic_rejected() {
        let mut bytes = vec![b'X', b'X']; // wrong magic
        bytes.extend_from_slice(&[1, 0]); // version + algo
        bytes.extend_from_slice(&[0u8; 100]); // padding
        let err = decode_entry(&bytes).unwrap_err();
        assert!(
            matches!(err, DirectoryError::Malformed(_)),
            "bad magic must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_4_truncated_bytes_rejected() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        let err = decode_entry(truncated).unwrap_err();
        assert!(
            matches!(err, DirectoryError::Malformed(_)),
            "truncated bytes must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic482_4_oversized_blob_rejected_pre_decode() {
        let bogus = vec![0u8; MAX_DIRECTORY_ENTRY_BYTES + 1];
        let err = decode_entry(&bogus).unwrap_err();
        assert!(
            matches!(err, DirectoryError::TooLarge { .. }),
            "oversized blob must be rejected pre-decode: {err:?}"
        );
    }

    #[test]
    fn epic482_4_typical_entry_well_under_4kib_cap() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        // Ed25519 entries should be ~ 200 bytes; cap is 4 KiB.
        assert!(
            bytes.len() < 512,
            "Ed25519 entry ballooned to {} bytes (cap 4 KiB; expected ~200)",
            bytes.len()
        );
    }

    // ── Sender-side discovery ─────────────

    use std::collections::HashMap;

    /// Test fixture: build a (node_id, signed_entry_bytes) pair for a
    /// freshly-generated relay so the discovery tests can populate
    /// their stub fetch maps.
    fn fixture_relay(t: u64) -> ([u8; NODE_ID_LEN], Vec<u8>) {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            t,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .expect("sign fixture");
        (node_id, bytes)
    }

    #[test]
    fn epic482_4_discover_empty_candidates_returns_empty() {
        let result = discover_relay_hops(&[], |_| None, T0 + 60, DEFAULT_FRESHNESS_WINDOW_SECS);
        assert!(result.is_empty());
    }

    #[test]
    fn epic482_4_discover_returns_valid_fresh_candidates() {
        let (n1, e1) = fixture_relay(T0);
        let (n2, e2) = fixture_relay(T0);
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(n1, e1);
        store.insert(n2, e2);

        let result = discover_relay_hops(
            &[n1, n2],
            |id| store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert_eq!(
            result.len(),
            2,
            "two fresh signed entries must both survive discovery"
        );
        assert_eq!(result[0].hop.node_id, n1);
        assert_eq!(result[1].hop.node_id, n2);
    }

    #[test]
    fn epic482_4_discover_skips_candidate_with_no_dht_entry() {
        // Candidate is in the routing table but never published a
        // directory entry — discovery quietly skips it.
        let (n_with, e) = fixture_relay(T0);
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(n_with, e);
        let n_without = [0xFFu8; NODE_ID_LEN]; // not in store

        let result = discover_relay_hops(
            &[n_with, n_without],
            |id| store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert_eq!(result.len(), 1, "only the candidate with an entry survives");
        assert_eq!(result[0].hop.node_id, n_with);
    }

    #[test]
    fn epic482_4_discover_skips_stale_candidate() {
        // Candidate has a valid entry but it's older than the
        // freshness window — discovery skips it.
        let (n_fresh, e_fresh) = fixture_relay(T0 + 100); // fresh
        let (n_stale, e_stale) = fixture_relay(T0); // stale
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(n_fresh, e_fresh);
        store.insert(n_stale, e_stale);

        // 150-second window, query at T0 + 200. Fresh entry is 100s
        // old (within), stale is 200s old (past).
        let result = discover_relay_hops(
            &[n_fresh, n_stale],
            |id| store.get(id).cloned(),
            T0 + 200,
            150,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].hop.node_id, n_fresh,
            "fresh candidate survives, stale gets filtered"
        );
    }

    #[test]
    fn epic482_4_discover_skips_tampered_entry() {
        // Candidate's published bytes have been tampered with (e.g.
        // attacker MITM'd the DHT response and flipped a bit).
        // Signature verify fails → discovery skips quietly, doesn't
        // poison the candidate set.
        let (n, mut bytes) = fixture_relay(T0);
        // Corrupt the signature region (last byte).
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(n, bytes);

        let result = discover_relay_hops(
            &[n],
            |id| store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert!(
            result.is_empty(),
            "tampered entry must be silently filtered out"
        );
    }

    #[test]
    fn epic482_4_discover_skips_node_id_mismatch_anti_impersonation() {
        // Attacker publishes A's signed entry under B's DHT key.
        // Because the entry's body still claims node_id == A
        // discovery (which looked up under B) detects the mismatch
        // and skips. Without this check, attacker could have B's
        // routing-table entry resolve to A's relay key — then any
        // sender picking B as a hop would actually encrypt for A
        // (whom the attacker controls).
        let (id_a, entry_for_a) = fixture_relay(T0);
        let id_b = [0xBBu8; NODE_ID_LEN];

        // The attacker mis-publishes A's entry under B's DHT key.
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(id_b, entry_for_a);

        let result = discover_relay_hops(
            &[id_b],
            |id| store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert!(
            result.is_empty(),
            "node_id mismatch must be filtered (anti-impersonation)"
        );
        // Sanity: A's own entry (under A's key) would have been valid.
        let mut sane_store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        sane_store.insert(id_a, store.remove(&id_b).unwrap());
        let sane_result = discover_relay_hops(
            &[id_a],
            |id| sane_store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert_eq!(
            sane_result.len(),
            1,
            "same entry under correct DHT key must be accepted"
        );
    }

    #[test]
    fn epic482_4_discover_mixed_candidates_returns_only_usable() {
        // Realistic mix: one valid+fresh, one missing, one stale
        // one tampered, one node-id-mismatch. Result: only the
        // first survives.
        let (id_good, entry_good) = fixture_relay(T0 + 100);
        let id_missing = [0xAAu8; NODE_ID_LEN];
        let (id_stale, entry_stale) = fixture_relay(T0);
        let (id_tampered, mut entry_tampered) = fixture_relay(T0 + 100);
        let last = entry_tampered.len() - 1;
        entry_tampered[last] ^= 0x01;
        let (id_real, entry_real) = fixture_relay(T0 + 100);
        let id_fake = [0xCCu8; NODE_ID_LEN];

        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(id_good, entry_good);
        store.insert(id_stale, entry_stale);
        store.insert(id_tampered, entry_tampered);
        store.insert(id_fake, entry_real); // mis-published under wrong DHT key
        // id_missing intentionally not in store
        let _ = id_real; // only used to build the entry, not the candidate list

        let result = discover_relay_hops(
            &[id_good, id_missing, id_stale, id_tampered, id_fake],
            |id| store.get(id).cloned(),
            T0 + 200,
            150,
        );
        assert_eq!(
            result.len(),
            1,
            "only the valid+fresh candidate should survive; got {} entries",
            result.len()
        );
        assert_eq!(result[0].hop.node_id, id_good);
        // Sanity: the surviving entry carries its bandwidth + timestamp.
        assert_eq!(result[0].advertised_bps, BPS);
        assert_eq!(result[0].last_published_unix, T0 + 100);
    }

    #[test]
    fn epic482_4_discover_preserves_candidate_input_order() {
        let (n1, e1) = fixture_relay(T0);
        let (n2, e2) = fixture_relay(T0);
        let (n3, e3) = fixture_relay(T0);
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(n1, e1);
        store.insert(n2, e2);
        store.insert(n3, e3);

        let order = [n3, n1, n2];
        let result = discover_relay_hops(
            &order,
            |id| store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].hop.node_id, n3);
        assert_eq!(result[1].hop.node_id, n1);
        assert_eq!(result[2].hop.node_id, n2);
    }

    /// End-to-end integration: round-trip through publish (sign_entry)
    /// then discovery (discover_relay_hops) — ensures the publish +
    /// discovery wiring stays consistent. If either side's wire
    /// format drifts, this test trips before the failure reaches a
    /// real DHT.
    #[test]
    fn epic482_4_discover_round_trip_with_publish_helper() {
        let (issuer_pk, issuer_sk, node_id, x25519_pk) = fresh_relay();
        let entry_bytes = sign_entry(
            node_id,
            x25519_pk,
            BPS,
            T0,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut store: HashMap<[u8; NODE_ID_LEN], Vec<u8>> = HashMap::new();
        store.insert(node_id, entry_bytes);

        let result = discover_relay_hops(
            &[node_id],
            |id| store.get(id).cloned(),
            T0 + 60,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hop.node_id, node_id);
        assert_eq!(
            result[0].hop.pubkey, x25519_pk,
            "round-trip x25519_pk must equal what publish signed"
        );
    }
}
