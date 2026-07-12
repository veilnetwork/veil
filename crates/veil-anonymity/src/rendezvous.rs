//! Rendezvous-point primitive.
//!
//! `RendezvousAd` is the **signed advertisement** a receiver publishes
//! to the DHT to announce "I can be reached via rendezvous node R
//! using auth cookie C, between unix-time T0 and T1, encrypt your
//! introduction frame to my X25519 key K".
//!
//! # Why rendezvous matters for censorship resistance
//!
//! Without rendezvous a receiver must be **directly reachable** by
//! the sender (or via a gateway). Under aggressive inbound-blocking
//! (CGN-NAT, censor blocking inbound TCP, mobile carrier firewall)
//! the receiver simply cannot accept inbound connections.
//!
//! Rendezvous flips the connectivity requirement: **both** sender and
//! receiver only need OUTBOUND connectivity. Both connect to a third
//! party (the rendezvous node) which relays the encrypted introduction
//! between them. Outbound connectivity is what HTTPS browsing needs
//! anyway — censors that block outbound HTTPS would cripple the
//! entire web.
//!
//! Architectural inspiration: Tor onion services. Tor uses similar
//! receiver-publishes-meeting-point pattern; we adopt the same
//! architecture with our veil primitives (Ed25519/Falcon-512 sigs
//! BLAKE3 DHT keys, X25519 ECDH for the introduction encryption).
//!
//! # What this slice ships
//!
//! Just the **signed wire-format primitive** — the building block
//! every later rendezvous slice composes against. Mirrors the
//! pattern (signed manifest primitive shipped
//! before fetch / failover / orchestrator / CLI slices).
//!
//! Deferred to follow-up slices:
//! * Rendezvous-relay state machine (third party that brokers).
//! * Sender-side: parse ad → build onion circuit to rendezvous →
//!   send Introduce frame.
//! * Receiver-side: publish ad to DHT + accept Introduce on the
//!   rendezvous side.
//! * Cookie enforcement at rendezvous.
//! * Periodic DHT republish loop.
//!
//! # Wire format
//!
//! ```text
//! magic : 2 B ("RA" — Rendezvous Ad)
//! version : 1 B (1..=5; see "Version compatibility" below)
//! sig_algo: 1 B (0=Ed25519, 1=Falcon-512, 2=Hybrid)
//! receiver_node_id : 32 B (BLAKE3 of receiver's identity pubkey)
//! rendezvous_node_id : 32 B (third-party meeting point, operator's choice)
//! auth_cookie : 16 B (shared secret receiver gives senders out-of-band)
//! receiver_x25519_pk : 32 B (sender encrypts Introduce frame to this key)
//! valid_from_unix : 8 B (BE)
//! valid_until_unix : 8 B (BE)
//! push_envelope_len : 2 B (BE; cap = 512; 0 = no push registered) — v2+
//! push_envelope : var (opaque sealed FCM/APNs token, decryptable
//! only by a push-relay operator the receiver trusts;
//! relays on the path forward this verbatim to the
//! configured push-relay when delivering an Introduce.
//! Sealing format defined separately in push_envelope.rs;
//! this layer treats the bytes as opaque.) — v2+
//! capability_token_len : 2 B (BE; cap = 2048; 0 = none) — v3+
//! capability_token : var (receiver-signed mailbox-PUT cap token) — v3+
//! wake_hmac_env_len : 2 B (BE; cap = 128; 0 = none) — v4+
//! wake_hmac_envelope : var (sealed wake-HMAC key to push-relay) — v4+
//! rendezvous_kem_algo : 1 B (0 = X25519; reserved: ML-KEM) — v5+
//! rendezvous_kem_pk_len: 2 B (BE; cap = 2048; 0 = no relay key) — v5+
//! rendezvous_kem_pk : var (the RELAY's KEM pubkey — seal target for an
//! anonymous mailbox PUT to this relay) — v5+
//! issuer_pk_len : 2 B (BE; cap = 2048)
//! issuer_pk : var (base64 of receiver's identity pubkey, utf-8)
//! signature_len : 2 B (BE; cap = 2048)
//! signature : var (issuer's signature over canonical message — covers
//! every field above incl. the length-prefixed envelopes /
//! cap-token / relay KEM key, so a censor cannot strip,
//! swap, or downgrade them)
//! ```
//!
//! Typical Ed25519 ad: ~190 B. Typical Falcon-512: ~1.6 KiB. Hard
//! cap: 8 KiB ([`MAX_RENDEZVOUS_AD_BYTES`]).
//!
//! Version compatibility: the decoder accepts v1..=v5 — each version is an
//! additive superset of the prior, so a field is present iff
//! `version >= the version that introduced it` (v2: push_envelope, v3:
//! capability_token, v4: wake_hmac_envelope, v5: rendezvous_kem_*). Older ads
//! decode with the newer fields empty. The encoder always emits v5; legacy ads
//! stored in the DHT re-sign as v5 on the receiver's next maintenance-tick
//! refresh. Each version has a DISJOINT signing domain (`:vN\0`) so a captured
//! ad cannot be replayed or downgraded across versions.
//!
//! # Anti-tamper
//!
//! Signature covers ALL fields including auth_cookie + receiver_x25519_pk
//! and validity window. Censor that captures an old ad and tries to
//! replay it after the receiver rotated their X25519 key cannot —
//! signature would be valid for old fields but verifier checks
//! current time against valid_until.
//!
//! # Domain separation
//!
//! Canonical message domain-prefixed `"veil-rendezvous-ad:v1\0"` so
//! signatures over this format CANNOT replay across other signed
//! primitives in the codebase (relay-directory, identity-document
//! signed-invite, update-manifest etc — each has its own domain).

use veil_crypto::{sign_message, verify_message};
use veil_types::SignatureAlgorithm;

/// 2-byte wire magic identifying a `RendezvousAd` value in the DHT. Public so
/// the recursive-STORE plane's `validate_store_value_by_magic` can recognise +
/// accept ad replication (the ad is structurally decoded + re-verified on the
/// resolver read path, like the other identity-family records).
pub const MAGIC: &[u8; 2] = b"RA";
const VERSION_LEGACY: u8 = 1;
const VERSION_V2: u8 = 2;
const VERSION_V3: u8 = 3;
const VERSION_V4: u8 = 4;
/// Current wire-format version.  v5 adds the relay's KEM public key
/// (`rendezvous_kem_algo` + `rendezvous_kem_pk`) so a sender can anonymously
/// deposit a mailbox PUT directly at the rendezvous relay without a second
/// identity lookup.  The key is ALGORITHM-TAGGED + variable-length so the
/// transport KEM can migrate to a post-quantum scheme (ML-KEM) without another
/// wire-format break — `algo = 0` is classical X25519 (32 B), the only value
/// produced/consumed today.  Encoder (v5 signer) always emits v5; decoder
/// accepts v1 / v2 / v3 / v4 / v5 (older versions yield empty KEM fields,
/// i.e. `algo = 0`, `pk = []` — "no relay key advertised").
const VERSION: u8 = 5;
// Domain separator bumped with v3 → v4 alongside the wire-format version
// so that signatures over old (no-wake-HMAC) and new (wake-HMAC-aware)
// ads cannot replay across versions — a censor that captured an old
// v3 ad cannot construct a v4 forgery by appending an arbitrary
// wake_hmac_envelope, since canonical message construction includes
// wake_hmac_envelope length + bytes, and v3's signing domain locks
// `:v3\0`.  Same disjoint-domain invariant as pre-existing v1→v2 and
// v2→v3 bumps.
const SIG_DOMAIN_V1: &[u8] = b"veil-rendezvous-ad:v1\0";
const SIG_DOMAIN_V2: &[u8] = b"veil-rendezvous-ad:v2\0";
const SIG_DOMAIN_V3: &[u8] = b"veil-rendezvous-ad:v3\0";
const SIG_DOMAIN_V4: &[u8] = b"veil-rendezvous-ad:v4\0";
// Domain bumped v4 → v5 alongside the wire bump: a censor that captured an
// old v4 ad cannot forge a v5 by appending an arbitrary KEM key, since v5
// canonical-message construction binds `rendezvous_kem_algo` + the
// length-prefixed `rendezvous_kem_pk`, and v4's signing domain locks `:v4\0`.
const SIG_DOMAIN_V5: &[u8] = b"veil-rendezvous-ad:v5\0";
const NODE_ID_LEN: usize = 32;
const X25519_PK_LEN: usize = 32;
const AUTH_COOKIE_LEN: usize = 16;
// Falcon-512 base64 pubkey is ~1196 chars; cap at 2048 to accommodate
// it AND give slack for potentially-longer post-quantum algos
// without expanding past the 4 KiB total-blob cap.
const MAX_ISSUER_PK_LEN: usize = 2048;
const MAX_SIGNATURE_LEN: usize = 2048;
/// Cap on `push_envelope`. Sized to accommodate a sealed FCM/APNs token:
/// X25519 ephemeral pubkey (32) + nonce (24) + ciphertext+tag (token ≤
/// ~250 chars + 16-byte AEAD tag) ≈ 322 bytes; cap at 512 leaves slack
/// for future opaque metadata (e.g. push-relay routing hint). Senders
/// that exceed this cap MUST split the metadata across a separate channel
/// or shorten the token (FCM token rotation supports replacement).
pub const MAX_PUSH_ENVELOPE_LEN: usize = 512;

/// cap on the optional mailbox capability
/// token bytes carried in the rendezvous ad. Mirrors
/// `veil_mailbox::MAX_CAPABILITY_TOKEN_BYTES` — 2 KiB fits Falcon-512
/// worst case with slack. Hardcoded here to keep `veil-anonymity` a
/// leaf crate (no dep on veil-mailbox).
pub const MAX_CAPABILITY_TOKEN_LEN: usize = 2048;

/// Cap on `wake_hmac_envelope` (Epic 489.10 slice 4.3.2).
///
/// Sized to accommodate a sealed `WakeHmacKey` to the chosen push relay
/// using the same envelope shape as [`MAX_PUSH_ENVELOPE_LEN`]: X25519
/// ephemeral pubkey (32) + nonce (12) + ciphertext+tag (32 B key +
/// 16 B AEAD tag) = 92 bytes worst case.  Cap at 128 leaves slack
/// for future expansion (e.g. a rotation epoch tag prepended to the
/// key).  Receivers que opt out of HMAC authentication publish empty
/// (`vec![]`); pre-v4 ads decoded under new code also yield empty.
pub const MAX_WAKE_HMAC_ENVELOPE_LEN: usize = 128;

/// KEM algorithm tag for `rendezvous_kem_pk` (v5+). `0` = classical X25519
/// (32-byte key — the only value produced/consumed today). Reserved:
/// `1` = ML-KEM-768, `2` = X25519+ML-KEM-768 hybrid. The tag lets the
/// transport KEM migrate to post-quantum without another ad wire-format break.
pub const RENDEZVOUS_KEM_ALGO_X25519: u8 = 0;

/// Cap on `rendezvous_kem_pk` (v5+). Sized to fit an ML-KEM-768 public key
/// (1184 B) with slack for a hybrid (X25519 ‖ ML-KEM-768 ≈ 1216 B) and future
/// PQ schemes, while staying well under [`MAX_RENDEZVOUS_AD_BYTES`]. Today's
/// X25519 key is 32 B. Empty (`vec![]`) = no relay key advertised.
pub const MAX_RENDEZVOUS_KEM_PK_LEN: usize = 2048;

/// Hard cap on wire size. Sized to accommodate Falcon-512
/// (~1.2 KiB pubkey + ~700 B sig) plus the field overhead PLUS
/// future PQ algos whose pubkeys may approach 2 KiB. At 8 KiB
/// the ad still fits in a single DHT-store frame (16 KiB frame
/// budget) with plenty of slack.
pub const MAX_RENDEZVOUS_AD_BYTES: usize = 8 * 1024;

/// Maximum allowed validity window (`valid_until - valid_from`).
/// Operators publishing for longer than this should rotate their
/// X25519 + auth cookie more often (compromise window grows linearly
/// with validity); 30 days matches the "rotate keys monthly" hygiene
/// recommendation. Anti-DoS: censor capturing one ad shouldn't be
/// able to keep using it indefinitely.
pub const MAX_VALIDITY_WINDOW_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RendezvousError {
    /// (eph_pk, nonce) fingerprint of this
    /// Introduce frame was previously consumed. Either an attacker is
    /// replaying a captured Introduce or the legitimate sender's frame
    /// was retransmitted by the network. Either way the receiver MUST
    /// drop without further AEAD work.
    #[error("introduce replay: (eph_pk, nonce) already consumed")]
    Replay,
    #[error("sign: {0}")]
    Sign(String),
    #[error("signature verification failed (wrong key, tampered fields, or wrong algo)")]
    Verify,
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported sig algo byte: {0}")]
    BadSigAlgo(u8),
    #[error("ad exceeds {MAX_RENDEZVOUS_AD_BYTES} byte cap (got {got})")]
    TooLarge { got: usize },
    #[error("issuer_pk_len {got} > {MAX_ISSUER_PK_LEN} cap")]
    IssuerPkTooLarge { got: usize },
    #[error("signature_len {got} > {MAX_SIGNATURE_LEN} cap")]
    SignatureTooLarge { got: usize },
    #[error("push_envelope_len {got} > {MAX_PUSH_ENVELOPE_LEN} cap")]
    PushEnvelopeTooLarge { got: usize },
    #[error("capability_token_len {got} > {MAX_CAPABILITY_TOKEN_LEN} cap")]
    CapabilityTokenTooLarge { got: usize },
    #[error("wake_hmac_envelope_len {got} > {MAX_WAKE_HMAC_ENVELOPE_LEN} cap")]
    WakeHmacEnvelopeTooLarge { got: usize },
    #[error("rendezvous_kem_pk_len {got} > {MAX_RENDEZVOUS_KEM_PK_LEN} cap")]
    KemPkTooLarge { got: usize },
    #[error("validity window {got} secs > {MAX_VALIDITY_WINDOW_SECS} cap")]
    ValidityWindowTooLarge { got: u64 },
    #[error("inverted validity window: valid_from {from} > valid_until {until}")]
    ValidityInverted { from: u64, until: u64 },
    #[error("ad expired: now={now} >= valid_until={valid_until}")]
    Expired { now: u64, valid_until: u64 },
    #[error("ad not yet valid: now={now} < valid_from={valid_from}")]
    NotYetValid { now: u64, valid_from: u64 },
}

/// Decoded rendezvous-point advertisement. Construct via
/// [`sign_rendezvous_ad`], publish bytes to DHT, decode on receiver
/// [`decode_rendezvous_ad`], verify [`verify_rendezvous_ad`]
/// optionally check current validity [`is_currently_valid`].
#[derive(Debug, Clone, PartialEq)]
pub struct RendezvousAd {
    /// Receiver's identity (BLAKE3 of issuer pubkey). DHT key for
    /// looking up this ad is derived from this field.
    pub receiver_node_id: [u8; NODE_ID_LEN],
    /// Third-party meeting point. Sender builds an onion circuit
    /// to this node, sends an Introduce frame addressed by the auth
    /// cookie; rendezvous relays to receiver who is also connected to
    /// this node out-of-band.
    pub rendezvous_node_id: [u8; NODE_ID_LEN],
    /// Shared secret that authorises a sender to use this ad.
    /// Receiver distributes to specific senders out-of-band (DM /
    /// QR / sneakernet); rendezvous accepts only Introduce frames
    /// presenting a known cookie. 16 bytes = 128-bit collision
    /// resistance, plenty for an authorisation token.
    pub auth_cookie: [u8; AUTH_COOKIE_LEN],
    /// Sender encrypts the Introduce frame to this key. Provides
    /// receiver-only readability — even the rendezvous node CAN'T
    /// see what sender sent (only that they sent it). Forward
    /// secrecy via per-ad rotation: receiver generates fresh
    /// X25519 keypair per ad republish.
    pub receiver_x25519_pk: [u8; X25519_PK_LEN],
    /// Unix-time when this ad becomes effective. Senders MUST
    /// reject ads with `now < valid_from` (catches clock-skew attacks
    /// + post-dated ads).
    pub valid_from_unix: u64,
    /// Unix-time when this ad expires. Senders MUST reject ads with
    /// `now >= valid_until`. Receiver republishes before expiry
    /// to maintain availability.
    pub valid_until_unix: u64,
    /// Receiver's identity pubkey (base64 of raw bytes; same shape
    /// as `IdentityConfig.public_key`). Verifier uses this to check
    /// the signature.
    pub issuer_pk: String,
    pub issuer_algo: SignatureAlgorithm,
    pub signature: Vec<u8>,
    /// opaque sealed envelope carrying receiver's push
    /// token (FCM / APNs). Decryptable only by a push-relay operator
    /// the receiver trusts; relays on the message-delivery path forward
    /// this verbatim to the configured push-relay so it can fire a
    /// silent wake-up to the receiver's device.
    ///
    /// Empty (`vec![]`) when the receiver did not register for push
    /// (default — desktop nodes, mobile nodes opted out of push).
    /// Cap [`MAX_PUSH_ENVELOPE_LEN`].
    pub push_envelope: Vec<u8>,
    /// opaque mailbox capability-token bytes
    /// (decoded by `veil-mailbox::MailboxCapabilityToken::decode`).
    /// Senders include this in their `MailboxPutPayload.capability_token`
    /// trailer when the relay enforces `require_capability_token = true`.
    /// Empty (`vec![]`) when the receiver did not mint a token (legacy
    /// senders / pre-slice-2 publishers). Cap [`MAX_CAPABILITY_TOKEN_LEN`].
    pub capability_token: Vec<u8>,
    /// opaque sealed envelope carrying receiver's wake-up
    /// HMAC key to the chosen push-relay (Epic 489.10 slice 4.3.2).
    /// Only the relay holding the matching X25519 sk can decrypt; the
    /// relay then uses the key to sign wake-up payloads made
    /// receivers' plugin can verify locally (closes leaked-FCM/APNs-
    /// token battery DoS / presence-oracle).
    ///
    /// Empty (`vec![]`) when the receiver did not register for wake-
    /// HMAC authentication (legacy desktop nodes, mobile nodes pre-v4,
    /// receivers running with trust-the-rate-limit only).  Cap
    /// [`MAX_WAKE_HMAC_ENVELOPE_LEN`].
    pub wake_hmac_envelope: Vec<u8>,
    /// KEM algorithm tag for [`Self::rendezvous_kem_pk`] (v5+).
    /// [`RENDEZVOUS_KEM_ALGO_X25519`] (`0`) = classical X25519. `0` for ads
    /// decoded from pre-v5 wire (no relay key advertised).
    pub rendezvous_kem_algo: u8,
    /// The rendezvous RELAY's KEM public key — the seal target a sender uses to
    /// anonymously deliver a mailbox PUT to this relay (`send_anonymous` to
    /// `(rendezvous_node_id, MAILBOX_APP_ID, PUT_ENDPOINT)`). Distinct from
    /// [`Self::receiver_x25519_pk`] (the RECEIVER's Introduce key). Algorithm
    /// per [`Self::rendezvous_kem_algo`]; for `algo = 0` this is the relay's
    /// 32-byte X25519 pubkey (the same key the receiver sealed
    /// [`Self::push_envelope`] to). Empty (`vec![]`) when the receiver did not
    /// advertise a relay key (pre-v5 ads / receiver opted out — senders then
    /// fall back to the live rendezvous path). Cap
    /// [`MAX_RENDEZVOUS_KEM_PK_LEN`].
    pub rendezvous_kem_pk: Vec<u8>,
    /// Wire-format version this ad was decoded from (or freshly signed
    /// at). Preserved across decode → verify so verify can pick the
    /// matching canonical-message domain (v1 ads signed pre-push don't
    /// include push_envelope; v2 don't include capability_token; v3
    /// don't include wake_hmac_envelope).  Encoder always emits v4;
    /// decoder tolerates v1 / v2 / v3 for backward-compat reads of
    /// DHT entries from a transition-period network.
    pub wire_version: u8,
}

/// Derive the DHT key under which `receiver_node_id`'s rendezvous
/// ad is published. Domain-separated from `relay_directory_dht_key`
/// and every other DHT-key derivation in the codebase — a rendezvous
/// query CANNOT accidentally hit a relay-directory slot.
///
/// Equivalent [`rendezvous_ad_dht_key_at(receiver_node_id, 0)`].
/// Kept as a separate function for backward compatibility — pre-T1.4
/// publishers and resolvers used this exact form.
pub fn rendezvous_ad_dht_key(receiver_node_id: &[u8; NODE_ID_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil:v1:rendezvous-ad\0");
    h.update(receiver_node_id);
    *h.finalize().as_bytes()
}

/// Maximum number of replica rendezvous-ad slots a receiver may
/// publish. K=8 leaves slack above the typical fan-out (3) without
/// blowing DHT storage costs (8× the per-receiver footprint).
pub const MAX_RENDEZVOUS_AD_SLOTS: u8 = 8;

/// Derive the DHT key for the `idx`-th replica slot of
/// `receiver_node_id`'s rendezvous publication (follow-up
/// to T1.4 —).
///
/// **Backward-compat invariant:** `rendezvous_ad_dht_key_at(_, 0)`
/// produces the SAME 32 bytes as legacy [`rendezvous_ad_dht_key`].
/// Pre-T1.4 publishers and resolvers therefore interoperate seamlessly
/// with new multi-replica nodes — they simply only see slot 0.
///
/// Slot indices ≥1 use a distinct domain separator so a malicious
/// adversary cannot conflate slot N's content with slot 0's by
/// crafting an input. `idx >= MAX_RENDEZVOUS_AD_SLOTS` saturates to
/// `MAX_RENDEZVOUS_AD_SLOTS - 1` (caller bug; we don't panic since
/// this is on the hot publishing path).
pub fn rendezvous_ad_dht_key_at(receiver_node_id: &[u8; NODE_ID_LEN], idx: u8) -> [u8; 32] {
    if idx == 0 {
        // Backward-compat: bit-exact with legacy single-key derivation.
        return rendezvous_ad_dht_key(receiver_node_id);
    }
    let idx = idx.min(MAX_RENDEZVOUS_AD_SLOTS - 1);
    let mut h = blake3::Hasher::new();
    h.update(b"veil:v1:rendezvous-ad-replica\0");
    h.update(receiver_node_id);
    h.update(&[idx]);
    *h.finalize().as_bytes()
}

/// Build, sign, and encode a rendezvous-point ad.
///
/// Many positional arguments — corresponds to the signed wire format's
/// fields. Bundling them in a params struct would add indirection
/// without improving readability; signed-primitive functions naturally
/// have many positional fields (see `sign_entry` in `directory.rs`
/// `sign_manifest` in `update::manifest`, etc).
///
/// `push_envelope` is the optional sealed FCM/APNs token blob (
/// Pass `&[]` when the receiver did not register for push
/// (desktop nodes; mobile-but-no-push); cap [`MAX_PUSH_ENVELOPE_LEN`].
///
/// `capability_token` is the optional
/// receiver-signed mailbox-PUT cookie (mint via
/// `veil_mailbox::capability::sign_token`). Pass `&[]` for relays
/// with `require_capability_token = false` (the default), the legacy
/// permissive path. Cap [`MAX_CAPABILITY_TOKEN_LEN`].
///
/// `wake_hmac_envelope` is the optional sealed wake-HMAC key for
/// push-relay-authenticated wakeups (Epic 489.10).  Pass `&[]` for
/// receivers that opt out of wake-HMAC authentication (legacy
/// desktop / pre-v4 mobile).  Cap [`MAX_WAKE_HMAC_ENVELOPE_LEN`].
#[allow(clippy::too_many_arguments)]
pub fn sign_rendezvous_ad(
    receiver_node_id: [u8; NODE_ID_LEN],
    rendezvous_node_id: [u8; NODE_ID_LEN],
    auth_cookie: [u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: [u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    wake_hmac_envelope: &[u8],
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
) -> Result<Vec<u8>, RendezvousError> {
    if issuer_pk.len() > MAX_ISSUER_PK_LEN {
        return Err(RendezvousError::IssuerPkTooLarge {
            got: issuer_pk.len(),
        });
    }
    if push_envelope.len() > MAX_PUSH_ENVELOPE_LEN {
        return Err(RendezvousError::PushEnvelopeTooLarge {
            got: push_envelope.len(),
        });
    }
    if capability_token.len() > MAX_CAPABILITY_TOKEN_LEN {
        return Err(RendezvousError::CapabilityTokenTooLarge {
            got: capability_token.len(),
        });
    }
    if wake_hmac_envelope.len() > MAX_WAKE_HMAC_ENVELOPE_LEN {
        return Err(RendezvousError::WakeHmacEnvelopeTooLarge {
            got: wake_hmac_envelope.len(),
        });
    }
    if valid_until_unix < valid_from_unix {
        return Err(RendezvousError::ValidityInverted {
            from: valid_from_unix,
            until: valid_until_unix,
        });
    }
    let window = valid_until_unix - valid_from_unix;
    if window > MAX_VALIDITY_WINDOW_SECS {
        return Err(RendezvousError::ValidityWindowTooLarge { got: window });
    }
    // Emit the CURRENT wire version (v5) with EMPTY relay-KEM fields
    // (`algo = 0`, `pk = []` — "no relay key advertised"). Callers that want to
    // advertise the relay's KEM key for anonymous mailbox deposit call
    // [`sign_rendezvous_ad_v5`] directly. The validation above is a fast
    // pre-check; v5 re-validates the same invariants.
    sign_rendezvous_ad_v5(
        receiver_node_id,
        rendezvous_node_id,
        auth_cookie,
        receiver_x25519_pk,
        valid_from_unix,
        valid_until_unix,
        push_envelope,
        capability_token,
        wake_hmac_envelope,
        RENDEZVOUS_KEM_ALGO_X25519,
        &[],
        issuer_pk,
        issuer_sk,
        issuer_algo,
    )
}

/// Build, sign, and encode a v5 rendezvous-point ad — like
/// [`sign_rendezvous_ad`] but additionally binds the rendezvous RELAY's KEM
/// public key (`rendezvous_kem_algo` + `rendezvous_kem_pk`) so a sender can
/// anonymously deposit a mailbox PUT at the relay without a second lookup.
///
/// `rendezvous_kem_algo` is the KEM tag ([`RENDEZVOUS_KEM_ALGO_X25519`] today);
/// `rendezvous_kem_pk` is the relay's KEM pubkey (32-byte X25519 for `algo=0`).
/// Pass `(RENDEZVOUS_KEM_ALGO_X25519, &[])` to advertise no relay key (sender
/// then falls back to the live rendezvous path); cap
/// [`MAX_RENDEZVOUS_KEM_PK_LEN`].
#[allow(clippy::too_many_arguments)]
pub fn sign_rendezvous_ad_v5(
    receiver_node_id: [u8; NODE_ID_LEN],
    rendezvous_node_id: [u8; NODE_ID_LEN],
    auth_cookie: [u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: [u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    wake_hmac_envelope: &[u8],
    rendezvous_kem_algo: u8,
    rendezvous_kem_pk: &[u8],
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
) -> Result<Vec<u8>, RendezvousError> {
    if issuer_pk.len() > MAX_ISSUER_PK_LEN {
        return Err(RendezvousError::IssuerPkTooLarge {
            got: issuer_pk.len(),
        });
    }
    if push_envelope.len() > MAX_PUSH_ENVELOPE_LEN {
        return Err(RendezvousError::PushEnvelopeTooLarge {
            got: push_envelope.len(),
        });
    }
    if capability_token.len() > MAX_CAPABILITY_TOKEN_LEN {
        return Err(RendezvousError::CapabilityTokenTooLarge {
            got: capability_token.len(),
        });
    }
    if wake_hmac_envelope.len() > MAX_WAKE_HMAC_ENVELOPE_LEN {
        return Err(RendezvousError::WakeHmacEnvelopeTooLarge {
            got: wake_hmac_envelope.len(),
        });
    }
    if rendezvous_kem_pk.len() > MAX_RENDEZVOUS_KEM_PK_LEN {
        return Err(RendezvousError::KemPkTooLarge {
            got: rendezvous_kem_pk.len(),
        });
    }
    if valid_until_unix < valid_from_unix {
        return Err(RendezvousError::ValidityInverted {
            from: valid_from_unix,
            until: valid_until_unix,
        });
    }
    let window = valid_until_unix - valid_from_unix;
    if window > MAX_VALIDITY_WINDOW_SECS {
        return Err(RendezvousError::ValidityWindowTooLarge { got: window });
    }
    let canonical = canonical_message_v5(
        &receiver_node_id,
        &rendezvous_node_id,
        &auth_cookie,
        &receiver_x25519_pk,
        valid_from_unix,
        valid_until_unix,
        push_envelope,
        capability_token,
        wake_hmac_envelope,
        rendezvous_kem_algo,
        rendezvous_kem_pk,
    );
    let signature = sign_message(issuer_algo, issuer_pk, issuer_sk, &canonical)
        .map_err(|e| RendezvousError::Sign(format!("{e}")))?;
    if signature.len() > MAX_SIGNATURE_LEN {
        return Err(RendezvousError::SignatureTooLarge {
            got: signature.len(),
        });
    }
    let bytes = encode_body_v5(
        &receiver_node_id,
        &rendezvous_node_id,
        &auth_cookie,
        &receiver_x25519_pk,
        valid_from_unix,
        valid_until_unix,
        push_envelope,
        capability_token,
        wake_hmac_envelope,
        rendezvous_kem_algo,
        rendezvous_kem_pk,
        issuer_pk.as_bytes(),
        issuer_algo,
        &signature,
    )?;
    if bytes.len() > MAX_RENDEZVOUS_AD_BYTES {
        return Err(RendezvousError::TooLarge { got: bytes.len() });
    }
    Ok(bytes)
}

/// Decode bytes from DHT into a [`RendezvousAd`]. Does NOT verify
/// the signature; callers MUST chain [`verify_rendezvous_ad`] before
/// trusting any field.
///
/// Accepts ALL wire-format versions:
/// * v1 (legacy, pre-push): no envelope/token fields present;
///   decoder sets all three optionals to empty `vec![]`.
/// * v2: includes `push_envelope_len` + `push_envelope` only.
/// * v3: also includes `capability_token_len` + `capability_token`.
/// * v4 (current): also includes `wake_hmac_envelope_len` +
///   `wake_hmac_envelope`.  Receivers still running pre-v4 will be
///   re-signed as v4 by their next maintenance-tick (with empty
///   wake_hmac_envelope if they did not register for wake-HMAC).
pub fn decode_rendezvous_ad(blob: &[u8]) -> Result<RendezvousAd, RendezvousError> {
    if blob.len() > MAX_RENDEZVOUS_AD_BYTES {
        return Err(RendezvousError::TooLarge { got: blob.len() });
    }
    let mut p = 0usize;
    let magic = read(blob, &mut p, 2)?;
    if magic != MAGIC {
        return Err(RendezvousError::Malformed(format!("bad magic: {magic:?}")));
    }
    let version = read(blob, &mut p, 1)?[0];
    if version != VERSION
        && version != VERSION_V4
        && version != VERSION_V3
        && version != VERSION_V2
        && version != VERSION_LEGACY
    {
        return Err(RendezvousError::Malformed(format!(
            "unsupported version {version}",
        )));
    }
    let sig_algo_byte = read(blob, &mut p, 1)?[0];
    let issuer_algo = match sig_algo_byte {
        0 => SignatureAlgorithm::Ed25519,
        1 => SignatureAlgorithm::Falcon512,
        2 => SignatureAlgorithm::Ed25519Falcon512Hybrid,
        3 => SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        b => return Err(RendezvousError::BadSigAlgo(b)),
    };
    let mut receiver_node_id = [0u8; NODE_ID_LEN];
    receiver_node_id.copy_from_slice(read(blob, &mut p, NODE_ID_LEN)?);
    let mut rendezvous_node_id = [0u8; NODE_ID_LEN];
    rendezvous_node_id.copy_from_slice(read(blob, &mut p, NODE_ID_LEN)?);
    let mut auth_cookie = [0u8; AUTH_COOKIE_LEN];
    auth_cookie.copy_from_slice(read(blob, &mut p, AUTH_COOKIE_LEN)?);
    let mut receiver_x25519_pk = [0u8; X25519_PK_LEN];
    receiver_x25519_pk.copy_from_slice(read(blob, &mut p, X25519_PK_LEN)?);
    let valid_from_unix = u64::from_be_bytes(read(blob, &mut p, 8)?.try_into().unwrap());
    let valid_until_unix = u64::from_be_bytes(read(blob, &mut p, 8)?.try_into().unwrap());
    // Versions are additive supersets (v1 ⊂ v2 ⊂ v3 ⊂ v4 ⊂ v5), so each field
    // is present iff `version >= the version that introduced it`.
    // push_envelope: v2+ (v1 skips it; field defaults to empty).
    let push_envelope = if version >= VERSION_V2 {
        let env_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
        if env_len > MAX_PUSH_ENVELOPE_LEN {
            return Err(RendezvousError::PushEnvelopeTooLarge { got: env_len });
        }
        read(blob, &mut p, env_len)?.to_vec()
    } else {
        Vec::new()
    };
    // capability_token: v3+ (pre-v3 ads yield empty).
    let capability_token = if version >= VERSION_V3 {
        let cap_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
        if cap_len > MAX_CAPABILITY_TOKEN_LEN {
            return Err(RendezvousError::CapabilityTokenTooLarge { got: cap_len });
        }
        read(blob, &mut p, cap_len)?.to_vec()
    } else {
        Vec::new()
    };
    // wake_hmac_envelope: v4+ (Epic 489.10 slice 4.3.2). Pre-v4 ads yield empty.
    let wake_hmac_envelope = if version >= VERSION_V4 {
        let env_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
        if env_len > MAX_WAKE_HMAC_ENVELOPE_LEN {
            return Err(RendezvousError::WakeHmacEnvelopeTooLarge { got: env_len });
        }
        read(blob, &mut p, env_len)?.to_vec()
    } else {
        Vec::new()
    };
    // rendezvous_kem_algo + rendezvous_kem_pk: v5+ (the relay's KEM key for
    // anonymous mailbox deposit). Pre-v5 ads yield `algo = 0`, `pk = []`.
    let (rendezvous_kem_algo, rendezvous_kem_pk) = if version >= VERSION {
        let algo = read(blob, &mut p, 1)?[0];
        let kem_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
        if kem_len > MAX_RENDEZVOUS_KEM_PK_LEN {
            return Err(RendezvousError::KemPkTooLarge { got: kem_len });
        }
        (algo, read(blob, &mut p, kem_len)?.to_vec())
    } else {
        (RENDEZVOUS_KEM_ALGO_X25519, Vec::new())
    };
    let pk_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
    if pk_len > MAX_ISSUER_PK_LEN {
        return Err(RendezvousError::IssuerPkTooLarge { got: pk_len });
    }
    let issuer_pk_bytes = read(blob, &mut p, pk_len)?;
    let issuer_pk = std::str::from_utf8(issuer_pk_bytes)
        .map_err(|e| RendezvousError::Malformed(format!("issuer_pk utf8: {e}")))?
        .to_owned();
    let sig_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
    if sig_len > MAX_SIGNATURE_LEN {
        return Err(RendezvousError::SignatureTooLarge { got: sig_len });
    }
    let signature = read(blob, &mut p, sig_len)?.to_vec();
    if p != blob.len() {
        return Err(RendezvousError::Malformed(format!(
            "{} trailing byte(s)",
            blob.len() - p,
        )));
    }
    Ok(RendezvousAd {
        receiver_node_id,
        rendezvous_node_id,
        auth_cookie,
        receiver_x25519_pk,
        valid_from_unix,
        valid_until_unix,
        issuer_pk,
        issuer_algo,
        signature,
        push_envelope,
        capability_token,
        wake_hmac_envelope,
        rendezvous_kem_algo,
        rendezvous_kem_pk,
        wire_version: version,
    })
}

/// Verify the signature on a decoded ad. Returns Ok when the
/// signature is valid; Err(Verify) when it's not. Caller is
/// responsible for additionally checking validity window via
/// [`is_currently_valid`] (kept separate so a debug tool can
/// validate signature on an expired ad without validity rejection).
///
/// Verification picks the canonical-message form via `ad.wire_version`
/// (preserved by decode). v1 ads signed pre-refactor use the v1
/// domain (no `push_envelope` in the signed payload); v2 ads use the
/// v2 domain which includes `push_envelope` length + bytes — ensures
/// a censor cannot strip the envelope post-sign and pass a v2 ad as
/// v1, since the v2 signature won't verify under v1 canonical.
pub fn verify_rendezvous_ad(ad: &RendezvousAd) -> Result<(), RendezvousError> {
    // Bind receiver_node_id to the issuer key: receiver_node_id MUST equal
    // BLAKE3(issuer_pk). Without this, an attacker holding ANY valid identity
    // key could sign an ad naming a *victim's* receiver_node_id (with an
    // attacker-chosen rendezvous_node_id + receiver_x25519_pk) and the
    // signature alone would pass — letting them hijack the victim's rendezvous
    // slot so a sender seals the Introduce frame to the attacker's X25519 key
    // and routes the onion to the attacker's relay (content + metadata capture
    // / MITM / deanonymization). Enforced HERE (not only at the resolver) so the
    // invariant holds for every caller. Mirrors `directory::verify_entry`'s
    // node_id↔issuer binding. (audit cycle-6 H1.)
    let issuer_pk_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &ad.issuer_pk)
            .map_err(|_| RendezvousError::Verify)?;
    if blake3::hash(&issuer_pk_bytes).as_bytes() != &ad.receiver_node_id {
        return Err(RendezvousError::Verify);
    }
    let canonical = match ad.wire_version {
        VERSION_LEGACY => canonical_message_v1(
            &ad.receiver_node_id,
            &ad.rendezvous_node_id,
            &ad.auth_cookie,
            &ad.receiver_x25519_pk,
            ad.valid_from_unix,
            ad.valid_until_unix,
        ),
        VERSION_V2 => canonical_message_v2(
            &ad.receiver_node_id,
            &ad.rendezvous_node_id,
            &ad.auth_cookie,
            &ad.receiver_x25519_pk,
            ad.valid_from_unix,
            ad.valid_until_unix,
            &ad.push_envelope,
        ),
        VERSION_V3 => canonical_message_v3(
            &ad.receiver_node_id,
            &ad.rendezvous_node_id,
            &ad.auth_cookie,
            &ad.receiver_x25519_pk,
            ad.valid_from_unix,
            ad.valid_until_unix,
            &ad.push_envelope,
            &ad.capability_token,
        ),
        VERSION_V4 => canonical_message_v4(
            &ad.receiver_node_id,
            &ad.rendezvous_node_id,
            &ad.auth_cookie,
            &ad.receiver_x25519_pk,
            ad.valid_from_unix,
            ad.valid_until_unix,
            &ad.push_envelope,
            &ad.capability_token,
            &ad.wake_hmac_envelope,
        ),
        VERSION => canonical_message_v5(
            &ad.receiver_node_id,
            &ad.rendezvous_node_id,
            &ad.auth_cookie,
            &ad.receiver_x25519_pk,
            ad.valid_from_unix,
            ad.valid_until_unix,
            &ad.push_envelope,
            &ad.capability_token,
            &ad.wake_hmac_envelope,
            ad.rendezvous_kem_algo,
            &ad.rendezvous_kem_pk,
        ),
        v => {
            return Err(RendezvousError::Malformed(format!(
                "unknown wire_version {v}"
            )));
        }
    };
    verify_message(ad.issuer_algo, &ad.issuer_pk, &canonical, &ad.signature)
        .map_err(|_| RendezvousError::Verify)
}

/// Check whether an ad is currently within its validity window.
/// Returns Err(NotYetValid) when `now < valid_from`, Err(Expired)
/// when `now >= valid_until`. Caller (sender) MUST chain after
/// `verify_rendezvous_ad` since validity is a freshness check —
/// signature still verifies on stale ads.
pub fn is_currently_valid(ad: &RendezvousAd, now_unix: u64) -> Result<(), RendezvousError> {
    if now_unix < ad.valid_from_unix {
        return Err(RendezvousError::NotYetValid {
            now: now_unix,
            valid_from: ad.valid_from_unix,
        });
    }
    if now_unix >= ad.valid_until_unix {
        return Err(RendezvousError::Expired {
            now: now_unix,
            valid_until: ad.valid_until_unix,
        });
    }
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Legacy v1 canonical-message form (no `push_envelope`). Used by
/// [`verify_rendezvous_ad`] when reading a legacy v1 ad from the DHT
/// during the transition period. Encoder NEVER produces
/// v1 form anymore — once a receiver runs maintenance-tick, the next
/// re-sign emits v2.
#[allow(clippy::too_many_arguments)]
fn canonical_message_v1(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        SIG_DOMAIN_V1.len() + NODE_ID_LEN * 2 + AUTH_COOKIE_LEN + X25519_PK_LEN + 16,
    );
    buf.extend_from_slice(SIG_DOMAIN_V1);
    buf.extend_from_slice(receiver_node_id);
    buf.extend_from_slice(rendezvous_node_id);
    buf.extend_from_slice(auth_cookie);
    buf.extend_from_slice(receiver_x25519_pk);
    buf.extend_from_slice(&valid_from_unix.to_be_bytes());
    buf.extend_from_slice(&valid_until_unix.to_be_bytes());
    buf
}

/// Current v2 canonical-message form (— includes
/// `push_envelope`). Length-prefix on the envelope ensures the
/// signature binds BOTH the envelope contents AND the operator's
/// intent to publish a push hint at all (length=0 still signs). A
/// censor cannot strip / replace / append the envelope without breaking
/// the signature.
#[allow(clippy::too_many_arguments)]
fn canonical_message_v2(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        SIG_DOMAIN_V2.len()
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len(),
    );
    buf.extend_from_slice(SIG_DOMAIN_V2);
    buf.extend_from_slice(receiver_node_id);
    buf.extend_from_slice(rendezvous_node_id);
    buf.extend_from_slice(auth_cookie);
    buf.extend_from_slice(receiver_x25519_pk);
    buf.extend_from_slice(&valid_from_unix.to_be_bytes());
    buf.extend_from_slice(&valid_until_unix.to_be_bytes());
    buf.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    buf.extend_from_slice(push_envelope);
    buf
}

// superseded by encode_body_v3 (signer always
// emits v3). Retained for symmetry with canonical_message_v2 (still needed
// by verify dispatch over existing-on-DHT v2 ads) and for cfg(test) callers
// that construct synthetic v2 wire to exercise backward-compat decode.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn encode_body_v2(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    issuer_pk_bytes: &[u8],
    issuer_algo: SignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, RendezvousError> {
    let mut out = Vec::with_capacity(
        2 + 1
            + 1
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + issuer_pk_bytes.len()
            + 2
            + signature.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION_V2);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(receiver_node_id);
    out.extend_from_slice(rendezvous_node_id);
    out.extend_from_slice(auth_cookie);
    out.extend_from_slice(receiver_x25519_pk);
    out.extend_from_slice(&valid_from_unix.to_be_bytes());
    out.extend_from_slice(&valid_until_unix.to_be_bytes());
    out.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    out.extend_from_slice(push_envelope);
    out.extend_from_slice(&(issuer_pk_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk_bytes);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

/// v3 canonical-message form. Adds
/// `capability_token` length + bytes after the v2 push_envelope tail.
/// Same length-prefix-inclusion invariant as v2: censor cannot strip
/// or replace the cap token without invalidating the v3 signature.
#[allow(clippy::too_many_arguments)]
fn canonical_message_v3(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        SIG_DOMAIN_V3.len()
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + capability_token.len(),
    );
    buf.extend_from_slice(SIG_DOMAIN_V3);
    buf.extend_from_slice(receiver_node_id);
    buf.extend_from_slice(rendezvous_node_id);
    buf.extend_from_slice(auth_cookie);
    buf.extend_from_slice(receiver_x25519_pk);
    buf.extend_from_slice(&valid_from_unix.to_be_bytes());
    buf.extend_from_slice(&valid_until_unix.to_be_bytes());
    buf.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    buf.extend_from_slice(push_envelope);
    buf.extend_from_slice(&(capability_token.len() as u16).to_be_bytes());
    buf.extend_from_slice(capability_token);
    buf
}

// superseded by encode_body_v4 (signer always emits v4).  Retained
// for symmetry with canonical_message_v3 (still needed by verify
// dispatch over existing-on-DHT v3 ads) and for cfg(test) callers
// that construct synthetic v3 wire to exercise backward-compat decode.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn encode_body_v3(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    issuer_pk_bytes: &[u8],
    issuer_algo: SignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, RendezvousError> {
    let mut out = Vec::with_capacity(
        2 + 1
            + 1
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + capability_token.len()
            + 2
            + issuer_pk_bytes.len()
            + 2
            + signature.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION_V3);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(receiver_node_id);
    out.extend_from_slice(rendezvous_node_id);
    out.extend_from_slice(auth_cookie);
    out.extend_from_slice(receiver_x25519_pk);
    out.extend_from_slice(&valid_from_unix.to_be_bytes());
    out.extend_from_slice(&valid_until_unix.to_be_bytes());
    out.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    out.extend_from_slice(push_envelope);
    out.extend_from_slice(&(capability_token.len() as u16).to_be_bytes());
    out.extend_from_slice(capability_token);
    out.extend_from_slice(&(issuer_pk_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk_bytes);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

/// v4 canonical-message form (Epic 489.10 slice 4.3.2).  Adds
/// `wake_hmac_envelope` length + bytes after the v3 capability_token
/// tail.  Same length-prefix-inclusion invariant: censor cannot strip
/// or replace the wake HMAC envelope without invalidating the v4 signature.
#[allow(clippy::too_many_arguments)]
fn canonical_message_v4(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    wake_hmac_envelope: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        SIG_DOMAIN_V4.len()
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + capability_token.len()
            + 2
            + wake_hmac_envelope.len(),
    );
    buf.extend_from_slice(SIG_DOMAIN_V4);
    buf.extend_from_slice(receiver_node_id);
    buf.extend_from_slice(rendezvous_node_id);
    buf.extend_from_slice(auth_cookie);
    buf.extend_from_slice(receiver_x25519_pk);
    buf.extend_from_slice(&valid_from_unix.to_be_bytes());
    buf.extend_from_slice(&valid_until_unix.to_be_bytes());
    buf.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    buf.extend_from_slice(push_envelope);
    buf.extend_from_slice(&(capability_token.len() as u16).to_be_bytes());
    buf.extend_from_slice(capability_token);
    buf.extend_from_slice(&(wake_hmac_envelope.len() as u16).to_be_bytes());
    buf.extend_from_slice(wake_hmac_envelope);
    buf
}

// superseded by encode_body_v5 (signer always emits v5).  Retained for
// symmetry with canonical_message_v4 (still needed by verify dispatch over
// existing-on-DHT v4 ads) and for cfg(test) callers that construct synthetic
// v4 wire to exercise backward-compat decode.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn encode_body_v4(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    wake_hmac_envelope: &[u8],
    issuer_pk_bytes: &[u8],
    issuer_algo: SignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, RendezvousError> {
    let mut out = Vec::with_capacity(
        2 + 1
            + 1
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + capability_token.len()
            + 2
            + wake_hmac_envelope.len()
            + 2
            + issuer_pk_bytes.len()
            + 2
            + signature.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION_V4);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(receiver_node_id);
    out.extend_from_slice(rendezvous_node_id);
    out.extend_from_slice(auth_cookie);
    out.extend_from_slice(receiver_x25519_pk);
    out.extend_from_slice(&valid_from_unix.to_be_bytes());
    out.extend_from_slice(&valid_until_unix.to_be_bytes());
    out.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    out.extend_from_slice(push_envelope);
    out.extend_from_slice(&(capability_token.len() as u16).to_be_bytes());
    out.extend_from_slice(capability_token);
    out.extend_from_slice(&(wake_hmac_envelope.len() as u16).to_be_bytes());
    out.extend_from_slice(wake_hmac_envelope);
    out.extend_from_slice(&(issuer_pk_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk_bytes);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

/// v5 canonical-message form. Adds `rendezvous_kem_algo` (1 B) +
/// length-prefixed `rendezvous_kem_pk` after the v4 wake_hmac_envelope tail.
/// Same length-prefix-inclusion invariant: a censor cannot strip, replace, or
/// append the relay KEM key without invalidating the v5 signature (and cannot
/// downgrade to v4 — the `:v5\0` domain won't verify under v4 canonical).
#[allow(clippy::too_many_arguments)]
fn canonical_message_v5(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    wake_hmac_envelope: &[u8],
    rendezvous_kem_algo: u8,
    rendezvous_kem_pk: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        SIG_DOMAIN_V5.len()
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + capability_token.len()
            + 2
            + wake_hmac_envelope.len()
            + 1
            + 2
            + rendezvous_kem_pk.len(),
    );
    buf.extend_from_slice(SIG_DOMAIN_V5);
    buf.extend_from_slice(receiver_node_id);
    buf.extend_from_slice(rendezvous_node_id);
    buf.extend_from_slice(auth_cookie);
    buf.extend_from_slice(receiver_x25519_pk);
    buf.extend_from_slice(&valid_from_unix.to_be_bytes());
    buf.extend_from_slice(&valid_until_unix.to_be_bytes());
    buf.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    buf.extend_from_slice(push_envelope);
    buf.extend_from_slice(&(capability_token.len() as u16).to_be_bytes());
    buf.extend_from_slice(capability_token);
    buf.extend_from_slice(&(wake_hmac_envelope.len() as u16).to_be_bytes());
    buf.extend_from_slice(wake_hmac_envelope);
    buf.push(rendezvous_kem_algo);
    buf.extend_from_slice(&(rendezvous_kem_pk.len() as u16).to_be_bytes());
    buf.extend_from_slice(rendezvous_kem_pk);
    buf
}

#[allow(clippy::too_many_arguments)]
fn encode_body_v5(
    receiver_node_id: &[u8; NODE_ID_LEN],
    rendezvous_node_id: &[u8; NODE_ID_LEN],
    auth_cookie: &[u8; AUTH_COOKIE_LEN],
    receiver_x25519_pk: &[u8; X25519_PK_LEN],
    valid_from_unix: u64,
    valid_until_unix: u64,
    push_envelope: &[u8],
    capability_token: &[u8],
    wake_hmac_envelope: &[u8],
    rendezvous_kem_algo: u8,
    rendezvous_kem_pk: &[u8],
    issuer_pk_bytes: &[u8],
    issuer_algo: SignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, RendezvousError> {
    let mut out = Vec::with_capacity(
        2 + 1
            + 1
            + NODE_ID_LEN * 2
            + AUTH_COOKIE_LEN
            + X25519_PK_LEN
            + 16
            + 2
            + push_envelope.len()
            + 2
            + capability_token.len()
            + 2
            + wake_hmac_envelope.len()
            + 1
            + 2
            + rendezvous_kem_pk.len()
            + 2
            + issuer_pk_bytes.len()
            + 2
            + signature.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(receiver_node_id);
    out.extend_from_slice(rendezvous_node_id);
    out.extend_from_slice(auth_cookie);
    out.extend_from_slice(receiver_x25519_pk);
    out.extend_from_slice(&valid_from_unix.to_be_bytes());
    out.extend_from_slice(&valid_until_unix.to_be_bytes());
    out.extend_from_slice(&(push_envelope.len() as u16).to_be_bytes());
    out.extend_from_slice(push_envelope);
    out.extend_from_slice(&(capability_token.len() as u16).to_be_bytes());
    out.extend_from_slice(capability_token);
    out.extend_from_slice(&(wake_hmac_envelope.len() as u16).to_be_bytes());
    out.extend_from_slice(wake_hmac_envelope);
    out.push(rendezvous_kem_algo);
    out.extend_from_slice(&(rendezvous_kem_pk.len() as u16).to_be_bytes());
    out.extend_from_slice(rendezvous_kem_pk);
    out.extend_from_slice(&(issuer_pk_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk_bytes);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

fn read<'a>(blob: &'a [u8], cursor: &mut usize, n: usize) -> Result<&'a [u8], RendezvousError> {
    if *cursor + n > blob.len() {
        return Err(RendezvousError::Malformed(format!(
            "ran past blob end: cursor={} need={n} len={}",
            cursor,
            blob.len()
        )));
    }
    let s = &blob[*cursor..*cursor + n];
    *cursor += n;
    Ok(s)
}

// ── receiver-side DHT republish loop ────────────────────────────────

/// One rendezvous publication that the receiver wants to keep alive.
///
/// The receiver registers `(rendezvous_node_id, auth_cookie, validity_window)`
/// once via `register_rendezvous_publisher`; the runtime's maintenance
/// tick re-signs + re-stores the resulting `RendezvousAd` to the DHT
/// before its `valid_until_unix` lapses, so senders fetching the ad
/// always see a freshly-signed entry.
#[derive(Debug, Clone, PartialEq)]
pub struct RendezvousPublisherEntry {
    /// Third-party meeting point. Must already have an OVL1 session
    /// open (via `connect_peer` or configured-peer dial); the receiver
    /// is also responsible for `register_with_rendezvous` to wire the
    /// cookie there.
    pub rendezvous_node_id: [u8; NODE_ID_LEN],
    /// Shared auth cookie. Same value the receiver passes to
    /// `register_with_rendezvous`.
    pub auth_cookie: [u8; AUTH_COOKIE_LEN],
    /// Lifetime of each signed ad. Maintenance re-signs at half-life.
    /// Hard-capped to [`MAX_VALIDITY_WINDOW_SECS`] (30 days) by sign.
    pub validity_window_secs: u64,
    /// opaque sealed push envelope (FCM/APNs token sealed
    /// for a trusted push-relay operator). Empty (`vec![]`) when the
    /// receiver has not registered for push. Persisted across re-signs;
    /// receiver updates it via a separate IPC call (TBD slice) when
    /// the underlying token rotates.
    pub push_envelope: Vec<u8>,
    /// opaque sealed wake-HMAC envelope (Epic 489.10 slice 4.3.2).
    /// Wraps the receiver's `WakeHmacKey` to the same push-relay's
    /// X25519 pubkey so relay can sign wake-up payloads receivers
    /// verify locally.  Empty (`vec![]`) when the receiver did not
    /// register for wake-HMAC authentication (defaults to opt-out
    /// for backward compat with pre-v4 ads).  Persisted across re-signs;
    /// receiver updates via a separate IPC call (slice 4.3.3) when
    /// the underlying key rotates.
    pub wake_hmac_envelope: Vec<u8>,
    /// The rendezvous RELAY's KEM algorithm tag + public key, published in the
    /// v5 ad ([`RendezvousAd::rendezvous_kem_pk`]) so a sender can anonymously
    /// deposit a mailbox PUT directly at the relay. `algo = 0` + empty `pk`
    /// means "no relay key advertised" (the default — senders fall back to the
    /// live rendezvous path). Set by the receiver at registration from the
    /// relay's X25519 pubkey (the same key it sealed [`Self::push_envelope`]
    /// to). NOT advertised for ephemeral/onion-service ads (those are reached
    /// via the blinded descriptor, not mailbox PUTs).
    pub rendezvous_kem_algo: u8,
    pub rendezvous_kem_pk: Vec<u8>,
    /// Per-service EPHEMERAL signing identity (diff-audit Δ2-c). `Some` for a
    /// LOCATION-ANONYMOUS (onion) service: the ad is signed + DHT-keyed under
    /// this pseudo identity instead of the real sovereign node_id, so it no
    /// longer publicly links the service identity to its live rendezvous point.
    /// `None` for a plain rendezvous receiver (signed under the sovereign
    /// identity, as senders discover it by the receiver's real node_id).
    pub ephemeral_ad_identity: Option<EphemeralAdIdentity>,
}

/// A per-service ephemeral identity used to sign + DHT-key a rendezvous ad
/// WITHOUT revealing the service's sovereign node_id (diff-audit Δ2-c). Derived
/// from a location-anonymous service's per-service registration keypair.
/// `pseudo_node_id == BLAKE3(public_key bytes)`, matching the ad verifier's
/// issuer↔node_id binding, so the pseudo-signed ad verifies normally.
#[derive(Debug, Clone, PartialEq)]
pub struct EphemeralAdIdentity {
    /// `BLAKE3(decoded public_key)` — the ad's `receiver_node_id` + DHT key base.
    pub pseudo_node_id: [u8; NODE_ID_LEN],
    /// Base64 Ed25519 public key (the ad's issuer pk).
    pub public_key: String,
    /// Base64 Ed25519 private key (signs the ad).
    pub private_key: String,
    /// Signature algorithm (Ed25519 for onion-service registration keys).
    pub algo: SignatureAlgorithm,
}

impl EphemeralAdIdentity {
    /// Build from a base64 keypair; `pseudo_node_id = BLAKE3(decoded pubkey)` so
    /// the resulting ad satisfies the verifier's issuer↔node_id binding.
    /// `None` if the public key is not valid base64.
    pub fn from_b64_keypair(
        public_key: String,
        private_key: String,
        algo: SignatureAlgorithm,
    ) -> Option<Self> {
        let pk_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &public_key).ok()?;
        let pseudo_node_id = *blake3::hash(&pk_bytes).as_bytes();
        Some(Self {
            pseudo_node_id,
            public_key,
            private_key,
            algo,
        })
    }
}

/// Default window for signed RendezvousAds — 1 day. Short enough to
/// limit damage from a captured ad (censor can replay max 24h before
/// it expires); long enough that maintenance only needs to re-sign
/// every ~12 hours, keeping DHT churn proportionate to real receiver
/// presence rather than to refresh cadence.
pub const DEFAULT_RENDEZVOUS_VALIDITY_SECS: u64 = 24 * 3600;

/// Refresh threshold — when `valid_until - now <= half-window`
/// the maintenance tick re-signs the ad. Half-life is the standard
/// "republish at 50%" pattern used elsewhere in the codebase
/// (sovereign-identity, local announcement, relay-directory).
///
/// refactored from
/// `now + half_window >= valid_until` to a subtraction-based form so
/// that an `now ≥ valid_until` (already-expired ad) returns true
/// regardless of overflow; and a far-future `valid_until` (very long
/// validity windows; legitimate config typo) doesn't accidentally
/// saturate `now + half_window` to `u64::MAX` and force a spurious
/// refresh on every tick. Subtraction always remains in range.
pub fn rendezvous_ad_needs_refresh(
    valid_until_unix: u64,
    now_unix: u64,
    validity_window_secs: u64,
) -> bool {
    let half_window = validity_window_secs / 2;
    if now_unix >= valid_until_unix {
        // Already expired — definitely refresh.
        return true;
    }
    let remaining = valid_until_unix - now_unix; // safe: now < valid_until from above
    remaining <= half_window
}

// ── Slices 2-4: rendezvous-relay state machine + crypto + wire types ─────────

/// Final-hop payload tag — distinguishes the kind of inner payload
/// the Final-hop expects. Direct-delivery pre-refactor payloads
/// were untagged; we add a 1-byte tag so the dispatcher can branch
/// between AppDeliver and Introduce without heuristic decode-then-fallback.
///
/// Wire-breaking change vs — the network is not yet live.
pub mod final_hop_kind {
    /// Body is a `crate::proto::AppDeliverPayload` — Final-hop is
    /// the destination and delivers locally via app_registry. The
    /// `src_node_id` is anonymous-to-recipient (zeroed / unauthenticated).
    pub const APP_DELIVER: u8 = 0x01;
    /// Body is a [`super::IntroducePayload`] — Final-hop is a
    /// rendezvous and forwards to the registered subscriber.
    pub const INTRODUCE: u8 = 0x02;
    /// Body is a `veil_proto::AuthAppDeliver` — Final-hop is the destination and
    /// delivers locally AFTER cryptographically verifying the sender's identity
    /// (authenticated onion delivery v1). Unlike [`APP_DELIVER`], the recipient
    /// learns + verifies WHO sent the message.
    pub const APP_DELIVER_AUTH: u8 = 0x03;
    /// Body is an `AuthDeliverFragment` framing chunk, reused as a bounded
    /// generic byte reassembly envelope for an UNAUTHENTICATED
    /// `AppDeliverPayload`. The completed delivery always surfaces a zero
    /// src_node_id; this supports capability traffic larger than one introduce
    /// without turning it into an identity-bearing authenticated send.
    pub const APP_DELIVER_FRAGMENT: u8 = 0x04;
}

/// Cap on `IntroducePayload.ciphertext` length. Sized to the Final-hop budget
/// of a 2-hop circuit: `[1 B onion tag] + IntroducePayload` (50 B fixed) +
/// ciphertext must fit `max_payload_for_hops(2)` (~348 B), so the ciphertext
/// can be ~297 B. 320 leaves a small margin and keeps the wire format
/// predictable; the authenticated fragmentation path clamps each fragment to
/// the actual per-hop budget regardless.
pub const MAX_INTRODUCE_CIPHERTEXT: usize = 320;

const INTRODUCE_DOMAIN: &[u8] = b"veil-introduce-v1\0";
const INTRODUCE_NONCE_LEN: usize = 12;
const INTRODUCE_TAG_LEN: usize = 16;
/// Per-`encrypt_introduce` ciphertext overhead: ephemeral X25519 pubkey +
/// nonce + AEAD tag. `ciphertext.len() == plaintext.len() + INTRODUCE_OVERHEAD`.
pub const INTRODUCE_OVERHEAD: usize = X25519_PK_LEN + INTRODUCE_NONCE_LEN + INTRODUCE_TAG_LEN;

/// Sender-built Introduce payload that the rendezvous receives as
/// the Final-hop of an onion circuit and forwards to the receiver
/// registered under `auth_cookie`.
///
/// Wire layout:
/// ```text
/// [0..32] receiver_node_id [u8; 32]
/// [32..48] auth_cookie [u8; 16]
/// [48..50] ciphertext_len u16 BE (≤ MAX_INTRODUCE_CIPHERTEXT)
/// [50..] ciphertext bytes — X25519+ChaCha20Poly1305 sealed
/// to receiver_x25519_pk; decrypts to an
/// inner `AppDeliverPayload`.
/// ```
///
/// `ciphertext` shape (matches `encrypt_introduce` output):
/// `[32B sender_eph_pk][12B nonce][AEAD ciphertext + 16B tag]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroducePayload {
    pub receiver_node_id: [u8; NODE_ID_LEN],
    pub auth_cookie: [u8; AUTH_COOKIE_LEN],
    pub ciphertext: Vec<u8>,
}

impl IntroducePayload {
    pub const FIXED_SIZE: usize = NODE_ID_LEN + AUTH_COOKIE_LEN + 2;

    pub fn encode(&self) -> Result<Vec<u8>, RendezvousError> {
        if self.ciphertext.len() > MAX_INTRODUCE_CIPHERTEXT {
            return Err(RendezvousError::Malformed(format!(
                "introduce ciphertext {} > MAX {MAX_INTRODUCE_CIPHERTEXT}",
                self.ciphertext.len()
            )));
        }
        let mut out = Vec::with_capacity(Self::FIXED_SIZE + self.ciphertext.len());
        out.extend_from_slice(&self.receiver_node_id);
        out.extend_from_slice(&self.auth_cookie);
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(blob: &[u8]) -> Result<Self, RendezvousError> {
        if blob.len() < Self::FIXED_SIZE {
            return Err(RendezvousError::Malformed(format!(
                "introduce too short: {} < {}",
                blob.len(),
                Self::FIXED_SIZE
            )));
        }
        let mut receiver_node_id = [0u8; NODE_ID_LEN];
        receiver_node_id.copy_from_slice(&blob[..NODE_ID_LEN]);
        let mut auth_cookie = [0u8; AUTH_COOKIE_LEN];
        auth_cookie.copy_from_slice(&blob[NODE_ID_LEN..NODE_ID_LEN + AUTH_COOKIE_LEN]);
        let len_off = NODE_ID_LEN + AUTH_COOKIE_LEN;
        let ciphertext_len = u16::from_be_bytes([blob[len_off], blob[len_off + 1]]) as usize;
        if ciphertext_len > MAX_INTRODUCE_CIPHERTEXT {
            return Err(RendezvousError::Malformed(format!(
                "introduce ciphertext_len {ciphertext_len} > MAX {MAX_INTRODUCE_CIPHERTEXT}"
            )));
        }
        let total = Self::FIXED_SIZE + ciphertext_len;
        // Exact-length: reject trailing bytes as well as truncation. A blob
        // longer than `total` carries unparsed bytes that no honest encoder
        // produces — accepting them would let a peer smuggle data past the
        // frame boundary (and silently de-sync any length-prefixed framing).
        if blob.len() != total {
            return Err(RendezvousError::Malformed(format!(
                "introduce length mismatch: have {}, need {total}",
                blob.len()
            )));
        }
        Ok(Self {
            receiver_node_id,
            auth_cookie,
            ciphertext: blob[Self::FIXED_SIZE..total].to_vec(),
        })
    }
}

/// Receiver → rendezvous: register interest in a specific
/// `auth_cookie`. The rendezvous holds (cookie → subscriber session)
/// in memory; on cookie collision (different receiver tries to claim
/// an existing cookie), the rendezvous rejects silently — receivers
/// generate cookies cryptographically (16 B random) so collision is
/// negligible.
///
/// Wire layout: `[32B receiver_x25519_pk_check][16B auth_cookie]`.
///
/// `receiver_x25519_pk_check` is included so the rendezvous can
/// log / audit which key the cookie was bound (it does NOT use
/// it to decrypt anything — payloads are sealed to receiver_x25519_pk
/// in the IntroducePayload itself, sealed-box style).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRendezvousPayload {
    pub receiver_x25519_pk: [u8; X25519_PK_LEN],
    pub auth_cookie: [u8; AUTH_COOKIE_LEN],
}

impl RegisterRendezvousPayload {
    pub const WIRE_SIZE: usize = X25519_PK_LEN + AUTH_COOKIE_LEN;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        out[..X25519_PK_LEN].copy_from_slice(&self.receiver_x25519_pk);
        out[X25519_PK_LEN..].copy_from_slice(&self.auth_cookie);
        out
    }

    pub fn decode(blob: &[u8]) -> Result<Self, RendezvousError> {
        if blob.len() != Self::WIRE_SIZE {
            return Err(RendezvousError::Malformed(format!(
                "register: expected {} B, got {}",
                Self::WIRE_SIZE,
                blob.len()
            )));
        }
        let mut receiver_x25519_pk = [0u8; X25519_PK_LEN];
        receiver_x25519_pk.copy_from_slice(&blob[..X25519_PK_LEN]);
        let mut auth_cookie = [0u8; AUTH_COOKIE_LEN];
        auth_cookie.copy_from_slice(&blob[X25519_PK_LEN..]);
        Ok(Self {
            receiver_x25519_pk,
            auth_cookie,
        })
    }
}

/// Receiver → rendezvous: stop forwarding for a previously registered
/// cookie. Wire layout: `[16B auth_cookie]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnregisterRendezvousPayload {
    pub auth_cookie: [u8; AUTH_COOKIE_LEN],
}

impl UnregisterRendezvousPayload {
    pub const WIRE_SIZE: usize = AUTH_COOKIE_LEN;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.auth_cookie
    }

    pub fn decode(blob: &[u8]) -> Result<Self, RendezvousError> {
        if blob.len() != Self::WIRE_SIZE {
            return Err(RendezvousError::Malformed(format!(
                "unregister: expected {} B, got {}",
                Self::WIRE_SIZE,
                blob.len()
            )));
        }
        let mut auth_cookie = [0u8; AUTH_COOKIE_LEN];
        auth_cookie.copy_from_slice(blob);
        Ok(Self { auth_cookie })
    }
}

/// Rendezvous → receiver: forward an Introduce ciphertext over the
/// established OVL1 session. The receiver decrypts and routes the
/// inner `AppDeliverPayload` locally.
///
/// Wire layout: `[u16 BE ciphertext_len][ciphertext bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardIntroducePayload {
    pub ciphertext: Vec<u8>,
}

impl ForwardIntroducePayload {
    pub fn encode(&self) -> Result<Vec<u8>, RendezvousError> {
        if self.ciphertext.len() > MAX_INTRODUCE_CIPHERTEXT {
            return Err(RendezvousError::Malformed(format!(
                "forward ciphertext {} > MAX {MAX_INTRODUCE_CIPHERTEXT}",
                self.ciphertext.len()
            )));
        }
        let mut out = Vec::with_capacity(2 + self.ciphertext.len());
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(blob: &[u8]) -> Result<Self, RendezvousError> {
        if blob.len() < 2 {
            return Err(RendezvousError::Malformed(format!(
                "forward too short: {} < 2",
                blob.len()
            )));
        }
        let len = u16::from_be_bytes([blob[0], blob[1]]) as usize;
        if len > MAX_INTRODUCE_CIPHERTEXT {
            return Err(RendezvousError::Malformed(format!(
                "forward ciphertext_len {len} > MAX {MAX_INTRODUCE_CIPHERTEXT}"
            )));
        }
        if blob.len() < 2 + len {
            return Err(RendezvousError::Malformed(format!(
                "forward truncated: have {}, need {}",
                blob.len(),
                2 + len
            )));
        }
        Ok(Self {
            ciphertext: blob[2..2 + len].to_vec(),
        })
    }
}

// ── Sealed-box style sender → receiver encryption ────────────────────────────

/// Encrypt `plaintext` to the recipient's X25519 pubkey. Generates a
/// fresh ephemeral keypair for this call (forward secrecy: leaking
/// the ciphertext + later compromise of the recipient's long-term
/// X25519 sk does NOT reveal the plaintext if the ephemeral SK was
/// truly random — `OsRng` here). Output is `[32B eph_pk][12B nonce]
/// [AEAD ciphertext + 16B tag]`.
///
/// AEAD: ChaCha20-Poly1305 with key = BLAKE3 of the X25519 shared
/// secret and AAD = `INTRODUCE_DOMAIN` + ephemeral_pk + nonce. AAD
/// binding catches tampering of any header field — in particular
/// substituting a different ephemeral_pk fails AEAD verification and
/// closes the cross-protocol replay attack from `wrap_for_hop`.
pub fn encrypt_introduce(
    plaintext: &[u8],
    recipient_x25519_pk: &[u8; X25519_PK_LEN],
) -> Result<Vec<u8>, RendezvousError> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let eph_pk = PublicKey::from(&eph_sk);
    let recipient_pk = PublicKey::from(*recipient_x25519_pk);
    let shared = eph_sk.diffie_hellman(&recipient_pk);
    // refuse low-order / non-contributory shared
    // secrets. If `recipient_x25519_pk` is one of the small-set
    // "torsion" points the X25519 spec admits, the shared secret
    // collapses to all-zeros — and an attacker who supplied that
    // pubkey can decrypt the resulting AEAD output by pre-deriving
    // the same key from the known shared. Hard-fail loudly so an
    // accidental small-order recipient pubkey doesn't silently leak
    // plaintext to anyone who holds (publicly-known) low-order
    // private key.
    if !shared.was_contributory() {
        return Err(RendezvousError::Malformed(
            "recipient X25519 pubkey is a low-order / non-contributory point".to_owned(),
        ));
    }

    // Derive AEAD key = BLAKE3(domain || shared). Domain prefix
    // prevents the same shared-secret derivation from reuse in a
    // future protocol that also DH-es to the same recipient pubkey.
    let mut h = blake3::Hasher::new();
    h.update(INTRODUCE_DOMAIN);
    h.update(shared.as_bytes());
    let key_bytes = h.finalize();
    let key = Key::from_slice(key_bytes.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; INTRODUCE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut aad = Vec::with_capacity(INTRODUCE_DOMAIN.len() + X25519_PK_LEN + INTRODUCE_NONCE_LEN);
    aad.extend_from_slice(INTRODUCE_DOMAIN);
    aad.extend_from_slice(eph_pk.as_bytes());
    aad.extend_from_slice(&nonce_bytes);

    let ct_with_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| RendezvousError::Malformed(format!("AEAD encrypt: {e}")))?;

    let mut out = Vec::with_capacity(INTRODUCE_OVERHEAD + plaintext.len());
    out.extend_from_slice(eph_pk.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct_with_tag);
    Ok(out)
}

/// Decrypt a sealed-box ciphertext built by [`encrypt_introduce`] using
/// the recipient's X25519 secret. Returns the plaintext, or
/// [`RendezvousError::Verify`] on AEAD failure (wrong key, tampered
/// fields, or replacement eph_pk).
pub fn decrypt_introduce(
    ciphertext: &[u8],
    recipient_x25519_sk: &x25519_dalek::StaticSecret,
) -> Result<Vec<u8>, RendezvousError> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    use x25519_dalek::PublicKey;

    if ciphertext.len() < INTRODUCE_OVERHEAD {
        return Err(RendezvousError::Malformed(format!(
            "introduce ciphertext too short: {} < {INTRODUCE_OVERHEAD}",
            ciphertext.len()
        )));
    }
    let mut eph_pk_bytes = [0u8; X25519_PK_LEN];
    eph_pk_bytes.copy_from_slice(&ciphertext[..X25519_PK_LEN]);
    let mut nonce_bytes = [0u8; INTRODUCE_NONCE_LEN];
    nonce_bytes.copy_from_slice(&ciphertext[X25519_PK_LEN..X25519_PK_LEN + INTRODUCE_NONCE_LEN]);
    let aead_payload = &ciphertext[X25519_PK_LEN + INTRODUCE_NONCE_LEN..];

    let eph_pk = PublicKey::from(eph_pk_bytes);
    let shared = recipient_x25519_sk.diffie_hellman(&eph_pk);
    // refuse a non-contributory eph_pk on the
    // wire. An attacker that submits one of the X25519 small-order
    // "torsion" points forces the shared secret to all-zeros — they
    // can then derive the same AEAD key locally and freely decrypt
    // (and forge) Introduce ciphertexts addressed at us, breaking
    // the unlinkability premise of the rendezvous flow.
    if !shared.was_contributory() {
        return Err(RendezvousError::Malformed(
            "introduce eph_pk is a low-order / non-contributory point".to_owned(),
        ));
    }

    let mut h = blake3::Hasher::new();
    h.update(INTRODUCE_DOMAIN);
    h.update(shared.as_bytes());
    let key_bytes = h.finalize();
    let key = Key::from_slice(key_bytes.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut aad = Vec::with_capacity(INTRODUCE_DOMAIN.len() + X25519_PK_LEN + INTRODUCE_NONCE_LEN);
    aad.extend_from_slice(INTRODUCE_DOMAIN);
    aad.extend_from_slice(&eph_pk_bytes);
    aad.extend_from_slice(&nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: aead_payload,
                aad: &aad,
            },
        )
        .map_err(|_| RendezvousError::Verify)
}

// ── Introduce-frame replay cache ──────────────────────

/// Maximum entries in [`IntroduceReplayCache`]. At ~24 B per
/// entry (16 B fingerprint + u64 expiry + map overhead), 65536 ≈
/// 1.5 MiB worst-case memory. When the cap is reached the cache
/// drops the FIFO-OLDEST entry (`queue.pop_front`), never an
/// iteration-order-arbitrary one — so an attacker pumping unique
/// fingerprints can only force-evict the oldest end, never the
/// freshly-recorded legitimate entry it is racing. The worst outcome
/// is that a force-evicted fingerprint becomes replay-able again
/// before its TTL would have expired.
pub const MAX_INTRODUCE_REPLAY_ENTRIES: usize = 65_536;

/// Replay-window for an Introduce-frame fingerprint. An ad's
/// `valid_until_unix` is the real upper bound on when a captured
/// Introduce can still be redirected to the receiver, and that bound
/// can be as high as [`MAX_VALIDITY_WINDOW_SECS`] (30 days). The TTL is
/// therefore pinned to that maximum so a single captured Introduce
/// cannot be replayed within ANY legal ad lifetime — the previous
/// 1-day value left a replay window for any ad published with a
/// validity > 1 day (e.g. the common 7-30 day ads).
///
/// This does NOT change the cache's memory bound: that is governed by
/// [`MAX_INTRODUCE_REPLAY_ENTRIES`] (FIFO cap), not the TTL. Under
/// sustained volume exceeding the cap, the FIFO cap-evict drops only
/// the OLDEST fingerprints (never freshly-recorded legitimate ones),
/// so the longer TTL trades a slightly higher steady-state occupancy
/// for full-lifetime replay protection.
pub const INTRODUCE_REPLAY_TTL_SECS: u64 = MAX_VALIDITY_WINDOW_SECS;

/// replay-protection cache for Introduce
/// frames. Each fingerprint is `BLAKE3(eph_pk || nonce)[..16]`
/// computed BEFORE the AEAD decrypt so a replay flood is rejected
/// without spending CPU on AEAD verification.
///
/// Without this cache, a captured Introduce ciphertext can be
/// re-submitted indefinitely to the rendezvous (or directly to the
/// receiver via a forwarded ForwardIntroducePayload), and the
/// receiver will keep decrypting + delivering the same plaintext —
/// defeating the rendezvous's anonymity claim, enabling
/// timing-oracle measurements at the receiver, and exhausting the
/// receiver's app_registry.
/// FIFO-ordered replay-cache state. replaces the
/// prior `HashMap<fp, expiry>` (whose `g.keys.next` eviction was non-
/// deterministic — let an attacker pumping unique fingerprints force-evict
/// arbitrary legitimate entries to make their previously-captured Introduce
/// replayable) with a VecDeque<(fp, expiry)> + HashSet<fp> pair providing
/// O(1) FIFO eviction. Attacker-forced evictions now come from the oldest
/// end ONLY — newly-arrived legitimate fingerprints survive until N more
/// entries have been recorded after them.
struct ReplayState {
    /// Insertion-ordered queue (fingerprint, expiry_unix).
    /// Both ends are popped: front during lazy-GC + cap-evict.
    queue: std::collections::VecDeque<([u8; 16], u64)>,
    /// O(1) membership lookup keyed by fingerprint.
    set: std::collections::HashSet<[u8; 16]>,
}

impl ReplayState {
    fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            set: std::collections::HashSet::new(),
        }
    }
}

pub struct IntroduceReplayCache {
    seen: std::sync::Mutex<ReplayState>,
    ttl_secs: u64,
}

impl Default for IntroduceReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IntroduceReplayCache {
    /// Construct a cache with the default TTL.
    pub fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(ReplayState::new()),
            ttl_secs: INTRODUCE_REPLAY_TTL_SECS,
        }
    }

    /// Construct a cache with an explicit TTL. Used by tests.
    #[cfg(test)]
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            seen: std::sync::Mutex::new(ReplayState::new()),
            ttl_secs,
        }
    }

    /// Compute the canonical fingerprint for an Introduce frame —
    /// `BLAKE3(eph_pk || nonce)[..16]`. Length-prefixed by the
    /// fixed-size inputs (no ambiguity).
    fn fingerprint(eph_pk: &[u8; X25519_PK_LEN], nonce: &[u8; INTRODUCE_NONCE_LEN]) -> [u8; 16] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.introduce.replay.v1");
        h.update(eph_pk);
        h.update(nonce);
        let full = h.finalize();
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&full.as_bytes()[..16]);
        fp
    }

    /// Check whether `(eph_pk, nonce)` has been seen before; if so
    /// return [`RendezvousError::Replay`]. Otherwise record the
    /// fingerprint for future lookups and return `Ok`.
    ///
    /// Performs a lazy GC of expired entries on every call so the
    /// cache never grows unboundedly.
    pub fn check_and_record(
        &self,
        eph_pk: &[u8; X25519_PK_LEN],
        nonce: &[u8; INTRODUCE_NONCE_LEN],
        now_unix: u64,
    ) -> Result<(), RendezvousError> {
        let fp = Self::fingerprint(eph_pk, nonce);
        let mut g = match self.seen.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // lazy GC of expired entries from the front. Queue
        // is insertion-ordered, and all entries have the same TTL, so the
        // front always carries the oldest expiry. Pop while expired.
        while let Some(&(fp_old, exp)) = g.queue.front() {
            if now_unix < exp {
                break;
            }
            g.queue.pop_front();
            g.set.remove(&fp_old);
        }
        if g.set.contains(&fp) {
            return Err(RendezvousError::Replay);
        }
        // cap-eviction — drop FIFO oldest, NOT
        // HashMap-iteration-order-arbitrary. Attacker pumping unique
        // fingerprints can only force-evict the OLDEST end, never not
        // newly-recorded legitimate entries.
        if g.set.len() >= MAX_INTRODUCE_REPLAY_ENTRIES
            && let Some((fp_old, _)) = g.queue.pop_front()
        {
            g.set.remove(&fp_old);
        }
        g.queue
            .push_back((fp, now_unix.saturating_add(self.ttl_secs)));
        g.set.insert(fp);
        Ok(())
    }

    /// Number of currently-tracked fingerprints. Exposed for metrics
    /// and tests.
    pub fn len(&self) -> usize {
        self.seen.lock().map(|g| g.set.len()).unwrap_or(0)
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// replay-protected variant of
/// [`decrypt_introduce`]. Performs (eph_pk, nonce) replay check
/// against `cache` BEFORE the AEAD decrypt so a replay flood costs
/// only a HashMap lookup per packet, not a full ChaCha20Poly1305
/// verification.
///
/// On `Ok`, the fingerprint has been recorded; subsequent decrypts of
/// the same ciphertext return [`RendezvousError::Replay`].
///
/// Caller passes `now_unix` for testability + clock-skew control.
pub fn decrypt_introduce_checked(
    ciphertext: &[u8],
    recipient_x25519_sk: &x25519_dalek::StaticSecret,
    cache: &IntroduceReplayCache,
    now_unix: u64,
) -> Result<Vec<u8>, RendezvousError> {
    if ciphertext.len() < INTRODUCE_OVERHEAD {
        return Err(RendezvousError::Malformed(format!(
            "introduce ciphertext too short: {} < {INTRODUCE_OVERHEAD}",
            ciphertext.len()
        )));
    }
    let mut eph_pk_bytes = [0u8; X25519_PK_LEN];
    eph_pk_bytes.copy_from_slice(&ciphertext[..X25519_PK_LEN]);
    let mut nonce_bytes = [0u8; INTRODUCE_NONCE_LEN];
    nonce_bytes.copy_from_slice(&ciphertext[X25519_PK_LEN..X25519_PK_LEN + INTRODUCE_NONCE_LEN]);
    // Replay check FIRST — cheaper than AEAD on a flood, and it
    // doesn't matter if a fingerprint is recorded for a malformed
    // ciphertext (an attacker can already spam fingerprints with
    // valid AEAD anyway, so the cache cost is symmetric).
    cache.check_and_record(&eph_pk_bytes, &nonce_bytes, now_unix)?;
    decrypt_introduce(ciphertext, recipient_x25519_sk)
}

// ── Rendezvous-side cookie registry ──────────────────────────────────────────

/// Per-cookie subscriber entry held by the rendezvous node. Maps an
/// `auth_cookie` to the subscriber's session peer_id, used to look up
/// their OVL1 session-tx for forwarding.
///
/// derives `Zeroize` + `ZeroizeOnDrop` so the
/// `(peer_node_id, receiver_x25519_pk)` pair is wiped from memory
/// when the entry leaves the registry (eviction, drop_subscriber
/// process exit) — bounds the linkability window for any future
/// memory-disclosure bug.
#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RendezvousSubscriber {
    pub peer_node_id: [u8; NODE_ID_LEN],
    /// Receiver's X25519 pubkey for audit / log purposes. The
    /// rendezvous does NOT decrypt anything — payloads are sealed to
    /// this key by the sender.
    pub receiver_x25519_pk: [u8; X25519_PK_LEN],
    pub registered_at_unix: u64,
}

/// In-memory `(peer_node_id, cookie)` → subscriber map. Bounded and
/// thread-safe.
///
/// The map is keyed by the **pair** of the registrant's authenticated
/// OVL1 `peer_node_id` *and* the cookie — not the cookie alone. The
/// `auth_cookie` is published in the receiver's DHT rendezvous-ad and
/// is therefore readable by anyone. Keying by cookie alone let an
/// attacker who scraped a victim's ad `register()` that cookie first
/// under their own session and lock the genuine receiver out with a
/// cookie-collision rejection — a pure availability DoS (the squatter could
/// never *read* the sender's Introduce, since those are sealed to the
/// receiver's X25519 key and the relay also matches
/// `intro.receiver_node_id` against the registrant, but the receiver
/// could no longer register). Namespacing by `peer_node_id` lets the
/// attacker's `(attacker, cookie)` and the victim's `(victim, cookie)`
/// coexist: the attacker's dead entry is never looked up (the
/// Introduce relay keys lookups by the ad's `receiver_node_id`), and
/// the victim is never blocked.
///
/// Bounded by `MAX_REGISTRATIONS` to prevent a single rogue receiver
/// from exhausting rendezvous memory by registering millions of cookies.
/// On overflow, new registrations are rejected (operator-friendly:
/// they get an explicit error, not silent drop, since this is a
/// receiver-controlled flow not a sender-probe).
pub struct RendezvousRegistry {
    inner: std::sync::Mutex<RendezvousRegistryInner>,
    max_registrations: usize,
}

/// Registry key: the registrant's authenticated `peer_node_id` paired
/// with the cookie. See [`RendezvousRegistry`] for why the cookie alone
/// is insufficient.
type RegistrationKey = ([u8; NODE_ID_LEN], [u8; AUTH_COOKIE_LEN]);

struct RendezvousRegistryInner {
    cookies: std::collections::HashMap<RegistrationKey, RendezvousSubscriber>,
    /// O(1) per-peer registration count, kept in lockstep with `cookies`
    /// (audit cycle-10). The cycle-9 per-peer fairness cap counted a peer's
    /// entries by scanning the WHOLE table (`cookies.keys().filter(..).count()`)
    /// on EVERY register — an always-on O(n) under the registry mutex, n up to
    /// `max_registrations` (10k default). This map makes that count O(1).
    /// Invariant: `per_peer[p]` == number of keys `(p, _)` in `cookies`, and a
    /// peer is absent from the map iff its count is 0. All mutations go through
    /// `insert_cookie` / `remove_cookie` (or the two retain sweeps, which fix
    /// the map up explicitly) so the two maps can never drift.
    per_peer: std::collections::HashMap<[u8; NODE_ID_LEN], usize>,
}

impl RendezvousRegistryInner {
    /// Insert or refresh a cookie, keeping `per_peer` in sync. A refresh
    /// (key already present) leaves the count unchanged.
    fn insert_cookie(&mut self, key: RegistrationKey, sub: RendezvousSubscriber) {
        let peer = key.0;
        if self.cookies.insert(key, sub).is_none() {
            *self.per_peer.entry(peer).or_insert(0) += 1;
        }
    }

    /// Remove a cookie, keeping `per_peer` in sync. Returns the removed
    /// subscriber, if any.
    fn remove_cookie(&mut self, key: &RegistrationKey) -> Option<RendezvousSubscriber> {
        let removed = self.cookies.remove(key);
        if removed.is_some()
            && let Some(c) = self.per_peer.get_mut(&key.0)
        {
            *c -= 1;
            if *c == 0 {
                self.per_peer.remove(&key.0);
            }
        }
        removed
    }

    /// O(1) count of live registrations for `peer`.
    fn peer_count(&self, peer: &[u8; NODE_ID_LEN]) -> usize {
        self.per_peer.get(peer).copied().unwrap_or(0)
    }
}

/// Default cap on rendezvous registrations. 10k cookies × ~80 B per
/// entry ≈ 800 KiB — comfortable on a 1 vCPU / 1 GiB VPS even with
/// other load. Operators can override at construction time.
pub const DEFAULT_MAX_RENDEZVOUS_REGISTRATIONS: usize = 10_000;

/// Per-peer fairness cap on rendezvous registrations (audit cycle-9). A
/// legitimate receiver needs only a handful of live cookies; this generous
/// ceiling stops a single authenticated peer from filling the registry and
/// LRU-evicting every other principal, while leaving ample room for cookie
/// rotation. With the 10 000 global cap that is ~156 distinct peers minimum.
pub const MAX_COOKIES_PER_PEER: usize = 64;

/// maximum age of a rendezvous registration
/// before it's lazily evicted. Without a TTL, stale `(peer_node_id
/// receiver_x25519_pk)` pairs accumulate over the lifetime of the
/// process and create a long-term linkability surface — a relay that
/// runs for months could correlate the same receiver across many
/// senders and rendezvous points by simply observing which cookies
/// stay live. 6 hours is comfortably longer than typical
/// rendezvous-ad republish cadences (which refresh every 1-2 hours)
/// while bounding the linkability window.
pub const DEFAULT_RENDEZVOUS_REGISTRY_TTL_SECS: u64 = 6 * 3600;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RegistryError {
    #[error("registry full ({cap} entries) — refusing new registration")]
    Full { cap: usize },
    /// a same-peer re-registration tried to swap
    /// `receiver_x25519_pk` without going through unregister-first.
    /// Silently allowing the swap is a receiver-pivot vector — an
    /// active-MITM on the rendezvous publication path could swap in a
    /// pubkey it controls and decrypt every subsequent Introduce.
    /// Peers that legitimately want to rotate their X25519 key must
    /// `unregister(cookie)` and then `register(new_cookie...)`.
    #[error(
        "X25519 pubkey rotation requires fresh cookie (current cookie still bound to a different x25519_pk)"
    )]
    PubkeyRotationNeedsFreshCookie,
}

impl Default for RendezvousRegistry {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_RENDEZVOUS_REGISTRATIONS)
    }
}

impl RendezvousRegistry {
    pub fn with_capacity(max_registrations: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(RendezvousRegistryInner {
                cookies: std::collections::HashMap::new(),
                per_peer: std::collections::HashMap::new(),
            }),
            max_registrations,
        }
    }

    /// Register a cookie for the given subscriber. The entry is keyed
    /// by `(subscriber.peer_node_id, cookie)` — the `peer_node_id` is
    /// the registrant's *authenticated* OVL1 session identity, set by
    /// the dispatcher at the crate boundary, not anything the caller
    /// can spoof.
    ///
    /// Idempotent on same-subscriber repeat (refreshes
    /// `registered_at_unix`). Because the key includes `peer_node_id`,
    /// two different peers registering the same (public) cookie no
    /// longer collide — each gets its own entry. This is what defeats
    /// cookie-squatting: an attacker who scraped a victim's ad cannot
    /// take over or block the victim's `(victim, cookie)` slot. See
    /// [`RendezvousRegistry`] for the full rationale.
    ///
    /// A silent swap of `receiver_x25519_pk` within an existing
    /// `(peer_node_id, cookie)` binding is a receiver-pivot vector and
    /// is rejected with
    /// [`RegistryError::PubkeyRotationNeedsFreshCookie`]. Peers
    /// rotating their X25519 key must unregister the old cookie first
    /// and register a fresh one. Other fields (e.g.
    /// `registered_at_unix`) may still refresh in-place.
    pub fn register(
        &self,
        cookie: [u8; AUTH_COOKIE_LEN],
        subscriber: RendezvousSubscriber,
    ) -> Result<(), RegistryError> {
        let key: RegistrationKey = (subscriber.peer_node_id, cookie);
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = g.cookies.get(&key) {
            // Same (peer_node_id, cookie) — peer matches by key
            // construction, so the only thing to guard is an x25519
            // rotation (receiver-pivot vector).
            if existing.receiver_x25519_pk != subscriber.receiver_x25519_pk {
                return Err(RegistryError::PubkeyRotationNeedsFreshCookie);
            }
            // Same subscriber AND same x25519_pk — refresh the rest.
            g.insert_cookie(key, subscriber);
            return Ok(());
        }
        // Per-peer fairness cap (audit cycle-9): the cookie is caller-supplied,
        // so one authenticated peer could register `max_registrations` distinct
        // cookies and, via the global LRU below, evict every OTHER principal's
        // entry (the cycle-8 F5 fix moved the DoS from fail-closed to LRU churn,
        // but didn't stop a single peer monopolizing the table). Bound each
        // peer's footprint: at its own cap, evict THIS peer's oldest entry rather
        // than the global oldest, so a flood churns only the attacker's own slots.
        let peer = subscriber.peer_node_id;
        // O(1) per-peer count (audit cycle-10). The oldest-own eviction below
        // still scans the table, but only fires when this peer is AT its cap —
        // a flood path, not every register.
        let this_peer_count = g.peer_count(&peer);
        if this_peer_count >= MAX_COOKIES_PER_PEER
            && let Some(oldest_own) = g
                .cookies
                .iter()
                .filter(|((p, _), _)| *p == peer)
                .min_by_key(|(_, s)| s.registered_at_unix)
                .map(|(k, _)| *k)
        {
            g.remove_cookie(&oldest_own);
        }
        if g.cookies.len() >= self.max_registrations {
            // At capacity: evict the oldest registration (smallest
            // `registered_at_unix`) to admit the new one rather than failing
            // closed. Plain fail-closed turned a flood of `(attacker, cookie_i)`
            // registrations into a full lockout of every legitimate receiver;
            // LRU eviction degrades that to churn — genuine receivers republish
            // their ads before expiry, refreshing `registered_at_unix` and
            // keeping themselves out of the oldest-eviction set. O(n) scan fires
            // only on the rare full-path. (audit cycle-8 F5.)
            if let Some(oldest_key) = g
                .cookies
                .iter()
                .min_by_key(|(_, s)| s.registered_at_unix)
                .map(|(k, _)| *k)
            {
                g.remove_cookie(&oldest_key);
            }
        }
        g.insert_cookie(key, subscriber);
        Ok(())
    }

    /// Remove the `(requesting_peer, cookie)` registration if present.
    /// Because the registry is keyed by `(peer_node_id, cookie)`, a
    /// requester can only ever address their own entry — an attacker
    /// who guesses someone else's cookie cannot deregister it (their
    /// key is `(attacker, cookie)`, a different slot). Returns whether
    /// an entry was removed.
    pub fn unregister(
        &self,
        cookie: &[u8; AUTH_COOKIE_LEN],
        requesting_peer: &[u8; NODE_ID_LEN],
    ) -> bool {
        let key: RegistrationKey = (*requesting_peer, *cookie);
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.remove_cookie(&key).is_some()
    }

    /// Look up the subscriber that registered `cookie` under
    /// `receiver_node_id`. The Introduce relay supplies the
    /// `receiver_node_id` from the sender's (signed) rendezvous-ad, so
    /// only the genuine receiver's entry is ever resolved — a squatter
    /// who registered the same cookie under a different identity is
    /// keyed elsewhere and never matched. Returns `None` if no such
    /// entry exists.
    pub fn lookup(
        &self,
        receiver_node_id: &[u8; NODE_ID_LEN],
        cookie: &[u8; AUTH_COOKIE_LEN],
    ) -> Option<RendezvousSubscriber> {
        let key: RegistrationKey = (*receiver_node_id, *cookie);
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cookies
            .get(&key)
            .cloned()
    }

    /// drop every registration older than
    /// `now_unix - ttl_secs`. Operators (typically the dispatcher's
    /// periodic-cleanup tick) call this with `DEFAULT_RENDEZVOUS_REGISTRY_TTL_SECS`
    /// to bound the linkability window of stale `(peer_node_id
    /// receiver_x25519_pk)` pairs. Returns the number of entries
    /// evicted.
    pub fn evict_expired(&self, now_unix: u64, ttl_secs: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let cutoff = now_unix.saturating_sub(ttl_secs);
        // Field-borrow both maps so the retain closure can decrement `per_peer`
        // in lockstep with each removed cookie (audit cycle-10).
        let RendezvousRegistryInner { cookies, per_peer } = &mut *g;
        let before = cookies.len();
        cookies.retain(|(p, _), sub| {
            let keep = sub.registered_at_unix >= cutoff;
            if !keep && let Some(c) = per_peer.get_mut(p) {
                *c -= 1;
            }
            keep
        });
        per_peer.retain(|_, c| *c > 0);
        before - cookies.len()
    }

    /// Remove every registration belonging to `peer_node_id` —
    /// called by the dispatcher when the OVL1 session to a subscriber
    /// closes. Returns the number of cookies dropped.
    pub fn drop_subscriber(&self, peer_node_id: &[u8; NODE_ID_LEN]) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let before = g.cookies.len();
        g.cookies.retain(|_, sub| &sub.peer_node_id != peer_node_id);
        // All of this peer's entries are gone → its per-peer count is 0.
        g.per_peer.remove(peer_node_id);
        before - g.cookies.len()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cookies
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    /// node_id that satisfies the in-band binding `BLAKE3(issuer_pk) ==
    /// receiver_node_id` enforced by `verify_rendezvous_ad`. Production ads
    /// always have this shape (receiver_node_id IS BLAKE3 of the identity
    /// pubkey); tests must construct coherent ads to exercise verify.
    fn coherent_node_id(issuer_pk_b64: &str) -> [u8; NODE_ID_LEN] {
        // Mirror verify_rendezvous_ad: hash the DECODED pubkey bytes, since
        // `issuer_pk` is stored base64-encoded.
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, issuer_pk_b64)
            .expect("test issuer_pk must be valid base64");
        *blake3::hash(&raw).as_bytes()
    }

    fn fixture_ed25519() -> (Vec<u8>, RendezvousAd, String) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let receiver_node_id = coherent_node_id(&kp.public_key);
        let rendezvous_node_id = [0xBBu8; 32];
        let auth_cookie = [0xCCu8; 16];
        let receiver_x25519_pk = [0xDDu8; 32];
        let valid_from = 1_700_000_000;
        let valid_until = 1_700_000_000 + 86_400; // 1 day
        let bytes = sign_rendezvous_ad(
            receiver_node_id,
            rendezvous_node_id,
            auth_cookie,
            receiver_x25519_pk,
            valid_from,
            valid_until,
            &[], // .10: empty push envelope (no push registered)
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let decoded = decode_rendezvous_ad(&bytes).unwrap();
        (bytes, decoded, kp.public_key)
    }

    // ── Round-trip ──────────────────────────────────────────────────────

    #[test]
    fn epic482_5_sign_decode_verify_round_trip_ed25519() {
        let (_bytes, ad, pk) = fixture_ed25519();
        verify_rendezvous_ad(&ad).expect("signature must verify");
        assert_eq!(ad.receiver_node_id, coherent_node_id(&pk));
        assert_eq!(ad.rendezvous_node_id, [0xBBu8; 32]);
        assert_eq!(ad.auth_cookie, [0xCCu8; 16]);
        assert_eq!(ad.receiver_x25519_pk, [0xDDu8; 32]);
        assert_eq!(ad.valid_from_unix, 1_700_000_000);
        assert_eq!(ad.valid_until_unix, 1_700_000_000 + 86_400);
        assert_eq!(ad.issuer_algo, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn epic482_5_sign_decode_verify_round_trip_falcon512() {
        let kp = generate_keypair(SignatureAlgorithm::Falcon512);
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Falcon512,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("Falcon signature must verify");
        assert_eq!(ad.issuer_algo, SignatureAlgorithm::Falcon512);
    }

    /// Regression (audit cycle-6 H1): an attacker holding their OWN valid
    /// identity key signs a well-formed ad that NAMES the victim's
    /// receiver_node_id while pointing receiver_x25519_pk + rendezvous_node_id
    /// at attacker-controlled values. The signature is internally valid, but
    /// `verify_rendezvous_ad` must reject it because
    /// `BLAKE3(issuer_pk) != receiver_node_id` (the in-band identity binding,
    /// mirroring directory::verify_entry). Without the binding this was a
    /// rendezvous-slot hijack → sender content/metadata capture + MITM.
    #[test]
    fn cycle6_h1_foreign_key_ad_naming_victim_node_id_fails_verify() {
        let attacker = generate_keypair(SignatureAlgorithm::Ed25519);
        // A victim id that is NOT BLAKE3(attacker pubkey).
        let victim_node_id = [0x77u8; 32];
        assert_ne!(
            victim_node_id,
            coherent_node_id(&attacker.public_key),
            "test precondition: victim id must differ from attacker's own node_id"
        );
        let forged = sign_rendezvous_ad(
            victim_node_id,
            [0xBBu8; 32], // attacker's rendezvous relay
            [0xCCu8; 16],
            [0xDDu8; 32], // attacker's x25519 key
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
            &attacker.public_key,
            &attacker.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let forged_ad = decode_rendezvous_ad(&forged).unwrap();
        assert!(
            verify_rendezvous_ad(&forged_ad).is_err(),
            "ad signed by a non-receiver key naming the victim's node_id must be rejected"
        );

        // Sanity: the SAME attacker key signing its OWN coherent node_id still
        // verifies — proves the binding rejects impersonation, not all ads.
        let own = sign_rendezvous_ad(
            coherent_node_id(&attacker.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
            &attacker.public_key,
            &attacker.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let own_ad = decode_rendezvous_ad(&own).unwrap();
        verify_rendezvous_ad(&own_ad).expect("ad bound to its own signer must verify");
    }

    #[test]
    fn epic482_5_typical_ed25519_ad_well_under_4kib_cap() {
        let (bytes, _ad, _pk) = fixture_ed25519();
        assert!(
            bytes.len() < 1024,
            "typical Ed25519 ad should be < 1 KiB; got {} B",
            bytes.len()
        );
        assert!(
            bytes.len() < MAX_RENDEZVOUS_AD_BYTES,
            "must fit under the 4 KiB cap"
        );
    }

    // ── Tamper detection ────────────────────────────────────────────────

    #[test]
    fn epic482_5_tampered_receiver_node_id_fails_verify() {
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.receiver_node_id[0] ^= 0x01;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_tampered_rendezvous_node_id_fails_verify() {
        // Critical: censor that captures an ad and tries to redirect
        // senders to their own rendezvous node MUST fail verify.
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.rendezvous_node_id[0] ^= 0x01;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_tampered_auth_cookie_fails_verify() {
        // Censor swapping cookie would break sender authorization
        // at rendezvous — but if the swap goes undetected, sender
        // sends Introduce frame to attacker's cookie + receiver
        // never sees it. Signature must catch this.
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.auth_cookie[0] ^= 0x01;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_tampered_receiver_x25519_pk_fails_verify() {
        // CRITICAL: censor swapping X25519 key → sender encrypts
        // Introduce to attacker's key → attacker reads sender's
        // identity and intent. Signature MUST catch this.
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.receiver_x25519_pk[0] ^= 0x01;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_tampered_valid_from_fails_verify() {
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.valid_from_unix += 1;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_tampered_valid_until_fails_verify() {
        // Critical: censor extending validity to keep an old
        // (compromised-key) ad alive past intended rotation.
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.valid_until_unix += 86_400;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_tampered_signature_fails_verify() {
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        ad.signature[0] ^= 0x01;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic482_5_wrong_issuer_pubkey_fails_verify() {
        let (_bytes, mut ad, _pk) = fixture_ed25519();
        let other_kp = generate_keypair(SignatureAlgorithm::Ed25519);
        ad.issuer_pk = other_kp.public_key;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    // ── Decode-time rejection ───────────────────────────────────────────

    #[test]
    fn epic482_5_bad_magic_rejected_at_decode() {
        let (mut bytes, _ad, _pk) = fixture_ed25519();
        bytes[0] = b'X';
        match decode_rendezvous_ad(&bytes).unwrap_err() {
            RendezvousError::Malformed(msg) => assert!(msg.contains("magic")),
            other => panic!("expected Malformed magic, got {other:?}"),
        }
    }

    #[test]
    fn epic482_5_unsupported_version_rejected_at_decode() {
        let (mut bytes, _ad, _pk) = fixture_ed25519();
        bytes[2] = 99; // version field
        let err = decode_rendezvous_ad(&bytes).unwrap_err();
        assert!(matches!(err, RendezvousError::Malformed(_)));
    }

    #[test]
    fn epic482_5_unknown_sig_algo_rejected_at_decode() {
        let (mut bytes, _ad, _pk) = fixture_ed25519();
        bytes[3] = 99; // sig_algo field
        let err = decode_rendezvous_ad(&bytes).unwrap_err();
        assert_eq!(err, RendezvousError::BadSigAlgo(99));
    }

    #[test]
    fn epic482_5_truncated_blob_rejected_at_decode() {
        let (bytes, _ad, _pk) = fixture_ed25519();
        let truncated = &bytes[..bytes.len() - 10];
        let err = decode_rendezvous_ad(truncated).unwrap_err();
        assert!(matches!(err, RendezvousError::Malformed(_)));
    }

    #[test]
    fn epic482_5_oversized_blob_rejected_pre_decode() {
        let huge = vec![0u8; MAX_RENDEZVOUS_AD_BYTES + 1];
        let err = decode_rendezvous_ad(&huge).unwrap_err();
        assert!(matches!(err, RendezvousError::TooLarge { .. }));
    }

    #[test]
    fn epic482_5_trailing_garbage_rejected() {
        let (mut bytes, _ad, _pk) = fixture_ed25519();
        bytes.push(0x00);
        let err = decode_rendezvous_ad(&bytes).unwrap_err();
        match err {
            RendezvousError::Malformed(msg) => assert!(msg.contains("trailing")),
            other => panic!("expected Malformed trailing, got {other:?}"),
        }
    }

    // ── Sign-time validation ────────────────────────────────────────────

    #[test]
    fn epic482_5_inverted_validity_window_rejected_at_sign() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let err = sign_rendezvous_ad(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            2_000_000_000,
            1_700_000_000, // until < from
            &[],
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(err, RendezvousError::ValidityInverted { .. }));
    }

    #[test]
    fn epic482_5_validity_window_too_long_rejected_at_sign() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let err = sign_rendezvous_ad(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + MAX_VALIDITY_WINDOW_SECS + 1, // 30 days + 1 sec
            &[],
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RendezvousError::ValidityWindowTooLarge { .. }
        ));
    }

    #[test]
    fn epic482_5_oversized_issuer_pk_rejected_at_sign() {
        let huge_pk = "A".repeat(MAX_ISSUER_PK_LEN + 1);
        let err = sign_rendezvous_ad(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &huge_pk,
            "doesntmatter",
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(err, RendezvousError::IssuerPkTooLarge { .. }));
    }

    // ── Validity-window check ───────────────────────────────────────────

    #[test]
    fn epic482_5_validity_within_window_passes() {
        let (_bytes, ad, _pk) = fixture_ed25519();
        // ad valid 1700000000.. 1700086400; now in middle.
        is_currently_valid(&ad, 1_700_000_000 + 1).unwrap();
        is_currently_valid(&ad, 1_700_000_000 + 86_399).unwrap();
    }

    #[test]
    fn epic482_5_validity_before_valid_from_rejected() {
        let (_bytes, ad, _pk) = fixture_ed25519();
        let err = is_currently_valid(&ad, 1_699_999_999).unwrap_err();
        assert!(matches!(err, RendezvousError::NotYetValid { .. }));
    }

    #[test]
    fn epic482_5_validity_at_or_after_valid_until_rejected() {
        let (_bytes, ad, _pk) = fixture_ed25519();
        // Boundary: at exactly valid_until, ad is NO LONGER valid
        // (>= rather than >). Forces unambiguous rejection at the
        // expiry instant — eliminates timing-window ambiguity for
        // censor that races to use ad at the last microsecond.
        let err = is_currently_valid(&ad, 1_700_000_000 + 86_400).unwrap_err();
        assert!(matches!(err, RendezvousError::Expired { .. }));
        // After expiry too.
        let err = is_currently_valid(&ad, 1_700_000_000 + 86_400 + 1).unwrap_err();
        assert!(matches!(err, RendezvousError::Expired { .. }));
    }

    #[test]
    fn epic482_5_validity_at_valid_from_passes_boundary() {
        let (_bytes, ad, _pk) = fixture_ed25519();
        // Boundary: AT valid_from, ad IS valid (>= rather than >).
        // Sender clock exactly aligned with operator's valid_from
        // shouldn't get NotYetValid.
        is_currently_valid(&ad, 1_700_000_000).unwrap();
    }

    // ── Domain separation + DHT key ─────────────────────────────────────

    #[test]
    fn epic482_5_canonical_message_includes_domain_separator() {
        let canonical =
            canonical_message_v2(&[0u8; 32], &[0u8; 32], &[0u8; 16], &[0u8; 32], 0, 0, &[]);
        assert!(
            canonical.starts_with(SIG_DOMAIN_V2),
            "canonical message must start with domain separator for cross-protocol replay protection"
        );
        assert!(canonical.starts_with(b"veil-rendezvous-ad:v2\0"));

        // v1 (legacy) form retains its own domain so signatures don't
        // replay between v1 and v2 ads even if all other fields match.
        let v1 = canonical_message_v1(&[0u8; 32], &[0u8; 32], &[0u8; 16], &[0u8; 32], 0, 0);
        assert!(v1.starts_with(b"veil-rendezvous-ad:v1\0"));
        assert_ne!(v1, canonical, "v1 and v2 canonical messages must differ");
    }

    #[test]
    fn epic482_5_dht_key_is_deterministic() {
        let node_id = [0xAAu8; 32];
        let k1 = rendezvous_ad_dht_key(&node_id);
        let k2 = rendezvous_ad_dht_key(&node_id);
        assert_eq!(k1, k2, "same input must produce same DHT key");
    }

    #[test]
    fn epic482_5_dht_key_distinct_from_relay_directory_key() {
        // CRITICAL domain-separation invariant: a rendezvous-ad
        // lookup MUST NOT hit a relay-directory slot (or vice
        // versa), even on the same node_id. Different domain
        // prefixes in the BLAKE3 input guarantee distinct keys.
        let node_id = [0xAAu8; 32];
        let rendezvous_key = rendezvous_ad_dht_key(&node_id);
        let relay_key = super::super::directory::relay_directory_dht_key(&node_id);
        assert_ne!(
            rendezvous_key, relay_key,
            "DHT keys for rendezvous-ad and relay-directory MUST differ to prevent cross-slot collision"
        );
    }

    #[test]
    fn epic482_5_dht_key_changes_with_node_id() {
        let k1 = rendezvous_ad_dht_key(&[0xAAu8; 32]);
        let k2 = rendezvous_ad_dht_key(&[0xBBu8; 32]);
        assert_ne!(k1, k2, "different node_ids must produce different DHT keys");
    }

    // ── Multi-key replica publication (T1.4 follow-up) ──────────────────

    #[test]
    fn t1_4_followup_dht_key_at_zero_matches_legacy() {
        // Backward-compat invariant: pre-T1.4 publishers used the
        // legacy single-key derivation; new publishers use slot 0
        // for their first replica. These MUST produce identical
        // bytes — otherwise legacy and new nodes can't see each
        // other's publications.
        for nid in &[[0u8; 32], [0xAAu8; 32], [0xFFu8; 32]] {
            let legacy = rendezvous_ad_dht_key(nid);
            let slot_0 = rendezvous_ad_dht_key_at(nid, 0);
            assert_eq!(
                legacy, slot_0,
                "rendezvous_ad_dht_key_at(_, 0) must equal legacy rendezvous_ad_dht_key"
            );
        }
    }

    #[test]
    fn t1_4_followup_dht_key_slots_are_distinct() {
        let nid = [0x42u8; 32];
        let mut keys = Vec::new();
        for idx in 0..MAX_RENDEZVOUS_AD_SLOTS {
            keys.push(rendezvous_ad_dht_key_at(&nid, idx));
        }
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "slot {i} key MUST differ from slot {j} key"
                );
            }
        }
    }

    #[test]
    fn t1_4_followup_dht_key_at_oversized_idx_saturates() {
        // Caller passing idx >= MAX_RENDEZVOUS_AD_SLOTS shouldn't
        // panic; key collapses to the last valid slot.
        let nid = [0x42u8; 32];
        let last = rendezvous_ad_dht_key_at(&nid, MAX_RENDEZVOUS_AD_SLOTS - 1);
        let beyond = rendezvous_ad_dht_key_at(&nid, MAX_RENDEZVOUS_AD_SLOTS);
        let way_beyond = rendezvous_ad_dht_key_at(&nid, 255);
        assert_eq!(last, beyond);
        assert_eq!(last, way_beyond);
    }

    #[test]
    fn t1_4_followup_dht_key_slots_distinct_from_relay_directory_key() {
        let nid = [0xAAu8; 32];
        let relay_key = super::super::directory::relay_directory_dht_key(&nid);
        for idx in 0..MAX_RENDEZVOUS_AD_SLOTS {
            let slot_key = rendezvous_ad_dht_key_at(&nid, idx);
            assert_ne!(
                slot_key, relay_key,
                "slot {idx} must not collide with relay-directory key"
            );
        }
    }

    #[test]
    fn t1_4_followup_dht_key_at_changes_with_node_id() {
        let k1 = rendezvous_ad_dht_key_at(&[0xAAu8; 32], 3);
        let k2 = rendezvous_ad_dht_key_at(&[0xBBu8; 32], 3);
        assert_ne!(
            k1, k2,
            "different node_ids at the same slot must produce different keys"
        );
    }

    // ── Cross-protocol signature replay protection ──────────────────────

    #[test]
    fn epic482_5_signature_does_not_replay_to_relay_directory() {
        // Critical: the signature on a RendezvousAd should NEVER
        // verify against the relay-directory canonical message
        // because canonical messages have different
        // domain prefixes. Verifies cross-protocol replay
        // protection — censor that captures an ad signature
        // can't repurpose it as a fake relay-directory entry.
        let (_bytes, ad, pk) = fixture_ed25519();
        // Reconstruct what would be the relay-directory canonical
        // for the same fields. If the prefix-domain protection
        // works, sign/verify should reject (signature was generated
        // over the rendezvous-domain message, not relay-directory).
        let relay_canonical = {
            let mut b = Vec::new();
            b.extend_from_slice(b"veil-relay-directory:v1\0"); // different domain
            b.extend_from_slice(&ad.receiver_node_id);
            b.extend_from_slice(&ad.receiver_x25519_pk);
            b.extend_from_slice(&0u32.to_be_bytes());
            b.extend_from_slice(&ad.valid_from_unix.to_be_bytes());
            b
        };
        let result =
            veil_crypto::verify_message(ad.issuer_algo, &pk, &relay_canonical, &ad.signature);
        assert!(
            result.is_err(),
            "ad signature MUST NOT verify against relay-directory canonical — \
             cross-protocol replay would let censor repurpose ad signatures"
        );
    }

    // ── Slices 2-4 wire-type + crypto + registry tests ───────────────────────

    #[test]
    fn epic482_5_introduce_roundtrip_typical() {
        let p = IntroducePayload {
            receiver_node_id: [0xAA; NODE_ID_LEN],
            auth_cookie: [0xCC; AUTH_COOKIE_LEN],
            ciphertext: vec![0u8; 96],
        };
        let buf = p.encode().unwrap();
        assert_eq!(buf.len(), IntroducePayload::FIXED_SIZE + 96);
        let d = IntroducePayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn epic482_5_introduce_oversize_rejected() {
        let p = IntroducePayload {
            receiver_node_id: [0; NODE_ID_LEN],
            auth_cookie: [0; AUTH_COOKIE_LEN],
            ciphertext: vec![0u8; MAX_INTRODUCE_CIPHERTEXT + 1],
        };
        assert!(p.encode().is_err());
    }

    #[test]
    fn epic482_5_introduce_truncated_rejected() {
        let mut buf = IntroducePayload {
            receiver_node_id: [0; NODE_ID_LEN],
            auth_cookie: [0; AUTH_COOKIE_LEN],
            ciphertext: vec![1, 2, 3, 4],
        }
        .encode()
        .unwrap();
        buf.pop(); // chop one byte
        assert!(IntroducePayload::decode(&buf).is_err());
    }

    #[test]
    fn epic482_5_introduce_trailing_bytes_rejected() {
        // Exact-length decode: a blob longer than the declared frame must be
        // rejected, not silently truncated to `total` (no smuggled tail).
        let mut buf = IntroducePayload {
            receiver_node_id: [0; NODE_ID_LEN],
            auth_cookie: [0; AUTH_COOKIE_LEN],
            ciphertext: vec![1, 2, 3, 4],
        }
        .encode()
        .unwrap();
        buf.push(0xFF); // append one stray byte past the frame
        assert!(IntroducePayload::decode(&buf).is_err());
    }

    #[test]
    fn epic482_5_register_roundtrip() {
        let p = RegisterRendezvousPayload {
            receiver_x25519_pk: [0xAB; X25519_PK_LEN],
            auth_cookie: [0xCD; AUTH_COOKIE_LEN],
        };
        let buf = p.encode();
        let d = RegisterRendezvousPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn epic482_5_register_wrong_size_rejected() {
        assert!(RegisterRendezvousPayload::decode(&[0u8; 47]).is_err());
        assert!(RegisterRendezvousPayload::decode(&[0u8; 49]).is_err());
    }

    #[test]
    fn epic482_5_unregister_roundtrip() {
        let p = UnregisterRendezvousPayload {
            auth_cookie: [0xEF; AUTH_COOKIE_LEN],
        };
        let buf = p.encode();
        let d = UnregisterRendezvousPayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn epic482_5_forward_roundtrip() {
        let p = ForwardIntroducePayload {
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let buf = p.encode().unwrap();
        let d = ForwardIntroducePayload::decode(&buf).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn epic482_5_forward_oversize_rejected() {
        let p = ForwardIntroducePayload {
            ciphertext: vec![0u8; MAX_INTRODUCE_CIPHERTEXT + 1],
        };
        assert!(p.encode().is_err());
    }

    // ── Sealed-box crypto ────────────────────────────────────────────────────

    #[test]
    fn epic482_5_encrypt_decrypt_roundtrip() {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};
        let receiver_sk = StaticSecret::random_from_rng(OsRng);
        let receiver_pk = PublicKey::from(&receiver_sk).to_bytes();
        let plaintext = b"hello rendezvous";
        let ciphertext = encrypt_introduce(plaintext, &receiver_pk).unwrap();
        let recovered = decrypt_introduce(&ciphertext, &receiver_sk).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn epic482_5_encrypt_two_calls_yield_distinct_ciphertexts() {
        // Anti-correlation: same plaintext + same recipient must
        // produce distinct ciphertexts (fresh ephemeral per call).
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let pt = b"same payload";
        let c1 = encrypt_introduce(pt, &pk).unwrap();
        let c2 = encrypt_introduce(pt, &pk).unwrap();
        assert_ne!(
            c1, c2,
            "fresh ephemeral key must produce distinct ciphertexts"
        );
    }

    #[test]
    fn epic482_5_decrypt_with_wrong_key_fails() {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};
        let receiver_sk = StaticSecret::random_from_rng(OsRng);
        let other_sk = StaticSecret::random_from_rng(OsRng);
        let receiver_pk = PublicKey::from(&receiver_sk).to_bytes();
        let ciphertext = encrypt_introduce(b"secret", &receiver_pk).unwrap();
        let result = decrypt_introduce(&ciphertext, &other_sk);
        assert!(matches!(result, Err(RendezvousError::Verify)));
    }

    #[test]
    fn epic482_5_decrypt_tampered_ciphertext_fails() {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let mut ct = encrypt_introduce(b"data", &pk).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // tamper one byte
        assert!(matches!(
            decrypt_introduce(&ct, &sk),
            Err(RendezvousError::Verify)
        ));
    }

    #[test]
    fn epic482_5_decrypt_truncated_fails() {
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let result = decrypt_introduce(&[0u8; 10], &sk);
        assert!(matches!(result, Err(RendezvousError::Malformed(_))));
    }

    // ── RendezvousRegistry ───────────────────────────────────────────────────

    fn make_subscriber(byte: u8) -> RendezvousSubscriber {
        RendezvousSubscriber {
            peer_node_id: [byte; NODE_ID_LEN],
            receiver_x25519_pk: [byte ^ 0xFF; X25519_PK_LEN],
            registered_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn epic482_5_registry_register_then_lookup() {
        let reg = RendezvousRegistry::default();
        let cookie = [0xAA; AUTH_COOKIE_LEN];
        let sub = make_subscriber(0x11);
        assert!(reg.register(cookie, sub.clone()).is_ok());
        assert_eq!(reg.len(), 1);
        let found = reg.lookup(&sub.peer_node_id, &cookie).unwrap();
        assert_eq!(found.peer_node_id, sub.peer_node_id);
    }

    #[test]
    fn epic482_5_registry_lookup_unknown_returns_none() {
        let reg = RendezvousRegistry::default();
        assert!(
            reg.lookup(&[0u8; NODE_ID_LEN], &[0u8; AUTH_COOKIE_LEN])
                .is_none()
        );
    }

    /// Two *different* peers registering the same (public) cookie must
    /// NOT collide — the registry is keyed by `(peer_node_id, cookie)`,
    /// so each gets an independent entry. This is the cookie-squatting
    /// defence: an attacker who scraped a victim's DHT ad and
    /// registered the victim's cookie under their own authenticated
    /// session cannot block or hijack the victim's slot.
    #[test]
    fn rendezvous_cross_peer_same_cookie_coexist_no_squat() {
        let reg = RendezvousRegistry::default();
        let cookie = [0xBB; AUTH_COOKIE_LEN];
        let victim = make_subscriber(0x11);
        let attacker = make_subscriber(0x22);
        // Attacker squats the cookie first.
        reg.register(cookie, attacker.clone()).unwrap();
        // Victim registers the SAME cookie — must still succeed.
        reg.register(cookie, victim.clone()).unwrap();
        assert_eq!(reg.len(), 2, "both entries coexist under distinct peers");
        // Each peer resolves to its OWN entry; the squatter cannot
        // shadow the victim's registration.
        let v = reg
            .lookup(&victim.peer_node_id, &cookie)
            .expect("victim entry present");
        assert_eq!(v.peer_node_id, victim.peer_node_id);
        assert_eq!(v.receiver_x25519_pk, victim.receiver_x25519_pk);
        let a = reg
            .lookup(&attacker.peer_node_id, &cookie)
            .expect("attacker entry present");
        assert_eq!(a.peer_node_id, attacker.peer_node_id);
    }

    #[test]
    fn epic482_5_registry_same_subscriber_refresh_ok() {
        let reg = RendezvousRegistry::default();
        let cookie = [0xCC; AUTH_COOKIE_LEN];
        let sub = make_subscriber(0x33);
        reg.register(cookie, sub.clone()).unwrap();
        // Same subscriber re-registers (e.g. periodic refresh) — must succeed.
        reg.register(cookie, sub).unwrap();
        assert_eq!(reg.len(), 1);
    }

    /// a same-peer re-registration that swaps
    /// `receiver_x25519_pk` is rejected. Permitting the silent swap
    /// is a receiver-pivot vector — any code path that delivers a
    /// re-register frame without verifying the new x25519_pk against
    /// the peer's identity (which is most of them) would let an
    /// active-MITM replace the rendezvous decrypt key with one they
    /// hold. Legitimate key rotation goes through unregister + fresh
    /// cookie + fresh register.
    #[test]
    fn phase647_h1_x25519_pk_swap_on_same_cookie_rejected() {
        let reg = RendezvousRegistry::default();
        let cookie = [0x77; AUTH_COOKIE_LEN];
        let sub_v1 = make_subscriber(0x44);
        reg.register(cookie, sub_v1.clone()).unwrap();
        // Same peer_node_id, fresh x25519_pk.
        let mut sub_v2 = sub_v1.clone();
        sub_v2.receiver_x25519_pk = [0xAB; X25519_PK_LEN];
        assert!(!matches!(sub_v2.receiver_x25519_pk, p if p == sub_v1.receiver_x25519_pk));
        let err = reg.register(cookie, sub_v2.clone()).unwrap_err();
        assert!(matches!(err, RegistryError::PubkeyRotationNeedsFreshCookie));
        // The original subscriber is still active — registry didn't
        // overwrite anything despite the rejection.
        let still = reg.lookup(&sub_v1.peer_node_id, &cookie).unwrap();
        assert_eq!(
            still.receiver_x25519_pk, sub_v1.receiver_x25519_pk,
            "rejected re-register must leave the original entry intact"
        );
    }

    /// refresh that keeps the same x25519_pk but bumps the
    /// timestamp is still allowed (legitimate "I'm still alive" ping).
    #[test]
    fn phase647_h1_same_pk_refresh_still_allowed() {
        let reg = RendezvousRegistry::default();
        let cookie = [0x88; AUTH_COOKIE_LEN];
        let sub_v1 = make_subscriber(0x55);
        reg.register(cookie, sub_v1.clone()).unwrap();
        let mut sub_v2 = sub_v1.clone();
        sub_v2.registered_at_unix = sub_v1.registered_at_unix + 60;
        reg.register(cookie, sub_v2.clone()).unwrap();
        let r = reg.lookup(&sub_v1.peer_node_id, &cookie).unwrap();
        assert_eq!(r.registered_at_unix, sub_v2.registered_at_unix);
    }

    /// escape valve: rotation through unregister-then-register
    /// works as the audit prescribed.
    #[test]
    fn phase647_h1_legitimate_rotation_via_unregister_works() {
        let reg = RendezvousRegistry::default();
        let cookie = [0x99; AUTH_COOKIE_LEN];
        let sub_v1 = make_subscriber(0x66);
        reg.register(cookie, sub_v1.clone()).unwrap();
        assert!(reg.unregister(&cookie, &sub_v1.peer_node_id));
        let mut sub_v2 = sub_v1.clone();
        sub_v2.receiver_x25519_pk = [0xCD; X25519_PK_LEN];
        // Fresh registration after unregister succeeds.
        reg.register(cookie, sub_v2.clone()).unwrap();
        let r = reg.lookup(&sub_v1.peer_node_id, &cookie).unwrap();
        assert_eq!(r.receiver_x25519_pk, sub_v2.receiver_x25519_pk);
    }

    /// stale registrations older than the TTL
    /// are evicted on `evict_expired`. Bounds the linkability
    /// window for a long-running rendezvous relay observing the same
    /// `(peer_node_id, receiver_x25519_pk)` over time.
    #[test]
    fn phase647_h4_evict_expired_drops_stale_entries() {
        let reg = RendezvousRegistry::default();
        let now = 1_700_000_000u64;
        let mut s_old = make_subscriber(0x10);
        s_old.registered_at_unix = now - 7 * 3600; // 7h old, stale
        let mut s_fresh = make_subscriber(0x20);
        s_fresh.registered_at_unix = now - 3600; // 1h old, still fresh
        reg.register([0xA0; AUTH_COOKIE_LEN], s_old).unwrap();
        reg.register([0xA1; AUTH_COOKIE_LEN], s_fresh).unwrap();
        let evicted = reg.evict_expired(now, DEFAULT_RENDEZVOUS_REGISTRY_TTL_SECS);
        assert_eq!(evicted, 1, "stale entry must be evicted");
        assert_eq!(reg.len(), 1);
        assert!(
            reg.lookup(&[0x20; NODE_ID_LEN], &[0xA1; AUTH_COOKIE_LEN])
                .is_some(),
            "fresh entry must survive"
        );
    }

    #[test]
    fn epic482_5_registry_unregister_only_by_owner() {
        let reg = RendezvousRegistry::default();
        let cookie = [0xDD; AUTH_COOKIE_LEN];
        let owner = make_subscriber(0x44);
        reg.register(cookie, owner.clone()).unwrap();
        // Stranger tries to unregister — silently ignored.
        let imposter = [0x99; NODE_ID_LEN];
        assert!(!reg.unregister(&cookie, &imposter));
        assert!(reg.lookup(&owner.peer_node_id, &cookie).is_some());
        // Real owner unregisters — succeeds.
        assert!(reg.unregister(&cookie, &owner.peer_node_id));
        assert!(reg.lookup(&owner.peer_node_id, &cookie).is_none());
    }

    #[test]
    fn epic482_5_registry_drop_subscriber_removes_all_their_cookies() {
        let reg = RendezvousRegistry::default();
        let sub = make_subscriber(0x55);
        for i in 0..5u8 {
            let mut cookie = [0u8; AUTH_COOKIE_LEN];
            cookie[0] = i;
            reg.register(cookie, sub.clone()).unwrap();
        }
        // Another subscriber's cookie should NOT be removed.
        let other = make_subscriber(0x66);
        reg.register([0xFF; AUTH_COOKIE_LEN], other).unwrap();
        assert_eq!(reg.len(), 6);
        let removed = reg.drop_subscriber(&sub.peer_node_id);
        assert_eq!(removed, 5);
        assert_eq!(reg.len(), 1);
    }

    // ── refresh threshold ───────────────────────────────────────────

    #[test]
    fn epic482_5_refresh_within_first_half_does_not_trigger() {
        // valid_until = now + 24h, validity_window = 24h. At now
        // half-window = 12h; now + 12h = valid_until, so AT exactly
        // half-life refresh fires. Before that — no refresh.
        let now = 1_000_000;
        let validity = 24 * 3600;
        let valid_until = now + validity;
        // 1 hour in: 23h remaining, well above half — no refresh.
        assert!(!rendezvous_ad_needs_refresh(
            valid_until,
            now + 3600,
            validity
        ));
        // 11 hours in: 13h remaining — still no refresh.
        assert!(!rendezvous_ad_needs_refresh(
            valid_until,
            now + 11 * 3600,
            validity
        ));
    }

    #[test]
    fn epic482_5_refresh_at_or_past_half_life_triggers() {
        let now = 1_000_000;
        let validity = 24 * 3600;
        let valid_until = now + validity;
        // 12 hours in: half-life — refresh fires.
        assert!(rendezvous_ad_needs_refresh(
            valid_until,
            now + 12 * 3600,
            validity
        ));
        // Past half-life: 18h in — refresh.
        assert!(rendezvous_ad_needs_refresh(
            valid_until,
            now + 18 * 3600,
            validity
        ));
    }

    #[test]
    fn epic482_5_refresh_at_or_past_expiry_triggers() {
        let now = 1_000_000;
        let validity = 24 * 3600;
        let valid_until = now + validity;
        // After expiry — refresh definitely fires.
        assert!(rendezvous_ad_needs_refresh(
            valid_until,
            valid_until,
            validity
        ));
        assert!(rendezvous_ad_needs_refresh(
            valid_until,
            valid_until + 1,
            validity
        ));
    }

    #[test]
    fn epic482_5_default_validity_is_one_day() {
        assert_eq!(DEFAULT_RENDEZVOUS_VALIDITY_SECS, 24 * 3600);
    }

    // ── push_envelope round-trip + tamper protection ──────

    #[test]
    fn epic489_10_default_no_push_envelope_yields_empty_field() {
        // Existing fixture passes &[] for push_envelope; round-trip
        // through encode → decode preserves "no push" intent.
        let (_bytes, ad, _pk) = fixture_ed25519();
        assert!(
            ad.push_envelope.is_empty(),
            "default sign uses empty push_envelope; decode must preserve this"
        );
        assert_eq!(
            ad.wire_version, VERSION,
            "fresh sign always emits current wire version"
        );
        verify_rendezvous_ad(&ad).expect("empty-envelope v2 ad must verify");
    }

    #[test]
    fn epic489_10_push_envelope_round_trips_through_encode_decode() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let envelope = b"sealed-fcm-token-blob-aaaa-bbbb-cccc-dddd-eeee-ffff".to_vec();
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &envelope,
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        assert_eq!(
            ad.push_envelope, envelope,
            "envelope bytes must round-trip exactly"
        );
        verify_rendezvous_ad(&ad).expect("v2 ad with envelope must verify");
    }

    #[test]
    fn epic489_10_signature_binds_push_envelope() {
        // Censor strips the envelope post-sign — verify must reject.
        // Without this binding, a push-relay could be redirected to
        // an attacker's FCM/APNs token, leaking wake-up timing to the
        // attacker (metadata).
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let envelope = b"original-sealed-token".to_vec();
        let bytes = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &envelope,
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        // Tamper: replace envelope with different bytes (same length).
        let mut tampered = envelope.clone();
        tampered[0] ^= 0x01;
        ad.push_envelope = tampered;
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify,
            "envelope tamper must break signature"
        );
    }

    #[test]
    fn epic489_10_signature_binds_envelope_presence() {
        // Different scenario: censor STRIPS the envelope entirely (sets
        // length to 0). Verify must reject because v2 canonical includes
        // length=0 vs length=N.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let envelope = b"original-sealed-token".to_vec();
        let bytes = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &envelope,
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        ad.push_envelope.clear();
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify,
            "envelope strip must break signature"
        );
    }

    #[test]
    fn epic489_10_oversized_push_envelope_rejected_at_sign() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let too_big = vec![0u8; MAX_PUSH_ENVELOPE_LEN + 1];
        let err = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &too_big,
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(err, RendezvousError::PushEnvelopeTooLarge { .. }));
    }

    #[test]
    fn epic489_10_max_size_push_envelope_accepted() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let max_envelope = vec![0xAB; MAX_PUSH_ENVELOPE_LEN];
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &max_envelope,
            &[], // empty capability token
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        assert_eq!(ad.push_envelope.len(), MAX_PUSH_ENVELOPE_LEN);
        verify_rendezvous_ad(&ad).expect("max-size envelope must verify");
        assert!(
            bytes.len() < MAX_RENDEZVOUS_AD_BYTES,
            "max-envelope ad still under total cap; got {}",
            bytes.len()
        );
    }

    #[test]
    fn epic489_10_v1_legacy_decode_yields_empty_envelope() {
        // Construct a v1 wire-format blob by hand (no push_envelope
        // field). Decoder must accept it and set push_envelope = vec![].
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);

        // Build v1 canonical and sign.
        let canonical = canonical_message_v1(
            &coherent_node_id(&kp.public_key),
            &[0xBB; 32],
            &[0xCC; 16],
            &[0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
        );
        let signature = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &canonical,
        )
        .unwrap();

        // Manually emit v1 wire format.
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION_LEGACY);
        out.push(0u8); // sig_algo Ed25519
        out.extend_from_slice(&coherent_node_id(&kp.public_key));
        out.extend_from_slice(&[0xBB; 32]);
        out.extend_from_slice(&[0xCC; 16]);
        out.extend_from_slice(&[0xDD; 32]);
        out.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        out.extend_from_slice(&(1_700_000_000u64 + 86_400).to_be_bytes());
        let pk_bytes = kp.public_key.as_bytes();
        out.extend_from_slice(&(pk_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(pk_bytes);
        out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&signature);

        let ad = decode_rendezvous_ad(&out).unwrap();
        assert_eq!(ad.wire_version, VERSION_LEGACY);
        assert!(
            ad.push_envelope.is_empty(),
            "v1 ad has no push_envelope field; decoder must default to empty"
        );
        verify_rendezvous_ad(&ad).expect("v1 signature must verify under v1 canonical");
    }

    #[test]
    fn epic489_10_v1_v2_canonical_messages_disjoint() {
        // Cross-version replay protection: an Ed25519 signature on a v1
        // canonical message MUST NOT verify against the same fields in
        // v2 form (with empty envelope), even though the data fields match.
        // Otherwise a censor could swap version bytes mid-flight and
        // confuse the receiver about whether push is registered.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);

        let v1_canonical = canonical_message_v1(
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            &[0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
        );
        let v1_sig = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &v1_canonical,
        )
        .unwrap();

        let v2_canonical = canonical_message_v2(
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            &[0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
        );
        // Cross-verify: v1 sig on v2 canonical fails.
        assert!(
            verify_message(
                SignatureAlgorithm::Ed25519,
                &kp.public_key,
                &v2_canonical,
                &v1_sig,
            )
            .is_err(),
            "v1 signature must NOT verify against v2 canonical"
        );
    }

    // ── End ─────────────────────────────────────────────────

    #[test]
    fn epic482_5_publisher_entry_is_simple_value_type() {
        // Smoke test: PublisherEntry is Clone/PartialEq, useful as
        // a Vec<>-stored handle in NodeRuntime.
        let e1 = RendezvousPublisherEntry {
            rendezvous_node_id: [0xAA; NODE_ID_LEN],
            auth_cookie: [0xBB; AUTH_COOKIE_LEN],
            validity_window_secs: 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            ephemeral_ad_identity: None,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn cycle9_per_peer_cap_one_peer_cannot_evict_other_principals() {
        // audit cycle-9: a single authenticated peer flooding cookies must not
        // displace another principal's registration. Its own footprint is capped
        // at MAX_COOKIES_PER_PEER; the global LRU never reaches the victim.
        let reg = RendezvousRegistry::with_capacity(10_000);
        let cookie_of = |i: u32| {
            let mut c = [0u8; AUTH_COOKIE_LEN];
            c[..4].copy_from_slice(&i.to_le_bytes());
            c
        };
        // Legitimate receiver B registers one cookie at t0.
        let victim_peer = [0xBBu8; NODE_ID_LEN];
        reg.register(
            cookie_of(0xAAAA),
            RendezvousSubscriber {
                peer_node_id: victim_peer,
                receiver_x25519_pk: [0x01; X25519_PK_LEN],
                registered_at_unix: 1_700_000_000,
            },
        )
        .unwrap();
        // Attacker A floods far more than its per-peer cap, all newer than B.
        for i in 0..(MAX_COOKIES_PER_PEER as u32 + 200) {
            reg.register(
                cookie_of(i),
                RendezvousSubscriber {
                    peer_node_id: [0xAAu8; NODE_ID_LEN],
                    receiver_x25519_pk: [0x02; X25519_PK_LEN],
                    registered_at_unix: 1_700_000_100 + i as u64,
                },
            )
            .unwrap();
        }
        // Victim B's registration survives the flood.
        assert!(
            reg.lookup(&victim_peer, &cookie_of(0xAAAA)).is_some(),
            "a single peer's flood must not evict another principal (CRIT)"
        );
        // Attacker's footprint is bounded by the per-peer cap (+ victim's 1).
        assert!(
            reg.len() <= MAX_COOKIES_PER_PEER + 1,
            "attacker footprint must be capped, registry len = {}",
            reg.len()
        );
    }

    #[test]
    fn cycle10_per_peer_count_stays_consistent_across_all_mutations() {
        // audit cycle-10: the O(1) per_peer count map must stay in perfect
        // lockstep with `cookies` across register / unregister / evict_expired /
        // drop_subscriber, or the per-peer cap would mis-fire (false lockout or
        // a bypass). Exercise every mutation path, then assert the invariant
        // `per_peer[p] == #keys (p,_) in cookies` and that the map has no zero or
        // stale peers.
        let reg = RendezvousRegistry::with_capacity(10_000);
        let cookie_of = |p: u8, i: u32| {
            let mut c = [0u8; AUTH_COOKIE_LEN];
            c[0] = p;
            c[1..5].copy_from_slice(&i.to_le_bytes());
            c
        };
        let sub = |p: u8, t: u64| RendezvousSubscriber {
            peer_node_id: [p; NODE_ID_LEN],
            receiver_x25519_pk: [0x01; X25519_PK_LEN],
            registered_at_unix: t,
        };
        let assert_consistent = |reg: &RendezvousRegistry| {
            let g = reg.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut recount: std::collections::HashMap<[u8; NODE_ID_LEN], usize> =
                std::collections::HashMap::new();
            for (p, _) in g.cookies.keys() {
                *recount.entry(*p).or_insert(0) += 1;
            }
            assert_eq!(g.per_peer, recount, "per_peer must mirror cookies exactly");
            assert!(
                g.per_peer.values().all(|c| *c > 0),
                "per_peer must never hold a zero-count peer",
            );
        };

        // Peer A: flood past its cap (triggers own-oldest eviction). Peer B: a few.
        for i in 0..(MAX_COOKIES_PER_PEER as u32 + 50) {
            reg.register(cookie_of(0xAA, i), sub(0xAA, 1_700_000_000 + i as u64))
                .unwrap();
        }
        for i in 0..5 {
            reg.register(cookie_of(0xBB, i), sub(0xBB, 1_700_000_500 + i as u64))
                .unwrap();
        }
        assert_consistent(&reg);

        // Refresh an existing key (count must NOT change).
        reg.register(cookie_of(0xBB, 0), sub(0xBB, 1_700_000_999))
            .unwrap();
        assert_consistent(&reg);

        // Unregister one of B's.
        reg.unregister(&cookie_of(0xBB, 1), &[0xBBu8; NODE_ID_LEN]);
        assert_consistent(&reg);

        // Expire everything older than a cutoff that catches all of A but not B.
        reg.evict_expired(1_700_000_600, 0);
        assert_consistent(&reg);

        // Drop all of B.
        reg.drop_subscriber(&[0xBBu8; NODE_ID_LEN]);
        assert_consistent(&reg);
        assert_eq!(reg.len(), 0, "all entries removed");
    }

    #[test]
    fn cycle8_f5_registry_full_evicts_oldest_instead_of_failing() {
        // audit cycle-8 F5 — at capacity, register() must evict the oldest
        // entry (smallest registered_at_unix) and admit the new one rather than
        // fail-closed, so a registration flood can't lock out fresh receivers.
        let reg = RendezvousRegistry::with_capacity(3);
        let cookie_of = |i: u8| {
            let mut c = [0u8; AUTH_COOKIE_LEN];
            c[0] = i;
            c
        };
        for i in 0..3u8 {
            let sub = RendezvousSubscriber {
                peer_node_id: [i; NODE_ID_LEN],
                receiver_x25519_pk: [i ^ 0xFF; X25519_PK_LEN],
                registered_at_unix: 1_700_000_000 + i as u64, // i=0 is oldest
            };
            reg.register(cookie_of(i), sub).unwrap();
        }
        // A 4th registration at capacity must succeed (no Full error).
        let newest = RendezvousSubscriber {
            peer_node_id: [0xAA; NODE_ID_LEN],
            receiver_x25519_pk: [0x55; X25519_PK_LEN],
            registered_at_unix: 1_700_000_100,
        };
        reg.register(cookie_of(0xAA), newest).unwrap();

        assert_eq!(reg.len(), 3, "cap held");
        // Oldest (i=0) evicted; the new one and the two newer survivors remain.
        assert!(reg.lookup(&[0u8; NODE_ID_LEN], &cookie_of(0)).is_none());
        assert!(reg.lookup(&[0xAA; NODE_ID_LEN], &cookie_of(0xAA)).is_some());
        assert!(reg.lookup(&[2u8; NODE_ID_LEN], &cookie_of(2)).is_some());
    }

    // ── Introduce replay protection ─────────────

    /// First decrypt of a captured Introduce ciphertext succeeds; second
    /// decrypt of the SAME ciphertext returns `Err(Replay)`. Closes the
    /// anonymity-claim-defeating replay vector where a captured Introduce
    /// could be re-submitted indefinitely to the receiver.
    #[test]
    fn phase647_c1_introduce_replay_rejected() {
        use x25519_dalek::StaticSecret;
        let receiver_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let receiver_pk = x25519_dalek::PublicKey::from(&receiver_sk);
        let plaintext = b"introduce payload bytes";
        let ct = encrypt_introduce(plaintext, receiver_pk.as_bytes()).unwrap();

        let cache = IntroduceReplayCache::new();
        let now = 1_700_000_000u64;
        let pt1 =
            decrypt_introduce_checked(&ct, &receiver_sk, &cache, now).expect("first decrypt OK");
        assert_eq!(pt1, plaintext);
        // Second decrypt of EXACT SAME bytes is rejected as replay.
        let err = decrypt_introduce_checked(&ct, &receiver_sk, &cache, now).unwrap_err();
        assert!(matches!(err, RendezvousError::Replay));
        assert_eq!(cache.len(), 1, "fingerprint recorded once");
    }

    /// Cycle-5 #4: the default replay window must cover the MAXIMUM ad
    /// validity, not just 1 day. An ad may be published with a validity up
    /// to `MAX_VALIDITY_WINDOW_SECS` (30 days); a captured Introduce must
    /// stay un-replayable for that whole window. With the old 1-day TTL a
    /// replay 24h+ later (still within a 7-30 day ad's life) slipped through.
    #[test]
    fn cycle5_4_introduce_replay_blocked_across_long_ad_validity() {
        // The const itself is pinned to the max validity window.
        assert_eq!(INTRODUCE_REPLAY_TTL_SECS, MAX_VALIDITY_WINDOW_SECS);

        use x25519_dalek::StaticSecret;
        let receiver_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let receiver_pk = x25519_dalek::PublicKey::from(&receiver_sk);
        let ct = encrypt_introduce(b"intro", receiver_pk.as_bytes()).unwrap();

        let cache = IntroduceReplayCache::new();
        let t0 = 1_700_000_000u64;
        decrypt_introduce_checked(&ct, &receiver_sk, &cache, t0).expect("first decrypt OK");

        // 7 days later — previously past the 1-day TTL, now still inside the
        // 30-day window → must be rejected as replay.
        let seven_days_later = t0 + 7 * 24 * 3600;
        let err = decrypt_introduce_checked(&ct, &receiver_sk, &cache, seven_days_later)
            .expect_err("replay within max ad validity must be rejected");
        assert!(matches!(err, RendezvousError::Replay));
    }

    /// Distinct introduces (each fresh ephemeral keypair) decrypt
    /// independently — replay protection is per-fingerprint, not per-
    /// receiver-key.
    #[test]
    fn phase647_c1_distinct_introduces_each_decrypt() {
        use x25519_dalek::StaticSecret;
        let receiver_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let receiver_pk = x25519_dalek::PublicKey::from(&receiver_sk);
        let cache = IntroduceReplayCache::new();
        let now = 1_700_000_000u64;
        for _ in 0..4 {
            let ct = encrypt_introduce(b"payload", receiver_pk.as_bytes()).unwrap();
            decrypt_introduce_checked(&ct, &receiver_sk, &cache, now)
                .expect("distinct introduces decrypt");
        }
        assert_eq!(cache.len(), 4);
    }

    /// Concurrent decrypts of the same captured Introduce: exactly ONE
    /// must succeed. Atomic check-and-record under the cache mutex.
    #[tokio::test]
    async fn phase647_c1_concurrent_replay_only_one_wins() {
        use std::sync::Arc;
        use x25519_dalek::StaticSecret;
        let receiver_sk = Arc::new(StaticSecret::random_from_rng(rand_core::OsRng));
        let receiver_pk = x25519_dalek::PublicKey::from(receiver_sk.as_ref());
        let ct = Arc::new(encrypt_introduce(b"payload", receiver_pk.as_bytes()).unwrap());
        let cache = Arc::new(IntroduceReplayCache::new());
        let now = 1_700_000_000u64;
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let sk_c = Arc::clone(&receiver_sk);
            let ct_c = Arc::clone(&ct);
            let cache_c = Arc::clone(&cache);
            tasks.push(tokio::spawn(async move {
                decrypt_introduce_checked(&ct_c, &sk_c, &cache_c, now).is_ok()
            }));
        }
        let mut wins = 0;
        for t in tasks {
            if t.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one concurrent decrypt must win");
    }

    /// Expired entries are GC'd lazily. After TTL the same fingerprint
    /// can decrypt again — overall replay window is bounded by the TTL
    /// not by cache lifetime.
    #[test]
    fn phase647_c1_expired_entries_gced() {
        use x25519_dalek::StaticSecret;
        let receiver_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let receiver_pk = x25519_dalek::PublicKey::from(&receiver_sk);
        let ct = encrypt_introduce(b"payload", receiver_pk.as_bytes()).unwrap();

        // Use a tiny TTL so the expiry is observable in the test.
        let cache = IntroduceReplayCache::with_ttl(60);
        let now = 1_700_000_000u64;
        decrypt_introduce_checked(&ct, &receiver_sk, &cache, now).unwrap();
        // Same ciphertext at `now + 1` (within TTL): replay rejected.
        let err = decrypt_introduce_checked(&ct, &receiver_sk, &cache, now + 1).unwrap_err();
        assert!(matches!(err, RendezvousError::Replay));
        // Same ciphertext at `now + 120` (TTL expired): the previous
        // fingerprint has been GC'd; decrypt succeeds again.
        decrypt_introduce_checked(&ct, &receiver_sk, &cache, now + 120)
            .expect("after TTL expiry, fingerprint replays from cache");
    }

    /// Malformed ciphertext (too short) doesn't pollute the cache.
    #[test]
    fn phase647_c1_malformed_does_not_record() {
        use x25519_dalek::StaticSecret;
        let receiver_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let cache = IntroduceReplayCache::new();
        let err = decrypt_introduce_checked(&[0u8; 10], &receiver_sk, &cache, 0).unwrap_err();
        assert!(matches!(err, RendezvousError::Malformed(_)));
        assert_eq!(
            cache.len(),
            0,
            "malformed ciphertext must not pollute the replay cache"
        );
    }

    /// an Introduce frame whose ephemeral X25519
    /// pubkey is a small-order ("torsion") point is rejected. The 25
    /// known low-order points all force the DH shared secret to
    /// all-zeros — an attacker that submitted such a pubkey could
    /// derive the same AEAD key and decrypt our reply, breaking
    /// rendezvous unlinkability.
    #[test]
    fn phase647_h2_low_order_eph_pk_rejected() {
        use x25519_dalek::StaticSecret;
        let receiver_sk = StaticSecret::random_from_rng(rand_core::OsRng);

        // Canonical X25519 small-order point: all-zeros pubkey.
        // `diffie_hellman` against this returns shared=[0;32] which is
        // exactly what `was_contributory` flags.
        let bad_eph_pk = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        // Build a "ciphertext" with the bad eph_pk + a plausible
        // (but unverifiable, since we never reach AEAD) tail.
        let mut payload = Vec::with_capacity(INTRODUCE_OVERHEAD);
        payload.extend_from_slice(&bad_eph_pk);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&[0u8; 16]); // empty msg + 16-byte tag
        let err = decrypt_introduce(&payload, &receiver_sk).unwrap_err();
        assert!(
            matches!(err, RendezvousError::Malformed(s) if s.contains("low-order")),
            "low-order eph_pk must be rejected before AEAD"
        );
    }

    /// encrypt path also refuses a low-order recipient pubkey so
    /// callers don't accidentally produce a ciphertext anyone holding
    /// (publicly-known) torsion-point private key can decrypt.
    #[test]
    fn phase647_h2_low_order_recipient_pk_rejected_in_encrypt() {
        let bad_recipient = [0u8; 32];
        let err = encrypt_introduce(b"secret", &bad_recipient).unwrap_err();
        assert!(
            matches!(err, RendezvousError::Malformed(s) if s.contains("low-order")),
            "low-order recipient pubkey must be rejected at encrypt time"
        );
    }

    // ── v3 capability_token wire format ──────────

    #[test]
    fn phase650b_316_v3_round_trip_with_capability_token() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let token = vec![0xCC; 128]; // opaque cap-token bytes
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &token,
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("v3 sig must verify");
        assert_eq!(ad.wire_version, VERSION);
        assert_eq!(ad.capability_token, token);
    }

    #[test]
    fn phase650b_316_v3_capability_token_signed_in_canonical() {
        // Tamper: strip the cap_token after sign — verify must reject.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let token = vec![0xCC; 64];
        let bytes = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &token,
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        ad.capability_token.clear();
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify,
            "cap_token strip must break v3 signature"
        );
    }

    #[test]
    fn phase650b_316_v3_capability_token_replace_breaks_sig() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let token = vec![0xCC; 64];
        let bytes = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &token,
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        ad.capability_token = vec![0xDD; 64]; // same length, different bytes
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn phase650b_316_oversized_cap_token_rejected_at_sign() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let too_big = vec![0u8; MAX_CAPABILITY_TOKEN_LEN + 1];
        let err = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &too_big,
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RendezvousError::CapabilityTokenTooLarge { .. }
        ));
    }

    #[test]
    fn phase650b_316_v3_with_both_envelope_and_cap_token() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let envelope = vec![0xEE; 80];
        let token = vec![0xCC; 100];
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &envelope,
            &token,
            &[], // empty wake_hmac_envelope
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("verify");
        assert_eq!(ad.push_envelope, envelope);
        assert_eq!(ad.capability_token, token);
        assert_eq!(ad.wire_version, VERSION);
    }

    // ── v4 wake_hmac_envelope wire format (Epic 489.10 slice 4.3.2) ──

    #[test]
    fn epic489_10_v4_round_trip_with_wake_hmac_envelope() {
        // Sign a fresh ad with a non-empty wake_hmac_envelope, decode + verify.
        // Confirms encoder emits v4, decoder reads the new field, and
        // signature covers the envelope content.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let wake_env = vec![0xEE; 92]; // typical sealed K_wake size
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &wake_env,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("v4 sig must verify");
        // sign_rendezvous_ad now delegates to the v5 encoder (empty KEM); the
        // wake envelope still round-trips and the ad is current-version.
        assert_eq!(ad.wire_version, VERSION);
        assert_eq!(ad.wake_hmac_envelope, wake_env);
    }

    #[test]
    fn v5_round_trip_with_relay_kem_pk() {
        // Sign a v5 ad carrying the relay's X25519 KEM key; decode + verify;
        // confirm the encoder emits v5, the decoder reads both KEM fields, and
        // the signature covers them.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let relay_kem_pk = vec![0x77u8; 32]; // relay's X25519 pubkey (algo 0)
        let bytes = sign_rendezvous_ad_v5(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
            RENDEZVOUS_KEM_ALGO_X25519,
            &relay_kem_pk,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("v5 sig must verify");
        assert_eq!(ad.wire_version, VERSION);
        assert_eq!(ad.rendezvous_kem_algo, RENDEZVOUS_KEM_ALGO_X25519);
        assert_eq!(ad.rendezvous_kem_pk, relay_kem_pk);
    }

    #[test]
    fn v5_relay_kem_pk_signed_in_canonical() {
        // Tamper the relay KEM key post-sign — verify must reject (the key is
        // length-prefixed into the v5 canonical message).
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let bytes = sign_rendezvous_ad_v5(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
            RENDEZVOUS_KEM_ALGO_X25519,
            &[0x77u8; 32],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        ad.rendezvous_kem_pk[0] ^= 0xFF;
        assert!(
            verify_rendezvous_ad(&ad).is_err(),
            "tampered relay KEM key must fail verify"
        );
    }

    #[test]
    fn v5_default_sign_emits_v5_with_empty_kem() {
        // The plain (non-KEM) signer delegates to v5 and advertises no relay key.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("v5 empty-kem sig must verify");
        assert_eq!(ad.wire_version, VERSION);
        assert_eq!(ad.rendezvous_kem_algo, RENDEZVOUS_KEM_ALGO_X25519);
        assert!(ad.rendezvous_kem_pk.is_empty());
    }

    #[test]
    fn v5_oversized_kem_pk_rejected_at_sign() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let huge = vec![0u8; MAX_RENDEZVOUS_KEM_PK_LEN + 1];
        let err = sign_rendezvous_ad_v5(
            coherent_node_id(&kp.public_key),
            [0xBBu8; 32],
            [0xCCu8; 16],
            [0xDDu8; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
            RENDEZVOUS_KEM_ALGO_X25519,
            &huge,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(err, RendezvousError::KemPkTooLarge { .. }));
    }

    #[test]
    fn epic489_10_v4_wake_hmac_envelope_signed_in_canonical() {
        // Strip the wake_hmac_envelope post-sign — verify must reject
        // (envelope length included in length-prefix binds signature).
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let wake_env = vec![0xEE; 64];
        let bytes = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &wake_env,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        ad.wake_hmac_envelope.clear();
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify,
            "wake_hmac_envelope strip must break v4 signature"
        );
    }

    #[test]
    fn epic489_10_v4_wake_hmac_envelope_replace_breaks_sig() {
        // Replace envelope with same-length different-bytes — verify rejects.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let wake_env = vec![0xEE; 64];
        let bytes = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &wake_env,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let mut ad = decode_rendezvous_ad(&bytes).unwrap();
        ad.wake_hmac_envelope = vec![0xFF; 64];
        assert_eq!(
            verify_rendezvous_ad(&ad).unwrap_err(),
            RendezvousError::Verify
        );
    }

    #[test]
    fn epic489_10_oversized_wake_hmac_envelope_rejected_at_sign() {
        // Caller passing > MAX_WAKE_HMAC_ENVELOPE_LEN bytes must get
        // a structured error rather than a corrupted ad.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let too_big = vec![0u8; MAX_WAKE_HMAC_ENVELOPE_LEN + 1];
        let err = sign_rendezvous_ad(
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &too_big,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RendezvousError::WakeHmacEnvelopeTooLarge { .. }
        ));
    }

    #[test]
    fn epic489_10_max_size_wake_hmac_envelope_accepted() {
        // Boundary: exactly MAX_WAKE_HMAC_ENVELOPE_LEN bytes accepted.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let max_env = vec![0xAA; MAX_WAKE_HMAC_ENVELOPE_LEN];
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &max_env,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("max-size envelope round-trips");
        assert_eq!(ad.wake_hmac_envelope.len(), MAX_WAKE_HMAC_ENVELOPE_LEN);
    }

    #[test]
    fn epic489_10_v4_with_all_three_envelopes() {
        // Combined: push_envelope + capability_token + wake_hmac_envelope.
        // Confirms all three independent fields preserve through encode
        // → decode → verify together.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let push_env = vec![0xEE; 80];
        let cap_tok = vec![0xCC; 100];
        let wake_env = vec![0xBB; 92];
        let bytes = sign_rendezvous_ad(
            coherent_node_id(&kp.public_key),
            [0xBB; 32],
            [0xCC; 16],
            [0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &push_env,
            &cap_tok,
            &wake_env,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        verify_rendezvous_ad(&ad).expect("v4 with all 3 envelopes verifies");
        assert_eq!(ad.push_envelope, push_env);
        assert_eq!(ad.capability_token, cap_tok);
        assert_eq!(ad.wake_hmac_envelope, wake_env);
        assert_eq!(ad.wire_version, VERSION);
    }

    #[test]
    fn epic489_10_v3_legacy_decode_under_v4_yields_empty_wake_hmac_envelope() {
        // Construct a v3 wire blob via encode_body_v3 + canonical_message_v3
        // then decode under the new v4 decoder.  Verify must succeed
        // using the v3 canonical, and wake_hmac_envelope must be empty —
        // matches the symmetric v1-under-v2 and v2-under-v3 cases.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let push_env = vec![0xEE; 64];
        let cap_tok = vec![0xCC; 50];
        let receiver_node_id = coherent_node_id(&kp.public_key);
        let rendezvous_node_id = [0xBBu8; 32];
        let auth_cookie = [0xCCu8; 16];
        let receiver_x25519_pk = [0xDDu8; 32];
        let valid_from = 1_700_000_000;
        let valid_until = valid_from + 86_400;
        let canonical = canonical_message_v3(
            &receiver_node_id,
            &rendezvous_node_id,
            &auth_cookie,
            &receiver_x25519_pk,
            valid_from,
            valid_until,
            &push_env,
            &cap_tok,
        );
        let signature = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &canonical,
        )
        .unwrap();
        let bytes = encode_body_v3(
            &receiver_node_id,
            &rendezvous_node_id,
            &auth_cookie,
            &receiver_x25519_pk,
            valid_from,
            valid_until,
            &push_env,
            &cap_tok,
            kp.public_key.as_bytes(),
            SignatureAlgorithm::Ed25519,
            &signature,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        assert_eq!(ad.wire_version, VERSION_V3);
        assert_eq!(ad.push_envelope, push_env);
        assert_eq!(ad.capability_token, cap_tok);
        assert!(
            ad.wake_hmac_envelope.is_empty(),
            "v3 ads must decode to empty wake_hmac_envelope under v4 decoder"
        );
        verify_rendezvous_ad(&ad).expect("v3 sig must verify under v4 verifier dispatch");
    }

    #[test]
    fn epic489_10_v3_v4_canonical_messages_disjoint() {
        // Cross-version replay protection: an Ed25519 signature on a v3
        // canonical message MUST NOT verify against the same fields in v4
        // form (with empty wake_hmac_envelope).  Otherwise a censor could
        // bump the version byte mid-flight and trick a v4 receiver into
        // accepting an old-style v3 ad as if it were authenticated for
        // HMAC wakeup.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);

        let v3_canonical = canonical_message_v3(
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            &[0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
        );
        let v3_sig = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &v3_canonical,
        )
        .unwrap();

        let v4_canonical = canonical_message_v4(
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            &[0xDD; 32],
            1_700_000_000,
            1_700_000_000 + 86_400,
            &[],
            &[],
            &[],
        );
        assert!(
            verify_message(
                SignatureAlgorithm::Ed25519,
                &kp.public_key,
                &v4_canonical,
                &v3_sig,
            )
            .is_err(),
            "v3 signature must NOT verify against v4 canonical"
        );
    }

    #[test]
    fn phase650b_316_v2_legacy_decode_under_v3_yields_empty_cap_token() {
        // Construct a v2 wire blob via encode_body_v2 + canonical_message_v2
        // then decode under the new decoder. Verify must
        // succeed using the v2 canonical, and cap_token must be empty.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let envelope = vec![0xEE; 64];
        let receiver_node_id = coherent_node_id(&kp.public_key);
        let rendezvous_node_id = [0xBBu8; 32];
        let auth_cookie = [0xCCu8; 16];
        let receiver_x25519_pk = [0xDDu8; 32];
        let valid_from = 1_700_000_000;
        let valid_until = valid_from + 86_400;
        let canonical = canonical_message_v2(
            &receiver_node_id,
            &rendezvous_node_id,
            &auth_cookie,
            &receiver_x25519_pk,
            valid_from,
            valid_until,
            &envelope,
        );
        let signature = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &canonical,
        )
        .unwrap();
        let bytes = encode_body_v2(
            &receiver_node_id,
            &rendezvous_node_id,
            &auth_cookie,
            &receiver_x25519_pk,
            valid_from,
            valid_until,
            &envelope,
            kp.public_key.as_bytes(),
            SignatureAlgorithm::Ed25519,
            &signature,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        assert_eq!(ad.wire_version, VERSION_V2);
        assert!(
            ad.capability_token.is_empty(),
            "v2 ads must decode to empty cap_token under slice-2 decoder"
        );
        verify_rendezvous_ad(&ad).expect("v2 sig must still verify under slice-2 verifier");
    }

    #[test]
    fn v5_v4_legacy_decode_under_v5_yields_empty_kem() {
        // Construct genuine v4 wire (encode_body_v4 + canonical_message_v4),
        // then decode under the v5 decoder: verify must succeed via the v4
        // canonical, and the relay-KEM fields must be empty (no key advertised).
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let wake_env = vec![0xEE; 64];
        let receiver_node_id = coherent_node_id(&kp.public_key);
        let rendezvous_node_id = [0xBBu8; 32];
        let auth_cookie = [0xCCu8; 16];
        let receiver_x25519_pk = [0xDDu8; 32];
        let valid_from = 1_700_000_000;
        let valid_until = valid_from + 86_400;
        let canonical = canonical_message_v4(
            &receiver_node_id,
            &rendezvous_node_id,
            &auth_cookie,
            &receiver_x25519_pk,
            valid_from,
            valid_until,
            &[],
            &[],
            &wake_env,
        );
        let signature = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &canonical,
        )
        .unwrap();
        let bytes = encode_body_v4(
            &receiver_node_id,
            &rendezvous_node_id,
            &auth_cookie,
            &receiver_x25519_pk,
            valid_from,
            valid_until,
            &[],
            &[],
            &wake_env,
            kp.public_key.as_bytes(),
            SignatureAlgorithm::Ed25519,
            &signature,
        )
        .unwrap();
        let ad = decode_rendezvous_ad(&bytes).unwrap();
        assert_eq!(ad.wire_version, VERSION_V4);
        assert_eq!(ad.wake_hmac_envelope, wake_env);
        assert_eq!(ad.rendezvous_kem_algo, RENDEZVOUS_KEM_ALGO_X25519);
        assert!(
            ad.rendezvous_kem_pk.is_empty(),
            "v4 ads must decode to empty relay-KEM under the v5 decoder"
        );
        verify_rendezvous_ad(&ad).expect("v4 sig must still verify under the v5 verifier");
    }
}
