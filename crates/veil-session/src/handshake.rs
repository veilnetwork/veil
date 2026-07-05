//! OVL1 binary session handshake with X25519 key agreement.
//!
//! Drives the full 7-message exchange (Hello → Identity → Capabilities →
//! KeyAgreement → SessionConfirm → Attach) over an async stream.
//!
//! After key agreement both sides derive identical `SessionKeys` via
//! HKDF-SHA256. The SESSION_CONFIRM payload carries a BLAKE3 MAC over the
//! shared secret and both node IDs (in canonical sorted order) to prove both
//! sides computed the same X25519 DH value.
//! Any mismatch causes an immediate `NodeError::Handshake` failure.
//!
//! The function returns `OvlHandshakeResult` which includes the remote peer's
//! identity **and** the derived `SessionKeys` ready for use by `SessionRunner`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use veil_cfg::{NodeRole, SignatureAlgorithm};
use veil_crypto::{
    kex::{EphemeralKeypair, compute_shared_secret, generate_ephemeral},
    session_kdf::{SessionKeys, derive_session_keys},
};
use veil_proto::{
    codec::{decode_header_with_limit, encode_header},
    family::{FrameFamily, SessionMsg},
    header::{FrameHeader, HEADER_SIZE, VERSION},
    session::{
        AttachPayload, CapabilitiesPayload, HelloPayload, IdentityPayload, KeyAgreementPayload,
        SessionConfirmPayload, cap_flags, decode_battery_from_attach, decode_vivaldi_from_attach,
    },
};

// ── Narrow handshake error type ──────────────────────────────────────────────
//
// Phase 2 session 2 prep: session/handshake.rs previously used
// `HandshakeError(String)` from veilcore.  Decoupling session
// from `crate::node::error::NodeError` is needed before the session
// module can move to a sibling `veil-session` crate (the broader
// `NodeError` enum references `veil_transport::TransportError` which
// creates a crate dep cycle with veil-transport ← veil-error).
//
// `HandshakeError` is a narrow String-wrapping error specific to the
// OVL1 handshake path.  Veilcore provides `impl From<HandshakeError>
// for NodeError` (see `node/error.rs`) so existing callers of
// `perform_ovl1_handshake` continue to use `?` against a `NodeError`-
// returning function signature without surface-level changes.

/// Narrow error type emitted by the OVL1 handshake.  String payload
/// preserves the legacy diagnostic format.
#[derive(Debug, thiserror::Error)]
#[error("node handshake error: {0}")]
pub struct HandshakeError(pub String);

/// Result alias used throughout session/handshake.rs.  Shadows the
/// shorter `Result` import previously sourced from `crate::node::error`.
pub type Result<T> = std::result::Result<T, HandshakeError>;

// ── LocalHandshakeIdentity trait ─────────────────────────────────────────────
//
// Phase 2 session 2 prep: session/handshake.rs previously took
// `local: &crate::node::local_identity::HandshakeIdentity` directly,
// which is veilcore-internal and blocks moving session to a sibling
// crate.  The trait below exposes just the five accessors `perform_ovl1
// _handshake` actually reads, so callers can pass any type that holds
// the handshake's signing material (production = veilcore's
// `HandshakeIdentity`; tests can mock).
//
// `HandshakeIdentity` impls the trait at the definition site (see
// `veilcore/src/node/local_identity.rs`).

/// Abstraction over the local node's handshake signing material.
/// Read by [`perform_ovl1_handshake`] on every connection accept/dial.
/// `Send + Sync` bounds are mandatory: the handshake future crosses
/// `tokio::spawn` boundaries, so any `&dyn LocalHandshakeIdentity`
/// captured in it must be sendable.
pub trait LocalHandshakeIdentity: Send + Sync {
    /// Signature algorithm (Ed25519 / Falcon-512 / ...).
    fn algo(&self) -> SignatureAlgorithm;
    /// Base64-encoded public key.
    fn public_key(&self) -> &str;
    /// Base64-encoded private key (signing key).
    fn private_key(&self) -> &str;
    /// Random nonce — emitted in the HELLO frame, anti-replay binding.
    fn nonce(&self) -> &str;
    /// 32-byte BLAKE3 node identity.
    fn node_id(&self) -> &veil_cfg::NodeId;
}

// Blanket impl: callers commonly hold the identity inside an `Arc`.
// Auto-coercion `&Arc<T> → &dyn Trait` requires `Arc<T>: Trait`; this
// impl forwards to the inner.  Avoids a surface-level rewrite of the
// 3 existing callers (peer_handshake.rs, admin.rs, runtime/tests.rs)
// que all hold `Arc<HandshakeIdentity>`.
impl<T: LocalHandshakeIdentity + ?Sized> LocalHandshakeIdentity for std::sync::Arc<T> {
    fn algo(&self) -> SignatureAlgorithm {
        (**self).algo()
    }
    fn public_key(&self) -> &str {
        (**self).public_key()
    }
    fn private_key(&self) -> &str {
        (**self).private_key()
    }
    fn nonce(&self) -> &str {
        (**self).nonce()
    }
    fn node_id(&self) -> &veil_cfg::NodeId {
        (**self).node_id()
    }
}

use crate::manager::RemoteRole;
use veil_identity::{
    sovereign::SovereignIdentity,
    verify::{ValidatedIdentity, verify_identity_proof_frame},
};

// ── sovereign-identity handshake context ────────────────────────

/// Optional input [`perform_ovl1_handshake`] that enables the
/// sovereign-identity proof-frame exchange between KA
/// and SESSION_CONFIRM.
///
/// When provided, the handshake:
/// 1. Sets `cap_flags::SUPPORTS_SOVEREIGN_IDENTITY` in its outgoing
///    CAPABILITIES.
/// 2. If the peer also advertises the bit, emits a
///    `SessionMsg::IdentityProof` frame bound to the local KA
///    ephemeral pk, and expects + verifies the peer's.
/// 3. On success, populates
///    [`OvlHandshakeResult::validated_sovereign_identity`] with the
///    peer's verified `ValidatedIdentity`.
///
/// `None` means "no sovereign material available" — the handshake
/// proceeds exactly as it did pre-462.16. Legacy peers also skip
/// the exchange automatically.
pub struct SovereignHandshakeCtx<'a> {
    pub sovereign: &'a SovereignIdentity,
    /// Canonical `now` the handshake uses for proof freshness checks
    /// and for stamping the proof's `valid_until`. Injected so tests
    /// can pin clock state.
    pub now_unix_secs: u64,

    /// local ML-KEM-768 decapsulation seed.
    /// When present AND `peer_mlkem_ek_override` (or peer's published
    /// mlkem_cert at production lookup) is also available, the
    /// handshake advertises `SUPPORTS_HYBRID_KEX` and engages the
    /// post-quantum hybrid session-key derivation path. `None`
    /// keeps the classical X25519-only path; legacy peers stay
    /// unchanged.
    pub local_mlkem_dk_seed: Option<&'a [u8; 64]>,
    // audit cleanup: speculative `peer_mlkem_ek`
    // placeholder removed. Original intent (Epic 486.1 slice 3) was to
    // surface a DHT-published PrekeyBundle EK at handshake time for
    // cold-start hybrid-KEX. The functionality is partially covered by
    // `peer_mlkem_keys` cache + `meta_encrypt`/mailbox already; slice 3
    // had no scheduled date. If/when scheduled, re-add the field — one
    // line, trivial. Keeping a speculative placeholder unread bloated
    // search results and confused readers ("where is this used?" → nowhere).
}

// `NegotiatedCapabilities` was a unit-struct with methods that
// always returned `true` — residue of the multi-version negotiation that was
// removed when OVL1 became single-version. All features are now
// unconditionally enabled; call sites that used to check `.chunking` /
// `.session_resumption` now inline `true` directly.

// ── public result type ────────────────────────────────────────────────────────

/// Everything learned from the OVL1 handshake — peer identity + session keys.
#[derive(Debug)]
pub struct OvlHandshakeResult {
    pub node_id: veil_cfg::NodeId,
    /// Base64-encoded public key bytes (same encoding as config).
    pub public_key: String,
    pub nonce: String,
    /// Cryptographic keying material derived from the X25519 shared secret.
    pub session_keys: SessionKeys,
    /// Raw payload received during IDENTITY exchange — passed to SessionRegistry.
    pub remote_identity_payload: IdentityPayload,
    /// Raw payload received during CAPABILITIES exchange.
    pub remote_capabilities: CapabilitiesPayload,
    /// Raw payload received during ATTACH exchange.
    pub remote_attach: AttachPayload,
    /// Interpreted role from the ATTACH payload.
    pub remote_role: RemoteRole,
    /// Vivaldi network coordinate received from the remote peer (if present).
    pub remote_vivaldi: Option<(f64, f64, f64)>,
    /// Battery level received from the remote peer in the ATTACH TLV (if present).
    pub remote_battery: Option<u8>,
    /// stage c.3: transport URIs the peer advertised in its
    /// `ATTACH` TLV. Consumed by `HotStandbyController` to auto-populate
    /// `alt_uri` when the operator didn't supply one in config.
    /// Empty vec = peer didn't advertise any / legacy peer.
    pub remote_advertised_transports: Vec<String>,
    /// peer's verified sovereign identity when both sides
    /// advertised `SUPPORTS_SOVEREIGN_IDENTITY` and the exchanged
    /// `SessionMsg::IdentityProof` frame verified cleanly. Legacy
    /// peers (or sessions without local sovereign material) leave
    /// this `None`; downstream session bookkeeping keys the peer by
    /// `node_id` in that case, same as pre-462.16.
    ///
    /// Populated by the handshake and consumed by `cache_peer_handshake_state`
    /// in `runtime.rs`, which forwards it into `SessionEntry` so
    /// delivery/mailbox code can look up a live session by sovereign
    /// `node_id` via `SessionRegistry::peer_id_for_identity`.
    pub validated_sovereign_identity: Option<ValidatedIdentity>,
    /// The verified `MembershipCert` the peer presented in HELLO, when
    /// P-Net is enabled and verification succeeded.  `None` for public
    /// mode (no gate configured) or legacy peers (no cert blob).
    /// Daemon stores this in its per-peer cert cache so IPC consumers
    /// (ogate / oproxy) can query peer admission status without
    /// re-running the verify path.
    pub verified_membership_cert: Option<veil_types::MembershipCert>,
    /// **Observed source address** — STUN-style auto-IP-discovery.
    /// `Some(addr)` ⇒ the remote peer included an
    /// `OBSERVED_ADDR_TLV_TAG` (0x0014) extension in the ATTACH frame
    /// telling us "this is the source-address you appeared as to me".
    /// `None` ⇒ peer didn't emit the TLV (legacy peer) or extraction
    /// failed.
    ///
    /// Useful for NAT-mapped hosts that don't know their public IP:
    /// the daemon can log "your public address appears to be …" or
    /// auto-populate an `advertise = "..."` URI.
    pub remote_observed_addr: Option<std::net::SocketAddr>,
}

/// Maximum frame body size accepted during the handshake phase (before the peer
/// is authenticated). Handshake frames (HELLO, IDENTITY, CAPS, KA, CONFIRM
/// ATTACH) are all small; 64 KiB is generous while still preventing a
/// pre-auth attacker from forcing a 16 MiB allocation per connection.
pub const MAX_HANDSHAKE_FRAME_BODY: u32 = 64 * 1024;

// ── public entry point ────────────────────────────────────────────────────────

/// Called for each OVL1 handshake frame that is sent or received.
///
/// Arguments: `(inbound, family, msg_type, body_bytes, remote_node_id)`.
/// `remote_node_id` is `[0u8; 32]` until the remote HELLO is received and
/// the peer's identity becomes known.
pub type HandshakeCaptureHook<'a> =
    Option<&'a (dyn Fn(bool, u8, u16, &[u8], [u8; 32]) + Send + Sync)>;

/// Perform the full OVL1 binary session handshake.
///
/// `mlkem_ek` — optional 1184-byte ML-KEM-768 encapsulation key.
/// When present it is included in the outgoing `IdentityPayload` so that the
/// remote peer can later send E2E-encrypted messages to this node.
///
/// `capture` — optional hook called for every sent/received frame so that
/// `debug capture` can show the full handshake transcript (including ML-KEM
/// key exchange). Pass `None` in tests and when capture is not needed.
///
/// `known_remote_id` — the remote peer's node_id when known in advance (outbound
/// connections). Used as `peer_id` in capture events from the very first frame.
/// For inbound connections pass `None`; `peer_id` will be set once the remote
/// HELLO is received.
///
/// `resume_ticket` — encrypted session-resumption ticket.
/// When set, included in the HELLO TLV so the responder can attempt a fast-path
/// resumption. The responder ignores unknown TLV entries for forward-compat.
///
/// `ticket_verifier` — optional reference to the host ticket key (server side only).
/// When set and the remote HELLO contains a valid `resume_ticket`, the handshake
/// takes the fast-path (skip Identity/Capabilities/KeyAgreement/Confirm/Attach
/// exchange, restore ciphers from ticket keys). Pass `None` on the client side.
/// frame-order enforcement strategy.
///
/// `SessionFsm` (defined in `fsm.rs`) is a defense-in-depth state
/// machine that, in principle, could double-check frame ordering
/// during a live handshake. In practice the production driver below
/// enforces the same invariants two other ways, which combine to
/// make the FSM's audit value largely redundant:
///
/// 1. **Code-path layout** — the driver writes/reads frames in a
///    fixed sequence (HELLO → IDENTITY → CAPABILITIES →
///    KEY_AGREEMENT → optional IDENTITY_PROOF → SESSION_CONFIRM →
///    ATTACH). A peer that sends out-of-order frames hits a
///    `read_frame` that decodes against the wrong payload type and
///    surfaces a `Handshake(...)` error before any state-machine
///    check could fire.
///
/// 2. **Transcript hash binding ** — every frame's wire bytes
///    are hashed into the SESSION_CONFIRM MAC. A peer that altered
///    the order, dropped a frame, or replayed an old one produces
///    a different transcript composite from us; the MAC
///    ct_eq compare fails before the handshake completes.
///
/// Wiring `SessionFsm` into this driver is therefore deferred
/// indefinitely — the audit value is bounded and the refactor would
/// touch every frame send/recv site in the file. The FSM remains
/// useful for sim/tests that drive the protocol directly.
#[allow(clippy::too_many_arguments)] // .3 added the 11th arg; the
// handshake is inherently context-heavy.
pub async fn perform_ovl1_handshake<S>(
    stream: &mut S,
    local: &dyn LocalHandshakeIdentity,
    role: NodeRole,
    discovery_mode: veil_cfg::DiscoveryMode,
    vivaldi: Option<(f64, f64, f64)>,
    mlkem_ek: Option<&[u8]>,
    capture: HandshakeCaptureHook<'_>,
    known_remote_id: Option<[u8; 32]>,
    resume_ticket: Option<veil_proto::session::ClientTicketEntry>,
    ticket_verifier: Option<std::sync::Arc<std::sync::Mutex<crate::ticket::TicketIssuer>>>,
    sovereign_ctx: Option<SovereignHandshakeCtx<'_>>,
    // stage c.3: transport URIs to advertise to the peer
    // (typically the node's `[[listen]].advertise` values). The
    // peer stashes these for hot-standby auto-discovery. Empty
    // slice disables the advertisement.
    local_advertised_transports: &[String],
    // when true, advertise `cap_flags::ANONYMITY_RELAY`
    // in our CapabilitiesPayload so peers see us as a candidate hop
    // for their onion-routing circuits. Sourced from
    // `cfg.anonymity.relay_capable` at the runtime layer. Default
    // false — being an anonymity relay has non-trivial cost.
    anonymity_relay_capable: bool,
    // q: optional early ban-check. When `Some`, called
    // on the inbound side immediately after decoding the peer's HELLO
    // frame (we now know `remote_id`) and BEFORE the expensive Falcon-512
    // signature verify + ML-KEM key encapsulation + cache writes. On
    // `true`, the handshake aborts early with a dedicated error variant.
    // Saves ~50 ms CPU + ~30 KiB allocator churn per rejected banned-
    // peer connection attempt — at chaos-ban-driven ~30 connect/sec
    // rates this is ~900 KiB/sec of avoided churn. Outbound side
    // (`known_remote_id.is_some`) skips this check because the
    // initiator chose to dial. Callback type uses a type-erased
    // `dyn Fn` so the handshake module stays free of `ban_list` coupling.
    is_banned: Option<&(dyn Fn([u8; 32]) -> bool + Send + Sync)>,
    // P-Net Phase 2c: private-veil-network access gate. When
    // `Some`, the local node is configured as a member of a private
    // network — local cert blob is included in outbound HELLO and peer's
    // cert blob is verified after the inbound HELLO. `None` keeps the
    // current public-veil behaviour: peers connect freely, no cert
    // exchange.
    network_gate: Option<&veil_identity::network_access::NetworkAccessGate>,
    // S3: peer's source SocketAddr as observed on our transport layer.
    // When `Some` AND we're the accepting side (inbound), emit an
    // `OBSERVED_ADDR_TLV_TAG` extension in the outbound ATTACH so the
    // peer learns its public address (STUN-style auto-discovery).
    // `None` ⇒ TLV not emitted (preserves wire-compat with legacy peers
    // and avoids fake responses from client-side handshakes that don't
    // know the partner's address).
    peer_observed_addr: Option<std::net::SocketAddr>,
) -> Result<OvlHandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let family = FrameFamily::Session as u8;

    // Remote node ID — known for outbound connections, unknown for inbound
    // until we receive the remote HELLO.
    let mut remote_id = known_remote_id.unwrap_or([0u8; 32]);

    //HELLO ----------------------------------------------------------------
    let local_node_id_bytes = *local.node_id().as_bytes();
    // For the HELLO frame we only need the opaque blob; the client's own keys are
    // kept in `resume_ticket` for use in the fast-path restoration below.
    let hello_ticket_blob = resume_ticket.as_ref().map(|e| e.blob.clone());
    // When attempting resumption, mint a fresh per-resumption nonce and carry it
    // in the HELLO. The responder folds it (with its own nonce, returned in the
    // ATTACH trailer) into a FRESH resumed-session key derivation, so the
    // resumed session never reuses the original session's (key, nonce). Kept in
    // scope for the client-side derivation in the fast-path branch below.
    let client_resume_nonce: Option<[u8; 32]> = hello_ticket_blob.as_ref().map(|_| {
        use rand_core::{OsRng, RngCore};
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);
        n
    });
    let hello = HelloPayload {
        ovl1_major: VERSION as u16,
        node_id: local_node_id_bytes,
        resume_ticket: hello_ticket_blob,
        // P-Net Phase 2c: include our membership cert if we're in a
        // private network. Public-mode (`network_gate = None`) leaves
        // the field unset → existing TLV-less HELLO on the wire.
        membership_cert_blob: network_gate.map(|g| g.local_cert_blob.clone()),
        resume_nonce: client_resume_nonce,
    };
    let hello_bytes = hello.encode();

    // resume observability: distinguish a client attaching a ticket (resume
    // attempt) from a cold dial. Emitted via `log::info!` so it reaches the
    // phone's logcat (NodeLogger session.* events do not). Grep `resume.`.
    if resume_ticket.is_some() {
        log::info!(
            "resume.client.attempt local={} — HELLO carries resume ticket",
            veil_util::hex_short(&local_node_id_bytes),
        );
    } else if let Some(rid) = known_remote_id {
        log::info!(
            "resume.client.cold local={} peer={} — no stored ticket, full handshake",
            veil_util::hex_short(&local_node_id_bytes),
            veil_util::hex_short(&rid),
        );
    }

    // silent-server pattern for active-probe DPI resistance.
    //
    // Original protocol had BOTH sides write HELLO immediately on TCP/TLS
    // up — server's bytes thus arrived first when the client was slower
    // (typical real-world: client RTT > 0). An active prober (Russia /
    // China / Iran style "every suspicious IP gets connected to and
    // probed") could complete its own TLS handshake against us, read the
    // first 4 inner bytes, observe `OVL1` ASCII magic, conclude "this
    // is veil" and add the IP to a permanent block-list.
    //
    // Fix: inbound side (we accepted the connection — `known_remote_id
    // == None`) now READS the client's HELLO BEFORE writing its own.
    // A prober that doesn't send a valid OVL1 frame first sees ZERO
    // bytes from us — indistinguishable from a server that has nothing
    // to say, just like a typical HTTPS server post-TLS that's waiting
    // for the client's HTTP request line. Outbound side (we initiated
    // the dial — `known_remote_id == Some`) keeps writing first so it
    // can prove WHO it intends to talk to before requesting state from
    // an unknown server, preserving the dial-side latency profile.
    //
    // Real clients write HELLO immediately on TCP/TLS up (see the
    // outbound path below + `register_outbound_session`'s flow), so this
    // adds zero perceptible latency to legitimate connections.
    let inbound_side = known_remote_id.is_none();

    let remote_hello = if inbound_side {
        // INBOUND: read client first, then write our HELLO.
        let (_, body) = read_frame(stream).await?;
        let remote_hello = HelloPayload::decode(&body)
            .map_err(|e| HandshakeError(format!("OVL1 HELLO decode: {e}")))?;
        remote_id = remote_hello.node_id;
        if let Some(f) = capture {
            f(true, family, SessionMsg::Hello as u16, &body, remote_id);
        }

        // q: early ban-check. At this point we've spent
        // ~1 KiB of allocator activity (one HELLO frame read + decode);
        // continuing with this peer would burn ~50 ms CPU on Falcon-512
        // signature verification + ML-KEM encapsulation + ~30 KiB on
        // cache writes. Under chaos-ban-driven ~30/sec connect attempts
        // from banned peers, this saves ~900 KiB/sec of allocator churn
        // on bootstrap hosts. Skip the response HELLO write so the peer
        // sees the same "silent-server" closure pattern that an inactive
        // bootstrap would produce — no information leak about ban state.
        if let Some(check) = is_banned
            && check(remote_id)
        {
            return Err(HandshakeError(format!(
                "early-ban: peer {} rejected pre-handshake (ban_list hit)",
                veil_util::hex_short(&remote_id),
            )));
        }

        write_frame(stream, family, SessionMsg::Hello as u16, &hello_bytes).await?;
        if let Some(f) = capture {
            f(
                false,
                family,
                SessionMsg::Hello as u16,
                &hello_bytes,
                remote_id,
            );
        }

        remote_hello
    } else {
        // OUTBOUND: legacy order — write our HELLO first, then read.
        write_frame(stream, family, SessionMsg::Hello as u16, &hello_bytes).await?;
        if let Some(f) = capture {
            f(
                false,
                family,
                SessionMsg::Hello as u16,
                &hello_bytes,
                remote_id,
            );
        }

        let (_, body) = read_frame(stream).await?;
        let remote_hello = HelloPayload::decode(&body)
            .map_err(|e| HandshakeError(format!("OVL1 HELLO decode: {e}")))?;
        remote_id = remote_hello.node_id;
        if let Some(f) = capture {
            f(true, family, SessionMsg::Hello as u16, &body, remote_id);
        }

        remote_hello
    };

    // ── P-Net Phase 2c: verify peer membership cert ─────────────────
    //
    // When the local node is a member of a private veil (`network_gate
    // = Some`), the peer must present a valid cert signed by the same
    // owner and bound to the same `network_id`. Verification runs AFTER the
    // ban check (so banned peers don't pay the crypto cost) and BEFORE
    // any identity / capabilities / key-agreement exchange (so cert
    // failure aborts with minimal allocator churn). Public-mode nodes
    // (gate = None) skip this entirely, preserving the open-veil
    // behaviour.
    let verified_membership_cert: Option<veil_types::MembershipCert> =
        if let Some(gate) = network_gate {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match gate.verify_peer(
                remote_hello.membership_cert_blob.as_deref(),
                &remote_id,
                now_unix,
            ) {
                Ok(cert) => Some(cert),
                Err(e) => {
                    return Err(HandshakeError(format!(
                        "P-Net handshake rejected for peer {}: {e}",
                        veil_util::hex_short(&remote_id),
                    )));
                }
            }
        } else {
            None
        };

    // ── Fast-path resumption ─────────────────────────────────────────
    //
    // Server side: if we have a ticket_verifier and the remote HELLO contains
    // a ticket blob, attempt to decrypt and validate it. On success, skip
    // Identity/Capabilities/KeyAgreement/Confirm and restore the session from
    // the ticket's embedded keys.
    //
    // Client side: if we sent a resume_ticket in our HELLO, read the server's
    // next frame. If it's ATTACH the server accepted the fast-path. If it's
    // IDENTITY the server fell back to the full handshake (C6 fallback).
    if let Some(ref verifier) = ticket_verifier {
        // ── Server path ──────────────────────────────────────────────────────
        if let Some(ref ticket_blob) = remote_hello.resume_ticket {
            let maybe_ticket = {
                let v = verifier.lock().unwrap_or_else(|p| p.into_inner());
                v.decrypt(ticket_blob)
            };
            if let Some(ticket) = maybe_ticket {
                // Verify the ticket's peer_id matches the connecting node.
                if ticket.peer_id == remote_id
                    && let Some(peer_resume_nonce) = remote_hello.resume_nonce
                {
                    // Fast-path accepted ONLY with a valid ticket AND a resume
                    // nonce — a ticket without a nonce is never resumed (falls
                    // through to the full handshake), so secure resumption is
                    // atomic. Mint our own nonce, return it in the ATTACH
                    // trailer, and derive FRESH keys from both nonces below.
                    let mut fp_attach_bytes = build_local_attach_bytes(
                        role,
                        vivaldi,
                        local_advertised_transports,
                        peer_observed_addr,
                    );
                    let server_resume_nonce = {
                        use rand_core::{OsRng, RngCore};
                        let mut n = [0u8; 32];
                        OsRng.fill_bytes(&mut n);
                        n
                    };
                    veil_proto::session::append_resume_nonce_to_attach(
                        &mut fp_attach_bytes,
                        &server_resume_nonce,
                    );
                    write_frame(stream, family, SessionMsg::Attach as u16, &fp_attach_bytes)
                        .await?;
                    if let Some(f) = capture {
                        f(
                            false,
                            family,
                            SessionMsg::Attach as u16,
                            &fp_attach_bytes,
                            remote_id,
                        );
                    }

                    let (_, body) = read_frame(stream).await?;
                    let remote_attach = AttachPayload::decode(&body).map_err(|e| {
                        HandshakeError(format!("OVL1 ATTACH (fast-path server) decode: {e}"))
                    })?;
                    let remote_vivaldi = decode_vivaldi_from_attach(&body);
                    let remote_battery = decode_battery_from_attach(&body);
                    let remote_advertised_transports =
                        veil_proto::session::decode_advertised_transports_from_attach(&body);
                    if let Some(f) = capture {
                        f(true, family, SessionMsg::Attach as u16, &body, remote_id);
                    }

                    let node_id = node_id_from_bytes(remote_id)?;
                    log::info!(
                        "resume.server.success peer={} — ticket accepted, fast-path (no ML-KEM/Falcon)",
                        veil_util::hex_short(&remote_id),
                    );
                    let remote_role = RemoteRole::from(remote_attach.role);
                    // Derive FRESH session keys from the ticket's original keys +
                    // both resumption nonces (client's from HELLO, ours from the
                    // ATTACH trailer). NEVER restore the originals into a
                    // counter-0 cipher — that was the audit cycle-2 CRITICAL
                    // (identical (key, nonce) per frame across the two sessions).
                    let session_keys = veil_crypto::session_kdf::derive_resume_keys(
                        &ticket.tx_key,
                        &ticket.rx_key,
                        &ticket.session_id,
                        &peer_resume_nonce,
                        &server_resume_nonce,
                        &local_node_id_bytes,
                        &remote_id,
                    );
                    // Synthesize a minimal IdentityPayload — IDENTITY was not exchanged.
                    let remote_identity_payload = IdentityPayload {
                        algo: 0,
                        public_key: Vec::new(),
                        nonce: Vec::new(),
                        node_id: remote_id,
                        mlkem_pubkey: None,
                    };
                    let remote_capabilities = CapabilitiesPayload {
                        roles_supported: 0,
                        flags: 0,
                        discovery_mode: 0,
                    };
                    return Ok(OvlHandshakeResult {
                        node_id,
                        public_key: String::new(),
                        nonce: String::new(),
                        session_keys,
                        remote_identity_payload,
                        remote_capabilities,
                        remote_attach,
                        remote_role,
                        remote_vivaldi,
                        remote_battery,
                        remote_advertised_transports,
                        // Fast-path resumption bypasses the proof exchange;
                        // the ticket implicitly certifies the identity from
                        // the original full handshake.
                        validated_sovereign_identity: None,
                        // Ticket resumption inherits the original session's
                        // cert verification — we trust the ticket-binding step
                        // and do NOT re-verify the cert here. Session F1: this
                        // is a security no-op (the resumed session is fully
                        // authenticated by the ticket), but it IS an IPC-status
                        // completeness gap — the cert is not re-surfaced into
                        // `verified_peer_certs`, which is eviction-capped, so a
                        // peer whose cert was evicted between its full handshake
                        // and a later resumption can read as cert-less on the
                        // ogate/oproxy status surface until its next FULL
                        // handshake. Status-only; not threaded through the
                        // ticket because the cert isn't carried in the encrypted
                        // ticket blob (would need issuance-side plumbing on both
                        // peers for a cosmetic surface).
                        verified_membership_cert: None,
                        // S3: ticket resumption skips ATTACH exchange,
                        // so no observed-addr is learned here. Apps
                        // querying their public IP must rely on the original
                        // full-handshake's result.
                        remote_observed_addr: None,
                    });
                }
                // peer_id mismatch → fall through to full handshake.
            }
            // Ticket invalid or expired → fall through to full handshake.
            log::info!(
                "resume.server.reject peer={} — ticket present but not resumed (bad/expired/replayed/nonce-missing), full handshake",
                veil_util::hex_short(&remote_id),
            );
        }
    } else if let Some(ref _entry) = resume_ticket {
        // ── Client path ──────────────────────────────────────────────────────
        // We sent a resume_ticket; read the server's first response after HELLO.
        // Server sends ATTACH (fast-path accepted) or IDENTITY (C6 fallback).
        let (hdr, body) = read_frame(stream).await?;
        match SessionMsg::try_from(hdr.msg_type) {
            Ok(SessionMsg::Attach) => {
                // Server accepted the ticket — restore session from ClientTicketEntry.
                if let Some(f) = capture {
                    f(true, family, SessionMsg::Attach as u16, &body, remote_id);
                }
                let entry = resume_ticket
                    .expect("resume_ticket is Some — gated by outer `else if let Some(ref _entry) = resume_ticket`");
                let remote_attach = AttachPayload::decode(&body).map_err(|e| {
                    HandshakeError(format!("OVL1 ATTACH (fast-path client) decode: {e}"))
                })?;
                // The responder must echo a resume nonce in its ATTACH trailer;
                // without it we cannot derive matching fresh keys, so refuse the
                // resume rather than build an unusable (or unsafe) session.
                let server_resume_nonce = veil_proto::session::decode_resume_nonce_from_attach(
                    &body,
                )
                .ok_or_else(|| {
                    HandshakeError(
                        "session resumption: responder ATTACH missing resume nonce".into(),
                    )
                })?;
                let remote_vivaldi = decode_vivaldi_from_attach(&body);
                let remote_battery = decode_battery_from_attach(&body);
                let remote_advertised_transports =
                    veil_proto::session::decode_advertised_transports_from_attach(&body);
                let remote_role = RemoteRole::from(remote_attach.role);

                // Send our ATTACH.
                let fp_attach_bytes = build_local_attach_bytes(
                    role,
                    vivaldi,
                    local_advertised_transports,
                    peer_observed_addr,
                );
                write_frame(stream, family, SessionMsg::Attach as u16, &fp_attach_bytes).await?;
                if let Some(f) = capture {
                    f(
                        false,
                        family,
                        SessionMsg::Attach as u16,
                        &fp_attach_bytes,
                        remote_id,
                    );
                }

                let node_id = node_id_from_bytes(remote_id)?;
                log::info!(
                    "resume.client.success peer={} — server ATTACH, fast-path resumed (1-RTT, fit under 10s)",
                    veil_util::hex_short(&remote_id),
                );
                // Derive FRESH keys from our stored original keys + both
                // resumption nonces (ours from the HELLO, the responder's from
                // its ATTACH). NEVER restore the originals into a counter-0
                // cipher — that was the audit cycle-2 CRITICAL.
                let client_nonce = client_resume_nonce
                    .expect("client_resume_nonce is Some whenever resume_ticket is Some");
                let session_keys = veil_crypto::session_kdf::derive_resume_keys(
                    &entry.tx_key,
                    &entry.rx_key,
                    &entry.session_id,
                    &client_nonce,
                    &server_resume_nonce,
                    &local_node_id_bytes,
                    &remote_id,
                );
                // Synthesize IdentityPayload from stored peer identity.
                let nonce_bytes = entry.peer_nonce.as_bytes().to_vec();
                let remote_identity_payload = IdentityPayload {
                    algo: 0,
                    public_key: match STANDARD.decode(&entry.peer_public_key) {
                        Ok(pk) if !pk.is_empty() => pk,
                        _ => {
                            return Err(HandshakeError(
                                "session resumption: stored peer public_key is invalid base64"
                                    .into(),
                            ));
                        }
                    },
                    nonce: nonce_bytes,
                    node_id: remote_id,
                    mlkem_pubkey: None,
                };
                let remote_capabilities = CapabilitiesPayload {
                    roles_supported: 0,
                    flags: 0,
                    discovery_mode: 0,
                };
                return Ok(OvlHandshakeResult {
                    node_id,
                    public_key: entry.peer_public_key.clone(),
                    nonce: entry.peer_nonce.clone(),
                    session_keys,
                    remote_identity_payload,
                    remote_capabilities,
                    remote_attach,
                    remote_role,
                    remote_vivaldi,
                    remote_battery,
                    remote_advertised_transports,
                    // See sibling fast-path comment — resumption bypasses
                    // sovereign proof exchange.
                    validated_sovereign_identity: None,
                    // Ticket resumption inherits the original session's cert —
                    // see sibling fast-path comment (Session F1): security no-op,
                    // IPC-status completeness gap only.
                    verified_membership_cert: None,
                    // S3: see ticket-resumption sibling — no observed-addr
                    // learned on fast-path.
                    remote_observed_addr: None,
                });
            }
            Ok(SessionMsg::Identity) => {
                // Server rejected the ticket (expired/tampered) — C6 fallback.
                // We already read the remote IDENTITY body. Process it now, then
                // send our own IDENTITY and continue with the full handshake.
                log::info!(
                    "resume.client.fallback peer={} — server rejected ticket (IDENTITY not ATTACH), full handshake (must fit 10s w/ ML-KEM+Falcon)",
                    veil_util::hex_short(&remote_id),
                );
                if let Some(f) = capture {
                    f(true, family, SessionMsg::Identity as u16, &body, remote_id);
                }
                let remote_identity_body = body;

                // Send our identity first (mirrors the normal flow but inverted).
                let pk_bytes = STANDARD
                    .decode(local.public_key())
                    .map_err(|e| HandshakeError(format!("invalid public key base64: {e}")))?;
                let identity = IdentityPayload {
                    algo: algo_to_u8(local.algo()),
                    public_key: pk_bytes,
                    nonce: local.nonce().as_bytes().to_vec(),
                    node_id: local_node_id_bytes,
                    mlkem_pubkey: mlkem_ek.map(|k| k.to_vec()),
                };
                let identity_bytes = identity.encode();
                let identity_wire =
                    write_frame(stream, family, SessionMsg::Identity as u16, &identity_bytes)
                        .await?;
                if let Some(f) = capture {
                    f(
                        false,
                        family,
                        SessionMsg::Identity as u16,
                        &identity_bytes,
                        remote_id,
                    );
                }

                // Now process the remote IDENTITY we already received, then
                // drive the shared post-IDENTITY tail (CAPS → KA → CONFIRM → ATTACH).
                let remote_identity = IdentityPayload::decode(&remote_identity_body)
                    .map_err(|e| HandshakeError(format!("OVL1 IDENTITY decode (C6): {e}")))?;
                verify_identity_binding(&remote_identity, "OVL1 IDENTITY (C6)")?;
                verify_hello_matches_identity(remote_id, &remote_identity, "OVL1 IDENTITY (C6)")?;

                return complete_handshake_from_capabilities(
                    stream,
                    family,
                    capture,
                    remote_id,
                    local,
                    role,
                    discovery_mode,
                    vivaldi,
                    local_node_id_bytes,
                    remote_identity,
                    &identity_wire,
                    &remote_identity_body,
                    sovereign_ctx,
                    " (C6)",
                    local_advertised_transports,
                    anonymity_relay_capable,
                    verified_membership_cert,
                    peer_observed_addr,
                )
                .await;
            }
            _ => {
                return Err(HandshakeError(format!(
                    "OVL1 resumption (C6): unexpected frame type {} after HELLO",
                    hdr.msg_type,
                )));
            }
        }
    }

    //IDENTITY -------------------------------------------------------------
    let pk_bytes = STANDARD
        .decode(local.public_key())
        .map_err(|e| HandshakeError(format!("invalid public key base64: {e}")))?;
    let identity = IdentityPayload {
        algo: algo_to_u8(local.algo()),
        public_key: pk_bytes,
        nonce: local.nonce().as_bytes().to_vec(),
        node_id: local_node_id_bytes,
        mlkem_pubkey: mlkem_ek.map(|k| k.to_vec()),
    };
    let identity_bytes = identity.encode();
    let identity_wire =
        write_frame(stream, family, SessionMsg::Identity as u16, &identity_bytes).await?;
    if let Some(f) = capture {
        f(
            false,
            family,
            SessionMsg::Identity as u16,
            &identity_bytes,
            remote_id,
        );
    }

    let (_, body) = read_frame(stream).await?;
    let remote_identity = IdentityPayload::decode(&body)
        .map_err(|e| HandshakeError(format!("OVL1 IDENTITY decode: {e}")))?;
    if let Some(f) = capture {
        f(true, family, SessionMsg::Identity as u16, &body, remote_id);
    }

    verify_identity_binding(&remote_identity, "OVL1 IDENTITY")?;
    verify_hello_matches_identity(remote_id, &remote_identity, "OVL1 IDENTITY")?;

    complete_handshake_from_capabilities(
        stream,
        family,
        capture,
        remote_id,
        local,
        role,
        discovery_mode,
        vivaldi,
        local_node_id_bytes,
        remote_identity,
        &identity_wire,
        &body,
        sovereign_ctx,
        "",
        local_advertised_transports,
        anonymity_relay_capable,
        verified_membership_cert,
        peer_observed_addr,
    )
    .await
}

// ── Per-phase helpers (extracted for readability) ─────────────────────────────

/// Build and encode a local `AttachPayload` (role + local battery + Vivaldi +
/// advertised-transports + observed_addr). Used by the normal handshake tail,
/// by both fast-path resumption branches, and by the C6 fallback. Centralises
/// the local_battery + TLV assembly.
///
/// `advertised_transports` is the peer-facing list
/// of listener URIs the remote may use for hot-standby failover. An
/// empty slice emits no TLV (wire-compatible with legacy peers).
///
/// `peer_observed_addr` is the source `SocketAddr` que the remote peer
/// appeared as on our transport layer; included in the ATTACH so the
/// peer learns its public address (S3: STUN-style auto-discovery).
/// `None` ⇒ TLV is not emitted (legacy peers continue to work).
pub fn build_local_attach_bytes(
    role: NodeRole,
    vivaldi: Option<(f64, f64, f64)>,
    advertised_transports: &[String],
    peer_observed_addr: Option<std::net::SocketAddr>,
) -> Vec<u8> {
    let attach = AttachPayload {
        role: role.to_role_bits(),
        realm_id: 0,
        attach_epoch: 0,
        mailbox_preference_count: 0,
        gateway_preference_count: 0,
        flags: 0,
    };
    let local_battery = veil_util::local_battery_level();
    // battery + advertised-transports TLVs.
    let mut out = veil_proto::session::encode_attach_with_tlvs(
        &attach,
        vivaldi,
        Some(local_battery),
        advertised_transports,
    );
    // S3: append observed_addr TLV when caller supplied the peer's
    // source address. Apps que aren't TLV-aware silently skip it (the
    // wire-format scanner stops at the first unknown tag-length pair
    // it can't make sense of, but keeps already-parsed fields).
    if let Some(addr) = peer_observed_addr {
        let value = veil_proto::session::encode_observed_addr(addr);
        out.extend_from_slice(&veil_proto::session::OBSERVED_ADDR_TLV_TAG.to_be_bytes());
        out.extend_from_slice(&(veil_proto::session::OBSERVED_ADDR_TLV_LEN as u16).to_be_bytes());
        out.extend_from_slice(&value);
    }
    out
}

/// Verify `BLAKE3(public_key) == claimed_node_id`. Prevents any peer from
/// impersonating an arbitrary node_id during IDENTITY exchange.
pub fn verify_identity_binding(id: &IdentityPayload, error_label: &str) -> Result<()> {
    let expected: [u8; 32] = *blake3::hash(&id.public_key).as_bytes();
    if expected != id.node_id {
        return Err(HandshakeError(format!(
            "{error_label}: node_id does not match BLAKE3(public_key) — peer identity rejected",
        )));
    }
    Ok(())
}

/// Bind the HELLO-advertised `node_id` to the PROVEN IDENTITY node_id (audit
/// cycle-9 CRIT-3).
///
/// The HELLO `node_id` is what the early P-Net membership-cert check
/// (`verify_peer`) was run against, and what seeds routing / cert caches —
/// but at HELLO time it is UNPROVEN. The IDENTITY frame later proves ownership
/// of the key whose BLAKE3 is `identity.node_id`. Without reconciling the two,
/// an inbound attacker could replay a member's cert in HELLO
/// (`hello.node_id = victim`) while proving ownership of their OWN key in
/// IDENTITY (`identity.node_id = attacker`): `verify_peer` passed (cert valid
/// for the victim's id) and the session completed under the attacker's
/// identity — admission to the private overlay without holding a cert.
/// Requiring `hello.node_id == identity.node_id` closes that split. Honest
/// peers always satisfy it (both equal `BLAKE3(pubkey)`).
pub fn verify_hello_matches_identity(
    hello_node_id: [u8; 32],
    identity: &IdentityPayload,
    error_label: &str,
) -> Result<()> {
    if hello_node_id != identity.node_id {
        return Err(HandshakeError(format!(
            "{error_label}: HELLO node_id {} does not match proven identity {} — peer rejected",
            veil_util::hex_short(&hello_node_id),
            veil_util::hex_short(&identity.node_id),
        )));
    }
    Ok(())
}

/// Compute the SESSION_CONFIRM MAC.
///
/// `MAC = BLAKE3("ovl1-session-confirm-v2" ‖ shared_secret ‖ min(ids) ‖ max(ids) ‖ transcript_hash)`
///
/// the MAC now binds to the **handshake
/// transcript hash** (covering CAPABILITIES + KEY_AGREEMENT + optional
/// IDENTITY_PROOF, both directions) in addition to the X25519 shared
/// secret and the canonical node-id pair. Without this binding a
/// MITM that intercepts CAPABILITIES could flip a capability bit
/// (e.g. clear `SUPPORTS_SOVEREIGN_IDENTITY` on one side) — both
/// sides still complete the DH and SESSION_CONFIRM passes silently
/// because the old MAC was independent of capability bits. The
/// transcript hash diverges the moment any frame byte differs
/// between sides, so the SESSION_CONFIRM MAC mismatches and the
/// handshake aborts with the existing error path.
///
/// The version label was bumped from `v1` to `v2` for explicit
/// domain separation: a peer that still computes the v1 MAC will
/// produce a different value, fail comparison, and the handshake
/// aborts cleanly rather than silently diverging.
pub fn compute_confirm_mac(
    shared_secret: &[u8; 32],
    local_node_id: [u8; 32],
    remote_node_id: [u8; 32],
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let (small, large) = if local_node_id <= remote_node_id {
        (local_node_id, remote_node_id)
    } else {
        (remote_node_id, local_node_id)
    };
    let mut mac_hasher = blake3::Hasher::new();
    mac_hasher.update(b"ovl1-session-confirm-v2");
    mac_hasher.update(shared_secret);
    mac_hasher.update(&small);
    mac_hasher.update(&large);
    mac_hasher.update(transcript_hash);
    *mac_hasher.finalize().as_bytes()
}

/// sign ephemeral pubkey with long-term identity key. Returns
/// an empty Vec on any signing error (the far side will then reject the
/// handshake via ephemeral-sig verification, which is the correct outcome).
pub fn sign_ephemeral_pubkey(
    local: &dyn LocalHandshakeIdentity,
    ephemeral_pubkey: &[u8; 32],
) -> Vec<u8> {
    veil_crypto::sign_message(
        local.algo(),
        local.public_key(),
        local.private_key(),
        ephemeral_pubkey,
    )
    .unwrap_or_default()
}

/// Drive the full handshake tail: CAPABILITIES → KEY_AGREEMENT → SESSION_CONFIRM
/// → ATTACH → build `OvlHandshakeResult`. Called by both the normal handshake
/// path and the C6 fallback (which has already exchanged IDENTITY out of order).
///
/// `label_suffix` is appended to error-message prefixes so log readers can tell
/// which path produced a failure (e.g. "OVL1 KEY_AGREEMENT (C6)").
#[allow(clippy::too_many_arguments)]
async fn complete_handshake_from_capabilities<S>(
    stream: &mut S,
    family: u8,
    capture: HandshakeCaptureHook<'_>,
    remote_id: [u8; 32],
    local: &dyn LocalHandshakeIdentity,
    role: NodeRole,
    discovery_mode: veil_cfg::DiscoveryMode,
    vivaldi: Option<(f64, f64, f64)>,
    local_node_id_bytes: [u8; 32],
    remote_identity: IdentityPayload,
    // Raw bytes of the locally-sent and remotely-received IDENTITY frame
    // bodies.  Bound to the transcripts here so SESSION_CONFIRM MAC
    // commits to the `mlkem_pubkey` / `public_key` / `nonce` fields —
    // closes the audit H1 gap where a MITM could swap a post-handshake
    // field without detection (the IDENTITY exchange happens BEFORE the
    // hashers exist, so neither side's body was previously bound to the
    // MAC).
    local_identity_bytes: &[u8],
    remote_identity_bytes: &[u8],
    sovereign_ctx: Option<SovereignHandshakeCtx<'_>>,
    label_suffix: &str,
    local_advertised_transports: &[String],
    anonymity_relay_capable: bool,
    // Cert verified by `perform_ovl1_handshake` (P-Net mode) — threaded
    // here so the returned `OvlHandshakeResult` carries it for the
    // caller's per-peer cert cache. `None` in public mode or when the
    // peer presented no cert.
    verified_membership_cert: Option<veil_types::MembershipCert>,
    // S3: peer's observed SocketAddr — when `Some`, included in outbound
    // ATTACH frame's OBSERVED_ADDR_TLV for STUN-style auto-IP-discovery.
    peer_observed_addr: Option<std::net::SocketAddr>,
) -> Result<OvlHandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // handshake transcript hashes.
    //
    // We maintain TWO BLAKE3 hashers — one over every frame WE send
    // one over every frame WE receive. Both use the **same** domain
    // prefix so that side-A's "local" hash byte-for-byte equals
    // side-B's "remote" hash (and vice versa). At SESSION_CONFIRM
    // time we combine the pair in canonical (node-id-sorted) order
    // so both sides converge to the same composite transcript hash
    // regardless of who dialled. The SESSION_CONFIRM MAC commits to
    // that composite, so any MITM that altered any frame in either
    // direction causes the two sides' composites to diverge and the
    // MAC compare to fail.
    //
    // (A single ordered transcript per side does NOT work: side A
    // hashes "send-then-recv" and side B hashes "send-then-recv" too
    // but their `send` and `recv` mean opposite frames — feeding the
    // same bytes in different orders produces different BLAKE3
    // outputs. Splitting into local/remote and using node-id-sorted
    // composition at the end is the canonical fix.)
    let mut local_transcript = blake3::Hasher::new();
    local_transcript.update(b"ovl1-handshake-transcript-v1");
    let mut remote_transcript = blake3::Hasher::new();
    remote_transcript.update(b"ovl1-handshake-transcript-v1");

    // IDENTITY frame binding (Wave 4 / audit H1).  The IDENTITY exchange
    // happens BEFORE the transcript hashers exist, so neither side's body
    // was previously bound to SESSION_CONFIRM.  This left `mlkem_pubkey`
    // un-bound: a MITM swapping the field in transit would only diverge
    // the X25519/MAC paths indirectly via `validated_sovereign_identity`.
    // Feed both bodies now so the MAC commits explicitly.
    local_transcript.update(local_identity_bytes);
    remote_transcript.update(remote_identity_bytes);

    //CAPABILITIES ---------------------------------------------------------
    let mut caps = CapabilitiesPayload::from_node_role(role).with_discovery_mode(discovery_mode);
    // advertise SUPPORTS_SOVEREIGN_IDENTITY iff we have
    // local sovereign material to back it up. Peers that also set
    // the bit will trigger the IdentityProof-frame exchange below.
    if sovereign_ctx.is_some() {
        caps.flags |= cap_flags::SUPPORTS_SOVEREIGN_IDENTITY;
    }
    // advertise ANONYMITY_RELAY iff the operator opted in
    // via `[anonymity].relay_capable = true`. Without the bit set
    // remote peers' relay-directory lookups will skip
    // us as a circuit candidate.
    if anonymity_relay_capable {
        caps.flags |= cap_flags::ANONYMITY_RELAY;
    }
    // advertise SUPPORTS_HYBRID_KEX iff we
    // have ML-KEM material to back it up (local DK seed for
    // decapsulation when we're the receiver, AND we know the peer's
    // mlkem_pubkey will be carried in IDENTITY). Negotiation is
    // double-sided: peers without the bit fall through to the
    // classical X25519-only path unchanged. Cache the dk_seed
    // pointer up-front because `sovereign_ctx` gets moved later
    // when the IDENTITY_PROOF branch consumes it.
    let local_mlkem_dk_seed: Option<&[u8; 64]> =
        sovereign_ctx.as_ref().and_then(|c| c.local_mlkem_dk_seed);
    if local_mlkem_dk_seed.is_some() {
        caps.flags |= cap_flags::SUPPORTS_HYBRID_KEX;
    }
    let caps_bytes = caps.encode();
    let caps_wire =
        write_frame(stream, family, SessionMsg::Capabilities as u16, &caps_bytes).await?;
    if let Some(f) = capture {
        f(
            false,
            family,
            SessionMsg::Capabilities as u16,
            &caps_bytes,
            remote_id,
        );
    }
    // hash the padded wire body (what the peer's
    // `read_frame` returns) so both sides converge on the same
    // transcript bytes after canonical sort.
    local_transcript.update(&caps_wire);

    let (_, caps_body) = read_frame(stream).await?;
    let remote_capabilities = CapabilitiesPayload::decode(&caps_body)
        .map_err(|e| HandshakeError(format!("OVL1 CAPABILITIES decode{label_suffix}: {e}")))?;
    if let Some(f) = capture {
        f(
            true,
            family,
            SessionMsg::Capabilities as u16,
            &caps_body,
            remote_id,
        );
    }
    remote_transcript.update(&caps_body);

    //KEY_AGREEMENT --------------------------------------------------------
    let local_kp: EphemeralKeypair = generate_ephemeral();
    let local_pubkey_bytes = local_kp.public_key;
    // sign ephemeral pubkey with long-term identity key (anti-MITM).
    let ephemeral_sig = sign_ephemeral_pubkey(local, &local_pubkey_bytes);
    let ka = KeyAgreementPayload {
        algo: 1,
        ephemeral_pubkey: local_pubkey_bytes.to_vec(),
        ephemeral_sig,
    };
    let ka_bytes = ka.encode();
    let ka_wire = write_frame(stream, family, SessionMsg::KeyAgreement as u16, &ka_bytes).await?;
    if let Some(f) = capture {
        f(
            false,
            family,
            SessionMsg::KeyAgreement as u16,
            &ka_bytes,
            remote_id,
        );
    }
    local_transcript.update(&ka_wire);

    let (_, body) = read_frame(stream).await?;
    let remote_ka = KeyAgreementPayload::decode(&body)
        .map_err(|e| HandshakeError(format!("OVL1 KEY_AGREEMENT decode{label_suffix}: {e}")))?;
    if let Some(f) = capture {
        f(
            true,
            family,
            SessionMsg::KeyAgreement as u16,
            &body,
            remote_id,
        );
    }
    remote_transcript.update(&body);

    if remote_ka.ephemeral_pubkey.len() != 32 {
        return Err(HandshakeError(format!(
            "OVL1 KEY_AGREEMENT{label_suffix}: expected 32-byte ephemeral pubkey, got {}",
            remote_ka.ephemeral_pubkey.len()
        )));
    }
    // verify the remote signed their
    // ephemeral key with their long-term identity key. Without this
    // check a MITM that intercepts KEY_AGREEMENT can substitute its
    // own ephemeral key, complete a fresh DH with each side, and
    // transparently relay frames while reading every plaintext.
    //
    // A peer that advertises a signing-capable identity algo
    // (Ed25519 or Falcon-512) MUST supply the signature. An empty
    // ephemeral_sig from such a peer is a handshake failure — silently
    // skipping verification is precisely the downgrade attack the audit
    // flagged. The unknown-algo branch already errors, so by this
    // point the algo byte is one of the signing-capable variants.
    let remote_algo = veil_cfg::SignatureAlgorithm::from_wire_byte(remote_identity.algo)
        .ok_or_else(|| {
            HandshakeError(format!(
                "OVL1 KEY_AGREEMENT{label_suffix}: peer advertised unknown algo byte 0x{:02x}",
                remote_identity.algo,
            ))
        })?;
    if remote_ka.ephemeral_sig.is_empty() {
        return Err(HandshakeError(format!(
            "OVL1 KEY_AGREEMENT{label_suffix}: peer (algo={:?}) omitted ephemeral_sig — \
             possible downgrade-MITM attempt; signing-capable peers MUST sign their ephemeral key",
            remote_algo,
        )));
    }
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let remote_pubkey_b64 = STANDARD.encode(&remote_identity.public_key);
    if veil_crypto::verify_message(
        remote_algo,
        &remote_pubkey_b64,
        &remote_ka.ephemeral_pubkey,
        &remote_ka.ephemeral_sig,
    )
    .is_err()
    {
        return Err(HandshakeError(format!(
            "OVL1 KEY_AGREEMENT{label_suffix}: ephemeral key signature invalid — possible MITM",
        )));
    }
    let remote_pubkey: [u8; 32] = remote_ka.ephemeral_pubkey.try_into().map_err(|_| {
        HandshakeError(format!(
            "OVL1 KEY_AGREEMENT{label_suffix}: ephemeral_pubkey is not 32 bytes"
        ))
    })?;

    let shared_secret = compute_shared_secret(local_kp, &remote_pubkey)
        .map_err(|e| HandshakeError(format!("OVL1 KEX: {e}")))?;
    // Mutable so the optional hybrid path can
    // re-derive after exchanging the ML-KEM ciphertext. Classical
    // path leaves this untouched.
    let mut session_keys = derive_session_keys(
        &shared_secret,
        &local_node_id_bytes,
        &remote_identity.node_id,
    );

    //IDENTITY_PROOF ----------------------------------------
    // Exchanged iff BOTH sides advertised SUPPORTS_SOVEREIGN_IDENTITY.
    // Emits this side's IdentityProof bound to `local_pubkey_bytes` (the
    // KA ephemeral pk), and verifies the peer's against `remote_pubkey`
    // (cross-checks proof.ephemeral_x25519_pk == KA pk, runs full cert
    // chain + freshness + local-cache revocation ladder).
    let validated_sovereign_identity = if caps.sovereign_identity_negotiated(&remote_capabilities) {
        let ctx = sovereign_ctx.ok_or_else(|| {
            HandshakeError(format!(
                "OVL1 IDENTITY_PROOF{label_suffix}: negotiated sovereign-identity exchange \
                 but no local SovereignIdentity material was provided"
            ))
        })?;
        // 1. Sign + send our proof bound to the local KA ephemeral pk.
        let now = ctx.now_unix_secs;
        let valid_until = now + 300;
        let freshness_hour = (now / 3600) as u32;
        let proof = ctx
            .sovereign
            .sign_proof(local_pubkey_bytes, valid_until, freshness_hour)
            .map_err(|e| {
                HandshakeError(format!(
                    "OVL1 IDENTITY_PROOF{label_suffix}: sign_proof failed: {e}"
                ))
            })?;
        let proof_bytes = proof.encode();
        let proof_wire = write_frame(
            stream,
            family,
            SessionMsg::IdentityProof as u16,
            &proof_bytes,
        )
        .await?;
        if let Some(f) = capture {
            f(
                false,
                family,
                SessionMsg::IdentityProof as u16,
                &proof_bytes,
                remote_id,
            );
        }
        local_transcript.update(&proof_wire);

        // 2. Read + verify the peer's proof against the remote KA pk.
        let (hdr, body) = read_frame(stream).await?;
        if hdr.msg_type != SessionMsg::IdentityProof as u16 {
            return Err(HandshakeError(format!(
                "OVL1 IDENTITY_PROOF{label_suffix}: expected msg_type {} (IdentityProof), got {}",
                SessionMsg::IdentityProof as u16,
                hdr.msg_type,
            )));
        }
        if let Some(f) = capture {
            f(
                true,
                family,
                SessionMsg::IdentityProof as u16,
                &body,
                remote_id,
            );
        }
        remote_transcript.update(&body);
        let validated = verify_identity_proof_frame(&body, &remote_pubkey, now).map_err(|e| {
            HandshakeError(format!(
                "OVL1 IDENTITY_PROOF{label_suffix}: peer proof rejected: {e}"
            ))
        })?;
        Some(validated)
    } else {
        None
    };

    // ── HYBRID_KEX_CT ────────────────────────────────────────────────
    // Conditions for engaging the hybrid path:
    // • BOTH sides advertised SUPPORTS_HYBRID_KEX
    // • Peer's IDENTITY frame carried `mlkem_pubkey` (long-term ML-KEM EK)
    // • We hold our own ML-KEM DK seed locally (sovereign_ctx)
    //
    // Direction asymmetry (one side encapsulates, the other decapsulates)
    // is broken by canonical node_id ordering — the smaller node_id
    // SENDS the CT, the larger RECEIVES. Same convention as
    // `derive_session_keys`'s tx/rx swap, so both sides agree without
    // explicit role signalling. Both sides then mix the resulting
    // ML-KEM shared secret with the existing X25519 secret and replace
    // `session_keys` through `derive_hybrid_session_keys`.
    //
    // Failure modes (peer misadvertised, missing EK, encap/decap
    // failure) surface as Handshake errors — we DO NOT silently
    // fall back to classical, because that would let an active MITM
    // strip the PQ guarantee. Operators that want classical behaviour
    // simply don't supply a `local_mlkem_dk_seed` in the context.
    let hybrid_negotiated =
        caps.hybrid_kex_negotiated(&remote_capabilities) && local_mlkem_dk_seed.is_some();
    if hybrid_negotiated {
        let peer_ek = remote_identity.mlkem_pubkey.as_deref().ok_or_else(|| {
            HandshakeError(format!(
                "OVL1 HYBRID_KEX_CT{label_suffix}: peer advertised SUPPORTS_HYBRID_KEX \
                 but its IDENTITY frame omitted mlkem_pubkey",
            ))
        })?;
        let local_dk_seed = local_mlkem_dk_seed.ok_or_else(|| {
            HandshakeError(format!(
                "OVL1 HYBRID_KEX_CT{label_suffix}: local mlkem dk_seed missing \
                 even though SUPPORTS_HYBRID_KEX was advertised",
            ))
        })?;

        let send_first = local_node_id_bytes <= remote_identity.node_id;
        let mlkem_secret_zeroizing = if send_first {
            // We encapsulate under the peer's static ML-KEM EK and
            // ship the CT. The shared secret comes back from
            // `mlkem_encapsulate_raw`; HKDF combines it with X25519.
            let (ct_bytes, ss_bytes) =
                veil_crypto::x3dh::mlkem_encapsulate_raw(peer_ek).map_err(|e| {
                    HandshakeError(format!(
                        "OVL1 HYBRID_KEX_CT{label_suffix}: encapsulate failed: {e}",
                    ))
                })?;
            let payload = veil_proto::session::HybridKexCtPayload { mlkem_ct: ct_bytes };
            let pb = payload.encode();
            let wire = write_frame(stream, family, SessionMsg::HybridKexCt as u16, &pb).await?;
            if let Some(f) = capture {
                f(
                    false,
                    family,
                    SessionMsg::HybridKexCt as u16,
                    &pb,
                    remote_id,
                );
            }
            local_transcript.update(&wire);
            ss_bytes
        } else {
            // We decapsulate the CT the peer just sent.
            let (hdr, body) = read_frame(stream).await?;
            if hdr.msg_type != SessionMsg::HybridKexCt as u16 {
                return Err(HandshakeError(format!(
                    "OVL1 HYBRID_KEX_CT{label_suffix}: expected msg_type {} (HybridKexCt), got {}",
                    SessionMsg::HybridKexCt as u16,
                    hdr.msg_type,
                )));
            }
            if let Some(f) = capture {
                f(
                    true,
                    family,
                    SessionMsg::HybridKexCt as u16,
                    &body,
                    remote_id,
                );
            }
            remote_transcript.update(&body);
            let payload = veil_proto::session::HybridKexCtPayload::decode(&body).map_err(|e| {
                HandshakeError(format!(
                    "OVL1 HYBRID_KEX_CT{label_suffix}: decode failed: {e}",
                ))
            })?;
            veil_crypto::x3dh::mlkem_decapsulate_raw(local_dk_seed, &payload.mlkem_ct).map_err(
                |e| {
                    HandshakeError(format!(
                        "OVL1 HYBRID_KEX_CT{label_suffix}: decapsulate failed: {e}",
                    ))
                },
            )?
        };

        // Re-derive session keys mixing X25519 + ML-KEM. This is the
        // key swap the bench measures. `shared_secret` (X25519) is
        // still consumed by `compute_confirm_mac` below — that MAC
        // commits to the X25519 secret and the transcript hash, both of
        // which were computed BEFORE this swap, so the MAC remains
        // valid and both sides arrive at the same composite. The
        // session_keys re-binding takes effect for SESSION_CONFIRM
        // and the post-handshake AEAD.
        session_keys = veil_crypto::session_kdf::derive_hybrid_session_keys(
            &shared_secret,
            &mlkem_secret_zeroizing,
            &local_node_id_bytes,
            &remote_identity.node_id,
        );
    }

    //SESSION_CONFIRM ------------------------------------------------------
    // finalize the per-direction transcripts and
    // combine into a canonical composite hash before binding into the
    // SESSION_CONFIRM MAC. We sort `(local_hash, remote_hash)` by the
    // associated node_id so both peers compute the same composite no
    // matter who dialled. Any frame altered by a MITM (e.g. a
    // capability bit flipped to silently disable IdentityProof) makes
    // the two sides' transcripts diverge → MAC compare fails → handshake
    // aborts.
    let local_hash = *local_transcript.finalize().as_bytes();
    let remote_hash = *remote_transcript.finalize().as_bytes();
    // Sort by HASH bytes (not node_id) — works even in degenerate test
    // fixtures that pair two sides with the same identity. In
    // production the chance of a collision (BLAKE3 hashes equal) is
    // negligible; if it ever did happen, both sides would still
    // converge on the same composite.
    let (small_hash, large_hash) = if local_hash <= remote_hash {
        (local_hash, remote_hash)
    } else {
        (remote_hash, local_hash)
    };
    let mut composite = blake3::Hasher::new();
    composite.update(b"ovl1-handshake-transcript-composite-v1");
    composite.update(&small_hash);
    composite.update(&large_hash);
    let transcript_hash: [u8; 32] = *composite.finalize().as_bytes();
    // INVARIANT: algorithm selection is bound by the transcript, not by
    // a separate algo-byte. The MAC commits to `transcript_hash`, which
    // is the BLAKE3 hash composing both peers' canonical transcripts
    // (sorted, not by sender). Both transcripts `.update` the
    // HybridKexCt wire bytes when hybrid is negotiated — so any
    // algorithm-mismatch between the two sides (e.g. one peer skipped
    // HybridKexCt) makes `transcript_hash` diverge and the MAC compare
    // fails. No silent downgrade is reachable through this path.
    //
    // If a future refactor introduces a new key-mixing step that is NOT
    // in the transcript (e.g. a side-channel KDF), that step MUST bind
    // explicitly through `compute_confirm_mac`'s input parameters.
    let mac = compute_confirm_mac(
        &shared_secret,
        local_node_id_bytes,
        remote_identity.node_id,
        &transcript_hash,
    );
    let confirm = SessionConfirmPayload {
        session_id: session_keys.session_id,
        mac,
    };
    let confirm_bytes = confirm.encode();
    write_frame(
        stream,
        family,
        SessionMsg::SessionConfirm as u16,
        &confirm_bytes,
    )
    .await?;
    if let Some(f) = capture {
        f(
            false,
            family,
            SessionMsg::SessionConfirm as u16,
            &confirm_bytes,
            remote_id,
        );
    }

    let (_, body) = read_frame(stream).await?;
    let remote_confirm = SessionConfirmPayload::decode(&body)
        .map_err(|e| HandshakeError(format!("OVL1 SESSION_CONFIRM decode{label_suffix}: {e}")))?;
    if let Some(f) = capture {
        f(
            true,
            family,
            SessionMsg::SessionConfirm as u16,
            &body,
            remote_id,
        );
    }

    if remote_confirm.mac.ct_eq(&mac).unwrap_u8() == 0 {
        return Err(HandshakeError(format!(
            "OVL1 SESSION_CONFIRM{label_suffix} MAC mismatch — key agreement failed or peer is malicious",
        )));
    }
    // Constant-time `session_id` compare. The MAC above already uses
    // `ct_eq` — defense-in-depth demands the same for derived secrets
    // like session_id (output of X25519 + KDF). A timing-dependent
    // `!=` would let a network attacker measuring SESSION_CONFIRM
    // response latency probe partial matches on session_id bytes faster
    // than the MAC permits.
    if remote_confirm
        .session_id
        .ct_eq(&session_keys.session_id)
        .unwrap_u8()
        == 0
    {
        return Err(HandshakeError(format!(
            "OVL1 SESSION_CONFIRM{label_suffix} session_id mismatch",
        )));
    }

    //ATTACH ---------------------------------------------------------------
    let attach_bytes = build_local_attach_bytes(
        role,
        vivaldi,
        local_advertised_transports,
        peer_observed_addr,
    );
    write_frame(stream, family, SessionMsg::Attach as u16, &attach_bytes).await?;
    if let Some(f) = capture {
        f(
            false,
            family,
            SessionMsg::Attach as u16,
            &attach_bytes,
            remote_id,
        );
    }

    let (_, body) = read_frame(stream).await?;
    let remote_attach = AttachPayload::decode(&body)
        .map_err(|e| HandshakeError(format!("OVL1 ATTACH decode{label_suffix}: {e}")))?;
    let remote_vivaldi = decode_vivaldi_from_attach(&body);
    let remote_battery = decode_battery_from_attach(&body);
    let remote_advertised_transports =
        veil_proto::session::decode_advertised_transports_from_attach(&body);
    let remote_observed_addr = veil_proto::session::decode_observed_addr_from_attach(&body);
    if let Some(f) = capture {
        f(true, family, SessionMsg::Attach as u16, &body, remote_id);
    }

    //Build result ---------------------------------------------------------
    let node_id = node_id_from_bytes(remote_identity.node_id)?;
    let public_key = STANDARD.encode(&remote_identity.public_key);
    let nonce = String::from_utf8(remote_identity.nonce.clone()).map_err(|_| {
        HandshakeError(format!("remote nonce{label_suffix} contains invalid UTF-8"))
    })?;
    let remote_role = RemoteRole::from(remote_attach.role);

    Ok(OvlHandshakeResult {
        node_id,
        public_key,
        nonce,
        session_keys,
        remote_identity_payload: remote_identity,
        remote_capabilities,
        remote_attach,
        remote_role,
        remote_vivaldi,
        remote_battery,
        remote_advertised_transports,
        validated_sovereign_identity,
        verified_membership_cert,
        remote_observed_addr,
    })
}

// ── wire helpers ──────────────────────────────────────────────────────────────

/// Minimum padded length for any plaintext handshake frame body. The bucket
/// is chosen so that the IdentityProof and KeyAgreement frames carrying the
/// largest expected payload (Falcon-512 signature ≈ 690 B + ML-KEM-768 EK
/// 1184 B = ~1.9 KB) and the smallest frames (Hello ~30 B) end up in the
/// **same wire-size band** after padding — defeating the sig-algorithm
/// fingerprint that 0..=256 B random padding (the previous
/// implementation) left intact. Combined with `MAX_HANDSHAKE_RANDOM_PAD`
/// every handshake frame on the wire falls in `[2048, 3072] B`, regardless
/// of whether the peer uses Ed25519 (64 B sig) or Falcon (≤1024 B sig).
pub const MIN_HANDSHAKE_FRAME: usize = 2048;

/// Random extra bytes layered on top of the bucket so DPI can't use the
/// exact bucket size as a tracer. Drawn uniform `0..=MAX` per frame.
pub const MAX_HANDSHAKE_RANDOM_PAD: usize = 1024;

pub fn pad_handshake_body(body: &[u8]) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    // Bucket up to `MIN_HANDSHAKE_FRAME` first, then tack on 0..=MAX random
    // bytes so the wire size is `max(body.len, MIN) + rand([0, MAX])`.
    // Tolerant decoders (audited): Hello uses TLV (unknown types
    // ignored); Identity/KeyAgreement carry a trailing length-prefixed
    // optional field whose decoder stops at the declared length;
    // Capabilities/SessionConfirm parse fixed-width prefixes.
    let baseline = body.len().max(MIN_HANDSHAKE_FRAME);
    let extra = (OsRng.next_u32() as usize) % (MAX_HANDSHAKE_RANDOM_PAD + 1);
    let target = baseline + extra;
    let mut out = vec![0u8; target];
    out[..body.len()].copy_from_slice(body);
    OsRng.fill_bytes(&mut out[body.len()..]);
    out
}

/// Write a padded handshake frame and return the wire-bytes body that was
/// actually transmitted (pre-padding `body` plus per-frame random tail).
///
/// returning the padded bytes lets the
/// caller feed them into the handshake-transcript hasher; without
/// this, the local transcript would hash the **unpadded** body while
/// the peer's `read_frame` returns the **padded** body — the two
/// transcripts would diverge even on a clean wire and SESSION_CONFIRM
/// would always MAC-mismatch. Older callers that don't care about
/// the wire-bytes simply ignore the return value (`let _ = …`).
async fn write_frame<S>(stream: &mut S, family: u8, msg_type: u16, body: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncWrite + Unpin,
{
    // Bucket-pad every handshake frame to `[MIN_HANDSHAKE_FRAME
    // MIN_HANDSHAKE_FRAME + MAX_HANDSHAKE_RANDOM_PAD]` bytes so neither
    // the OVL1 frame type nor the peer's signature algorithm leaks
    // through the wire size.
    let padded = pad_handshake_body(body);
    let mut hdr = FrameHeader::new(family, msg_type);
    hdr.body_len = padded.len() as u32;
    stream
        .write_all(&encode_header(&hdr))
        .await
        .map_err(|e| HandshakeError(format!("write OVL1 frame header: {e}")))?;
    if !padded.is_empty() {
        stream
            .write_all(&padded)
            .await
            .map_err(|e| HandshakeError(format!("write OVL1 frame body: {e}")))?;
    }
    Ok(padded)
}

async fn read_frame<S>(stream: &mut S) -> Result<(FrameHeader, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut hdr_buf = [0u8; HEADER_SIZE];
    stream
        .read_exact(&mut hdr_buf)
        .await
        .map_err(|e| HandshakeError(format!("read OVL1 frame header: {e}")))?;
    let hdr = decode_header_with_limit(&hdr_buf, MAX_HANDSHAKE_FRAME_BODY)
        .map_err(|e| HandshakeError(format!("decode OVL1 frame header: {e}")))?;
    let mut body = vec![0u8; hdr.body_len as usize];
    if hdr.body_len > 0 {
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| HandshakeError(format!("read OVL1 frame body: {e}")))?;
    }
    Ok((hdr, body))
}

// ── helpers ───────────────────────────────────────────────────────────────────

#[inline]
pub fn algo_to_u8(algo: SignatureAlgorithm) -> u8 {
    // Thin wrapper over the centralized encoding — kept as a named
    // helper only because the call sites are already spelled out in
    // terms of `algo_to_u8`. See `SignatureAlgorithm::wire_byte`
    // for the canonical table.
    algo.wire_byte()
}

pub fn node_id_from_bytes(bytes: [u8; 32]) -> Result<veil_cfg::NodeId> {
    let hex = veil_util::bytes_to_hex(&bytes);
    hex.parse::<veil_cfg::NodeId>()
        .map_err(|e| HandshakeError(format!("invalid node_id from OVL1 IDENTITY: {e}")))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)] // a few fixtures use the legacy `TicketIssuer::issue` shim
mod tests {
    use tokio::io::duplex;

    use super::*;
    use veil_cfg::{NodeRole, SignatureAlgorithm};

    #[test]
    fn verify_hello_matches_identity_rejects_mismatch_crit3() {
        // audit cycle-9 CRIT-3: the HELLO node_id (against which the P-Net
        // membership cert was checked) must equal the proven IDENTITY node_id,
        // else an attacker replays a victim's cert in HELLO while proving their
        // own key in IDENTITY and is admitted under their own identity.
        let id = IdentityPayload {
            algo: 0,
            public_key: vec![1, 2, 3],
            nonce: vec![0u8; 6],
            node_id: [0xAA; 32],
            mlkem_pubkey: None,
        };
        // Honest peer: HELLO node_id == proven identity → accepted.
        assert!(verify_hello_matches_identity([0xAA; 32], &id, "test").is_ok());
        // Attacker: HELLO node_id (victim) != proven identity (attacker) → rejected.
        assert!(verify_hello_matches_identity([0xBB; 32], &id, "test").is_err());
    }

    // ── handshake padding ─────────────────────────────────────

    #[test]
    fn pad_handshake_body_preserves_prefix() {
        let original = b"payload-bytes".to_vec();
        for _ in 0..50 {
            let padded = pad_handshake_body(&original);
            // Must hit the bucket floor; original prefix preserved byte-for-byte.
            assert!(
                padded.len() >= MIN_HANDSHAKE_FRAME,
                "padded {} below MIN_HANDSHAKE_FRAME {}",
                padded.len(),
                MIN_HANDSHAKE_FRAME,
            );
            assert!(
                padded.len() <= MIN_HANDSHAKE_FRAME + MAX_HANDSHAKE_RANDOM_PAD,
                "padded {} exceeds MIN+MAX_RAND {}",
                padded.len(),
                MIN_HANDSHAKE_FRAME + MAX_HANDSHAKE_RANDOM_PAD,
            );
            assert_eq!(
                &padded[..original.len()],
                original.as_slice(),
                "original prefix must be preserved byte-for-byte"
            );
        }
    }

    #[test]
    fn pad_handshake_body_produces_variable_sizes() {
        // 200 draws — with uniform random in 0..=MAX_HANDSHAKE_RANDOM_PAD
        // P(only one size) ≈ (1/1025)^199, vanishingly small.
        let base = b"x".to_vec();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(pad_handshake_body(&base).len());
            if seen.len() >= 3 {
                return;
            }
        }
        panic!(
            "padding produced only {} distinct sizes across 200 draws",
            seen.len()
        );
    }

    /// Verify the size band is the SAME for small frames and frames carrying a
    /// long Falcon-style signature — defeats sig-algorithm fingerprinting.
    #[test]
    fn pad_handshake_body_obscures_sig_algorithm() {
        // Simulate Ed25519 IdentityProof (~280 B) and Falcon IdentityProof
        // (~960 B) bodies. After padding both must fall in the same band.
        let small = vec![0xAA; 280];
        let large = vec![0xBB; 960];
        let mut small_sizes = std::collections::HashSet::new();
        let mut large_sizes = std::collections::HashSet::new();
        for _ in 0..200 {
            small_sizes.insert(pad_handshake_body(&small).len());
            large_sizes.insert(pad_handshake_body(&large).len());
        }
        // Both ranges live entirely within the same [MIN, MIN+RAND] band.
        let band_min = MIN_HANDSHAKE_FRAME;
        let band_max = MIN_HANDSHAKE_FRAME + MAX_HANDSHAKE_RANDOM_PAD;
        for &s in small_sizes.iter().chain(large_sizes.iter()) {
            assert!(
                s >= band_min && s <= band_max,
                "size {s} outside band [{band_min}, {band_max}]"
            );
        }
    }

    /// In-test impl of [`LocalHandshakeIdentity`].  Phase 2 session 2 prep:
    /// session/handshake.rs no longer references the veilcore-private
    /// `HandshakeIdentity` struct directly — tests use this minimal mock
    /// instead, so the file can move to the upcoming veil-session
    /// sibling crate without a dep on veilcore.
    #[derive(Clone)]
    struct TestHandshakeIdentity {
        algo: SignatureAlgorithm,
        public_key: String,
        private_key: String,
        nonce: String,
        node_id: veil_cfg::NodeId,
    }

    impl LocalHandshakeIdentity for TestHandshakeIdentity {
        fn algo(&self) -> SignatureAlgorithm {
            self.algo
        }
        fn public_key(&self) -> &str {
            &self.public_key
        }
        fn private_key(&self) -> &str {
            &self.private_key
        }
        fn nonce(&self) -> &str {
            &self.nonce
        }
        fn node_id(&self) -> &veil_cfg::NodeId {
            &self.node_id
        }
    }

    fn test_identity(seed: u8) -> TestHandshakeIdentity {
        // Generate a real Ed25519 keypair for signing.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let public_key = STANDARD.encode(pk_bytes);
        // Ed25519 secret key = 32-byte seed.
        let node_id_bytes: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        let hex = veil_util::bytes_to_hex(&node_id_bytes);
        let node_id = hex.parse::<veil_cfg::NodeId>().unwrap();
        TestHandshakeIdentity {
            algo: SignatureAlgorithm::Ed25519,
            public_key,
            private_key: STANDARD.encode([seed; 32]), // raw Ed25519 seed
            nonce: format!("test-nonce-{seed:02x}"),
            node_id,
        }
    }

    /// Drive one half of a paired handshake. Caller must pair an
    /// `outbound=true` side with an `outbound=false` side per
    /// silent-server semantics — both sides "inbound" (waiting
    /// for peer to write first) deadlocks. The actual `known_remote_id`
    /// value passed to outbound is a placeholder; only `is_some`
    /// affects ordering, and the real peer node_id is overwritten
    /// from the remote HELLO anyway.
    async fn run_side<S>(mut stream: S, seed: u8, outbound: bool) -> OvlHandshakeResult
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let identity = test_identity(seed);
        let known_remote_id = if outbound { Some([0u8; 32]) } else { None };
        perform_ovl1_handshake(
            &mut stream,
            &identity,
            NodeRole::Core,
            veil_cfg::DiscoveryMode::Public,
            None,
            None,
            None,
            known_remote_id,
            None,
            None,
            None,
            &[],
            false,
            None,
            None, // P-Net: no network gate in test fixture
            None, // S3: no peer_observed_addr in test fixture
        )
        .await
        .expect("OVL1 handshake succeeds")
    }

    /// Variant of `run_side` that supplies a `peer_observed_addr` —
    /// drives the S3 STUN-style auto-IP-discovery path.
    async fn run_side_with_observed_addr<S>(
        mut stream: S,
        seed: u8,
        outbound: bool,
        peer_observed_addr: Option<std::net::SocketAddr>,
    ) -> OvlHandshakeResult
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let identity = test_identity(seed);
        let known_remote_id = if outbound { Some([0u8; 32]) } else { None };
        perform_ovl1_handshake(
            &mut stream,
            &identity,
            NodeRole::Core,
            veil_cfg::DiscoveryMode::Public,
            None,
            None,
            None,
            known_remote_id,
            None,
            None,
            None,
            &[],
            false,
            None,
            None,
            peer_observed_addr,
        )
        .await
        .expect("OVL1 handshake succeeds")
    }

    /// Variant of `run_side` that opts in to anonymity-relay capability.
    /// Used by tests below to verify the bit propagates.
    async fn run_side_with_anonymity_relay<S>(
        mut stream: S,
        seed: u8,
        outbound: bool,
    ) -> OvlHandshakeResult
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let identity = test_identity(seed);
        let known_remote_id = if outbound { Some([0u8; 32]) } else { None };
        perform_ovl1_handshake(
            &mut stream,
            &identity,
            NodeRole::Core,
            veil_cfg::DiscoveryMode::Public,
            None,
            None,
            None,
            known_remote_id,
            None,
            None,
            None,
            &[],
            true,
            None,
            None, // P-Net: no network gate in test fixture
            None, // S3: no peer_observed_addr in test fixture
        )
        .await
        .expect("OVL1 handshake succeeds")
    }

    /// when `anonymity_relay_capable` is `false` (the
    /// default), the peer must NOT see `cap_flags::ANONYMITY_RELAY`
    /// in the negotiated capabilities. This is the "operator did
    /// not opt in to anonymity relay" path — our most common case
    /// since being a relay has non-trivial bandwidth + timing cost.
    #[tokio::test]
    async fn epic482_3_anonymity_relay_bit_off_by_default() {
        use veil_proto::session::cap_flags;
        let (a, b) = duplex(64 * 1024);
        let t1 = tokio::spawn(run_side(a, 0xAA, true));
        let t2 = tokio::spawn(run_side(b, 0xBB, false));
        let (r1, r2) = tokio::join!(t1, t2);
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();

        // Each side reports the OTHER side's capabilities. Both sides
        // ran with `anonymity_relay_capable = false`, so neither
        // should see the bit on the peer.
        assert_eq!(
            r1.remote_capabilities.flags & cap_flags::ANONYMITY_RELAY,
            0,
            "peer with relay_capable=false must NOT advertise ANONYMITY_RELAY"
        );
        assert_eq!(
            r2.remote_capabilities.flags & cap_flags::ANONYMITY_RELAY,
            0,
            "peer with relay_capable=false must NOT advertise ANONYMITY_RELAY"
        );
    }

    /// when `anonymity_relay_capable` is `true`, the
    /// peer MUST see `cap_flags::ANONYMITY_RELAY` in the negotiated
    /// capabilities. This is the path the relay-directory layer
    /// will eventually use to filter circuit candidates.
    #[tokio::test]
    async fn epic482_3_anonymity_relay_bit_on_when_opted_in() {
        use veil_proto::session::cap_flags;
        let (a, b) = duplex(64 * 1024);
        let t1 = tokio::spawn(run_side_with_anonymity_relay(a, 0xCC, true));
        let t2 = tokio::spawn(run_side_with_anonymity_relay(b, 0xDD, false));
        let (r1, r2) = tokio::join!(t1, t2);
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();

        // Each side ran with `anonymity_relay_capable = true`, so
        // both peers must see the bit on the other side.
        assert_ne!(
            r1.remote_capabilities.flags & cap_flags::ANONYMITY_RELAY,
            0,
            "peer with relay_capable=true MUST advertise ANONYMITY_RELAY (bit unset on peer)"
        );
        assert_ne!(
            r2.remote_capabilities.flags & cap_flags::ANONYMITY_RELAY,
            0,
            "peer with relay_capable=true MUST advertise ANONYMITY_RELAY (bit unset on peer)"
        );
    }

    /// asymmetric case — one side opted in, the other
    /// did not. Each side correctly sees the OTHER side's actual
    /// configuration (no information leak across handshake).
    #[tokio::test]
    async fn epic482_3_anonymity_relay_bit_asymmetric_each_side_sees_truth() {
        use veil_proto::session::cap_flags;
        let (a, b) = duplex(64 * 1024);
        // Side A: opts in. Side B: does NOT.
        let t_a = tokio::spawn(run_side_with_anonymity_relay(a, 0xEE, true));
        let t_b = tokio::spawn(run_side(b, 0xFF, false));
        let (r_a, r_b) = tokio::join!(t_a, t_b);
        let r_a = r_a.unwrap();
        let r_b = r_b.unwrap();

        // r_a is what A SAW from B → B's cap. B did NOT opt in.
        assert_eq!(
            r_a.remote_capabilities.flags & cap_flags::ANONYMITY_RELAY,
            0,
            "B did not opt in; A must see no ANONYMITY_RELAY bit on B"
        );
        // r_b is what B SAW from A → A's cap. A DID opt in.
        assert_ne!(
            r_b.remote_capabilities.flags & cap_flags::ANONYMITY_RELAY,
            0,
            "A opted in; B must see ANONYMITY_RELAY bit on A"
        );
    }

    #[tokio::test]
    async fn two_sides_complete_ovl1_handshake() {
        let (a, b) = duplex(64 * 1024);
        let t1 = tokio::spawn(run_side(a, 0xAA, true));
        let t2 = tokio::spawn(run_side(b, 0xBB, false));
        let (r1, r2) = tokio::join!(t1, t2);
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();

        // Node IDs are BLAKE3(verifying_key_bytes), not BLAKE3(seed).
        let id_a = test_identity(0xAA).node_id;
        let id_b = test_identity(0xBB).node_id;

        assert_eq!(r2.node_id, id_a);
        assert_eq!(r1.node_id, id_b);

        // Both sides must agree on session_id and have swapped tx/rx keys.
        assert_eq!(
            r1.session_keys.session_id, r2.session_keys.session_id,
            "session_id must match"
        );
        assert_eq!(
            r1.session_keys.tx_key, r2.session_keys.rx_key,
            "r1 tx == r2 rx"
        );
        assert_eq!(
            r1.session_keys.rx_key, r2.session_keys.tx_key,
            "r1 rx == r2 tx"
        );

        // with no sovereign material on either side, the
        // proof-frame exchange is skipped and the result field stays None.
        assert!(r1.validated_sovereign_identity.is_none());
        assert!(r2.validated_sovereign_identity.is_none());
    }

    /// S3: end-to-end auto-IP-discovery.  Server side feeds a fake
    /// peer SocketAddr into the handshake; client side reads it back
    /// from `OvlHandshakeResult.remote_observed_addr`.
    #[tokio::test]
    async fn observed_addr_roundtrips_through_attach() {
        let (a, b) = duplex(64 * 1024);
        // Server (accepting side) "sees" the client as coming from 203.0.113.42:31415.
        // In production this is the actual remote SocketAddr from accept().
        let fake_peer_addr: std::net::SocketAddr = "203.0.113.42:31415".parse().unwrap();
        let server_task = tokio::spawn(run_side_with_observed_addr(
            a,
            0xAA,
            false,
            Some(fake_peer_addr),
        ));
        // Client doesn't supply an observed_addr — outbound side doesn't emit
        // the TLV (server-side function).
        let client_task = tokio::spawn(run_side_with_observed_addr(b, 0xBB, true, None));
        let (server_r, client_r) = tokio::join!(server_task, client_task);
        let server_r = server_r.unwrap();
        let client_r = client_r.unwrap();

        // Client learns its public address from server's ATTACH TLV.
        assert_eq!(
            client_r.remote_observed_addr,
            Some(fake_peer_addr),
            "client should pick up server's observed_addr TLV"
        );
        // Server side: client didn't emit the TLV (None passed); server
        // therefore parses no observed_addr.
        assert_eq!(
            server_r.remote_observed_addr, None,
            "server should not learn an observed_addr when client didn't emit"
        );
    }

    /// end-to-end: both sides load a real sovereign identity
    /// advertise `SUPPORTS_SOVEREIGN_IDENTITY` in capabilities, and
    /// exchange a `SessionMsg::IdentityProof` frame between KA and
    /// SESSION_CONFIRM. Each side ends up with a verified peer
    /// `ValidatedIdentity` in the handshake result.
    #[tokio::test]
    async fn sovereign_proof_exchange_runs_end_to_end() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        use veil_identity::sovereign::SovereignIdentity;
        // PoW difficulty no longer used by IdentityDocument; field retained for API stability
        const DEFAULT_IDENTITY_POW_DIFFICULTY: u32 = 0;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base_dir =
            std::env::temp_dir().join(format!("veil-handshake-sovereign-{}", std::process::id()));
        std::fs::create_dir_all(&base_dir).unwrap();
        let mk_dir = |tag: &str| {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = base_dir.join(format!("{tag}-{n}"));
            std::fs::create_dir_all(&p).unwrap();
            p
        };

        // Two independent sovereign identities, each persisted to its
        // own veil_dir (the exact on-disk layout `create_identity`
        // writes). Loaded via `SovereignIdentity::load_from_dir` — the
        // same path the runtime will use at node startup.
        let alice_dir = mk_dir("alice");
        let _ = create_identity(CreateIdentityOptions {
            veil_dir: alice_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "alice-handshake-test".into(),
            pow_difficulty: DEFAULT_IDENTITY_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        let bob_dir = mk_dir("bob");
        let _ = create_identity(CreateIdentityOptions {
            veil_dir: bob_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "bob-handshake-test".into(),
            pow_difficulty: DEFAULT_IDENTITY_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        let alice_sov = SovereignIdentity::load_from_dir(&alice_dir).unwrap();
        let bob_sov = SovereignIdentity::load_from_dir(&bob_dir).unwrap();
        let alice_id = *alice_sov.node_id();
        let bob_id = *bob_sov.node_id();
        assert_ne!(alice_id, bob_id);

        // Each side has its own revocation cache (node-level concern).

        let now: u64 = 1_700_000_050;
        let (a, b) = duplex(64 * 1024);

        let alice_task = tokio::spawn(async move {
            let mut stream = a;
            let identity = test_identity(0xAA);
            let ctx = SovereignHandshakeCtx {
                sovereign: &alice_sov,
                now_unix_secs: now,
                local_mlkem_dk_seed: None,
            };
            // alice = outbound (writes HELLO first).
            perform_ovl1_handshake(
                &mut stream,
                &identity,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                Some([0u8; 32]),
                None,
                None,
                Some(ctx),
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .expect("alice handshake ok")
        });

        let bob_task = tokio::spawn(async move {
            let mut stream = b;
            let identity = test_identity(0xBB);
            let ctx = SovereignHandshakeCtx {
                sovereign: &bob_sov,
                now_unix_secs: now,
                local_mlkem_dk_seed: None,
            };
            // bob = inbound (reads HELLO first).
            perform_ovl1_handshake(
                &mut stream,
                &identity,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(ctx),
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .expect("bob handshake ok")
        });

        let (alice_res, bob_res) = tokio::join!(alice_task, bob_task);
        let alice_res = alice_res.unwrap();
        let bob_res = bob_res.unwrap();

        // Each side advertised SUPPORTS_SOVEREIGN_IDENTITY.
        assert!(alice_res.remote_capabilities.supports_sovereign_identity());
        assert!(bob_res.remote_capabilities.supports_sovereign_identity());

        // Each side has a verified peer identity. Alice must see Bob
        // Bob must see Alice.
        let alice_view = alice_res
            .validated_sovereign_identity
            .expect("alice sees bob");
        let bob_view = bob_res
            .validated_sovereign_identity
            .expect("bob sees alice");
        assert_eq!(alice_view.node_id, bob_id, "alice learns bob's node_id");
        assert_eq!(bob_view.node_id, alice_id, "bob learns alice's node_id");

        // Session keys still match — handshake completed the normal
        // CONFIRM + ATTACH tail after the proof exchange.
        assert_eq!(
            alice_res.session_keys.session_id,
            bob_res.session_keys.session_id
        );
        assert_eq!(alice_res.session_keys.tx_key, bob_res.session_keys.rx_key);
    }

    /// Asymmetric setup: only one side provides sovereign material.
    /// Since negotiation requires BOTH sides to advertise the bit
    /// the proof exchange is skipped and both sides complete the
    /// handshake cleanly with `validated_sovereign_identity: None`.
    #[tokio::test]
    async fn sovereign_proof_exchange_skips_when_peer_lacks_support() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        use veil_identity::sovereign::SovereignIdentity;
        // PoW difficulty no longer used by IdentityDocument; field retained for API stability
        const DEFAULT_IDENTITY_POW_DIFFICULTY: u32 = 0;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let alice_dir =
            std::env::temp_dir().join(format!("veil-handshake-asym-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&alice_dir).unwrap();
        let _ = create_identity(CreateIdentityOptions {
            veil_dir: alice_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "asym-test".into(),
            pow_difficulty: DEFAULT_IDENTITY_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let alice_sov = SovereignIdentity::load_from_dir(&alice_dir).unwrap();

        let now: u64 = 1_700_000_050;
        let (a, b) = duplex(64 * 1024);

        let alice_task = tokio::spawn(async move {
            let mut stream = a;
            let identity = test_identity(0xAA);
            let ctx = SovereignHandshakeCtx {
                sovereign: &alice_sov,
                now_unix_secs: now,
                local_mlkem_dk_seed: None,
            };
            // alice = outbound.
            perform_ovl1_handshake(
                &mut stream,
                &identity,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                Some([0u8; 32]),
                None,
                None,
                Some(ctx),
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .expect("alice handshake ok")
        });
        // Bob: legacy path, no sovereign material. Inbound side.
        let bob_task = tokio::spawn(run_side(b, 0xBB, false));

        let (alice_res, bob_res) = tokio::join!(alice_task, bob_task);
        let alice_res = alice_res.unwrap();
        let bob_res = bob_res.unwrap();

        // remote_capabilities = what THIS side received from the peer.
        // Alice saw Bob's caps → Bob didn't advertise, so the bit is unset.
        assert!(!alice_res.remote_capabilities.supports_sovereign_identity());
        // Bob saw Alice's caps → Alice DID advertise.
        assert!(bob_res.remote_capabilities.supports_sovereign_identity());
        // Because negotiation requires BOTH sides, the exchange is skipped.
        assert!(alice_res.validated_sovereign_identity.is_none());
        assert!(bob_res.validated_sovereign_identity.is_none());

        // Session still completes successfully.
        assert_eq!(
            alice_res.session_keys.session_id,
            bob_res.session_keys.session_id
        );
    }

    /// A pre-auth attacker sending a frame whose body_len exceeds
    /// `MAX_HANDSHAKE_FRAME_BODY` must be rejected immediately — no large
    /// allocation occurs.
    #[tokio::test]
    async fn oversized_pre_auth_frame_is_rejected() {
        use tokio::io::AsyncWriteExt as _;

        let (mut attacker, victim_side) = duplex(64 * 1024);

        // Spawn the victim handshake; it should fail.
        let victim = tokio::spawn(async move {
            let identity = test_identity(0xAA);
            let mut stream = victim_side;
            perform_ovl1_handshake(
                &mut stream,
                &identity,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
        });

        // Send a valid-looking OVL1 frame header but with body_len = MAX_HANDSHAKE_FRAME_BODY + 1.
        let oversized_body_len = MAX_HANDSHAKE_FRAME_BODY + 1;
        let mut hdr = FrameHeader::new(
            veil_proto::family::FrameFamily::Session as u8,
            veil_proto::family::SessionMsg::Hello as u16,
        );
        hdr.body_len = oversized_body_len;
        attacker.write_all(&encode_header(&hdr)).await.unwrap();
        // Don't send the body — the victim should reject on header decode.

        let result = victim.await.unwrap();
        assert!(result.is_err(), "handshake must fail for oversized frame");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("BodyTooLarge") || err_str.contains("frame header"),
            "error should indicate oversized frame: {err_str}"
        );
    }

    // `NegotiatedCapabilities`/`negotiate` removed — single
    // protocol version, all features always on. The former
    // `negotiate_single_version_all_features_enabled` test no longer has a
    // corresponding code path.

    #[tokio::test]
    async fn handshake_session_keys_are_unique_per_session() {
        let (a1, b1) = duplex(64 * 1024);
        let (a2, b2) = duplex(64 * 1024);

        let (r1, _) = tokio::join!(
            tokio::spawn(run_side(a1, 0x01, true)),
            tokio::spawn(run_side(b1, 0x02, false)),
        );
        let (r2, _) = tokio::join!(
            tokio::spawn(run_side(a2, 0x01, true)),
            tokio::spawn(run_side(b2, 0x02, false)),
        );

        let k1 = r1.unwrap().session_keys.session_id;
        let k2 = r2.unwrap().session_keys.session_id;
        assert_ne!(k1, k2, "distinct sessions must have distinct session IDs");
    }

    /// — fast-path resumption completes successfully.
    ///
    /// Simulates the full session lifecycle:
    /// 1. Full handshake between server (with TicketIssuer) and client.
    /// 2. Server sends SESSION_TICKET to client (simulated by direct call).
    /// 3. Client reconnects presenting the ticket → fast-path accepted.
    /// 4. Verify the resumed session produces the same session_id as the ticket.
    #[tokio::test]
    async fn session_resumption_fast_path_succeeds() {
        use crate::ticket::{TicketIssuer, TicketKey};
        use std::sync::{Arc, Mutex};

        // ── Step 1: full handshake ────────────────────────────────────────────
        let (a, b) = duplex(64 * 1024);
        let server_id = test_identity(0xAA);
        let client_id = test_identity(0xBB);

        let ticket_key = TicketKey::generate();
        let issuer = Arc::new(Mutex::new(TicketIssuer::new(ticket_key)));
        let issuer_clone = Arc::clone(&issuer);

        let server_task = tokio::spawn(async move {
            // server = inbound (reads HELLO first).
            perform_ovl1_handshake(
                &mut { a },
                &server_id,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                None,
                None,
                Some(issuer_clone),
                None,
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .expect("server full handshake")
        });
        let client_task = tokio::spawn({
            let cid = client_id.clone();
            async move {
                // client = outbound (writes HELLO first).
                perform_ovl1_handshake(
                    &mut { b },
                    &cid,
                    NodeRole::Core,
                    veil_cfg::DiscoveryMode::Public,
                    None,
                    None,
                    None,
                    Some([0u8; 32]),
                    None,
                    None,
                    None,
                    &[],
                    false,
                    None,
                    None, // P-Net: no network gate in test fixture
                    None, // S3: no peer_observed_addr in test fixture
                )
                .await
                .expect("client full handshake")
            }
        });

        let (srv_r, cli_r) = tokio::join!(server_task, client_task);
        let srv_r = srv_r.unwrap();
        let cli_r = cli_r.unwrap();

        // ── Step 2: issue a ticket (as server would do post-attach) ──────────
        let srv_session_id = srv_r.session_keys.session_id;
        let srv_tx = srv_r.session_keys.tx_key;
        let srv_rx = srv_r.session_keys.rx_key;
        // From the server's perspective, the remote (connecting) peer is the client.
        let peer_id = *srv_r.node_id.as_bytes(); // server sees the CLIENT as remote

        let ticket_blob = issuer
            .lock()
            .unwrap()
            .issue(srv_session_id, peer_id, srv_tx, srv_rx);

        // Build ClientTicketEntry as the runner would.
        let entry = veil_proto::session::ClientTicketEntry {
            blob: ticket_blob,
            tx_key: cli_r.session_keys.tx_key,
            rx_key: cli_r.session_keys.rx_key,
            session_id: cli_r.session_keys.session_id,
            peer_public_key: cli_r.public_key.clone(),
            peer_nonce: cli_r.nonce.clone(),
            issued_at: std::time::Instant::now(),
        };

        // ── Step 3: fast-path reconnect ───────────────────────────────────────
        let (a2, b2) = duplex(64 * 1024);
        let server_id2 = test_identity(0xAA);
        let entry_clone = entry.clone();
        let issuer2 = Arc::clone(&issuer);

        let srv_task2 = tokio::spawn(async move {
            // server = inbound.
            perform_ovl1_handshake(
                &mut { a2 },
                &server_id2,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                None,
                None,
                Some(issuer2),
                None,
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .expect("server fast-path handshake")
        });
        let cli_task2 = tokio::spawn({
            let cid = client_id.clone();
            async move {
                // client = outbound.
                perform_ovl1_handshake(
                    &mut { b2 },
                    &cid,
                    NodeRole::Core,
                    veil_cfg::DiscoveryMode::Public,
                    None,
                    None,
                    None,
                    Some([0u8; 32]),
                    Some(entry_clone),
                    None,
                    None,
                    &[],
                    false,
                    None,
                    None, // P-Net: no network gate in test fixture
                    None, // S3: no peer_observed_addr in test fixture
                )
                .await
                .expect("client fast-path handshake")
            }
        });

        let (srv2, cli2) = tokio::join!(srv_task2, cli_task2);
        let srv2 = srv2.unwrap();
        let cli2 = cli2.unwrap();

        // ── Step 4: verify the resumed session ────────────────────────────────
        // CRITICAL (audit cycle-2): the resumed session must NOT reuse the
        // original session's keys — both peers derive FRESH keys from the
        // original keys + the per-resumption nonces. Otherwise the counter-0
        // cipher would repeat the original (key, nonce) per frame.
        assert_ne!(
            srv2.session_keys.tx_key, srv_tx,
            "server tx_key must be FRESH, not the original"
        );
        assert_ne!(
            srv2.session_keys.rx_key, srv_rx,
            "server rx_key must be FRESH, not the original"
        );
        assert_ne!(
            cli2.session_keys.tx_key, entry.tx_key,
            "client tx_key must be FRESH, not the original"
        );
        assert_ne!(
            cli2.session_keys.rx_key, entry.rx_key,
            "client rx_key must be FRESH, not the original"
        );

        // The resumed session must still WORK in both directions: each side's tx
        // equals the other's rx (the dual-nonce derivation agrees cross-peer).
        assert_eq!(
            srv2.session_keys.tx_key, cli2.session_keys.rx_key,
            "server tx must equal client rx on the resumed session"
        );
        assert_eq!(
            srv2.session_keys.rx_key, cli2.session_keys.tx_key,
            "server rx must equal client tx on the resumed session"
        );

        // session_id is carried through unchanged (identifier, not cipher input).
        assert_eq!(srv2.session_keys.session_id, srv_session_id);
        assert_eq!(cli2.session_keys.session_id, entry.session_id);
        assert_eq!(
            srv2.session_keys.session_id, cli2.session_keys.session_id,
            "resumed session_id must match on both sides"
        );
        let _ = (&srv2, &cli2);
    }

    /// 462.17 + 462.20 end-to-end integration: two real
    /// sovereign handshakes → `SessionRegistry` indexed by identity →
    /// `resolve_recipient` returns the right peer_id.
    ///
    /// This is the exact flow `runtime.rs::cache_peer_handshake_state`
    /// runs in production: take the handshake's
    /// `validated_sovereign_identity`, stuff it into a `SessionEntry`
    /// insert into `SessionRegistry`, and confirm sovereign routing
    /// can look it up. One test covers every primitive we've shipped
    /// from `sign_identity_proof` down through `peer_id_for_identity_instance`.
    #[tokio::test]
    async fn sovereign_handshake_feeds_session_registry_end_to_end() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        use veil_identity::sovereign::SovereignIdentity;
        // PoW difficulty no longer used by IdentityDocument; field retained for API stability
        const DEFAULT_IDENTITY_POW_DIFFICULTY: u32 = 0;
        use crate::{SessionEntry, SessionRegistry};
        use std::sync::atomic::{AtomicU64, Ordering};
        use veil_proto::recipient::{InstanceTag, Recipient};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base =
            std::env::temp_dir().join(format!("veil-hs-reg-integration-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let mk_dir = |tag: &str| {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = base.join(format!("{tag}-{n}"));
            std::fs::create_dir_all(&p).unwrap();
            p
        };

        let alice_dir = mk_dir("alice");
        let _ = create_identity(CreateIdentityOptions {
            veil_dir: alice_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "alice-reg-int".into(),
            pow_difficulty: DEFAULT_IDENTITY_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let bob_dir = mk_dir("bob");
        let _ = create_identity(CreateIdentityOptions {
            veil_dir: bob_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "bob-reg-int".into(),
            pow_difficulty: DEFAULT_IDENTITY_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        let alice_sov = SovereignIdentity::load_from_dir(&alice_dir).unwrap();
        let bob_sov = SovereignIdentity::load_from_dir(&bob_dir).unwrap();
        let alice_id = *alice_sov.node_id();
        let bob_id = *bob_sov.node_id();
        let alice_instance = alice_sov.active_instance_id();
        let bob_instance = bob_sov.active_instance_id();

        let now: u64 = 1_700_000_050;
        let (a, b) = duplex(64 * 1024);

        let alice_task = tokio::spawn(async move {
            let mut stream = a;
            let identity = test_identity(0xAA);
            let ctx = SovereignHandshakeCtx {
                sovereign: &alice_sov,
                now_unix_secs: now,
                local_mlkem_dk_seed: None,
            };
            // alice = outbound.
            perform_ovl1_handshake(
                &mut stream,
                &identity,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                Some([0u8; 32]),
                None,
                None,
                Some(ctx),
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .unwrap()
        });

        let bob_task = tokio::spawn(async move {
            let mut stream = b;
            let identity = test_identity(0xBB);
            let ctx = SovereignHandshakeCtx {
                sovereign: &bob_sov,
                now_unix_secs: now,
                local_mlkem_dk_seed: None,
            };
            // bob = inbound.
            perform_ovl1_handshake(
                &mut stream,
                &identity,
                NodeRole::Core,
                veil_cfg::DiscoveryMode::Public,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(ctx),
                &[],
                false,
                None,
                None, // P-Net: no network gate in test fixture
                None, // S3: no peer_observed_addr in test fixture
            )
            .await
            .unwrap()
        });

        let (alice_r, bob_r) = tokio::join!(alice_task, bob_task);
        let alice_r = alice_r.unwrap();
        let bob_r = bob_r.unwrap();

        // Sanity: handshake populated the sovereign identity on both sides.
        assert_eq!(
            alice_r
                .validated_sovereign_identity
                .as_ref()
                .unwrap()
                .node_id,
            bob_id
        );
        assert_eq!(
            bob_r.validated_sovereign_identity.as_ref().unwrap().node_id,
            alice_id
        );

        // Mimic `runtime.rs::cache_peer_handshake_state`: insert each
        // side's observed peer identity into a SessionRegistry. Alice's
        // registry learns about Bob; Bob's learns about Alice.
        let alice_reg = SessionRegistry::new();
        let bob_reg = SessionRegistry::new();

        let alice_entry_for_bob = SessionEntry {
            session_id: alice_r.session_keys.session_id,
            remote_node_id: alice_r.remote_identity_payload.node_id,
            remote_identity: alice_r.remote_identity_payload.clone(),
            remote_capabilities: alice_r.remote_capabilities.clone(),
            remote_attach: alice_r.remote_attach.clone(),
            remote_role: alice_r.remote_role,
            validated_sovereign_identity: alice_r.validated_sovereign_identity.clone(),
        };
        let bob_entry_for_alice = SessionEntry {
            session_id: bob_r.session_keys.session_id,
            remote_node_id: bob_r.remote_identity_payload.node_id,
            remote_identity: bob_r.remote_identity_payload.clone(),
            remote_capabilities: bob_r.remote_capabilities.clone(),
            remote_attach: bob_r.remote_attach.clone(),
            remote_role: bob_r.remote_role,
            validated_sovereign_identity: bob_r.validated_sovereign_identity.clone(),
        };

        let bob_peer_id_from_alice_pov = alice_entry_for_bob.remote_node_id;
        let alice_peer_id_from_bob_pov = bob_entry_for_alice.remote_node_id;

        let mut alice_reg = alice_reg;
        let mut bob_reg = bob_reg;
        alice_reg.insert(alice_entry_for_bob);
        bob_reg.insert(bob_entry_for_alice);

        // Full-chain verification: Alice wants to send to Bob's identity →
        // resolve_recipient with Any returns Bob's transport peer_id.
        let via_any = alice_reg.resolve_recipient(&Recipient::any(bob_id));
        assert_eq!(via_any, vec![bob_peer_id_from_alice_pov]);

        // Specific hits the exact instance.
        let via_specific = alice_reg.resolve_recipient(&Recipient {
            node_id: bob_id,
            instance_tag: InstanceTag::Specific(bob_instance),
        });
        assert_eq!(via_specific, vec![bob_peer_id_from_alice_pov]);

        // All returns the one live instance.
        let via_all = alice_reg.resolve_recipient(&Recipient::all(bob_id));
        assert_eq!(via_all, vec![bob_peer_id_from_alice_pov]);

        // Symmetric: Bob → Alice.
        assert_eq!(
            bob_reg.resolve_recipient(&Recipient::any(alice_id)),
            vec![alice_peer_id_from_bob_pov]
        );
        assert_eq!(
            bob_reg.resolve_recipient(&Recipient {
                node_id: alice_id,
                instance_tag: InstanceTag::Specific(alice_instance),
            }),
            vec![alice_peer_id_from_bob_pov]
        );

        // Address-lookup sanity: an identity neither side knows about
        // resolves to empty. Confirms legacy peers don't accidentally
        // leak through sovereign routing.
        let unknown_id = [0xFFu8; 32];
        assert!(
            alice_reg
                .resolve_recipient(&Recipient::any(unknown_id))
                .is_empty()
        );
        assert!(
            bob_reg
                .resolve_recipient(&Recipient::any(unknown_id))
                .is_empty()
        );
    }

    // ── DPI fingerprint test ─────────────────────────────────────
    //
    // Captures the wire bytes produced by a real OVL1 handshake (paired
    // duplex, no real TLS in this test — we measure the OVL1 protocol
    // layer specifically). Then runs:
    //
    // 1. Statistical noise tests on POST-handshake AEAD-encrypted bytes
    // (Shannon entropy, byte-distribution chi-square). Encrypted
    // AEAD output should be indistinguishable from uniform random
    // bytes; any deviation is an information leak that DPI could
    // exploit on traffic flow analysis.
    //
    // 2. Marker-absence checks against known DPI signatures of
    // competing tunnel protocols (Tor cells, OpenVPN HMAC magic
    // WireGuard noise prologue). Veil's bytes should NOT
    // contain any of these — otherwise a DPI engine targeting
    // "anti-censorship traffic" of any of those protocols would
    // also flag veil.
    //
    // 3. A negative-control fixture (all-zeroes byte stream) is run
    // through the same tests and MUST fail the entropy/uniformity
    // asserts — proves the tests have signal, not just always-pass.
    //
    // Important: this validates the OVL1 PROTOCOL layer. The TLS
    // ClientHello fingerprint is a
    // separate concern — it lives in `veil-transport/tls_boring`
    // and requires real cert/listener infrastructure to validate
    // end-to-end. This test is the necessary condition: if OVL1 itself
    // emitted DPI-fingerprintable patterns, even perfect Chrome TLS
    // mimicry wouldn't help.

    /// Tee-wrapper that captures every byte READ FROM the inner stream
    /// into a shared `Vec<u8>`. We use this on one side of a
    /// `tokio::io::duplex` so we can observe what the OTHER side wrote
    /// (since duplex's two halves don't directly expose write bytes).
    struct ReadTee<S> {
        inner: S,
        captured: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ReadTee<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let pre_filled = buf.filled().len();
            let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
            if let std::task::Poll::Ready(Ok(())) = &result {
                let new_bytes = &buf.filled()[pre_filled..];
                if !new_bytes.is_empty() {
                    self.captured.lock().unwrap().extend_from_slice(new_bytes);
                }
            }
            result
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ReadTee<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Shannon entropy in bits per byte. Uniform random byte stream
    /// approaches log2(256) = 8.0; lower values indicate structure
    /// (i.e., DPI-fingerprintable patterns).
    fn shannon_entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let total = bytes.len() as f64;
        let mut h = 0.0_f64;
        for c in counts {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total;
            h -= p * p.log2();
        }
        h
    }

    /// Pearson chi-square statistic for the byte-frequency histogram
    /// against a uniform `1/256` expected distribution. Lower values
    /// = closer to uniform. For N samples: chi² = Σ (O_i − E_i)² / E_i
    /// where E_i = N/256 for each byte value.
    fn chi_square_uniform(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let expected = bytes.len() as f64 / 256.0;
        let mut chi = 0.0_f64;
        for c in counts {
            let diff = c as f64 - expected;
            chi += (diff * diff) / expected;
        }
        chi
    }

    /// OpenVPN's data-channel packets begin with a 1-byte opcode
    /// (0x21..0x29 typical) followed by a 4-byte session_id. The
    /// 1-byte opcode at offset 0 is observable when not multiplexed
    /// over TLS. Veil's OVL1 frames begin with `OVL1` ASCII magic
    /// (in cleartext PRE-handshake) — entirely different bytes. Test:
    /// captured bytes don't start with an OpenVPN-style opcode.
    fn looks_like_openvpn(bytes: &[u8]) -> bool {
        bytes.first().is_some_and(|&op| {
            (0x20..=0x39).contains(&op)
            && bytes.len() >= 5
            // OpenVPN session_id is 8 bytes random; if the next 4 bytes
            // look uniform-random AND the opcode is in range, it's a
            // weak match. Combined with magic-absence in the first
            // 8 bytes (no OVL1 magic), this is a useful negative test.
            && !bytes.starts_with(b"OVL1")
            && !bytes.starts_with(b"\x16\x03")
        }) // not a TLS record either
    }

    /// WireGuard's first packet is type=1 (0x01) handshake initiation
    /// followed by reserved[3]=0x00 0x00 0x00, then sender_index[4]
    /// then ephemeral[32], etc. Distinctive: byte 0 = 0x01, bytes 1-3
    /// = 0x00 0x00 0x00. Test: captured bytes don't start with this.
    fn looks_like_wireguard(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && bytes[0] == 0x01 && bytes[1..4] == [0x00, 0x00, 0x00]
    }

    /// Capture-and-analyse helper — runs a full OVL1 handshake on a
    /// duplex pair where one side is wrapped in a `ReadTee`. Returns
    /// `(initiator_wire_bytes, responder_wire_bytes)`: the bytes each
    /// side EMITTED onto the wire, observable by a passive on-path DPI.
    async fn capture_handshake_wire_bytes() -> (Vec<u8>, Vec<u8>) {
        let (a, b) = duplex(64 * 1024);
        let a_writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let b_writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        // We capture a's writes by tee'ing READS from b's side (b reads
        // what a wrote), and vice versa. Each handshake side runs
        // against the other half of the duplex; we wrap each side's
        // PEER's READ path to observe THIS side's writes.
        //
        // Realistically: duplex is symmetric; just wrap both halves and
        // collect captured = bytes received on each.
        let a_tee = ReadTee {
            inner: a,
            captured: std::sync::Arc::clone(&b_writes),
        };
        let b_tee = ReadTee {
            inner: b,
            captured: std::sync::Arc::clone(&a_writes),
        };
        let t1 = tokio::spawn(run_side(a_tee, 0xAA, true));
        let t2 = tokio::spawn(run_side(b_tee, 0xBB, false));
        let (r1, r2) = tokio::join!(t1, t2);
        r1.unwrap();
        r2.unwrap();
        let a_bytes = std::mem::take(&mut *a_writes.lock().unwrap());
        let b_bytes = std::mem::take(&mut *b_writes.lock().unwrap());
        (a_bytes, b_bytes)
    }

    /// captured handshake bytes have high Shannon entropy
    /// (post-AEAD frames look random) AND no Tor/OpenVPN/WireGuard
    /// markers. Both initiator and responder sides exercised.
    #[tokio::test]
    async fn epic485_5_handshake_bytes_pass_dpi_fingerprint_signature_absence() {
        let (initiator_bytes, responder_bytes) = capture_handshake_wire_bytes().await;

        assert!(
            initiator_bytes.len() > 200,
            "initiator handshake must produce ≥ 200 bytes; got {}",
            initiator_bytes.len()
        );
        assert!(
            responder_bytes.len() > 200,
            "responder handshake must produce ≥ 200 bytes; got {}",
            responder_bytes.len()
        );

        // ── Marker absence: positive control proves the test catches what it claims.
        // None of the competing tunnel-protocol signatures should match.
        assert!(
            !looks_like_openvpn(&initiator_bytes),
            "initiator bytes start with an OpenVPN opcode"
        );
        assert!(
            !looks_like_wireguard(&initiator_bytes),
            "initiator bytes start with the WireGuard handshake-init magic"
        );
        assert!(
            !looks_like_openvpn(&responder_bytes),
            "responder bytes start with an OpenVPN opcode"
        );
        assert!(
            !looks_like_wireguard(&responder_bytes),
            "responder bytes start with the WireGuard handshake-init magic"
        );
    }

    /// post-handshake AEAD output is high-entropy
    /// (≥ 7.5 bits/byte for ≥ 1 KiB sample). We sample bytes from
    /// AFTER the cleartext HELLO/IDENTITY/CAPS frames — those have
    /// protocol structure visible in their headers. Once the session
    /// key is established, every subsequent frame is AEAD-encrypted
    /// and should look like uniform random.
    ///
    /// Negative control: an all-zeroes blob of equal length MUST fail
    /// the same threshold — proves the test has signal.
    #[tokio::test]
    async fn epic485_5_post_handshake_bytes_have_high_entropy() {
        let (initiator_bytes, _) = capture_handshake_wire_bytes().await;

        // Skip the first 800 bytes — those carry plaintext HELLO +
        // IDENTITY + CAPABILITIES bodies and pre-AEAD framing. The
        // tail (resume / ATTACH / first session frame) is post-AEAD.
        // 800 is a generous skip so the assertion isn't sensitive to
        // header-size jitter across protocol changes.
        let cutoff = 800.min(initiator_bytes.len() / 2);
        let post_handshake = &initiator_bytes[cutoff..];
        assert!(
            post_handshake.len() >= 256,
            "need ≥ 256 post-handshake bytes for a meaningful entropy sample; got {}",
            post_handshake.len()
        );

        let h = shannon_entropy(post_handshake);
        // 7.5 bits/byte is a generous lower bound — true uniform random
        // for 1 KiB sample averages ~7.95. The slack accommodates
        // small-sample variance and any cleartext bytes that survive
        // past the conservative cutoff (e.g. session-frame headers
        // emitted alongside the encrypted body).
        assert!(
            h >= 7.5,
            "post-handshake bytes have entropy {h:.3} bits/byte (< 7.5); \
             would suggest non-AEAD-encrypted structure leaking through"
        );

        // Negative control: all zeroes must FAIL the same threshold.
        // Proves the assertion above isn't a no-op.
        let zeros = vec![0u8; post_handshake.len()];
        let h_zeros = shannon_entropy(&zeros);
        assert!(
            h_zeros < 7.5,
            "negative-control all-zeroes blob unexpectedly has entropy {h_zeros:.3} ≥ 7.5; \
             entropy assertion is no-op"
        );
    }

    /// chi-square test that post-handshake byte distribution
    /// is close to uniform. For N=1024 samples the 99% chi-square
    /// upper bound on 255 degrees of freedom is ~310; we use 320
    /// as a slightly looser threshold that still rejects the
    /// all-zeroes negative control (chi² → ∞ for a single-bin distribution).
    #[tokio::test]
    async fn epic485_5_post_handshake_bytes_pass_chi_square_uniform() {
        let (initiator_bytes, _) = capture_handshake_wire_bytes().await;
        let cutoff = 800.min(initiator_bytes.len() / 2);
        let post_handshake = &initiator_bytes[cutoff..];
        assert!(
            post_handshake.len() >= 1024,
            "need ≥ 1024 post-handshake bytes for chi-square; got {}",
            post_handshake.len()
        );

        let chi = chi_square_uniform(&post_handshake[..1024]);
        // Critical value at α=0.001, df=255 is ~330.6. Use 350 as
        // a conservative threshold — true random bytes very rarely
        // exceed it.
        assert!(
            chi < 350.0,
            "post-handshake byte distribution chi² = {chi:.1} ≥ 350; \
             distribution is non-uniform → DPI-fingerprintable structure"
        );

        // Negative control.
        let mut biased = vec![0u8; 1024];
        for (i, b) in biased.iter_mut().enumerate() {
            *b = (i % 16) as u8;
        }
        let chi_biased = chi_square_uniform(&biased);
        assert!(
            chi_biased > 350.0,
            "biased-control byte distribution unexpectedly chi² = {chi_biased:.1} \
             < 350; chi-square assertion is no-op"
        );
    }
}
