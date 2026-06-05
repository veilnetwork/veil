//! NTOR handshake над elligator2-encoded Curve25519.
//!
//! Phase 1c of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! Adapted от Tor's obfs4 spec.  Two-flight handshake:
//!
//! ```text
//! Client → Server:
//!   [ 32 byte client elligator-representative Cr  ]
//!   [ 1 byte  client tweak                        ]
//!   [ 32 byte HMAC(node_id_mac_key, Cr || tweak || epoch_c) ]
//!   [ 1 byte  pad_len                              ]
//!   [ pad_len bytes random padding (0..=128)       ]
//!
//! Server response (silent drop on bad MAC):
//!   [ 32 byte server elligator-representative Sr  ]
//!   [ 1 byte  server tweak                        ]
//!   [ 32 byte AUTH = HMAC(auth_key, "obfs4-auth-v1:" || Cr || Sr || epoch_c || epoch_s) ]
//!   [ 1 byte  pad_len                              ]
//!   [ pad_len bytes random padding                 ]
//! ```
//!
//! C-01: there is NO plaintext timestamp on the wire. The hour-granular
//! `epoch = unix_secs / 3600` is bound into the MAC/AUTH only; the receiver
//! reconstructs candidate epochs `{e-1, e, e+1}` from its own clock. A Unix-
//! seconds timestamp would otherwise be a low-entropy near-constant island
//! (high bytes `00 00 00 00 6a …`) a DPI could fingerprint inside the
//! uniform-random opener.
//!
//! Where:
//! - `node_id_mac_key` = pre-shared 32-byte secret, derived от server's
//!   identity by HKDF.  Both sides know it (server-id-bound PSK).
//! - `auth_key` = HKDF(`shared_secret`, "obfs4-auth-key-v1") computed
//!   AFTER ECDH.
//! - `shared_secret` = ECDH(C, S) = ECDH(Cx, S) = ECDH(Sx, C).  Both
//!   sides compute the same value.
//!
//! ## Anti-probe properties
//!
//! - Server silent-drops connections где the client's MAC doesn't verify
//!   under `node_id_mac_key`.  Active prober без the PSK cannot
//!   trigger а response.
//! - The hour-granular `epoch` bound into the MAC (never sent on the wire,
//!   C-01) prevents replay across a wide window: the receiver reconstructs
//!   candidate epochs `{e-1, e, e+1}` from its own clock, so a handshake
//!   captured and replayed outside the ±1h window matches no candidate
//!   and is silent-dropped — the anti-replay property without a plaintext
//!   timestamp a DPI could fingerprint.
//! - Random padding makes handshake length variable (no fixed-size
//!   fingerprint).
//!
//! ## Output
//!
//! On successful handshake, both sides derive matching `DirectionKey`s
//! consumable by [`super::OutboundStream`] / [`super::InboundStream`]:
//!
//! - `dk_c_to_s` = `DirectionKey::derive(shared_secret, b"c2s")`,
//! - `dk_s_to_c` = `DirectionKey::derive(shared_secret, b"s2c")`.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::elligator2::{ElligatorKeypair, REPRESENTATIVE_LEN, decode_representative, ecdh};
use super::{DirectionKey, HandshakeError};

// ── Wire constants ───────────────────────────────────────────────────────────

/// Length of an HMAC-SHA256 tag.
pub const MAC_LEN: usize = 32;

/// Tweak byte length.
pub const TWEAK_LEN: usize = 1;

/// Pad-length byte length.
pub const PAD_LEN_LEN: usize = 1;

/// Maximum random padding bytes in а handshake message.
pub const MAX_HANDSHAKE_PADDING: usize = 128;

/// Minimum handshake message size (no padding).
///
/// SECURITY (C-01): the handshake no longer carries an 8-byte plaintext
/// `timestamp_secs` field. A Unix-seconds timestamp has a low-entropy,
/// near-constant high half (e.g. `00 00 00 00 6a …` for years), which a DPI
/// could fingerprint as a deterministic island inside an otherwise uniform-
/// random opener. The epoch is now bound into the MAC/AUTH only and the peer
/// reconstructs it from its own clock (see [`current_epoch`]).
pub const HANDSHAKE_MIN_BYTES: usize = REPRESENTATIVE_LEN + TWEAK_LEN + MAC_LEN + PAD_LEN_LEN;

/// Maximum handshake message size.
pub const HANDSHAKE_MAX_BYTES: usize = HANDSHAKE_MIN_BYTES + MAX_HANDSHAKE_PADDING;

/// Maximum permissible skew between client и server clocks (seconds), and the
/// granularity of the epoch bound into the MAC/AUTH. Because the epoch is
/// `unix_secs / 3600`, any peer whose clock is within ±1h reconstructs a
/// matching epoch from the candidate set {e-1, e, e+1}; a handshake captured
/// and replayed outside that window matches no candidate and is silent-dropped
/// — preserving the original anti-replay property without a wire timestamp.
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 3600;

/// Epoch granularity for the MAC-bound timestamp (== the skew tolerance).
const HANDSHAKE_EPOCH_SECS: u64 = MAX_TIMESTAMP_SKEW_SECS;

// Phase 2 kill-switch: per-variant labels live on
// [`super::wire_variant::WireFormatVariant`].  V1 callers go through
// the V1-default wrappers (`start()`, `accept_full()`); variant-aware
// callers reach the labels directly via `variant.hkdf_auth_key_info()`
// и `variant.auth_mac_context()`.

// ── Server PSK ───────────────────────────────────────────────────────────────

/// Server's pre-shared MAC key (32 bytes).  Derived от the server's
/// long-term obfs4-PSK material — distributed out-of-band via
/// `transport_hints` (Phase 3).  Both sides need it: server uses it
/// к check incoming client MACs; client uses it к craft the outgoing
/// client MAC.
///
/// A wrong PSK на the client side causes the server к silent-drop —
/// this is the anti-probe property.
#[derive(Clone)]
pub struct NodeIdMacKey(pub [u8; 32]);

impl Drop for NodeIdMacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current handshake epoch (hour-granular). Bound into the MAC/AUTH and
/// NEVER sent on the wire, so the first/second flight carries no low-entropy
/// plaintext timestamp a DPI could fingerprint. The peer reconstructs
/// candidate epochs from its own clock via [`candidate_epochs`].
fn current_epoch() -> u64 {
    unix_timestamp() / HANDSHAKE_EPOCH_SECS
}

/// The peer-epoch values to try when verifying a received MAC/AUTH: the
/// receiver's current epoch and its immediate neighbours. Because the epoch
/// granularity equals the skew tolerance (1h), a peer whose clock is within
/// ±1h always falls in {e-1, e, e+1}. A replay outside that window matches no
/// candidate and is dropped — the same anti-replay guarantee the wire
/// timestamp used to provide, now with zero plaintext on the wire. Trying 3
/// candidates is 3 HMAC-SHA256 ops — negligible, and not a probe-DoS amplifier.
fn candidate_epochs() -> [u64; 3] {
    let e = current_epoch();
    [e.saturating_sub(1), e, e.saturating_add(1)]
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Variant-aware padding length sampler.  V1 uses 0..=128; V2 uses
/// 0..=96 к break length-distribution fingerprint correlation.
fn fresh_pad_len_for(variant: super::wire_variant::WireFormatVariant) -> u8 {
    let mut b = [0u8; 1];
    rand::rng().fill_bytes(&mut b);
    (b[0] as usize % (variant.max_handshake_padding() + 1)) as u8
}

fn random_padding(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

// ── Client side ──────────────────────────────────────────────────────────────

/// Client-side handshake state held between `ClientHandshake::start` и
/// `ClientHandshake::complete`.  Holds the ephemeral private key и
/// the outgoing client representative; releases shared_secret after
/// complete.
pub struct ClientHandshake {
    ephemeral: ElligatorKeypair,
    /// Snapshot of the bytes we sent — included в the auth-MAC compute
    /// on response к bind the AUTH к this specific handshake.
    sent_repr: [u8; REPRESENTATIVE_LEN],
    /// Epoch (hour-granular) we bound into the first-flight MAC. The server
    /// echoes it in the AUTH; `complete()` uses it (not the wall clock) for
    /// the client-epoch component so the AUTH check is exact on our side.
    sent_epoch: u64,
    /// Variant chosen by the client at start time.  `complete()` uses
    /// this к pick the matching AUTH-context label when verifying
    /// the server's response.  Default V1 — kept private к force
    /// callers through `start_variant()` если they need а different.
    variant: super::wire_variant::WireFormatVariant,
}

/// Result of а successful client-side handshake.
#[derive(Debug)]
pub struct ClientHandshakeOutput {
    /// Direction key для outgoing (client-to-server) framing.
    pub dk_c_to_s: DirectionKey,
    /// Direction key для incoming (server-to-client) framing.
    pub dk_s_to_c: DirectionKey,
}

impl ClientHandshake {
    /// Begin а client-side handshake (V1 — default, backwards-compat wrapper).
    /// Caller writes `wire_bytes` к the underlying transport и retains
    /// `state` to call `complete` on the server's response.
    pub fn start(node_id_mac_key: &NodeIdMacKey) -> Result<(Self, Vec<u8>), HandshakeError> {
        Self::start_variant(node_id_mac_key, super::wire_variant::WireFormatVariant::V1)
    }

    /// Variant-aware handshake initiator — Phase 2 kill-switch.
    /// Client builds first frame с variant-specific MAC tag + variant
    /// padding bounds.  V1 produces bit-identical wire bytes к the
    /// legacy `start()`; V2 prepends а variant tag к the MAC input и
    /// uses а tighter padding bound (см. `WireFormatVariant`).
    ///
    /// Returned `Self` state remembers the variant so `complete()`
    /// uses the matching AUTH context when verifying the server's
    /// response.
    pub fn start_variant(
        node_id_mac_key: &NodeIdMacKey,
        variant: super::wire_variant::WireFormatVariant,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let ephemeral = ElligatorKeypair::generate()?;
        let epoch = current_epoch();
        let repr = *ephemeral.representative();
        let tweak = ephemeral.tweak();

        // V1 tag is empty (backwards compat), V2 tag = "obfs4-v2:".
        // Including the tag в the MAC input means а V1 server (no tag
        // в its expected MAC) cannot validate а V2 client's MAC, и
        // vice versa — silent-drop on mismatch.
        //
        // The epoch is bound into the MAC but NOT written to the wire (C-01):
        // the server reconstructs candidate epochs from its own clock. This
        // removes the plaintext-timestamp DPI tell while preserving the
        // replay-window property.
        let mac = hmac_sha256(
            &node_id_mac_key.0,
            &[
                variant.first_frame_mac_tag(),
                &repr,
                &[tweak],
                &epoch.to_be_bytes(),
            ],
        );

        let pad_len = fresh_pad_len_for(variant);
        let padding = random_padding(pad_len as usize);

        let mut wire = Vec::with_capacity(HANDSHAKE_MIN_BYTES + pad_len as usize);
        wire.extend_from_slice(&repr);
        wire.push(tweak);
        wire.extend_from_slice(&mac);
        wire.push(pad_len);
        wire.extend_from_slice(&padding);

        Ok((
            Self {
                ephemeral,
                sent_repr: repr,
                sent_epoch: epoch,
                variant,
            },
            wire,
        ))
    }

    /// Process the server's response.  Returns direction keys on
    /// success, или an error on AUTH/decode failure.
    ///
    /// Note: this consumes `self` because the ephemeral private key
    /// is no longer needed после ECDH derivation.
    pub fn complete(self, wire: &[u8]) -> Result<ClientHandshakeOutput, HandshakeError> {
        let (server_repr, _server_tweak, auth_received) = parse_handshake_message(wire)?;

        // ECDH с server's elligator-decoded pubkey.
        let server_pk = decode_representative(&server_repr);
        let mut shared = ecdh(self.ephemeral.private(), &server_pk);

        // Derive AUTH key + verify server's AUTH MAC.  Variant-aware
        // HKDF label + MAC context — а V2 client cannot validate а
        // V1 server's response (different auth_key) и vice versa.
        //
        // The server's epoch is not on the wire (C-01): we reconstruct
        // candidate server epochs from our own clock and accept if the AUTH
        // verifies under any of them. This both authenticates the response
        // AND enforces the ±1h freshness window (a stale/replayed response
        // matches no candidate). The client-epoch component is the exact
        // value we sent (`self.sent_epoch`).
        let auth_key = derive_auth_key_for(&shared, self.variant);
        let auth_ok = candidate_epochs().iter().any(|&server_epoch| {
            let expected = hmac_sha256(
                &auth_key,
                &[
                    self.variant.auth_mac_context(),
                    &self.sent_repr,
                    &server_repr,
                    &self.sent_epoch.to_be_bytes(),
                    &server_epoch.to_be_bytes(),
                ],
            );
            bool::from(expected.ct_eq(&auth_received))
        });

        if !auth_ok {
            shared.zeroize();
            return Err(HandshakeError::AuthMismatch);
        }

        let dk_c_to_s = DirectionKey::derive(&shared, b"c2s");
        let dk_s_to_c = DirectionKey::derive(&shared, b"s2c");
        shared.zeroize();
        Ok(ClientHandshakeOutput {
            dk_c_to_s,
            dk_s_to_c,
        })
    }
}

// ── Server side ──────────────────────────────────────────────────────────────

/// Server-side handshake entry point.  Stateless — все computation
/// happens within `accept_full`; this is а namespace marker для
/// API symmetry с `ClientHandshake`.
pub struct ServerHandshake;

/// Result of а successful server-side handshake.
#[derive(Debug)]
pub struct ServerHandshakeOutput {
    /// Direction key для incoming (client-to-server) framing.
    pub dk_c_to_s: DirectionKey,
    /// Direction key для outgoing (server-to-client) framing.
    pub dk_s_to_c: DirectionKey,
}

impl ServerHandshake {
    /// Process а client's handshake message (V1 — default,
    /// backwards-compat wrapper).  See `accept_full_variant` for
    /// variant-aware variants и `accept_full_multi` for multi-variant
    /// accept used by the Phase 2 kill-switch.
    ///
    /// Silent-drop policy: on MAC failure (which also covers replay — a
    /// handshake outside the ±1h epoch window matches no candidate epoch)
    /// or decode failure, returns `Err`.  Caller (transport layer) drops
    /// the connection без sending **anything** so что active probers
    /// observe only TCP RST/FIN, not а protocol error frame.
    pub fn accept_full(
        wire: &[u8],
        node_id_mac_key: &NodeIdMacKey,
    ) -> Result<(ServerHandshakeOutput, Vec<u8>), HandshakeError> {
        let (output, _matched_variant, wire_resp) = Self::accept_full_multi(
            wire,
            node_id_mac_key,
            &[super::wire_variant::WireFormatVariant::V1],
        )?;
        Ok((output, wire_resp))
    }

    /// Variant-aware single-variant accept.  Caller pins а specific
    /// variant; client's MAC must verify under that variant's tag
    /// or accept fails (silent-drop policy preserved).
    pub fn accept_full_variant(
        wire: &[u8],
        node_id_mac_key: &NodeIdMacKey,
        variant: super::wire_variant::WireFormatVariant,
    ) -> Result<(ServerHandshakeOutput, Vec<u8>), HandshakeError> {
        let (output, _matched, wire_resp) =
            Self::accept_full_multi(wire, node_id_mac_key, &[variant])?;
        Ok((output, wire_resp))
    }

    /// **Phase 2 kill-switch multi-variant accept**: tries each
    /// variant в `accept_variants` priority order.  Returns the
    /// `(output, matched_variant, response_wire)` tuple on the first
    /// variant whose MAC verifies; returns `Err(ClientMacMismatch)`
    /// if no variant's MAC verifies (silent-drop).
    ///
    /// Operator config wires this from `[transport] obfs4_accept_variants
    /// = ["v2", "v1"]` — server prefers V2 но still accepts V1 during
    /// а grace period.  Once V1 cut off, operator sets `["v2"]`.
    ///
    /// Empty `accept_variants` is а programmer error (returns
    /// `ClientMacMismatch` — vacuously no variant matches).  Caller
    /// should default к `&[V1]` if no operator override.
    pub fn accept_full_multi(
        wire: &[u8],
        node_id_mac_key: &NodeIdMacKey,
        accept_variants: &[super::wire_variant::WireFormatVariant],
    ) -> Result<
        (
            ServerHandshakeOutput,
            super::wire_variant::WireFormatVariant,
            Vec<u8>,
        ),
        HandshakeError,
    > {
        let (client_repr, client_tweak, mac_received) = parse_handshake_message(wire)?;

        // Find (variant, client_epoch) whose MAC verifies. The client epoch is
        // not on the wire (C-01) so we reconstruct candidates from our clock
        // and try each. This also IS the freshness gate: a handshake captured
        // and replayed outside the ±1h window matches no candidate epoch and is
        // silent-dropped (replacing the old explicit skew check). Cost is
        // |variants| * 3 HMAC-SHA256 over ~45 bytes — negligible, not a
        // probe-DoS amplifier. The matched client_epoch is echoed in the AUTH.
        let epochs = candidate_epochs();
        let (matched_variant, client_epoch) = accept_variants
            .iter()
            .copied()
            .find_map(|v| {
                epochs
                    .iter()
                    .copied()
                    .find(|&client_epoch| {
                        let expected = hmac_sha256(
                            &node_id_mac_key.0,
                            &[
                                v.first_frame_mac_tag(),
                                &client_repr,
                                &[client_tweak],
                                &client_epoch.to_be_bytes(),
                            ],
                        );
                        bool::from(expected.ct_eq(&mac_received))
                    })
                    .map(|client_epoch| (v, client_epoch))
            })
            .ok_or(HandshakeError::ClientMacMismatch)?;

        let ephemeral = ElligatorKeypair::generate()?;
        let server_epoch = current_epoch();

        let client_pk = decode_representative(&client_repr);
        let mut shared = ecdh(ephemeral.private(), &client_pk);
        let auth_key = derive_auth_key_for(&shared, matched_variant);
        // AUTH binds the matched client epoch (echoed) and our server epoch.
        // Neither is on the wire; the client reconstructs our epoch from its
        // own clock and knows its own client epoch.
        let auth_mac = hmac_sha256(
            &auth_key,
            &[
                matched_variant.auth_mac_context(),
                &client_repr,
                ephemeral.representative(),
                &client_epoch.to_be_bytes(),
                &server_epoch.to_be_bytes(),
            ],
        );

        let pad_len = fresh_pad_len_for(matched_variant);
        let padding = random_padding(pad_len as usize);

        let mut wire_resp = Vec::with_capacity(HANDSHAKE_MIN_BYTES + pad_len as usize);
        wire_resp.extend_from_slice(ephemeral.representative());
        wire_resp.push(ephemeral.tweak());
        wire_resp.extend_from_slice(&auth_mac);
        wire_resp.push(pad_len);
        wire_resp.extend_from_slice(&padding);

        let dk_c_to_s = DirectionKey::derive(&shared, b"c2s");
        let dk_s_to_c = DirectionKey::derive(&shared, b"s2c");
        shared.zeroize();

        Ok((
            ServerHandshakeOutput {
                dk_c_to_s,
                dk_s_to_c,
            },
            matched_variant,
            wire_resp,
        ))
    }
}

// ── Wire parser ──────────────────────────────────────────────────────────────

/// Parse а handshake message (request or response — same format) and
/// return its components.  Validates structural minimum length only;
/// MAC/AUTH verification happens at the caller.
fn parse_handshake_message(
    wire: &[u8],
) -> Result<([u8; REPRESENTATIVE_LEN], u8, [u8; MAC_LEN]), HandshakeError> {
    if wire.len() < HANDSHAKE_MIN_BYTES {
        return Err(HandshakeError::TooShort(wire.len()));
    }
    let mut repr = [0u8; REPRESENTATIVE_LEN];
    repr.copy_from_slice(&wire[..REPRESENTATIVE_LEN]);
    let tweak = wire[REPRESENTATIVE_LEN];
    // No plaintext timestamp on the wire (C-01) — the MAC binds an epoch the
    // peer reconstructs from its own clock. MAC immediately follows the tweak.
    let mac_offset = REPRESENTATIVE_LEN + TWEAK_LEN;
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&wire[mac_offset..mac_offset + MAC_LEN]);
    // pad_len byte + padding are after the MAC; we ignore them — they
    // only randomize wire length.
    let pad_len_offset = mac_offset + MAC_LEN;
    if pad_len_offset >= wire.len() {
        return Err(HandshakeError::TooShort(wire.len()));
    }
    let pad_len = wire[pad_len_offset] as usize;
    if pad_len_offset + 1 + pad_len > wire.len() {
        return Err(HandshakeError::BadPadding {
            declared: pad_len,
            available: wire.len() - pad_len_offset - 1,
        });
    }
    if wire.len() > pad_len_offset + 1 + pad_len {
        // Trailing bytes — be strict.
        return Err(HandshakeError::TrailingBytes(
            wire.len() - pad_len_offset - 1 - pad_len,
        ));
    }
    Ok((repr, tweak, mac))
}

// ── Auth-key derivation ──────────────────────────────────────────────────────

fn derive_auth_key_for(
    shared_secret: &[u8; 32],
    variant: super::wire_variant::WireFormatVariant,
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(variant.hkdf_auth_key_info(), &mut key)
        .expect("HKDF-SHA256 32-byte expand cannot fail");
    key
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InboundStream;
    use crate::OutboundStream;

    fn test_psk() -> NodeIdMacKey {
        NodeIdMacKey([0x42; 32])
    }

    /// SECURITY regression (C-01): the handshake must carry NO plaintext
    /// timestamp. The pre-fix format placed an 8-byte Unix-seconds timestamp
    /// at offset `REPRESENTATIVE_LEN + TWEAK_LEN` (33) whose high bytes were
    /// near-constant for years — a deterministic DPI island inside an
    /// otherwise uniform-random opener. Verify those bytes now (a) vary per
    /// handshake and (b) never decode to a plausible live timestamp.
    #[test]
    fn handshake_carries_no_plaintext_timestamp() {
        let psk = test_psk();
        let now = unix_timestamp();
        let old_ts_offset = REPRESENTATIVE_LEN + TWEAK_LEN;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let (_state, wire) = ClientHandshake::start(&psk).unwrap();
            let window: [u8; 8] = wire[old_ts_offset..old_ts_offset + 8].try_into().unwrap();
            // These bytes are now MAC material — astronomically unlikely to
            // land within a day of the current wall clock (a live timestamp
            // would be exactly there).
            let as_u64 = u64::from_be_bytes(window);
            assert!(
                as_u64.abs_diff(now) > 86_400,
                "8 bytes at the old timestamp offset look like a live timestamp \
                 ({as_u64} vs now {now}) — plaintext timestamp may have regressed"
            );
            seen.insert(window);
        }
        // 64 fresh handshakes ⇒ 64 distinct windows (high entropy, no
        // near-constant timestamp island).
        assert_eq!(
            seen.len(),
            64,
            "bytes at the old timestamp offset must vary per handshake"
        );
    }

    #[test]
    fn round_trip_handshake() {
        let psk = test_psk();

        // Client builds and sends.
        let (client_state, c_wire) = ClientHandshake::start(&psk).unwrap();
        assert!(c_wire.len() >= HANDSHAKE_MIN_BYTES);
        assert!(c_wire.len() <= HANDSHAKE_MAX_BYTES);

        // Server receives, validates, responds.
        let (server_out, s_wire) = ServerHandshake::accept_full(&c_wire, &psk).unwrap();
        assert!(s_wire.len() >= HANDSHAKE_MIN_BYTES);

        // Client completes на server's response.
        let client_out = client_state.complete(&s_wire).unwrap();

        // Both sides MUST derive the same direction keys; round-trip
        // а frame через c2s direction.
        let mut tx = OutboundStream::new(client_out.dk_c_to_s);
        let mut rx = InboundStream::new(server_out.dk_c_to_s);
        let payload = b"hello via handshake";
        let frame = tx.wrap_next(payload).unwrap();
        let (_, got) = rx.unwrap_next(&frame).unwrap();
        assert_eq!(got, payload);

        // s2c direction too.
        let mut tx2 = OutboundStream::new(server_out.dk_s_to_c);
        let mut rx2 = InboundStream::new(client_out.dk_s_to_c);
        let payload2 = b"reply via handshake";
        let frame2 = tx2.wrap_next(payload2).unwrap();
        let (_, got2) = rx2.unwrap_next(&frame2).unwrap();
        assert_eq!(got2, payload2);
    }

    #[test]
    fn wrong_psk_rejected_silently() {
        let server_psk = NodeIdMacKey([0x42; 32]);
        let wrong_psk = NodeIdMacKey([0xAB; 32]);

        // Client uses wrong PSK.
        let (_state, c_wire) = ClientHandshake::start(&wrong_psk).unwrap();
        // Server rejects.
        let err = ServerHandshake::accept_full(&c_wire, &server_psk).unwrap_err();
        assert_eq!(err, HandshakeError::ClientMacMismatch);
    }

    #[test]
    fn tampered_client_repr_rejected() {
        let psk = test_psk();
        let (_state, mut c_wire) = ClientHandshake::start(&psk).unwrap();
        c_wire[0] ^= 0x01;
        assert_eq!(
            ServerHandshake::accept_full(&c_wire, &psk).unwrap_err(),
            HandshakeError::ClientMacMismatch
        );
    }

    #[test]
    fn tampered_server_auth_rejected_by_client() {
        let psk = test_psk();
        let (client_state, c_wire) = ClientHandshake::start(&psk).unwrap();
        let (_, mut s_wire) = ServerHandshake::accept_full(&c_wire, &psk).unwrap();
        // Tamper the AUTH MAC (offset 41 = 32 + 1 + 8).
        s_wire[41] ^= 0x01;
        assert_eq!(
            client_state.complete(&s_wire).unwrap_err(),
            HandshakeError::AuthMismatch
        );
    }

    #[test]
    fn handshake_messages_look_random() {
        // Both flights should NOT contain the OVL1 magic.
        let psk = test_psk();
        for _ in 0..50 {
            let (client_state, c_wire) = ClientHandshake::start(&psk).unwrap();
            let (_, s_wire) = ServerHandshake::accept_full(&c_wire, &psk).unwrap();
            let _ = client_state.complete(&s_wire);
            for window in c_wire.windows(4).chain(s_wire.windows(4)) {
                assert_ne!(window, b"OVL1");
            }
        }
    }

    #[test]
    fn too_short_rejected() {
        let psk = test_psk();
        let short = vec![0u8; HANDSHAKE_MIN_BYTES - 1];
        assert!(matches!(
            ServerHandshake::accept_full(&short, &psk).unwrap_err(),
            HandshakeError::TooShort(_)
        ));
    }

    #[test]
    fn padding_varies_handshake_length() {
        let psk = test_psk();
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..200 {
            let (_state, wire) = ClientHandshake::start(&psk).unwrap();
            lengths.insert(wire.len());
        }
        assert!(
            lengths.len() > 5,
            "padding should vary handshake length, got {} distinct lengths",
            lengths.len()
        );
    }

    // ── Phase 2 kill-switch: variant-aware handshake tests ─────────

    use super::super::wire_variant::WireFormatVariant;

    /// V2 client ↔ V2 server — full round-trip succeeds, frames
    /// encrypt/decrypt correctly on both sides via derived keys.
    #[test]
    fn v2_round_trip_handshake_succeeds() {
        let psk = test_psk();
        let (client_state, client_wire) =
            ClientHandshake::start_variant(&psk, WireFormatVariant::V2).unwrap();
        let (server_out, matched, server_wire) =
            ServerHandshake::accept_full_multi(&client_wire, &psk, &[WireFormatVariant::V2])
                .unwrap();
        assert_eq!(matched, WireFormatVariant::V2);
        let client_out = client_state.complete(&server_wire).unwrap();

        // Bidi frame round-trip — implicitly verifies direction keys match.
        let mut tx = OutboundStream::new(client_out.dk_c_to_s);
        let mut rx = InboundStream::new(server_out.dk_c_to_s);
        let frame = tx.wrap_next(b"v2 payload").unwrap();
        let (_, got) = rx.unwrap_next(&frame).unwrap();
        assert_eq!(got, b"v2 payload");

        let mut tx2 = OutboundStream::new(server_out.dk_s_to_c);
        let mut rx2 = InboundStream::new(client_out.dk_s_to_c);
        let frame2 = tx2.wrap_next(b"v2 reply").unwrap();
        let (_, got2) = rx2.unwrap_next(&frame2).unwrap();
        assert_eq!(got2, b"v2 reply");
    }

    /// V1 client ↔ V2-only server — server's expected MAC includes
    /// the V2 tag, V1 client's MAC omits it.  MAC verify fails →
    /// silent-drop (ClientMacMismatch).
    #[test]
    fn v1_client_rejected_by_v2_only_server() {
        let psk = test_psk();
        let (_state, client_wire) =
            ClientHandshake::start_variant(&psk, WireFormatVariant::V1).unwrap();
        let err = ServerHandshake::accept_full_multi(&client_wire, &psk, &[WireFormatVariant::V2])
            .unwrap_err();
        assert!(
            matches!(err, HandshakeError::ClientMacMismatch),
            "expected ClientMacMismatch, got {err:?}"
        );
    }

    /// V2 client ↔ V1-only server — symmetric к the above.
    /// V1 server's expected MAC omits the V2 tag, V2 client's MAC
    /// includes it.  MAC verify fails → silent-drop.
    #[test]
    fn v2_client_rejected_by_v1_only_server() {
        let psk = test_psk();
        let (_state, client_wire) =
            ClientHandshake::start_variant(&psk, WireFormatVariant::V2).unwrap();
        let err = ServerHandshake::accept_full_multi(&client_wire, &psk, &[WireFormatVariant::V1])
            .unwrap_err();
        assert!(
            matches!(err, HandshakeError::ClientMacMismatch),
            "expected ClientMacMismatch, got {err:?}"
        );
    }

    /// V1 client ↔ multi-accept server [V2, V1] — server tries V2
    /// MAC first (mismatches), then V1 MAC (matches), accepts via V1.
    #[test]
    fn multi_accept_server_routes_v1_client_via_v1() {
        let psk = test_psk();
        let (state, client_wire) =
            ClientHandshake::start_variant(&psk, WireFormatVariant::V1).unwrap();
        let (server_out, matched, server_wire) = ServerHandshake::accept_full_multi(
            &client_wire,
            &psk,
            &[WireFormatVariant::V2, WireFormatVariant::V1],
        )
        .unwrap();
        assert_eq!(matched, WireFormatVariant::V1);

        let client_out = state.complete(&server_wire).unwrap();
        let mut tx = OutboundStream::new(client_out.dk_c_to_s);
        let mut rx = InboundStream::new(server_out.dk_c_to_s);
        let frame = tx.wrap_next(b"v1 via multi").unwrap();
        let (_, got) = rx.unwrap_next(&frame).unwrap();
        assert_eq!(got, b"v1 via multi");
    }

    /// V2 client ↔ multi-accept server [V2, V1] — server matches V2
    /// immediately on the first try.  Server's response uses V2
    /// labels так что V2 client's `complete()` verifies the AUTH.
    #[test]
    fn multi_accept_server_routes_v2_client_via_v2() {
        let psk = test_psk();
        let (state, client_wire) =
            ClientHandshake::start_variant(&psk, WireFormatVariant::V2).unwrap();
        let (server_out, matched, server_wire) = ServerHandshake::accept_full_multi(
            &client_wire,
            &psk,
            &[WireFormatVariant::V2, WireFormatVariant::V1],
        )
        .unwrap();
        assert_eq!(matched, WireFormatVariant::V2);

        let client_out = state.complete(&server_wire).unwrap();
        let mut tx = OutboundStream::new(client_out.dk_c_to_s);
        let mut rx = InboundStream::new(server_out.dk_c_to_s);
        let frame = tx.wrap_next(b"v2 via multi").unwrap();
        let (_, got) = rx.unwrap_next(&frame).unwrap();
        assert_eq!(got, b"v2 via multi");
    }

    /// Empty `accept_variants` slice — vacuously no variant matches,
    /// server returns silent-drop (matches programmer-error contract).
    #[test]
    fn empty_accept_variants_silent_drops() {
        let psk = test_psk();
        let (_state, client_wire) =
            ClientHandshake::start_variant(&psk, WireFormatVariant::V1).unwrap();
        let err = ServerHandshake::accept_full_multi(&client_wire, &psk, &[]).unwrap_err();
        assert!(matches!(err, HandshakeError::ClientMacMismatch));
    }

    /// V2 padding range is tighter than V1 (0..=96 vs 0..=128).
    /// Sample 200 handshakes и assert V2's max length stays under
    /// V1's max length.  Defense-in-depth against accidental constant
    /// regression that would re-align V1/V2 length distributions.
    #[test]
    fn v2_handshake_max_length_below_v1() {
        let psk = test_psk();
        let mut v1_max = 0usize;
        let mut v2_max = 0usize;
        for _ in 0..200 {
            let (_s, w1) = ClientHandshake::start_variant(&psk, WireFormatVariant::V1).unwrap();
            v1_max = v1_max.max(w1.len());
            let (_s, w2) = ClientHandshake::start_variant(&psk, WireFormatVariant::V2).unwrap();
            v2_max = v2_max.max(w2.len());
        }
        // V1 max-padding = 128; V2 max-padding = 96.  Empirical max
        // approaches the theoretical bound on enough samples.
        // V1 lengths range [MIN, MIN+128], V2 [MIN, MIN+96] — so
        // theoretical max(V2) < theoretical max(V1) by ≥ 32 bytes.
        assert!(
            v2_max < v1_max,
            "V2 max length ({v2_max}) should be below V1 max ({v1_max}) — \
             length-distribution distinguishability anchor"
        );
    }
}
