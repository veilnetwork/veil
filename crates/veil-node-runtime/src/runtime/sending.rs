//! Sending: every road a message can take out of this node.
//!
//! Five of them, and the reason they are one file is that the CHOICE between
//! them is the interesting part, not any one road:
//!
//!  * through a rendezvous relay, authenticated to the receiver;
//!  * down an anonymous onion circuit, to an address or with a reply path;
//!  * to an onion service, by its identity key rather than its node id;
//!  * anonymously, with no sender attribution at all;
//!  * back along a reply path somebody else built.
//!
//! They share the failure modes that matter. Every one of them has to resolve
//! something first — an ad, a period body, a relay directory — and every one
//! can find an answer that is still signed and no longer true, because a
//! receiver rotates relays long before its ad expires. The resolve helpers for
//! the onion path live here rather than with the resolver for exactly that
//! reason: they are part of deciding where to send, not part of answering a
//! lookup.
//!
//! Moved verbatim out of `node_services.rs` (report24 RUNTIME-3), which was
//! six thousand lines covering reaching a peer, building a circuit and sending
//! through it. These are the same inherent methods on the same type, so
//! `rendezvous_resolver.rs` still reaches them by name.

use std::sync::Arc;

use super::*;

type BuiltIntroduce = ([u8; 32], Vec<u8>);

/// Select one current chat registration from already verified advertisements.
/// A linked device publishes at its physical address using its identity's chat
/// cookie. Its old self cookie can remain valid in DHT after the restart. Only
/// a verified device delegation may supply the additional chat-cookie candidate;
/// unrelated (possibly newer) onion-stream advertisements are not chat routes.
fn chat_rendezvous_ads(
    mut ads: Vec<veil_anonymity::rendezvous::RendezvousAd>,
    receiver_node_id: &[u8; 32],
    identity: Option<&[u8; 32]>,
    cap: usize,
) -> Vec<veil_anonymity::rendezvous::RendezvousAd> {
    if cap == 0 {
        return Vec::new();
    }
    let physical_cookie = service_tasks::rendezvous_cookie_from_node_id(receiver_node_id);
    let identity_cookie = identity.map(service_tasks::rendezvous_cookie_from_node_id);
    // Prefer the current identity when pre-link and post-link publications land
    // in the same second. Otherwise freshness decides between the two known
    // chat cookies, before the generation filter below.
    ads.sort_by_key(|ad| {
        std::cmp::Reverse((ad.valid_from_unix, Some(ad.auth_cookie) == identity_cookie))
    });
    let primary = ads
        .iter()
        .find(|ad| ad.auth_cookie == physical_cookie || Some(ad.auth_cookie) == identity_cookie);
    // Keep the legacy fallback only when no delegated identity is known.
    let Some(primary) = primary.or_else(|| identity.is_none().then(|| ads.first()).flatten())
    else {
        return Vec::new();
    };
    let cookie = primary.auth_cookie;
    let generation = primary.valid_from_unix;
    let receiver_key = primary.receiver_x25519_pk;
    let kem_algo = primary.rendezvous_kem_algo;
    let kem_key = primary.rendezvous_kem_pk.clone();
    let mut seen_relays = std::collections::HashSet::new();
    ads.into_iter()
        .filter(|ad| {
            ad.auth_cookie == cookie
                && ad.valid_from_unix == generation
                && ad.receiver_x25519_pk == receiver_key
                && ad.rendezvous_kem_algo == kem_algo
                && ad.rendezvous_kem_pk == kem_key
                && seen_relays.insert(ad.rendezvous_node_id)
        })
        .take(cap)
        .collect()
}

/// The local sovereign document is already signature-verified on admission;
/// still check the selected sibling's authorization window and revocation now.
fn own_chat_identity(
    doc: &veil_proto::identity_document::IdentityDocument,
    device: &[u8; 32],
    now: u64,
) -> Option<[u8; 32]> {
    if &doc.node_id == device
        || doc.valid_until_unix < now
        || doc
            .revoked_devices
            .iter()
            .any(|revoked| &revoked.device_id == device)
    {
        return None;
    }
    doc.identity_keys
        .iter()
        .enumerate()
        .find_map(|(index, key)| {
            (&key.device_id == device
                && veil_identity::verify::authorize_device_key_at(doc, index, now).is_ok())
            .then_some(doc.node_id)
        })
}

/// Wait only for source-local capacity, retaining one already-built cell.
/// The bounded FIFO and neutral wire header are unchanged. No registry lock is
/// held while waiting; session closure/removal is never retried here.
async fn enqueue_introduce_with_backpressure(
    registry: &std::sync::RwLock<veil_session::SessionTxRegistry>,
    peer: &[u8; 32],
    local_lane: u8,
    frame: Vec<u8>,
    deadline: tokio::time::Instant,
) -> std::result::Result<(), veil_session::SendToError> {
    let frame = veil_bufpool::pooled_shared_from_vec(frame);
    loop {
        let result = rlock!(registry).send_to_arc_result(peer, local_lane, frame.clone());
        if result != Err(veil_session::SendToError::Full) {
            return result;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return result;
        }
        tokio::time::sleep_until(deadline.min(now + std::time::Duration::from_millis(2))).await;
    }
}

/// One `RelayChain::<msg>` control frame, header and body.
pub(crate) fn relay_chain_frame(msg: veil_proto::family::RelayChainMsg, body: &[u8]) -> Vec<u8> {
    use veil_proto::{codec::encode_header, family::FrameFamily, header::FrameHeader};
    let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, msg as u16);
    hdr.body_len = body.len() as u32;
    hdr.set_priority(veil_proto::priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(body);
    frame
}

fn enqueue_relay_chain_frame(
    registry: &veil_session::SessionTxRegistry,
    peer: &[u8; 32],
    msg: veil_proto::family::RelayChainMsg,
    body: &[u8],
    local_lane: u8,
) -> std::result::Result<(), veil_session::SendToError> {
    // The process-local lane is never written into the frame: every relay
    // receives the same ordinary header regardless of the originating task.
    registry.send_to_result(peer, local_lane, relay_chain_frame(msg, body))
}

fn enqueue_relay_chain_frame_before(
    registry: &veil_session::SessionTxRegistry,
    peer: &[u8; 32],
    msg: veil_proto::family::RelayChainMsg,
    body: &[u8],
    local_lane: u8,
    expires_at: std::time::Instant,
) -> std::result::Result<(), veil_session::SendToError> {
    registry.send_to_before_result(peer, local_lane, relay_chain_frame(msg, body), expires_at)
}

impl NodeServices {
    /// Build + enqueue one `RelayChain::<msg>` control frame to `peer`'s session.
    pub(crate) fn send_relay_chain_frame(
        &self,
        peer: &[u8; 32],
        msg: veil_proto::family::RelayChainMsg,
        body: &[u8],
    ) -> std::result::Result<(), veil_session::SendToError> {
        self.send_relay_chain_frame_on_local_lane(
            peer,
            msg,
            body,
            veil_proto::priority::INTERACTIVE,
        )
    }

    pub(crate) fn send_relay_chain_frame_on_local_lane(
        &self,
        peer: &[u8; 32],
        msg: veil_proto::family::RelayChainMsg,
        body: &[u8],
        local_lane: u8,
    ) -> std::result::Result<(), veil_session::SendToError> {
        let guard = wlock!(self.session_tx_registry);
        enqueue_relay_chain_frame(&guard, peer, msg, body, local_lane)
    }

    pub(crate) fn send_relay_chain_frame_on_local_lane_before(
        &self,
        peer: &[u8; 32],
        msg: veil_proto::family::RelayChainMsg,
        body: &[u8],
        local_lane: u8,
        expires_at: std::time::Instant,
    ) -> std::result::Result<(), veil_session::SendToError> {
        let guard = rlock!(self.session_tx_registry);
        enqueue_relay_chain_frame_before(&guard, peer, msg, body, local_lane, expires_at)
    }

    /// Authenticated rendezvous send (Epic 482 v1, "any recipient"): like
    /// [`send_via_rendezvous`] but the sealed payload is a per-message Ed25519/
    /// Falcon-signed [`veil_proto::AuthAppDeliver`], so the recipient
    /// cryptographically verifies WHO sent it. A signed message rarely fits one
    /// onion cell, so it is sign-whole-then-fragmented across multiple
    /// introduces (`AuthDeliverFragment`); the recipient reassembles + verifies
    /// once. Requires a loaded sovereign identity. One-way (sender → recipient).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_via_rendezvous_authenticated(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        // Additional DISTINCT-relay ads for the SAME recipient (it registered on
        // several rendezvous relays). When non-empty, fragments are ROUND-ROBINED
        // across `[ad] + these` — independent endpoint relays carry different
        // fragments, so the recipient's aggregate receive throughput scales with
        // the relay count instead of funneling `redundancy` copies of every
        // fragment through ONE relay. Empty → the classic single-relay path with
        // `redundancy` retransmit. No new exposure: the recipient already
        // registered the SAME cookie at each of these relays.
        extra_relays: &[veil_anonymity::rendezvous::RendezvousAd],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // When `Some((reply_app_id, reply_endpoint_id))`, attach a one-time
        // reply block so the recipient can reply WITHOUT us publishing a public
        // ad (presence-leak mitigation): we register R-locally with a rendezvous
        // relay under a fresh cookie and embed the sealed reply path.
        reply: Option<([u8; 32], u32)>,
        // Send each fragment this many times over independent circuits (bounded
        // retransmit). The recipient's fragment reassembler de-dups by
        // `(msg_id, frag_idx)`, so duplicates collapse → exactly-once delivery at
        // higher odds. 1 = no redundancy (forward sends); >1 for fire-and-forget
        // replies that have no end-to-end ack.
        redundancy: usize,
        // True for a circuit-backed / location-anonymous recipient: the introduce
        // cleartext receiver_node_id is replaced by a cookie-derived pseudo-id so
        // R cannot learn the recipient's transport node_id (L3). The AuthDeliver
        // signature below still binds the REAL `ad.receiver_node_id`.
        circuit_backed: bool,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        self.send_via_rendezvous_authenticated_on_local_lane(
            ad,
            extra_relays,
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
            redundancy,
            circuit_backed,
            veil_proto::priority::INTERACTIVE,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_via_rendezvous_authenticated_on_local_lane(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        // Additional DISTINCT-relay ads for the SAME recipient (it registered on
        // several rendezvous relays). When non-empty, fragments are ROUND-ROBINED
        // across `[ad] + these` — independent endpoint relays carry different
        // fragments, so the recipient's aggregate receive throughput scales with
        // the relay count instead of funneling `redundancy` copies of every
        // fragment through ONE relay. Empty → the classic single-relay path with
        // `redundancy` retransmit. No new exposure: the recipient already
        // registered the SAME cookie at each of these relays.
        extra_relays: &[veil_anonymity::rendezvous::RendezvousAd],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // When `Some((reply_app_id, reply_endpoint_id))`, attach a one-time
        // reply block so the recipient can reply WITHOUT us publishing a public
        // ad (presence-leak mitigation): we register R-locally with a rendezvous
        // relay under a fresh cookie and embed the sealed reply path.
        reply: Option<([u8; 32], u32)>,
        // Send each fragment this many times over independent circuits (bounded
        // retransmit). The recipient's fragment reassembler de-dups by
        // `(msg_id, frag_idx)`, so duplicates collapse → exactly-once delivery at
        // higher odds. 1 = no redundancy (forward sends); >1 for fire-and-forget
        // replies that have no end-to-end ack.
        redundancy: usize,
        // True for a circuit-backed / location-anonymous recipient: the introduce
        // cleartext receiver_node_id is replaced by a cookie-derived pseudo-id so
        // R cannot learn the recipient's transport node_id (L3). The AuthDeliver
        // signature below still binds the REAL `ad.receiver_node_id`.
        circuit_backed: bool,
        local_lane: u8,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;
        use veil_anonymity::rendezvous::final_hop_kind;

        let sovereign = self
            .identity
            .sovereign_identity
            .get()
            .ok_or(veil_anonymity::sender::SenderError::MissingSenderIdentity)?;

        const REPLY_CIRCUIT_HOPS: usize = 2;
        // Optionally set up an ephemeral reply path (no public ad). diff-audit
        // S4: we PREPARE the reply block (select the relay path + cookie) here so
        // its bytes are included in the size validation below, but DEFER actually
        // building the onion circuit (which registers a cookie at R_a) until
        // AFTER all the PayloadTooLarge / fragment-budget checks pass — otherwise
        // a late size failure would strand the ephemeral circuit + its R_a
        // registration to expire on idle-GC.
        let (reply_block, pending_reply_circuit) = match reply {
            Some((reply_app_id, reply_endpoint_id)) => {
                // We must own the anonymity key to unseal the eventual reply —
                // i.e. be receive-capable (`receive_anonymous`/`relay_capable`).
                let x25519_pk = match self.dispatcher.anonymity_x25519_sk.as_ref() {
                    Some(sk) => x25519_dalek::PublicKey::from(sk.as_ref()).to_bytes(),
                    None => {
                        return Err(veil_anonymity::sender::SenderError::MissingReplyCapability);
                    }
                };
                // The reply cookie will be registered over an ONION CIRCUIT to
                // R_a (not a direct session), so R_a never learns OUR location
                // either (1c). No ad is published: the signed reply block IS the
                // private descriptor sent to the replier. Ephemeral (build-once,
                // no maintenance entry) — the reply happens within the block TTL.
                let relay_path =
                    self.select_onion_relay_path(REPLY_CIRCUIT_HOPS)
                        .map_err(|_| {
                            veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                                need: REPLY_CIRCUIT_HOPS,
                                have: 0,
                            }
                        })?;
                let relay = *relay_path.last().expect("non-empty relay path");
                // Ephemeral one-shot reply circuit (build-once, no maintenance
                // rebuild), so a fresh registration key is fine — no CookieClaimed
                // concern (L1 only matters for the rebuilt hosted-service circuits).
                // The cookie is derived from that key rather than drawn
                // independently: the relay checks the pairing, so an unpaired
                // cookie would simply be refused.
                let (reply_reg_kp, cookie) = Self::onion_reg_pair(None, 0, None);
                let block = veil_proto::ReplyBlock {
                    rendezvous_node_id: relay,
                    auth_cookie: cookie,
                    x25519_pk,
                    reply_app_id,
                    reply_endpoint_id,
                    // Circuit-backed: R_a forwards the reply DOWN our circuit by
                    // COOKIE alone, so this transport id is now unused on the
                    // circuit path (kept for wire compatibility / the legacy
                    // session path).
                    receiver_node_id: *self.identity.local_identity.node_id.as_bytes(),
                };
                (Some(block), Some((relay_path, cookie, reply_reg_kp)))
            }
            None => (None, None),
        };

        // Build + sign the whole message. dst = the ad's receiver_node_id (bound
        // by the signature; the verifier reconstructs it as its own node_id).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce = rand_core::OsRng.next_u64();
        let auth = sovereign.sign_auth_deliver(
            ad.receiver_node_id,
            target_app_id,
            target_endpoint_id,
            now_unix,
            nonce,
            data.to_vec(),
            reply_block.into_iter().collect(),
        );
        let auth_bytes = auth.encode();
        if auth_bytes.len() > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
            });
        }

        // Largest signed-blob chunk that fits one fragment at this hop_count:
        //   Final-hop budget − [1 onion tag] − IntroducePayload fixed − introduce
        //   overhead − [1 inner tag] − fragment header.
        let chunk_size = introduce_fragment_chunk_size(hop_count).ok_or(
            veil_anonymity::sender::SenderError::HopCountExceedsCellBudget {
                hop_count,
                max: veil_anonymity::packet::MAX_HOPS_PER_CELL,
            },
        )?;
        if chunk_size == 0 {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: 0,
            });
        }
        let frag_count = auth_bytes.len().div_ceil(chunk_size).max(1);
        if frag_count > veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: chunk_size * veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize,
            });
        }

        // Reassembly is ALL-OR-NOTHING across the fragments: the recipient
        // verifies the signed whole only once every fragment of `msg_id` lands.
        // Each fragment is one tiny onion cell (~100-200 B), independently lost,
        // so at F fragments the delivery odds collapse as (1-p)^F — a 27-fragment
        // bulk chunk at p≈0.27 / redundancy 1 delivers ~0.01%. Single-fragment
        // chat text is fine at redundancy 1, but any MULTI-fragment message
        // (bulk file content) needs redundancy to survive: each fragment is then
        // sent over `redundancy` independent circuits and de-duped by
        // (msg_id, frag_idx), lifting per-fragment delivery to 1-p^redundancy.
        // Auto-bump here so small messages stay cheap and only bulk pays the cost
        // — no API/FFI plumbing, and the reply path's explicit 3 is preserved.
        // The rendezvous relays to spread across: the primary `ad` plus any
        // distinct extra relays the recipient registered on (dedup by relay id).
        let mut relays: Vec<&veil_anonymity::rendezvous::RendezvousAd> = vec![ad];
        for e in extra_relays {
            if !relays
                .iter()
                .any(|r| r.rendezvous_node_id == e.rendezvous_node_id)
            {
                relays.push(e);
            }
        }
        // Spreading pays ONLY for a message that actually fragments. A
        // single-fragment message round-robins to exactly ONE relay at
        // redundancy 1 (see the send loop), which is strictly fewer copies than
        // the caller's redundant retransmit down one relay. On the reply path —
        // fire-and-forget, no end-to-end ack — that would trade reliability for
        // a throughput win that a one-fragment message cannot even collect.
        // `frag_count` is known here, so gate on it rather than on relay count
        // alone.
        let parallel = relays.len() > 1 && frag_count >= BULK_FRAGMENT_THRESHOLD;

        let redundancy = onion_send_redundancy(redundancy, frag_count, parallel, relays.len());

        // S4: all size/fragment validation passed — NOW build the ephemeral reply
        // circuit (registers the cookie at R_a). Doing it here means a size
        // failure above returns without ever creating a circuit to strand.
        if let Some((relay_path, cookie, reply_reg_kp)) = pending_reply_circuit {
            // Reply circuits are one-shot with a fresh (cookie, reg_pk), so a
            // throwaway epoch counter is fine — the registration is unique at R
            // and never collides; the epoch is just `unix_now`.
            let reply_epoch = std::sync::atomic::AtomicU64::new(0);
            let confirmed = self
                .build_onion_circuit_once(&relay_path, cookie, &reply_reg_kp, &reply_epoch, true)
                .map_err(
                    |_| veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                        need: REPLY_CIRCUIT_HOPS,
                        have: 0,
                    },
                )?;
            self.wait_reply_circuit_confirmed(&confirmed).await;
        }

        let mut msg_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut msg_id);

        // Each fragment: [APP_DELIVER_AUTH tag][AuthDeliverFragment] → sealed +
        // onion-routed to the rendezvous independently.
        let enqueue_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        for (idx, chunk) in auth_bytes.chunks(chunk_size).enumerate() {
            let frag = veil_proto::AuthDeliverFragment {
                msg_id,
                frag_count: frag_count as u16,
                frag_idx: idx as u16,
                chunk: chunk.to_vec(),
            };
            let frag_bytes = frag.encode();
            let mut sealed_plaintext = Vec::with_capacity(1 + frag_bytes.len());
            sealed_plaintext.push(final_hop_kind::APP_DELIVER_AUTH);
            sealed_plaintext.extend_from_slice(&frag_bytes);
            if parallel {
                // Round-robin fragments across relays for throughput, ONE copy
                // per fragment. A ⌈relays/frags⌉ per-fragment spread briefly
                // lived here to mask single-fragment chat losses, but those were
                // introduces landing on relays without a live registration
                // (`cookie_unknown`): the spread is now generation-gated to the
                // receiver's CURRENT registration set, so a single chain lands
                // and the extra copies were pure traffic (device-verified
                // 2026-07-05: 15/15 delivered at redundancy=1). A genuine
                // forward loss needs an application retry of the signed whole.
                // Local backpressure below keeps source queue pressure from
                // discarding fragments before they reach the first hop.
                let relay = relays[idx % relays.len()];
                self.send_sealed_introduce_with_backpressure(
                    relay,
                    &sealed_plaintext,
                    hop_count,
                    circuit_backed,
                    local_lane,
                    enqueue_deadline,
                )
                .await?;
            } else {
                // Bounded retransmit: send the fragment `redundancy` times over
                // independent circuits; the recipient de-dups by (msg_id, frag_idx).
                for _ in 0..redundancy.max(1) {
                    self.send_sealed_introduce_with_backpressure(
                        ad,
                        &sealed_plaintext,
                        hop_count,
                        circuit_backed,
                        local_lane,
                        enqueue_deadline,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// Authenticated anonymous send to a KNOWN relay (KEM key given) with an
    /// optional one-time reply block — the mailbox FETCH primitive.
    ///
    /// This is the proven key-given direct-onion send (reaches the target as the
    /// final onion hop with NO rendezvous-ad resolve, exactly like the mailbox
    /// DEPOSIT) plus the one-time reply-block construction from
    /// [`Self::send_via_rendezvous_authenticated`]. It exists because the mailbox
    /// drain must reach the RELAY directly: a relay publishes no `RendezvousAd`
    /// for itself, so the ad-resolving [`Self::send_anonymous_authenticated_to`]
    /// always returns `NoRendezvous` for a relay node_id. Here the caller hands us
    /// the relay's KEM key (cached at registration), so the sealed `AuthAppDeliver`
    /// is onion-routed straight to the relay — zero DHT ad lookup, no
    /// `NoRendezvous`.
    ///
    /// Anonymity: the forward send is a source-routed onion (the relay learns
    /// nothing of our location); the relay sees our sovereign node_id ONLY because
    /// the mailbox is, by design, keyed on the verified receiver identity
    /// (identical exposure to the ad-resolving path this replaces). The reply
    /// rides a one-time onion reply circuit to a relay WE pick, forwarded by
    /// cookie alone, so the mailbox relay cannot correlate our identity to a
    /// network location or to the reply path. No plain/direct-session fallback —
    /// on `InsufficientRelayCandidates` this errors rather than degrading.
    ///
    /// FETCH `data` is empty, so the signed `AuthAppDeliver` is a single onion
    /// cell — no fragmentation loop (unlike the rendezvous path).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_anonymous_authenticated_direct_with_reply(
        &self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // `Some((reply_app_id, reply_endpoint_id))` attaches a one-time reply
        // block so the relay can answer our mailbox over an onion reply circuit
        // WITHOUT either side publishing a public ad.
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;

        const REPLY_CIRCUIT_HOPS: usize = 2;

        let sovereign = self
            .identity
            .sovereign_identity
            .get()
            .ok_or(veil_anonymity::sender::SenderError::MissingSenderIdentity)?;

        // PREPARE the reply block (select relay path + cookie) so its bytes are
        // counted in the size check below, but DEFER building the onion circuit
        // (which registers a cookie at R_a) until AFTER the size check passes —
        // otherwise a late size failure would strand the ephemeral circuit + its
        // R_a registration (presence leak + idle-GC churn). Mirrors
        // `send_via_rendezvous_authenticated` exactly.
        let (reply_block, pending_reply_circuit) = match reply {
            Some((reply_app_id, reply_endpoint_id)) => {
                // We must own the anonymity key to unseal the eventual reply
                // (receive-capable: `receive_anonymous`/`relay_capable`).
                let x25519_pk = match self.dispatcher.anonymity_x25519_sk.as_ref() {
                    Some(sk) => x25519_dalek::PublicKey::from(sk.as_ref()).to_bytes(),
                    None => {
                        return Err(veil_anonymity::sender::SenderError::MissingReplyCapability);
                    }
                };
                let relay_path = self
                    .select_onion_relay_path(REPLY_CIRCUIT_HOPS)
                    .map_err(|e| {
                        // Surface the REAL reason before collapsing to the
                        // coarse IPC-visible error — this used to vanish into
                        // "status 2/NO_ROUTE" and made the mailbox-FETCH
                        // failure bursts undiagnosable from logs.
                        log::warn!(
                            "mailbox.fetch.reply_path_failed hops={REPLY_CIRCUIT_HOPS} err={e:?}"
                        );
                        veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                            need: REPLY_CIRCUIT_HOPS,
                            have: 0,
                        }
                    })?;
                let relay = *relay_path.last().expect("non-empty relay path");
                // Cookie derived from the one-shot reply key — see the sibling
                // reply path; the relay refuses an unpaired cookie.
                let (reply_reg_kp, cookie) = Self::onion_reg_pair(None, 0, None);
                let block = veil_proto::ReplyBlock {
                    rendezvous_node_id: relay,
                    auth_cookie: cookie,
                    x25519_pk,
                    reply_app_id,
                    reply_endpoint_id,
                    receiver_node_id: *self.identity.local_identity.node_id.as_bytes(),
                };
                (Some(block), Some((relay_path, cookie, reply_reg_kp)))
            }
            None => (None, None),
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce = rand_core::OsRng.next_u64();

        let auth = sovereign.sign_auth_deliver(
            target_node_id,
            target_app_id,
            target_endpoint_id,
            now_unix,
            nonce,
            data.to_vec(),
            reply_block.into_iter().collect(),
        );
        let auth_bytes = auth.encode();
        if auth_bytes.len() > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
            });
        }

        // Size OK — NOW build the ephemeral reply circuit (registers the cookie at
        // R_a). A size failure above returns without ever creating one.
        if let Some((relay_path, cookie, reply_reg_kp)) = pending_reply_circuit {
            let reply_epoch = std::sync::atomic::AtomicU64::new(0);
            let confirmed = self
                .build_onion_circuit_once(&relay_path, cookie, &reply_reg_kp, &reply_epoch, true)
                .map_err(|e| {
                    // See reply_path_failed above — keep the real circuit-build
                    // error visible instead of the generic NO_ROUTE it becomes
                    // at the IPC boundary.
                    if e == veil_types::AnonOnionSendError::NoRelays {
                        log::debug!(
                            "mailbox.fetch.reply_circuit_unavailable relay={} err={e:?}",
                            veil_util::hex_short(relay_path.last().unwrap_or(&[0u8; 32])),
                        );
                    } else {
                        log::warn!(
                            "mailbox.fetch.reply_circuit_failed relay={} err={e:?}",
                            veil_util::hex_short(relay_path.last().unwrap_or(&[0u8; 32])),
                        );
                    }
                    veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                        need: REPLY_CIRCUIT_HOPS,
                        have: 0,
                    }
                })?;
            self.wait_reply_circuit_confirmed(&confirmed).await;
        }

        let mut payload_bytes = Vec::with_capacity(1 + auth_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER_AUTH);
        payload_bytes.extend_from_slice(&auth_bytes);

        self.send_anonymous_onion(&payload_bytes, target_node_id, target_x25519_pk, hop_count)
    }

    /// Resolve the recipient's `RendezvousAd` and send an authenticated
    /// anonymous message to it (Epic 482 v1, "any recipient"). This is the
    /// production entry point behind the IPC `anonymous_authenticated` flag.
    /// Fetches + verifies the ad from the DHT (recursive, across replica slots),
    /// pre-resolves the rendezvous relay's directory entry into the local shard
    /// (so the onion build can reach it instead of silent-dropping), then
    /// signs/fragments/sends via [`Self::send_via_rendezvous_authenticated`].
    /// Errors are local/pre-transmit; once the cell is on the wire it is
    /// fire-and-forget (no end-to-end ACK).
    pub async fn send_anonymous_authenticated_to(
        &self,
        receiver_node_id: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // `Some((reply_app_id, reply_endpoint_id))` attaches a one-time reply
        // block (see `send_via_rendezvous_authenticated`).
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        self.send_anonymous_authenticated_to_on_local_lane(
            receiver_node_id,
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
            veil_proto::priority::INTERACTIVE,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_anonymous_authenticated_to_on_local_lane(
        &self,
        receiver_node_id: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // `Some((reply_app_id, reply_endpoint_id))` attaches a one-time reply
        // block (see `send_via_rendezvous_authenticated`).
        reply: Option<([u8; 32], u32)>,
        local_lane: u8,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        const AD_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(3500);
        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        // Sender-side stall self-heal. The introduce is fire-and-forget and a
        // relay drops a cookie-less introduce SILENTLY (`cookie_unknown` must
        // not answer probes), so the only sender-observable failure is "my
        // sends to R pile up and nothing verified ever comes back from R"
        // (their delivery-ACKs / replies all arrive as verified AuthDeliver —
        // see the note_answer hook in process_auth_deliver). When that trips:
        //  * drop R's resolve-cache entry (once per window) so THIS send
        //    re-compares fresh replicas instead of re-firing into the hole;
        //  * widen the introduce fan-out below with connected relay candidates
        //    ordered by XOR distance to R — approximating R's OWN deterministic
        //    relay pick, so if R is live-registered at a relay whose fresh ad
        //    simply hasn't propagated to us, the introduce still lands there.
        let stall_now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Only reply-expecting sends DRIVE the stall accounting: their
        // delivery-ACK comes back over OUR ephemeral reply circuit, so its
        // absence is a true me→R signal. Beacons / acks / content chunks carry
        // no reply block and are legitimately unanswered — counting them made
        // a quiet-but-healthy pair re-trip the verdict every widen window.
        // They still ride an ACTIVE widen (peek) so a stalled route widens
        // every outgoing frame, not just the messages.
        let stall = if reply.is_some() {
            self.anonymity
                .send_stall
                .note_send(receiver_node_id, stall_now_unix)
        } else {
            self.anonymity
                .send_stall
                .peek(&receiver_node_id, stall_now_unix)
        };
        if stall.invalidate_cache {
            self.anonymity
                .rendezvous_resolve_cache
                .remove(&receiver_node_id);
            self.logger.info(
                "anonymity.sender.stall",
                format!(
                    "no verified inbound from {} across repeated sends — forcing \
                     fresh ad resolve + widened introduce fan-out",
                    veil_util::hex_short(&receiver_node_id),
                ),
            );
        }
        // A merely-valid local ad is not sufficient here. The receiver may
        // have reconnected and moved to a different relay while the old signed
        // ad remains unexpired; using it produces a valid-looking introduce at
        // a relay that no longer owns the cookie (`cookie_unknown`). Compare
        // independently-served candidates on a short cadence and repair the
        // local mirror with the newest publication.
        let ads = rendezvous_resolver::resolve_fresh_rendezvous_ads(
            &self.dht,
            &self.session_tx_registry,
            &self.dispatcher.pending_recursive,
            *self.identity.local_identity.node_id.as_bytes(),
            &self.anonymity.rendezvous_resolve_cache,
            &self.logger,
            receiver_node_id,
            AD_RESOLVE_TIMEOUT,
            rendezvous_resolver::ResolveMode::Any,
            &self.identity.peer_mlkem_cert_store.document_floor,
        )
        .await;
        let identity = self
            .identity
            .sovereign_identity
            .get()
            .and_then(|sov| own_chat_identity(&sov.document, &receiver_node_id, stall_now_unix))
            .or_else(|| {
                self.identity
                    .peer_mlkem_cert_store
                    .document_floor
                    .identity_hint_for_device(&receiver_node_id, stall_now_unix)
            });
        let mut chosen = chat_rendezvous_ads(ads, &receiver_node_id, identity.as_ref(), 3);
        if chosen.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }
        let mut seen_relays: std::collections::HashSet<_> =
            chosen.iter().map(|ad| ad.rendezvous_node_id).collect();
        // Stalled route: additionally introduce at connected relay candidates
        // the resolvable ads did NOT name, XOR-ordered by R's node_id (the same
        // metric R's own recipient task uses to pick its relays, so the overlap
        // is high). The chat cookie is deterministic per identity — identical at
        // every relay R registers with — so the primary cookie is the right one
        // at a widened relay too; where R is NOT registered the introduce drops
        // exactly like today (silent, bounded). The receiver's E2E key comes
        // from the freshest ad; only the rendezvous target differs.
        if stall.widen {
            const WIDEN_EXTRA_RELAYS: usize = 2;
            let widened = service_tasks::pick_rendezvous_relays_deterministic(
                &self.live_sessions,
                &self.dht,
                &self.dispatcher.crypto.peer_cap_flags,
                &[],
                &receiver_node_id,
            );
            let template = chosen[0].clone();
            let mut added = 0usize;
            for relay in widened {
                if added >= WIDEN_EXTRA_RELAYS {
                    break;
                }
                if seen_relays.insert(relay) {
                    let mut ad = template.clone();
                    ad.rendezvous_node_id = relay;
                    chosen.push(ad);
                    added += 1;
                }
            }
            if added > 0 {
                self.logger.info(
                    "anonymity.sender.stall_widen",
                    format!(
                        "stalled route to {} — introducing at {added} extra \
                         connected relay(s) beyond the resolved ads",
                        veil_util::hex_short(&receiver_node_id),
                    ),
                );
            }
        }

        // Pre-resolve EACH chosen relay's directory entry into our local DHT shard
        // so `send_via_rendezvous_authenticated`'s `get_local` lookup finds it for
        // every relay we round-robin across (otherwise that path silent-drops when
        // the entry isn't organically cached — review fix).
        for a in &chosen {
            let relay_key =
                veil_anonymity::directory::relay_directory_dht_key(&a.rendezvous_node_id);
            if self.dht.get_local(&relay_key).is_none()
                && let Some(bytes) = self.dht_recursive_get(relay_key, RESOLVE_TIMEOUT).await
            {
                self.dht.store_local(relay_key, bytes);
            }
        }

        // The rendezvous relay alone is not enough: `select_onion_relay_path`
        // needs >= hop_count-1 MIDDLE relays drawn from our connected peers and
        // filtered by `get_local(relay_directory_dht_key(peer))`. A cold sender
        // holds none of those entries (passive Kademlia replication hasn't run),
        // so the circuit can't be built and the introduce silently fails with
        // `InsufficientRelayCandidates { have: 0 }`. Actively FIND_VALUE + verify
        // + cache the connected relays' directory entries first — the exact
        // sender-side analogue of the recipient cold-start warm. (review fix)
        let outbox: Arc<dyn veil_dht::FrameRouter> =
            Arc::clone(&self.session_outbox) as Arc<dyn veil_dht::FrameRouter>;
        service_tasks::warm_connected_relay_directory(
            &self.live_sessions,
            &self.dht,
            &outbox,
            &self.logger,
            Some(&self.dispatcher.crypto.peer_cap_flags),
        )
        .await;

        self.send_via_rendezvous_authenticated_on_local_lane(
            &chosen[0],
            &chosen[1..], // extra distinct-relay endpoints → round-robin parallelism
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
            1,     // forward sends: no redundancy (the recipient is reachable via its ad)
            false, // by-node_id: recipient may be session-backed → keep real id (L3)
            local_lane,
        )
        .await
        .map_err(|e| match e {
            veil_anonymity::sender::SenderError::MissingSenderIdentity => {
                AnonOnionSendError::NoIdentity
            }
            veil_anonymity::sender::SenderError::InsufficientRelayCandidates { .. } => {
                AnonOnionSendError::NoRelays
            }
            veil_anonymity::sender::SenderError::PayloadTooLarge { .. } => {
                AnonOnionSendError::PayloadTooLarge
            }
            _ => AnonOnionSendError::NoRelays,
        })
    }

    /// Send an authenticated anonymous message to a LOCATION-anonymous (onion)
    /// service addressed by its Ed25519 IDENTITY key — the unlinkable analogue of
    /// [`Self::send_anonymous_authenticated_to`] (which addresses by node_id and
    /// resolves a node_id-keyed `RendezvousAd`). Here we resolve the service's
    /// per-period BLINDED descriptor: `descriptor_dht_key(identity, period)` is
    /// derived from the blinded key, so a DHT enumerator who doesn't know the
    /// identity cannot find or read it. We decrypt it (we know the identity),
    /// reconstruct a synthetic ad from the body, and route over the onion exactly
    /// as the node_id path does.
    ///
    /// We try the current period plus ±1 to tolerate clock skew across a period
    /// boundary and a service that registered in the previous period and hasn't
    /// rotated yet (the descriptor's blinded key + enc key + signature all bind
    /// the period, so a wrong-period attempt simply fails to open).
    pub async fn send_to_onion_service(
        &self,
        service_identity_vk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        // The authenticated path signs with our sovereign identity.
        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        let ads = self.resolve_onion_service_ads(&service_identity_vk).await?;
        let ad = Self::select_rendezvous_candidates(&ads, data, 1)
            .into_iter()
            .next()
            .ok_or(AnonOnionSendError::NoRendezvous)?;

        // Other provider slots published by the SAME node are additional
        // introduction points to one service instance, so a FRAGMENTED message
        // can be round-robined across them instead of funnelling redundant
        // copies of every fragment through one relay — which is what caps bulk
        // throughput here, since reassembly is all-or-nothing. (A single-
        // fragment message is unaffected: the spread is gated on frag_count.)
        //
        // Ads from OTHER providers are DIFFERENT NODES holding the same
        // content. They must never be mixed in: each fragment would go to
        // whichever node the round-robin landed on, and no node would ever
        // hold the whole message.
        let extra_ads = Self::same_node_extra_ads(&ads, ad);

        self.send_via_rendezvous_authenticated(
            ad,
            &extra_ads,
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
            1,
            true, // by-identity → circuit-backed: pseudo cleartext receiver id (L3)
        )
        .await
        .map_err(map_sender_err)
    }

    /// Like [`Self::send_to_onion_service`] but UNAUTHENTICATED: the service
    /// receives the message with `src_node_id = [0; 32]`, so it never learns who
    /// sent it. Combined with the unlinkable descriptor resolution, this is the
    /// fully-anonymous "anonymous user → anonymous service" quadrant — neither the
    /// relays, R, nor the service itself learn the sender's location or identity.
    /// `src_app_id` rides inside the sealed payload for the service's app-level
    /// routing only (no node identity). No sovereign identity is required.
    pub async fn send_to_onion_service_anonymous(
        &self,
        service_identity_vk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        let ads = self.resolve_onion_service_ads(&service_identity_vk).await?;

        // Unauthenticated final-hop payload: src_node_id zero (anonymity).
        let app_deliver = veil_proto::AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id,
            app_id: target_app_id,
            endpoint_id: target_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            reply_id: 0,
            // Sender-written; the receiver decides provenance itself.
            provenance: veil_proto::SenderProvenance::Claimed,
            origin_device: None,
        };
        let app_deliver_bytes = app_deliver.encode();

        // by-identity anonymous send → circuit-backed: pseudo cleartext id (L3).
        // AppDeliver framing alone is 112 B and introduce HPKE adds another
        // 60 B, leaving far less than one public-cloud chunk in the 320 B
        // ciphertext budget. Fragment the opaque AppDeliver bytes without
        // adding a sovereign signature (the receiver must still see node_id=0).
        // A send enqueue cannot prove end-to-end delivery, so a sequential
        // fallback would be illusory. Fan out to at most three independently
        // hosted providers. Cloud requests carry a fresh nonce; hashing the
        // opaque request rotates the starting provider across retries while a
        // fixed cap bounds traffic and duplicate responses.
        let mut first_error = None;
        let mut enqueued = 0usize;
        let candidates = Self::select_rendezvous_candidates(&ads, data, 3);
        for ad in &candidates {
            match self.send_via_rendezvous_anonymous_payload(
                ad,
                &app_deliver_bytes,
                hop_count,
                true,
            ) {
                Ok(()) => enqueued += 1,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if candidates.is_empty() {
            return Err(veil_types::AnonOnionSendError::NoRendezvous);
        }
        if enqueued == 0 {
            // Nothing got out over any candidate, so the cached route set is
            // the prime suspect — drop it rather than re-firing into it for the
            // rest of the TTL. (A route that accepts sends but silently eats
            // them is a different problem: the receiver-addressed path detects
            // that with a stall counter, which this path does not yet have.)
            self.anonymity
                .onion_resolve_cache
                .remove(&service_identity_vk);
        }
        match (enqueued, first_error) {
            (0, Some(error)) => Err(map_sender_err(error)),
            (0, None) => Err(veil_types::AnonOnionSendError::NoRendezvous),
            _ => Ok(()),
        }
    }

    fn send_via_rendezvous_anonymous_payload(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        app_deliver_bytes: &[u8],
        hop_count: usize,
        circuit_backed: bool,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;
        use veil_anonymity::rendezvous::final_hop_kind;

        let hops_fit = || veil_anonymity::sender::SenderError::HopCountExceedsCellBudget {
            hop_count,
            max: veil_anonymity::packet::MAX_HOPS_PER_CELL,
        };
        let plaintext_budget = introduce_plaintext_budget(hop_count).ok_or_else(hops_fit)?;
        if app_deliver_bytes.len() < plaintext_budget {
            let mut plaintext = Vec::with_capacity(1 + app_deliver_bytes.len());
            plaintext.push(final_hop_kind::APP_DELIVER);
            plaintext.extend_from_slice(app_deliver_bytes);
            return self.send_sealed_introduce(ad, &plaintext, hop_count, circuit_backed);
        }

        let chunk_size = introduce_fragment_chunk_size(hop_count).ok_or_else(hops_fit)?;
        if chunk_size == 0 {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: app_deliver_bytes.len(),
                max: 0,
            });
        }
        let frag_count = app_deliver_bytes.len().div_ceil(chunk_size);
        if frag_count == 0 || frag_count > veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: app_deliver_bytes.len(),
                max: chunk_size * veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize,
            });
        }
        let mut msg_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut msg_id);
        // Multi-fragment delivery is all-or-nothing. Match the authenticated
        // bulk path's bounded redundancy; app-level chunk retry handles the
        // remaining loss without unbounded transport amplification.
        let redundancy = if frag_count >= 3 { 3 } else { 1 };
        for (index, chunk) in app_deliver_bytes.chunks(chunk_size).enumerate() {
            let fragment = veil_proto::AuthDeliverFragment {
                msg_id,
                frag_count: frag_count as u16,
                frag_idx: index as u16,
                chunk: chunk.to_vec(),
            };
            let encoded = fragment.encode();
            let mut plaintext = Vec::with_capacity(1 + encoded.len());
            plaintext.push(final_hop_kind::APP_DELIVER_FRAGMENT);
            plaintext.extend_from_slice(&encoded);
            for _ in 0..redundancy {
                self.send_sealed_introduce(ad, &plaintext, hop_count, circuit_backed)?;
            }
        }
        Ok(())
    }

    /// Send `data` to a KNOWN peer `(target_node_id, target_x25519_pk)` as an
    /// UNAUTHENTICATED anonymous onion message — the direct (non-rendezvous)
    /// sender-anonymous path. The source-routed onion hides our network location
    /// from every relay, and the receiver sees `src_node_id = [0; 32]` (it does
    /// NOT learn who sent it; replies need the separate rendezvous flow).
    /// Fire-and-forget: `Ok` means handed to the first hop, not delivered.
    // 8-arg signature — destination+payload+anonymity shape is one tuple;
    // a struct adds boilerplate without ergonomic gain.
    #[allow(clippy::too_many_arguments)]
    pub fn send_anonymous(
        &self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        // Wrap data in `AppDeliverPayload` so the receiver's Final-hop dispatcher
        // can route to the addressed endpoint. src_node_id stays zero — the
        // anonymity guarantee: the receiver does NOT learn the sender's node id.
        let deliver_payload = veil_proto::AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id,
            app_id: target_app_id,
            endpoint_id: target_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            reply_id: 0,
            // Sender-written; the receiver decides provenance itself.
            provenance: veil_proto::SenderProvenance::Claimed,
            origin_device: None,
        };
        let deliver_bytes = deliver_payload.encode();
        let mut payload_bytes = Vec::with_capacity(1 + deliver_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER);
        payload_bytes.extend_from_slice(&deliver_bytes);

        self.send_anonymous_onion(&payload_bytes, target_node_id, target_x25519_pk, hop_count)
    }

    /// Common onion-send path shared by [`Self::send_anonymous`] (un-authenticated)
    /// and the Runtime's `send_anonymous_authenticated`. `payload` is the
    /// already-assembled final-hop blob: a `final_hop_kind` tag byte followed by
    /// the kind-specific body. This helper owns candidate selection, relay
    /// discovery/verify, AS-diversity + reputation-weighted circuit picking, the
    /// onion wrap, and the fire-and-forget first-hop send.
    pub(crate) fn send_anonymous_onion(
        &self,
        payload: &[u8],
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use veil_anonymity::{
            directory::{
                DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops_cached, relay_directory_dht_key,
            },
            sender::{DiversityOutcome, build_outbound_anonymous_cell_guarded},
        };

        // W0 measurement (anonymity-preserving plan): time the SELECTION phase
        // (candidate snapshot + relay discovery/verify + diversity map) vs the
        // BUILD phase (pick + onion wrap) to decide whether selection dominates
        // the per-send overhead (gates W2 selection-input caching). Local timing
        // of our OWN send — nothing is transmitted, no peer correlation; emitted
        // at debug level (off by default).
        let t_select = std::time::Instant::now();

        // Step 1: snapshot candidates from local DHT routing table.
        // We could also pull from PEX-discovered peers or the live-
        // sessions registry, but routing table is the canonical
        // "peers we already know about" set + matches the security
        // story (anonymity layer must not consult sources that an
        // attacker can poison faster than DHT).
        let candidate_node_ids: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();

        // Step 2 + 3: fetch + verify + filter via discovery helper.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dht = Arc::clone(&self.dht);
        let usable_relays = discover_relay_hops_cached(
            &candidate_node_ids,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        );

        // Step 4: build the cell. RTT estimator pulls from Vivaldi
        // when local coords have converged; falls back to None
        // (which the picker handles by sorting unknown-RTT to last).
        let local_vivaldi = self.dispatcher.local_vivaldi.clone();
        let peer_vivaldi = Arc::clone(&self.dispatcher.peer_vivaldi);
        let rtt_estimator = move |node_id: &[u8; 32]| -> Option<u32> {
            // Vivaldi distance estimate: Euclidean distance between
            // local + peer coords, scaled. When either coord is
            // unknown, return None (picker treats as worst-priority).
            let local = local_vivaldi.as_ref()?;
            let peer_map = rlock!(peer_vivaldi);
            let (peer_coord, _) = peer_map.get(node_id)?;
            let local_guard = lock!(local);
            let estimated_ms = local_guard.distance_estimate(peer_coord) * 1000.0;
            // Sanity: clamp to u32 range. Vivaldi can return
            // negative or NaN values during convergence — treat as
            // unknown (None) so picker doesn't sort by garbage.
            if !estimated_ms.is_finite() || estimated_ms < 0.0 {
                return None;
            }
            Some(estimated_ms.min(u32::MAX as f64) as u32)
        };

        // Anti-censorship AS-diversity extractor — snapshots already-
        // dialed peers' IPs from discovered_peers_cache + builds a
        // node_id → /16 (IPv4) / /32 (IPv6) prefix map.  Used by the
        // circuit picker to enforce "no two hops in the same /16" even
        // when relay-directory wire format doesn't carry IP/ASN.
        // Unknown relays get `None` (graceful degradation —
        // picker accepts them without a diversity gate).
        let diversity_map = build_as_diversity_map(&self.discovered_peers_cache);
        let diversity_key_of =
            move |node_id: &[u8; 32]| -> Option<String> { diversity_map.get(node_id).cloned() };

        // Downweight relays with recorded failures (Epic 482.3/482.4 Phase A):
        // a misbehaving relay's effective RTT is bumped by its penalty so it
        // sorts behind viable alternatives.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let reputation_penalty_ms =
            move |node_id: &[u8; 32]| -> u32 { relay_reputation.rtt_penalty_ms(*node_id) };
        // First-hop liveness guard: the finished cell is handed to hops[0]
        // over a DIRECT session (no dial-on-demand below), so a sessionless
        // first hop means the cell silently evaporates — the dominant
        // first-attempt-loss source. Snapshot the live-session set and let
        // the picker prefer it for the guard slot. Tor-guard semantics: the
        // first hop learns our IP from the direct session anyway, so
        // preferring already-connected relays reveals nothing new.
        let live_first_hops: std::collections::HashSet<[u8; 32]> = self
            .dispatcher
            .session_tx_registry
            .as_ref()
            .map(|reg| rlock!(reg).active_node_ids())
            .unwrap_or_default();
        let first_hop_live = |node_id: &[u8; 32]| live_first_hops.contains(node_id);
        let select_us = t_select.elapsed().as_micros();
        let t_build = std::time::Instant::now();
        let ((first_hop_node_id, cell), diversity) = build_outbound_anonymous_cell_guarded(
            payload,
            &usable_relays,
            rtt_estimator,
            diversity_key_of,
            reputation_penalty_ms,
            first_hop_live,
            target_node_id,
            target_x25519_pk,
            hop_count,
        )?;
        if !live_first_hops.contains(&first_hop_node_id) {
            // Guard fallback: no live-session candidate was available in the
            // relay pool (or the target itself is the first hop) — this send
            // rides the old sessionless-first-hop odds and may be lost until
            // an app-layer retry.
            log::debug!(
                "anonymity.first_hop.guard_fallback path=onion first_hop={} \
                 live_sessions={} usable={}",
                veil_util::hex_short(&first_hop_node_id),
                live_first_hops.len(),
                usable_relays.len(),
            );
        }
        // W0 measurement: selection (candidate prep + discovery + diversity map)
        // vs build (pick + onion wrap). The anonymity-preserving plan expects
        // selection to dominate → justifies W2 selection-input caching.
        log::debug!(
            "anonymity.send.timing select_us={select_us} build_us={} \
             payload={} hops={hop_count} candidates={} usable={}",
            t_build.elapsed().as_micros(),
            payload.len(),
            candidate_node_ids.len(),
            usable_relays.len(),
        );
        if diversity == DiversityOutcome::DegradedToLatency {
            // AS-correlation protection was silently lost — surface it so an
            // operator can see when circuits aren't netblock-diverse. (cycle-8 F4.)
            log::warn!(
                "anonymity.circuit.diversity_degraded hop_count={hop_count} \
                 candidates={} — no AS-diverse relay set; fell back to latency-only",
                usable_relays.len()
            );
        }

        // Step 5: hit the wire. RelayChain::Hop frame to first hop's
        // session. If first_hop has no live session, the send is a
        // silent drop — caller learns from app-layer timeout, NOT
        // from a synchronous error (which would leak whether the
        // first hop is reachable to a sender-side observer).
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&cell[..]);
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let sent =
                guard.send_to_result(&first_hop_node_id, veil_proto::priority::INTERACTIVE, frame);
            drop(guard);
            if let Err(e) = sent {
                // The cell is lost. With the first-hop liveness guard above
                // this should be rare (session died between snapshot and
                // send, or TX queue Full ≠ no session). Log the reason —
                // Full vs Missing/Closed need different remedies — and
                // record the failure so the picker downweights this relay.
                // Still fire-and-forget (return Ok): a synchronous error
                // would leak first-hop reachability to a sender-side observer.
                match e {
                    veil_session::SendToError::Missing => log::debug!(
                        "anonymity.first_hop.session_missing path=onion first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                    _ => log::warn!(
                        "anonymity.first_hop.send_failed path=onion reason={e:?} first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                }
                self.anonymity
                    .relay_reputation
                    .record_failure(first_hop_node_id);
            }
        }
        Ok(())
    }

    /// Resolve a location-anonymous service's BLINDED descriptor (by its Ed25519
    /// identity) into a synthetic `RendezvousAd` ready for the send path. Tries
    /// the current period plus ±1 to tolerate clock skew across a period boundary
    /// and a service that registered in the previous period and hasn't rotated yet
    /// (the descriptor's blinded key + enc key + signature all bind the period, so
    /// a wrong-period attempt simply fails to open). Also pre-resolves the
    /// rendezvous relay's directory entry into our local shard so the onion build
    /// finds it. `NoRendezvous` if no descriptor resolves/decrypts.
    /// The other introduction points of the SAME service instance as
    /// `primary`: ads that name the same receiver node at a different
    /// rendezvous relay, deduplicated by relay.
    ///
    /// A service may publish into several provider slots, and ads from OTHER
    /// providers are DIFFERENT NODES holding the same content. Those must never
    /// be mixed in: round-robin would send each fragment to whichever node it
    /// landed on, and no node would ever hold the whole message.
    pub(crate) fn same_node_extra_ads(
        ads: &[veil_anonymity::rendezvous::RendezvousAd],
        primary: &veil_anonymity::rendezvous::RendezvousAd,
    ) -> Vec<veil_anonymity::rendezvous::RendezvousAd> {
        let mut extras: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        for candidate in ads {
            if candidate.receiver_node_id != primary.receiver_node_id
                || candidate.rendezvous_node_id == primary.rendezvous_node_id
                || extras
                    .iter()
                    .any(|e| e.rendezvous_node_id == candidate.rendezvous_node_id)
            {
                continue;
            }
            extras.push(candidate.clone());
        }
        extras
    }

    pub(crate) fn select_rendezvous_candidates<'a>(
        ads: &'a [veil_anonymity::rendezvous::RendezvousAd],
        request_bytes: &[u8],
        limit: usize,
    ) -> Vec<&'a veil_anonymity::rendezvous::RendezvousAd> {
        if ads.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"veil.provider.candidate-order.v1\0");
        hash.update(request_bytes);
        let digest = hash.finalize();
        let mut start_bytes = [0u8; 8];
        start_bytes.copy_from_slice(&digest.as_bytes()[..8]);
        let start = (u64::from_le_bytes(start_bytes) as usize) % ads.len();
        (0..ads.len().min(limit))
            .map(|offset| &ads[(start + offset) % ads.len()])
            .collect()
    }

    /// How long the remaining slot lookups may still join after the first one
    /// has answered. Long enough for a peer that is merely a little slower to be
    /// counted — the fan-out picks up to three providers and wants the choice —
    /// short enough that a service publishing one slot no longer pays the full
    /// timeout for the eight it left empty.
    const SLOT_GRACE: std::time::Duration = std::time::Duration::from_millis(400);

    async fn resolve_onion_service_period_bodies(
        &self,
        service_identity_vk: &[u8; 32],
        period: u64,
        timeout: std::time::Duration,
    ) -> Vec<veil_anonymity::blinded_descriptor::BlindedDescriptorBody> {
        use veil_anonymity::blinded_descriptor as bd;

        let provider_lookups = (0..bd::MAX_PROVIDER_SLOTS).filter_map(|slot| {
            bd::provider_descriptor_dht_key(service_identity_vk, period, slot)
                .map(|key| (slot, key))
        });
        let lookups = provider_lookups
            .map(|(slot, key)| (Some(slot), key))
            .chain(bd::descriptor_dht_key(service_identity_vk, period).map(|key| (None, key)));
        // Every key is still QUERIED — the lookup shape must not reveal how many
        // provider slots are occupied, and that invariant is about what goes out
        // on the wire. It is not about how long we sit here: a service normally
        // fills one slot, so the other eight have nothing to find and each runs
        // its full timeout. Waiting for all of them made every resolve cost
        // exactly `timeout`, measured at 5003/5003/5002/5002/5003/5002/5003/5004
        // ms across one 8 KiB pull while the answer itself was already in hand.
        //
        // So: collect as they land, and once something HAS landed, give the rest
        // a short grace to join before returning. A resolve that finds nothing
        // still waits the whole budget, because there the wait is the search.
        use futures::stream::StreamExt;
        let mut pending: futures::stream::FuturesUnordered<_> = lookups
            .map(|(slot, key)| async move {
                let bytes = self.dht_recursive_get(key, timeout).await?;
                let body = match slot {
                    Some(slot) => {
                        bd::open_provider_descriptor(service_identity_vk, period, slot, &bytes)
                    }
                    None => bd::open_descriptor(service_identity_vk, period, &bytes),
                }?;
                Some(body)
            })
            .collect();

        let mut bodies: Vec<bd::BlindedDescriptorBody> = Vec::new();
        let mut grace_deadline: Option<tokio::time::Instant> = None;
        loop {
            let next = match grace_deadline {
                None => pending.next().await,
                Some(deadline) => match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(item) => item,
                    // The stragglers are still in flight and their answers still
                    // reach the local store through the dispatcher, so the next
                    // resolve benefits from them even though this one moved on.
                    Err(_) => break,
                },
            };
            let Some(found) = next else { break };
            if let Some(body) = found {
                if !bodies.contains(&body) {
                    bodies.push(body);
                }
                grace_deadline
                    .get_or_insert_with(|| tokio::time::Instant::now() + Self::SLOT_GRACE);
            }
        }
        bodies
    }

    async fn resolve_onion_service_ads(
        &self,
        service_identity_vk: &[u8; 32],
    ) -> std::result::Result<
        Vec<veil_anonymity::rendezvous::RendezvousAd>,
        veil_types::AnonOnionSendError,
    > {
        use veil_anonymity::blinded_descriptor as bd;
        use veil_types::AnonOnionSendError;

        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // A resolve ran on EVERY send. A member content pull issues one send
        // per 256-byte chunk, so a single file paid a whole DHT fan-out — nine
        // slot lookups against a multi-second budget — for every chunk of it.
        // The receiver-addressed path was given this cache long ago; the
        // identity-addressed one was simply never wired to it.
        if let Some(ads) = self
            .anonymity
            .onion_resolve_cache
            .get(service_identity_vk, now)
        {
            return Ok(ads);
        }
        // Coalesce the burst. Without this a window of chunk requests all miss
        // the cold cache together and each launches its own fan-out before the
        // first one has anything to share.
        let _refresh = self
            .anonymity
            .onion_resolve_cache
            .lock_refresh(*service_identity_vk)
            .await;
        // Whoever held the lock has published by now.
        if let Some(ads) = self
            .anonymity
            .onion_resolve_cache
            .get(service_identity_vk, now)
        {
            return Ok(ads);
        }
        let cur = bd::current_period(now);
        let resolve_started = std::time::Instant::now();

        // Query every fixed slot, not "until missing": the lookup shape must
        // not reveal the provider count. Legacy `od` participates as a ninth
        // compatibility candidate. Adjacent periods are queried only when the
        // current period has no valid descriptor at all.
        let mut bodies = self
            .resolve_onion_service_period_bodies(service_identity_vk, cur, RESOLVE_TIMEOUT)
            .await;
        if bodies.is_empty() {
            let adjacent = futures::future::join_all([
                self.resolve_onion_service_period_bodies(
                    service_identity_vk,
                    cur.saturating_sub(1),
                    RESOLVE_TIMEOUT,
                ),
                self.resolve_onion_service_period_bodies(
                    service_identity_vk,
                    cur.saturating_add(1),
                    RESOLVE_TIMEOUT,
                ),
            ])
            .await;
            for body in adjacent.into_iter().flatten() {
                if !bodies.contains(&body) {
                    bodies.push(body);
                }
            }
        }
        if bodies.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }

        let ads: Vec<_> = bodies
            .into_iter()
            .map(|body| veil_anonymity::rendezvous::RendezvousAd {
                receiver_node_id: body.receiver_node_id,
                rendezvous_node_id: body.rendezvous_node_id,
                auth_cookie: body.auth_cookie,
                receiver_x25519_pk: body.receiver_x25519_pk,
                valid_from_unix: 0,
                valid_until_unix: u64::MAX,
                issuer_pk: String::new(),
                issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
                signature: Vec::new(),
                push_envelope: Vec::new(),
                capability_token: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: Vec::new(),
                wire_version: 0,
            })
            .collect();

        // Drop our OWN registrations for this service. A node can be both a
        // provider and a client of the same service — member content is exactly
        // that: adopting bytes makes a member a servable replica, and every
        // member derives the same service identity. Our own ad is then one of
        // the candidates, an anonymous send can pick it, and we answer our own
        // request holding nothing it asked for. Denials there are silent by
        // design, so the fetch could only ever time out.
        //
        // Matched on (rendezvous relay, cookie) like `withdraw_ephemeral_onion_
        // service` does, and scoped to THIS service identity so a legitimate
        // send to some other locally hosted service is untouched.
        let ads: Vec<_> = {
            let mine: Vec<([u8; 32], [u8; 16])> = {
                let services = lock!(self.anonymity.onion_services);
                services
                    .iter()
                    .filter(|entry| {
                        entry
                            .descriptor_identity_seed
                            .as_deref()
                            .map(|seed| {
                                veil_crypto::key_blinding::ed25519_public_from_seed(seed)
                                    == *service_identity_vk
                            })
                            .unwrap_or(false)
                    })
                    .filter_map(|entry| entry.relay_path.last().map(|r| (*r, entry.cookie)))
                    .collect()
            };
            ads.into_iter()
                .filter(|ad| {
                    !mine.iter().any(|(relay, cookie)| {
                        *relay == ad.rendezvous_node_id && *cookie == ad.auth_cookie
                    })
                })
                .collect()
        };
        // Being the only provider is not "no service" — but there is nobody
        // else to ask, and saying so at once beats a silent self-timeout.
        if ads.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }

        let relay_keys: Vec<_> = ads
            .iter()
            .map(|ad| veil_anonymity::directory::relay_directory_dht_key(&ad.rendezvous_node_id))
            .collect();
        let resolved = futures::future::join_all(relay_keys.iter().map(|relay_key| async move {
            if self.dht.get_local(relay_key).is_some() {
                return None;
            }
            self.dht_recursive_get(*relay_key, RESOLVE_TIMEOUT)
                .await
                .map(|bytes| (*relay_key, bytes))
        }))
        .await;
        for (relay_key, bytes) in resolved.into_iter().flatten() {
            self.dht.store_local(relay_key, bytes);
        }
        // Short-lived on purpose, and the TTL is the whole safety argument: a
        // descriptor stays cryptographically valid after the service reconnects
        // onto a different rendezvous relay, and the old relay no longer holds
        // the cookie, so every introduce sent to it disappears without a word.
        self.anonymity
            .onion_resolve_cache
            .put(*service_identity_vk, ads.clone());
        // What a cache miss actually costs, so the value of caching it is a
        // measurement rather than an inference from the timeout constant.
        self.logger.info(
            "anonymity.onion_resolve.cold",
            format!(
                "service={} took_ms={} ads={}",
                veil_util::hex_short(service_identity_vk),
                resolve_started.elapsed().as_millis(),
                ads.len(),
            ),
        );
        Ok(ads)
    }

    /// Reply to a previously-received authenticated message via its one-time
    /// reply block. `reply_id` is the opaque handle the recipient app got
    /// alongside the inbound message; we look the daemon-side block up,
    /// reconstruct the original sender's rendezvous path from it, and send an
    /// authenticated anonymous message back — WITHOUT either side publishing a
    /// public ad (the whole point of the reply channel: no presence leak).
    ///
    /// The reply itself carries no further reply block (`reply = None`): a v1
    /// reply is terminal. The block is NON-consuming and valid until its TTL (1b),
    /// so a reply whose cell the network drops can be RETRIED with the same
    /// `reply_id`; delivery is at-least-once (the recipient de-dups). An unknown
    /// or TTL-expired id fails with `NoRendezvous`.
    pub async fn send_reply(
        &self,
        reply_id: u64,
        data: &[u8],
        hop_count: usize,
        src_app_id: [u8; 32],
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;
        // Per-fragment redundancy for the fire-and-forget reply (2).
        const REPLY_SEND_REDUNDANCY: usize = 3;

        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Look up the reply block (NON-consuming — stays valid until TTL so the
        // app can retry if this reply's cell is dropped; 1b). gone/expired → no
        // reply path.
        // D3: only the app that received the original message (and was handed
        // this reply_id) may reply through it — peek enforces the owner binding.
        let Some(blocks) = self
            .anonymity
            .reply_block_store
            .peek(reply_id, src_app_id, now)
        else {
            return Err(AnonOnionSendError::NoRendezvous);
        };
        // `peek` never yields an empty list, so `blocks[0]` is sound below.
        let primary = &blocks[0];

        // Reconstruct the original sender's rendezvous path as a synthetic ad.
        // Only the four routing fields are read downstream
        // (`send_via_rendezvous_authenticated` → `send_sealed_introduce`); the
        // signed-ad fields are irrelevant here because the path came from a
        // signature-bound reply block, not a DHT lookup, so it needs no
        // re-verification. Validity bounds are set wide-open for the same reason.
        let synthetic = |block: &veil_proto::ReplyBlock| veil_anonymity::rendezvous::RendezvousAd {
            receiver_node_id: block.receiver_node_id,
            rendezvous_node_id: block.rendezvous_node_id,
            auth_cookie: block.auth_cookie,
            receiver_x25519_pk: block.x25519_pk,
            valid_from_unix: 0,
            valid_until_unix: u64::MAX,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            // Inert: the synthetic ad is never re-encoded or verified.
            wire_version: 0,
        };
        // One ad per DISTINCT rendezvous relay the original sender registered
        // under. `send_via_rendezvous_authenticated` round-robins a fragmented
        // reply across them, so the reply's aggregate throughput stops being one
        // relay's — duplicates would just funnel it back onto one endpoint.
        let mut ads: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        for block in &blocks {
            if !ads
                .iter()
                .any(|a| a.rendezvous_node_id == block.rendezvous_node_id)
            {
                ads.push(synthetic(block));
            }
        }

        // Pre-resolve EVERY reply relay's directory entry into our local shard
        // so the onion build can reach it (same fix as `send_anonymous_*_to`).
        // A relay whose entry cannot be resolved is dropped rather than left to
        // fail the build: the remaining relays still carry the reply, and
        // keeping it would hand round-robin a hop it cannot route.
        let mut resolved: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        for ad in ads {
            let relay_key =
                veil_anonymity::directory::relay_directory_dht_key(&ad.rendezvous_node_id);
            if self.dht.get_local(&relay_key).is_none()
                && let Some(bytes) = self.dht_recursive_get(relay_key, RESOLVE_TIMEOUT).await
            {
                self.dht.store_local(relay_key, bytes);
            }
            if self.dht.get_local(&relay_key).is_some() || resolved.is_empty() {
                // The first relay is kept even unresolved: it is the one the
                // pre-multi-block path always used, so dropping it would turn a
                // previously-working single-relay reply into `NoRendezvous`.
                resolved.push(ad);
            }
        }
        let ads = resolved;

        // Reverse-leg RD-staleness fix: the introduce cell `send_via_rendezvous_
        // authenticated` builds needs several DISTINCT relays whose RD is fresh
        // locally (`usable_relays` in `send_sealed_introduce`). On mobile we hold
        // ~one relay session, so `warm_connected_relay_directory` (session-only)
        // caches at most one RD → the guard falls back to a sessionless first hop
        // and the live-ACK evaporates (`guard_fallback` / `send_failed Missing`).
        // Actively pull the KNOWN relay set's RDs over whatever session exists so
        // the freshest-first pick has real candidates. Bounded + freshness-gated
        // (a no-op when already warm). The connected relay stays the guard's
        // preferred first hop; this just makes it — and the middles — RD-fresh.
        {
            let mut relays: Vec<[u8; 32]> = self
                .dht
                .routing_table_contacts()
                .into_iter()
                .map(|c| c.node_id)
                .collect();
            // Union in ACTIVE live-session relays too — the introduce/reply middle
            // selection draws from routing_table ∪ live_sessions, but this warm only
            // sourced the routing table, which thins to near-empty across Doze on
            // mobile while the seed sessions stay live. Mirror the selector's set so
            // the session-backed relays' RD is warmed for the middle pick. Freshness-
            // gated + capped ⇒ no-op (zero RPC) when already fresh.
            {
                let g = lock!(self.live_sessions);
                relays.extend(
                    g.values()
                        .filter(|i| i.state == crate::types::SessionState::Active)
                        .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
                );
            }
            relays.sort_unstable();
            relays.dedup();
            relays.retain(|n| {
                service_tasks::peer_advertised_anonymity_relay(
                    &self.dispatcher.crypto.peer_cap_flags,
                    n,
                )
            });
            self.warm_known_relay_directory(&relays, 6, RESOLVE_TIMEOUT)
                .await;
        }

        self.send_via_rendezvous_authenticated(
            &ads[0],
            // Every extra relay the sender registered under. Empty on a
            // single-block reply, which is then byte-for-byte the old path.
            &ads[1..],
            primary.reply_app_id,
            primary.reply_endpoint_id,
            data,
            hop_count,
            None,
            // Replies are fire-and-forget with no end-to-end ack and a lossy
            // onion+circuit return path — send each fragment a few times; the
            // recipient de-dups (1b/2). Bounded so the amplification is small.
            REPLY_SEND_REDUNDANCY,
            true, // reply goes over the original sender's circuit-backed cookie (L3)
        )
        .await
        .map_err(|e| match e {
            veil_anonymity::sender::SenderError::MissingSenderIdentity => {
                AnonOnionSendError::NoIdentity
            }
            veil_anonymity::sender::SenderError::InsufficientRelayCandidates { .. } => {
                AnonOnionSendError::NoRelays
            }
            veil_anonymity::sender::SenderError::PayloadTooLarge { .. } => {
                AnonOnionSendError::PayloadTooLarge
            }
            _ => AnonOnionSendError::NoRelays,
        })
    }

    /// Seal `sealed_plaintext` (which already carries its `final_hop_kind` tag)
    /// to the ad's recipient, wrap it as an `IntroducePayload`, and onion-route
    /// it to the rendezvous relay as the Final hop. Shared by the plain
    /// ([`send_via_rendezvous`]) and authenticated
    /// ([`send_via_rendezvous_authenticated`]) rendezvous paths.
    pub(crate) fn send_sealed_introduce(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        sealed_plaintext: &[u8],
        hop_count: usize,
        // When true (circuit-backed / location-anonymous service), the cleartext
        // `receiver_node_id` R reads is replaced by a cookie-derived pseudo-id so
        // R never learns the service's transport node_id (L3). The AuthDeliver
        // signature still binds the real id inside the seal.
        circuit_backed: bool,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        self.send_sealed_introduce_on_local_lane(
            ad,
            sealed_plaintext,
            hop_count,
            circuit_backed,
            veil_proto::priority::INTERACTIVE,
        )
    }

    pub(crate) fn send_sealed_introduce_on_local_lane(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        sealed_plaintext: &[u8],
        hop_count: usize,
        // When true (circuit-backed / location-anonymous service), the cleartext
        // `receiver_node_id` R reads is replaced by a cookie-derived pseudo-id so
        // R never learns the service's transport node_id (L3). The AuthDeliver
        // signature still binds the real id inside the seal.
        circuit_backed: bool,
        local_lane: u8,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        let Some((first_hop_node_id, frame)) =
            self.build_sealed_introduce(ad, sealed_plaintext, hop_count, circuit_backed)?
        else {
            return Ok(());
        };
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let sent = guard.send_to_result(&first_hop_node_id, local_lane, frame);
            drop(guard);
            if let Err(e) = sent {
                // Introduce lost. Rare with the liveness guard above (session
                // died between snapshot and send, or TX queue Full). Log the
                // reason + record the failure; still fire-and-forget (see
                // send_anonymous — a synchronous error would leak first-hop
                // reachability).
                match e {
                    veil_session::SendToError::Missing => log::debug!(
                        "anonymity.first_hop.session_missing path=introduce first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                    _ => log::warn!(
                        "anonymity.first_hop.send_failed path=introduce reason={e:?} first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                }
                self.anonymity
                    .relay_reputation
                    .record_failure(first_hop_node_id);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_sealed_introduce_with_backpressure(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        sealed_plaintext: &[u8],
        hop_count: usize,
        circuit_backed: bool,
        local_lane: u8,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        let Some((first_hop, frame)) =
            self.build_sealed_introduce(ad, sealed_plaintext, hop_count, circuit_backed)?
        else {
            return Ok(());
        };
        if let Some(ref registry) = self.dispatcher.session_tx_registry {
            match enqueue_introduce_with_backpressure(
                registry, &first_hop, local_lane, frame, deadline,
            )
            .await
            {
                Ok(()) => {}
                Err(veil_session::SendToError::Full) => {
                    // Source congestion is not a remote relay failure. Let the
                    // application retry the signed whole instead of claiming
                    // success after dropping a necessary fragment locally.
                    log::warn!(
                        "anonymity.source_queue.full authenticated message could not \
                         enter the local queue within its deadline"
                    );
                    return Err(veil_anonymity::sender::SenderError::LocalBackpressure);
                }
                Err(_) => {
                    // Preserve silent-drop behavior for first-hop reachability.
                    self.anonymity.relay_reputation.record_failure(first_hop);
                }
            }
        }
        Ok(())
    }

    fn build_sealed_introduce(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        sealed_plaintext: &[u8],
        hop_count: usize,
        circuit_backed: bool,
    ) -> std::result::Result<Option<BuiltIntroduce>, veil_anonymity::sender::SenderError> {
        use veil_anonymity::rendezvous::{IntroducePayload, encrypt_introduce, final_hop_kind};

        // Step 2: seal to receiver_x25519_pk. Rendezvous cannot read
        // this — only the receiver after their `decrypt_introduce`.
        // encrypt_introduce only fails on AEAD library error (vanishingly
        // rare); treat as PayloadTooLarge for surface-level error
        // reporting (caller's recourse is the same: shrink payload or
        // retry).
        let ciphertext =
            encrypt_introduce(sealed_plaintext, &ad.receiver_x25519_pk).map_err(|_| {
                veil_anonymity::sender::SenderError::PayloadTooLarge {
                    hop_count,
                    got: sealed_plaintext.len(),
                    max: 0,
                }
            })?;

        // Step 3: wrap as IntroducePayload. For a circuit-backed service the
        // cleartext receiver_node_id is a cookie-derived pseudo-id (L3) — R
        // routes by cookie and never forwards this field to the service.
        let intro = IntroducePayload {
            receiver_node_id: if circuit_backed {
                circuit_backed_cleartext_id(&ad.auth_cookie)
            } else {
                ad.receiver_node_id
            },
            auth_cookie: ad.auth_cookie,
            ciphertext,
        };
        let intro_bytes =
            intro
                .encode()
                .map_err(|_| veil_anonymity::sender::SenderError::PayloadTooLarge {
                    hop_count,
                    got: sealed_plaintext.len(),
                    max: 0,
                })?;

        // Step 4: prepend final-hop kind tag.
        let mut payload_bytes = Vec::with_capacity(1 + intro_bytes.len());
        payload_bytes.push(final_hop_kind::INTRODUCE);
        payload_bytes.extend_from_slice(&intro_bytes);

        // Step 5: build + dispatch the onion cell with rendezvous_node_id
        // as the Final-hop target. Rendezvous's anonymity_x25519_pk
        // is needed for the outermost onion layer; we look it up from
        // its directory entry (shipped in).
        use veil_anonymity::{
            directory::{
                DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops_cached, relay_directory_dht_key,
            },
            sender::{DiversityOutcome, build_outbound_anonymous_cell_guarded},
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Resolve rendezvous's directory entry to fetch its x25519_pk.
        let dht = Arc::clone(&self.dht);
        let candidates = vec![ad.rendezvous_node_id];
        let resolved = discover_relay_hops_cached(
            &candidates,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        );
        let rendezvous_relay = match resolved.into_iter().next() {
            Some(r) => r,
            None => {
                // Rendezvous not in our DHT cache — same silent-drop
                // semantics as `send_anonymous` first-hop unreachable.
                return Ok(None);
            }
        };

        // Snapshot relay candidates (excluding rendezvous itself —
        // rendezvous is the Final-hop, not a middle-hop).
        // W0 measurement: time selection vs build (see send_anonymous).
        let t_select = std::time::Instant::now();
        let mut candidate_node_ids: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        // Union the live-session relays into the candidate pool (mirrors
        // `select_onion_relay_path_to`). A relay we hold a session to is the
        // guard's preferred first hop, but it only becomes a valid candidate here
        // if it appears in the pool AND its RD is fresh — the pre-warm at the
        // async call sites (`send_reply` / mailbox FETCH) makes the RD fresh; this
        // guarantees the relay is present even if it briefly dropped out of the
        // routing table between handshake and send.
        {
            let sessions = lock!(self.live_sessions);
            candidate_node_ids.extend(
                sessions
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
            );
        }
        candidate_node_ids.sort_unstable();
        candidate_node_ids.dedup();
        candidate_node_ids.retain(|nid| *nid != ad.rendezvous_node_id);
        let usable_relays = discover_relay_hops_cached(
            &candidate_node_ids,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        );

        // Vivaldi-based RTT estimator (same shape as send_anonymous).
        let local_vivaldi = self.dispatcher.local_vivaldi.clone();
        let peer_vivaldi = Arc::clone(&self.dispatcher.peer_vivaldi);
        let rtt_estimator = move |node_id: &[u8; 32]| -> Option<u32> {
            let local = local_vivaldi.as_ref()?;
            let peer_map = rlock!(peer_vivaldi);
            let (peer_coord, _) = peer_map.get(node_id)?;
            let local_guard = lock!(local);
            let estimated_ms = local_guard.distance_estimate(peer_coord) * 1000.0;
            if !estimated_ms.is_finite() || estimated_ms < 0.0 {
                return None;
            }
            Some(estimated_ms.min(u32::MAX as f64) as u32)
        };

        // Anti-censorship AS-diversity extractor (same shape as
        // send_anonymous) — see the helper comments in that function.
        let diversity_map = build_as_diversity_map(&self.discovered_peers_cache);
        let diversity_key_of =
            move |node_id: &[u8; 32]| -> Option<String> { diversity_map.get(node_id).cloned() };

        // Downweight relays with recorded failures (Epic 482.3/482.4 Phase A) —
        // see send_anonymous for rationale.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let reputation_penalty_ms =
            move |node_id: &[u8; 32]| -> u32 { relay_reputation.rtt_penalty_ms(*node_id) };
        // First-hop liveness guard — same rationale as `send_anonymous_onion`:
        // the introduce cell dies silently if hops[0] has no live session, so
        // the guard slot prefers the live-session set (Tor-guard semantics).
        let live_first_hops: std::collections::HashSet<[u8; 32]> = self
            .dispatcher
            .session_tx_registry
            .as_ref()
            .map(|reg| rlock!(reg).active_node_ids())
            .unwrap_or_default();
        let first_hop_live = |node_id: &[u8; 32]| live_first_hops.contains(node_id);
        let select_us = t_select.elapsed().as_micros();
        let t_build = std::time::Instant::now();
        let ((first_hop_node_id, cell), diversity) = build_outbound_anonymous_cell_guarded(
            &payload_bytes,
            &usable_relays,
            rtt_estimator,
            diversity_key_of,
            reputation_penalty_ms,
            first_hop_live,
            ad.rendezvous_node_id,
            rendezvous_relay.hop.pubkey,
            hop_count,
        )?;
        if !live_first_hops.contains(&first_hop_node_id) {
            // Guard fallback: no live-session candidate in the pool — this
            // introduce rides the old sessionless-first-hop odds.
            log::debug!(
                "anonymity.first_hop.guard_fallback path=introduce first_hop={} \
                 live_sessions={} usable={}",
                veil_util::hex_short(&first_hop_node_id),
                live_first_hops.len(),
                usable_relays.len(),
            );
        }
        // W0 measurement (see send_anonymous).
        log::debug!(
            "anonymity.rendezvous.timing select_us={select_us} build_us={} \
             payload={} hops={hop_count} candidates={} usable={}",
            t_build.elapsed().as_micros(),
            payload_bytes.len(),
            candidate_node_ids.len(),
            usable_relays.len(),
        );
        if diversity == DiversityOutcome::DegradedToLatency {
            log::warn!(
                "anonymity.rendezvous.diversity_degraded hop_count={hop_count} \
                 candidates={} — no AS-diverse relay set; fell back to latency-only",
                usable_relays.len()
            );
        }

        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&cell[..]);
        Ok(Some((first_hop_node_id, frame)))
    }
}

#[cfg(test)]
mod local_circuit_lanes_tests {
    #[tokio::test]
    async fn short_circuit_control_keeps_local_expiry_and_neutral_wire_header() {
        use veil_proto::{
            codec::decode_header_with_limit, family::RelayChainMsg, header::HEADER_SIZE, priority,
        };
        let peer = [0x8d; 32];
        let mut registry = veil_session::SessionTxRegistry::default();
        let mut rx = registry.register(peer);
        super::enqueue_relay_chain_frame_before(
            &registry,
            &peer,
            RelayChainMsg::CircuitDatagram,
            b"expired",
            veil_session::LOCAL_SIGNALING_LANE,
            std::time::Instant::now(),
        )
        .unwrap();
        assert!(rx.try_recv().is_err());
        super::enqueue_relay_chain_frame_before(
            &registry,
            &peer,
            RelayChainMsg::CircuitDatagram,
            b"opaque",
            veil_session::LOCAL_SIGNALING_LANE,
            std::time::Instant::now() + std::time::Duration::from_millis(200),
        )
        .unwrap();
        let (lane, frame) = rx.recv().await.unwrap();
        assert_eq!(lane, veil_session::LOCAL_SIGNALING_LANE);
        let header = decode_header_with_limit(&frame[..HEADER_SIZE], 1024).unwrap();
        assert_eq!(header.priority(), priority::INTERACTIVE);
        assert_eq!(header.flags, u16::from(priority::INTERACTIVE));
        assert_eq!(&frame[HEADER_SIZE..], b"opaque");
    }

    #[tokio::test]
    async fn originating_circuit_lanes_are_local_and_relay_headers_stay_equal() {
        use veil_proto::{
            codec::decode_header_with_limit, family::RelayChainMsg, header::HEADER_SIZE, priority,
        };
        let peer = [0x8c; 32];
        let mut registry = veil_session::SessionTxRegistry::default();
        let mut rx = registry.register(peer);
        super::enqueue_relay_chain_frame(
            &registry,
            &peer,
            RelayChainMsg::CircuitData,
            b"video",
            priority::BULK,
        )
        .unwrap();
        super::enqueue_relay_chain_frame(
            &registry,
            &peer,
            RelayChainMsg::CircuitData,
            b"audio",
            priority::REALTIME,
        )
        .unwrap();
        for (expected_lane, body) in [(priority::REALTIME, b"audio"), (priority::BULK, b"video")] {
            let (local_lane, frame) = rx.recv().await.unwrap();
            assert_eq!(local_lane, expected_lane);
            let header = decode_header_with_limit(&frame[..HEADER_SIZE], 1024).unwrap();
            assert_eq!(header.priority(), priority::INTERACTIVE);
            assert_eq!(header.msg_type, RelayChainMsg::CircuitData as u16);
            assert_eq!(&frame[HEADER_SIZE..], body);
        }
    }
}

#[cfg(test)]
mod chat_ad_tests {
    use super::*;
    fn ad(
        receiver: [u8; 32],
        cookie: [u8; 16],
        relay: u8,
        generation: u64,
    ) -> veil_anonymity::rendezvous::RendezvousAd {
        veil_anonymity::rendezvous::RendezvousAd {
            receiver_node_id: receiver,
            rendezvous_node_id: [relay; 32],
            auth_cookie: cookie,
            receiver_x25519_pk: [7; 32],
            valid_from_unix: generation,
            valid_until_unix: generation + 10_000,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            wire_version: 5,
        }
    }
    #[test]
    fn a_linked_devices_current_chat_cookie_precedes_its_old_self_cookie() {
        let mut device = [0; 32];
        device[0] = 0x11;
        let mut identity = [0; 32];
        identity[0] = 0x42;
        let before = service_tasks::rendezvous_cookie_from_node_id(&device);
        let current = service_tasks::rendezvous_cookie_from_node_id(&identity);
        assert_ne!(before, current);
        let selected = chat_rendezvous_ads(
            vec![
                ad(device, before, 1, 10),
                ad(device, current, 2, 20),
                ad(device, current, 3, 20),
                ad(device, [0x99; 16], 4, 30), // an even newer STREAM ad
            ],
            &device,
            Some(&identity),
            3,
        );
        assert_eq!(
            selected
                .iter()
                .map(|a| a.rendezvous_node_id)
                .collect::<Vec<_>>(),
            vec![[2; 32], [3; 32]]
        );
        assert!(selected.iter().all(|a| a.auth_cookie == current));
    }

    #[test]
    fn same_second_identity_rotation_does_not_select_the_old_self_cookie() {
        let device = [1; 32];
        let mut identity = device;
        identity[0] = 2;
        let old = service_tasks::rendezvous_cookie_from_node_id(&device);
        let current = service_tasks::rendezvous_cookie_from_node_id(&identity);
        let selected = chat_rendezvous_ads(
            vec![ad(device, old, 1, 10), ad(device, current, 2, 10)],
            &device,
            Some(&identity),
            3,
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].auth_cookie, current);
    }

    #[test]
    fn stream_ads_are_not_a_fallback_for_a_known_identity() {
        let device = [1; 32];
        let identity = [2; 32];
        assert!(
            chat_rendezvous_ads(
                vec![ad(device, [9; 16], 1, 100)],
                &device,
                Some(&identity),
                3,
            )
            .is_empty()
        );
    }

    #[test]
    fn a_generation_uses_distinct_relays_with_the_same_receiver_keys() {
        let device = [1; 32];
        let cookie = service_tasks::rendezvous_cookie_from_node_id(&device);
        let mut wrong_key = ad(device, cookie, 4, 10);
        wrong_key.receiver_x25519_pk = [8; 32];
        let mut wrong_kem = ad(device, cookie, 5, 10);
        wrong_kem.rendezvous_kem_pk = vec![8; 32];
        let selected = chat_rendezvous_ads(
            vec![
                ad(device, cookie, 1, 10),
                ad(device, cookie, 1, 10),
                ad(device, cookie, 2, 9),
                wrong_key,
                wrong_kem,
                ad(device, cookie, 3, 10),
                ad(device, cookie, 6, 10),
            ],
            &device,
            None,
            2,
        );
        assert_eq!(
            selected
                .iter()
                .map(|a| a.rendezvous_node_id)
                .collect::<Vec<_>>(),
            vec![[1; 32], [3; 32]]
        );
    }

    #[tokio::test]
    async fn a_full_local_queue_waits_for_capacity_without_losing_a_fragment() {
        let peer = [0x67; 32];
        let mut registry = veil_session::SessionTxRegistry::with_capacity(1);
        let mut rx = registry.register(peer);
        let lane = veil_proto::priority::INTERACTIVE;
        registry.send_to_result(&peer, lane, vec![1]).unwrap();
        let registry = std::sync::RwLock::new(registry);
        let (sent, mut rx) = tokio::join!(
            enqueue_introduce_with_backpressure(
                &registry,
                &peer,
                lane,
                vec![2],
                tokio::time::Instant::now() + std::time::Duration::from_millis(200)
            ),
            async {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let (actual_lane, first) = rx.recv().await.unwrap();
                assert_eq!(actual_lane, lane);
                assert_eq!(&first[..], &[1]);
                rx
            },
        );
        assert!(
            sent.is_ok(),
            "a transient local queue must not discard a signed fragment: {sent:?}"
        );
        let (actual_lane, second) = rx.try_recv().unwrap();
        assert_eq!(actual_lane, lane);
        assert_eq!(&second[..], &[2]);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn local_queue_wait_is_bounded_and_does_not_retry_missing_sessions() {
        let peer = [0x68; 32];
        let mut registry = veil_session::SessionTxRegistry::with_capacity(1);
        let mut rx = registry.register(peer);
        let lane = veil_proto::priority::INTERACTIVE;
        registry.send_to_result(&peer, lane, vec![1]).unwrap();
        let registry = std::sync::RwLock::new(registry);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            enqueue_introduce_with_backpressure(
                &registry,
                &peer,
                lane,
                vec![2],
                tokio::time::Instant::now() + std::time::Duration::from_millis(10),
            ),
        )
        .await
        .unwrap();
        assert_eq!(result, Err(veil_session::SendToError::Full));
        assert_eq!(&rx.try_recv().unwrap().1[..], &[1]);
        assert!(rx.try_recv().is_err());
        assert_eq!(
            enqueue_introduce_with_backpressure(
                &registry,
                &[0; 32],
                lane,
                vec![3],
                tokio::time::Instant::now() + std::time::Duration::from_secs(1)
            )
            .await,
            Err(veil_session::SendToError::Missing)
        );
    }

    #[test]
    fn a_chat_alias_requires_a_current_signed_device_delegation() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_crypto::identity::{certify_message, compute_node_id};
        use veil_proto::identity_document::{
            ALGO_ED25519, DOC_SIG_CONTEXT, IdentityDocument, IdentityKey, RevokedDevice,
        };
        let master = SigningKey::from_bytes(&[1; 32]);
        let sub = SigningKey::from_bytes(&[2; 32]);
        let pubkey = sub.verifying_key().to_bytes();
        let device = compute_node_id(&pubkey);
        let identity = compute_node_id(master.verifying_key().as_bytes());
        let mut doc = IdentityDocument {
            node_id: identity,
            master_algo: ALGO_ED25519,
            master_pubkey: master.verifying_key().to_bytes().to_vec(),
            issued_at_unix: 100,
            valid_until_unix: 2000,
            sig_key_idx: 0,
            identity_keys: vec![IdentityKey {
                algo: ALGO_ED25519,
                pubkey: pubkey.to_vec(),
                device_id: device,
                valid_from_unix: 100,
                valid_until_unix: 2000,
                master_sig: master
                    .sign(&certify_message(
                        &identity,
                        ALGO_ED25519,
                        &pubkey,
                        &device,
                        100,
                        2000,
                    ))
                    .to_bytes()
                    .to_vec(),
            }],
            revoked_devices: vec![],
            document_sig: vec![],
        };
        let sign = |doc: &mut IdentityDocument| {
            let mut message = DOC_SIG_CONTEXT.to_vec();
            message.extend_from_slice(&doc.canonical_signing_bytes());
            doc.document_sig = sub.sign(&message).to_bytes().to_vec();
        };
        sign(&mut doc);
        assert_eq!(own_chat_identity(&doc, &device, 1000), Some(identity));
        assert_eq!(own_chat_identity(&doc, &[9; 32], 1000), None);
        assert_eq!(own_chat_identity(&doc, &device, 2001), None);
        let mut invalid = doc.clone();
        invalid.document_sig[0] ^= 1;
        assert_eq!(own_chat_identity(&invalid, &device, 1000), None);
        doc.revoked_devices.push(RevokedDevice {
            device_id: device,
            master_sig: master
                .sign(&RevokedDevice::signing_message(&identity, &device))
                .to_bytes()
                .to_vec(),
        });
        sign(&mut doc);
        assert!(veil_identity::verify::verify_identity_document(&doc, 1000).is_ok());
        assert_eq!(own_chat_identity(&doc, &device, 1000), None);
    }
}
