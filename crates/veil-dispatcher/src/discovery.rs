use super::{DispatchResult, FrameDispatcher, encode_response};
use veil_cfg::NodeId;
use veil_proto::{
    discovery::{
        AnnounceAttachmentPayload, AppEndpointResponse, FindNodeV2Payload, FindValuePayload,
        GetAppEndpointPayload, GetAttachmentPayload, ResolveTransportPayload, StorePayload,
    },
    family::{DiscoveryMsg, FrameFamily},
    header::FrameHeader,
};
use veil_util::hex_short;
use veil_util::lock;

impl FrameDispatcher {
    pub fn dispatch_discovery(
        &self,
        header: &FrameHeader,
        body: &[u8],
        node_id: NodeId,
    ) -> DispatchResult {
        let msg = match DiscoveryMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown discovery msg_type {}",
                    header.msg_type
                ));
            }
        };

        match msg {
            DiscoveryMsg::AnnounceAttachment => {
                // rate-limit before signature verification (which is
                // the expensive part) so a flooding peer cannot saturate the CPU.
                if !lock!(self.abuse.announce_attachment_limiter).allow(*node_id.as_bytes()) {
                    return DispatchResult::NoResponse;
                }

                let payload = match AnnounceAttachmentPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad AnnounceAttachment: {e}"));
                    }
                };

                // A peer may only announce their own node_id.
                if &payload.node_id != node_id.as_bytes() {
                    return DispatchResult::Violation(format!(
                        "AnnounceAttachment: node_id {} does not match peer_id {} — impersonation rejected",
                        hex_short(&payload.node_id),
                        hex_short(node_id.as_bytes()),
                    ));
                }

                // Every AnnounceAttachment MUST carry a valid signature.
                // The peer_pubkeys cache is populated during handshake, so the
                // key is always available at this point.
                {
                    let cache = lock!(self.crypto.peer_pubkeys);
                    let (algo_byte, pubkey_bytes) = match cache.get(node_id.as_bytes()) {
                        Some(entry) => entry,
                        None => {
                            // Pubkey not in cache — this should never happen because
                            // SessionRunner is only started after a successful handshake
                            // that populates the cache. Treat as a security violation.
                            return DispatchResult::Violation(format!(
                                "AnnounceAttachment: no pubkey cached for peer_id={} — handshake incomplete?",
                                hex_short(node_id.as_bytes()),
                            ));
                        }
                    };
                    if payload.signature.is_empty() {
                        return DispatchResult::Violation(format!(
                            "AnnounceAttachment: unsigned announcement rejected from peer_id={}",
                            hex_short(node_id.as_bytes()),
                        ));
                    }
                    let algo = if *algo_byte == 2 {
                        veil_cfg::SignatureAlgorithm::Falcon512
                    } else {
                        veil_cfg::SignatureAlgorithm::Ed25519
                    };
                    if !veil_discovery::verify_announcement_signature(&payload, algo, pubkey_bytes)
                    {
                        return DispatchResult::Violation(format!(
                            "AnnounceAttachment: invalid signature from peer_id={}",
                            hex_short(node_id.as_bytes()),
                        ));
                    }
                }

                // Verify that the declared role is a subset of the handshake-negotiated
                // capabilities — prevents a peer from claiming gateway/core roles it
                // did not advertise during the OVL1 handshake.
                {
                    let roles_cache = lock!(self.crypto.peer_roles);
                    if let Some(&peer_role_bits) = roles_cache.get(node_id.as_bytes())
                        && payload.role & !peer_role_bits != 0
                    {
                        return DispatchResult::Violation(format!(
                            "AnnounceAttachment: claimed role {:#04x} exceeds handshake capabilities {:#04x} from peer_id={}",
                            payload.role,
                            peer_role_bits,
                            hex_short(node_id.as_bytes()),
                        ));
                    }
                }

                // republish to the DHT as a signed wrapper so
                // non-neighbour Core nodes can find this attachment via DHT
                // lookup. We already verified the signature above, so we can
                // safely package the owner's pubkey (from peer_pubkeys cache)
                // and the raw payload into the self-authenticating "AT"
                // wrapper. Fire-and-forget; failures don't block the primary
                // local-directory store below.
                let dht_wrapper = {
                    let cache = lock!(self.crypto.peer_pubkeys);
                    cache.get(node_id.as_bytes()).cloned()
                };
                if let Some((algo_byte, pubkey_bytes)) = dht_wrapper {
                    let algo = if algo_byte == 2 {
                        veil_cfg::SignatureAlgorithm::Falcon512
                    } else {
                        veil_cfg::SignatureAlgorithm::Ed25519
                    };
                    let wrapper = veil_discovery::directory::encode_signed_attachment(
                        &payload,
                        algo,
                        &pubkey_bytes,
                    );
                    let key = veil_proto::discovery::attachment_key(&payload.node_id);
                    // audit cycle-6 (P1): store the verified AT wrapper via the
                    // per-origin-capped `store_with_origin` (origin =
                    // payload.node_id, == peer's node_id, proven == BLAKE3(pubkey)
                    // by the handshake + signature check above), NOT
                    // `handle_store(unsigned)`. With `allow_unsigned_store=false`,
                    // `handle_store` would reject this StorePayload::unsigned —
                    // it inspects only STORE-level authenticator fields, not the
                    // inner AT signature — silently breaking cross-node DHT
                    // propagation of attachment records (this call is
                    // fire-and-forget). Matches the dispatcher Store arm's AT
                    // attribution.
                    let _ = self.dht.store_with_origin(key, wrapper, payload.node_id);
                }

                let _ = self.discovery.handle_announce_attachment(payload);
                DispatchResult::NoResponse
            }

            DiscoveryMsg::GetAttachment => {
                let payload = match GetAttachmentPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad GetAttachment: {e}"));
                    }
                };
                // in `IntroductionOnly` mode the node refuses
                // to disclose its own (or replicated peers') gateway-plane
                // metadata over discovery. Clients must reach us via a
                // pre-shared bootstrap contact instead. `Public` and
                // `ContactsOnly` keep the existing behaviour — a direct
                // GetAttachment is already authenticated by the session
                // (peer_id ∈ peer_pubkeys by definition for a live session)
                // so `ContactsOnly` would be redundant here.
                if matches!(
                    self.discovery_mode,
                    veil_cfg::DiscoveryMode::IntroductionOnly
                ) {
                    return DispatchResult::Response(encode_response(
                        header,
                        FrameFamily::Discovery as u8,
                        DiscoveryMsg::GetAttachment as u16,
                        &veil_proto::discovery::AttachmentResponse::not_found().encode(),
                    ));
                }
                let resp = self.discovery.handle_get_attachment(payload);
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Discovery as u8,
                    DiscoveryMsg::GetAttachment as u16,
                    &resp.encode(),
                ))
            }

            DiscoveryMsg::GetAppEndpoint => {
                let payload = match GetAppEndpointPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad GetAppEndpoint: {e}"));
                    }
                };
                // same `IntroductionOnly` gate as
                // `GetAttachment`. App-endpoint registration is metadata
                // about which apps a node hosts; introduction-only nodes
                // refuse to publish that over discovery.
                if matches!(
                    self.discovery_mode,
                    veil_cfg::DiscoveryMode::IntroductionOnly
                ) {
                    return DispatchResult::Response(encode_response(
                        header,
                        FrameFamily::Discovery as u8,
                        DiscoveryMsg::GetAppEndpoint as u16,
                        &AppEndpointResponse::not_found().encode(),
                    ));
                }
                // DiscoveryService owns the full lookup: local directory first,
                // then its own DHT fallback (`AppEndpointEntry::decode_from_dht_any`,
                // the correct AP-magic decoder, which also warms the cache).
                //
                // audit cycle-6 dead-code cleanup: the former dispatcher-level
                // DHT fallback here decoded the AP-magic DHT value with
                // `AppEndpointResponse::decode` — a structurally incompatible
                // format — so it could never succeed (always `not_found`) and
                // only ran after DiscoveryService's own (correct) DHT fallback
                // had already failed. Removed: behaviour is identical.
                let resp = self.discovery.handle_get_app_endpoint(payload);
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Discovery as u8,
                    DiscoveryMsg::GetAppEndpoint as u16,
                    &resp.encode(),
                ))
            }

            // DHT messages — handled by KademliaService (core/gateway only).
            //
            // V1 FindNode / FindNodeResponse (slots 0/8) were removed in
            // (475.6). Frames carrying msg_type 0 or 8
            // now fail `DiscoveryMsg::try_from` upstream → `Violation`.
            DiscoveryMsg::FindValue => {
                // b: soft-drop — see FindNode for rationale.
                if !lock!(self.abuse.dht_quota).allow(*node_id.as_bytes()) {
                    return DispatchResult::RateLimited;
                }
                let payload = match FindValuePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad FindValue: {e}")),
                };
                let resp = self.dht.handle_find_value(payload);
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Discovery as u8,
                    DiscoveryMsg::FindValueResponse as u16,
                    &resp.encode(),
                ))
            }
            DiscoveryMsg::FindValueResponse => {
                // Responses are consumed by SessionRunner via pending_responses;
                // if one arrives here it means no pending request matched — ignore.
                DispatchResult::NotHandled
            }

            DiscoveryMsg::Store => {
                // b: quota overflow → soft-drop (`RateLimited`), not
                // `Violation`. Heavy-but-legitimate publishers (a well-known
                // node republishing many application records to K=20 closest
                // neighbours) must not trigger `abuse.auto_ban` loops. True
                // abuse escalates via the RateLimited → backpressure →
                // violation path the caller already wires up.
                if !lock!(self.abuse.dht_quota).allow(*node_id.as_bytes()) {
                    return DispatchResult::RateLimited;
                }
                let payload = match StorePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad Store: {e}")),
                };
                // Reject oversized values before they reach the store.
                // Without this check a single peer could store up to MAX_FRAME_BODY
                // (16 MiB) per entry, exhausting memory.
                if payload.value.len() > veil_proto::budget::MAX_DHT_VALUE_BYTES {
                    return DispatchResult::Violation(format!(
                        "Store: value too large ({} > {} bytes)",
                        payload.value.len(),
                        veil_proto::budget::MAX_DHT_VALUE_BYTES,
                    ));
                }

                // (A2 mitigation) — require proof of key ownership for all
                // network STORE requests.
                //
                // Accepted cases:
                // (a) Signed STORE: ed25519_pubkey + ed25519_sig present
                // BLAKE3(pubkey) == key, and signature valid over key||value.
                // (b) Session-identity STORE: no authenticator, but
                // key == BLAKE3(peer_id). The session handshake already proves
                // the peer owns this key, so no explicit signature is needed.
                //
                // Every other combination is a protocol violation — in particular
                // unsigned STOREs for arbitrary keys are rejected to prevent DHT
                // poisoning (A2).
                // audit cycle-6 (P1): P-Net ban (`PBAN`) records are verified by
                // the `NetworkAuthGate`, which lives ONLY on `KademliaService`
                // (`handle_store`'s fast-path) — the dispatcher has no gate. Route
                // PBAN straight to `handle_store` so the gate runs. (Before P1
                // this branch fell into the unsigned path below and was rejected
                // by `validate_store_value_by_magic` as "unrecognised magic" — a
                // latent gap that silently no-op'd cross-node ban propagation via
                // this arm; P1 fixes it by letting PBAN reach its gate.)
                if payload.value.len() >= 4 && &payload.value[..4] == b"PBAN" {
                    if let Err(e) = self.dht.handle_store(payload) {
                        return DispatchResult::Violation(format!("Store rejected: {e}"));
                    }
                    return DispatchResult::NoResponse;
                }

                // (A2 mitigation) — require proof of key ownership for all
                // network STORE requests.
                match (payload.ed25519_pubkey, payload.ed25519_sig) {
                    (Some(pubkey), Some(sig)) => {
                        // Signed path: require key == BLAKE3(pubkey). This is a
                        // self-store (the signer owns the key), so it goes through
                        // `handle_store`'s signed path unchanged (P1 does not touch
                        // signed STOREs — they are already authenticated).
                        let expected_key: [u8; 32] = *blake3::hash(&pubkey).as_bytes();
                        if payload.key != expected_key {
                            return DispatchResult::Violation(
                                "Store: authenticator pubkey does not match key (BLAKE3(pubkey) ≠ key)".to_owned()
                            );
                        }
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                        let vk = match VerifyingKey::from_bytes(&pubkey) {
                            Ok(k) => k,
                            Err(_) => {
                                return DispatchResult::Violation(
                                    "Store: invalid ed25519 pubkey in authenticator".to_owned(),
                                );
                            }
                        };
                        let sig = Signature::from_bytes(&sig);
                        let signable = payload.signable_bytes();
                        if vk.verify(&signable, &sig).is_err() {
                            return DispatchResult::Violation(
                                "Store: ed25519 signature verification failed".to_owned(),
                            );
                        }
                        // Signed STORE: hand to handle_store (signed path, per-origin
                        // accounting keyed on the signer pubkey).
                        if let Err(e) = self.dht.handle_store(payload) {
                            return DispatchResult::Violation(format!("Store rejected: {e}"));
                        }
                        DispatchResult::NoResponse
                    }
                    _ => {
                        // Unsigned path: permit if EITHER
                        // (a) key == BLAKE3(peer_id) — peer storing its own routing
                        //     record (handshake already proved key ownership); or
                        // (b) value carries one of the self-authenticating magic
                        //     prefixes (AP / AT / NM / ID / IR / MC / SB) — fully
                        //     validated by `validate_store_value_by_magic`, which
                        //     also returns the per-origin accounting bucket.
                        //
                        // audit cycle-6 (P1): a VALIDATED unsigned record is written
                        // via `store_with_origin` (per-origin-capped, bypasses the
                        // `allow_unsigned_store` gate) — mirroring the recursive
                        // STORE plane (`routing.rs` recursive_query_type::STORE).
                        // This lets the `allow_unsigned_store=false` default reject
                        // ONLY truly-unsigned junk that bypassed validation, without
                        // breaking these self-authenticating record types.
                        let self_key: [u8; 32] = *blake3::hash(node_id.as_bytes()).as_bytes();
                        let origin = if payload.key == self_key {
                            // Peer's own routing record — attribute to the peer.
                            *node_id.as_bytes()
                        } else {
                            // A STORE for a key we ALREADY hold is a TTL/content
                            // refresh (the `dht_republish` task re-fans every
                            // self-record via this DIRECT STORE path every
                            // `republish_interval`), not new-state growth — exempt
                            // it from the per-identity write quota so a node's own
                            // self-authenticating records (rendezvous ad, relay key,
                            // …) stay alive at the K-closest. NEW keys still pay the
                            // quota. Mirrors the recursive STORE plane.
                            let already_present = self.dht.get_local(&payload.key).is_some();
                            let origin = match self
                                .validate_store_value_by_magic_ex(&payload.value, already_present)
                            {
                                Ok(origin) => origin,
                                Err(violation) => return violation,
                            };
                            // audit cycle-7 (HIGH — DHT key-binding): bind the
                            // owner-verified record to its CANONICAL DHT key.
                            // `validate_store_value_by_magic` proves the record is
                            // internally owner-signed, but NOT that it belongs at
                            // `payload.key`. Without this, an attacker can store its
                            // OWN validly-signed AP/AT/SB record under a VICTIM's key
                            // — poisoning resolver lookups, clobbering the legit
                            // record (`put_with_origin_at` overwrites), and getting
                            // re-broadcast network-wide by the republish task.
                            // `mirror_cache_key_ok` enforces canonical-key ==
                            // `payload.key` for the derivable owner-verified types
                            // (AP/AT/SB); nc/id/ir/mc pass through unchanged
                            // (re-verified on the resolver read path). This is the
                            // same binding the FIND_VALUE mirror-cache already applies
                            // (cycle-6 A8) — previously missing on the STORE write
                            // path. Legitimate cross-DHT replication by intermediate
                            // nodes is unaffected: it stores under the record's own
                            // canonical key.
                            if !self.mirror_cache_key_ok(&payload.value, &payload.key) {
                                return DispatchResult::Violation(
                                    "Store: self-authenticating record stored under non-canonical DHT key".to_owned(),
                                );
                            }
                            origin
                        };
                        if !self
                            .dht
                            .store_with_origin(payload.key, payload.value, origin)
                        {
                            // per-origin byte cap exceeded — soft-drop (matches the
                            // recursive plane's DoS-resistant behaviour).
                            return DispatchResult::RateLimited;
                        }
                        DispatchResult::NoResponse
                    }
                }
            }

            DiscoveryMsg::Delete => {
                // audit cycle-6 (P4): gate on the per-peer DHT quota BEFORE
                // decode + `handle_delete`, mirroring every sibling DHT write
                // op (`Store`/`FindValue`/`FindNodeV2`/`ResolveTransport`/
                // `AnnounceTransport`). `Delete` was the only write-class arm
                // without this gate, so an authenticated peer could send
                // `Delete` frames at the (orders-of-magnitude looser) global
                // rate-limiter rate and saturate CPU on the per-delete
                // signature verification inside `handle_delete` — a per-peer
                // quota bypass / CPU-amplification vector.
                if !lock!(self.abuse.dht_quota).allow(*node_id.as_bytes()) {
                    return DispatchResult::RateLimited;
                }
                let payload = match veil_proto::discovery::DeletePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad Delete: {e}")),
                };
                if let Err(e) = self.dht.handle_delete(payload) {
                    return DispatchResult::Violation(format!("Delete rejected: {e}"));
                }
                DispatchResult::NoResponse
            }

            // V2 FIND_NODE — wire-identical request, but
            // response carries node_ids only (no transports). Same DHT
            // quota as V1. Caller follows up with `ResolveTransport`
            // (below) to obtain a transport URL for any node_id.
            DiscoveryMsg::FindNodeV2 => {
                if !lock!(self.abuse.dht_quota).allow(*node_id.as_bytes()) {
                    return DispatchResult::RateLimited;
                }
                let payload = match FindNodeV2Payload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad FindNodeV2: {e}")),
                };
                let resp = self.dht.handle_find_node_v2(payload);
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Discovery as u8,
                    DiscoveryMsg::FindNodeV2Response as u16,
                    &resp.encode(),
                ))
            }
            DiscoveryMsg::FindNodeV2Response => {
                // Consumed by the outbound DHT-walker via `pending_responses`.
                // If one arrives here unmatched it's stale — silently ignore.
                DispatchResult::NotHandled
            }

            //per-node-id transport resolution
            // with PoW gate + privacy filter. The handler verifies the
            // PoW solution covers `(peer_id, target, time_bucket, nonce)`
            // — peer_id is the OVL1-session-authenticated requester id, so
            // an attacker cannot forge it. PoW failure is silently mapped
            // to `not_found` (see handler doc). will
            // additionally sign the response.
            DiscoveryMsg::ResolveTransport => {
                if !lock!(self.abuse.dht_quota).allow(*node_id.as_bytes()) {
                    return DispatchResult::RateLimited;
                }
                let payload = match ResolveTransportPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad ResolveTransport: {e}"));
                    }
                };
                let resp = self
                    .dht
                    .handle_resolve_transport(*node_id.as_bytes(), payload);
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Discovery as u8,
                    DiscoveryMsg::ResolveTransportResponse as u16,
                    &resp.encode(),
                ))
            }
            DiscoveryMsg::ResolveTransportResponse => {
                // Consumed via `pending_responses`; stale → silent drop.
                DispatchResult::NotHandled
            }

            //a peer is gossiping their
            // self-signed transport announcement so we can return it to
            // future walkers asking `ResolveTransport(this_peer)`. The
            // handler verifies signature + node_id binding + non-expiry
            // before storing; bad announcements are silently dropped
            // (verification cost is one Ed25519 verify ~50 µs, no
            // amplification, dht_quota already bounds rate). No
            // response — fire-and-forget gossip.
            DiscoveryMsg::AnnounceTransport => {
                if !lock!(self.abuse.dht_quota).allow(*node_id.as_bytes()) {
                    return DispatchResult::RateLimited;
                }
                let announcement =
                    match veil_proto::discovery::SignedTransportAnnouncement::decode(body) {
                        Ok(a) => a,
                        Err(e) => {
                            return DispatchResult::Violation(format!(
                                "bad AnnounceTransport: {e}"
                            ));
                        }
                    };
                // Defence: peer can only announce *their own* node_id.
                // Without this binding, a malicious Bob could gossip
                // an announcement for Alice's node_id (overwriting
                // whatever we have for Alice if Bob's signature happens
                // to verify against a key whose hash is Alice's id).
                if &announcement.node_id != node_id.as_bytes() {
                    return DispatchResult::Violation(
                        "AnnounceTransport node_id ≠ session peer_id".to_owned(),
                    );
                }
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = self
                    .dht
                    .store_transport_announcement(announcement, now_unix);
                DispatchResult::NoResponse
            }
        }
    }

    /// Validate a STORE-payload `value` against the per-magic authenticator
    /// policy.  Used by both the direct `DiscoveryMsg::Store` arm and the
    /// `RecursiveQuery::STORE` arm in routing.rs so the recursive plane
    /// cannot bypass signed-store invariants.
    ///
    /// Direct STORE arms its own "signed ed25519_pubkey + sig (BLAKE3(pk)
    /// == key)" and "unsigned-self-key (key == BLAKE3(peer_id))" shortcuts
    /// BEFORE calling this — those two cases are inapplicable on the
    /// recursive forward path (the recursive payload carries no
    /// authenticator field; `peer_id` is the forwarder, not the origin).
    /// This helper covers the six magic-prefix cases that both ingress
    /// paths share:
    ///
    /// * `AP`  — signed AppEndpointEntry (full verify)
    /// * `AT`  — signed AnnounceAttachment (full verify)
    /// * `NM`  — NameClaim v2 (decode + identity_write_quota)
    /// * `ID`  — IdentityDocument (decode + identity_write_quota)
    /// * `IR`  — InstanceRegistry (decode + identity_write_quota)
    /// * `MC`  — MlKemKeyCert (decode + identity_write_quota)
    ///
    /// Anything else → `Violation`.  `Err(DispatchResult::NoResponse)` is
    /// returned when the identity-write quota refuses the write — a quota
    /// hit isn't a protocol violation, just a silent drop.
    #[allow(clippy::result_large_err)]
    pub fn validate_store_value_by_magic(
        &self,
        payload_value: &[u8],
    ) -> Result<[u8; 32], DispatchResult> {
        // Default: treat every write as a NEW record (quota applies). Callers on
        // the replication/republish plane that already hold the key use
        // `validate_store_value_by_magic_ex(.., already_present = true)` to skip
        // the per-identity write quota for a TTL/content refresh — see below.
        self.validate_store_value_by_magic_ex(payload_value, false)
    }

    /// As [`Self::validate_store_value_by_magic`], but `already_present` lets the
    /// recursive-STORE replication plane signal that this exact DHT key is
    /// ALREADY held locally. The per-identity write quota
    /// (`DEFAULT_MAX_WRITES_PER_HOUR`) exists to bound how fast an
    /// (unverified-at-this-gate) identity can grow DISTINCT-record state on a
    /// holder. Re-storing a key we already hold is a TTL/content REFRESH — it
    /// grows no state — so legitimate republication (a node keeping its own
    /// rendezvous ad / relay key / app-endpoint records alive at the K-closest,
    /// which `dht_republish` re-fans every `republish_interval` via BOTH the
    /// recursive and the direct STORE plane) must NOT be throttled. Without this,
    /// a node's own records climb the counter to the cap within minutes and then
    /// every NEW key — including a receiver's plain rendezvous ad — is refused at
    /// the K-closest, so a cold sender's FIND_VALUE finds no holder →
    /// `NoRendezvous` → anonymous send / offline delivery to that receiver
    /// silently fails. NEW (not-yet-held) keys still pay the quota, so an attacker
    /// injecting fresh distinct records stays capped.
    #[allow(clippy::result_large_err)]
    pub fn validate_store_value_by_magic_ex(
        &self,
        payload_value: &[u8],
        already_present: bool,
    ) -> Result<[u8; 32], DispatchResult> {
        let magic = payload_value.get(..2);
        let is_app_ep = magic == Some(&veil_discovery::directory::APP_ENDPOINT_DHT_MAGIC[..]);
        let is_attach = magic == Some(&veil_discovery::directory::ATTACHMENT_DHT_MAGIC[..]);
        let is_nc = magic == Some(&veil_proto::name_claim_v2::NAME_CLAIM_MAGIC[..]);
        let is_id = magic == Some(&veil_proto::identity_document::IDENTITY_DOCUMENT_MAGIC[..]);
        let is_ir = magic == Some(&veil_proto::instance_registry::INSTANCE_REGISTRY_MAGIC[..]);
        let is_mc = magic == Some(&veil_proto::mlkem_cert::MLKEM_CERT_MAGIC[..]);
        let is_sb = magic == Some(&veil_bootstrap::SIGNED_BUNDLE_MAGIC[..]);
        let is_desc = magic == Some(&veil_anonymity::blinded_descriptor::DESCRIPTOR_DHT_MAGIC[..]);
        let is_rk = magic == Some(&veil_proto::relay_key::RELAY_KEY_MAGIC[..]);
        let is_ra = magic == Some(&veil_anonymity::rendezvous::MAGIC[..]);
        let is_rd = magic == Some(&veil_anonymity::directory::RELAY_DIRECTORY_DHT_MAGIC[..]);

        if is_sb {
            // Signed operator bootstrap bundle (cf. `veil-bootstrap::
            // signed_bundle`).  Structural decode catches obvious garbage;
            // full Ed25519 / Falcon verification + issuer-pk pinning
            // happens on the resolver path (callers of
            // `dht.get_local(bootstrap_bundle_dht_key())` must run
            // `verify_signed_bundle`).  Per-peer dht_quota bounds spam
            // independent of issuer; SB isn't tied to sovereign identity,
            // so no `identity_write_quota` gate applies.
            if veil_bootstrap::decode_signed_bundle(payload_value).is_err() {
                return Err(DispatchResult::Violation(
                    "Store: malformed SignedBootstrapBundle".to_owned(),
                ));
            }
            // Audit N1: bundles carry no per-identity owner — attribute them to
            // one shared per-origin bucket so the byte cap still bounds spam.
            return Ok(veil_dht::store::ORIGIN_RECURSIVE_BUNDLE);
        }

        // Audit N1: return the record's owner node_id as the per-origin
        // accounting bucket so the recursive STORE path charges bytes to the
        // signer, exactly like the direct `handle_store` path (which derives
        // the origin from the STORE-level signature).
        let origin = if is_app_ep {
            match veil_discovery::directory::AppEndpointEntry::decode_and_verify_signed_from_dht_status(
                payload_value,
            ) {
                Ok(entry) => entry.node_id,
                // Stale (validly signed but past expires_at): a peer
                // republishing its cached copy is NOT misbehaving — drop the
                // store WITHOUT a violation (same disposition as a quota hit).
                // Audit cycle-7: stops a rejoining node banning its closest
                // peers over its own just-expired AppEndpointEntry.
                Err(veil_discovery::directory::SignedDhtReject::Expired) => {
                    return Err(DispatchResult::NoResponse);
                }
                Err(veil_discovery::directory::SignedDhtReject::Invalid) => {
                    return Err(DispatchResult::Violation(
                        "Store: signed AppEndpointEntry failed verification".to_owned(),
                    ));
                }
            }
        } else if is_attach {
            match veil_discovery::directory::decode_and_verify_signed_attachment_status(
                payload_value,
            ) {
                Ok(record) => record.node_id,
                // Stale (validly signed but expired): benign republish of a
                // cached copy — drop without a violation (cf. the AP arm).
                Err(veil_discovery::directory::SignedDhtReject::Expired) => {
                    return Err(DispatchResult::NoResponse);
                }
                Err(veil_discovery::directory::SignedDhtReject::Invalid) => {
                    return Err(DispatchResult::Violation(
                        "Store: signed AnnounceAttachment failed verification".to_owned(),
                    ));
                }
            }
        } else if is_nc {
            // Audit cycle-5 (N1-residue): NameClaim/IdentityDocument/
            // InstanceRegistry/MlKemKeyCert are STRUCTURALLY decoded here, NOT
            // signature-verified (verification happens on the read/resolver
            // path), so the record's `node_id` field is attacker-controlled at
            // this gate. It must NOT be used as the per-origin cap bucket: an
            // attacker could set it to a victim's id (cap-poisoning), rotate it
            // per record (cap-evasion), or set it to [0u8;32] == ORIGIN_INTERNAL
            // to make the write fully cap-EXEMPT. Decode for structural
            // validation, rate-limit per claimed id, then attribute the bytes to
            // the shared recursive bucket — like signed bundles, which also have
            // no per-identity owner trustworthy at this gate. (app-endpoint /
            // attachment above DO verify node_id == BLAKE3(pubkey), so they keep
            // the real owner origin.)
            //
            // Audit cycle-8 (quota-exhaustion DoS, attack-model-1): the shared
            // `ORIGIN_RECURSIVE_BUNDLE` byte-bucket is one of THREE layers, not
            // the sole defense — so it is intentionally NOT split into per-type
            // sub-buckets (a byte-accounting change to a live, integrity-safe
            // path whose marginal benefit over the existing layers is low):
            //   1. `identity_write_quota.try_allow(claimed_id)` — per-claimed-id
            //      hourly write cap (below), so flooding with one id is throttled;
            //   2. that quota's LRU-bounded map — rotating ids can't grow state
            //      unbounded;
            //   3. the shared byte-bucket — final aggregate ceiling.
            // Integrity is never at risk (the resolver re-verifies on read).
            // Residual: an attacker rotating many ids can still pressure the
            // aggregate ceiling within the per-id rate-limit; if that ever shows
            // up as real availability loss, add per-type sub-limits here.
            let id = match veil_proto::name_claim_v2::NameClaim::decode(payload_value) {
                Ok(c) => c.node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed NameClaim (v2)".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE
        } else if is_id {
            let id = match veil_proto::identity_document::IdentityDocument::decode(payload_value) {
                Ok(d) => d.node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed IdentityDocument".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE // audit cycle-5 N1-residue
        } else if is_ir {
            let id = match veil_proto::instance_registry::InstanceRegistry::decode(payload_value) {
                Ok(r) => r.node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed InstanceRegistry".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE // audit cycle-5 N1-residue
        } else if is_mc {
            let id = match veil_proto::mlkem_cert::MlKemKeyCert::decode(payload_value) {
                Ok(c) => c.node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed MlKemKeyCert".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE // audit cycle-5 N1-residue
        } else if is_desc {
            // Blinded onion-service descriptor (diff-audit L5). CRYPTOGRAPHICALLY
            // self-authenticating: verify the signature under the descriptor's
            // embedded blinded_pub. The canonical-key binding (DHT key ==
            // H(domain ‖ blinded_pub)) is enforced by `mirror_cache_key_ok` on the
            // STORE path, so an attacker can't store a valid descriptor under a
            // victim's key. Blinded keys are cheap to grind (per-period,
            // unlinkable), so attribute bytes to the shared aggregate bucket
            // rather than a per-key bucket an attacker could multiply.
            if veil_anonymity::blinded_descriptor::verify_descriptor_self(payload_value).is_none() {
                return Err(DispatchResult::Violation(
                    "Store: blinded descriptor failed self-verification".to_owned(),
                ));
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE
        } else if is_rk {
            // RelayKeyRecord (relay X25519 KEM key, resolvable by node_id).
            // STRUCTURALLY decoded here, NOT signature-verified — like
            // NameClaim/IdentityDocument/InstanceRegistry/MlKemKeyCert, its
            // `node_id` field is attacker-controlled at this gate, so we
            // rate-limit per claimed id but attribute the bytes to the shared
            // recursive bucket (the resolver re-verifies the subkey signature on
            // read via `verify_relay_key`). Without this arm the record's magic
            // ("RK") falls into the catch-all reject below and peers refuse its
            // replication STORE — so it never becomes cross-node discoverable.
            let id = match veil_proto::relay_key::RelayKeyRecord::decode(payload_value) {
                Ok(r) => r.node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed RelayKeyRecord".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE
        } else if is_ra {
            // RendezvousAd (carries a receiver's mailbox/onion rendezvous relay
            // node_id + its KEM key, keyed under the receiver's ad slots).
            // STRUCTURALLY decoded here, NOT signature-verified — like
            // NameClaim/IdentityDocument/.../RelayKeyRecord, so rate-limit per
            // the ad's claimed receiver node_id but attribute bytes to the shared
            // recursive bucket (the resolver re-verifies the ad signature +
            // receiver-binding on read via verify_rendezvous_ad). Without this
            // arm the "RA" magic falls into the catch-all reject below and peers
            // refuse the ad's replication STORE — so a receiver's mailbox relay
            // never becomes cross-node discoverable.
            let id = match veil_anonymity::rendezvous::decode_rendezvous_ad(payload_value) {
                Ok(ad) => ad.receiver_node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed RendezvousAd".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE
        } else if is_rd {
            // RelayDirectoryEntry ("RD"): a relay's anonymity x25519 pk (for the
            // outer onion layer), resolvable by node_id. STRUCTURALLY decoded
            // here, NOT signature-verified — like RelayKeyRecord/RendezvousAd, so
            // rate-limit per the entry's claimed node_id but attribute bytes to
            // the shared recursive bucket (the resolver re-verifies the entry
            // signature on read via `verify_entry`). Without this arm the "RD"
            // magic falls into the catch-all reject below and peers refuse its
            // replication STORE — so the entry stays local-only at the relay and
            // a COLD sender can never resolve an arbitrary advertised rendezvous
            // relay → introduce silent-drop → `NoRendezvous`.
            let id = match veil_anonymity::directory::decode_entry(payload_value) {
                Ok(e) => e.node_id,
                Err(_) => {
                    return Err(DispatchResult::Violation(
                        "Store: malformed RelayDirectoryEntry".to_owned(),
                    ));
                }
            };
            if !already_present && !self.abuse.identity_write_quota.try_allow(&id).is_allowed() {
                return Err(DispatchResult::NoResponse);
            }
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE
        } else {
            return Err(DispatchResult::Violation(
                "Store: unrecognised payload magic — recursive plane requires a signed-record magic prefix"
                    .to_owned(),
            ));
        };
        Ok(origin)
    }

    /// audit cycle-6 (A8): for the recursive FIND_VALUE mirror-cache, verify a
    /// self-authenticating record's CANONICAL DHT key equals the queried
    /// `target_key` before caching the value under that key.
    /// [`Self::validate_store_value_by_magic`] proves the record is internally
    /// well-formed / owner-signed, but NOT that it belongs at `target_key`: a
    /// responder whose XOR distance lets it answer `FIND_VALUE(target_key)`
    /// could otherwise return a valid record of its OWN (e.g. its app-endpoint)
    /// and have us mirror-cache it under the victim's key.
    ///
    /// Returns `true` only when it is safe to mirror-cache:
    ///  * derivable record types (AppEndpoint / Attachment / SignedBundle) —
    ///    `true` iff the key derived from the record equals `target_key`;
    ///  * non-derivable types (NameClaim / IdentityDocument / InstanceRegistry /
    ///    MlKemKeyCert), whose canonical key is not a pure function of the value
    ///    decodable here — `true` (unchanged behaviour; these are structurally
    ///    decoded and re-verified on the resolver read path).
    pub fn mirror_cache_key_ok(&self, payload: &[u8], target_key: &[u8; 32]) -> bool {
        let Some(magic) = payload.get(..2) else {
            return false;
        };
        if magic == &veil_discovery::directory::APP_ENDPOINT_DHT_MAGIC[..] {
            match veil_discovery::directory::AppEndpointEntry::decode_and_verify_signed_from_dht(
                payload,
            ) {
                Some(e) => {
                    veil_proto::discovery::app_endpoint_key(&e.node_id, &e.app_id, e.endpoint_id)
                        == *target_key
                }
                None => false,
            }
        } else if magic == &veil_discovery::directory::ATTACHMENT_DHT_MAGIC[..] {
            match veil_discovery::directory::decode_and_verify_signed_attachment(payload) {
                Some(r) => veil_proto::discovery::attachment_key(&r.node_id) == *target_key,
                None => false,
            }
        } else if magic == &veil_bootstrap::SIGNED_BUNDLE_MAGIC[..] {
            veil_bootstrap::bootstrap_bundle_dht_key() == *target_key
        } else if magic == &veil_anonymity::blinded_descriptor::DESCRIPTOR_DHT_MAGIC[..] {
            // Blinded descriptor (diff-audit L5): cryptographically verified at
            // the STORE gate, so it is an owner-VERIFIED type — bind its canonical
            // DHT key (H(domain ‖ blinded_pub), returned by verify_descriptor_self)
            // to target_key, else a valid descriptor could be stored under a
            // victim's / arbitrary key and poison resolver lookups.
            match veil_anonymity::blinded_descriptor::verify_descriptor_self(payload) {
                Some(canonical) => canonical == *target_key,
                None => false,
            }
        } else {
            // nc / id / ir / mc: caching left unchanged (returns true). The
            // canonical key IS structurally derivable from the record's
            // node_id (+ name / instance) fields, but at THIS gate those fields
            // are attacker-controlled (the record is structurally decoded, not
            // signature-verified — verification happens on the resolver read
            // path, which is the real bound). Adding a key-derivation check here
            // would not meaningfully help: an attacker can set node_id to make
            // the derived key equal target_key, and the resolver re-verifies and
            // rejects the forged record regardless. (The owner-VERIFIED types
            // above — AppEndpoint / Attachment — are different: they ARE
            // verified at this gate, so binding their key to target_key is the
            // one missing check, which this method adds.)
            true
        }
    }
}
