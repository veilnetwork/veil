//! The tests for `service_tasks.rs`.
//!
//! Moved out as a unit rather than split by subject, and that is deliberate:
//! the fixtures here — `peer`, `config_with`, `seed_fixture`,
//! `test_rendezvous_ad` before it left with its own module — are shared
//! across subjects, so cutting the module by topic would have meant either
//! duplicating them or leaving tests behind their code. Neither is worth it
//! while the production file is what needs to become readable (report24
//! RUNTIME-3): this alone takes `service_tasks.rs` from 5 811 lines to 2 866.
//!
//! `use super::*` still names the production module, so nothing about how
//! these tests reach what they test has changed.

use super::*;
use veil_cfg::{BootstrapPeer, SignatureAlgorithm};

/// A rotation that took must pull the republish forward; one the ring
/// refused must not.
///
/// The second half is the one worth a test. Announcing after a refusal
/// publishes a cert around the key the node still holds — harmless-looking,
/// and it hides the refusal behind a republish that appears to have worked.
#[tokio::test]
async fn only_a_rotation_that_took_pulls_the_republish_forward() {
    let keys = veil_e2e::MlKemSeedRing::new(
        1,
        [0x11; veil_e2e::DK_SEED_BYTES],
        [0x11; veil_e2e::EK_BYTES],
    );
    let notify = tokio::sync::Notify::new();
    let overlap = veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS;

    // A waiter must already be parked: `notify_waiters` wakes whoever is
    // waiting NOW and stores nothing, which is the behaviour the republish
    // loop relies on (it is always parked in its select). The first poll
    // both parks it and shows nothing has fired yet.
    let mut announced = Box::pin(notify.notified());
    assert!(
        futures_lite_ready(&mut announced).is_none(),
        "nothing has rotated yet"
    );

    // Refused: the epoch does not advance.
    let refused = NodeRuntime::rotate_and_announce(
        &keys,
        &notify,
        2_000,
        1,
        [0x22; veil_e2e::DK_SEED_BYTES],
        [0x22; veil_e2e::EK_BYTES],
        overlap,
    );
    assert!(refused.is_err(), "epoch 1 does not advance on epoch 1");
    assert_eq!(keys.current_ek(), [0x11u8; veil_e2e::EK_BYTES]);
    assert!(
        futures_lite_ready(&mut announced).is_none(),
        "a refused rotation must not announce a key that never changed"
    );

    // Accepted: the epoch advances.
    NodeRuntime::rotate_and_announce(
        &keys,
        &notify,
        2_000,
        2,
        [0x33; veil_e2e::DK_SEED_BYTES],
        [0x33; veil_e2e::EK_BYTES],
        overlap,
    )
    .expect("epoch 2 advances");
    assert_eq!(keys.current_ek(), [0x33u8; veil_e2e::EK_BYTES]);
    assert!(
        futures_lite_ready(&mut announced).is_some(),
        "a rotation that took must publish the new key rather than wait out the 6h tick"
    );
}

/// Poll a parked future once without awaiting it.
fn futures_lite_ready<F: std::future::Future<Output = ()> + Unpin>(f: &mut F) -> Option<()> {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match std::pin::Pin::new(f).poll(&mut cx) {
        std::task::Poll::Ready(()) => Some(()),
        std::task::Poll::Pending => None,
    }
}

#[test]
fn ordinary_retransmit_advances_attempt_without_changing_terminal_content_id() {
    use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
    use veil_proto::family::{DeliveryMsg, FrameFamily};
    use veil_proto::header::FrameHeader;

    let envelope = DeliveryEnvelope {
        recipient: veil_proto::recipient::Recipient::any([0x21; 32]),
        sender_node_id: [0x22; 32],
        src_app_id: [0x23; 32],
        app_id: [0x24; 32],
        endpoint_id: 9,
        content_id: [0x25; 32],
        created_at: 1,
        ttl_secs: 30,
        payload: vec![1, 2, 3],
        trace_id: 0,
        require_ack: true,
    };
    let body = ForwardPayload {
        next_hop_node_id: [0x26; 32],
        envelope,
        relay_hops: 0,
        delivery_attempt: Some(1),
        traffic_class: None,
    }
    .encode();
    let mut header = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
    header.body_len = body.len() as u32;
    let frame = veil_proto::codec::encode_frame(&header, &body);

    let retried = prepare_ack_retransmit_frame(&frame, [0x27; 32], 2).unwrap();
    let retried = ForwardPayload::decode(&retried[veil_proto::HEADER_SIZE..]).unwrap();
    assert_eq!(retried.next_hop_node_id, [0x27; 32]);
    assert_eq!(retried.envelope.content_id, [0x25; 32]);
    assert_eq!(retried.delivery_attempt, Some(2));
    assert!(prepare_ack_retransmit_frame(&frame, [0x27; 32], 256).is_none());
}

#[test]
fn chunk_retransmit_refreshes_only_carrier_id_and_next_hop() {
    use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload};
    use veil_proto::family::{DeliveryMsg, FrameFamily};
    use veil_proto::header::FrameHeader;

    let chunk = ChunkedEnvelopePayload {
        transfer_id: [0x11; 16],
        chunk_index: 2,
        chunk_count: 4,
        total_size: 9,
        orig_content_id: [0x22; 32],
        require_ack: true,
        data: vec![7, 8, 9],
    };
    let envelope = DeliveryEnvelope {
        recipient: veil_proto::recipient::Recipient::any([0x33; 32]),
        sender_node_id: [0x44; 32],
        src_app_id: [0x55; 32],
        app_id: [0x66; 32],
        endpoint_id: 7,
        content_id: [0x77; 32],
        created_at: 1,
        ttl_secs: 30,
        payload: chunk.encode(),
        trace_id: 9,
        require_ack: false,
    };
    let body = ForwardPayload {
        next_hop_node_id: [0x88; 32],
        envelope,
        relay_hops: 0,
        delivery_attempt: None,
        traffic_class: None,
    }
    .encode();
    let mut header = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
    header.body_len = body.len() as u32;
    let frame = veil_proto::codec::encode_frame(&header, &body);

    let first = prepare_ack_retransmit_frame(&frame, [0x99; 32], 2).unwrap();
    let second = prepare_ack_retransmit_frame(&frame, [0xAA; 32], 2).unwrap();
    let first = ForwardPayload::decode(&first[veil_proto::header::HEADER_SIZE..]).unwrap();
    let second = ForwardPayload::decode(&second[veil_proto::header::HEADER_SIZE..]).unwrap();
    assert_eq!(first.next_hop_node_id, [0x99; 32]);
    assert_eq!(second.next_hop_node_id, [0xAA; 32]);
    assert_ne!(first.envelope.content_id, [0x77; 32]);
    assert_ne!(second.envelope.content_id, [0x77; 32]);
    assert_ne!(first.envelope.content_id, second.envelope.content_id);
    assert_eq!(
        ChunkedEnvelopePayload::decode(&first.envelope.payload).unwrap(),
        chunk
    );
    assert_eq!(
        ChunkedEnvelopePayload::decode(&second.envelope.payload).unwrap(),
        chunk
    );
}

#[test]
fn whole_batch_retry_fills_loss_once_and_leaves_no_phantom_transfer() {
    use veil_dispatcher::envelope_chunks::{AddChunkResult, EnvelopeChunkReassembler};
    use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload};
    use veil_proto::family::{DeliveryMsg, FrameFamily};
    use veil_proto::header::FrameHeader;

    let transfer_id = [0xB1; 16];
    let original_id = [0xB2; 32];
    let make_frame = |index: u32| {
        let chunk = ChunkedEnvelopePayload {
            transfer_id,
            chunk_index: index,
            chunk_count: 4,
            total_size: 8,
            orig_content_id: original_id,
            require_ack: true,
            data: vec![index as u8; 2],
        };
        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([0xB3; 32]),
            sender_node_id: [0xB4; 32],
            src_app_id: [0xB5; 32],
            app_id: [0xB6; 32],
            endpoint_id: 1,
            content_id: [index as u8 + 1; 32],
            created_at: 1,
            ttl_secs: 30,
            payload: chunk.encode(),
            trace_id: 0,
            require_ack: false,
        };
        let body = ForwardPayload {
            next_hop_node_id: [0xB7; 32],
            envelope,
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: None,
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        header.body_len = body.len() as u32;
        veil_proto::codec::encode_frame(&header, &body)
    };
    let frames: Vec<_> = (0..4).map(make_frame).collect();
    let mut reassembler = EnvelopeChunkReassembler::new();

    // First attempt arrives reordered and loses index 2 after the relay;
    // 3,0,1 remain buffered.
    for index in [3usize, 0, 1] {
        let fwd = ForwardPayload::decode(&frames[index][veil_proto::HEADER_SIZE..]).unwrap();
        let chunk = ChunkedEnvelopePayload::decode(&fwd.envelope.payload).unwrap();
        assert!(matches!(
            reassembler.add(&fwd.envelope, fwd.envelope.sender_node_id, chunk, 100),
            AddChunkResult::Pending
        ));
    }

    let mut completed = 0;
    let mut replayed_tail = 0;
    for (index, frame) in frames.iter().enumerate() {
        let retried = prepare_ack_retransmit_frame(frame, [0xC1; 32], 2).unwrap();
        let fwd = ForwardPayload::decode(&retried[veil_proto::HEADER_SIZE..]).unwrap();
        assert_ne!(fwd.envelope.content_id, [index as u8 + 1; 32]);
        let chunk = ChunkedEnvelopePayload::decode(&fwd.envelope.payload).unwrap();
        match reassembler.add(&fwd.envelope, fwd.envelope.sender_node_id, chunk, 101) {
            AddChunkResult::Complete(envelope) => {
                completed += 1;
                assert_eq!(envelope.content_id, original_id);
                assert_eq!(envelope.payload, vec![0, 0, 1, 1, 2, 2, 3, 3]);
            }
            AddChunkResult::CompletedReplay(id) => {
                replayed_tail += 1;
                assert_eq!(id, original_id);
            }
            AddChunkResult::Pending | AddChunkResult::Rejected("duplicate chunk") => {}
            other => panic!("unexpected retry outcome: {other:?}"),
        }
    }
    assert_eq!(completed, 1);
    assert_eq!(replayed_tail, 1);
    assert_eq!(reassembler.transfer_count(), 0);
    assert_eq!(reassembler.buffered_bytes(), 0);
}

fn peer(pk: &str) -> BootstrapPeer {
    BootstrapPeer {
        transport: format!("tls://{pk}.example:9906"),
        public_key: pk.to_owned(),
        nonce: "AAAA".to_owned(),
        algo: SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_ca_cert: None,
    }
}

#[test]
fn kemless_reregister_preserves_existing_kem() {
    // The app registers the relay's KEM pk (mailbox-by-discovery deposit
    // target); veil's built-in receiver task then re-registers the SAME
    // (relay, cookie) KEM-LESS on its tick. A full overwrite would drop the
    // KEM and a sender would resolve usable(KEM)=0 (cannot deposit offline
    // mail) — so the KEM-less path must PRESERVE an existing KEM.
    let sk = std::sync::Arc::new(x25519_dalek::StaticSecret::from([7u8; 32]));
    let state = std::sync::Arc::new(crate::runtime::anonymity_state::AnonymityState::new(
        false,
        0,
        sk,
        None,
        Vec::new(),
    ));
    let relay = [0xAB; 32];
    let cookie = [0xCD; 16];
    let kem = vec![0x42u8; 32];

    rendezvous_register_publisher_with_kem(&state, &relay, cookie, 3600, 1, kem.clone(), 0);
    rendezvous_register_publisher(&state, &relay, cookie, 3600, None);

    let entries = lock!(state.rendezvous_publisher_entries);
    assert_eq!(entries.len(), 1, "same (relay,cookie) dedups to one entry");
    assert_eq!(
        entries[0].rendezvous_kem_pk, kem,
        "KEM key must survive a KEM-less re-register (else usable(KEM)=0)"
    );
    assert_eq!(entries[0].rendezvous_kem_algo, 1);
}

#[test]
fn kem_register_overwrites_kemless() {
    // The reverse order must ALSO end KEM-bearing: a KEM-less entry first,
    // then the app's KEM register, leaves the entry with the KEM.
    let sk = std::sync::Arc::new(x25519_dalek::StaticSecret::from([9u8; 32]));
    let state = std::sync::Arc::new(crate::runtime::anonymity_state::AnonymityState::new(
        false,
        0,
        sk,
        None,
        Vec::new(),
    ));
    let relay = [0x01; 32];
    let cookie = [0x02; 16];
    let kem = vec![0x55u8; 32];

    rendezvous_register_publisher(&state, &relay, cookie, 3600, None);
    rendezvous_register_publisher_with_kem(&state, &relay, cookie, 3600, 1, kem.clone(), 0);

    let entries = lock!(state.rendezvous_publisher_entries);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].rendezvous_kem_pk, kem);
}

#[test]
fn filter_self_seeds_drops_matching_pubkey() {
    let peers = vec![peer("ME"), peer("OTHER1"), peer("OTHER2")];
    let kept = filter_self_seeds(peers, "ME");
    assert_eq!(kept.len(), 2);
    assert!(kept.iter().all(|p| p.public_key != "ME"));
}

// ── builtin-seed policy: alternative entry points ────────────────────
//
// The seeds are the only entry points a stock binary knows. When they are
// blocked the operator's answer is to name other hosts — but naming them
// used to switch the seeds OFF, so the node swapped one single point of
// failure for another. These pin the policy that lets it hold both.

fn row(source: crate::types::PeerSource, node: u8, transport: &str) -> PeerConfigEntry {
    PeerConfigEntry {
        peer_id: PeerId::new(7),
        node_id: veil_cfg::NodeId::from([node; 32]),
        public_key: String::new(),
        nonce: String::new(),
        transport: transport.to_owned(),
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        bootstrap_only: false,
        source,
    }
}

fn listener(uri: &str, advertise: Option<&str>) -> veil_cfg::ListenConfig {
    veil_cfg::ListenConfig {
        id: crate::types::ListenId::new(1),
        transport: uri.to_owned(),
        advertise: advertise.map(str::to_owned),
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        relay: None,
        ..Default::default()
    }
}

/// A 32-byte key and 4-byte nonce, base64, as the identity carries them.
fn identity_b64() -> (String, String) {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    (b64.encode([7u8; 32]), b64.encode([1u8, 2, 3, 4]))
}

fn announce_for_listeners(
    listeners: Vec<veil_cfg::ListenConfig>,
) -> Option<veil_bootstrap::LanAnnounce> {
    let (key, nonce) = identity_b64();
    let mut c = veil_cfg::Config::default();
    c.listen = listeners;
    lan_announce_for(&c, &key, &nonce, &[])
}

fn address_for_listeners(uris: &[(&str, Option<&str>)]) -> Option<(String, u16)> {
    let mut c = veil_cfg::Config::default();
    c.listen = uris.iter().map(|(u, a)| listener(u, *a)).collect();
    public_address_for(&c, &[])
}

#[test]
fn exactly_one_side_of_a_pair_places_the_call() {
    use veil_bootstrap::DiscoveredPeerCache;
    use veil_cfg::{NodeId, SignatureAlgorithm};

    // A pair dials one way: `ours < theirs`. `outbound_connector` has
    // always honoured that; the rendezvous dial went straight to
    // `connect_peer_active` and never did, so both ends called each other
    // at every pass. Measured on a production seed with the largest id:
    // 24 dials in 54 minutes, every one refused as a duplicate.
    let key = "fyU1fAlyHVNMat6NZBJ+KBU/aeJhCP+OBsomlgJ1Cjo=";
    let theirs = NodeId::from_public_key(SignatureAlgorithm::Ed25519, key).expect("valid");
    let addr = "obfs4-tcp://198.51.100.7:5556";

    let mut c = DiscoveredPeerCache::in_memory();
    c.upsert(
        veil_cfg::BootstrapPeer {
            transport: addr.to_owned(),
            public_key: key.to_owned(),
            nonce: "AOCZRA==".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        },
        1_700_000_000,
    );
    let cache = Arc::new(std::sync::Mutex::new(c));

    let mut smaller = *theirs.as_bytes();
    smaller[0] = smaller[0].wrapping_sub(1);
    let mut larger = *theirs.as_bytes();
    larger[0] = larger[0].wrapping_add(1);

    assert!(
        we_should_place_the_call(&smaller, &cache, addr),
        "the smaller id must call, or nobody does"
    );
    assert!(
        !we_should_place_the_call(&larger, &cache, addr),
        "the larger id called anyway; its dial is refused as a duplicate \
         and the working session goes down around the refusal"
    );

    // A first meeting has no mapping, and somebody has to call or the
    // mapping is never learned at all.
    let empty = Arc::new(std::sync::Mutex::new(DiscoveredPeerCache::in_memory()));
    assert!(we_should_place_the_call(&larger, &empty, addr));
    // An address the cache knows nothing about is a first meeting too.
    assert!(we_should_place_the_call(
        &larger,
        &cache,
        "obfs4-tcp://203.0.113.9:5556"
    ));
    // Nothing dialable, nothing to decide.
    assert!(!we_should_place_the_call(
        &smaller,
        &cache,
        "no-scheme-here"
    ));
}

#[test]
fn a_refused_duplicate_is_an_answer_and_keeps_its_row() {
    // The producer and the reader of this refusal live in different files,
    // and the reader matches on the text. Pin them together, or a reworded
    // message turns "you already have this peer" back into "retry next
    // pass" -- which is the loop that was measured.
    let produced = include_str!("../peer_handshake.rs");
    assert!(
        produced.contains("{DUPLICATE_SESSION} to node"),
        "the refusal no longer carries the shared marker"
    );
    let reader = production_source(include_str!("../service_tasks.rs"));
    assert!(
        reader.contains("refusal.contains(crate::runtime::peer_handshake::DUPLICATE_SESSION)"),
        "the rendezvous dial no longer recognises the refusal"
    );
    // And the row survives it: removing it is what made the next pass
    // dial the same peer again.
    let at = reader
        .find("let refusal = format!(\"{e}\");")
        .expect("the failure arm is gone; this guard is stale");
    let arm = &reader[at..];
    let recognise = arm
        .find("DUPLICATE_SESSION")
        .expect("the failure arm no longer recognises a duplicate");
    let remove = arm
        .find("peers.remove(&peer_id)")
        .expect("the failure arm no longer removes anything; guard is stale");
    assert!(
        recognise < remove,
        "the row is removed before the duplicate case is recognised, so the \
         next pass dials the same peer again"
    );
}

/// The file WITHOUT its test module.
///
/// A guard that greps its own file finds its own assertion string and
/// passes no matter what the production code does. That is not a
/// hypothetical: the first version of the algorithm guard below did
/// exactly this, and the break-check that should have reddened stayed
/// green.
/// The slot alone, for the assertions that only care WHICH one.
fn rendezvous_slot_for(known: &[PeerConfigEntry], transport: &str) -> Option<PeerId> {
    rendezvous_slot_claim(known, transport).map(RendezvousSlot::peer_id)
}

fn production_source(file: &str) -> &str {
    file.split("#[cfg(test)]").next().unwrap_or(file)
}

/// report20 V18-M4: an entry that can never be published takes no slot.
///
/// The slots are bounded and the publish tick signs what is in them, so an
/// entry the signer refuses costs a slot a working publisher could have
/// had — silently, because the refusal lands later, on a tick, in a log
/// line nobody reads, while the registration answered "registered".
#[test]
fn an_entry_the_signer_would_refuse_never_takes_a_slot() {
    use veil_anonymity::rendezvous::{
        MAX_PUSH_ENVELOPE_LEN, MAX_RENDEZVOUS_KEM_PK_LEN, MAX_VALIDITY_WINDOW_SECS,
        MAX_WAKE_HMAC_ENVELOPE_LEN,
    };
    let base = || veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: [3; 32],
        auth_cookie: [3; 16],
        validity_window_secs: 3600,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        rendezvous_kem_algo: 0,
        rendezvous_kem_pk: Vec::new(),
        rendezvous_kem_valid_until_unix: 0,
        ephemeral_ad_identity: None,
    };

    // Vacuity first: the ordinary entry is admitted, or every refusal
    // below is passing on a function that refuses everything.
    let mut entries = Vec::new();
    assert!(
        insert_publisher_entry(&mut entries, base()),
        "a publishable entry was refused"
    );
    assert_eq!(entries.len(), 1);

    let unpublishable: Vec<(&str, veil_anonymity::rendezvous::RendezvousPublisherEntry)> = vec![
        ("a window of zero is expired the moment it is signed", {
            let mut e = base();
            e.validity_window_secs = 0;
            e
        }),
        ("a window past the signer's cap", {
            let mut e = base();
            e.validity_window_secs = MAX_VALIDITY_WINDOW_SECS + 1;
            e
        }),
        ("a push envelope past the cap", {
            let mut e = base();
            e.push_envelope = vec![0u8; MAX_PUSH_ENVELOPE_LEN + 1];
            e
        }),
        ("a wake envelope past the cap", {
            let mut e = base();
            e.wake_hmac_envelope = vec![0u8; MAX_WAKE_HMAC_ENVELOPE_LEN + 1];
            e
        }),
        ("a relay key past the cap", {
            let mut e = base();
            e.rendezvous_kem_algo = 1;
            e.rendezvous_kem_pk = vec![0u8; MAX_RENDEZVOUS_KEM_PK_LEN + 1];
            e
        }),
        ("an algorithm named with no key behind it", {
            let mut e = base();
            e.rendezvous_kem_algo = 1;
            e
        }),
    ];

    for (why, entry) in unpublishable {
        // A DIFFERENT (relay, cookie) each time, so a refusal cannot be
        // mistaken for the replace path.
        let mut entry = entry;
        entry.rendezvous_node_id = [9; 32];
        let mut fresh = Vec::new();
        assert!(
            !insert_publisher_entry(&mut fresh, entry),
            "{why}: it was registered anyway"
        );
        assert!(fresh.is_empty(), "{why}: it took a slot anyway");
    }

    // And the clock-dependent one, which the admission does not judge
    // because it has no clock: a relay stamp already in the past makes
    // every tick refuse the ad.
    let mut stale = base();
    stale.rendezvous_kem_algo = 1;
    stale.rendezvous_kem_pk = vec![7u8; 32];
    stale.rendezvous_kem_valid_until_unix = 1_000;
    assert!(
        publisher_entry_is_publishable(&stale, 2_000).is_err(),
        "a relay key whose stamp has passed was called publishable"
    );
    assert!(
        publisher_entry_is_publishable(&stale, 0).is_ok(),
        "with no clock offered, the stamp is not judged"
    );
    assert!(
        publisher_entry_is_publishable(&stale, 500).is_ok(),
        "a stamp still in the future is fine"
    );
}

/// report21 V18-L1: every registration goes through the one admission.
///
/// `NodeRuntime::register_rendezvous_publisher_with_push` kept its own copy
/// of "replace or push", so it kept none of what the shared helper had been
/// taught: it pushed past the slot bound (an entry past it is cloned on
/// every publish tick and never signed), and its replace overwrote the KEM
/// key with the empty one it registers with — the erasure the helper exists
/// to prevent, arriving through a different door.
#[test]
fn the_runtime_registration_uses_the_bounded_admission() {
    let src = include_str!("../mod.rs");
    let f = src
        .split("pub fn register_rendezvous_publisher_with_push")
        .nth(1)
        .and_then(|t| t.split("\n    ///").next())
        .expect("the registration");
    assert!(
        f.contains("insert_publisher_entry(&mut entries, entry)"),
        "the registration keeps its own admission again, so the slot bound \
         and the KEM-preservation rule do not apply to it"
    );
    assert!(
        !f.contains("entries.push(entry)"),
        "an entry is pushed past the slot bound: it is cloned on every \
         publish tick and never signed"
    );

    // And setting a relay key moves its expiry with it, or a fresh key is
    // advertised under the lifetime of the one it replaced.
    let setter = src
        .split("pub fn set_rendezvous_relay_kem")
        .nth(1)
        .and_then(|t| t.split("\n    ///").next())
        .expect("the relay-key setter");
    assert!(
        setter.contains("entry.rendezvous_kem_valid_until_unix = 0;"),
        "a rotated relay key keeps the previous key's expiry"
    );
}

/// report20 V18-M13: a refused publisher slot must stop the relay from
/// being counted as one we are reachable through.
///
/// `insert_publisher_entry` returns whether the entry actually took a
/// slot, and the re-pick loop threw that answer away: the relay went into
/// `registered`, `current` could become a relay carrying NO ad, and the
/// node then sat at a meeting point no sender was ever told about. There
/// is no seam to call this loop through — it wants a live session
/// registry, a DHT and an outbox — so the guard is on the source: the
/// answer has to be read.
#[test]
fn the_repick_loop_reads_the_publisher_slot_answer() {
    let src = production_source(include_str!("../service_tasks.rs"));
    // The definition itself matches the same shape; only CALLS count.
    let calls = src.matches("rendezvous_register_publisher(\n").count()
        - src.matches("fn rendezvous_register_publisher(\n").count();
    assert!(
        calls >= 1,
        "the re-pick loop no longer registers a publisher at all; this \
         guard is now vacuous and has to be re-aimed"
    );
    assert_eq!(
        src.matches("if !rendezvous_register_publisher(\n").count(),
        calls,
        "a call to rendezvous_register_publisher ignores its answer: a \
         refused slot means no ad, and the relay must not be counted as \
         one this node is reachable through"
    );
}

#[test]
fn a_peer_is_recorded_under_the_algorithm_it_proved() {
    use veil_cfg::SignatureAlgorithm;
    // Ed25519 was written down as fact for every peer met at a meeting
    // point. The node id the direction rule compares derives from the key
    // and its algorithm, so a mislabelled Falcon peer puts the pair back to
    // both ends dialling each other.
    for proved in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::Falcon512] {
        assert_eq!(
            proven_algorithm(Some(proved)),
            proved,
            "the handshake proved {proved:?} and the row said otherwise"
        );
    }
    // An algorithm this build cannot name still yields a session; the row
    // takes the historical default rather than the peer being dropped.
    assert_eq!(proven_algorithm(None), SignatureAlgorithm::Ed25519);

    // And the value actually travels: handshake -> session -> row.
    let hs = include_str!("../peer_handshake.rs");
    assert!(
        hs.contains("pub algo: Option<veil_cfg::SignatureAlgorithm>"),
        "the handshake no longer carries the proved algorithm"
    );
    assert!(
        hs.contains("peer_algo: remote_identity.algo"),
        "the session no longer receives the proved algorithm"
    );
    let here = production_source(include_str!("../service_tasks.rs"));
    assert!(
        here.contains("proven_algorithm(session.peer_algo)"),
        "the row no longer asks what was proved"
    );
}

/// A bootstrap dial that could not ask for contacts must SAY so.
///
/// A rendezvous peer is dialled for exactly one reason: to be asked for
/// contacts, and then broken. The ask is spawned behind a wait for the
/// session outbox, so a session that ends first takes the ask with it —
/// no contacts, no peers, and the node then reports itself connected with
/// zero peers for the rest of the process, which reads exactly like having
/// no network at all.
///
/// Measured on a fresh identity with nothing configured: three seeds
/// dialled, three sessions opened and closed inside the same millisecond,
/// and not one `bootstrap.find_node_done` line — the burst was skipped and
/// nothing recorded that it had been.
#[test]
fn a_bootstrap_burst_that_never_ran_leaves_a_trace() {
    let src = production_source(include_str!("../../outbound_connector.rs"));
    assert!(
        src.contains("bootstrap.find_node_skipped"),
        "a bootstrap dial that lost its session before it could ask for \
         contacts is silent again, and silence there is indistinguishable \
         from a node that simply has no peers"
    );
    let at = src
        .find("bootstrap.find_node_skipped")
        .expect("checked above");

    // And it has to be REACHABLE. A line behind `if false` reads exactly
    // like a line behind the real condition, and the first version of this
    // test could not tell them apart: it asked whether the string was in
    // the file, which is existence, not a decision.
    let condition = src[..at]
        .rmatch_indices("if ")
        .map(|(i, _)| src[i..].lines().next().unwrap_or_default())
        .next()
        .expect("no condition governs the skip");
    assert!(
        condition.contains("registered"),
        "the skip is governed by `{}` rather than by whether the session \
         ever registered, so it cannot fire for the case it exists for",
        condition.trim()
    );

    // The skip has to END the task. Falling through to `find_node` on a
    // session that is gone logs `find_node_done contacts_received=0`,
    // which says the peer answered with nothing — a different and wrong
    // story about the same failure.
    let after = &src[at..];
    let ret = after.find("return;").unwrap_or(usize::MAX);
    let ask = after.find("querier.find_node").unwrap_or(usize::MAX);
    assert!(
        ret < ask,
        "the skipped burst falls through and asks anyway, so an ask that \
         could not happen is reported as a peer that answered with nothing"
    );
}

/// `session.close` says only THAT a session ended, never why or for how
/// long, and it is written by our own teardown after `run()` returns — so
/// a far end that hung up and an orderly local wind-down produce the same
/// line. The lifetime is what separates them, and separating them is the
/// whole diagnosis for a bootstrap dial that taught us nothing.
#[test]
fn a_session_says_how_long_it_lived() {
    let src = production_source(include_str!("../../outbound_connector.rs"));
    assert!(
        src.contains("\"session.ended\""),
        "the session lifetime is unrecorded again"
    );
    assert!(
        src.contains("lived_ms="),
        "session.ended no longer carries the one field it exists for"
    );
}

/// report21 V20-M7a: a failed dial retires ITS OWN placeholder and
/// nothing else.
///
/// The lock that claims the slot is let go before the dial. The other
/// meeting-point pass can take the same address in that window, complete
/// a handshake and write a proven row into the same id — and the rollback
/// removed the row by id regardless, deleting a peer somebody is talking
/// to on the strength of a dial that was ours.
#[test]
fn a_failed_dial_retires_only_the_row_it_minted() {
    let transport = "obfs4-tcp://198.51.100.7:5556";
    let placeholder = veil_cfg::NodeId::from(*blake3::hash(transport.as_bytes()).as_bytes());
    let mine = PeerConfigEntry {
        peer_id: PeerId::new(0x9200_0000),
        node_id: placeholder,
        public_key: String::new(),
        nonce: String::new(),
        transport: transport.to_owned(),
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        bootstrap_only: true,
        source: crate::types::PeerSource::Rendezvous,
    };

    assert!(
        rendezvous_row_is_our_placeholder(Some(&mine), &placeholder, transport),
        "vacuity: the row this dial minted must be retirable, or a failed \
         dial leaves a slot claimed forever"
    );

    // The other pass got there first and proved who is at that address.
    let mut proven = mine.clone();
    proven.node_id = veil_cfg::NodeId::from([0xAB; 32]);
    proven.public_key = "their-key".to_owned();
    proven.bootstrap_only = false;
    assert!(
        !rendezvous_row_is_our_placeholder(Some(&proven), &placeholder, transport),
        "a proven row written by the other pass was deleted by our failure"
    );

    // A key alone is enough: a row that learned an identity is not ours.
    let mut keyed = mine.clone();
    keyed.public_key = "their-key".to_owned();
    assert!(!rendezvous_row_is_our_placeholder(
        Some(&keyed),
        &placeholder,
        transport
    ));

    // The slot was reclaimed for a DIFFERENT address while we waited.
    let mut elsewhere = mine.clone();
    elsewhere.transport = "obfs4-tcp://203.12.31.146:5556".to_owned();
    elsewhere.node_id =
        veil_cfg::NodeId::from(*blake3::hash(elsewhere.transport.as_bytes()).as_bytes());
    assert!(
        !rendezvous_row_is_our_placeholder(Some(&elsewhere), &placeholder, transport),
        "another pass's claim on this slot was retired by our failure"
    );

    // And a slot already empty has nothing to retire.
    assert!(!rendezvous_row_is_our_placeholder(
        None,
        &placeholder,
        transport
    ));
}

#[test]
fn a_rendezvous_address_keeps_its_slot_across_passes() {
    use crate::types::synthetic_peer_id::{RENDEZVOUS_BASE, RENDEZVOUS_WINDOW};

    fn rz(id: u32, transport: &str) -> PeerConfigEntry {
        PeerConfigEntry {
            peer_id: PeerId::new(id),
            node_id: veil_cfg::NodeId::from([id as u8; 32]),
            public_key: "k".to_owned(),
            nonce: "n".to_owned(),
            transport: transport.to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: false,
            source: crate::types::PeerSource::Rendezvous,
        }
    }

    // THE defect. The slot was `BASE + taken`, and `taken` restarted every
    // pass: whoever was dialled first took `BASE + 0` and overwrote the
    // row of whoever held it. The overwritten peer's connector then found
    // no row for its node_id, exited, and dropped a live session -- two
    // seeds rebuilt their link every few seconds because of it.
    let a = "obfs4-tcp://198.51.100.7:5556";
    let b = "obfs4-tcp://198.51.100.8:5556";
    let first = rendezvous_slot_for(&[], a).expect("an empty table has room");
    let known = vec![rz(first.get(), a)];
    assert_eq!(
        rendezvous_slot_for(&known, a),
        Some(first),
        "the same address took a different slot on a later pass; the row it \
         overwrites belongs to a peer whose session then dies"
    );
    assert_ne!(
        rendezvous_slot_for(&known, b),
        Some(first),
        "a second address was handed the slot the first one is using"
    );

    // The scheme is ours to choose and must not decide identity.
    assert_eq!(
        rendezvous_slot_for(&known, "tcp://198.51.100.7:5556"),
        Some(first)
    );
    // A neighbour that merely looks similar is a different peer.
    for near in [
        "obfs4-tcp://198.51.100.70:5556",
        "obfs4-tcp://198.51.100.7:55560",
    ] {
        assert_ne!(
            rendezvous_slot_for(&known, near),
            Some(first),
            "{near} was given the slot of 198.51.100.7:5556"
        );
    }

    // A row OUTSIDE the window belongs to another allocator and must not
    // be reused, however well its address matches. (That it also does not
    // occupy a slot is true by construction rather than by this check --
    // it cannot fall inside the range being scanned.)
    let foreign = vec![rz(0xD100_0000, a)];
    let fresh = rendezvous_slot_for(&foreign, a).expect("room");
    assert!(
        (RENDEZVOUS_BASE..RENDEZVOUS_BASE + RENDEZVOUS_WINDOW).contains(&fresh.get()),
        "allocated outside the rendezvous window"
    );

    // A full window REFUSES rather than evicting a peer we may be talking
    // to -- the whole failure being fixed here is an overwrite.
    let full: Vec<PeerConfigEntry> = (0..RENDEZVOUS_WINDOW)
        .map(|i| {
            rz(
                RENDEZVOUS_BASE + i,
                &format!("obfs4-tcp://198.51.100.7:{}", 6000 + i),
            )
        })
        .collect();
    assert_eq!(
        rendezvous_slot_for(&full, "obfs4-tcp://203.0.113.9:5556"),
        None,
        "a full window handed out a slot that is in use"
    );
    // ...but an address already in a full window still finds its own row.
    assert_eq!(
        rendezvous_slot_for(&full, "obfs4-tcp://198.51.100.7:6000"),
        Some(PeerId::new(RENDEZVOUS_BASE))
    );

    // A full window of rows that never learned an identity is a different
    // matter: those are refused duplicates, kept only so the address is not
    // dialled again. Enough aliases for one host would otherwise wall the
    // window off for the life of the process, so the lowest one yields.
    let tombstones: Vec<PeerConfigEntry> = (0..RENDEZVOUS_WINDOW)
        .map(|i| {
            let mut r = rz(
                RENDEZVOUS_BASE + i,
                &format!("obfs4-tcp://198.51.100.7:{}", 6000 + i),
            );
            r.public_key = String::new();
            r
        })
        .collect();
    assert_eq!(
        rendezvous_slot_for(&tombstones, "obfs4-tcp://203.0.113.9:5556"),
        Some(PeerId::new(RENDEZVOUS_BASE)),
        "a window full of identity-less rows refused a new peer forever"
    );
    // A single row WITH an identity is never the one taken: something
    // completed a handshake with it and may be holding that session.
    let mut mixed = tombstones.clone();
    mixed[0] = rz(RENDEZVOUS_BASE, "obfs4-tcp://198.51.100.7:6000");
    assert_eq!(
        rendezvous_slot_for(&mixed, "obfs4-tcp://203.0.113.9:5556"),
        Some(PeerId::new(RENDEZVOUS_BASE + 1)),
        "a row that had proved an identity was reclaimed"
    );

    // Something unparseable gets nothing rather than slot zero.
    assert_eq!(rendezvous_slot_for(&[], "no-scheme-here"), None);

    // AND THE CALLER HAS TO KNOW WHICH OF THE THREE IT GOT. The number
    // alone reads a reclaimed slot as an occupied one, so the row keeps
    // the previous tenant's address, the dial goes to a URI nobody asked
    // for, and whoever answers THAT is written down beside the address we
    // meant to call (report21 V20-M7b).
    assert_eq!(
        rendezvous_slot_claim(&known, a),
        Some(RendezvousSlot::Held(first)),
        "a row already holding this address must be dialled as it stands"
    );
    assert!(
        matches!(
            rendezvous_slot_claim(&known, b),
            Some(RendezvousSlot::Free(_))
        ),
        "a new address in a window with room takes a free slot"
    );
    assert_eq!(
        rendezvous_slot_claim(&tombstones, "obfs4-tcp://203.0.113.9:5556"),
        Some(RendezvousSlot::Reclaimed(PeerId::new(RENDEZVOUS_BASE))),
        "a slot taken from an identity-less row is indistinguishable from \
         one that already held this address"
    );
    assert_eq!(
        rendezvous_slot_claim(&full, "obfs4-tcp://203.0.113.9:5556"),
        None
    );
}

#[test]
fn an_address_a_stranger_named_is_not_dialled_into_this_network() {
    // A meeting point is an open index. The address in a record is
    // whatever its author wrote, and a DHT node answers with whatever it
    // likes, so without this a stranger could aim this host's dial at
    // loopback, at the machine next to it, or at a cloud metadata
    // endpoint. The handshake fails either way -- but which ports answered
    // is the answer they were after, and our host did the probing.
    for private in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.54",
        "172.16.0.1",
        "169.254.169.254", // the cloud metadata address
        "100.64.0.1",      // carrier NAT
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "203.0.113.9", // documentation range
        "::1",
        "[fe80::1]",
        "[fc00::1]",
        "veil.example.com", // a NAME resolves later, and could resolve anywhere
        // The SAME addresses written in the other notation. A v4 address
        // wearing a v6 coat is a v4 address, and none of the v6 rules look
        // at the octets it carries — so every one of the refusals above
        // could be had simply by spelling it this way (report21 V20-M1a).
        "[::ffff:127.0.0.1]",
        "[::ffff:10.1.2.3]",
        "[::ffff:192.168.1.54]",
        "[::ffff:169.254.169.254]",
        "[::ffff:100.64.0.1]",
        "[::ffff:0.0.0.0]",
        "[::ffff:224.0.0.1]",
        // ::a.b.c.d, the deprecated compatible form, carries the same
        // address without the ffff to key off.
        "[::127.0.0.1]",
        "[::10.1.2.3]",
        // Documentation and NAT64: neither is a host on this internet.
        "[2001:db8::1]",
        "[64:ff9b::7f00:1]",
    ] {
        assert!(
            !rendezvous_destination_is_dialable(private),
            "{private} was accepted from a public meeting point"
        );
    }

    // ...and a real public address still is, or the layer finds nobody.
    for public in [
        "8.8.8.8",
        "203.12.31.146",
        "1.1.1.1",
        "[2001:4860:4860::8888]",
        // A mapped PUBLIC address is still public: the normalisation must
        // not refuse everything it touches.
        "[::ffff:8.8.8.8]",
        "[::ffff:203.12.31.146]",
    ] {
        assert!(
            rendezvous_destination_is_dialable(public),
            "{public} is a public address and was refused"
        );
    }
}

#[test]
fn a_node_does_not_dial_its_own_announcement() {
    // Found live, on layer 8's first real run: the node announced itself,
    // read its own record back on the same pass, dialled its own listener
    // and sat out the full ten-second handshake timeout -- then logged the
    // result as a peer that could not be reached. Every fifteen minutes,
    // for as long as the node runs.
    let me = ("203.0.113.9".to_owned(), 5556);
    assert!(rendezvous_address_is_self(
        Some(&me),
        "obfs4://203.0.113.9:5556"
    ));
    // The scheme is ours to choose, so it must not decide this.
    assert!(rendezvous_address_is_self(
        Some(&me),
        "tcp://203.0.113.9:5556"
    ));
    assert!(rendezvous_address_is_self(
        Some(&me),
        "ws://203.0.113.9:5556/veil"
    ));

    // A different port on the same host is a different node -- two nodes
    // behind one address is an ordinary way to run them.
    assert!(!rendezvous_address_is_self(
        Some(&me),
        "obfs4://203.0.113.9:5557"
    ));
    assert!(!rendezvous_address_is_self(
        Some(&me),
        "obfs4://203.0.113.8:5556"
    ));
    // A host that merely CONTAINS ours, or is contained by it, is not
    // ours -- in both directions, because a prefix test reads as correct
    // and is wrong on one side each way. `.90` and `.9` are neighbours on
    // a real subnet, and mistaking one for this node makes it invisible.
    for near in [
        "obfs4://203.0.113.99:5556",
        "obfs4://1203.0.113.9:5556",
        "obfs4://203.0.113.9:55560",
    ] {
        assert!(
            !rendezvous_address_is_self(Some(&me), near),
            "{near} was mistaken for this node and skipped"
        );
    }
    let long = ("203.0.113.90".to_owned(), 5556);
    assert!(
        !rendezvous_address_is_self(Some(&long), "obfs4://203.0.113.9:5556"),
        "a neighbour whose address is a prefix of ours was skipped as us"
    );
    assert!(
        !rendezvous_address_is_self(Some(&me), "obfs4://203.0.113.90:5556"),
        "a neighbour whose address extends ours was skipped as us"
    );

    let v6 = ("2001:db8::1".to_owned(), 5556);
    assert!(rendezvous_address_is_self(
        Some(&v6),
        "obfs4://[2001:db8::1]:5556"
    ));

    // A node with no address of its own recognises nothing, rather than
    // everything: this must never become a filter that skips real peers.
    for any in [
        "obfs4://203.0.113.9:5556",
        "obfs4://198.51.100.1:5556",
        "nonsense",
    ] {
        assert!(!rendezvous_address_is_self(None, any));
    }
}

fn listener_seen_as(uri: &str, visibility: veil_cfg::Visibility) -> veil_cfg::ListenConfig {
    let mut l = listener(uri, None);
    l.visibility = visibility;
    l
}

#[test]
fn a_listener_the_operator_hid_is_not_offered_at_a_meeting_point() {
    use veil_cfg::Visibility;
    // `build_advertised_transports` states the contract: "Trusted and
    // Hidden listeners stay invisible on the network -- peers learn about
    // them only through invite-bundles." A meeting point is the most public
    // index there is. Stealth is not even bound at startup, so publishing
    // it would advertise a port that answers nobody.
    let (key, nonce) = identity_b64();
    for hidden in [Visibility::Trusted, Visibility::Hidden, Visibility::Stealth] {
        let mut c = veil_cfg::Config::default();
        c.listen = vec![listener_seen_as(
            "obfs4-tcp://203.0.113.9:5556",
            hidden.clone(),
        )];
        assert_eq!(
            public_address_for(&c, &[]),
            None,
            "a {hidden:?} listener was offered as this node's public address"
        );
        assert!(
            lan_announce_for(&c, &key, &nonce, &[]).is_none(),
            "a {hidden:?} listener was announced on the local network"
        );
    }

    // Public still works, or the gate would silence every layer.
    let mut c = veil_cfg::Config::default();
    c.listen = vec![listener_seen_as(
        "obfs4-tcp://203.0.113.9:5556",
        Visibility::Public,
    )];
    assert_eq!(
        public_address_for(&c, &[]),
        Some(("203.0.113.9".to_owned(), 5556))
    );
    assert!(lan_announce_for(&c, &key, &nonce, &[]).is_some());

    // A hidden listener does not veto a public one standing behind it.
    let mut c = veil_cfg::Config::default();
    c.listen = vec![
        listener_seen_as("obfs4-tcp://198.51.100.1:5556", Visibility::Hidden),
        listener_seen_as("obfs4-tcp://203.0.113.9:5557", Visibility::Public),
    ];
    assert_eq!(
        public_address_for(&c, &[]),
        Some(("203.0.113.9".to_owned(), 5557)),
        "the hidden listener hid the public one behind it"
    );
}

#[test]
fn a_node_never_publishes_an_address_that_is_true_only_where_it_stands() {
    // Layers 6 and 7 observe the host from the packet. A relay does not
    // tell us ours and must not be asked to, so this is the one place the
    // node claims its own address -- and a claim of `0.0.0.0` would list
    // it at a rendezvous while being unreachable from every one of them,
    // which reads in the log exactly like a node that is listed and fine.
    for bad in [
        "obfs4://0.0.0.0:5556",
        "obfs4://127.0.0.1:5556",
        "obfs4://localhost:5556",
        "obfs4://[::]:5556",
        "obfs4://[::1]:5556",
        "obfs4://1.2.3.4:0",
        "obfs4://:5556",
        "not-a-uri",
    ] {
        assert_eq!(
            address_for_listeners(&[(bad, None)]),
            None,
            "{bad} was offered to strangers as this node's address"
        );
    }

    assert_eq!(
        address_for_listeners(&[("obfs4://203.0.113.9:5556", None)]),
        Some(("203.0.113.9".to_owned(), 5556)),
        "a listener with a real address was not usable"
    );
    // `advertise` wins: the bind address is where the socket is, the
    // advertised one is where the world can reach it, and behind NAT they
    // are not the same string.
    assert_eq!(
        address_for_listeners(&[("obfs4://0.0.0.0:5556", Some("obfs4://203.0.113.9:443"))]),
        Some(("203.0.113.9".to_owned(), 443)),
        "the bind address was published instead of the advertised one"
    );
    // An unusable listener does not veto a usable one behind it -- and
    // once per REASON it can be unusable, because "skip" and "give up" are
    // one keyword apart and each branch has its own.
    for first in [
        "obfs4://0.0.0.0:5556",
        "obfs4://127.0.0.1:5556",
        "obfs4://203.0.113.7:0",
        "obfs4://:5556",
        "obfs4://203.0.113.7:not-a-port",
        "no-scheme-here",
    ] {
        assert_eq!(
            address_for_listeners(&[(first, None), ("obfs4://203.0.113.9:5556", None)]),
            Some(("203.0.113.9".to_owned(), 5556)),
            "a listener of {first} hid the usable one after it"
        );
    }
    // Paths and IPv6 brackets both survive the split.
    assert_eq!(
        address_for_listeners(&[("ws://203.0.113.9:8080/veil", None)]),
        Some(("203.0.113.9".to_owned(), 8080))
    );
    assert_eq!(
        address_for_listeners(&[("obfs4://[2001:db8::1]:5556", None)]),
        Some(("2001:db8::1".to_owned(), 5556))
    );
}

/// A hundred rounds of announce-and-evict must leave nothing behind.
///
/// The cap counted SLOTS, and reclaiming one deleted only the local
/// bookkeeping. The row, the DHT contact and the reconnect task the
/// admission had created all stayed, and the next eight announces reused
/// the same fixed slots — so an attacker on the broadcast domain added up
/// to eight more of each every five minutes, without bound, for the life
/// of the process (report22 V-02).
#[test]
fn a_hundred_lan_rounds_leave_no_rows_or_contacts() {
    use crate::types::PeerId;
    let mut peers: std::collections::BTreeMap<PeerId, PeerConfigEntry> = Default::default();
    let mut contacts: std::collections::HashSet<[u8; 32]> = Default::default();
    // Every eviction gives the connector claim back too, synchronously —
    // the abort alone gives it back at some later poll, and a re-admission
    // before then finds the slot held by a task that is dying
    // (report24 RUNTIME-2).
    let mut released: Vec<[u8; 32]> = Vec::new();

    for round in 0..100u32 {
        let mut admitted = Vec::new();
        for slot in 0..MAX_LAN_PEERS as u32 {
            let node_id = [(round as u8).wrapping_add((slot as u8).wrapping_mul(37)); 32];
            let peer_id = PeerId::new(0x9000_0000u32.wrapping_add(slot));
            let mut entry = lan_entry(node_id);
            entry.peer_id = peer_id;
            peers.insert(peer_id, entry);
            contacts.insert(node_id);
            admitted.push(LanCandidate {
                node_id,
                slot,
                admitted: std::time::Instant::now(),
                peer_id,
                abort: None,
            });
        }
        assert_eq!(
            peers.len(),
            MAX_LAN_PEERS,
            "round {round}: the admissions themselves are already over the cap"
        );
        for candidate in admitted {
            evict_lan_candidate(
                &mut peers,
                candidate,
                |id| {
                    contacts.remove(id);
                },
                |id| {
                    released.push(*id);
                },
            );
        }
        assert!(
            peers.is_empty(),
            "round {round}: {} row(s) survived their eviction",
            peers.len()
        );
        assert_eq!(
            released.len(),
            MAX_LAN_PEERS,
            "round {round}: {} of the evicted connector claims were left \
             for the aborted task to give back",
            released.len(),
        );
        released.clear();
        assert!(
            contacts.is_empty(),
            "round {round}: {} contact(s) survived their eviction",
            contacts.len()
        );
    }
}

/// The slot is local and gets reused, so eviction must check the OCCUPANT.
#[test]
fn eviction_leaves_a_row_that_is_no_longer_ours() {
    use crate::types::PeerId;
    let peer_id = PeerId::new(0x9000_0000);
    let mine = [7u8; 32];
    let someone_else = [9u8; 32];

    let mut peers: std::collections::BTreeMap<PeerId, PeerConfigEntry> = Default::default();
    let mut entry = lan_entry(someone_else);
    entry.peer_id = peer_id;
    peers.insert(peer_id, entry);

    let mut dropped = Vec::new();
    evict_lan_candidate(
        &mut peers,
        LanCandidate {
            node_id: mine,
            slot: 0,
            admitted: std::time::Instant::now(),
            peer_id,
            abort: None,
        },
        |id| dropped.push(*id),
        |_| {},
    );
    assert!(
        peers.contains_key(&peer_id),
        "a stale eviction deleted the row that had already replaced it"
    );
    assert_eq!(
        dropped,
        vec![mine],
        "the contact removed must be the evicted candidate's own"
    );

    // Vacuity: the same shape where the row IS ours does get removed, or
    // the assertion above would hold over a function that removes nothing.
    let mut ours = lan_entry(mine);
    ours.peer_id = peer_id;
    peers.insert(peer_id, ours);
    evict_lan_candidate(
        &mut peers,
        LanCandidate {
            node_id: mine,
            slot: 0,
            admitted: std::time::Instant::now(),
            peer_id,
            abort: None,
        },
        |_| {},
        |_| {},
    );
    assert!(peers.is_empty());
}

/// A row a LAN admission would write, with only the fields these rules read.
fn lan_entry(node_id: [u8; 32]) -> PeerConfigEntry {
    let hex = veil_util::hex_str(&node_id);
    PeerConfigEntry {
        peer_id: crate::types::PeerId::new(0),
        node_id: <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex).unwrap(),
        public_key: String::new(),
        nonce: String::new(),
        transport: String::new(),
        algo: Default::default(),
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        bootstrap_only: true,
        source: crate::types::PeerSource::Lan,
    }
}

/// A candidate with no history: `admit_lan_peer` only counts and dedups.
fn lan_slot(slot: u32) -> LanCandidate {
    LanCandidate {
        node_id: [slot as u8; 32],
        slot,
        admitted: std::time::Instant::now(),
        peer_id: crate::types::PeerId::new(0),
        abort: None,
    }
}

/// report21 V20-M3b: what this node publishes about itself is a public
/// address, written so a stranger can read it back.
///
/// Two halves. The helper refused only "unspecified or loopback", so a
/// node whose listener sits on `192.168.1.5` posted that to seven public
/// relays — a record nobody can use, and this network's shape written down
/// where anyone can read it. And the helper strips the brackets from a v6
/// literal, so `{host}:{port}` produced `2001:db8::1:5556`, whose last
/// colon belongs to the address: every receiver split it in the wrong
/// place.
#[test]
fn what_we_publish_about_ourselves_is_public_and_unambiguous() {
    let listener = |uri: &str| veil_cfg::Config {
        listen: vec![veil_cfg::ListenConfig {
            transport: uri.to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    };

    for inside in [
        "obfs4://192.168.1.5:5556",
        "obfs4://10.0.0.4:5556",
        "obfs4://172.16.9.9:5556",
        "obfs4://169.254.169.254:5556",
        "obfs4://100.64.0.1:5556",
        "obfs4://[fe80::1]:5556",
        "obfs4://[fc00::1]:5556",
        "obfs4://[::ffff:192.168.1.5]:5556",
        "obfs4://localhost:5556",
    ] {
        assert_eq!(
            public_address_for(&listener(inside), &[]),
            None,
            "{inside} would have been published to the public relays"
        );
    }

    // Vacuity: a real public listener is still published, or the node
    // never announces itself anywhere.
    assert_eq!(
        public_address_for(&listener("obfs4://203.12.31.146:5556"), &[]),
        Some(("203.12.31.146".to_owned(), 5556))
    );

    // The helper hands back a BARE v6 host, which is why the publisher has
    // to put the brackets back rather than interpolating.
    let (host, port) = public_address_for(&listener("obfs4://[2001:4860::1]:5556"), &[])
        .expect("a public v6 listener is publishable");
    assert_eq!(host, "2001:4860::1", "premise: the brackets are stripped");
    let published = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => std::net::SocketAddr::new(ip, port).to_string(),
        Err(_) => format!("{host}:{port}"),
    };
    assert_eq!(
        published, "[2001:4860::1]:5556",
        "the published record is ambiguous: its last colon is part of the \
         address, so a receiver splits it in the wrong place"
    );
    // And a receiver reading it back finds the address that was meant.
    let (h, p) = published.rsplit_once(':').expect("a record splits");
    assert_eq!(p, "5556");
    assert!(rendezvous_destination_is_dialable(h), "unreadable by us");
}

/// report20 V20-M3: what gets published is the port the listener BOUND.
///
/// Both publishers read the config. A listener configured on port 0 asks
/// the OS to choose, so there was no port in the config to publish and the
/// node advertised itself nowhere; an ephemeral listener rotates and the
/// config goes on naming the port it started on, so every meeting point
/// held a dead one.
#[test]
fn the_port_we_publish_is_the_port_we_bound() {
    let mut c = veil_cfg::Config::default();
    c.listen = vec![veil_cfg::ListenConfig {
        transport: "obfs4://203.0.113.7:0".to_owned(),
        ..Default::default()
    }];
    assert_eq!(
        public_address_for(&c, &[]),
        None,
        "premise: with nothing bound there is no port to publish"
    );

    let bound = vec![("obfs4://203.0.113.7:0".to_owned(), 41337u16)];
    assert_eq!(
        public_address_for(&c, &bound),
        Some(("203.0.113.7".to_owned(), 41337)),
        "an OS-chosen port was never published, so the node advertised \
         itself at no meeting point at all"
    );

    // A rotated listener: the config still names the first port.
    c.listen[0].transport = "obfs4://203.0.113.7:5556".to_owned();
    let rotated = vec![("obfs4://203.0.113.7:5556".to_owned(), 47001u16)];
    assert_eq!(
        public_address_for(&c, &rotated),
        Some(("203.0.113.7".to_owned(), 47001)),
        "the config port was published over the one the listener rotated to"
    );

    // An operator's `advertise` is a claim about the outside world — a
    // published port behind a proxy has nothing to do with the bound one.
    c.listen[0].advertise = Some("obfs4://example.test:443".to_owned());
    assert_eq!(
        public_address_for(&c, &rotated),
        Some(("example.test".to_owned(), 443)),
        "a bound port overrode the address the operator stated"
    );
}

/// What is published follows the listener, pass by pass.
///
/// `bound_ports` reading the listener table instead of the config fixed the
/// startup case — an OS-chosen port was published as zero. Rotation is the
/// same question later: the discovery tasks computed the announcement once,
/// before their loop, so a listener that took a new port left them naming
/// the old one for the life of the process, and it closes when the old
/// listener's grace ends (report24 RUNTIME-3).
#[test]
fn the_announcement_follows_a_listener_that_rotates() {
    use std::sync::{Arc, Mutex};

    let mut c = veil_cfg::Config::default();
    c.listen = vec![veil_cfg::ListenConfig {
        transport: "obfs4-tcp://203.0.113.7:0".to_owned(),
        ..Default::default()
    }];
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x11u8; 32]);
    let nonce = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8, 1, 2, 3]);

    let listen = |addr: &str| crate::types::ListenConfigEntry {
        listen_id: crate::types::ListenId::new(1),
        listener_handle: None,
        transport: "obfs4-tcp://203.0.113.7:0".to_owned(),
        advertise: None,
        relay: None,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        psk_file: None,
        visibility: veil_cfg::Visibility::Public,
        allowlist_node_ids: vec![],
        group_label: None,
        ephemeral: None,
        on_demand: None,
        local_addr: Some(addr.to_owned()),
        active: true,
    };

    let state = Arc::new(Mutex::new(crate::state::NodeState::new(
        veil_cfg::NodeId::from([0xAAu8; 32]),
        crate::types::NodeRole::Core,
        std::path::PathBuf::from("/nonexistent/veil.toml"),
        true,
        std::time::Instant::now(),
        false,
        None,
        vec![],
        vec![listen("obfs4-tcp://203.0.113.7:41337")],
    )));

    let (announce, address) = current_announcement(&state, &c, &key, &nonce);
    assert_eq!(
        address,
        Some(("203.0.113.7".to_owned(), 41337)),
        "premise: the bound port is what is published"
    );
    assert_eq!(announce.map(|a| a.port), Some(41337));

    // The listener rotates: same entry, new bound address.
    {
        let mut st = crate::runtime::lock_state(&state);
        for entry in st.listens.values_mut() {
            entry.local_addr = Some("obfs4-tcp://203.0.113.7:47001".to_owned());
        }
    }

    let (announce, address) = current_announcement(&state, &c, &key, &nonce);
    assert_eq!(
        address,
        Some(("203.0.113.7".to_owned(), 47001)),
        "the address still names the port the listener left behind"
    );
    assert_eq!(
        announce.map(|a| a.port),
        Some(47001),
        "the LAN announcement still names the port the listener left behind"
    );
}

/// The short id in a log line is SIXTEEN characters, in both places that
/// write one.
///
/// Two identical implementations stood here and in `builtin::mailbox`,
/// each formatting a byte at a time. They are one call now — and the
/// obvious shared helper is the wrong one: `veil_util::hex_short` takes
/// FOUR bytes, so reaching for it by name would have halved every id in
/// these logs without a single test noticing (report24, dead-code table).
#[test]
fn the_short_id_is_sixteen_characters_in_both_writers() {
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = i as u8;
    }
    let here = hex_short(&id);
    assert_eq!(here, "0001020304050607", "the short id changed shape");
    assert_eq!(here.len(), 16);
    assert_eq!(
        here,
        crate::builtin::mailbox::hex_short(&id),
        "the two log writers no longer print the same id",
    );
    assert_ne!(
        here,
        veil_util::hex_short(&id),
        "the four-byte helper was substituted for the eight-byte one",
    );
}

/// And the bound ports come only from listeners that are actually bound.
#[test]
fn only_a_bound_listener_offers_a_port() {
    let entry =
        |transport: &str, addr: Option<&str>, active: bool| crate::types::ListenConfigEntry {
            listen_id: crate::types::ListenId::new(1),
            listener_handle: None,
            transport: transport.to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            psk_file: None,
            visibility: veil_cfg::Visibility::Public,
            allowlist_node_ids: vec![],
            group_label: None,
            ephemeral: None,
            on_demand: None,
            local_addr: addr.map(str::to_owned),
            active,
        };
    let listens = vec![
        entry("obfs4://0.0.0.0:0", Some("obfs4://0.0.0.0:41337"), true),
        // Not bound: its address is whatever it was last time, and that is
        // worse than the config.
        entry("tcp://0.0.0.0:0", Some("tcp://0.0.0.0:5000"), false),
        // Bound but with no address recorded, and a port of zero says
        // nothing.
        entry("ws://0.0.0.0:0", None, true),
        entry("wss://0.0.0.0:0", Some("wss://0.0.0.0:0"), true),
    ];
    assert_eq!(
        bound_ports(&listens),
        vec![("obfs4://0.0.0.0:0".to_owned(), 41337u16)],
        "a listener that is not bound, or has no address, offered a port"
    );
}

#[test]
fn a_talkative_neighbour_cannot_grow_this_nodes_memory_without_bound() {
    // The defect this closes was mine: the announcer was recorded BEFORE
    // the ceiling was checked, so somebody rotating keys on the segment
    // grew the set forever while none of those peers was ever attached.
    // The set is what the cap has to bound, not the attach count.
    let mut taken: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    for i in 0..1000 {
        let key = format!("neighbour-{i}");
        if admit_lan_peer(&key, "ME", &taken) {
            let slot = free_lan_slot(&taken).expect("a slot the admit just allowed");
            taken.insert(key, lan_slot(slot));
        }
    }
    assert_eq!(
        taken.len(),
        MAX_LAN_PEERS,
        "the set a LAN can grow is not bounded by the cap"
    );
}

/// report20 V20-M2: eight announces must not close local discovery for
/// the rest of the run.
///
/// The cap counted ANNOUNCEMENTS, and an announcement costs a datagram.
/// Anybody on the segment could send eight naming eight keys, fill every
/// slot before a handshake, and the real neighbour that announced ninth
/// was ignored until the node restarted.
#[test]
fn announces_that_never_connect_give_their_slots_back() {
    let t0 = std::time::Instant::now();
    let mut taken: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    for i in 0..MAX_LAN_PEERS as u32 {
        let key = format!("flood-{i}");
        assert!(admit_lan_peer(&key, "ME", &taken));
        taken.insert(
            key,
            LanCandidate {
                node_id: [i as u8; 32],
                slot: free_lan_slot(&taken).expect("a free slot below the cap"),
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
    }
    assert!(
        !admit_lan_peer("the-real-neighbour", "ME", &taken),
        "premise: the cap is full, so a real neighbour is refused"
    );

    // Nothing connected. One grace later every slot is a claim, not a peer.
    let connected = std::collections::HashSet::new();
    let stale = stale_lan_candidates(
        &taken,
        &connected,
        LAN_CANDIDATE_GRACE,
        t0 + LAN_CANDIDATE_GRACE,
    );
    assert_eq!(
        stale.len(),
        MAX_LAN_PEERS,
        "a flood that never connected still holds the cap: local \
         discovery stays closed for the life of the process"
    );
    for key in stale {
        taken.remove(&key);
    }
    assert!(
        admit_lan_peer("the-real-neighbour", "ME", &taken),
        "the reclaimed slots did not let a real neighbour in"
    );

    // Before the grace nothing is reclaimed — a slot is not taken away
    // from an announce that simply has not finished connecting yet.
    let mut fresh: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    fresh.insert(
        "dialling".to_owned(),
        LanCandidate {
            node_id: [42; 32],
            slot: 0,
            admitted: t0,
            peer_id: crate::types::PeerId::new(0),
            abort: None,
        },
    );
    assert!(
        stale_lan_candidates(
            &fresh,
            &connected,
            LAN_CANDIDATE_GRACE,
            t0 + LAN_CANDIDATE_GRACE - std::time::Duration::from_secs(1),
        )
        .is_empty(),
        "a slot was taken from an announce still inside its grace"
    );
}

/// And a CONNECTED neighbour keeps its slot however long it holds it.
/// The cap is on how many LAN peers this node takes; one it is talking to
/// is one of them, and reclaiming its slot would hand the peer table to
/// whoever announces next.
#[test]
fn a_connected_neighbour_never_loses_its_slot() {
    let t0 = std::time::Instant::now();
    let mut taken: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    taken.insert(
        "live".to_owned(),
        LanCandidate {
            node_id: [1; 32],
            slot: 0,
            admitted: t0,
            peer_id: crate::types::PeerId::new(0),
            abort: None,
        },
    );
    taken.insert(
        "silent".to_owned(),
        LanCandidate {
            node_id: [2; 32],
            slot: 1,
            admitted: t0,
            peer_id: crate::types::PeerId::new(0),
            abort: None,
        },
    );
    let connected: std::collections::HashSet<[u8; 32]> = [[1u8; 32]].into_iter().collect();
    assert_eq!(
        stale_lan_candidates(
            &taken,
            &connected,
            LAN_CANDIDATE_GRACE,
            t0 + LAN_CANDIDATE_GRACE * 100,
        ),
        vec!["silent".to_owned()],
        "the reclaim does not separate a peer we are talking to from one \
         that never answered"
    );
}

/// A reclaimed slot must not be handed out twice.
///
/// The peer id was `seen.len()`, which equals the free slot only while
/// nothing ever leaves. With reclamation the length repeats, and the same
/// peer id would overwrite a live neighbour's entry in the peer table.
#[test]
fn a_reclaimed_slot_is_reused_without_colliding_with_a_live_one() {
    let t0 = std::time::Instant::now();
    let mut taken: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    for (i, key) in ["a", "b", "c"].iter().enumerate() {
        taken.insert(
            (*key).to_owned(),
            LanCandidate {
                node_id: [i as u8; 32],
                slot: i as u32,
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
    }
    taken.remove("b"); // slot 1 goes back
    assert_eq!(
        free_lan_slot(&taken),
        Some(1),
        "the free slot is not the reclaimed one"
    );
    taken.insert(
        "d".to_owned(),
        LanCandidate {
            node_id: [9; 32],
            slot: 1,
            admitted: t0,
            peer_id: crate::types::PeerId::new(0),
            abort: None,
        },
    );
    let slots: std::collections::BTreeSet<u32> = taken.values().map(|c| c.slot).collect();
    assert_eq!(slots.len(), taken.len(), "two neighbours share a peer id");
    // And a full ledger offers nothing.
    let mut full: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    for i in 0..MAX_LAN_PEERS as u32 {
        full.insert(
            format!("n{i}"),
            LanCandidate {
                node_id: [i as u8; 32],
                slot: i,
                admitted: t0,
                peer_id: crate::types::PeerId::new(0),
                abort: None,
            },
        );
    }
    assert_eq!(
        free_lan_slot(&full),
        None,
        "a slot past the cap was offered"
    );
}

#[test]
fn we_do_not_take_ourselves_or_the_same_neighbour_twice() {
    let mut taken: std::collections::BTreeMap<String, LanCandidate> =
        std::collections::BTreeMap::new();
    assert!(
        !admit_lan_peer("ME", "ME", &taken),
        "a node took its own announce"
    );
    assert!(admit_lan_peer("THEM", "ME", &taken));
    taken.insert("THEM".to_owned(), lan_slot(0));
    assert!(
        !admit_lan_peer("THEM", "ME", &taken),
        "the same neighbour was taken twice, which spawns a second connector"
    );
    // Vacuity: with the ceiling not yet reached, a NEW key is still taken —
    // otherwise the two assertions above would pass on a function that
    // refuses everything.
    assert!(admit_lan_peer("SOMEBODY-ELSE", "ME", &taken));
}

#[test]
fn an_inbound_peer_is_recognised_by_identity_not_by_address() {
    // The half the first attempt missed. An inbound session reports OUR
    // listener as its transport, so address comparison alone learns
    // nothing from it -- and seeds meet each other inbound. The join is
    // the peer's node_id, which the session knows, against the
    // discovered-peer cache, which maps address to public key.
    use veil_bootstrap::DiscoveredPeerCache;
    use veil_cfg::{NodeId, SignatureAlgorithm};

    // A real key, so the id derives the way production derives it.
    let key = "fyU1fAlyHVNMat6NZBJ+KBU/aeJhCP+OBsomlgJ1Cjo=";
    let their_id =
        NodeId::from_public_key(SignatureAlgorithm::Ed25519, key).expect("a valid ed25519 key");

    let mut cache = DiscoveredPeerCache::in_memory();
    cache.upsert(
        veil_cfg::BootstrapPeer {
            transport: "obfs4-tcp://198.51.100.7:5556".to_owned(),
            public_key: key.to_owned(),
            nonce: "AOCZRA==".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        },
        1_700_000_000,
    );
    // A second entry, for a peer we are NOT talking to. Everything below
    // that says "still dialled" is about this one.
    cache.upsert(
        veil_cfg::BootstrapPeer {
            transport: "obfs4-tcp://198.51.100.9:5556".to_owned(),
            public_key: "VVxxLVptuXZ/qFV94aPP1daiz6ZYg2yf1JLbc1VHXhQ=".to_owned(),
            nonce: "AdW8kw==".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        },
        1_700_000_000,
    );

    // The session as an INBOUND one actually looks: our own listener, and
    // no useful address anywhere in it.
    let inbound = crate::types::SessionInfo {
        link_id: crate::types::LinkId::new(1),
        node_id: Some(their_id),
        nonce: None,
        matched_peer_id: None,
        source: crate::types::SessionSource::Inbound(crate::types::ListenId::new(2)),
        listener_handle: None,
        state: crate::types::SessionState::Active,
        transport: "obfs4-tcp://0.0.0.0:5556".to_owned(),
        remote_addr: None,
        description: String::new(),
    };
    let mut live = std::collections::BTreeMap::new();
    live.insert(inbound.link_id, inbound);
    let live = Arc::new(std::sync::Mutex::new(live));
    let cache = Arc::new(std::sync::Mutex::new(cache));

    let held = addresses_we_already_hold(&live, &cache);
    assert!(
        !rendezvous_address_is_new(&[], &held, "obfs4-tcp://198.51.100.7:5556"),
        "a peer we hold an INBOUND session with was dialled again; that is \
         the churn between two seeds, once per rendezvous pass"
    );

    // A cached address whose peer we are NOT in session with is still
    // dialled, or the cache would silence the layer for everybody it has
    // ever met. It has to be IN THE CACHE for this to test anything --
    // an address the cache never heard of proves nothing about the join.
    assert!(
        rendezvous_address_is_new(&[], &held, "obfs4-tcp://198.51.100.9:5556"),
        "an address we merely have in cache stopped being dialled"
    );

    // With no sessions at all the cache contributes nothing.
    let empty = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    assert!(rendezvous_address_is_new(
        &[],
        &addresses_we_already_hold(&empty, &cache),
        "obfs4-tcp://198.51.100.7:5556"
    ));
}

#[test]
fn a_peer_we_are_talking_to_is_not_dialled_again_when_its_row_is_gone() {
    // The peer TABLE is not the record of who we are talking to. A row
    // learned at a rendezvous lives in the autodiscovered range and gets
    // scored out between passes, so the next pass read "not known" about a
    // peer with an open session, dialled it, and the far side dedupped the
    // duplicate -- tearing down the session that was already working.
    // Two production seeds met each other again on every single round.
    let known: Vec<PeerConfigEntry> = vec![];
    let live = vec!["obfs4-tcp://198.51.100.7:5556".to_owned()];
    assert!(
        !rendezvous_address_is_new(&known, &live, "obfs4-tcp://198.51.100.7:5556"),
        "an address this node holds a session to was dialled again"
    );

    // The observed remote address is bare, and it has to compare too.
    let bare = vec!["198.51.100.7:5556".to_owned()];
    assert!(
        !rendezvous_address_is_new(&known, &bare, "obfs4-tcp://198.51.100.7:5556"),
        "the address a session actually came from did not count as ours"
    );

    // ...and this must not become a filter that silences the layer: a
    // different port, a different host, and an empty session list all
    // still dial.
    assert!(rendezvous_address_is_new(
        &known,
        &live,
        "obfs4-tcp://198.51.100.7:5557"
    ));
    assert!(rendezvous_address_is_new(
        &known,
        &live,
        "obfs4-tcp://203.0.113.9:5556"
    ));
    assert!(rendezvous_address_is_new(
        &known,
        &[],
        "obfs4-tcp://198.51.100.7:5556"
    ));
    // An address that merely CONTAINS ours, or is contained by it, is not
    // ours -- both directions, because a containment test reads as right
    // and is wrong on one side each way.
    for near in [
        "obfs4-tcp://198.51.100.70:5556",
        "obfs4-tcp://198.51.100.7:55560",
        "obfs4-tcp://8.198.51.100.7:5556",
    ] {
        let held = vec![near.to_owned()];
        assert!(
            rendezvous_address_is_new(&known, &held, "obfs4-tcp://198.51.100.7:5556"),
            "a session to {near} was mistaken for one to 198.51.100.7:5556"
        );
    }
    let held = vec!["obfs4-tcp://198.51.100.7:5556".to_owned()];
    assert!(
        rendezvous_address_is_new(&known, &held, "obfs4-tcp://198.51.100.7:55560"),
        "a session to :5556 was mistaken for one to :55560"
    );
}

#[test]
fn an_address_this_node_already_has_is_not_dialled_again() {
    // Measured, not imagined: a live host found all three announcing nodes
    // at the rendezvous, was already in session with every one of them
    // through PEX, dialled all three anyway, and logged three
    // "handshake timed out after 10s" — which reads like a network fault
    // and was a duplicate connection the far side dropped.
    let known = vec![
        row(
            crate::types::PeerSource::Exchanged,
            0xAA,
            "obfs4-tcp://198.51.100.7:5556",
        ),
        row(
            crate::types::PeerSource::Configured,
            0xBB,
            "tcp://198.51.100.8:5556",
        ),
    ];
    assert!(
        !rendezvous_address_is_new(&known, &[], "obfs4-tcp://198.51.100.7:5556"),
        "an address already held was treated as new"
    );
    // The AUTHORITY decides, not the whole URI: the same host reached over
    // a different transport is the same machine, and a second session to
    // it is the same duplicate.
    assert!(
        !rendezvous_address_is_new(&known, &[], "tcp://198.51.100.7:5556"),
        "the same host under another scheme was treated as new"
    );
    // A different port is a different node, and a genuinely new address is
    // still worth a dial — or the guard would silence the whole layer.
    assert!(rendezvous_address_is_new(
        &known,
        &[],
        "obfs4-tcp://198.51.100.7:5557"
    ));
    assert!(rendezvous_address_is_new(
        &known,
        &[],
        "obfs4-tcp://203.0.113.9:5556"
    ));
    assert!(
        rendezvous_address_is_new(&[], &[], "obfs4-tcp://203.0.113.9:5556"),
        "a node with no peers must dial what it finds"
    );
    // Something unparseable is not dialled rather than dialled blindly.
    assert!(!rendezvous_address_is_new(&known, &[], "no-scheme-here"));
}

#[test]
fn a_node_with_no_listener_still_knows_how_to_dial_what_it_found() {
    // The defect this closes was measured on a live host: it found three
    // addresses at the rendezvous and dialled none of them, because the
    // dial was gated on having something to ANNOUNCE. A client listens for
    // nobody -- that is the ordinary shape, not an edge case -- so the
    // gate made layer 7 useless to exactly the nodes it is for.
    let bare = veil_cfg::Config::default();
    assert_eq!(
        rendezvous_dial_scheme(&bare),
        "obfs4-tcp",
        "a node with nothing at all must still have a scheme to dial with"
    );

    // What the operator already named wins over the default: a network
    // running plain tcp must not be dialled with obfs4.
    let mut named = veil_cfg::Config::default();
    named.bootstrap_peers.push(veil_cfg::BootstrapPeer {
        transport: "tcp://198.51.100.4:5556".to_owned(),
        public_key: "K".to_owned(),
        nonce: "N".to_owned(),
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_ca_cert: None,
    });
    assert_eq!(rendezvous_dial_scheme(&named), "tcp");
}

/// WHAT THIS NODE LISTENS ON MUST NOT DECIDE HOW IT DIALS.
///
/// It used to, and it won over everything else — including a transport
/// the operator had named. A listener says what this node ACCEPTS; the
/// dial needs what the other end SERVES, and on a client those are chosen
/// by different people. The app gives every phone `quic://0.0.0.0:9000`
/// for its own inbound while every seed serves obfs4-tcp on 5556, so a
/// phone found all three seeds at the rendezvous, rewrote each address to
/// `quic://…:5556` and timed out against them forever. Measured on a
/// device: `nostr.looked … 3 record(s)`, then `peer.connect.attempt
/// transport=quic://…:5556`, then `connection timed out after 10s`, on a
/// loop.
///
/// A node that offered NOTHING fell through to obfs4-tcp and worked, so
/// having a listener was strictly worse than having none.
#[test]
fn a_quic_listener_does_not_make_this_node_dial_quic() {
    // The exact shape the app composes for a phone: a QUIC listener of
    // its own, and no peer anybody named.
    let mut phone = veil_cfg::Config::default();
    phone.listen.push(veil_cfg::ListenConfig {
        transport: "quic://0.0.0.0:9000".to_owned(),
        ..Default::default()
    });
    assert_eq!(
        rendezvous_dial_scheme(&phone),
        "obfs4-tcp",
        "a phone rewrote every seed address to its own listener's scheme \
         and timed out against all of them"
    );

    // And the operator's own answer still wins over the default, which is
    // the case the local listener used to override.
    let mut named = phone.clone();
    named.bootstrap_peers.push(veil_cfg::BootstrapPeer {
        transport: "tcp://198.51.100.4:5556".to_owned(),
        public_key: "K".to_owned(),
        nonce: "N".to_owned(),
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_ca_cert: None,
    });
    assert_eq!(
        rendezvous_dial_scheme(&named),
        "tcp",
        "a network the operator said runs plain tcp was dialled otherwise"
    );
}

#[test]
fn each_layer_runs_exactly_when_its_meeting_point_is_named() {
    // One setting decides both layers now, and the mapping is the whole of
    // it: a config that names one point must not start the other.
    use veil_cfg::{MeetingPoint as P, MeetingPoints as M, MeetingPointsPreset as Pre};

    let all = M::default();
    for point in P::ALL {
        assert!(all.includes(*point), "`all` does not run {point:?}");
    }

    let off = M::Preset(Pre::Off);
    for point in P::ALL {
        assert!(!off.includes(*point), "`off` runs {point:?}");
    }

    // Named subsets, walked over every point so a third one added later
    // has to be decided rather than inherited.
    for point in P::ALL {
        let only = M::Only(vec![*point]);
        for other in P::ALL {
            assert_eq!(
                only.includes(*other),
                other == point,
                "naming {point:?} alone got {other:?} wrong"
            );
        }
    }
}

#[test]
fn what_we_tell_the_lan_is_a_listener_a_neighbour_could_actually_dial() {
    let a = announce_for_listeners(vec![listener("obfs4-tcp://0.0.0.0:5556", None)])
        .expect("a bound listener should be announceable");
    assert_eq!(a.port, 5556);
    assert_eq!(a.scheme, veil_bootstrap::LanScheme::Obfs4Tcp);

    // A path after the authority is not part of the port.
    let ws = announce_for_listeners(vec![listener("ws://192.168.1.5:7001/veil", None)])
        .expect("a ws listener should be announceable");
    assert_eq!(ws.port, 7001);
    assert_eq!(ws.scheme, veil_bootstrap::LanScheme::Ws);
}

#[test]
fn a_loopback_listener_is_not_offered_to_the_wire() {
    // A neighbour dialling 127.0.0.1 reaches its own machine. Announcing
    // it costs somebody else a failed dial and tells them nothing.
    assert!(
        announce_for_listeners(vec![listener("tcp://127.0.0.1:5556", None)]).is_none(),
        "a loopback-only listener was announced"
    );
    // Unless the operator said otherwise: `advertise` exists for exactly
    // the case where the bind address and the reachable one differ.
    let a = announce_for_listeners(vec![listener(
        "tcp://127.0.0.1:5556",
        Some("tcp://192.168.1.5:443"),
    )])
    .expect("an advertised address should win over the bind address");
    assert_eq!(a.port, 443, "the advertised port was ignored");
}

#[test]
fn a_node_with_nothing_dialable_says_nothing() {
    assert!(announce_for_listeners(Vec::new()).is_none(), "no listeners");
    assert!(
        announce_for_listeners(vec![listener("memory://whatever:1", None)]).is_none(),
        "a transport the wire format cannot name was announced anyway"
    );
    assert!(
        announce_for_listeners(vec![listener("tcp://0.0.0.0:0", None)]).is_none(),
        "port 0 is what the kernel assigns, not what a neighbour dials"
    );
    // A bad identity is not announceable either, and must not panic.
    let mut c = veil_cfg::Config::default();
    c.listen = vec![listener("tcp://0.0.0.0:5556", None)];
    assert!(lan_announce_for(&c, "not base64!!", "AE1JRw==", &[]).is_none());
    assert!(
        lan_announce_for(&c, "c2hvcnQ=", "AE1JRw==", &[]).is_none(),
        "a key of the wrong length"
    );
}

#[test]
fn the_first_dialable_listener_wins_and_the_undialable_ones_are_skipped() {
    // Order matters: a node whose first listener is loopback must still
    // announce its second, or a common config (localhost admin + public
    // transport) announces nothing at all.
    let a = announce_for_listeners(vec![
        listener("tcp://127.0.0.1:9999", None),
        listener("memory://x:1", None),
        listener("obfs4-tcp://0.0.0.0:5556", None),
    ])
    .expect("the third listener should have been reached");
    assert_eq!(a.port, 5556);
}

fn config_with(
    bootstrap: Vec<BootstrapPeer>,
    policy: veil_cfg::BuiltinSeedPolicy,
) -> veil_cfg::Config {
    let mut c = veil_cfg::Config::default();
    c.bootstrap_peers = bootstrap;
    c.global.builtin_seed_policy = policy;
    c
}

#[test]
fn auto_keeps_the_historical_either_or() {
    let builtin = vec![peer("SEED1"), peer("SEED2")];
    // Nothing configured → seeds contribute.
    assert_eq!(
        builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Auto, true, builtin.clone()).len(),
        2,
    );
    // Something configured → seeds stay out, exactly as before.
    assert!(
        builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Auto, false, builtin).is_empty(),
    );
}

#[test]
fn always_contributes_alongside_a_configured_alternative() {
    let builtin = vec![peer("SEED1"), peer("SEED2")];
    // The point of the knob: seeds contribute even though the operator
    // has named their own entry points.
    assert_eq!(
        builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Always, false, builtin).len(),
        2,
    );
}

#[test]
fn never_is_an_off_switch_that_does_not_depend_on_build_features() {
    let builtin = vec![peer("SEED1")];
    assert!(
        builtin_seed_contribution(veil_cfg::BuiltinSeedPolicy::Never, true, builtin).is_empty(),
    );
}

// ── DNS seed-discovery gate ──────────────────────────────────────────
//
// The crash these pin: an identity that declined the shared seeds boots
// with `builtin_seed_policy = "never"`, no `peers` and no
// `[[bootstrap_peers]]`. The runtime used to answer that by querying
// `veil.example` — a domain RFC 6761 guarantees cannot resolve — which
// ran the DoT and DoH stages for nothing and then entered
// `discover_seeds_dns_system`. On Android that constructor calls
// `ndk_context::android_context()`, whose `expect` fires on a tokio
// worker; with `panic = "abort"` the whole process takes SIGABRT
// ("android context was not initialized") 12-90 s after boot.

/// The exact shipped shape of the defect: seeds refused, no peers, no
/// bootstrap peers, no DNS domain. Nothing must be spawned. Weakening the
/// gate back to the `unwrap_or(DEFAULT_BOOTSTRAP_DOMAIN)` default makes
/// this return `Some("veil.example")` and go red.
#[test]
fn refusing_seeds_with_no_peers_does_not_start_dns_discovery() {
    let cfg = config_with(Vec::new(), veil_cfg::BuiltinSeedPolicy::Never);
    assert!(cfg.peers.is_empty(), "fixture must have no peers");
    assert!(
        cfg.global.bootstrap_dns_domain.is_none(),
        "fixture must not name a DNS domain — that is the shipped config"
    );
    assert_eq!(
        dns_seed_discovery_domain(&cfg),
        None,
        "a node with nothing to dial and no configured bootstrap DNS \
         domain must NOT run seed discovery: the only domain available is \
         the RFC 6761-reserved placeholder, and reaching the system-DNS \
         stage aborts the process on Android"
    );
}

/// Same for the default policy — the gate is about the missing domain, not
/// about the refusal, so a stock node with an empty candidate set is
/// covered too.
#[test]
fn no_domain_means_no_dns_discovery_under_any_policy() {
    for policy in [
        veil_cfg::BuiltinSeedPolicy::Never,
        veil_cfg::BuiltinSeedPolicy::Auto,
        veil_cfg::BuiltinSeedPolicy::Always,
    ] {
        let cfg = config_with(Vec::new(), policy);
        assert_eq!(
            dns_seed_discovery_domain(&cfg),
            None,
            "policy {policy} must not reach DNS discovery without a domain"
        );
    }
}

/// The gate must not cost a deployment that genuinely uses DNS discovery:
/// naming a domain still arms it, including under `Never` (declining the
/// compile-time seeds is not declining your own operator's domain).
#[test]
fn a_configured_domain_still_arms_dns_discovery() {
    let mut cfg = config_with(Vec::new(), veil_cfg::BuiltinSeedPolicy::Never);
    cfg.global.bootstrap_dns_domain = Some("seeds.testnet.invalid".to_owned());
    assert_eq!(
        dns_seed_discovery_domain(&cfg),
        Some("seeds.testnet.invalid".to_owned()),
        "an operator who named a bootstrap DNS domain must still get \
         discovery — the gate targets the placeholder, not the feature"
    );
}

/// Condition 1 preserved: DNS discovery stays the LAST fallback.
#[test]
fn dns_discovery_stays_last_behind_configured_entry_points() {
    let mut cfg = config_with(vec![peer("ALT")], veil_cfg::BuiltinSeedPolicy::Never);
    cfg.global.bootstrap_dns_domain = Some("seeds.testnet.invalid".to_owned());
    assert_eq!(
        dns_seed_discovery_domain(&cfg),
        None,
        "a node with bootstrap_peers has something to dial; DNS discovery \
         is the last fallback and must not run"
    );
}

/// A seed list these tests own.
///
/// NOT `veil_bootstrap::builtin_seeds()`: that is empty under
/// `allow-empty-seeds`, which is one of the features CI builds with — so
/// every test below asserted its own premise and failed on it there, red
/// for a reason unrelated to what it was checking. What these tests are
/// about is what resolution does to a list.
fn seed_fixture() -> Vec<veil_cfg::BootstrapPeer> {
    vec![peer("SEED-A"), peer("SEED-B"), peer("SEED-C")]
}

#[test]
fn a_configured_alternative_no_longer_disables_the_builtin_seeds() {
    // The defect this closes: `bootstrap_peers` REPLACED the builtin list,
    // so one non-seed entry point silently cost the node every seed.
    let seeds = seed_fixture();
    let cfg = config_with(vec![peer("ALT")], veil_cfg::BuiltinSeedPolicy::Always);
    let resolved = resolve_bootstrap_candidates_from(&cfg, "ME", seeds.clone());

    assert_eq!(
        resolved.len(),
        seeds.len() + 1,
        "expected the alternative AND every builtin seed",
    );
    assert!(resolved.iter().any(|p| p.public_key == "ALT"));
    for s in &seeds {
        assert!(
            resolved.iter().any(|p| p.public_key == s.public_key),
            "builtin seed {} was dropped by the configured alternative",
            s.public_key,
        );
    }
}

#[test]
fn a_seed_only_node_has_a_non_empty_watchdog_retry_set() {
    // The defect this closes: the partition watchdog early-returned on
    // `config.bootstrap_peers.is_empty()`, which is the state of every
    // stock install — the seeds live in a local clone it never sees. Those
    // nodes got no partition recovery at all.
    let cfg = config_with(Vec::new(), veil_cfg::BuiltinSeedPolicy::Auto);
    assert!(
        cfg.bootstrap_peers.is_empty(),
        "precondition: the raw field the watchdog used to read is empty",
    );
    assert!(
        !resolve_bootstrap_candidates_from(&cfg, "ME", seed_fixture()).is_empty(),
        "watchdog would have nothing to re-dial for a seed-only node",
    );
}

#[test]
fn resolve_dedups_a_peer_that_is_both_configured_and_builtin() {
    let seeds = seed_fixture();
    // Pin the first builtin seed in `bootstrap_peers` too — the operator
    // curating a host that is also a seed must not double-dial it.
    let cfg = config_with(vec![seeds[0].clone()], veil_cfg::BuiltinSeedPolicy::Always);
    let resolved = resolve_bootstrap_candidates_from(&cfg, "ME", seeds.clone());

    assert_eq!(resolved.len(), seeds.len(), "duplicate was dialed twice");
    let occurrences = resolved
        .iter()
        .filter(|p| p.public_key == seeds[0].public_key)
        .count();
    assert_eq!(occurrences, 1);
}

#[test]
fn resolving_twice_is_a_fixed_point() {
    // `spawn_bootstrap_task` splices the resolved set back into a config
    // clone and recurses while `resolved.len() > configured.len()`. If
    // resolution were not idempotent that recursion would never bottom
    // out — the node would blow its stack at startup instead of dialing
    // anyone. Checked for both policies that contribute anything.
    for policy in [
        veil_cfg::BuiltinSeedPolicy::Always,
        veil_cfg::BuiltinSeedPolicy::Auto,
    ] {
        let cfg = config_with(vec![peer("ALT")], policy);
        let once = resolve_bootstrap_candidates_from(&cfg, "ME", seed_fixture());
        let mut next = cfg.clone();
        next.bootstrap_peers = once.clone();
        let twice = resolve_bootstrap_candidates_from(&next, "ME", seed_fixture());
        assert_eq!(
            twice.len(),
            once.len(),
            "policy={policy}: resolution is not a fixed point, \
             spawn_bootstrap_task would recurse forever",
        );
    }
}

#[test]
fn resolve_drops_our_own_key_from_both_sources() {
    let seeds = seed_fixture();
    // A seed host bootstrapping itself: its own key appears in the builtin
    // list, and must not be dialed from either source.
    let me = seeds[0].public_key.clone();
    let cfg = config_with(vec![peer("ALT")], veil_cfg::BuiltinSeedPolicy::Always);
    let resolved = resolve_bootstrap_candidates_from(&cfg, &me, seeds.clone());
    assert!(resolved.iter().all(|p| p.public_key != me));
}

// ── deterministic rendezvous cookie + relay anchor ────────────────────

/// report17 V17-M6: an accepted registration must own a slot that is
/// actually published.
///
/// The registry was an unbounded `Vec` while the maintenance tick signed
/// only the first `MAX_RENDEZVOUS_AD_SLOTS` of it. Every registration past
/// that was answered with success and never published: the caller believed
/// its mailbox was discoverable while nothing signed an ad for it, and the
/// entry stayed in memory to be cloned on every tick — one `Vec` grown by
/// anything that can reach the IPC socket.
#[test]
fn the_publisher_registry_is_no_larger_than_what_gets_published() {
    use veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS;
    let slots = MAX_RENDEZVOUS_AD_SLOTS as usize;
    let mut entries = Vec::new();

    let entry = |n: u8| veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: [n; 32],
        auth_cookie: [n; 16],
        validity_window_secs: 3600,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        rendezvous_kem_algo: 0,
        rendezvous_kem_pk: Vec::new(),
        rendezvous_kem_valid_until_unix: 0,
        ephemeral_ad_identity: None,
    };

    for n in 0..slots as u8 {
        assert!(
            insert_publisher_entry(&mut entries, entry(n)),
            "registration {n} was refused inside the slot count"
        );
    }
    assert_eq!(entries.len(), slots, "premise: the slots are full");

    assert!(
        !insert_publisher_entry(&mut entries, entry(0xEE)),
        "a registration past the publishable slots was accepted: it will \
         never be signed, and the caller was told its mailbox is live"
    );
    assert_eq!(entries.len(), slots, "the refused entry was kept anyway");

    // A REPLACEMENT still fits — it takes a slot already accounted for.
    // The built-in recipient task re-registers the same (relay, cookie) on
    // every tick, so refusing this would break a working publisher.
    assert!(
        insert_publisher_entry(&mut entries, entry(0)),
        "re-registering an existing (relay, cookie) was refused, which \
         breaks the publisher that already holds that slot"
    );
    assert_eq!(entries.len(), slots);
}

/// And a replacement keeps the KEM key the app registered.
///
/// The built-in task re-registers KEM-LESS on its tick; a full overwrite
/// drops the deposit target and senders can no longer leave offline mail.
#[test]
fn a_kemless_re_registration_keeps_the_key_the_app_supplied() {
    let mut entries = Vec::new();
    let base = |kem: Vec<u8>, until: u64| veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: [7; 32],
        auth_cookie: [7; 16],
        validity_window_secs: 3600,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        rendezvous_kem_algo: if kem.is_empty() { 0 } else { 1 },
        rendezvous_kem_pk: kem,
        rendezvous_kem_valid_until_unix: until,
        ephemeral_ad_identity: None,
    };

    assert!(insert_publisher_entry(
        &mut entries,
        base(vec![9; 32], 1_700_000_000)
    ));
    assert!(insert_publisher_entry(&mut entries, base(Vec::new(), 0)));

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].rendezvous_kem_pk,
        vec![9; 32],
        "the KEM was dropped"
    );
    assert_eq!(
        entries[0].rendezvous_kem_valid_until_unix, 1_700_000_000,
        "the KEM survived but its expiry did not, so the ad stops being \
         clipped to it (V17-M1)"
    );
}

/// But a re-registration that brings its OWN key ROTATES.
///
/// The inheritance above is for the KEM-less tick only. When the app hands
/// in a new key it also hands in that key's expiry, and the two belong
/// together: keeping the old key while adopting the new key's lifetime
/// re-published a rotated-out key for another full window, and no sender
/// ever saw the new one (report20 V18-M2).
#[test]
fn a_rotated_kem_key_replaces_the_one_it_supersedes() {
    let mut entries = Vec::new();
    let base = |kem: Vec<u8>, until: u64| veil_anonymity::rendezvous::RendezvousPublisherEntry {
        rendezvous_node_id: [7; 32],
        auth_cookie: [7; 16],
        validity_window_secs: 3600,
        push_envelope: Vec::new(),
        wake_hmac_envelope: Vec::new(),
        rendezvous_kem_algo: if kem.is_empty() { 0 } else { 1 },
        rendezvous_kem_pk: kem,
        rendezvous_kem_valid_until_unix: until,
        ephemeral_ad_identity: None,
    };

    assert!(insert_publisher_entry(
        &mut entries,
        base(vec![9; 32], 1_700_000_000)
    ));
    assert!(insert_publisher_entry(
        &mut entries,
        base(vec![4; 32], 1_800_000_000)
    ));

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].rendezvous_kem_pk,
        vec![4; 32],
        "the rotation was discarded: senders keep sealing to the key the \
         receiver replaced"
    );
    assert_eq!(
        entries[0].rendezvous_kem_valid_until_unix, 1_800_000_000,
        "the rotated-in key kept the old expiry"
    );
    assert!(
        !(entries[0].rendezvous_kem_pk == vec![9; 32]
            && entries[0].rendezvous_kem_valid_until_unix == 1_800_000_000),
        "the SUPERSEDED key is advertised under the NEW key's lifetime — \
         it stays sealable for a window it was retired before"
    );
}

#[test]
fn rendezvous_cookie_is_deterministic_xor_fold() {
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = i as u8; // 0,1,..,31
    }
    let c = rendezvous_cookie_from_node_id(&id);
    // XOR-fold: c[i] = id[i] ^ id[i+16]; here i ^ (i+16) == 16 for all i.
    assert_eq!(c, [16u8; 16]);
    // Deterministic: same input → same cookie, every call.
    assert_eq!(c, rendezvous_cookie_from_node_id(&id));
}

#[test]
fn rendezvous_cookie_matches_app_side_derivation() {
    // Mirror of Dart `MailboxService._deriveCookie` (c[i] = id[i] ^ id[i+16]).
    let id: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a);
    let want: [u8; 16] = std::array::from_fn(|i| id[i] ^ id[i + 16]);
    assert_eq!(rendezvous_cookie_from_node_id(&id), want);
}

#[test]
fn xor_distance_cmp_orders_by_kademlia_metric() {
    use std::cmp::Ordering;
    let anchor = [0u8; 32];
    let near = {
        let mut n = [0u8; 32];
        n[31] = 1; // distance 1
        n
    };
    let far = {
        let mut f = [0u8; 32];
        f[0] = 1; // distance 2^248
        f
    };
    assert_eq!(xor_distance_cmp(&anchor, &near, &far), Ordering::Less);
    assert_eq!(xor_distance_cmp(&anchor, &far, &near), Ordering::Greater);
    assert_eq!(xor_distance_cmp(&anchor, &near, &near), Ordering::Equal);
}

#[test]
fn xor_distance_min_is_stable_and_anchor_relative() {
    // The closest-to-anchor relay is picked deterministically, and DIFFERENT
    // anchors (receivers) select DIFFERENT relays from the same set — the
    // load-spreading property that replaces the old random draw.
    let relays = [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]];
    let pick = |anchor: &[u8; 32]| {
        *relays
            .iter()
            .min_by(|a, b| xor_distance_cmp(anchor, a, b))
            .unwrap()
    };
    // Anchor near 0x10 → picks 0x10; stable across repeated calls.
    assert_eq!(pick(&[0x11u8; 32]), [0x10u8; 32]);
    assert_eq!(pick(&[0x11u8; 32]), [0x10u8; 32]);
    // A different receiver anchors elsewhere → different relay.
    assert_eq!(pick(&[0x2eu8; 32]), [0x20u8; 32]);
}

#[test]
fn rendezvous_replica_picker_keeps_all_connected_pins_up_to_slot_cap() {
    use crate::types::{LinkId, NodeId, SessionInfo, SessionSource, SessionState};

    let pinned: Vec<[u8; 32]> = (1u8..=10).map(|n| [n; 32]).collect();
    let mut sessions = std::collections::BTreeMap::new();
    for (idx, node) in pinned.iter().enumerate() {
        sessions.insert(
            LinkId::new(idx as u64 + 1),
            SessionInfo {
                link_id: LinkId::new(idx as u64 + 1),
                node_id: Some(NodeId::from(*node)),
                nonce: None,
                matched_peer_id: None,
                source: SessionSource::Inbound(crate::types::ListenId::new(1)),
                listener_handle: None,
                state: SessionState::Active,
                transport: "test".to_owned(),
                remote_addr: None,
                description: String::new(),
            },
        );
    }
    let live = Arc::new(std::sync::Mutex::new(sessions));
    let dht = Arc::new(veil_dht::KademliaService::new([9u8; 32]));
    let caps = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

    let got = pick_rendezvous_relays_deterministic(&live, &dht, &caps, &pinned, &[9u8; 32]);
    assert_eq!(
        got,
        pinned[..veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize]
    );
}

#[test]
fn rendezvous_replica_picker_requires_anonymity_relay_capability() {
    use crate::types::{LinkId, NodeId, SessionInfo, SessionSource, SessionState};

    let ordinary_relay = [0x11u8; 32];
    let anonymity_relay = [0x22u8; 32];
    let mut sessions = std::collections::BTreeMap::new();
    for (idx, node) in [ordinary_relay, anonymity_relay].iter().enumerate() {
        sessions.insert(
            LinkId::new(idx as u64 + 1),
            SessionInfo {
                link_id: LinkId::new(idx as u64 + 1),
                node_id: Some(NodeId::from(*node)),
                nonce: None,
                matched_peer_id: None,
                source: SessionSource::Inbound(crate::types::ListenId::new(1)),
                listener_handle: None,
                state: SessionState::Active,
                transport: "test".to_owned(),
                remote_addr: None,
                description: String::new(),
            },
        );
    }
    let live = Arc::new(std::sync::Mutex::new(sessions));
    let dht = Arc::new(veil_dht::KademliaService::new([9u8; 32]));
    let caps = Arc::new(std::sync::RwLock::new(std::collections::HashMap::from([
        (ordinary_relay, veil_proto::session::cap_flags::CAN_RELAY),
        (
            anonymity_relay,
            veil_proto::session::cap_flags::CAN_RELAY
                | veil_proto::session::cap_flags::ANONYMITY_RELAY,
        ),
    ])));

    let got = pick_rendezvous_relays_deterministic(&live, &dht, &caps, &[], &[9u8; 32]);
    assert_eq!(
        got,
        vec![anonymity_relay],
        "ordinary CAN_RELAY transport peers must not become onion rendezvous relays",
    );
}

// ── BootstrapWatchdog: decision-fn coverage ──────────────────────────
//
// Drives `evaluate_watchdog_tick` with mock inputs covering every
// transition (sessions OK, streak below threshold, streak reached
// but inside cool-down, streak reached past cool-down, first-ever
// retry). The real watchdog loop is a thin wrapper around this fn
// plus a 30 s tokio interval, so behavioural coverage of the decision
// logic is enough to catch logic regressions without 90 s real-clock tests.

const TEST_THRESHOLD: u32 = 3;
const TEST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

#[test]
fn watchdog_idle_when_sessions_present() {
    assert_eq!(
        evaluate_watchdog_tick(1, 0, TEST_THRESHOLD, None, TEST_COOLDOWN),
        WatchdogDecision::Idle,
    );
    assert_eq!(
        evaluate_watchdog_tick(7, 5, TEST_THRESHOLD, None, TEST_COOLDOWN),
        WatchdogDecision::Idle,
        "non-zero session count overrides any prior zero-streak",
    );
}

#[test]
fn watchdog_waits_below_threshold() {
    for streak in 0..TEST_THRESHOLD {
        assert_eq!(
            evaluate_watchdog_tick(0, streak, TEST_THRESHOLD, None, TEST_COOLDOWN),
            WatchdogDecision::Wait,
            "streak={streak} below threshold should Wait",
        );
    }
}

#[test]
fn watchdog_retries_immediately_on_first_threshold_hit() {
    assert_eq!(
        evaluate_watchdog_tick(0, TEST_THRESHOLD, TEST_THRESHOLD, None, TEST_COOLDOWN),
        WatchdogDecision::Retry,
        "first-ever retry must fire as soon as threshold is reached",
    );
}

#[test]
fn watchdog_waits_inside_cooldown() {
    // Streak past threshold, but only 60 s elapsed since last retry
    // — cool-down is 300 s, so we wait.
    assert_eq!(
        evaluate_watchdog_tick(
            0,
            TEST_THRESHOLD + 10,
            TEST_THRESHOLD,
            Some(std::time::Duration::from_secs(60)),
            TEST_COOLDOWN,
        ),
        WatchdogDecision::Wait,
    );
}

#[test]
fn watchdog_retries_after_cooldown_expires() {
    // Streak past threshold, cool-down fully elapsed → retry.
    assert_eq!(
        evaluate_watchdog_tick(
            0,
            TEST_THRESHOLD + 10,
            TEST_THRESHOLD,
            Some(TEST_COOLDOWN + std::time::Duration::from_secs(1)),
            TEST_COOLDOWN,
        ),
        WatchdogDecision::Retry,
    );
}

#[test]
fn watchdog_treats_threshold_zero_as_immediate() {
    // Edge case: threshold=0 means "fire on first zero-tick".
    // saturating math should not panic, decision should be Retry.
    assert_eq!(
        evaluate_watchdog_tick(0, 1, 0, None, TEST_COOLDOWN),
        WatchdogDecision::Retry,
    );
}

#[test]
fn filter_self_seeds_keeps_all_when_self_absent() {
    let peers = vec![peer("A"), peer("B")];
    let kept = filter_self_seeds(peers.clone(), "Z");
    assert_eq!(kept, peers);
}

#[test]
fn filter_self_seeds_handles_empty() {
    assert!(filter_self_seeds(vec![], "ME").is_empty());
}

// ── dedup hardening ────────────────────────────────────────────

fn pkset(pks: &[&str]) -> std::collections::HashSet<String> {
    pks.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn epic481_4_dedup_drops_pubkey_already_in_bootstrap_peers() {
    let known = pkset(&["IN_BOOTSTRAP"]);
    let kept = filter_already_known(
        vec![peer("IN_BOOTSTRAP"), peer("FRESH"), peer("ALSO_FRESH")],
        &known,
    );
    assert_eq!(kept.len(), 2);
    assert!(kept.iter().all(|p| p.public_key != "IN_BOOTSTRAP"));
}

#[test]
fn epic481_4_dedup_drops_pubkey_already_in_cache() {
    // The cache snapshot contributes pubkeys to `known_pubkeys` —
    // verify the helper drops a peer whose pubkey came from there.
    let known = pkset(&["FRIEND_FROM_LAST_RUN"]);
    let kept = filter_already_known(vec![peer("FRIEND_FROM_LAST_RUN"), peer("NEW_SEED")], &known);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].public_key, "NEW_SEED");
}

#[test]
fn epic481_4_dedup_keeps_all_when_known_is_empty() {
    let known = std::collections::HashSet::new();
    let peers = vec![peer("A"), peer("B"), peer("C")];
    let kept = filter_already_known(peers.clone(), &known);
    assert_eq!(kept, peers);
}

#[test]
fn epic481_4_dedup_handles_empty_input() {
    let known = pkset(&["A", "B"]);
    assert!(filter_already_known(vec![], &known).is_empty());
}

#[test]
fn epic481_4_dedup_drops_all_when_every_pubkey_known() {
    // Pathological case: HTTPS bundle returns ONLY pubkeys we
    // already know. Result: empty Vec, no double-dialing — the
    // task's downstream `if seeds.is_empty { return; }` will
    // skip all per-peer registration, which is the correct
    // behaviour (saves CPU + battery + DPI-visible handshakes).
    let known = pkset(&["A", "B", "C"]);
    let kept = filter_already_known(vec![peer("A"), peer("B"), peer("C")], &known);
    assert!(
        kept.is_empty(),
        "every pubkey already known → nothing to add"
    );
}
