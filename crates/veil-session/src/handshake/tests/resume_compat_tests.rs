//! Exercise the actual fast path against peers speaking the previous protocol.
use super::*;
use crate::ticket::{TicketIssuer, TicketKey};
use std::sync::{Arc, Mutex};
use veil_proto::session::ClientTicketEntry;

fn ticket_fixture() -> (Arc<Mutex<TicketIssuer>>, ClientTicketEntry) {
    let issuer = Arc::new(Mutex::new(TicketIssuer::new(TicketKey::generate())));
    let client = test_identity(0xBB);
    let server = test_identity(0xAA);
    let blob = issuer.lock().unwrap().issue_for_instance(
        [3; 32],
        *client.node_id.as_bytes(),
        [5; 16],
        [1; 32],
        [2; 32],
    );
    let entry = ClientTicketEntry {
        blob,
        tx_key: [2; 32],
        rx_key: [1; 32],
        session_id: [3; 32],
        peer_public_key: server.public_key,
        peer_nonce: server.nonce,
        issued_at: std::time::Instant::now(),
    };
    (issuer, entry)
}

async fn upgraded(
    mut stream: tokio::io::DuplexStream,
    server: bool,
    issuer: Arc<Mutex<TicketIssuer>>,
    entry: ClientTicketEntry,
) -> Result<OvlHandshakeResult> {
    let identity = test_identity(if server { 0xAA } else { 0xBB });
    perform_ovl1_handshake(
        &mut stream,
        &identity,
        NodeRole::Core,
        veil_cfg::DiscoveryMode::Public,
        None,
        None,
        None,
        (!server).then_some([0; 32]),
        (!server).then_some(entry),
        server.then_some(issuer),
        None,
        &[],
        false,
        true,
        None,
        None,
        None,
    )
    .await
}

async fn old_peer(
    mut stream: tokio::io::DuplexStream,
    server: bool,
    issuer: Arc<Mutex<TicketIssuer>>,
    entry: ClientTicketEntry,
    bad_proof: bool,
) -> SessionKeys {
    let identity = test_identity(if server { 0xAA } else { 0xBB });
    let local_id = *identity.node_id.as_bytes();
    let family = FrameFamily::Session as u8;
    let hello = HelloPayload {
        ovl1_major: VERSION as u16,
        node_id: local_id,
        resume_ticket: (!server).then_some(entry.blob.clone()),
        membership_cert_blob: None,
        resume_nonce: (!server).then_some([6; 32]),
    };
    let remote_hello = if server {
        let (_, body) = read_frame(&mut stream).await.unwrap();
        write_frame(
            &mut stream,
            family,
            SessionMsg::Hello as u16,
            &hello.encode(),
        )
        .await
        .unwrap();
        HelloPayload::decode(&body).unwrap()
    } else {
        write_frame(
            &mut stream,
            family,
            SessionMsg::Hello as u16,
            &hello.encode(),
        )
        .await
        .unwrap();
        let (_, body) = read_frame(&mut stream).await.unwrap();
        HelloPayload::decode(&body).unwrap()
    };
    let mut attach = build_local_attach_bytes(NodeRole::Core, None, &[], None);
    if server {
        let ticket = issuer
            .lock()
            .unwrap()
            .decrypt(remote_hello.resume_ticket.as_ref().unwrap())
            .unwrap();
        let nonce = [7; 32];
        let keys = veil_crypto::session_kdf::derive_resume_keys(
            &ticket.tx_key,
            &ticket.rx_key,
            &ticket.session_id,
            &remote_hello.resume_nonce.unwrap(),
            &nonce,
            &local_id,
            &remote_hello.node_id,
        );
        veil_proto::session::append_resume_nonce_to_attach(&mut attach, &nonce);
        if bad_proof {
            // A network peer cannot enable new lanes using a stale ticket key.
            crate::resume_capabilities::append(
                &mut attach,
                &local_capabilities(
                    NodeRole::Core,
                    veil_cfg::DiscoveryMode::Public,
                    None,
                    false,
                    true,
                ),
                &ticket.tx_key,
                &local_id,
                &remote_hello.node_id,
            );
        }
        write_frame(&mut stream, family, SessionMsg::Attach as u16, &attach)
            .await
            .unwrap();
        let _ = read_frame(&mut stream).await; // New client may reject the proof.
        keys
    } else {
        let (_, body) = read_frame(&mut stream).await.unwrap();
        let nonce = veil_proto::session::decode_resume_nonce_from_attach(&body).unwrap();
        let keys = veil_crypto::session_kdf::derive_resume_keys(
            &entry.tx_key,
            &entry.rx_key,
            &entry.session_id,
            &hello.resume_nonce.unwrap(),
            &nonce,
            &local_id,
            &remote_hello.node_id,
        );
        write_frame(&mut stream, family, SessionMsg::Attach as u16, &attach)
            .await
            .unwrap();
        keys
    }
}

#[tokio::test]
async fn upgraded_client_and_server_keep_legacy_resume_fallback() {
    for new_server in [false, true] {
        let (issuer, entry) = ticket_fixture();
        let (a, b) = duplex(64 * 1024);
        let (new, old) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                upgraded(a, new_server, Arc::clone(&issuer), entry.clone()),
                old_peer(b, !new_server, issuer, entry, false),
            )
        })
        .await
        .unwrap();
        let new = new.unwrap();
        assert_eq!(new.session_keys.tx_key, old.rx_key);
        assert_eq!(new.session_keys.rx_key, old.tx_key);
        assert!(!new.remote_caps_stated);
        assert!(!new.remote_capabilities.supports_circuit_datagrams());
        assert!(!new.remote_capabilities.supports_parallel_quic());
    }
}

#[tokio::test]
async fn stale_key_capability_proof_aborts_actual_resume() {
    let (issuer, entry) = ticket_fixture();
    let (a, b) = duplex(64 * 1024);
    let (new, _) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            upgraded(a, false, Arc::clone(&issuer), entry.clone()),
            old_peer(b, true, issuer, entry, true),
        )
    })
    .await
    .unwrap();
    assert!(
        new.unwrap_err()
            .0
            .contains("invalid resumed capability proof")
    );
}
