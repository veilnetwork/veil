//! Re-export shim for the extracted [`veil-session`](veil_session) crate.
//!
//! Phase 2 of `veilcore` extraction (see
//! [`docs/en/PLAN_VEILCORE_EXTRACTION.md`](../../../docs/en/PLAN_VEILCORE_EXTRACTION.md)):
//! all session production code (27 files, ~21 KLoC) moved to the
//! sibling crate.  This module preserves the existing
//! `crate::node::session::X` import paths so the rest of veilcore
//! (dispatcher, runtime, node bootstrap) does not need a mass
//! find/replace.
//!
//! Integration tests + chaos sim stay here because they need a
//! real `FrameDispatcher` (Strategy A in the plan doc).

pub use veil_session::*;

// Wildcard re-exports from the runner module so `runner_tests.rs`'s
// `super::*` reaches every helper fn / struct it touches.  Bulk-promote
// applied to runner.rs items moved every previous `pub(crate)` to `pub`.
pub use veil_session::runner::*;

// Sub-module re-exports for callers using fully-qualified paths
// (e.g. `crate::node::session::handshake::perform_ovl1_handshake`).
pub use veil_session::backpressure_signal;
pub use veil_session::battery_adjusted_keepalive;
pub use veil_session::cover_traffic;
pub use veil_session::dispatcher_sink;
pub use veil_session::fsm;
pub use veil_session::handoff;
pub use veil_session::handshake;
pub use veil_session::hot_standby;
pub use veil_session::keepalive_emit;
pub use veil_session::manager;
pub use veil_session::mlkem_rekey_context;
pub use veil_session::once_trigger;
pub use veil_session::outbound_batch_coalescer;
pub use veil_session::outbox;
pub use veil_session::pending_response_table;
pub use veil_session::priority_queue;
pub use veil_session::rekey_context;
pub use veil_session::rekey_rx_grace_buffer;
pub use veil_session::rendezvous;
pub use veil_session::rotation_deadline;
pub use veil_session::runner;
pub use veil_session::session_alias_guard;
pub use veil_session::ticket;
pub use veil_session::timers;
pub use veil_session::tx_registry;
pub use veil_session::warm_probe;
pub use veil_session::write_error_tracker;

#[cfg(test)]
pub(crate) mod chaos_sim;

// `runner_tests.rs` extracted to the standalone
// `crates/veil-session-integration-tests/tests/runner_tests.rs` (audit
// batch 2026-05-21 Phase D14).  5568 LoC that previously coupled the
// veilcore-private dispatcher factory + session shim's `use super::*;`
// now compile against the published surface of veil-session +
// sibling crates.

#[cfg(test)]
mod integration_tests {
    //! Integration test: two nodes (initiator + responder) drive the full OVL1
    //! session handshake over a Tokio in-memory duplex stream.

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use crate::{
        node::session::{SessionFsm, SessionPhase},
        proto::{
            codec::{MAX_FRAME_BODY, decode_header, encode_header},
            family::{FrameFamily, SessionMsg},
            header::{FrameHeader, HEADER_SIZE, VERSION},
            session::{
                AttachPayload, CapabilitiesPayload, HelloPayload, IdentityPayload,
                KeyAgreementPayload, SessionConfirmPayload, cap_flags, role_bits,
            },
        },
    };

    async fn write_frame(stream: &mut DuplexStream, family: u8, msg_type: u16, body: &[u8]) {
        let mut hdr = FrameHeader::new(family, msg_type);
        hdr.body_len = body.len() as u32;
        stream.write_all(&encode_header(&hdr)).await.unwrap();
        if !body.is_empty() {
            stream.write_all(body).await.unwrap();
        }
    }

    async fn read_frame(stream: &mut DuplexStream) -> (FrameHeader, Vec<u8>) {
        let mut hdr_buf = [0u8; HEADER_SIZE];
        stream.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = decode_header(&hdr_buf).unwrap();
        assert!(hdr.body_len <= MAX_FRAME_BODY);
        let mut body = vec![0u8; hdr.body_len as usize];
        if hdr.body_len > 0 {
            stream.read_exact(&mut body).await.unwrap();
        }
        (hdr, body)
    }

    async fn run_handshake(mut stream: DuplexStream, node_seed: u8) {
        let sess_family = FrameFamily::Session as u8;
        let mut fsm = SessionFsm::new();

        let hello = HelloPayload {
            ovl1_major: VERSION as u16,
            node_id: [node_seed; 32],
            resume_ticket: None,
            membership_cert_blob: None,
        };
        write_frame(
            &mut stream,
            sess_family,
            SessionMsg::Hello as u16,
            &hello.encode(),
        )
        .await;
        fsm.on_hello_sent();

        let (hdr, body) = read_frame(&mut stream).await;
        assert_eq!(hdr.msg_type, SessionMsg::Hello as u16);
        let remote_hello = HelloPayload::decode(&body).unwrap();
        fsm.on_hello_received(remote_hello);

        let identity = IdentityPayload {
            algo: 1,
            public_key: vec![node_seed; 32],
            nonce: b"test-nonce".to_vec(),
            node_id: [node_seed; 32],
            mlkem_pubkey: None,
        };
        write_frame(
            &mut stream,
            sess_family,
            SessionMsg::Identity as u16,
            &identity.encode(),
        )
        .await;
        fsm.on_identity_sent();

        let (hdr, body) = read_frame(&mut stream).await;
        assert_eq!(hdr.msg_type, SessionMsg::Identity as u16);
        let remote_identity = IdentityPayload::decode(&body).unwrap();
        fsm.on_identity_received(remote_identity);

        let caps = CapabilitiesPayload {
            roles_supported: role_bits::LEAF,
            flags: cap_flags::CAN_RELAY,
            discovery_mode: 0,
        };
        write_frame(
            &mut stream,
            sess_family,
            SessionMsg::Capabilities as u16,
            &caps.encode(),
        )
        .await;
        fsm.on_capabilities_sent();

        let (hdr, body) = read_frame(&mut stream).await;
        assert_eq!(hdr.msg_type, SessionMsg::Capabilities as u16);
        let remote_caps = CapabilitiesPayload::decode(&body).unwrap();
        fsm.on_capabilities_received(remote_caps);

        let ka = KeyAgreementPayload {
            algo: 1,
            ephemeral_pubkey: vec![node_seed ^ 0xFF; 32],
            ephemeral_sig: vec![],
        };
        write_frame(
            &mut stream,
            sess_family,
            SessionMsg::KeyAgreement as u16,
            &ka.encode(),
        )
        .await;
        fsm.on_key_agreement_sent();

        let (hdr, body) = read_frame(&mut stream).await;
        assert_eq!(hdr.msg_type, SessionMsg::KeyAgreement as u16);
        let remote_ka = KeyAgreementPayload::decode(&body).unwrap();
        fsm.on_key_agreement_received(remote_ka);

        let confirm = SessionConfirmPayload {
            session_id: [0xCC; 32],
            mac: [0xDD; 32],
        };
        write_frame(
            &mut stream,
            sess_family,
            SessionMsg::SessionConfirm as u16,
            &confirm.encode(),
        )
        .await;
        fsm.on_confirm_sent();

        let (hdr, body) = read_frame(&mut stream).await;
        assert_eq!(hdr.msg_type, SessionMsg::SessionConfirm as u16);
        let remote_confirm = SessionConfirmPayload::decode(&body).unwrap();
        fsm.on_confirm_received(remote_confirm);

        let attach = AttachPayload {
            role: 0,
            realm_id: 1,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        write_frame(
            &mut stream,
            sess_family,
            SessionMsg::Attach as u16,
            &attach.encode(),
        )
        .await;
        fsm.on_attach_sent();

        let (hdr, body) = read_frame(&mut stream).await;
        assert_eq!(hdr.msg_type, SessionMsg::Attach as u16);
        let remote_attach = AttachPayload::decode(&body).unwrap();
        fsm.on_attach_received(remote_attach);

        assert_eq!(
            fsm.phase,
            SessionPhase::Attached,
            "node {node_seed}: expected Attached"
        );
    }

    #[tokio::test]
    async fn two_nodes_complete_ovl1_handshake() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let t1 = tokio::spawn(run_handshake(a, 0xAA));
        let t2 = tokio::spawn(run_handshake(b, 0xBB));
        t1.await.unwrap();
        t2.await.unwrap();
    }
}
