//! Read-only IPC query handlers.
//!
//! All five handlers gate на the per-connection `allow_query` rate
//! limiter so а sandboxed-but-IPC-capable adversary can't spam fast
//! enough к reconstruct peer-graph snapshots or amplify outbound DNS-TXT
//! lookups (the JoinBootstrapUri path).  When the bucket is empty the
//! request is silently dropped — silent drop avoids making the limit
//! itself а probing oracle.
//!
//! Without а wired provider / sink, each handler replies с а sensible
//! default (empty list / zero-state payload / `INTERNAL_ERROR`) so apps
//! see "feature off" cleanly rather than а protocol error.

use std::sync::Arc;

use veil_proto::{
    CreateBootstrapInvitePayload, CreateBootstrapInviteResultPayload, FrameFamily,
    JoinBootstrapPayload, JoinBootstrapResultPayload, LocalAppMsg, LookupRendezvousReplicasPayload,
    LookupRendezvousReplicasRespPayload, MAX_CREATE_INVITE_DETAIL_LEN, MAX_CREATE_INVITE_URI_LEN,
    MAX_JOIN_DETAIL_LEN, MAX_PAIR_CEREMONY_BYTES, MAX_PAIR_DETAIL_LEN, MAX_PAIR_URI_LEN,
    MAX_RENDEZVOUS_REPLICAS, MOBILE_BATTERY_AC_OR_UNKNOWN, MOBILE_LOW_BATTERY_THRESHOLD_DISABLED,
    MobileStatusPayload, NodeIdentityPayload, PairCeremonyFramePayload,
    PairCeremonyFrameResultPayload, PairCeremonyOobResultPayload, PairSourceCreateInvitePayload,
    PairSourceCreateInviteResultPayload, PairStatusResultPayload, PairTargetBuildConfirmPayload,
    PairTargetConsumeUriPayload, ReplicaWire, create_invite_status, join_status,
    pair_source_status, pair_target_status,
};

use crate::frame_io::write_frame_wh;
use crate::server::IpcClientState;
use crate::transport::IpcWriteHalf;
use crate::{
    BootstrapInviteCreateOutcome, BootstrapInviteCreateSink, BootstrapJoinOutcome,
    BootstrapJoinSink, MobileStatusProvider, PairSourceCreateOutcome,
    PairSourceHandleConfirmOutcome, PairSourceHandleHelloOutcome, PairSourceSink,
    PairTargetBuildConfirmOutcome, PairTargetConsumeOutcome, PairTargetHandleCertOutcome,
    PairTargetSink, PeerListProvider, PnetStatusProvider, RendezvousReplicaResolver,
};

pub(crate) async fn handle_lookup_rendezvous_replicas(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    rendezvous_resolver: Option<&Arc<dyn RendezvousReplicaResolver>>,
) -> std::io::Result<()> {
    // App asks daemon к resolve K candidate mailbox-relays for а
    // receiver.  Daemon does the DHT lookup + verification; reply carries
    // up к `min(MAX_RENDEZVOUS_REPLICAS, request.max_replicas)` verified
    // entries.  Empty list = DHT miss / no fresh ad / verification failed.
    if !client_state.allow_query() {
        return Ok(());
    }
    let Ok(req) = LookupRendezvousReplicasPayload::decode(body) else {
        return Ok(());
    };
    let cap = if req.max_replicas == 0 {
        MAX_RENDEZVOUS_REPLICAS
    } else {
        (req.max_replicas as usize).min(MAX_RENDEZVOUS_REPLICAS)
    };
    let entries: Vec<ReplicaWire> = match rendezvous_resolver {
        Some(r) => r
            .resolve_replicas(req.receiver_id, cap)
            .await
            .into_iter()
            .take(cap)
            .map(|e| ReplicaWire {
                relay_node_id: e.relay_node_id,
                valid_until_unix: e.valid_until_unix,
                push_envelope: e.push_envelope,
                capability_token: e.capability_token,
                wake_hmac_envelope: e.wake_hmac_envelope,
            })
            .collect(),
        None => Vec::new(),
    };
    let reply = LookupRendezvousReplicasRespPayload { entries };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::LookupRendezvousReplicasResp as u16,
        &reply.encode(),
    )
    .await
}

pub(crate) async fn handle_get_node_identity(
    wh: &mut IpcWriteHalf,
    client_state: &mut IpcClientState,
    node_id: [u8; 32],
    local_identity_algo: u8,
    local_identity_pubkey: &[u8],
    local_relay_x25519_pubkey: Option<[u8; 32]>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let payload = NodeIdentityPayload {
        node_id,
        algo: local_identity_algo,
        public_key: local_identity_pubkey.to_vec(),
        relay_x25519_pubkey: local_relay_x25519_pubkey,
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::NodeIdentity as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_get_peers(
    wh: &mut IpcWriteHalf,
    client_state: &mut IpcClientState,
    peer_list_provider: Option<&Arc<dyn PeerListProvider>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    // Without а provider, replies an empty list — apps see "0 peers"
    // cleanly rather than а protocol error.
    let mut payload = peer_list_provider
        .map(|p| p.list_peers())
        .unwrap_or_default();
    // Defensive trim — provider should respect the cap но а bug or race
    // could push past it.  Truncating ("first N peers") beats failing
    // the encode и surfacing а confusing IPC error.
    if payload.peers.len() > veil_proto::MAX_PEERS_LIST_ENTRIES {
        payload.peers.truncate(veil_proto::MAX_PEERS_LIST_ENTRIES);
    }
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PeersList as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_pnet_status_query(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    pnet_status_provider: Option<&Arc<dyn PnetStatusProvider>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    // Query body is just the 32-byte peer_node_id.  Malformed bodies →
    // not-admitted reply (apps still get а correlated correlation_id'd
    // result; no protocol error).
    let peer_node_id: [u8; 32] = body.try_into().unwrap_or_default();
    // Without а provider, all queries reply admitted=false / has_cert=false.
    // Apps в strict p_net mode treat this as "no daemon support" → reject.
    let payload = pnet_status_provider
        .map(|p| p.peer_status(&peer_node_id))
        .unwrap_or_else(|| veil_proto::PnetStatusResultPayload {
            admitted: false,
            has_cert: false,
            admin: false,
            valid_until_unix: 0,
            network_id: [0u8; 32],
            peer_node_id,
        });
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PnetStatusResult as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_get_mobile_status(
    wh: &mut IpcWriteHalf,
    client_state: &mut IpcClientState,
    mobile_status_provider: Option<&Arc<dyn MobileStatusProvider>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    // Without а provider, replies а default zero-state payload — apps
    // see "feature off" rather than а protocol error.
    let payload =
        mobile_status_provider
            .map(|p| p.mobile_status())
            .unwrap_or(MobileStatusPayload {
                background_tier: 0,
                background_keepalive_multiplier: 1,
                background_keepalive_factor: 1,
                battery_level_pct: MOBILE_BATTERY_AC_OR_UNKNOWN,
                low_battery_threshold_pct: MOBILE_LOW_BATTERY_THRESHOLD_DISABLED,
                low_battery_multiplier: 1,
                battery_route_probe_factor: 1,
            });
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::MobileStatus as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_join_bootstrap_uri(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    bootstrap_join_sink: Option<&Arc<dyn BootstrapJoinSink>>,
) -> std::io::Result<()> {
    // JoinBootstrap is heavier (DNS-TXT lookups, signed-invite verification)
    // so the cap also bounds outbound network amplification from а
    // misbehaving local app.
    if !client_state.allow_query() {
        return Ok(());
    }
    // Wire-format errors map к `INVALID_URI` с the proto error as detail.
    let req = match JoinBootstrapPayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let detail = format!("decode request: {e}");
            let payload = JoinBootstrapResultPayload {
                status: join_status::INVALID_URI,
                peer_node_id: [0u8; 32],
                detail: detail.into_bytes(),
            };
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::JoinBootstrapResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = bootstrap_join_sink {
        let outcome = sink.join_uri(
            &req.uri,
            req.password.as_deref(),
            req.expected_issuer_pk.as_deref(),
        );
        match outcome {
            BootstrapJoinOutcome::Ok {
                peer_node_id,
                detail,
            } => JoinBootstrapResultPayload {
                status: join_status::OK,
                peer_node_id,
                detail: detail.into_bytes(),
            },
            BootstrapJoinOutcome::AlreadyRegistered { peer_node_id } => {
                JoinBootstrapResultPayload {
                    status: join_status::ALREADY_REGISTERED,
                    peer_node_id,
                    detail: b"peer already in runtime peer-set".to_vec(),
                }
            }
            BootstrapJoinOutcome::InvalidUri(d) => JoinBootstrapResultPayload {
                status: join_status::INVALID_URI,
                peer_node_id: [0u8; 32],
                detail: d.into_bytes(),
            },
            BootstrapJoinOutcome::PasswordRequired => JoinBootstrapResultPayload {
                status: join_status::PASSWORD_REQUIRED,
                peer_node_id: [0u8; 32],
                detail: "URI is `veil:pair?…`; supply password".as_bytes().to_vec(),
            },
            BootstrapJoinOutcome::PasswordWrong => JoinBootstrapResultPayload {
                status: join_status::PASSWORD_WRONG,
                peer_node_id: [0u8; 32],
                detail: b"AEAD verify failed (wrong password or tampered URI)".to_vec(),
            },
            BootstrapJoinOutcome::SignatureInvalid(d) => JoinBootstrapResultPayload {
                status: join_status::SIGNATURE_INVALID,
                peer_node_id: [0u8; 32],
                detail: d.into_bytes(),
            },
            BootstrapJoinOutcome::InternalError(d) => JoinBootstrapResultPayload {
                status: join_status::INTERNAL_ERROR,
                peer_node_id: [0u8; 32],
                detail: d.into_bytes(),
            },
        }
    } else {
        JoinBootstrapResultPayload {
            status: join_status::INTERNAL_ERROR,
            peer_node_id: [0u8; 32],
            detail: b"bootstrap-join sink not wired".to_vec(),
        }
    };
    // Truncate detail in case sink emitted а very long error message
    // (avoids accidentally exceeding wire cap).
    if payload.detail.len() > MAX_JOIN_DETAIL_LEN {
        payload.detail.truncate(MAX_JOIN_DETAIL_LEN);
    }
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::JoinBootstrapResult as u16,
        &payload.encode(),
    )
    .await
}

/// Handler [`LocalAppMsg::CreateBootstrapInvite`] (Epic 489.7
/// generator side).  Reads optional password from the payload,
/// invokes the sink к assemble + encode the invite, и returns the
/// resulting URI на success или а status-coded error.
pub(crate) async fn handle_create_bootstrap_invite(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    invite_create_sink: Option<&Arc<dyn BootstrapInviteCreateSink>>,
) -> std::io::Result<()> {
    // Same rate-limit class as JoinBootstrap — invite encoding is
    // cheap но encryption variant adds Argon2id which would let а
    // misbehaving app pin CPU. Gate it consistently.
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match CreateBootstrapInvitePayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = CreateBootstrapInviteResultPayload {
                status: create_invite_status::INTERNAL_ERROR,
                uri: String::new(),
                detail: format!("decode request: {e}").into_bytes(),
            };
            if payload.detail.len() > MAX_CREATE_INVITE_DETAIL_LEN {
                payload.detail.truncate(MAX_CREATE_INVITE_DETAIL_LEN);
            }
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::CreateBootstrapInviteResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = invite_create_sink {
        match sink.create_invite(req.password.as_deref()) {
            BootstrapInviteCreateOutcome::Ok { uri } => CreateBootstrapInviteResultPayload {
                status: create_invite_status::OK,
                uri,
                detail: Vec::new(),
            },
            BootstrapInviteCreateOutcome::NotConfigured(d) => CreateBootstrapInviteResultPayload {
                status: create_invite_status::NOT_CONFIGURED,
                uri: String::new(),
                detail: d.into_bytes(),
            },
            BootstrapInviteCreateOutcome::BadPassword(d) => CreateBootstrapInviteResultPayload {
                status: create_invite_status::BAD_PASSWORD,
                uri: String::new(),
                detail: d.into_bytes(),
            },
            BootstrapInviteCreateOutcome::InternalError(d) => CreateBootstrapInviteResultPayload {
                status: create_invite_status::INTERNAL_ERROR,
                uri: String::new(),
                detail: d.into_bytes(),
            },
        }
    } else {
        CreateBootstrapInviteResultPayload {
            status: create_invite_status::INTERNAL_ERROR,
            uri: String::new(),
            detail: b"create-invite sink not wired".to_vec(),
        }
    };
    if payload.uri.len() > MAX_CREATE_INVITE_URI_LEN {
        // Should never happen (sink contract); clip и report.
        payload.status = create_invite_status::INTERNAL_ERROR;
        payload.detail = format!(
            "encoded URI {}B exceeds MAX_CREATE_INVITE_URI_LEN ({MAX_CREATE_INVITE_URI_LEN})",
            payload.uri.len()
        )
        .into_bytes();
        payload.uri = String::new();
    }
    if payload.detail.len() > MAX_CREATE_INVITE_DETAIL_LEN {
        payload.detail.truncate(MAX_CREATE_INVITE_DETAIL_LEN);
    }
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::CreateBootstrapInviteResult as u16,
        &payload.encode(),
    )
    .await
}

// ── Multi-device pairing handlers (Epic 489.8) ─────────────────

/// Truncate detail к the wire cap to prevent oversized payloads.
fn clip_pair_detail(v: &mut Vec<u8>) {
    if v.len() > MAX_PAIR_DETAIL_LEN {
        v.truncate(MAX_PAIR_DETAIL_LEN);
    }
}

pub(crate) async fn handle_pair_source_create_invite(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    sink: Option<&Arc<dyn PairSourceSink>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match PairSourceCreateInvitePayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = PairSourceCreateInviteResultPayload {
                status: pair_source_status::INTERNAL_ERROR,
                uri: String::new(),
                detail: format!("decode request: {e}").into_bytes(),
            };
            clip_pair_detail(&mut payload.detail);
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::PairSourceCreateInviteResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = sink {
        match sink.create_invite(req.master_password.as_deref()) {
            PairSourceCreateOutcome::Ok { uri } => PairSourceCreateInviteResultPayload {
                status: pair_source_status::OK,
                uri,
                detail: Vec::new(),
            },
            PairSourceCreateOutcome::NotConfigured(d) => PairSourceCreateInviteResultPayload {
                status: pair_source_status::NOT_CONFIGURED,
                uri: String::new(),
                detail: d.into_bytes(),
            },
            PairSourceCreateOutcome::AlreadyInProgress(d) => PairSourceCreateInviteResultPayload {
                status: pair_source_status::ALREADY_IN_PROGRESS,
                uri: String::new(),
                detail: d.into_bytes(),
            },
            PairSourceCreateOutcome::InternalError(d) => PairSourceCreateInviteResultPayload {
                status: pair_source_status::INTERNAL_ERROR,
                uri: String::new(),
                detail: d.into_bytes(),
            },
        }
    } else {
        PairSourceCreateInviteResultPayload {
            status: pair_source_status::INTERNAL_ERROR,
            uri: String::new(),
            detail: b"pair-source sink not wired".to_vec(),
        }
    };
    if payload.uri.len() > MAX_PAIR_URI_LEN {
        payload.status = pair_source_status::INTERNAL_ERROR;
        payload.detail = format!(
            "encoded URI {}B exceeds MAX_PAIR_URI_LEN ({MAX_PAIR_URI_LEN})",
            payload.uri.len()
        )
        .into_bytes();
        payload.uri = String::new();
    }
    clip_pair_detail(&mut payload.detail);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PairSourceCreateInviteResult as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_pair_source_handle_hello(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    sink: Option<&Arc<dyn PairSourceSink>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match PairCeremonyFramePayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = PairCeremonyOobResultPayload {
                status: pair_source_status::INTERNAL_ERROR,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: format!("decode hello: {e}").into_bytes(),
            };
            clip_pair_detail(&mut payload.detail);
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::PairSourceHandleHelloResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = sink {
        match sink.handle_hello(&req.bytes) {
            PairSourceHandleHelloOutcome::Ok {
                cert_bytes,
                oob_code,
            } => PairCeremonyOobResultPayload {
                status: pair_source_status::OK,
                oob_code,
                response_bytes: cert_bytes,
                detail: Vec::new(),
            },
            PairSourceHandleHelloOutcome::WrongState(d) => PairCeremonyOobResultPayload {
                status: pair_source_status::WRONG_STATE,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairSourceHandleHelloOutcome::BadHello(d) => PairCeremonyOobResultPayload {
                status: pair_source_status::BAD_HELLO,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairSourceHandleHelloOutcome::InternalError(d) => PairCeremonyOobResultPayload {
                status: pair_source_status::INTERNAL_ERROR,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: d.into_bytes(),
            },
        }
    } else {
        PairCeremonyOobResultPayload {
            status: pair_source_status::INTERNAL_ERROR,
            oob_code: [0u8; 6],
            response_bytes: Vec::new(),
            detail: b"pair-source sink not wired".to_vec(),
        }
    };
    if payload.response_bytes.len() > MAX_PAIR_CEREMONY_BYTES {
        payload.status = pair_source_status::INTERNAL_ERROR;
        payload.detail = b"cert bytes exceed wire cap".to_vec();
        payload.response_bytes.clear();
        payload.oob_code = [0u8; 6];
    }
    clip_pair_detail(&mut payload.detail);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PairSourceHandleHelloResult as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_pair_source_handle_confirm(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    sink: Option<&Arc<dyn PairSourceSink>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match PairCeremonyFramePayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = PairStatusResultPayload {
                status: pair_source_status::INTERNAL_ERROR,
                detail: format!("decode confirm: {e}").into_bytes(),
            };
            clip_pair_detail(&mut payload.detail);
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::PairSourceHandleConfirmResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = sink {
        match sink.handle_confirm(&req.bytes) {
            PairSourceHandleConfirmOutcome::Ok => PairStatusResultPayload {
                status: pair_source_status::OK,
                detail: Vec::new(),
            },
            PairSourceHandleConfirmOutcome::UserAborted(d) => PairStatusResultPayload {
                status: pair_source_status::USER_ABORTED,
                detail: d.into_bytes(),
            },
            PairSourceHandleConfirmOutcome::BadConfirm(d) => PairStatusResultPayload {
                status: pair_source_status::BAD_CONFIRM,
                detail: d.into_bytes(),
            },
            PairSourceHandleConfirmOutcome::WrongState(d) => PairStatusResultPayload {
                status: pair_source_status::WRONG_STATE,
                detail: d.into_bytes(),
            },
            PairSourceHandleConfirmOutcome::InternalError(d) => PairStatusResultPayload {
                status: pair_source_status::INTERNAL_ERROR,
                detail: d.into_bytes(),
            },
        }
    } else {
        PairStatusResultPayload {
            status: pair_source_status::INTERNAL_ERROR,
            detail: b"pair-source sink not wired".to_vec(),
        }
    };
    clip_pair_detail(&mut payload.detail);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PairSourceHandleConfirmResult as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_pair_target_consume_uri(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    sink: Option<&Arc<dyn PairTargetSink>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match PairTargetConsumeUriPayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = PairCeremonyFrameResultPayload {
                status: pair_target_status::BAD_URI,
                bytes: Vec::new(),
                detail: format!("decode request: {e}").into_bytes(),
            };
            clip_pair_detail(&mut payload.detail);
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::PairTargetConsumeUriResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = sink {
        match sink.consume_uri(&req.uri, req.instance_label.as_deref()) {
            PairTargetConsumeOutcome::Ok { hello_bytes } => PairCeremonyFrameResultPayload {
                status: pair_target_status::OK,
                bytes: hello_bytes,
                detail: Vec::new(),
            },
            PairTargetConsumeOutcome::BadUri(d) => PairCeremonyFrameResultPayload {
                status: pair_target_status::BAD_URI,
                bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairTargetConsumeOutcome::Expired(d) => PairCeremonyFrameResultPayload {
                status: pair_target_status::EXPIRED,
                bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairTargetConsumeOutcome::AlreadyInProgress(d) => PairCeremonyFrameResultPayload {
                status: pair_target_status::ALREADY_IN_PROGRESS,
                bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairTargetConsumeOutcome::InternalError(d) => PairCeremonyFrameResultPayload {
                status: pair_target_status::INTERNAL_ERROR,
                bytes: Vec::new(),
                detail: d.into_bytes(),
            },
        }
    } else {
        PairCeremonyFrameResultPayload {
            status: pair_target_status::INTERNAL_ERROR,
            bytes: Vec::new(),
            detail: b"pair-target sink not wired".to_vec(),
        }
    };
    if payload.bytes.len() > MAX_PAIR_CEREMONY_BYTES {
        payload.status = pair_target_status::INTERNAL_ERROR;
        payload.detail = b"hello bytes exceed wire cap".to_vec();
        payload.bytes.clear();
    }
    clip_pair_detail(&mut payload.detail);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PairTargetConsumeUriResult as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_pair_target_handle_cert(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    sink: Option<&Arc<dyn PairTargetSink>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match PairCeremonyFramePayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = PairCeremonyOobResultPayload {
                status: pair_target_status::BAD_CERT,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: format!("decode cert: {e}").into_bytes(),
            };
            clip_pair_detail(&mut payload.detail);
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::PairTargetHandleCertResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = sink {
        match sink.handle_cert(&req.bytes) {
            PairTargetHandleCertOutcome::Ok { oob_code } => PairCeremonyOobResultPayload {
                status: pair_target_status::OK,
                oob_code,
                response_bytes: Vec::new(),
                detail: Vec::new(),
            },
            PairTargetHandleCertOutcome::BadCert(d) => PairCeremonyOobResultPayload {
                status: pair_target_status::BAD_CERT,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairTargetHandleCertOutcome::WrongState(d) => PairCeremonyOobResultPayload {
                status: pair_target_status::WRONG_STATE,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairTargetHandleCertOutcome::InternalError(d) => PairCeremonyOobResultPayload {
                status: pair_target_status::INTERNAL_ERROR,
                oob_code: [0u8; 6],
                response_bytes: Vec::new(),
                detail: d.into_bytes(),
            },
        }
    } else {
        PairCeremonyOobResultPayload {
            status: pair_target_status::INTERNAL_ERROR,
            oob_code: [0u8; 6],
            response_bytes: Vec::new(),
            detail: b"pair-target sink not wired".to_vec(),
        }
    };
    clip_pair_detail(&mut payload.detail);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PairTargetHandleCertResult as u16,
        &payload.encode(),
    )
    .await
}

pub(crate) async fn handle_pair_target_build_confirm(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    sink: Option<&Arc<dyn PairTargetSink>>,
) -> std::io::Result<()> {
    if !client_state.allow_query() {
        return Ok(());
    }
    let req = match PairTargetBuildConfirmPayload::decode(body) {
        Ok(r) => r,
        Err(e) => {
            let mut payload = PairCeremonyFrameResultPayload {
                status: pair_target_status::INTERNAL_ERROR,
                bytes: Vec::new(),
                detail: format!("decode request: {e}").into_bytes(),
            };
            clip_pair_detail(&mut payload.detail);
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::PairTargetBuildConfirmResult as u16,
                &payload.encode(),
            )
            .await;
        }
    };
    let mut payload = if let Some(sink) = sink {
        match sink.build_confirm(req.confirmed) {
            PairTargetBuildConfirmOutcome::Ok { confirm_bytes } => PairCeremonyFrameResultPayload {
                status: pair_target_status::OK,
                bytes: confirm_bytes,
                detail: Vec::new(),
            },
            PairTargetBuildConfirmOutcome::WrongState(d) => PairCeremonyFrameResultPayload {
                status: pair_target_status::WRONG_STATE,
                bytes: Vec::new(),
                detail: d.into_bytes(),
            },
            PairTargetBuildConfirmOutcome::InternalError(d) => PairCeremonyFrameResultPayload {
                status: pair_target_status::INTERNAL_ERROR,
                bytes: Vec::new(),
                detail: d.into_bytes(),
            },
        }
    } else {
        PairCeremonyFrameResultPayload {
            status: pair_target_status::INTERNAL_ERROR,
            bytes: Vec::new(),
            detail: b"pair-target sink not wired".to_vec(),
        }
    };
    clip_pair_detail(&mut payload.detail);
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::PairTargetBuildConfirmResult as u16,
        &payload.encode(),
    )
    .await
}
