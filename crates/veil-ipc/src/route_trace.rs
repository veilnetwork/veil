//! Sparse origin observations for local IPC relay admission. No relay policy,
//! relay payload parsing or wire fields; queue admission is not end-to-end delivery.
//! `datagram_transport` reports live support for this neutral Forward format,
//! not merely generic QUIC readiness and not proof of a particular send path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
type Key = ([u8; 32], [u8; 32], u8, [u8; 32]);
struct Sample {
    logged_at: Instant,
    accepted: u64,
    refused: u64,
}
static SAMPLES: LazyLock<Mutex<HashMap<Key, Sample>>> = LazyLock::new(Default::default);

fn enabled() -> &'static AtomicBool {
    ENABLED.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Embedded-node twin of the existing VEIL_RT_TRACE stand switch.
pub fn set_enabled(on: bool) {
    enabled().store(on, Ordering::Relaxed);
    if !on {
        SAMPLES.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

/// Sample only the existing sealed header of a LOCAL IPC send. This is an
/// observation, never an authorization, routing or scheduling decision. Match
/// its epoch/sequence to the SDK's pre-write and authenticated receive samples.
pub fn sealed_local_sample(stage: &str, local_lane: u8, body: &[u8]) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    let flags = body
        .get(100..104)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    let required = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
        | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
    if flags & required != required || flags & veil_proto::ipc::IPC_SEND_FLAG_REQUIRE_ACK != 0 {
        return;
    }
    // Borrow the existing bytes. Decoding into PooledShared would copy every
    // video cell even though only one in fifty is sampled, skewing the stand.
    let Some(length) = body
        .get(104..108)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
    else {
        return;
    };
    let Some(end) = 108usize.checked_add(length) else {
        return;
    };
    let Some(data) = body.get(108..end) else {
        return;
    };
    if data.len() < 36 || !data.starts_with(&veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC) {
        return;
    }
    let epoch = u64::from_be_bytes(data[4..12].try_into().unwrap());
    let seq = u64::from_be_bytes(data[12..20].try_into().unwrap());
    if seq != 0 && seq.is_multiple_of(50) {
        log::info!(
            "ipc.rt_trace.sealed_sample at={} stage={stage} dst={} local_slot={local_lane} epoch={epoch:016x} seq={seq} bytes={}",
            veil_util::unix_secs_now_u64(),
            veil_util::bytes_to_hex(&body[..4]),
            data.len(),
        );
    }
}

/// Called by the local SDK writer after writing a complete IPC frame, or
/// before dropping it. The daemon entry sample alone cannot prove socket write.
pub fn sealed_local_frame_sample(stage: &str, frame: &[u8]) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    let Ok(header) = veil_proto::codec::decode_header(frame) else {
        return;
    };
    if header.family != veil_proto::family::FrameFamily::LocalApp as u8
        || header.msg_type != veil_proto::family::LocalAppMsg::AppIpcSend as u16
    {
        return;
    }
    let Some(body) = frame.get(veil_proto::header::HEADER_SIZE..) else {
        return;
    };
    sealed_local_sample(stage, veil_proto::ipc::ipc_local_source_lane(&header), body);
}

pub(crate) fn observe(
    local: [u8; 32],
    destination: [u8; 32],
    local_lane: u8,
    hop: [u8; 32],
    accepted: bool,
    datagram_transport: bool,
) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    let now = Instant::now();
    let key = (local, destination, local_lane, hop);
    let snapshot = {
        let mut samples = SAMPLES.lock().unwrap_or_else(|p| p.into_inner());
        let fresh = !samples.contains_key(&key);
        if fresh && samples.len() >= 256 {
            samples.retain(|_, s| now.duration_since(s.logged_at) < Duration::from_secs(10));
            if samples.len() >= 256 {
                return;
            }
        }
        let s = samples.entry(key).or_insert(Sample {
            logged_at: now,
            accepted: 0,
            refused: 0,
        });
        if accepted {
            s.accepted = s.accepted.saturating_add(1);
        } else {
            s.refused = s.refused.saturating_add(1);
        }
        if !fresh && now.duration_since(s.logged_at) < Duration::from_secs(1) {
            return;
        }
        let result = (s.accepted, s.refused);
        s.accepted = 0;
        s.refused = 0;
        s.logged_at = now;
        result
    };
    log::info!(
        "ipc.rt_trace.relay_admission source={} dst={} local_slot={} hop={} accepted={} refused={} datagram_transport={}",
        veil_util::hex_short(&local),
        veil_util::hex_short(&destination),
        local_lane,
        veil_util::hex_short(&hop),
        snapshot.0,
        snapshot.1,
        datagram_transport,
    );
}
