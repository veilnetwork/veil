//! Sparse origin observations for local IPC direct/relay admission. No relay policy,
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
    if let Some(sample) = relay_sample(body) {
        log_sample(stage, local_lane, sample, None);
    }
}

/// Direct RT-send observations use only the originating endpoint's LOCAL IPC
/// envelope. No network receiver or relay inspects a sealed media header.
pub fn sealed_rt_local_sample(stage: &str, local_lane: u8, body: &[u8]) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    if let Some(sample) = rt_sample(body) {
        log_sample(stage, local_lane, sample, None);
    }
}

/// Correlate origin fan-out admission with its first physical hop, not only
/// with the final identity address. The relays receive no extra metadata.
pub(crate) fn sealed_relay_hop_sample(stage: &str, local_lane: u8, hop: &[u8; 32], body: &[u8]) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    if let Some(sample) = relay_sample(body) {
        log_sample(stage, local_lane, sample, Some(hop));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SealedLocalSample {
    destination: [u8; 4],
    epoch: u64,
    seq: u64,
    bytes: usize,
}

fn relay_sample(body: &[u8]) -> Option<SealedLocalSample> {
    let flags = body
        .get(100..104)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    let required = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
        | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
    if flags & required != required || flags & veil_proto::ipc::IPC_SEND_FLAG_REQUIRE_ACK != 0 {
        return None;
    }
    // Borrow the existing bytes. Decoding into PooledShared would copy every
    // video cell even though only one in fifty is sampled, skewing the stand.
    let data = borrowed_data(body, 108)?;
    sealed_sample(body, data)
}

fn rt_sample(body: &[u8]) -> Option<SealedLocalSample> {
    let data = borrowed_data(body, veil_proto::ipc::AppIpcRtSendPayload::FIXED_SIZE)?;
    sealed_sample(body, data)
}

fn borrowed_data(body: &[u8], data_start: usize) -> Option<&[u8]> {
    let length =
        u32::from_be_bytes(body.get(data_start - 4..data_start)?.try_into().ok()?) as usize;
    body.get(data_start..data_start.checked_add(length)?)
}

fn sealed_sample(body: &[u8], data: &[u8]) -> Option<SealedLocalSample> {
    if data.len() < 36 || !data.starts_with(&veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC) {
        return None;
    }
    let epoch = u64::from_be_bytes(data[4..12].try_into().unwrap());
    let seq = u64::from_be_bytes(data[12..20].try_into().unwrap());
    if seq == 0 || !seq.is_multiple_of(50) {
        return None;
    }
    Some(SealedLocalSample {
        destination: body.get(..4)?.try_into().ok()?,
        epoch,
        seq,
        bytes: data.len(),
    })
}

fn log_sample(stage: &str, local_lane: u8, sample: SealedLocalSample, hop: Option<&[u8; 32]>) {
    let at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let hop = hop.map_or_else(|| "local".to_owned(), |id| veil_util::hex_short(id));
    log::info!(
        "ipc.rt_trace.sealed_sample at={} at_ms={at_ms} stage={stage} dst={} local_slot={local_lane} epoch={:016x} seq={} bytes={} hop={hop}",
        at_ms / 1000,
        veil_util::bytes_to_hex(&sample.destination),
        sample.epoch,
        sample.seq,
        sample.bytes,
    );
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
    if header.family != veil_proto::family::FrameFamily::LocalApp as u8 {
        return;
    }
    let Some(body) = frame.get(veil_proto::header::HEADER_SIZE..) else {
        return;
    };
    match veil_proto::family::LocalAppMsg::try_from(header.msg_type) {
        Ok(veil_proto::family::LocalAppMsg::AppIpcSend) => {
            sealed_local_sample(stage, veil_proto::ipc::ipc_local_source_lane(&header), body);
        }
        Ok(veil_proto::family::LocalAppMsg::AppRtSend) => {
            sealed_rt_local_sample(stage, header.priority(), body);
        }
        _ => {}
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::ipc::{AppIpcRtSendPayload, AppIpcSendPayload};

    fn cell(seq: u64) -> Vec<u8> {
        let mut data = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
        data.extend_from_slice(&17u64.to_be_bytes());
        data.extend_from_slice(&seq.to_be_bytes());
        data.extend_from_slice(&[0xa5; 32]);
        data
    }

    fn direct(data: Vec<u8>) -> Vec<u8> {
        AppIpcRtSendPayload {
            dst_node_id: [0x11; 32],
            src_app_id: [0x22; 32],
            dst_app_id: [0x33; 32],
            endpoint_id: 13,
            seq: 500,
            timestamp_us: 987654,
            marker: 0,
            payload_type: 0,
            data,
        }
        .encode()
    }

    fn relay(data: Vec<u8>, flags: u32) -> Vec<u8> {
        let mut body = AppIpcSendPayload {
            dst_node_id: [0x11; 32],
            src_app_id: [0x22; 32],
            app_id: [0x33; 32],
            endpoint_id: 13,
            require_ack: false,
            anonymous: false,
            anonymous_authenticated: false,
            expect_reply: false,
            my_other_devices: false,
            is_reply: false,
            reply_id: 0,
            reply_endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(data),
        }
        .encode();
        body[100..104].copy_from_slice(&flags.to_be_bytes());
        body
    }

    #[test]
    fn typed_local_encoders_correlate_the_same_sealed_cell_without_payload_copy() {
        let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
            | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
        let expected = SealedLocalSample {
            destination: [0x11; 4],
            epoch: 17,
            seq: 50,
            bytes: cell(50).len(),
        };
        assert_eq!(rt_sample(&direct(cell(50))), Some(expected));
        assert_eq!(
            relay_sample(&relay(cell(50), flags)),
            rt_sample(&direct(cell(50)))
        );
        for seq in [0, 1, 49, 51, u64::MAX] {
            assert_eq!(rt_sample(&direct(cell(seq))), None);
            assert_eq!(relay_sample(&relay(cell(seq), flags)), None);
        }
        for excluded in [
            0,
            flags & !veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED,
            flags | veil_proto::ipc::IPC_SEND_FLAG_REQUIRE_ACK,
        ] {
            assert_eq!(relay_sample(&relay(cell(50), excluded)), None);
        }
    }

    #[test]
    fn malformed_and_unsealed_local_inputs_never_produce_a_sample() {
        let body = direct(cell(50));
        for len in 0..body.len() {
            assert_eq!(rt_sample(&body[..len]), None, "truncated at {len}");
        }
        let mut too_long = body.clone();
        too_long[117..121].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(rt_sample(&too_long), None);
        let mut foreign_magic = cell(50);
        foreign_magic[0] ^= 1;
        assert_eq!(rt_sample(&direct(foreign_magic)), None);
        assert_eq!(rt_sample(&direct(cell(50)[..35].to_vec())), None);
        assert_eq!(rt_sample(&direct(vec![0xa5; 1200])), None);
    }
}
