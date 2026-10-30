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

/// Process-local receipt boundaries, recorded without publishing an
/// unauthenticated cell's header. The owning SDK consumes these observations
/// only after opening the cell with its channel key. Nothing travels on IPC or
/// the network; a separate-process SDK simply has no daemon observation.
#[derive(Clone, Copy)]
pub enum LocalDeliveryStage {
    DaemonQueued,
    DaemonEncode,
    SdkRead,
}

#[derive(Default)]
struct LocalDeliveryTimes {
    daemon_queued: Option<Instant>,
    daemon: Option<Instant>,
    sdk: Option<Instant>,
}

#[derive(Default)]
struct LocalDeliveries(HashMap<[u8; 32], LocalDeliveryTimes>);

impl LocalDeliveries {
    const CAP: usize = 256;
    const TTL: Duration = Duration::from_secs(30);

    #[cfg(test)]
    fn record(&mut self, digest: [u8; 32], stage: LocalDeliveryStage, now: Instant) {
        self.record_at(digest, stage, now, now);
    }

    fn record_at(
        &mut self,
        digest: [u8; 32],
        stage: LocalDeliveryStage,
        observed_at: Instant,
        now: Instant,
    ) {
        if now.saturating_duration_since(observed_at) >= Self::TTL {
            return;
        }
        self.0.retain(|_, times| {
            times
                .daemon_queued
                .or(times.daemon)
                .or(times.sdk)
                .is_some_and(|first| now.saturating_duration_since(first) < Self::TTL)
        });
        if !self.0.contains_key(&digest) && self.0.len() >= Self::CAP {
            return;
        }
        let times = self.0.entry(digest).or_default();
        match stage {
            LocalDeliveryStage::DaemonQueued => times.daemon_queued.get_or_insert(observed_at),
            LocalDeliveryStage::DaemonEncode => times.daemon.get_or_insert(observed_at),
            LocalDeliveryStage::SdkRead => times.sdk.get_or_insert(observed_at),
        };
    }

    fn take(&mut self, digest: &[u8; 32], now: Instant) -> Option<LocalDeliveryAges> {
        let times = self.0.remove(digest)?;
        let age = |stamp: Option<Instant>| {
            stamp.and_then(|at| {
                let elapsed = now.saturating_duration_since(at);
                (elapsed < Self::TTL).then(|| elapsed.as_micros().min(i64::MAX as u128) as i64)
            })
        };
        Some(LocalDeliveryAges {
            daemon_queue_age_us: age(times.daemon_queued),
            daemon_age_us: age(times.daemon),
            sdk_age_us: age(times.sdk),
        })
    }
}

static LOCAL_DELIVERIES: LazyLock<Mutex<LocalDeliveries>> = LazyLock::new(Default::default);

/// Ages measured on this process's monotonic clock, not a remote clock.
pub struct LocalDeliveryAges {
    pub daemon_queue_age_us: Option<i64>,
    pub daemon_age_us: Option<i64>,
    pub sdk_age_us: Option<i64>,
}

fn delivery_digest(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 36 || !data.starts_with(&veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC) {
        return None;
    }
    let seq = u64::from_be_bytes(data[12..20].try_into().ok()?);
    // Inspect only a fixed encrypted header for sparse sampling. Hash the
    // ENTIRE ciphertext so an unverified header cannot alias an authentic cell.
    (seq == 1 || (seq != 0 && seq.is_multiple_of(50))).then(|| *blake3::hash(data).as_bytes())
}

/// Record a bounded, silent observation on the locally terminating delivery
/// path. This never authorizes, classifies or schedules a network packet.
pub fn observe_local_delivery(stage: LocalDeliveryStage, data: &[u8]) {
    observe_local_delivery_at(stage, data, Instant::now());
}

/// Record a timestamp already established by this terminal's local queue.
/// The caller cannot supply a remote timestamp through a protocol frame.
pub fn observe_local_delivery_at(stage: LocalDeliveryStage, data: &[u8], observed_at: Instant) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    let Some(digest) = delivery_digest(data) else {
        return;
    };
    let mut samples = LOCAL_DELIVERIES.lock().unwrap_or_else(|p| p.into_inner());
    if enabled().load(Ordering::Relaxed) {
        samples.record_at(digest, stage, observed_at, Instant::now());
    }
}

/// Consume timings only AFTER the endpoint authenticates `data`. Observations
/// that never authenticate expire without a log. Missing stages remain unknown.
pub fn authenticated_local_delivery_ages(data: &[u8]) -> Option<LocalDeliveryAges> {
    if !enabled().load(Ordering::Relaxed) {
        return None;
    }
    let digest = delivery_digest(data)?;
    LOCAL_DELIVERIES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take(&digest, Instant::now())
}

fn enabled() -> &'static AtomicBool {
    ENABLED.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Observe the same switch without adding a dependency on the session crate.
pub(crate) fn is_enabled() -> bool {
    enabled().load(Ordering::Relaxed)
}

/// Embedded-node twin of the existing VEIL_RT_TRACE stand switch.
pub fn set_enabled(on: bool) {
    enabled().store(on, Ordering::Relaxed);
    if !on {
        SAMPLES.lock().unwrap_or_else(|p| p.into_inner()).clear();
        LOCAL_DELIVERIES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .clear();
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
        .get(veil_proto::AppIpcSendPayload::FLAGS_RANGE)
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
    // A fresh candidate sends its delivery probe as sequence one. Sampling
    // only later RTP packets hid exactly the first send needed to locate a
    // failed handover. This remains opt-in endpoint metadata, never a wire
    // feature or relay classification.
    if !veil_util::sealed_trace::sample(seq) {
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
    let hop = hop.map_or_else(|| "local".to_owned(), veil_util::hex_short);
    let monotonic_us = veil_util::diagnostic_clock::monotonic_us().map_or(-1i128, i128::from);
    log::info!(
        "ipc.rt_trace.sealed_sample at={} at_ms={at_ms} monotonic_us={monotonic_us} stage={stage} dst={} local_slot={local_lane} epoch={:016x} seq={} bytes={} hop={hop}",
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
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
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
        let first = SealedLocalSample {
            destination: [0x11; 4],
            epoch: 17,
            seq: 1,
            bytes: cell(1).len(),
        };
        assert_eq!(rt_sample(&direct(cell(1))), Some(first));
        assert_eq!(
            relay_sample(&relay(cell(1), flags)),
            rt_sample(&direct(cell(1)))
        );
        for seq in [0, 2, 49, 51, u64::MAX] {
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

    #[test]
    fn terminal_queue_wait_is_distinct_from_encode_and_sdk_waits() {
        let queued_at = Instant::now();
        let digest = delivery_digest(&cell(50)).unwrap();
        let mut samples = LocalDeliveries::default();
        let encoded_at = queued_at + Duration::from_millis(80);
        samples.record_at(
            digest,
            LocalDeliveryStage::DaemonQueued,
            queued_at,
            encoded_at,
        );
        samples.record(digest, LocalDeliveryStage::DaemonEncode, encoded_at);
        samples.record(
            digest,
            LocalDeliveryStage::SdkRead,
            queued_at + Duration::from_millis(100),
        );
        // Duplicate local receipts retain the original terminal queue entry.
        samples.record_at(
            digest,
            LocalDeliveryStage::DaemonQueued,
            queued_at + Duration::from_millis(60),
            encoded_at,
        );
        let ages = samples
            .take(&digest, queued_at + Duration::from_millis(120))
            .unwrap();
        assert_eq!(ages.daemon_queue_age_us, Some(120_000));
        assert_eq!(ages.daemon_age_us, Some(40_000));
        assert_eq!(ages.sdk_age_us, Some(20_000));

        let too_late = queued_at + LocalDeliveries::TTL;
        samples.record_at(
            digest,
            LocalDeliveryStage::DaemonQueued,
            queued_at,
            too_late,
        );
        assert!(samples.take(&digest, too_late).is_none());
    }

    #[test]
    fn authenticated_delivery_timing_keeps_first_receipt_and_unknown_stages() {
        let now = Instant::now();
        let digest = delivery_digest(&cell(50)).unwrap();
        let mut samples = LocalDeliveries::default();
        samples.record(digest, LocalDeliveryStage::DaemonEncode, now);
        samples.record(
            digest,
            LocalDeliveryStage::SdkRead,
            now + Duration::from_millis(150),
        );
        // A duplicate ciphertext must not erase time spent in the first queue.
        samples.record(
            digest,
            LocalDeliveryStage::SdkRead,
            now + Duration::from_millis(200),
        );
        let ages = samples
            .take(&digest, now + Duration::from_millis(250))
            .unwrap();
        assert_eq!(ages.daemon_age_us, Some(250_000));
        assert_eq!(ages.sdk_age_us, Some(100_000));
        assert!(
            samples
                .take(&digest, now + Duration::from_millis(251))
                .is_none()
        );

        // Separate-process IPC cannot supply a local daemon stamp.
        samples.record(digest, LocalDeliveryStage::SdkRead, now);
        let ages = samples
            .take(&digest, now + Duration::from_millis(20))
            .unwrap();
        assert_eq!(ages.daemon_age_us, None);
        assert_eq!(ages.sdk_age_us, Some(20_000));
    }

    #[test]
    fn unverified_delivery_observations_are_bounded_expire_and_cannot_alias() {
        let now = Instant::now();
        let mut samples = LocalDeliveries::default();
        for i in 0..LocalDeliveries::CAP {
            let mut data = cell(50);
            data.extend_from_slice(&i.to_be_bytes());
            samples.record(
                delivery_digest(&data).unwrap(),
                LocalDeliveryStage::SdkRead,
                now,
            );
        }
        let authentic = cell(100);
        let digest = delivery_digest(&authentic).unwrap();
        samples.record(digest, LocalDeliveryStage::SdkRead, now);
        assert_eq!(samples.0.len(), LocalDeliveries::CAP);
        assert!(
            samples.take(&digest, now).is_none(),
            "overflow is unknown, not a fabricated timing"
        );
        samples.record(
            digest,
            LocalDeliveryStage::SdkRead,
            now + LocalDeliveries::TTL,
        );
        assert_eq!(samples.0.len(), 1);
        let ages = samples
            .take(&digest, now + LocalDeliveries::TTL * 2)
            .unwrap();
        assert_eq!(ages.sdk_age_us, None, "expired timings are never current");

        let mut forged = authentic.clone();
        forged[35] ^= 1;
        assert_eq!(&forged[..20], &authentic[..20]);
        let forged_digest = delivery_digest(&forged).unwrap();
        assert_ne!(
            forged_digest, digest,
            "same unverified epoch/sequence cannot alias a ciphertext"
        );
        samples.record(forged_digest, LocalDeliveryStage::SdkRead, now);
        assert!(samples.take(&digest, now).is_none());
        assert!(delivery_digest(&cell(1)).is_some());
        for seq in [0, 2, 49, 51] {
            assert!(delivery_digest(&cell(seq)).is_none());
        }
        assert!(delivery_digest(&authentic[..35]).is_none());
        assert!(delivery_digest(&[0xa5; 100]).is_none());
    }
}
