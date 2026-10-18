//! Endpoint-local source framing, never a relay scheduling instruction.
use super::*;

fn frame_size(sealed_bytes: usize, relayed: bool) -> usize {
    let body = if relayed {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        ForwardPayload {
            next_hop_node_id: [0; 32],
            envelope: DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any([0; 32]),
                sender_node_id: [0; 32],
                src_app_id: [0; 32],
                app_id: [0; 32],
                endpoint_id: 0,
                content_id: [0; 32],
                created_at: 1,
                ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
                payload: vec![0; sealed_bytes],
                trace_id: 0,
                require_ack: false,
            },
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: Some(veil_proto::priority::INTERACTIVE),
        }
        .encode()
    } else {
        veil_proto::app::AppRtDataPayload {
            src_app_id: [0; 32],
            app_id: [0; 32],
            endpoint_id: 0,
            seq: 0,
            timestamp_us: 0,
            marker: 0,
            payload_type: 0,
            payload: vec![0; sealed_bytes],
        }
        .encode()
    };
    veil_proto::HEADER_SIZE + body.len()
}

fn estimate(
    packet_bytes: usize,
    relayed: bool,
    paths: &[veil_session::LocalPacketFraming],
) -> Option<serde_json::Value> {
    let frame = frame_size(packet_bytes + media::MEDIA_SEAL_OVERHEAD, relayed);
    let wire: Vec<_> = paths
        .iter()
        .map(|path| path.frame_bytes_x2(frame))
        .collect::<Option<_>>()?;
    let largest = *wire.iter().max()?;
    Some(serde_json::json!({
        "packet_bytes": packet_bytes,
        "per_path_overhead_bytes": largest.checked_sub(2 * packet_bytes)?.div_ceil(2),
        "per_path_wire_bytes_x2": largest,
        "source_wire_bytes_x2": wire.iter().sum::<usize>(),
        "source_copies_limit": paths.len(),
        "ordered_paths": paths.iter().filter(|p| matches!(p, veil_session::LocalPacketFraming::Obfs4Record)).count(),
        "quic_paths": paths.iter().filter(|p| matches!(p, veil_session::LocalPacketFraming::QuicDatagram { .. })).count(),
        "unbatched_model": true
    }))
}

/// Snapshot per-path framing and aggregate replication cost for one RTP packet.
/// Unbatched cost bounds compact batching in expectation, without claiming
/// measured savings or a bound on an individual random padding sample.
/// Obfs4 padding is an expectation; QUIC/TCP/IP are excluded. No packets/RPCs
/// are sent. Null means closed/onion/unprepared/unknown embedded node state.
/// Free a non-null string with veil_free_string. This is not delivery proof.
#[unsafe(no_mangle)]
pub extern "C" fn veil_media_channel_packet_cost(chan: u64, packet_bytes: size_t) -> *mut c_char {
    veil_media_channel_source_packet_cost(chan, veil_proto::priority::REALTIME, packet_bytes)
}

/// Same local framing model on the selected prepared source: 0 audio, 2 video,
/// 3 screen. These selectors are local only; no media role is sent to relays.
/// Video/screen never inherit audio's small-packet replication policy.
#[unsafe(no_mangle)]
pub extern "C" fn veil_media_channel_source_packet_cost(
    chan: u64,
    local_lane: u8,
    packet_bytes: size_t,
) -> *mut c_char {
    if !matches!(local_lane, 0 | 2 | 3) {
        return ptr::null_mut();
    }
    if !(12..=1000).contains(&packet_bytes) {
        return ptr::null_mut();
    }
    let (bundle, peer, relay) = {
        let Ok(channels) = MEDIA_CHANNELS.try_read() else {
            return ptr::null_mut();
        };
        let Some(channel) = channels.get(&chan) else {
            return ptr::null_mut();
        };
        let Some(bundle) = &channel.cost_context else {
            return ptr::null_mut();
        };
        (bundle.clone(), channel.peer, channel.relay_stats.is_some())
    };
    // Boot's get_node_id already supplies this authenticated local id. Cost
    // polling must never acquire the client RPC mutex or guess a latest node.
    let Some(me) = bundle.cached_node_id.try_lock().ok().and_then(|id| *id) else {
        return ptr::null_mut();
    };
    let Some(services) = veil_node_runtime::embedded_services_for(&me) else {
        return ptr::null_mut();
    };
    let sealed_bytes = packet_bytes + media::MEDIA_SEAL_OVERHEAD;
    let copies_limit = source_copies_limit(local_lane, relay, sealed_bytes);
    let Some(paths) =
        services.local_source_framing(&peer, local_lane, relay, copies_limit)
    else {
        return ptr::null_mut();
    };
    let Some(cost) = estimate(packet_bytes, relay, &paths) else {
        return ptr::null_mut();
    };
    CString::new(cost.to_string())
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

fn source_copies_limit(local_lane: u8, relayed: bool, sealed_bytes: usize) -> usize {
    if local_lane == veil_proto::priority::REALTIME && relayed && sealed_bytes <= 512 {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_session::LocalPacketFraming::{Obfs4Record, QuicDatagram};
    #[test]
    fn serialized_routes_carriers_and_replication_are_distinct() {
        let quic = QuicDatagram { ceiling: 1382 };
        for size in [40, 200, 480] {
            let direct = estimate(size, false, &[quic]).unwrap();
            let relay = estimate(size, true, &[quic, quic]).unwrap();
            let ordered = estimate(size, true, &[Obfs4Record]).unwrap();
            assert_eq!(direct["per_path_overhead_bytes"], 209);
            assert_eq!(relay["per_path_overhead_bytes"], 360);
            assert_eq!(relay["source_copies_limit"], 2);
            assert_eq!(
                relay["source_wire_bytes_x2"].as_u64().unwrap(),
                2 * relay["per_path_wire_bytes_x2"].as_u64().unwrap()
            );
            assert_eq!(ordered["per_path_overhead_bytes"], 509);
        }
        // Fragmented ordered delivery must count both opaque and obfs4 records.
        assert!(
            estimate(1000, true, &[Obfs4Record]).unwrap()["per_path_overhead_bytes"]
                .as_u64()
                .unwrap()
                > 509
        );
        assert!(estimate(200, true, &[]).is_none());
        assert!(veil_media_channel_packet_cost(0, 200).is_null());
        assert!(veil_media_channel_packet_cost(0, usize::MAX).is_null());
    }

    #[test]
    fn source_selection_does_not_charge_video_for_audio_replication() {
        assert_eq!(source_copies_limit(0, true, 512), 2);
        assert_eq!(source_copies_limit(0, true, 513), 1);
        assert_eq!(source_copies_limit(0, false, 200), 1);
        for lane in [2, 3] {
            assert_eq!(source_copies_limit(lane, true, 200), 1);
            assert_eq!(source_copies_limit(lane, false, 200), 1);
        }
        for lane in [1, 4, 255] {
            assert!(veil_media_channel_source_packet_cost(0, lane, 200).is_null());
        }
    }
}
