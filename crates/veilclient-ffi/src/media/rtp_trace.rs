//! Endpoint-only RTP-to-sealed-cell witnesses. Receive callers authenticate
//! first. Logs retain header metadata, never payloads or cipher key identity.

#[derive(Debug, PartialEq, Eq)]
struct Rtp {
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
    payload_bytes: usize,
}

fn rtp(packet: &[u8]) -> Option<Rtp> {
    if packet.len() < 12 || packet[0] >> 6 != 2 || (64..=95).contains(&(packet[1] & 127)) {
        return None;
    }
    let mut header = 12 + usize::from(packet[0] & 15) * 4;
    if packet[0] & 16 != 0 {
        let extension = packet.get(header..header.checked_add(4)?)?;
        let words = usize::from(u16::from_be_bytes([extension[2], extension[3]]));
        header = header.checked_add(4)?.checked_add(words.checked_mul(4)?)?;
    }
    let mut payload_bytes = packet.len().checked_sub(header)?;
    if packet[0] & 32 != 0 {
        let padding = usize::from(*packet.last()?);
        if padding == 0 {
            return None;
        }
        payload_bytes = payload_bytes.checked_sub(padding)?;
    }
    if payload_bytes == 0 {
        return None;
    }
    Some(Rtp {
        ssrc: u32::from_be_bytes(packet[8..12].try_into().ok()?),
        sequence: u16::from_be_bytes(packet[2..4].try_into().ok()?),
        timestamp: u32::from_be_bytes(packet[4..8].try_into().ok()?),
        payload_bytes,
    })
}

// Validate an entire bounded batch before emitting even its first witness.
// Stack-only packet slices; no allocation or retained borrowed data.
fn packets(cell: &[u8], mut visit: impl FnMut(usize, &[u8])) -> Option<()> {
    if cell.first() != Some(&super::MEDIA_BATCH_MAGIC) {
        visit(0, cell);
        return Some(());
    }
    let count = usize::from(u16::from_be_bytes(cell.get(1..3)?.try_into().ok()?));
    if !(1..=64).contains(&count) {
        return None;
    }
    let mut selected: [&[u8]; 64] = [&[]; 64];
    let mut offset: usize = 3;
    for slot in &mut selected[..count] {
        let length_end = offset.checked_add(2)?;
        let length = usize::from(u16::from_be_bytes(
            cell.get(offset..length_end)?.try_into().ok()?,
        ));
        if length == 0 {
            return None;
        }
        offset = length_end.checked_add(length)?;
        *slot = cell.get(length_end..offset)?;
    }
    if offset != cell.len() {
        return None;
    }
    for (index, packet) in selected[..count].iter().enumerate() {
        visit(index, packet);
    }
    Some(())
}

pub(super) fn record(stage: &str, sealed: &[u8], plaintext: &[u8]) {
    if !veil_session::rt_trace::rt_trace_enabled()
        || sealed.len() < super::MEDIA_SEALED_HEADER_LEN
        || !sealed.starts_with(&super::MEDIA_SEALED_MAGIC)
    {
        return;
    }
    let epoch = u64::from_be_bytes(sealed[4..12].try_into().unwrap());
    let sequence = u64::from_be_bytes(sealed[12..20].try_into().unwrap());
    if !veil_util::sealed_trace::sample(sequence) {
        return;
    }
    let _ = packets(plaintext, |index, packet| {
        let Some(rtp) = rtp(packet) else { return };
        let monotonic_us = veil_util::diagnostic_clock::monotonic_us().map_or(-1i128, i128::from);
        log::info!(
            "media.rtp.cell stage={stage} monotonic_us={monotonic_us} epoch={epoch:016x} seq={sequence} index={index} ssrc={} rtp_seq={} timestamp={} payload_bytes={}",
            rtp.ssrc,
            rtp.sequence,
            rtp.timestamp,
            rtp.payload_bytes,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audio() -> Vec<u8> {
        vec![
            0x80, 0xef, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfc, 0, 0, 0, 7, 1, 2,
        ]
    }

    #[test]
    fn rtp_header_witness_preserves_wrapped_values_and_marker() {
        assert_eq!(
            rtp(&audio()),
            Some(Rtp {
                ssrc: 7,
                sequence: 65534,
                timestamp: 4294967292,
                payload_bytes: 2,
            })
        );
        let mut video = audio();
        video[1] = 96;
        assert_eq!(rtp(&video).unwrap().payload_bytes, 2);
    }

    #[test]
    fn rtcp_padding_and_malformed_headers_do_not_become_rtp_witnesses() {
        for end in 0..=12 {
            assert!(rtp(&audio()[..end]).is_none());
        }
        for pt in 192..=223 {
            let mut packet = audio();
            packet[1] = pt;
            assert!(rtp(&packet).is_none());
        }
        let mut packet = audio();
        packet[0] = 0xa0;
        assert!(rtp(&packet).is_none()); // Entire payload is padding.
        packet[13] = 0;
        assert!(rtp(&packet).is_none());
        packet[13] = 3;
        assert!(rtp(&packet).is_none());
        packet[0] = 0x8f; // Missing CSRCs.
        assert!(rtp(&packet).is_none());
        packet[0] = 0x90; // Missing extension body.
        assert!(rtp(&packet).is_none());
    }

    #[test]
    fn csrc_extension_and_padding_are_excluded_from_payload_size() {
        let mut packet = audio()[..12].to_vec();
        packet[0] = 0xb1;
        packet.extend([0, 0, 0, 8]); // One CSRC.
        packet.extend([0xbe, 0xde, 0, 1, 0, 0, 0, 0]);
        packet.extend([1, 2, 0, 2]); // Two payload bytes, two padding bytes.
        assert_eq!(rtp(&packet).unwrap().payload_bytes, 2);
        packet[18] = 255;
        packet[19] = 255;
        assert!(rtp(&packet).is_none());
    }

    #[test]
    fn batches_keep_each_packet_identity_and_reject_partial_corruption() {
        let first = audio();
        let mut second = audio();
        second[3] = 255;
        let body = super::super::encode_batch(&[first, second], 1024).unwrap();
        let cell = [&[super::super::MEDIA_BATCH_MAGIC], body.as_slice()].concat();
        let mut rows = Vec::new();
        packets(&cell, |i, p| rows.push((i, rtp(p).unwrap().sequence))).unwrap();
        assert_eq!(rows, [(0, 65534), (1, 65535)]);
        for bad in [
            &cell[..cell.len() - 1],
            &[super::super::MEDIA_BATCH_MAGIC, 0, 65][..],
            &[super::super::MEDIA_BATCH_MAGIC, 0, 0][..],
        ] {
            let mut emitted = false;
            assert!(packets(bad, |_, _| emitted = true).is_none());
            assert!(!emitted);
        }
    }
}
