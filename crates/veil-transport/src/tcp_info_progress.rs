//! Optional Linux TCP_INFO extensions. Native-endian UAPI offsets are also
//! checked against the Android NDK in device qualification. A short kernel
//! reply means unknown, even when the caller's unused buffer contains zeros.

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ByteProgress {
    pub sent_bytes: Option<u64>,
    pub acked_bytes: Option<u64>,
    pub received_bytes: Option<u64>,
    pub retransmitted_bytes: Option<u64>,
    pub rto_retries: Option<u8>,
    pub rto_backoff: Option<u8>,
}

fn native_u64(raw: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        raw.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

pub(super) fn read(raw: &[u8]) -> ByteProgress {
    ByteProgress {
        sent_bytes: native_u64(raw, 200),
        acked_bytes: native_u64(raw, 120),
        received_bytes: native_u64(raw, 128),
        retransmitted_bytes: native_u64(raw, 208),
        rto_retries: raw.get(2).copied(),
        rto_backoff: raw.get(4).copied(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_truncated_prefix_keeps_unavailable_counters_unknown() {
        let mut raw = [0; 232];
        let values = [
            (120, 0x1122_3344_5566_7788u64),
            (128, 0x8877_6655_4433_2211),
            (200, u64::MAX - 1),
            (208, 1u64 << 40),
        ];
        for (offset, value) in values {
            raw[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
        raw[2] = 3;
        raw[4] = 2;
        for length in 0..=raw.len() {
            let counters = read(&raw[..length]);
            for ((offset, expected), actual) in values.into_iter().zip([
                counters.acked_bytes,
                counters.received_bytes,
                counters.sent_bytes,
                counters.retransmitted_bytes,
            ]) {
                assert_eq!(actual, (length >= offset + 8).then_some(expected));
            }
            assert_eq!(counters.rto_retries, (length >= 3).then_some(3));
            assert_eq!(counters.rto_backoff, (length >= 5).then_some(2));
        }
    }

    #[test]
    fn a_supported_zero_counter_is_different_from_missing_data() {
        let raw = [0; 216];
        assert_eq!(read(&raw).sent_bytes, Some(0));
        assert_eq!(read(&raw[..207]).sent_bytes, None);
        assert_eq!(read(&raw).retransmitted_bytes, Some(0));
        assert_eq!(read(&raw[..215]).retransmitted_bytes, None);
    }
}
