//! Bounded replica storage. Buckets never cross the STORE or response plane:
//! every wire value remains one original, independently signed XS carrier.
use super::*;

pub const MAX_SPACE_DISCOVERY_SAMPLES: usize = 5;
pub const SPACE_DISCOVERY_SAMPLES_MAGIC: [u8; 2] = *b"XB";
pub const SPACE_DISCOVERY_SAMPLE_QUERY_MAGIC: [u8; 3] = *b"XSQ";
const MAX_BUCKET_BYTES: usize =
    4 + MAX_SPACE_DISCOVERY_SAMPLES * (4 + MAX_SPACE_DISCOVERY_RECORD_BYTES);

/// Decode local storage only. The aggregate is not an authenticated wire type.
pub fn decode_space_discovery_samples(bytes: &[u8]) -> Option<Vec<SpaceDiscoveryRecord>> {
    if bytes.len() > MAX_BUCKET_BYTES {
        return None;
    }
    if bytes.get(..2) == Some(&SPACE_DISCOVERY_DHT_MAGIC[..]) {
        return Some(vec![SpaceDiscoveryRecord::from_bytes(bytes)?]);
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(2)? != SPACE_DISCOVERY_SAMPLES_MAGIC || reader.u8()? != 1 {
        return None;
    }
    let count = usize::from(reader.u8()?);
    if !(2..=MAX_SPACE_DISCOVERY_SAMPLES).contains(&count) {
        return None;
    }
    let mut records = Vec::with_capacity(count);
    let mut identities = std::collections::HashSet::new();
    for _ in 0..count {
        let length = reader.u32()? as usize;
        if length > MAX_SPACE_DISCOVERY_RECORD_BYTES {
            return None;
        }
        let record = SpaceDiscoveryRecord::from_bytes(reader.take(length)?)?;
        if !identities.insert((record.space_id, record.holder_node_id)) {
            return None;
        }
        records.push(record);
    }
    (reader.offset == bytes.len()).then_some(records)
}

/// Validate each original signature/key binding; expiry prunes just that row.
pub fn live_space_discovery_samples(
    bytes: &[u8],
    key: &[u8; 32],
    now_ms: u64,
) -> Option<Vec<SpaceDiscoveryRecord>> {
    let mut live = Vec::new();
    for record in decode_space_discovery_samples(bytes)? {
        if record.route.dht_key() != *key {
            return None;
        }
        match record.verify_at(now_ms) {
            Ok(()) => live.push(record),
            Err(SpaceDiscoveryError::Expired) => {}
            Err(_) => return None,
        }
    }
    Some(live)
}

/// Merge one authenticated STORE into a replica's deterministic top-five set.
/// Ranking depends only on replica/Space/holder identities, so refreshing or
/// grinding timestamps/payloads cannot win another sample slot.
pub fn merge_space_discovery_sample(
    existing: Option<&[u8]>,
    incoming: &[u8],
    now_ms: u64,
    replica: &[u8; 32],
) -> Option<Vec<u8>> {
    let candidate = SpaceDiscoveryRecord::from_bytes(incoming)?;
    candidate.verify_at(now_ms).ok()?;
    let key = candidate.route.dht_key();
    let mut records = existing
        .and_then(|bytes| live_space_discovery_samples(bytes, &key, now_ms))
        .unwrap_or_default();
    if let Some(index) = records.iter().position(|record| {
        record.space_id == candidate.space_id && record.holder_node_id == candidate.holder_node_id
    }) {
        if candidate.issued_at_unix_ms <= records[index].issued_at_unix_ms {
            return None;
        }
        records.remove(index);
    }
    let identity = (candidate.space_id, candidate.holder_node_id);
    records.push(candidate);
    records.sort_by_key(|record| sample_rank(replica, record));
    // Space ids are cheap to create. One holder publishing many Spaces under
    // a common token must not consume every slot without another identity.
    let mut holders = std::collections::HashSet::new();
    records.retain(|record| holders.insert(record.holder_node_id));
    records.truncate(MAX_SPACE_DISCOVERY_SAMPLES);
    if !records
        .iter()
        .any(|r| (r.space_id, r.holder_node_id) == identity)
    {
        return None;
    }
    if records.len() == 1 {
        return Some(records[0].to_bytes());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SPACE_DISCOVERY_SAMPLES_MAGIC);
    bytes.extend_from_slice(&[1, records.len() as u8]);
    for record in records {
        let value = record.to_bytes();
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&value);
    }
    Some(bytes)
}

pub fn space_discovery_sample_query(index: usize) -> Option<[u8; 4]> {
    (index < MAX_SPACE_DISCOVERY_SAMPLES).then_some([b'X', b'S', b'Q', index as u8])
}

/// Select one bounded carrier. Legacy empty queries get the first sample;
/// upgraded callers ask for all bounded slots with separate query ids. Old
/// peers ignore the selector and repeat their singleton, which readers dedup.
pub fn space_discovery_sample_for_query(value: &[u8], query: &[u8]) -> Option<Vec<u8>> {
    let index = if query.get(..3) == Some(&SPACE_DISCOVERY_SAMPLE_QUERY_MAGIC[..]) {
        if query.len() != 4 || usize::from(query[3]) >= MAX_SPACE_DISCOVERY_SAMPLES {
            return None;
        }
        usize::from(query[3])
    } else {
        0
    };
    decode_space_discovery_samples(value)?
        .get(index)
        .map(SpaceDiscoveryRecord::to_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seed: u8, issued: u64) -> SpaceDiscoveryRecord {
        SpaceDiscoveryRecord::sign(
            SpaceDiscoveryRoute::Search([42; 32]),
            [17; 32],
            &SigningKey::from_bytes(&[seed; 32]),
            issued,
            issued + 3_600_000,
            b"opaque signed application payload".to_vec(),
        )
    }

    #[test]
    fn space_samples_keep_two_holders_on_every_replica_in_either_order() {
        let first = record(1, 1_000).to_bytes();
        let second = record(2, 1_000).to_bytes();
        for replica in [[3; 32], [4; 32], [5; 32]] {
            for order in [[&first, &second], [&second, &first]] {
                let one = merge_space_discovery_sample(None, order[0], 1_500, &replica).unwrap();
                let two =
                    merge_space_discovery_sample(Some(&one), order[1], 1_500, &replica).unwrap();
                assert_eq!(decode_space_discovery_samples(&two).unwrap().len(), 2);
                let wire: Vec<_> = (0..MAX_SPACE_DISCOVERY_SAMPLES)
                    .filter_map(|i| {
                        space_discovery_sample_for_query(
                            &two,
                            &space_discovery_sample_query(i).unwrap(),
                        )
                    })
                    .collect();
                assert_eq!(wire.len(), 2);
                assert!(wire.contains(&first) && wire.contains(&second));
                assert_eq!(
                    space_discovery_sample_for_query(&two, &[]),
                    Some(wire[0].clone())
                );
            }
        }
    }

    #[test]
    fn space_samples_are_bounded_order_independent_and_refresh_only_their_holder() {
        let values: Vec<_> = (1..=12)
            .map(|seed| record(seed, 1_000).to_bytes())
            .collect();
        let mut forward = None;
        let mut reverse = None;
        for value in &values {
            if let Some(merged) =
                merge_space_discovery_sample(forward.as_deref(), value, 1_500, &[9; 32])
            {
                forward = Some(merged);
            }
        }
        for value in values.iter().rev() {
            if let Some(merged) =
                merge_space_discovery_sample(reverse.as_deref(), value, 1_500, &[9; 32])
            {
                reverse = Some(merged);
            }
        }
        assert_eq!(forward, reverse);
        let before = forward.unwrap();
        let records = decode_space_discovery_samples(&before).unwrap();
        assert_eq!(records.len(), MAX_SPACE_DISCOVERY_SAMPLES);
        let selected = records[0].holder_node_id;
        let seed = (1..=12)
            .find(|s| record(*s, 1_000).holder_node_id == selected)
            .unwrap();
        let refreshed = record(seed, 1_200).to_bytes();
        let after =
            merge_space_discovery_sample(Some(&before), &refreshed, 1_500, &[9; 32]).unwrap();
        let records_after = decode_space_discovery_samples(&after).unwrap();
        assert_eq!(
            records.iter().map(|r| r.holder_node_id).collect::<Vec<_>>(),
            records_after
                .iter()
                .map(|r| r.holder_node_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(records_after[0].issued_at_unix_ms, 1_200);
        assert_eq!(&records_after[1..], &records[1..]);
        assert!(
            merge_space_discovery_sample(
                Some(&after),
                &record(seed, 1_000).to_bytes(),
                1_500,
                &[9; 32]
            )
            .is_none()
        );
        assert!(merge_space_discovery_sample(Some(&after), &refreshed, 1_500, &[9; 32]).is_none());
    }

    #[test]
    fn space_samples_one_identity_cannot_fill_every_slot_with_many_spaces() {
        let mut bucket = None;
        for seed in [1, 2] {
            bucket = merge_space_discovery_sample(
                bucket.as_deref(),
                &record(seed, 1_000).to_bytes(),
                1_500,
                &[9; 32],
            );
        }
        for space in 50..=99 {
            let candidate = SpaceDiscoveryRecord::sign(
                SpaceDiscoveryRoute::Search([42; 32]),
                [space; 32],
                &SigningKey::from_bytes(&[3; 32]),
                1_000,
                3_601_000,
                vec![1],
            );
            if let Some(merged) = merge_space_discovery_sample(
                bucket.as_deref(),
                &candidate.to_bytes(),
                1_500,
                &[9; 32],
            ) {
                bucket = Some(merged);
            }
        }
        let records = decode_space_discovery_samples(&bucket.unwrap()).unwrap();
        assert_eq!(records.len(), 3);
        for seed in [1, 2, 3] {
            assert_eq!(
                records
                    .iter()
                    .filter(|r| r.holder_node_id == record(seed, 1_000).holder_node_id)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn space_samples_expiry_and_invalid_records_do_not_poison_other_holders() {
        let old = record(1, 1_000);
        let fresh = record(2, 3_600_900);
        let one = merge_space_discovery_sample(None, &old.to_bytes(), 3_600_950, &[9; 32]).unwrap();
        let two = merge_space_discovery_sample(Some(&one), &fresh.to_bytes(), 3_600_950, &[9; 32])
            .unwrap();
        let key = old.route.dht_key();
        assert_eq!(
            live_space_discovery_samples(&two, &key, 3_601_000).unwrap(),
            vec![fresh]
        );
        assert!(live_space_discovery_samples(&two, &[0; 32], 3_601_000).is_none());
        let mut forged = record(3, 3_600_900);
        forged.signature[0] ^= 1;
        assert!(
            merge_space_discovery_sample(Some(&two), &forged.to_bytes(), 3_601_000, &[9; 32])
                .is_none()
        );
        assert!(
            merge_space_discovery_sample(Some(&two), &old.to_bytes(), 3_601_000, &[9; 32])
                .is_none()
        );
        assert!(
            merge_space_discovery_sample(None, &two, 3_600_950, &[9; 32]).is_none(),
            "local buckets must never be accepted as authenticated STOREs"
        );
    }

    #[test]
    fn space_samples_maximum_values_fit_individual_wire_budget_and_reject_bad_buckets() {
        let mut bucket: Option<Vec<u8>> = None;
        for seed in 1..=5 {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let record = SpaceDiscoveryRecord::sign(
                SpaceDiscoveryRoute::Search([42; 32]),
                [17; 32],
                &key,
                1_000,
                3_601_000,
                vec![seed; MAX_SPACE_DISCOVERY_PAYLOAD],
            );
            assert_eq!(record.to_bytes().len(), MAX_SPACE_DISCOVERY_RECORD_BYTES);
            bucket = merge_space_discovery_sample(
                bucket.as_deref(),
                &record.to_bytes(),
                1_500,
                &[9; 32],
            );
        }
        let bucket = bucket.unwrap();
        assert!(bucket.len() <= MAX_BUCKET_BYTES);
        for index in 0..5 {
            let value = space_discovery_sample_for_query(
                &bucket,
                &space_discovery_sample_query(index).unwrap(),
            )
            .unwrap();
            assert_eq!(value.len(), MAX_SPACE_DISCOVERY_RECORD_BYTES);
            SpaceDiscoveryRecord::from_bytes(&value)
                .unwrap()
                .verify_at(1_500)
                .unwrap();
        }
        assert!(space_discovery_sample_query(5).is_none());
        assert!(space_discovery_sample_for_query(&bucket, b"XSQ\xff").is_none());
        for end in [0, 1, 3, 4, 8, bucket.len() - 1] {
            assert!(decode_space_discovery_samples(&bucket[..end]).is_none());
        }
        let mut trailing = bucket.clone();
        trailing.push(0);
        assert!(decode_space_discovery_samples(&trailing).is_none());
        let mut excess = bucket.clone();
        excess[3] = 6;
        assert!(decode_space_discovery_samples(&excess).is_none());
    }
}
