//! DHT keyspace sharding.
//!
//! The 256-byte keyspace is divided into 256 shards (`shard_id = key[0]`).
//! Each node participates in the `MAX_LOCAL_SHARDS` shards closest to its
//! `node_id[0]` by XOR distance. This limits per-node storage while
//! maintaining full keyspace coverage at the network level.
//!
//! # Shard membership
//!
//! ```text
//! local_shards = { s ∈ [0,255] : xor(s, node_id[0]) ranks in top MAX_LOCAL_SHARDS }
//! ```
//!
//! # Cross-shard forwarding
//!
//! When a STORE/FIND_VALUE targets a shard outside `local_shards`, the request
//! is forwarded to the XOR-closest contact whose `node_id[0]` belongs to the
//! target shard.

/// Maximum number of shards a single node participates in.
///
/// 16 shards out of 256 = 6.25% of the keyspace per node.
/// A network needs at least `256 / MAX_LOCAL_SHARDS ≈ 16` storage-capable
/// nodes for full keyspace coverage.
pub const MAX_LOCAL_SHARDS: usize = 16;

/// Compute the shard ID for a DHT key.
#[inline]
pub fn shard_of(key: &[u8; 32]) -> u8 {
    key[0]
}

/// Compute the set of local shards for a node based on its `node_id[0]`.
///
/// Returns up to `MAX_LOCAL_SHARDS` shard IDs, sorted by XOR distance to
/// `node_id[0]` (closest first).
///
/// (tie invariant): when two shards have an
/// identical XOR distance, the lower shard_id wins. This is a
/// deterministic consequence of `sort_by_key`'s stable ordering plus
/// the input being enumerated in ascending shard-id order; we
/// document it here so any future caller can rely on it. An
/// observable consequence: a node's local-shard set is bit-by-bit
/// reproducible across processes and across versions.
pub fn local_shards(node_id: &[u8; 32]) -> Vec<u8> {
    let prefix = node_id[0];
    let mut shards: Vec<(u8, u8)> = (0u16..=255)
        .map(|s| (s as u8, (s as u8) ^ prefix))
        .collect();
    // Stable sort + ascending shard-id input → lower shard_id breaks ties.
    shards.sort_by_key(|&(_, dist)| dist);
    shards
        .into_iter()
        .take(MAX_LOCAL_SHARDS)
        .map(|(s, _)| s)
        .collect()
}

/// Check whether `shard_id` is within a node's local shard set.
pub fn is_local_shard(node_id: &[u8; 32], shard_id: u8) -> bool {
    let prefix = node_id[0];
    let dist = shard_id ^ prefix;
    // Local if XOR distance ≤ the distance of the MAX_LOCAL_SHARDS-th shard.
    // For MAX_LOCAL_SHARDS=16, local shards are the 16 with smallest XOR to prefix.
    // Distance threshold = 15 (0..15 are the 16 closest values).
    (dist as usize) < MAX_LOCAL_SHARDS
}

/// Find the shard ID of a contact's node_id (for routing decisions).
#[inline]
pub fn node_shard_prefix(node_id: &[u8; 32]) -> u8 {
    node_id[0]
}

// ── Shard rebalancing ───────────────────────────────────────────

/// Identify DHT entries that should be transferred to a new node that has
/// joined a shard.
///
/// Returns keys from `local_entries` whose shard is closer (by XOR) to
/// `new_node_id[0]` than to `local_node_id[0]`. These entries should be
/// sent via STORE to the new node.
pub fn entries_to_transfer(
    local_node_id: &[u8; 32],
    new_node_id: &[u8; 32],
    local_entries: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    let local_prefix = local_node_id[0];
    let new_prefix = new_node_id[0];
    local_entries
        .iter()
        .filter(|key| {
            let shard = shard_of(key);
            let dist_local = shard ^ local_prefix;
            let dist_new = shard ^ new_prefix;
            dist_new < dist_local // new node is strictly closer
        })
        .copied()
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_of_uses_first_byte() {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        assert_eq!(shard_of(&key), 0xAB);
    }

    #[test]
    fn local_shards_returns_max_local() {
        let node_id = [0x80u8; 32];
        let shards = local_shards(&node_id);
        assert_eq!(shards.len(), MAX_LOCAL_SHARDS);
        // First shard should be 0x80 (distance 0).
        assert_eq!(shards[0], 0x80);
    }

    #[test]
    fn is_local_shard_consistent_with_local_shards() {
        let node_id = [0x42u8; 32];
        let shards = local_shards(&node_id);
        for &s in &shards {
            assert!(is_local_shard(&node_id, s), "shard {s} should be local");
        }
        // Shards NOT in the set should not be local.
        let non_local: Vec<u8> = (0..=255u8).filter(|s| !shards.contains(s)).collect();
        for &s in non_local.iter().take(10) {
            assert!(
                !is_local_shard(&node_id, s),
                "shard {s} should NOT be local"
            );
        }
    }

    #[test]
    fn local_shards_sorted_by_xor_distance() {
        let node_id = [0x00u8; 32];
        let shards = local_shards(&node_id);
        // node_id[0] = 0x00, so shards 0..15 are the closest (XOR = identity).
        for (i, &s) in shards.iter().enumerate() {
            assert_eq!(s, i as u8);
        }
    }

    #[test]
    fn entries_to_transfer_closer_node() {
        let local = [0x00u8; 32];
        let new_node = [0x10u8; 32]; // closer to shard 0x10 than local
        let mut key_in_shard_10 = [0u8; 32];
        key_in_shard_10[0] = 0x10;
        let mut key_in_shard_00 = [0u8; 32];
        key_in_shard_00[0] = 0x00;
        let entries = vec![key_in_shard_10, key_in_shard_00];
        let to_transfer = entries_to_transfer(&local, &new_node, &entries);
        // key_in_shard_10: dist_local=0x10, dist_new=0x00 → transfer
        // key_in_shard_00: dist_local=0x00, dist_new=0x10 → keep
        assert_eq!(to_transfer.len(), 1);
        assert_eq!(to_transfer[0], key_in_shard_10);
    }
}
