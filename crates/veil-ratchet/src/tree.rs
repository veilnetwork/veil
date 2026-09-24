//! A symmetric chain as a key TREE rather than a hash chain.
//!
//! The chain step of the Double Ratchet walks one key at a time: reaching
//! message `n` costs `n` derivations, and every message skipped on the way has
//! to be banked as its own key. That is why a receiver refuses a gap wider
//! than [`MAX_SKIP`](crate::MAX_SKIP) — and why a gap that wide, which a
//! mailbox holding a week of re-drives produces as a matter of course, used to
//! end the conversation.
//!
//! Here the chain key is instead the root of a binary tree 32 levels deep (the
//! message index is a `u32`), in the GGM construction: each node's two
//! children are two independent PRF outputs of it, and the leaf at index `n`
//! is message key `n`. Any index is 32 derivations away, whatever the gap.
//!
//! Forward secrecy comes from what is KEPT. A [`Holes`] set holds only the
//! roots of subtrees whose indices are still wanted; taking a leaf splits the
//! node that covers it, keeps the siblings along the path and erases the rest.
//! A used key cannot be re-derived from anything left behind, exactly as with
//! the chain. What a gap costs is the number of distinct runs of missing
//! indices, not their length: one contiguous run of any size is covered by at
//! most two nodes per level.
//!
//! Nothing here decides WHEN a chain is a tree. That is negotiated per chain
//! by [`crate::ratchet`] and carried in the frame header.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::KEY_LEN;

/// Levels in the tree: one per bit of the message index.
pub(crate) const TREE_DEPTH: u8 = 32;

/// Left child (index bit 0). Distinct from every chain-layer label, so no tree
/// node can equal a chain key or message key derived from the same input.
const INFO_TREE_LEFT: &[u8] = b"veil.ratchet.v1.tree.0";
/// Right child (index bit 1).
const INFO_TREE_RIGHT: &[u8] = b"veil.ratchet.v1.tree.1";

/// How many subtree roots one chain may hold.
///
/// A receiver in order holds about 32 (the path to the next index); each
/// separate run of missing messages adds up to about 64. So this is roughly
/// thirty independent gaps in one chain before a message is refused — a peer
/// can only get here by genuinely losing that many separate runs, and only
/// with frames that authenticate, because state from a failed tag is thrown
/// away.
pub const MAX_TREE_NODES_PER_CHAIN: usize = 2_048;

/// How many subtree roots one conversation may hold across all its chains.
///
/// The counterpart of [`MAX_SKIP_TOTAL`](crate::MAX_SKIP_TOTAL), and not a
/// second knob: tree chains age by epoch to the current one and the one before
/// it, so this is two chains at [`MAX_TREE_NODES_PER_CHAIN`] — enforced as a
/// runtime check it could never fire. At 37 bytes a node in the stored state,
/// about 150 kB, the same order as the 137 kB the chain's worst case costs. A
/// stored state claiming more is refused on load.
pub const MAX_TREE_NODES_TOTAL: usize = 2 * MAX_TREE_NODES_PER_CHAIN;

/// One child of a node.
pub(crate) fn child(node: &[u8; KEY_LEN], right: bool) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::from_prk(node.as_slice())
        .expect("a 32-byte pseudo-random key is exactly SHA-256's output length");
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(
        if right {
            INFO_TREE_RIGHT
        } else {
            INFO_TREE_LEFT
        },
        out.as_mut(),
    )
    .expect("HKDF-SHA256 with a 32-byte output is always valid");
    out
}

/// Number of indices a node at `depth` covers, as `u64` so the root's 2^32 fits.
fn span(depth: u8) -> u64 {
    1u64 << (TREE_DEPTH - depth)
}

/// The subtree roots still covering wanted indices of ONE chain.
///
/// Keyed by the first index a node covers; nodes never overlap, so the node
/// covering an index is the one with the greatest start at or below it. A
/// `BTreeMap` rather than anything hashed, for the same reason as the chain's
/// skipped-key bank: the stored session must come out byte-identical every
/// time.
#[derive(Clone, Default)]
pub(crate) struct Holes {
    nodes: BTreeMap<u32, (u8, Zeroizing<[u8; KEY_LEN]>)>,
}

impl core::fmt::Debug for Holes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Holes")
            .field("nodes", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl Holes {
    /// A whole chain: every index, under its root.
    pub(crate) fn root(chain_key: &[u8; KEY_LEN]) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(0, (0, Zeroizing::new(*chain_key)));
        Self { nodes }
    }

    /// Rebuild from stored nodes, refusing anything that is not a set of
    /// disjoint, well-formed subtrees. `(start, depth, key)` in any order.
    pub(crate) fn from_nodes(
        nodes: impl IntoIterator<Item = (u32, u8, [u8; KEY_LEN])>,
    ) -> Result<Self, &'static str> {
        let mut map = BTreeMap::new();
        for (start, depth, key) in nodes {
            if depth > TREE_DEPTH {
                return Err("tree node deeper than the tree");
            }
            if u64::from(start) % span(depth) != 0 {
                return Err("tree node not aligned to its depth");
            }
            if map.insert(start, (depth, Zeroizing::new(key))).is_some() {
                return Err("duplicate tree node");
            }
        }
        let mut end = 0u64;
        for (&start, (depth, _)) in &map {
            if u64::from(start) < end {
                return Err("overlapping tree nodes");
            }
            end = u64::from(start) + span(*depth);
        }
        Ok(Self { nodes: map })
    }

    /// `(start, depth, key)` in index order — the canonical stored form.
    pub(crate) fn nodes(&self) -> impl Iterator<Item = (u32, u8, &[u8; KEY_LEN])> {
        self.nodes.iter().map(|(&s, (d, k))| (s, *d, &**k))
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Nodes lying wholly below `index` — the gaps behind the highest index
    /// received, as opposed to the path that covers what is still to come.
    pub(crate) fn len_below(&self, index: u32) -> usize {
        self.nodes
            .range(..index)
            .filter(|(s, (d, _))| u64::from(**s) + span(*d) <= u64::from(index))
            .count()
    }

    /// The node covering `index`, if any: `(start, depth)`.
    fn covering(&self, index: u32) -> Option<(u32, u8)> {
        let (&start, (depth, _)) = self.nodes.range(..=index).next_back()?;
        (u64::from(index) < u64::from(start) + span(*depth)).then_some((start, *depth))
    }

    /// Take the key for `index`, keeping every other index its node covered.
    ///
    /// `None` when nothing covers it: the key was already taken (a replay) or
    /// was never kept (outside the range this chain still wants). Either way
    /// there is nothing to decrypt with, and the set is left untouched.
    pub(crate) fn take_leaf(&mut self, index: u32) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let (start, depth) = self.covering(index)?;
        let (_, mut key) = self.nodes.remove(&start).expect("just found");
        let mut at = start;
        for level in depth..TREE_DEPTH {
            // Bit `level` from the top of the index says which way to go.
            let right = (index >> (TREE_DEPTH - 1 - level)) & 1 == 1;
            let half = span(level + 1) as u32;
            let left_child = child(&key, false);
            let right_child = child(&key, true);
            if right {
                self.nodes.insert(at, (level + 1, left_child));
                at += half;
                key = right_child;
            } else {
                self.nodes.insert(at + half, (level + 1, right_child));
                key = left_child;
            }
        }
        Some(key)
    }

    /// Keep only indices in `lo..hi` (`hi` exclusive, `u64` so 2^32 can end the
    /// range), splitting any node that straddles a boundary and erasing every
    /// key that covered only what falls outside.
    ///
    /// What ends a chain (`0..pn`: nothing past the last index the peer says it
    /// sent can ever arrive) and what a sender does after using an index
    /// (`n + 1..`: its own past is never needed again).
    pub(crate) fn retain(&mut self, lo: u64, hi: u64) {
        let starts: Vec<u32> = self.nodes.keys().copied().collect();
        for start in starts {
            let end = u64::from(start) + span(self.nodes[&start].0);
            if end <= lo || u64::from(start) >= hi {
                self.nodes.remove(&start);
            } else if u64::from(start) < lo || end > hi {
                let (depth, key) = self.nodes.remove(&start).expect("listed");
                self.split_into(start, depth, key, lo, hi);
            }
        }
    }

    fn split_into(
        &mut self,
        start: u32,
        depth: u8,
        key: Zeroizing<[u8; KEY_LEN]>,
        lo: u64,
        hi: u64,
    ) {
        let s = u64::from(start);
        let end = s + span(depth);
        if end <= lo || s >= hi {
            return;
        }
        if s >= lo && end <= hi {
            self.nodes.insert(start, (depth, key));
            return;
        }
        // Straddles a boundary, so it is not a leaf (a leaf spans one index).
        let half = span(depth + 1);
        self.split_into(start, depth + 1, child(&key, false), lo, hi);
        self.split_into((s + half) as u32, depth + 1, child(&key, true), lo, hi);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Leaf `index` straight from the root, by the definition: one child per
    /// bit, most significant first. The reference every set operation is held
    /// to.
    fn leaf(root: &[u8; 32], index: u32) -> [u8; 32] {
        let mut k = Zeroizing::new(*root);
        for level in 0..TREE_DEPTH {
            k = child(&k, (index >> (31 - level)) & 1 == 1);
        }
        *k
    }

    /// Known-answer vectors. Specific to veil's labels, so no external vector
    /// exists; these were computed OUTSIDE this crate (Python's `hmac`, as
    /// HKDF-Expand of one block) rather than read back from the code under
    /// test, and pinned so that a change to the labels, the bit order or the
    /// hash re-keys nothing silently.
    #[test]
    fn tree_known_answer() {
        let root = [0x06u8; 32];
        assert_eq!(
            hex(&*child(&root, false)),
            "83fee08fe21d820d732ed7efa6061a35a8530dcb6d4853d8db0c631b801fb0d7"
        );
        assert_eq!(
            hex(&*child(&root, true)),
            "304255e65ab34f627b0233378bb06ac9a405c56c4c90614dfe366d79c0a59268"
        );
        assert_eq!(
            hex(&leaf(&root, 0)),
            "fd35eb8b393c26672743e6e1fbb2c1b49c68cc0f55f0441469eee93487801dd7"
        );
        assert_eq!(
            hex(&leaf(&root, 1_000_000)),
            "bc5c92287769ccf5e47c7bc269f0864583afb09e965433127946ee048f696b4d"
        );
    }

    #[test]
    fn a_leaf_taken_from_the_set_is_the_leaf_of_the_definition() {
        let root = [0x07u8; 32];
        for index in [0u32, 1, 2, 3, 999, 1_000_000, u32::MAX] {
            let mut h = Holes::root(&root);
            assert_eq!(*h.take_leaf(index).expect("covered"), leaf(&root, index));
        }
    }

    #[test]
    fn every_index_is_taken_once_in_any_order() {
        let root = [0x08u8; 32];
        let mut h = Holes::root(&root);
        let order = [5u32, 0, 7, 3, 1_000_000, 6, 1, 2, 4];
        for i in order {
            assert_eq!(
                *h.take_leaf(i).expect("first time"),
                leaf(&root, i),
                "index {i}"
            );
            assert!(h.take_leaf(i).is_none(), "index {i} twice must be refused");
        }
    }

    /// The whole point: a gap of any length is a handful of nodes, not a key
    /// per missing message.
    #[test]
    fn a_long_gap_costs_nodes_per_level_not_per_message() {
        let root = [0x09u8; 32];
        let mut h = Holes::root(&root);
        h.take_leaf(0).expect("first");
        h.take_leaf(1_000_000).expect("after a million lost");
        assert!(h.len() <= 64, "held {} nodes", h.len());
        // And the gap is still fully openable.
        assert_eq!(*h.take_leaf(500_000).expect("late"), leaf(&root, 500_000));
    }

    #[test]
    fn in_order_receipt_holds_about_one_path() {
        let root = [0x0Au8; 32];
        let mut h = Holes::root(&root);
        let mut most = 0;
        for i in 0..5_000u32 {
            h.take_leaf(i).expect("in order");
            most = most.max(h.len());
        }
        assert!(most <= usize::from(TREE_DEPTH), "held up to {most}");
    }

    #[test]
    fn retain_keeps_exactly_the_range_and_erases_the_rest() {
        let root = [0x0Bu8; 32];
        let mut h = Holes::root(&root);
        h.take_leaf(3).expect("first");
        h.retain(0, 10);
        for i in 0..10u32 {
            if i == 3 {
                assert!(h.take_leaf(i).is_none());
            } else {
                assert_eq!(*h.clone().take_leaf(i).expect("kept"), leaf(&root, i));
            }
        }
        assert!(
            h.clone().take_leaf(10).is_none(),
            "past the end must be gone"
        );
        assert!(h.clone().take_leaf(u32::MAX).is_none());

        let mut s = Holes::root(&root);
        s.retain(1_000, 1u64 << 32);
        assert!(
            s.clone().take_leaf(999).is_none(),
            "below the start must be gone"
        );
        assert_eq!(*s.take_leaf(1_000).expect("kept"), leaf(&root, 1_000));
    }

    #[test]
    fn stored_nodes_round_trip_and_bad_sets_are_refused() {
        let root = [0x0Cu8; 32];
        let mut h = Holes::root(&root);
        h.take_leaf(12).expect("take");
        let stored: Vec<_> = h.nodes().map(|(s, d, k)| (s, d, *k)).collect();
        let mut back = Holes::from_nodes(stored.clone()).expect("round trip");
        assert_eq!(*back.take_leaf(13).expect("kept"), leaf(&root, 13));

        assert!(Holes::from_nodes([(0, 33, [0u8; 32])]).is_err(), "too deep");
        assert!(
            Holes::from_nodes([(1, 31, [0u8; 32])]).is_err(),
            "misaligned"
        );
        assert!(
            Holes::from_nodes([(0, 30, [0u8; 32]), (2, 31, [0u8; 32])]).is_err(),
            "overlapping"
        );
    }
}
