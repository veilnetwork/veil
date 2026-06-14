//! Kademlia routing table.
//!
//! Implements an XOR-metric k-bucket routing table. Each bucket holds at most
//! `K` contacts that are "close" to the local node within a specific bit-range
//! of the 256-bit XOR space.
//!
//! # Design
//!
//! * 256 buckets — one per bit position of the XOR distance.
//! * Each bucket is a `VecDeque<Contact>` capped at `K`.
//! * Contacts are ordered LRU: most recently seen at the back.
//! * `find_closest(target, k)` returns the `k` closest contacts across all
//!   buckets, sorted by XOR distance ascending.
//!
//! This is a simplified but correct Kademlia routing table. Network I/O
//! (ping/eviction) is out of scope — it belongs in the connector layer.

use std::collections::VecDeque;
use std::net::IpAddr;

use veil_proto::budget::{
    DHT_BUCKET_BACKOFF_BASE_SECS, DHT_BUCKET_BACKOFF_MAX_SECS, DHT_BUCKET_TOKEN_REFILL_PER_SEC,
    DHT_BUCKET_TOKENS_MAX, MAX_NODES_PER_AS16_PER_BUCKET,
};
use veil_proto::discovery::NodeContact;

/// Default bucket size (k = 20 per the Kademlia paper).
pub const K: usize = 20;

/// Maximum number of contacts from the same /24 IPv4 (or /48 IPv6) subnet
/// allowed in a single k-bucket. Limits Eclipse attacks where an adversary
/// fills an entire bucket with nodes from one address block.
///
/// Value: `K / 4 = 5` — one quarter of the bucket.
pub const MAX_NODES_PER_SUBNET_PER_BUCKET: usize = K / 4;

// ── XOR distance ──────────────────────────────────────────────────────────────

/// Compute the XOR distance between two 32-byte keys.
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Compute the bucket index for a distance value.
///
/// Returns the index of the most-significant set bit in `distance`, or 0 if
/// the distance is zero (same node — should never be stored).
pub fn bucket_index(distance: &[u8; 32]) -> usize {
    for (byte_idx, &byte) in distance.iter().enumerate() {
        if byte != 0 {
            let bit_offset = byte.leading_zeros() as usize;
            return byte_idx * 8 + bit_offset;
        }
    }
    255 // same key — sentinel (bucket 255 is for self, never used in practice)
}

// ── Contact ───────────────────────────────────────────────────────────────────

/// A routing-table entry.
///
/// `discovery_mode` is the peer's last-known DHT-discoverability
/// preference, populated from `CapabilitiesPayload.discovery_mode` at OVL1
/// handshake time. `handle_find_node_v2` filters to Public-only before
/// returning contacts, so this field gates which peers we advertise to
/// other nodes via the DHT. Defaults to `Public` for legacy paths
/// (`Contact::new`, `From<NodeContact>`, deserialised legacy snapshots).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Contact {
    pub node_id: [u8; 32],
    pub transport: String,
    /// `0` = Public, `1` = ContactsOnly, `2` = IntroductionOnly.
    /// Stored as raw u8 (not the typed enum) so legacy persisted snapshots
    /// without this field deserialise cleanly to `0` (Public).
    #[serde(default)]
    pub discovery_mode: u8,
}

impl Contact {
    /// Construct a Contact with default `discovery_mode = Public`. Used
    /// from legacy code paths and tests; production handshake code uses
    /// [`Self::with_mode`] to record the peer's actual mode.
    pub fn new(node_id: [u8; 32], transport: impl Into<String>) -> Self {
        Self {
            node_id,
            transport: transport.into(),
            discovery_mode: 0,
        }
    }

    /// build a Contact with the peer's last-known
    /// `discovery_mode`. Called from outbound + inbound handshake-complete
    /// paths after reading `OvlHandshakeResult.remote_capabilities`.
    pub fn with_mode(
        node_id: [u8; 32],
        transport: impl Into<String>,
        mode: veil_types::DiscoveryMode,
    ) -> Self {
        let discovery_mode = match mode {
            veil_types::DiscoveryMode::Public => 0,
            veil_types::DiscoveryMode::ContactsOnly => 1,
            veil_types::DiscoveryMode::IntroductionOnly => 2,
        };
        Self {
            node_id,
            transport: transport.into(),
            discovery_mode,
        }
    }

    /// typed accessor for the `discovery_mode` byte.
    /// Unknown values map to `IntroductionOnly` (most-restrictive
    /// forward-compat default — see `parse_discovery_mode` on
    /// `CapabilitiesPayload`).
    pub fn discovery_mode(&self) -> veil_types::DiscoveryMode {
        match self.discovery_mode {
            0 => veil_types::DiscoveryMode::Public,
            1 => veil_types::DiscoveryMode::ContactsOnly,
            _ => veil_types::DiscoveryMode::IntroductionOnly,
        }
    }

    pub fn to_node_contact(&self) -> NodeContact {
        NodeContact {
            node_id: self.node_id,
            transport: self.transport.clone(),
        }
    }
}

impl From<NodeContact> for Contact {
    fn from(nc: NodeContact) -> Self {
        Self {
            node_id: nc.node_id,
            transport: nc.transport,
            discovery_mode: 0,
        }
    }
}

// ── Subnet diversity helpers ──────────────────────────────────────────────────

/// Extract a /24 (IPv4) or /48 (IPv6) subnet prefix from a transport URL.
///
/// Returns `None` for non-IP transports (e.g. BLE, in-memory test strings)
/// and for parse failures.
fn subnet_prefix(transport: &str) -> Option<SubnetKey> {
    let host = host_from_transport(transport);
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // /24 prefix: first 3 octets
            Some(SubnetKey::V4([octets[0], octets[1], octets[2]]))
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // /48 prefix: first 3 16-bit segments
            Some(SubnetKey::V6([segs[0], segs[1], segs[2]]))
        }
    }
}

/// A /24 IPv4 or /48 IPv6 subnet identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SubnetKey {
    V4([u8; 3]),
    V6([u16; 3]),
}

/// AS-proxy prefix — /16 IPv4 or /32 IPv6.
/// Used as a coarse stand-in for an autonomous-system membership check
/// without an external GeoIP/ASN dataset on disk. See
/// [`MAX_NODES_PER_AS16_PER_BUCKET`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum As16Key {
    V4([u8; 2]),
    V6([u16; 2]),
}

/// Extract a /16 (IPv4) or /32 (IPv6) AS-proxy prefix from a transport URL.
/// Returns `None` for non-IP transports.
fn as16_prefix(transport: &str) -> Option<As16Key> {
    let host = host_from_transport(transport);
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(As16Key::V4([octets[0], octets[1]]))
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            Some(As16Key::V6([segs[0], segs[1]]))
        }
    }
}

/// Shared host-extraction helper: strips scheme + port from a transport URL.
fn host_from_transport(transport: &str) -> &str {
    let host_part = if let Some(rest) = transport
        .strip_prefix("tcp://")
        .or_else(|| transport.strip_prefix("quic://"))
        .or_else(|| transport.strip_prefix("udp://"))
    {
        rest
    } else {
        transport
    };
    if host_part.starts_with('[') {
        host_part
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host_part)
    } else {
        host_part.split(':').next().unwrap_or(host_part)
    }
}

/// Count how many contacts in `bucket` share the given `subnet`.
fn subnet_count(bucket: &VecDeque<Contact>, subnet: &SubnetKey) -> usize {
    bucket
        .iter()
        .filter(|c| subnet_prefix(&c.transport).as_ref() == Some(subnet))
        .count()
}

/// Count how many contacts in `bucket` share the given /16 AS-proxy prefix.
fn as16_count(bucket: &VecDeque<Contact>, key: &As16Key) -> usize {
    bucket
        .iter()
        .filter(|c| as16_prefix(&c.transport).as_ref() == Some(key))
        .count()
}

// ── RoutingTable ──────────────────────────────────────────────────────────────

/// XOR-metric k-bucket routing table.
///
/// buckets below `sketch_threshold` are "sketch" buckets — capped at
/// 1 contact each (memory-efficient coverage of far keyspace). Buckets at or
/// above the threshold are "full" buckets — capped at `k` contacts.
#[derive(Debug)]
pub struct RoutingTable {
    local_id: [u8; 32],
    buckets: Vec<VecDeque<Contact>>,
    pub k: usize,
    /// Bucket indices `[0, sketch_threshold)` are capped at 1 contact.
    sketch_threshold: usize,
    /// per-bucket token-bucket state.
    /// Replaces the legacy `bucket_last_insert: Vec<Instant>` 1/sec gate
    /// with a token bucket (allows bursts up to `DHT_BUCKET_TOKENS_MAX`
    /// then refills at `DHT_BUCKET_TOKEN_REFILL_PER_SEC`) plus
    /// exponential backoff on sustained pressure.
    bucket_rate: Vec<BucketRateState>,
    /// Disable rate limit for tests.
    #[cfg(test)]
    pub rate_limit_disabled: bool,
}

/// token-bucket + exponential-backoff state for one
/// k-bucket. Stored as a parallel `Vec` (256 entries) on `RoutingTable`.
#[derive(Debug, Clone)]
struct BucketRateState {
    /// Available tokens (fractional — refilled in real-valued rate).
    tokens: f64,
    /// Last time `tokens` was refilled.
    last_refill: std::time::Instant,
    /// Number of consecutive rate-limit hits (resets on a successful
    /// non-bypassed insert). Drives the exponential-backoff delay.
    consecutive_hits: u32,
    /// Earliest `Instant` at which a non-bypassed insert is allowed to
    /// retry while `consecutive_hits > 0`.
    backoff_until: Option<std::time::Instant>,
}

impl BucketRateState {
    fn new(now: std::time::Instant) -> Self {
        Self {
            tokens: DHT_BUCKET_TOKENS_MAX as f64,
            last_refill: now,
            consecutive_hits: 0,
            backoff_until: None,
        }
    }

    /// Refill `tokens` based on elapsed time since the last refill, capped
    /// at `DHT_BUCKET_TOKENS_MAX`.
    fn refill(&mut self, now: std::time::Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * DHT_BUCKET_TOKEN_REFILL_PER_SEC)
                .min(DHT_BUCKET_TOKENS_MAX as f64);
            self.last_refill = now;
        }
    }

    /// Try to consume one token. Returns `true` on success, `false` when
    /// rate-limited (and updates the exponential-backoff window).
    fn try_consume(&mut self, now: std::time::Instant) -> bool {
        // Exponential-backoff gate first: while the window is in effect
        // reject without touching tokens.
        if let Some(until) = self.backoff_until
            && now < until
        {
            return false;
        }
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            // Successful insert resets the streak so a single rejection
            // doesn't permanently penalise an honest peer.
            self.consecutive_hits = 0;
            self.backoff_until = None;
            true
        } else {
            // Rate-limit hit: schedule exponential backoff.
            self.consecutive_hits = self.consecutive_hits.saturating_add(1);
            let secs = DHT_BUCKET_BACKOFF_BASE_SECS
                .saturating_mul(1u64 << self.consecutive_hits.min(10).saturating_sub(1))
                .min(DHT_BUCKET_BACKOFF_MAX_SECS);
            self.backoff_until = Some(now + std::time::Duration::from_secs(secs));
            false
        }
    }
}

impl RoutingTable {
    pub fn new(local_id: [u8; 32]) -> Self {
        Self::with_k(local_id, K)
    }

    pub fn with_k(local_id: [u8; 32], k: usize) -> Self {
        let buckets = (0..256).map(|_| VecDeque::new()).collect();
        let now = std::time::Instant::now();
        let bucket_rate = (0..256).map(|_| BucketRateState::new(now)).collect();
        Self {
            local_id,
            buckets,
            k,
            sketch_threshold: 0,
            bucket_rate,
            #[cfg(test)]
            rate_limit_disabled: true, // tests run without rate limit by default
        }
    }

    /// Set the sketch bucket threshold.
    ///
    /// Buckets with index `< threshold` are capped at 1 contact (sketch).
    /// Set to 0 to disable sketch mode (all buckets use full K).
    pub fn set_sketch_threshold(&mut self, threshold: usize) {
        self.sketch_threshold = threshold;
    }

    /// Update the bucket size K at runtime.
    ///
    /// Increasing K allows more contacts per bucket (better coverage).
    /// Decreasing K trims buckets from the back (oldest contacts removed).
    pub fn set_k(&mut self, new_k: usize) {
        if new_k < self.k {
            // Shrink: trim excess contacts from each full bucket.
            for bucket in &mut self.buckets {
                while bucket.len() > new_k {
                    bucket.pop_front(); // LRU eviction
                }
            }
        }
        self.k = new_k;
    }

    /// This node's ID.
    pub fn local_id(&self) -> &[u8; 32] {
        &self.local_id
    }

    /// Effective capacity for a given bucket index.
    fn bucket_cap(&self, idx: usize) -> usize {
        if idx < self.sketch_threshold {
            1
        } else {
            self.k
        }
    }

    /// Insert or update a contact.
    ///
    /// If the contact already exists (matched by `node_id`), it is moved to
    /// the tail of the bucket (most recently seen). If the bucket is full:
    ///
    /// 1. **Subnet diversity** — if the incoming contact's /24 (IPv4) or /48
    ///    (IPv6) subnet already has `MAX_NODES_PER_SUBNET_PER_BUCKET` or more
    ///    contacts in the bucket, the contact is **dropped** (not inserted).
    ///    This limits Eclipse attacks from a single address block.
    ///
    /// 2. **Eviction** — if the bucket is full but the subnet quota allows the
    ///    new contact, the oldest contact from the most-populated subnet is
    ///    evicted to make room. Ties are broken by evicting the oldest entry
    ///    overall (LRU — front of the deque).
    pub fn insert(&mut self, contact: Contact) {
        self.insert_inner(contact, false);
    }

    /// Like [`insert`] but bypasses the per-bucket rate limit. Use this
    /// for contacts learned from sources we already trust (e.g. just
    /// completed an OVL1 handshake —). The rate limit is an
    /// Eclipse-attack defense aimed at unsolicited adds; for known-good
    /// peers it causes startup-time mesh races to lose entries when
    /// several handshakes complete inside the same 1-second window.
    pub fn insert_trusted(&mut self, contact: Contact) {
        self.insert_inner(contact, true);
    }

    fn insert_inner(&mut self, contact: Contact, bypass_rate_limit: bool) {
        if contact.node_id == self.local_id {
            return; // never store self
        }
        let dist = xor_distance(&self.local_id, &contact.node_id);
        let idx = bucket_index(&dist);
        // trusted callers (post-handshake) get full bucket
        // capacity even for distant XOR-distance buckets that would
        // normally be sketch (cap=1). Sketch buckets are a Kademlia
        // optimisation for far-away peers we rarely talk to; but
        // direct-session peers ARE talked to, so we want all of them
        // visible to `find_closest_nodes`. Without this, two trusted
        // peers landing in the same sketch bucket would overwrite each
        // other (LRU on cap=1) and leave only the latest visible.
        let cap = if bypass_rate_limit {
            self.k
        } else {
            self.bucket_cap(idx)
        };
        let bucket = &mut self.buckets[idx];

        // Update existing entry: move to tail (most recently seen).
        // (Updates bypass rate limit — only NEW contacts are limited.)
        if let Some(pos) = bucket.iter().position(|c| c.node_id == contact.node_id) {
            bucket.remove(pos);
            bucket.push_back(contact);
            return;
        }
        // token-bucket rate limit replaces the legacy
        // `1-insert-per-second-per-bucket` gate. Allows initial bursts up to
        // `DHT_BUCKET_TOKENS_MAX`, then refills at
        // `DHT_BUCKET_TOKEN_REFILL_PER_SEC`. Rejection triggers exponential
        // backoff so a sustained-pressure attacker is locked out for
        // increasing windows. trusted callers bypass entirely
        // — Eclipse defence is for unsolicited adds.
        if !bypass_rate_limit {
            #[cfg(not(test))]
            {
                let now = std::time::Instant::now();
                if !self.bucket_rate[idx].try_consume(now) {
                    return; // rate-limited — drop this new contact
                }
            }
            #[cfg(test)]
            if !self.rate_limit_disabled {
                let now = std::time::Instant::now();
                if !self.bucket_rate[idx].try_consume(now) {
                    return;
                }
            }
        }
        if bucket.len() < cap {
            // Bucket has space — check diversity quotas before inserting
            // (full buckets only — sketch buckets cap=1 use replace-on-full).
            if cap > 1 {
                if let Some(subnet) = subnet_prefix(&contact.transport)
                    && subnet_count(bucket, &subnet) >= MAX_NODES_PER_SUBNET_PER_BUCKET
                {
                    return; // /24 quota exceeded — drop this contact
                }
                // AS-proxy (16) diversity check.
                if let Some(as16) = as16_prefix(&contact.transport)
                    && as16_count(bucket, &as16) >= MAX_NODES_PER_AS16_PER_BUCKET
                {
                    return; // /16 AS quota exceeded — drop this contact
                }
            }
            bucket.push_back(contact);
        } else if cap == 1 {
            // Sketch bucket: replace the single entry with the newer contact.
            bucket.pop_front();
            bucket.push_back(contact);
        } else {
            // Full bucket is full.
            // 1a. Check /24 subnet quota for the incoming contact.
            if let Some(subnet) = subnet_prefix(&contact.transport) {
                if subnet_count(bucket, &subnet) >= MAX_NODES_PER_SUBNET_PER_BUCKET {
                    return; // /24 subnet quota exceeded — drop this contact
                }
                // 1b. / : also check /16 AS-proxy quota.
                if let Some(as16) = as16_prefix(&contact.transport)
                    && as16_count(bucket, &as16) >= MAX_NODES_PER_AS16_PER_BUCKET
                {
                    return; // /16 AS quota exceeded — drop this contact
                }
                // 2. Prefer to evict the oldest entry from the most-populated subnet.
                // M2: replace per-insert `HashMap::new` allocation
                // with an inline Vec. Buckets are bounded by K (≤ 20 contacts)
                // so linear search costs O(N²) ≤ ~400 comparisons — comparable
                // to HashMap hash+probe but with zero heap allocation on the
                // bucket-full path (which fires repeatedly under DHT churn).
                let mut subnet_stats: Vec<(SubnetKey, usize, usize)> = Vec::with_capacity(8);
                for (i, c) in bucket.iter().enumerate() {
                    if let Some(s) = subnet_prefix(&c.transport) {
                        if let Some(slot) = subnet_stats.iter_mut().find(|(k, _, _)| *k == s) {
                            slot.1 += 1; // increment count; oldest_index sticks at first occurrence
                        } else {
                            subnet_stats.push((s, 1, i));
                        }
                    }
                }
                let mut best_evict: Option<usize> = None;
                let mut best_count = 0usize;
                for (_, count, oldest_idx) in &subnet_stats {
                    if *count > best_count {
                        best_count = *count;
                        best_evict = Some(*oldest_idx);
                    }
                }
                if let Some(evict_idx) = best_evict {
                    bucket.remove(evict_idx);
                } else {
                    // No parseable IP subnets — fall back to LRU eviction.
                    bucket.pop_front();
                }
            } else {
                // Incoming contact has no parseable IP — LRU eviction.
                bucket.pop_front();
            }
            bucket.push_back(contact);
        }
    }

    /// Remove a contact by node_id.
    pub fn remove(&mut self, node_id: &[u8; 32]) {
        let dist = xor_distance(&self.local_id, node_id);
        let idx = bucket_index(&dist);
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|c| &c.node_id == node_id) {
            bucket.remove(pos);
        }
    }

    /// Return up to `k` contacts closest to `target`, sorted by XOR distance
    /// ascending.
    ///
    /// M1: complexity reduced from O(N log N) (full table sort)
    /// to O(N log K) using a bounded max-heap. At default `K = 20` and
    /// adversarial table size `N ≥ 1000`, this is ~5-7× fewer comparisons
    /// and the working-set memory is `K` rather than `N` — important for
    /// the lookup hot path which runs on every recursive DHT walk.
    pub fn find_closest(&self, target: &[u8; 32], k: usize) -> Vec<&Contact> {
        if k == 0 {
            return Vec::new();
        }
        // Use a max-heap of size ≤ k. Items are `(distance, contact-index)`
        // where the largest distance is at the top. As we walk all contacts
        // we keep only the k smallest by popping the max whenever a closer
        // candidate arrives. `BinaryHeap::peek` + `pop` is O(log K).
        use std::collections::BinaryHeap;
        // Wrap (distance, index) in Reverse-of-(index) for stable tie-break:
        // the heap orders by `(distance, index)` ascending so equal-distance
        // contacts come back in deterministic insertion order.
        let mut heap: BinaryHeap<([u8; 32], usize)> = BinaryHeap::with_capacity(k);
        let contacts: Vec<&Contact> = self.buckets.iter().flatten().collect();
        for (idx, c) in contacts.iter().enumerate() {
            let d = xor_distance(target, &c.node_id);
            if heap.len() < k {
                heap.push((d, idx));
            } else if let Some(&(top_dist, _)) = heap.peek()
                && d < top_dist
            {
                heap.pop();
                heap.push((d, idx));
            }
        }
        // Drain the heap (largest first) into a Vec, then reverse so the
        // closest contact is at the front. This is O(K log K) — small
        // constant compared to the O(N log K) accumulation.
        let mut sorted: Vec<([u8; 32], usize)> = heap.into_sorted_vec();
        // `into_sorted_vec` returns ascending order, which is what we want.
        sorted.shrink_to(k);
        sorted.into_iter().map(|(_, idx)| contacts[idx]).collect()
    }

    pub fn total_contacts(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// check whether `node_id` is already in the routing
    /// table. Used by the 2-tier eclipse-defence to skip adding
    /// unverified contacts for peers that are already verified.
    /// O(total_contacts) — acceptable for the call frequency (a few
    /// times per FIND_NODE response).
    pub fn contains(&self, node_id: &[u8; 32]) -> bool {
        self.buckets
            .iter()
            .flat_map(|b| b.iter())
            .any(|c| &c.node_id == node_id)
    }

    /// Return all contacts from all buckets (cloned).
    pub fn all_contacts(&self) -> Vec<Contact> {
        self.buckets.iter().flatten().cloned().collect()
    }

    /// iterator-based accessor that avoids cloning
    /// `Vec<Contact>` (which has `String`-backed transport, ~80 B per
    /// entry plus heap allocation) when callers only need to inspect or
    /// count. Caller invokes the closure under the routing-table lock
    /// so keep it short.
    pub fn for_each_contact<F: FnMut(&Contact)>(&self, mut f: F) {
        for bucket in &self.buckets {
            for c in bucket {
                f(c);
            }
        }
    }

    /// returns just the node_ids (32 B each, no
    /// heap allocation per entry) instead of cloning the full Contact
    /// struct. At 65 K contacts this is ~2 MB instead of ~13 MB.
    pub fn node_ids(&self) -> Vec<[u8; 32]> {
        let total: usize = self.buckets.iter().map(|b| b.len()).sum();
        let mut out = Vec::with_capacity(total);
        for bucket in &self.buckets {
            for c in bucket {
                out.push(c.node_id);
            }
        }
        out
    }

    /// Return all contacts as a snapshot for persistence.
    pub fn snapshot(&self) -> Vec<Contact> {
        self.all_contacts()
    }

    /// Restore contacts from a persisted snapshot.
    ///
    /// Each contact is inserted via `insert` so bucket placement and LRU
    /// order are respected. Duplicates are silently merged (existing entry
    /// moves to tail = most-recently-seen).
    pub fn restore(&mut self, contacts: Vec<Contact>) {
        for c in contacts {
            self.insert(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(seed: u8) -> Contact {
        Contact::new([seed; 32], format!("tcp://node-{seed}:9000"))
    }

    #[test]
    fn insert_and_find_closest() {
        let mut rt = RoutingTable::new([0u8; 32]);
        rt.insert(make_contact(1));
        rt.insert(make_contact(2));
        rt.insert(make_contact(3));

        let closest = rt.find_closest(&[1u8; 32], 2);
        assert_eq!(closest.len(), 2);
        // The contact with node_id=[1u8;32] should be closest to target=[1u8;32]
        assert_eq!(closest[0].node_id, [1u8; 32]);
    }

    #[test]
    fn does_not_store_self() {
        let local = [42u8; 32];
        let mut rt = RoutingTable::new(local);
        rt.insert(Contact::new(local, "tcp://self:9000"));
        assert_eq!(rt.total_contacts(), 0);
    }

    #[test]
    fn update_moves_to_tail() {
        let mut rt = RoutingTable::new([0u8; 32]);
        rt.insert(Contact::new([1u8; 32], "tcp://old:9000"));
        rt.insert(Contact::new([1u8; 32], "tcp://new:9000")); // update

        assert_eq!(rt.total_contacts(), 1);
        let closest = rt.find_closest(&[1u8; 32], 1);
        assert_eq!(closest[0].transport, "tcp://new:9000");
    }

    #[test]
    fn remove_contact() {
        let mut rt = RoutingTable::new([0u8; 32]);
        rt.insert(make_contact(5));
        assert_eq!(rt.total_contacts(), 1);
        rt.remove(&[5u8; 32]);
        assert_eq!(rt.total_contacts(), 0);
    }

    #[test]
    fn bucket_evicts_oldest_when_full() {
        let mut rt = RoutingTable::with_k([0u8; 32], 2);
        // sketch_threshold=0 by default — all buckets use full K
        // Insert contacts that all land in the same bucket (same XOR prefix)
        // We need 3 contacts in the same bucket to test eviction.
        // Bucket index = leading zeros of XOR(local, contact).
        // local = [0;32]; contact=[0xFF;32] → XOR = [0xFF;32] → msb = bit 0 → bucket 0.
        // Let's make 3 contacts that differ only in their last bytes but have the
        // same bucket (same distance prefix).
        // All contacts with node_id[0]=0xFF will have XOR distance byte[0]=0xFF
        // meaning bucket index 0 (leading zeros count = 0).
        let c1 = Contact::new(
            {
                let mut a = [0u8; 32];
                a[0] = 0xFF;
                a[31] = 1;
                a
            },
            "tcp://1",
        );
        let c2 = Contact::new(
            {
                let mut a = [0u8; 32];
                a[0] = 0xFF;
                a[31] = 2;
                a
            },
            "tcp://2",
        );
        let c3 = Contact::new(
            {
                let mut a = [0u8; 32];
                a[0] = 0xFF;
                a[31] = 3;
                a
            },
            "tcp://3",
        );

        rt.insert(c1.clone());
        rt.insert(c2.clone());
        rt.insert(c3.clone()); // should evict c1

        let dist1 = xor_distance(&[0u8; 32], &c1.node_id);
        let dist2 = xor_distance(&[0u8; 32], &c2.node_id);
        let idx1 = bucket_index(&dist1);
        let idx2 = bucket_index(&dist2);
        assert_eq!(
            idx1, idx2,
            "c1, c2, c3 must be in the same bucket for this test"
        );

        assert_eq!(rt.total_contacts(), 2);
        let ids: Vec<[u8; 32]> = rt.buckets[idx1].iter().map(|c| c.node_id).collect();
        assert!(!ids.contains(&c1.node_id), "oldest (c1) should be evicted");
    }

    #[test]
    fn subnet_diversity_limits_contacts_per_subnet() {
        // k=8, MAX_NODES_PER_SUBNET_PER_BUCKET=k/4=2 (but K/4=5 for K=20;
        // here we use with_k to test the ratio).
        // Use k=4 so MAX_NODES_PER_SUBNET_PER_BUCKET = 4/4 = 1 for demonstration.
        // Actually MAX_NODES_PER_SUBNET_PER_BUCKET is a global const (K/4=5).
        // Use a large enough k to test quota: bucket with k=20, quota=5.
        let mut rt = RoutingTable::new([0u8; 32]);
        // sketch_threshold=0 by default — all buckets use full K

        // Insert MAX_NODES_PER_SUBNET_PER_BUCKET contacts from 192.168.1.x
        for i in 0..MAX_NODES_PER_SUBNET_PER_BUCKET {
            let mut id = [0u8; 32];
            id[0] = 0xFF; // same bucket (XOR distance high bit set)
            id[31] = i as u8;
            rt.insert(Contact::new(id, format!("tcp://192.168.1.{}:9000", i + 1)));
        }
        let before = rt.total_contacts();
        assert_eq!(before, MAX_NODES_PER_SUBNET_PER_BUCKET);

        // One more from the same /24 — must be rejected.
        let mut id = [0u8; 32];
        id[0] = 0xFF;
        id[31] = 99;
        rt.insert(Contact::new(id, "tcp://192.168.1.99:9000".to_owned()));
        assert_eq!(
            rt.total_contacts(),
            before,
            "contact from over-represented /24 subnet must be dropped"
        );

        // Contact from a different /24 must still be accepted.
        let mut id2 = [0u8; 32];
        id2[0] = 0xFF;
        id2[31] = 200;
        rt.insert(Contact::new(id2, "tcp://10.0.0.1:9000".to_owned()));
        assert_eq!(
            rt.total_contacts(),
            before + 1,
            "contact from a different subnet must be accepted"
        );
    }

    #[test]
    fn xor_distance_identity() {
        let a = [0xABu8; 32];
        assert_eq!(xor_distance(&a, &a), [0u8; 32]);
    }

    #[test]
    fn xor_distance_symmetric() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn bucket_index_zero_distance_returns_255() {
        assert_eq!(bucket_index(&[0u8; 32]), 255);
    }

    // ── routing table snapshot/restore ──────────────────────────────

    #[test]
    fn snapshot_restore_roundtrip() {
        let mut rt = RoutingTable::new([0u8; 32]);
        // sketch_threshold=0 by default — all buckets use full K
        rt.insert(make_contact(1));
        rt.insert(make_contact(2));
        rt.insert(make_contact(3));
        let count_before = rt.total_contacts();

        let snap = rt.snapshot();
        assert_eq!(
            snap.len(),
            count_before,
            "snapshot must capture all contacts"
        );

        let mut rt2 = RoutingTable::new([0u8; 32]);
        // sketch_threshold=0 by default
        rt2.restore(snap);
        assert_eq!(
            rt2.total_contacts(),
            count_before,
            "restored table must have same contact count"
        );

        // All node_ids must be present.
        for seed in 1u8..=3 {
            let closest = rt2.find_closest(&[seed; 32], 1);
            assert_eq!(
                closest[0].node_id, [seed; 32],
                "contact {seed} must survive restore"
            );
        }
    }

    #[test]
    fn restore_does_not_duplicate_existing_contacts() {
        let mut rt = RoutingTable::new([0u8; 32]);
        rt.insert(make_contact(10));

        // Restore with the same contact — should not appear twice.
        let snap = rt.snapshot();
        rt.restore(snap);
        assert_eq!(
            rt.total_contacts(),
            1,
            "restore must not duplicate existing entries"
        );
    }

    #[test]
    fn snapshot_json_roundtrip() {
        let mut rt = RoutingTable::new([0u8; 32]);
        rt.insert(make_contact(5));
        rt.insert(make_contact(6));

        let snap = rt.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let loaded: Vec<Contact> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(loaded.len(), snap.len());
        assert_eq!(loaded[0].node_id, snap[0].node_id);
    }
}
