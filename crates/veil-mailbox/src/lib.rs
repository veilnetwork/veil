//! Relay-side store-and-forward mailbox for offline message delivery.
//!
//!.4 P1: when sender A wants to deliver to
//! receiver B but B is offline, A's node deposits the encrypted message
//! blob into a mailbox at one of B's chosen replica relays. When B
//! comes online (or wakes up via a push notification), B fetches the
//! pending blobs and acknowledges them; the relay then deletes them.
//!
//! ## Why a real KV (redb) and not flat files
//!
//! Quota enforcement requires **atomic** reads+writes of byte counters
//! alongside the blob insert. Flat files would race two concurrent
//! `put`s into a quota over-shoot. redb gives us serialisable trans-
//! actions with zero external dependencies (pure Rust, no C linker).
//!
//! ## Schema
//!
//! Three redb tables:
//!
//! `blobs[(receiver[32] || content_id[32])] → BlobRecord(encoded)` —
//! primary key/value. Content is opaque to the mailbox; the relay
//! neither inspects nor decrypts it.
//! `receiver_bytes[receiver[32]] → u64` — per-receiver size counter
//! for quota enforcement. Updated atomically with each put/ack.
//! `eviction_index[(deposited_at_be[8] || receiver[32] || content_id[32])]
//! → ` — sorted by deposit time. Lets `prune_expired` and
//! `evict_oldest_global` walk in oldest-first order without scanning
//! the entire `blobs` table.
//!
//! ## Limits
//!
//! Defaults (override [`MailboxConfig`]):
//!
//! 100 MiB per receiver (cap)
//! 10 GiB per relay (cap, eviction-on-hit)
//! 7-day TTL on individual blobs
//! 60 puts per receiver per minute (rate limit)
//!
//! ## What this module does **not** do
//!
//! **No replication.** Each `Mailbox` owns its blobs. Replication
//! across K=3 relays is the sender's responsibility (P5).
//! **No push trigger.** Wiring `put` to FCM/APNs is P3.
//! **No wire protocol.** IPC opcodes for `MailboxPut/Fetch/Ack` are
//! P2.
//! **No anonymity.** Caller is responsible for onion-wrapping the
//! transport so the mailbox sees an anonymous deposit, not source IP.

#![deny(missing_docs)]

use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

mod rate_limit;
use rate_limit::ReceiverRateLimiter;

pub mod outbox;
pub use outbox::{
    DEFAULT_OUTBOX_TTL_SECS, MAX_FIND_MISSING_RESULTS, Outbox, OutboxConfig, OutboxEntry,
};

pub mod service;
pub use service::{
    MAILBOX_ACK_ENDPOINT_CAPACITY, MAILBOX_ACK_ENDPOINT_ID, MAILBOX_APP_ID, MAILBOX_APP_NAME,
    MAILBOX_FETCH_ENDPOINT_CAPACITY, MAILBOX_FETCH_ENDPOINT_ID, MAILBOX_FETCH_REPLY_MAX_BYTES,
    MAILBOX_PUT_ENDPOINT_CAPACITY, MAILBOX_PUT_ENDPOINT_ID, MAILBOX_WAKE_ENDPOINT_CAPACITY,
    MAILBOX_WAKE_ENDPOINT_ID,
};

pub mod capability;
pub mod fetch_cookie;
pub use capability::{
    ALGO_ED25519, ALGO_FALCON512, CapTokenError, MAX_TOKEN_BYTES as MAX_CAPABILITY_TOKEN_BYTES,
    MailboxCapabilityToken, SIGN_CONTEXT as CAPABILITY_SIGN_CONTEXT,
    TOKEN_VERSION as CAPABILITY_TOKEN_VERSION,
};

// ── Constants & defaults ────────────────────────────────────────────────────

/// Default per-receiver quota in bytes (100 MiB).
pub const DEFAULT_QUOTA_PER_RECEIVER_BYTES: u64 = 100 * 1024 * 1024;

/// Default per-sender quota in bytes (10 MiB ≈ 10 % of per-receiver cap).
///
/// Without an explicit per-sender bound, a single OVL1-authenticated peer
/// can deposit up to `DEFAULT_RATE_LIMIT_PER_MINUTE` × `MAX_BLOB_BYTES` =
/// 60 × 1 MiB = 60 MiB/min targeted at one victim's `receiver_id` (which
/// is public information from `RendezvousAd`), filling the victim's
/// 100 MiB quota in ~2 min.  10 MiB caps a single sender to ~10 % of the
/// receiver's window per quota cycle, allowing K legitimate senders to
/// co-exist before any one of them locks out the rest.  Operator can
/// raise via `MailboxConfig::quota_per_sender_bytes`.
pub const DEFAULT_QUOTA_PER_SENDER_BYTES: u64 = 10 * 1024 * 1024;

/// Default global per-relay quota in bytes (10 GiB).
pub const DEFAULT_QUOTA_GLOBAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Default TTL for individual blobs (7 days).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Default rate limit (puts per receiver per minute).
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;

/// Maximum size of a single deposited blob (1 MiB).
///
/// The protocol-level message tier (small ≤4 KiB padded; large up to
/// 256 KiB) sits well under this; we leave headroom for future
/// large-tier growth. Hard cap stops a malicious sender from
/// trying to put a single multi-GiB blob to exhaust the quota.
pub const MAX_BLOB_BYTES: u64 = 1024 * 1024;

/// minimum age in seconds before a blob
/// becomes eligible for **global-quota eviction** during another
/// receiver's [`Mailbox::put`]. Pre-fix the eviction loop would pick
/// the oldest blob globally regardless of age and evict it to make room
/// for a new put — meaning an attacker spamming `put` to random
/// `receiver_id`s could fill the global 10 GiB cap and displace a
/// legitimate receiver's recent offline message (data loss, not just
/// availability). Now blobs younger than this threshold are protected;
/// if no eligible victim exists, the put is rejected with
/// `QuotaGlobalExceeded` instead of evicting fresh authenticated
/// content. Stale attacker traffic ages out via TTL prune (default
/// 7 days — see `DEFAULT_TTL_SECS`).
pub const MIN_EVICTION_AGE_SECS: u64 = 3600;

/// hard cap on the number of records
/// returned by a single [`Mailbox::fetch`] call. Pre-fix `fetch` would
/// allocate a `Vec<MailboxBlob>` containing every record for the
/// receiver, with no count cap. Combined with the byte-only quota
/// (100 MiB default) and [`MIN_BLOB_BYTES`] = 1, an attacker could
/// deposit up to ~100M one-byte records under the per-receiver quota and
/// trigger ~10 GiB of heap allocation when the receiver fetches. Now
/// `fetch` returns at most this many records (oldest-first); callers
/// that need the rest are expected to ack-then-fetch in batches.
pub const MAX_FETCH_COUNT: usize = 1024;

/// Minimum size of a deposited blob (1 byte).
///
/// pre-fix the only check was the
/// upper bound, so a sender could spam empty (`blob.len == 0`) puts.
/// Each empty put still consumes the quota counter at 0 bytes (no-op
/// for the per-receiver quota) AND consumes a row in the redb blobs
/// table (40+ bytes of redb overhead per empty record). Combined with
/// many distinct content_ids OR many distinct receivers, this turns
/// into a disk-fill DoS that the quota subsystem cannot account for.
/// Empty blobs also have no protocol use case — every legitimate
/// payload type (small message, attachment, identity proof, push
/// envelope) carries at least one byte of header.
pub const MIN_BLOB_BYTES: u64 = 1;

/// `(receiver_id, content_id)` composite key for the primary blob table.
const KEY_LEN: usize = 32 + 32;

const TABLE_BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs_v1");
const TABLE_RECEIVER_BYTES: TableDefinition<&[u8], u64> = TableDefinition::new("receiver_bytes_v1");
const TABLE_EVICTION_INDEX: TableDefinition<&[u8], ()> = TableDefinition::new("eviction_index_v1");
const TABLE_GLOBAL_BYTES: TableDefinition<&str, u64> = TableDefinition::new("global_bytes_v1");
const GLOBAL_BYTES_KEY: &str = "total";

/// per-sender byte quota tracking. Maps
/// `sender_id[32]` → currently-occupied bytes. Decremented on ack / TTL
/// prune / eviction. Capped by [`MailboxConfig::quota_per_sender_bytes`]
/// (audit L-17: default is `DEFAULT_QUOTA_PER_SENDER_BYTES` = 10 MiB, NOT
/// `u64::MAX` — `u64::MAX` is the explicit opt-out value).
const TABLE_SENDER_BYTES: TableDefinition<&[u8], u64> = TableDefinition::new("sender_bytes_v1");

/// secondary eviction index keyed only by
/// **anonymous-pool** blobs (puts arriving without a valid capability
/// token, or with `require_capability_token = false` policy and no token).
/// Eviction loop scans this first; only falls back to the main
/// `TABLE_EVICTION_INDEX` (identified pool) if the anon pool is empty.
/// Pre-slice-3 records exist only in the main index; first put after
/// upgrade adds the new index, and existing records continue in the
/// "identified pool" (conservative — doesn't lose existing bytes).
const TABLE_EVICTION_INDEX_ANON: TableDefinition<&[u8], ()> =
    TableDefinition::new("eviction_index_anon_v1");

/// trust class assigned to a blob at deposit
/// time. Determines which eviction-index table it goes into and therefore
/// which pool gets evicted first under global-quota pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustClass {
    /// Anonymous deposit: sender either omitted a capability token
    /// or supplied an invalid one (but the relay's policy was permissive
    /// and accepted the put anyway). Evicted FIRST under global pressure.
    Anonymous,
    /// Identified deposit: sender supplied a receiver-signed capability
    /// token that verified successfully. Evicted only after the anon
    /// pool drains. Also the default for in-process callers (`Mailbox::put`).
    Identified,
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Operations that may fail.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// Underlying redb database error.
    #[error("redb error: {0}")]
    Db(String),
    /// I/O error opening or syncing the database.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Caller passed a blob exceeding [`MAX_BLOB_BYTES`].
    #[error("blob too large: {actual} > {max}")]
    BlobTooLarge {
        /// Size of the blob the caller tried to put.
        actual: u64,
        /// Hard cap.
        max: u64,
    },
    /// Caller passed an empty (or below-minimum) blob.
    /// audit follow-up: empty blobs would otherwise accumulate redb
    /// row-overhead without consuming the byte-counted quota.
    #[error("blob too small: {actual} < {min}")]
    BlobTooSmall {
        /// Size of the blob the caller tried to put.
        actual: u64,
        /// Hard floor.
        min: u64,
    },
    /// Stored record is corrupt (wrong length / bad magic). Should
    /// never happen unless the DB file was tampered with externally.
    #[error("corrupt record: {0}")]
    Corrupt(&'static str),
    /// outbox total-bytes quota would be exceeded.
    /// IPC client can flood `Outbox::put` to fill disk; the per-blob
    /// and total quotas (`outbox::MAX_OUTBOX_BLOB_BYTES` /
    /// `OutboxConfig::quota_total_bytes`) bound this. Sender should
    /// drain outbox via ack or wait for TTL prune before retrying.
    #[error("outbox quota exceeded: current={current_bytes} blob={blob_size} cap={cap_bytes}")]
    OutboxQuotaExceeded {
        /// Bytes the outbox currently occupies (sum of all blob payloads).
        current_bytes: u64,
        /// Size of the blob the caller tried to put.
        blob_size: u64,
        /// Hard cap configured for this outbox.
        cap_bytes: u64,
    },
}

// Concrete From impls for each redb error type we encounter.
// Each maps to `MailboxError::Db(string)` — we don't try to preserve
// the source's specific type because it's not actionable for callers.
macro_rules! redb_err_from {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for MailboxError {
                fn from(e: $ty) -> Self { Self::Db(e.to_string()) }
            }
        )*
    };
}
redb_err_from!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
);

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for a [`Mailbox`].
#[derive(Debug, Clone)]
pub struct MailboxConfig {
    /// Per-receiver quota (bytes). Put rejected with
    /// [`PutOutcome::QuotaPerReceiverExceeded`] when the receiver's
    /// total would exceed this.
    pub quota_per_receiver_bytes: u64,
    /// Global per-relay quota (bytes). When a put would push the
    /// global total over this, the mailbox evicts oldest blobs (by
    /// deposit time) until the put fits, then stores the new blob.
    /// If even after evicting everything the put would not fit (e.g.
    /// because the new blob alone is larger than the global cap), the
    /// put is rejected with [`PutOutcome::QuotaGlobalExceeded`].
    pub quota_global_bytes: u64,
    /// Time-to-live for individual blobs (seconds). Blobs older than
    /// `now - ttl_secs` are removed by [`Mailbox::prune_expired`].
    pub ttl_secs: u64,
    /// Maximum puts per receiver per minute (token-bucket). Burst-DoS
    /// protection independent of storage quota.
    pub rate_limit_per_minute: u32,
    /// when `true`, every PUT must include
    /// a valid receiver-signed [`MailboxCapabilityToken`]. Puts without
    /// a token, or with a token that fails verify (expired, wrong receiver
    /// bad signature), are rejected with [`PutOutcome::CapabilityRequired`]
    /// or [`PutOutcome::CapabilityInvalid`] respectively.
    ///
    /// Default `false` for backward compatibility — pre-slice-1 senders
    /// emit no token, and a relay flipping this to `true` would refuse all
    /// existing traffic. Flip to `true` only after the receiver-side mint
    /// API and the sender-side propagation through `RendezvousAd`
    /// have rolled out.
    pub require_capability_token: bool,
    /// cap on bytes a single sender_id may
    /// occupy across the entire mailbox (sum across all receivers).
    /// Without this a sender targeting many receivers can drive the
    /// global quota up while staying under each receiver's per-receiver
    /// cap individually.
    ///
    /// Audit L-17: default `DEFAULT_QUOTA_PER_SENDER_BYTES` = 10 MiB (caps a
    /// single OVL1 sender to ~10% of the receiver's 100 MiB window — flipping
    /// this to the old `u64::MAX` made the default-config deployment silently
    /// unsafe). Set to `u64::MAX` to disable the per-sender cap explicitly. PUT
    /// over this cap returns [`PutOutcome::QuotaPerSenderExceeded`].
    pub quota_per_sender_bytes: u64,
    /// This relay's own `node_id`, used to verify v2 (relay-bound) capability
    /// tokens. When non-zero, v2 tokens MUST claim this id; v1 tokens are
    /// still accepted unchanged (backward compat). Set to `[0u8; 32]` if the
    /// mailbox is running in-process for the receiver's own node (no
    /// cross-relay attack surface) or for tests.
    pub local_node_id: [u8; 32],
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            quota_per_receiver_bytes: DEFAULT_QUOTA_PER_RECEIVER_BYTES,
            quota_global_bytes: DEFAULT_QUOTA_GLOBAL_BYTES,
            ttl_secs: DEFAULT_TTL_SECS,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            require_capability_token: false,
            quota_per_sender_bytes: DEFAULT_QUOTA_PER_SENDER_BYTES,
            local_node_id: [0u8; 32],
        }
    }
}

// ── Outcomes & data types ───────────────────────────────────────────────────

/// Result [`Mailbox::put`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// Blob persisted. `evicted` is the number of older blobs that
    /// had to be removed to make room (only nonzero when the global
    /// quota was the binding constraint).
    Stored {
        /// Count of older blobs evicted to fit the new one.
        evicted: u32,
    },
    /// The receiver's per-receiver quota would have been exceeded.
    /// No eviction is applied at the per-receiver level — receivers
    /// who hit their cap have to wait for older blobs to be acked or
    /// expire. Sender should fall back to peer-sync.
    QuotaPerReceiverExceeded {
        /// Bytes the receiver currently uses.
        current_bytes: u64,
        /// Cap the receiver is bound to.
        cap_bytes: u64,
    },
    /// Even after evicting every existing blob, the new blob would not
    /// fit under the global cap. Practically this means the blob is
    /// itself larger than the global cap, which should never happen
    /// given [`MAX_BLOB_BYTES`] is much smaller.
    QuotaGlobalExceeded {
        /// Size of the blob that didn't fit.
        blob_size: u64,
        /// Global cap.
        cap_bytes: u64,
    },
    /// Sender exceeded the per-receiver rate limit. The token bucket
    /// is in-memory and resets gradually; sender should retry after
    /// at least one second.
    RateLimited,
    /// A blob with the same `(receiver, content_id)` was already
    /// stored. No-op — the existing blob is preserved unchanged.
    Duplicate,
    /// relay configured with
    /// `require_capability_token = true` rejected a PUT that arrived
    /// without a capability token. Sender should re-fetch the receiver's
    /// `RendezvousAd` (which carries the current token) and retry.
    CapabilityRequired,
    /// capability token decode or verify
    /// failed. Either the wire shape is malformed, the token expired
    /// the issuer pubkey doesn't hash to the declared receiver, or the
    /// signature is invalid. Caller does not learn the specific failure
    /// reason — same fail-closed pattern as auth_cookie mismatch in
    /// `MailboxFetchPayload` to avoid signaling-side-channels to a probing
    /// attacker. Operator-side trace logs (WARN level in the relay app
    /// service) carry the granular reason.
    CapabilityInvalid,
    /// sender's per-sender byte cap would be
    /// exceeded. Sender_id is the BLAKE3 of the sender's identity
    /// pubkey, so this gates abuse spread across many receiver targets.
    QuotaPerSenderExceeded {
        /// Bytes the sender currently occupies across all receivers.
        current_bytes: u64,
        /// Cap the sender is bound to.
        cap_bytes: u64,
    },
}

/// A blob fetched from the mailbox. Returned by [`Mailbox::fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBlob {
    /// 32-byte sender node id (set by caller at put-time).
    pub sender_id: [u8; 32],
    /// 32-byte content id (caller-chosen, e.g. BLAKE3 of plaintext).
    /// Used for ack and dedup.
    pub content_id: [u8; 32],
    /// Unix-seconds when the blob was deposited.
    pub deposited_at: u64,
    /// Encrypted blob. The mailbox does not interpret this.
    pub blob: Vec<u8>,
}

/// Snapshot of a [`Mailbox`]'s storage state. Returned by [`Mailbox::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxStats {
    /// Total bytes occupied by blob payloads (does not include redb
    /// overhead or the receiver-bytes index).
    pub total_blob_bytes: u64,
    /// Number of blobs currently stored.
    pub blob_count: u64,
}

// ── Storage record format ───────────────────────────────────────────────────

/// On-disk record format for the `blobs` table value.
///
/// Layout: `[sender_id (32) | deposited_at (8 BE) | blob_len (4 BE) | blob_bytes]`.
fn encode_record(sender_id: &[u8; 32], deposited_at: u64, blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 8 + 4 + blob.len());
    out.extend_from_slice(sender_id);
    out.extend_from_slice(&deposited_at.to_be_bytes());
    out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    out.extend_from_slice(blob);
    out
}

fn decode_record(bytes: &[u8]) -> Result<([u8; 32], u64, Vec<u8>), MailboxError> {
    if bytes.len() < 32 + 8 + 4 {
        return Err(MailboxError::Corrupt("record too short for header"));
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[..32]);
    let deposited_at = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| MailboxError::Corrupt("record deposited_at slice"))?,
    );
    let blob_len = u32::from_be_bytes(
        bytes[40..44]
            .try_into()
            .map_err(|_| MailboxError::Corrupt("record blob_len slice"))?,
    ) as usize;
    if bytes.len() != 44 + blob_len {
        return Err(MailboxError::Corrupt("record blob_len mismatch"));
    }
    Ok((sender, deposited_at, bytes[44..].to_vec()))
}

/// read just (sender_id, deposited_at)
/// header without allocating the blob bytes — useful when the eviction loop
/// needs the sender for per-sender counter bookkeeping but otherwise
/// throws the blob away.
fn decode_record_header(bytes: &[u8]) -> Result<([u8; 32], u64), MailboxError> {
    if bytes.len() < 32 + 8 + 4 {
        return Err(MailboxError::Corrupt("record too short for header"));
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[..32]);
    let deposited_at = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| MailboxError::Corrupt("record deposited_at slice"))?,
    );
    Ok((sender, deposited_at))
}

fn make_key(receiver: &[u8; 32], content_id: &[u8; 32]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[..32].copy_from_slice(receiver);
    key[32..].copy_from_slice(content_id);
    key
}

fn make_eviction_key(deposited_at: u64, receiver: &[u8; 32], content_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 32 + 32);
    k.extend_from_slice(&deposited_at.to_be_bytes());
    k.extend_from_slice(receiver);
    k.extend_from_slice(content_id);
    k
}

// ── Mailbox ─────────────────────────────────────────────────────────────────

/// Relay-side store-and-forward mailbox.
///
/// Cheap to clone (`Arc<Database>` + `Arc<Mutex>`-wrapped rate limiter
/// inside). Operations are serialisable via redb transactions; concurrent
/// callers will be safe but may contend.
pub struct Mailbox {
    db: Arc<Database>,
    config: MailboxConfig,
    rate_limiter: Arc<StdMutex<ReceiverRateLimiter>>,
    /// Wall-clock source. Production uses `SystemTime::now`; tests
    /// override to a controllable clock.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailbox")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Mailbox {
    /// Open (or create) a mailbox at `<veil_dir>/mailbox/blobs.db`.
    pub fn open(veil_dir: &Path, config: MailboxConfig) -> Result<Self, MailboxError> {
        let dir = veil_dir.join("mailbox");
        std::fs::create_dir_all(&dir)?;
        // Owner-only dir: the stored blobs are E2E ciphertext, but the metadata
        // (sender/receiver ids, deposit timestamps, sizes) would otherwise be
        // world-readable on a multi-user host. Matches the 0o600/0o700 discipline
        // used for keystore / IPC token files. Best-effort on non-Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let db_path = dir.join("blobs.db");
        let db = Database::create(&db_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
        }
        // Touch tables so an empty DB has the schema initialised.
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(TABLE_BLOBS)?;
            let _ = txn.open_table(TABLE_RECEIVER_BYTES)?;
            let _ = txn.open_table(TABLE_EVICTION_INDEX)?;
            let _ = txn.open_table(TABLE_GLOBAL_BYTES)?;
            // ensure new tables are created
            // at first open. redb auto-creates on first open_table in
            // a write transaction; idempotent on existing DBs.
            let _ = txn.open_table(TABLE_SENDER_BYTES)?;
            let _ = txn.open_table(TABLE_EVICTION_INDEX_ANON)?;
        }
        txn.commit()?;
        Ok(Self {
            db: Arc::new(db),
            rate_limiter: Arc::new(StdMutex::new(ReceiverRateLimiter::new(
                config.rate_limit_per_minute,
            ))),
            config,
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs()
            }),
        })
    }

    #[doc(hidden)]
    /// Test helper — open with an injected clock. Not part of the
    /// public API; only `cfg(test)` callers should use this.
    pub fn open_with_clock<F: Fn() -> u64 + Send + Sync + 'static>(
        veil_dir: &Path,
        config: MailboxConfig,
        clock: F,
    ) -> Result<Self, MailboxError> {
        let mut mb = Self::open(veil_dir, config)?;
        mb.clock = Arc::new(clock);
        Ok(mb)
    }

    /// deposit a blob with a capability check
    /// against the relay's [`MailboxConfig::require_capability_token`]
    /// policy.
    ///
    /// `capability_token` carries the receiver-signed
    /// [`MailboxCapabilityToken`] wire bytes (typically obtained from the
    /// receiver's published `RendezvousAd`). Pass `None` for in-process
    /// callers that don't need authorisation (the receiver's own node
    /// depositing to its own mailbox via the IPC bridge — the receiver
    /// is trusting itself).
    ///
    /// Verify path:
    /// 1. If `require_capability_token` is `false`, the token is verified
    ///    if provided (still rejects malformed) but absence is accepted.
    ///    This is the backward-compat default.
    /// 2. If `require_capability_token` is `true`, a missing token →
    ///    [`PutOutcome::CapabilityRequired`]; a token that fails decode
    ///    or verify → [`PutOutcome::CapabilityInvalid`].
    /// 3. On verify success the call delegates to [`Self::put`].
    pub fn put_with_capability(
        &self,
        receiver: [u8; 32],
        content_id: [u8; 32],
        sender: [u8; 32],
        blob: Vec<u8>,
        capability_token: Option<&[u8]>,
    ) -> Result<PutOutcome, MailboxError> {
        // derive trust class from token
        // outcome. Verified token → Identified pool; tokenless put
        // accepted under permissive policy → Anonymous pool (evicted
        // first under global pressure). Invalid token → reject.
        let trust_class = match (self.config.require_capability_token, capability_token) {
            (true, None) => return Ok(PutOutcome::CapabilityRequired),
            (true, Some(bytes)) | (false, Some(bytes)) => {
                let token = match crate::capability::MailboxCapabilityToken::decode(bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        // INFO-level — a malformed token is more likely a
                        // misconfigured client than an attack; routine spam
                        // would be hidden by INFO level. Operator can
                        // bump to DEBUG if digging into a probe.
                        tracing::info!(
                            target: "veil-mailbox",
                            "capability decode failed: {e}",
                        );
                        return Ok(PutOutcome::CapabilityInvalid);
                    }
                };
                let now = (self.clock)();
                // Pass local relay node_id if configured (non-zero) — v2 tokens
                // require it for relay-binding check; v1 tokens ignore it.
                let local = self.config.local_node_id;
                let local_ref = if local == [0u8; 32] {
                    None
                } else {
                    Some(&local)
                };
                if let Err(e) = token.verify(&receiver, local_ref, now) {
                    tracing::info!(
                        target: "veil-mailbox",
                        "capability verify failed: {e}",
                    );
                    return Ok(PutOutcome::CapabilityInvalid);
                }
                // Verified token → identified pool.
                TrustClass::Identified
            }
            (false, None) => {
                // Permissive policy + no token = anonymous pool.
                TrustClass::Anonymous
            }
        };
        self.put_classified(receiver, content_id, sender, blob, trust_class)
    }

    /// Deposit a blob for `receiver`. The mailbox treats `blob` as
    /// opaque bytes — the caller is responsible for any encryption
    /// padding, and authenticating ciphertext.
    ///
    /// **:** this entry-point bypasses the capability
    /// token policy gate. Production callers that accept inbound puts
    /// from arbitrary senders should use [`Self::put_with_capability`]
    /// to enforce the receiver-signed-token requirement. This method
    /// remains for in-process callers that are inherently trusted (e.g.
    /// the receiver's own node depositing into its own mailbox via the
    /// IPC bridge, or test code) — they are stored in the identified
    /// pool so as the daemon trusts itself.
    pub fn put(
        &self,
        receiver: [u8; 32],
        content_id: [u8; 32],
        sender: [u8; 32],
        blob: Vec<u8>,
    ) -> Result<PutOutcome, MailboxError> {
        self.put_classified(receiver, content_id, sender, blob, TrustClass::Identified)
    }

    /// storage path with trust-class
    /// classification. Anonymous-class blobs go into a secondary
    /// eviction index that gets scanned first under global-quota
    /// pressure, so identified-class deposits won't be displaced by
    /// a tokenless flood.
    pub fn put_classified(
        &self,
        receiver: [u8; 32],
        content_id: [u8; 32],
        sender: [u8; 32],
        blob: Vec<u8>,
        trust_class: TrustClass,
    ) -> Result<PutOutcome, MailboxError> {
        let blob_size = blob.len() as u64;
        if blob_size > MAX_BLOB_BYTES {
            return Err(MailboxError::BlobTooLarge {
                actual: blob_size,
                max: MAX_BLOB_BYTES,
            });
        }
        // audit: reject empty / below-minimum blobs. See
        // `MIN_BLOB_BYTES` doc-comment for why — empty puts bypass
        // the byte-counted quota and accumulate redb row overhead.
        if blob_size < MIN_BLOB_BYTES {
            return Err(MailboxError::BlobTooSmall {
                actual: blob_size,
                min: MIN_BLOB_BYTES,
            });
        }

        // ── Rate-limit gate (fast-path; in-memory) ────────────────
        // SECURITY (audit 2026-05-29, poison-DoS fix): recover from a
        // poisoned rate-limiter mutex instead of `.expect()`-panicking.
        // A poisoned lock (some prior holder panicked) must NOT cascade
        // into a panic on every subsequent PUT — that would convert one
        // transient panic into a permanent mailbox DoS.  The rate-limiter
        // state is a simple counter map; recovering the guard via
        // `into_inner()` is logically safe (worst case: one stale count).
        let now = (self.clock)();
        if !self
            .rate_limiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .check_and_consume(receiver, now)
        {
            return Ok(PutOutcome::RateLimited);
        }

        // ── Storage path: serialisable redb transaction ───────────
        let txn = self.db.begin_write()?;
        let outcome = {
            let mut blobs = txn.open_table(TABLE_BLOBS)?;
            let mut bytes_per_receiver = txn.open_table(TABLE_RECEIVER_BYTES)?;
            let mut eviction_index = txn.open_table(TABLE_EVICTION_INDEX)?;
            let mut eviction_index_anon = txn.open_table(TABLE_EVICTION_INDEX_ANON)?;
            let mut global_bytes = txn.open_table(TABLE_GLOBAL_BYTES)?;
            let mut sender_bytes = txn.open_table(TABLE_SENDER_BYTES)?;

            let key = make_key(&receiver, &content_id);

            // Dedup: same (receiver, content_id) → no-op.
            if blobs.get(key.as_slice())?.is_some() {
                PutOutcome::Duplicate
            } else {
                // Per-receiver quota (no eviction at this layer).
                let receiver_total = bytes_per_receiver
                    .get(receiver.as_slice())?
                    .map(|v| v.value())
                    .unwrap_or(0);
                if receiver_total.saturating_add(blob_size) > self.config.quota_per_receiver_bytes {
                    PutOutcome::QuotaPerReceiverExceeded {
                        current_bytes: receiver_total,
                        cap_bytes: self.config.quota_per_receiver_bytes,
                    }
                } else {
                    // per-sender quota check.
                    // Audit L-17: default cap = DEFAULT_QUOTA_PER_SENDER_BYTES
                    // (10 MiB), NOT u64::MAX. u64::MAX is the explicit opt-out.
                    let sender_total = sender_bytes
                        .get(sender.as_slice())?
                        .map(|v| v.value())
                        .unwrap_or(0);
                    if sender_total.saturating_add(blob_size) > self.config.quota_per_sender_bytes {
                        PutOutcome::QuotaPerSenderExceeded {
                            current_bytes: sender_total,
                            cap_bytes: self.config.quota_per_sender_bytes,
                        }
                    } else {
                        // Global quota: evict oldest until the new blob fits.
                        // scan anonymous pool
                        // first; only fall back to the identified pool
                        // when anonymous is empty. This protects
                        // tokenized senders' blobs from tokenless-flood
                        // displacement.
                        let mut global_total = global_bytes
                            .get(GLOBAL_BYTES_KEY)?
                            .map(|v| v.value())
                            .unwrap_or(0);
                        let mut evicted: u32 = 0;
                        while global_total.saturating_add(blob_size)
                            > self.config.quota_global_bytes
                        {
                            // Read the oldest entry of BOTH pools up-front. The
                            // eviction-index key is prefixed with the 8-byte
                            // big-endian `deposited_at`, so the first entry of
                            // each index is that pool's oldest blob.
                            let (anon_head, ident_head) = {
                                let anon_head = eviction_index_anon
                                    .iter()?
                                    .next()
                                    .transpose()?
                                    .map(|(k, _)| k.value().to_vec());
                                let ident_head = eviction_index
                                    .iter()?
                                    .next()
                                    .transpose()?
                                    .map(|(k, _)| k.value().to_vec());
                                (anon_head, ident_head)
                            };
                            // audit / C-13: protect recently-deposited blobs from
                            // random-receiver-flood eviction — a victim younger
                            // than [`MIN_EVICTION_AGE_SECS`] is never displaced.
                            // Prefer the anonymous pool (shields tokenized
                            // senders from tokenless-flood displacement), but when
                            // its oldest entry is too young, fall through to an
                            // older *identified* victim instead of rejecting:
                            // otherwise a flood of FRESH anon blobs would bounce
                            // legitimate identified puts even while old,
                            // evictable identified blobs sit below the cap. Only
                            // reject when NEITHER pool has an old-enough head.
                            // Stale attacker traffic ages past this window via
                            // the TTL prune tick (default 7 days, DEFAULT_TTL_SECS).
                            let evictable = |key: &[u8]| -> bool {
                                if key.len() >= 8 {
                                    let mut ts_bytes = [0u8; 8];
                                    ts_bytes.copy_from_slice(&key[..8]);
                                    now.saturating_sub(u64::from_be_bytes(ts_bytes))
                                        >= MIN_EVICTION_AGE_SECS
                                } else {
                                    true
                                }
                            };
                            let (victim_idx_key, victim_class) =
                                if let Some(k) = anon_head.filter(|k| evictable(k)) {
                                    (k, TrustClass::Anonymous)
                                } else if let Some(k) = ident_head.filter(|k| evictable(k)) {
                                    (k, TrustClass::Identified)
                                } else {
                                    // Both heads are too young (or both pools
                                    // empty) → nothing evictable. Reject rather
                                    // than displace fresh content / overflow.
                                    return Ok(PutOutcome::QuotaGlobalExceeded {
                                        blob_size,
                                        cap_bytes: self.config.quota_global_bytes,
                                    });
                                };
                            let (victim_receiver, victim_content_id) =
                                split_eviction_key(&victim_idx_key)?;
                            let victim_blob_key = make_key(&victim_receiver, &victim_content_id);
                            // Read the victim's record so we know its byte count
                            // and its sender_id for per-sender accounting.
                            let victim_record = blobs
                                .get(victim_blob_key.as_slice())?
                                .ok_or(MailboxError::Corrupt(
                                    "eviction-index entry without blobs row",
                                ))?
                                .value()
                                .to_vec();
                            let (victim_sender, _victim_now) =
                                decode_record_header(&victim_record)?;
                            // record header overhead; saturating so a malformed
                            // sub-44-byte record can never underflow-panic here
                            // (decode_record_header above already enforces ≥ 44).
                            let victim_size = (victim_record.len() as u64).saturating_sub(44);
                            // Remove from blobs + correct eviction index +
                            // adjust counters (receiver, sender, global).
                            blobs.remove(victim_blob_key.as_slice())?;
                            match victim_class {
                                TrustClass::Anonymous => {
                                    eviction_index_anon.remove(victim_idx_key.as_slice())?;
                                }
                                TrustClass::Identified => {
                                    eviction_index.remove(victim_idx_key.as_slice())?;
                                }
                            }
                            let victim_recv_total = bytes_per_receiver
                                .get(victim_receiver.as_slice())?
                                .map(|v| v.value())
                                .unwrap_or(0);
                            let victim_recv_after = victim_recv_total.saturating_sub(victim_size);
                            if victim_recv_after == 0 {
                                bytes_per_receiver.remove(victim_receiver.as_slice())?;
                            } else {
                                bytes_per_receiver
                                    .insert(victim_receiver.as_slice(), victim_recv_after)?;
                            }
                            // per-sender counter
                            // bookkeeping on eviction.
                            let victim_sender_total = sender_bytes
                                .get(victim_sender.as_slice())?
                                .map(|v| v.value())
                                .unwrap_or(0);
                            let victim_sender_after =
                                victim_sender_total.saturating_sub(victim_size);
                            if victim_sender_after == 0 {
                                sender_bytes.remove(victim_sender.as_slice())?;
                            } else {
                                sender_bytes
                                    .insert(victim_sender.as_slice(), victim_sender_after)?;
                            }
                            global_total = global_total.saturating_sub(victim_size);
                            evicted = evicted.saturating_add(1);
                        }

                        // Now there is room. Insert.
                        let record = encode_record(&sender, now, &blob);
                        blobs.insert(key.as_slice(), record.as_slice())?;
                        let new_recv_total = receiver_total.saturating_add(blob_size);
                        bytes_per_receiver.insert(receiver.as_slice(), new_recv_total)?;
                        let new_sender_total = sender_total.saturating_add(blob_size);
                        sender_bytes.insert(sender.as_slice(), new_sender_total)?;
                        let evict_key = make_eviction_key(now, &receiver, &content_id);
                        match trust_class {
                            TrustClass::Anonymous => {
                                eviction_index_anon.insert(evict_key.as_slice(), ())?;
                            }
                            TrustClass::Identified => {
                                eviction_index.insert(evict_key.as_slice(), ())?;
                            }
                        }
                        let new_global = global_total.saturating_add(blob_size);
                        global_bytes.insert(GLOBAL_BYTES_KEY, new_global)?;
                        PutOutcome::Stored { evicted }
                    }
                }
            }
        };
        txn.commit()?;
        Ok(outcome)
    }

    /// Fetch up to [`MAX_FETCH_COUNT`] currently-stored blobs for `receiver`
    /// oldest first. Does not delete — caller must call [`Self::ack`] for
    /// each blob after the receiver has received it end-to-end.
    ///
    /// ** bounded result. Pre-fix a
    /// receiver could trigger ~10 GiB heap allocation if an attacker
    /// deposited ~100M one-byte blobs against its 100 MiB byte quota.
    /// Now the result is capped and a caller with more queued messages must
    /// ack the returned batch and call `fetch` again. Caller-visible
    /// behaviour change: of clients written before this fix that didn't
    /// drain in loops would now leave older blobs unacked indefinitely;
    /// the standard mailbox-IPC consumer (`MailboxIpcBridge`) already
    /// drains in a loop because it ack's per-record after delivery.
    pub fn fetch(&self, receiver: [u8; 32]) -> Result<Vec<MailboxBlob>, MailboxError> {
        let txn = self.db.begin_read()?;
        let blobs = txn.open_table(TABLE_BLOBS)?;
        // Range scan: prefix = receiver_id || 0..0.. receiver_id || ff..ff.
        let mut start = [0u8; KEY_LEN];
        start[..32].copy_from_slice(&receiver);
        let mut end = [0xFFu8; KEY_LEN];
        end[..32].copy_from_slice(&receiver);
        // audit U10: select the MAX_FETCH_COUNT OLDEST records by scanning
        // HEADERS only (decode_record_header does NOT allocate the blob) into a
        // bounded max-heap, then load the blob for ONLY the survivors below.
        // Peak memory is therefore ~MAX_FETCH_COUNT small (u64, [u8;32]) tuples
        // regardless of how many records the receiver has accumulated. The
        // previous loop materialized every matching record's full blob before
        // truncating, so peak RSS scaled with the stored count (bounded only by
        // the per-receiver byte quota), not the documented MAX_FETCH_COUNT cap.
        //
        // BinaryHeap is a max-heap on `(deposited_at, content_id)`: the newest
        // sits on top, so popping once we exceed the cap leaves the N OLDEST.
        let mut heap: std::collections::BinaryHeap<(u64, [u8; 32])> =
            std::collections::BinaryHeap::with_capacity(MAX_FETCH_COUNT + 1);
        for entry in blobs.range::<&[u8]>(start.as_slice()..=end.as_slice())? {
            let (k, v) = entry?;
            let key_bytes = k.value();
            if key_bytes.len() != KEY_LEN || key_bytes[..32] != receiver {
                // Should not happen given the range bounds, but a corrupt
                // key shouldn't crash the fetcher — skip and continue.
                continue;
            }
            let mut content_id = [0u8; 32];
            content_id.copy_from_slice(&key_bytes[32..]);
            let (_sender, deposited_at) = decode_record_header(v.value())?;
            heap.push((deposited_at, content_id));
            if heap.len() > MAX_FETCH_COUNT {
                heap.pop(); // drop the newest beyond the cap
            }
        }
        // Order the selected survivors oldest-first (FIFO drain semantics).
        let mut selected: Vec<(u64, [u8; 32])> = heap.into_vec();
        selected.sort_unstable();
        // Load the blob for ONLY the selected records.
        let mut out: Vec<MailboxBlob> = Vec::with_capacity(selected.len());
        for (deposited_at, content_id) in selected {
            let mut key = [0u8; KEY_LEN];
            key[..32].copy_from_slice(&receiver);
            key[32..].copy_from_slice(&content_id);
            if let Some(v) = blobs.get(key.as_slice())? {
                let (sender, _ts, blob) = decode_record(v.value())?;
                out.push(MailboxBlob {
                    sender_id: sender,
                    content_id,
                    deposited_at,
                    blob,
                });
            }
        }
        Ok(out)
    }

    /// Acknowledge receipt: delete `(receiver, content_id)` if it
    /// exists. Idempotent — acking a non-existent or already-acked
    /// blob is a successful no-op.
    pub fn ack(&self, receiver: [u8; 32], content_id: [u8; 32]) -> Result<bool, MailboxError> {
        let txn = self.db.begin_write()?;
        let mut should_commit = false;
        let removed = {
            let mut blobs = txn.open_table(TABLE_BLOBS)?;
            let mut bytes_per_receiver = txn.open_table(TABLE_RECEIVER_BYTES)?;
            let mut eviction_index = txn.open_table(TABLE_EVICTION_INDEX)?;
            let mut eviction_index_anon = txn.open_table(TABLE_EVICTION_INDEX_ANON)?;
            let mut global_bytes = txn.open_table(TABLE_GLOBAL_BYTES)?;
            let mut sender_bytes = txn.open_table(TABLE_SENDER_BYTES)?;

            let key = make_key(&receiver, &content_id);
            // Materialise the record bytes before touching mutable APIs so
            // the immutable borrow of `blobs` ends before `blobs.remove`.
            let record_bytes_opt = blobs.get(key.as_slice())?.map(|g| g.value().to_vec());
            match record_bytes_opt {
                None => false,
                Some(record_bytes) => {
                    let (sender, deposited_at, blob) = decode_record(&record_bytes)?;
                    let blob_size = blob.len() as u64;
                    blobs.remove(key.as_slice())?;
                    let evict_key = make_eviction_key(deposited_at, &receiver, &content_id);
                    // ack does not know which
                    // index the entry lives in — try both (remove on missing
                    // is a no-op). At most one will fire.
                    eviction_index.remove(evict_key.as_slice())?;
                    eviction_index_anon.remove(evict_key.as_slice())?;
                    let recv_total = bytes_per_receiver
                        .get(receiver.as_slice())?
                        .map(|v| v.value())
                        .unwrap_or(0)
                        .saturating_sub(blob_size);
                    if recv_total == 0 {
                        bytes_per_receiver.remove(receiver.as_slice())?;
                    } else {
                        bytes_per_receiver.insert(receiver.as_slice(), recv_total)?;
                    }
                    // per-sender counter bookkeeping.
                    let sender_total = sender_bytes
                        .get(sender.as_slice())?
                        .map(|v| v.value())
                        .unwrap_or(0)
                        .saturating_sub(blob_size);
                    if sender_total == 0 {
                        sender_bytes.remove(sender.as_slice())?;
                    } else {
                        sender_bytes.insert(sender.as_slice(), sender_total)?;
                    }
                    let new_global = global_bytes
                        .get(GLOBAL_BYTES_KEY)?
                        .map(|v| v.value())
                        .unwrap_or(0)
                        .saturating_sub(blob_size);
                    global_bytes.insert(GLOBAL_BYTES_KEY, new_global)?;
                    should_commit = true;
                    true
                }
            }
        };
        if should_commit {
            txn.commit()?;
        }
        // If!should_commit, txn drops here without commit (= abort).
        Ok(removed)
    }

    /// Remove all blobs older than `now - ttl_secs`. Returns the
    /// count of pruned blobs. Designed for periodic background
    /// invocation (every few minutes).
    pub fn prune_expired(&self) -> Result<u64, MailboxError> {
        let now = (self.clock)();
        let cutoff = now.saturating_sub(self.config.ttl_secs);
        let txn = self.db.begin_write()?;
        let pruned = {
            let mut blobs = txn.open_table(TABLE_BLOBS)?;
            let mut bytes_per_receiver = txn.open_table(TABLE_RECEIVER_BYTES)?;
            let mut eviction_index = txn.open_table(TABLE_EVICTION_INDEX)?;
            let mut eviction_index_anon = txn.open_table(TABLE_EVICTION_INDEX_ANON)?;
            let mut global_bytes = txn.open_table(TABLE_GLOBAL_BYTES)?;
            let mut sender_bytes = txn.open_table(TABLE_SENDER_BYTES)?;

            // Range walk on eviction_index: keys with deposited_at < cutoff.
            let cutoff_be = cutoff.to_be_bytes();
            // Build an upper-bound key that compares strictly less than
            // `(cutoff, 0..0, 0..0)`. Iterate up (exclusive).
            let mut upper = [0u8; 8 + 32 + 32];
            upper[..8].copy_from_slice(&cutoff_be);
            // Collect victim keys first; redb table mutation while
            // iterating the same table is forbidden.
            // walk both indexes.
            let mut victims_anon: Vec<Vec<u8>> = Vec::new();
            let mut victims_id: Vec<Vec<u8>> = Vec::new();
            {
                let lower = [0u8; 8 + 32 + 32];
                let iter = eviction_index.range::<&[u8]>(lower.as_slice()..upper.as_slice())?;
                for entry in iter {
                    let (k, _) = entry?;
                    victims_id.push(k.value().to_vec());
                }
                let iter =
                    eviction_index_anon.range::<&[u8]>(lower.as_slice()..upper.as_slice())?;
                for entry in iter {
                    let (k, _) = entry?;
                    victims_anon.push(k.value().to_vec());
                }
            }
            let mut pruned: u64 = 0;
            let mut global_total = global_bytes
                .get(GLOBAL_BYTES_KEY)?
                .map(|v| v.value())
                .unwrap_or(0);
            // Drain anon pool first, then identified. Same shape for both;
            // only the index-table reference differs.
            for (victim_idx_key, is_anon) in victims_anon
                .into_iter()
                .map(|k| (k, true))
                .chain(victims_id.into_iter().map(|k| (k, false)))
            {
                let (recv, cid) = split_eviction_key(&victim_idx_key)?;
                let blob_key = make_key(&recv, &cid);
                let record_bytes_opt = blobs.get(blob_key.as_slice())?.map(|g| g.value().to_vec());
                if let Some(record_bytes) = record_bytes_opt {
                    let (sender, _ts, blob) = decode_record(&record_bytes)?;
                    let blob_size = blob.len() as u64;
                    blobs.remove(blob_key.as_slice())?;
                    let recv_total = bytes_per_receiver
                        .get(recv.as_slice())?
                        .map(|v| v.value())
                        .unwrap_or(0)
                        .saturating_sub(blob_size);
                    if recv_total == 0 {
                        bytes_per_receiver.remove(recv.as_slice())?;
                    } else {
                        bytes_per_receiver.insert(recv.as_slice(), recv_total)?;
                    }
                    // per-sender bookkeeping.
                    let sender_total = sender_bytes
                        .get(sender.as_slice())?
                        .map(|v| v.value())
                        .unwrap_or(0)
                        .saturating_sub(blob_size);
                    if sender_total == 0 {
                        sender_bytes.remove(sender.as_slice())?;
                    } else {
                        sender_bytes.insert(sender.as_slice(), sender_total)?;
                    }
                    global_total = global_total.saturating_sub(blob_size);
                    pruned = pruned.saturating_add(1);
                }
                if is_anon {
                    eviction_index_anon.remove(victim_idx_key.as_slice())?;
                } else {
                    eviction_index.remove(victim_idx_key.as_slice())?;
                }
            }
            global_bytes.insert(GLOBAL_BYTES_KEY, global_total)?;
            pruned
        };
        txn.commit()?;
        Ok(pruned)
    }

    /// Snapshot global storage stats. Cheap (single-key reads).
    pub fn stats(&self) -> Result<MailboxStats, MailboxError> {
        let txn = self.db.begin_read()?;
        let global_bytes = txn.open_table(TABLE_GLOBAL_BYTES)?;
        let blobs = txn.open_table(TABLE_BLOBS)?;
        let total_blob_bytes = global_bytes
            .get(GLOBAL_BYTES_KEY)?
            .map(|v| v.value())
            .unwrap_or(0);
        let blob_count = blobs.len()?;
        Ok(MailboxStats {
            total_blob_bytes,
            blob_count,
        })
    }

    /// Bytes currently used by `receiver` (for quota observability).
    pub fn receiver_bytes(&self, receiver: [u8; 32]) -> Result<u64, MailboxError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(TABLE_RECEIVER_BYTES)?;
        Ok(t.get(receiver.as_slice())?.map(|v| v.value()).unwrap_or(0))
    }
}

fn split_eviction_key(k: &[u8]) -> Result<([u8; 32], [u8; 32]), MailboxError> {
    if k.len() != 8 + 32 + 32 {
        return Err(MailboxError::Corrupt("eviction key wrong length"));
    }
    let mut recv = [0u8; 32];
    let mut cid = [0u8; 32];
    recv.copy_from_slice(&k[8..40]);
    cid.copy_from_slice(&k[40..72]);
    Ok((recv, cid))
}

#[cfg(test)]
mod tests;
