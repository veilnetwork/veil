//! Anonymous reliable byte-streams over veil's onion transport.
//!
//! The fire-and-forget anonymous DATAGRAM path has no congestion control, so a
//! fast sender outruns the relays' bounded TX queues and ~80 % of a bulk
//! transfer is dropped (the ~200 KB/s file-transfer wall). [`AnonStreamHub`]
//! fixes that by running `veil-onion-stream` (end-to-end ARQ + AIMD congestion
//! control) over a [`CellSender`]. Two backends:
//!
//! - DEFAULT (`AnonCells`): each cell rides `send_anonymous_authenticated` — a
//!   FRESH onion circuit + per-cell signature/verify. Reliable, but the per-cell
//!   circuit build inflates the RTT and the varying paths cause reordering →
//!   spurious recoveries → ~42 KB/s (device-measured).
//! - PINNED CIRCUIT (`CircuitCells`, opt-in `VEIL_ONION_STREAM_CIRCUIT=1`): a
//!   build-once inbound stateful circuit to this node's published rendezvous relay
//!   plus lazy per-peer outbound circuits to each receiver's published R; cheap XOR
//!   `CircuitData` cells, no per-cell ECDH/signature, in-order, stable RTT. R
//!   splices each cell onto the peer's registered circuit. Published mode hides
//!   the sender node id from R behind an opaque per-circuit tag plus encrypted
//!   handshake intro; validation mode keeps the old clear sender-id shortcut.
//!   Needs the embedded node (in-process `NodeServices`).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;
use veil_anonymity::circuit_register::COOKIE_LEN;
use veil_onion_stream::wire::Frame;
use veil_onion_stream::{Addr, CellSender, Config, End, OnionStream, StreamMux};
use veilclient::{AppSender, IncomingMessage};

/// Emit a one-line diagnostic that NEVER panics. `eprintln!` PANICS if the
/// underlying stderr write fails — and under `flutter run` the desktop app's
/// stderr is a pipe that can break, so an `eprintln!` mid-stream panicked and,
/// unwinding across the `extern "C"` FFI boundary, aborted the whole process
/// (the observed silent desktop crash). Write directly and swallow any error;
/// mirror to logcat on Android (the node's tracing logger doesn't reach it).
fn diag(msg: &str) {
    #[cfg(target_os = "android")]
    log::warn!("{msg}");
    #[cfg(not(target_os = "android"))]
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "{msg}");
    }
}

fn diag_node(node: &[u8; 32], msg: &str) {
    diag(&format!("onion-stream[{}]: {msg}", short_node(node)));
}

/// Well-known endpoint the onion-stream cells ride (distinct from the chat
/// inbox). Both peers bind it; a peer's app id is `deriveAppId(peer_node,
/// STREAM_NAMESPACE, STREAM_NAME)` — the caller supplies it (mirrors how the
/// direct `veil_stream_open` takes `dst_app_id`).
pub const STREAM_NAMESPACE: &str = "xveil";
pub const STREAM_NAME: &str = "onion-stream";
pub const STREAM_ENDPOINT_ID: u32 = 12;

/// Gate for the PINNED STATEFUL-CIRCUIT stream path.
///
/// Default is ON (published-rendezvous mode): the pinned circuit IS the
/// production bulk path — it was opt-in only while experimental, and a
/// distribution build launched without the soak harness's env then silently
/// ran the legacy ~40 KB/s datagram path (live symptom: file transfers that
/// never finish, while a soak-launched peer on the circuit backend cannot
/// interoperate on bulk streams at all). Runtime fallback to the datagram
/// path still happens automatically when no embedded node is present or the
/// circuit backend fails to start. On Android, where process env is not
/// normally injectable, the same values are also read from system property
/// `debug.veil.onion_stream_circuit`. Values:
///
/// - unset / `1|true|yes|on|published|prod|production`: resolve published
///   rendezvous ads and build per-peer circuits to the receiver's R.
/// - `validation|legacy|min-routing`: old test-net shortcut where both
///   endpoints independently pick `min(routing)` as R.
/// - anything else (`0|off|false|datagram|…`): force the datagram path.
///
/// Both peers must agree.
const CIRCUIT_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT";
const CIRCUIT_PREFER_RENDEZVOUS_ENV: &str = "VEIL_ONION_STREAM_PREFER_RENDEZVOUS";
// Current public test stand preference. c6ace22e repeatedly reset long
// published-rendezvous stream soaks, while 3d3575c9 completed the same 64 MiB
// transfers without session resets. Operators can still override this order via
// VEIL_ONION_STREAM_PREFER_RENDEZVOUS / debug.veil.onion_stream_prefer_rendezvous.
const CIRCUIT_TEST_STAND_PREFERRED_RENDEZVOUS_PREFIX: &str = "3d3575c9";
const ANDROID_CIRCUIT_PROP: &str = "debug.veil.onion_stream_circuit";
const ANDROID_PREFER_RENDEZVOUS_PROP: &str = "debug.veil.onion_stream_prefer_rendezvous";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CircuitMode {
    PublishedRendezvous,
    ValidationMinRouting,
}

/// Whether/how to attempt the pinned-circuit backend (default ON; an explicit
/// env/property value can force a mode or the datagram path — see CIRCUIT_ENV).
fn circuit_mode() -> Option<CircuitMode> {
    match std::env::var(CIRCUIT_ENV)
        .ok()
        .or_else(|| android_string_property(ANDROID_CIRCUIT_PROP))
    {
        Some(v) => circuit_env_value_mode(&v),
        None => Some(CircuitMode::PublishedRendezvous),
    }
}

fn circuit_env_value_mode(v: &str) -> Option<CircuitMode> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "published" | "prod" | "production" => {
            Some(CircuitMode::PublishedRendezvous)
        }
        "validation" | "legacy" | "min-routing" | "min_routing" => {
            Some(CircuitMode::ValidationMinRouting)
        }
        _ => None,
    }
}

#[cfg(not(target_os = "android"))]
fn android_string_property(_name: &str) -> Option<String> {
    None
}

#[cfg(target_os = "android")]
fn android_string_property(name: &str) -> Option<String> {
    android_system_property(name)
}

#[cfg(target_os = "android")]
fn android_system_property(name: &str) -> Option<String> {
    use std::ffi::{CStr, CString};

    unsafe extern "C" {
        fn __system_property_get(
            name: *const libc::c_char,
            value: *mut libc::c_char,
        ) -> libc::c_int;
    }

    let name = CString::new(name).ok()?;
    // Android PROP_VALUE_MAX is 92 including NUL. libc does not expose it on all
    // targets, so keep the platform constant local.
    let mut value = [0 as libc::c_char; 92];
    let len = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(value.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn preferred_rendezvous_prefixes() -> Vec<String> {
    std::env::var(CIRCUIT_PREFER_RENDEZVOUS_ENV)
        .ok()
        .or_else(|| android_string_property(ANDROID_PREFER_RENDEZVOUS_PROP))
        .map(|value| {
            value
                .split([',', ';', ' '])
                .filter_map(|part| {
                    let normalized = part.trim().to_ascii_lowercase();
                    if normalized.chars().all(|c| c.is_ascii_hexdigit()) && normalized.len() >= 4 {
                        Some(normalized)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn rendezvous_preference_rank(relay: &[u8; 32], prefixes: &[String]) -> usize {
    if prefixes.is_empty() {
        return usize::MAX;
    }
    let relay_hex = relay.iter().map(|b| format!("{b:02x}")).collect::<String>();
    prefixes
        .iter()
        .position(|prefix| relay_hex.starts_with(prefix))
        .unwrap_or(usize::MAX)
}

fn rendezvous_default_stand_rank(relay: &[u8; 32]) -> usize {
    let relay_hex = relay.iter().map(|b| format!("{b:02x}")).collect::<String>();
    if relay_hex.starts_with(CIRCUIT_TEST_STAND_PREFERRED_RENDEZVOUS_PREFIX) {
        0
    } else {
        1
    }
}

fn short_cookie(cookie: &[u8; COOKIE_LEN]) -> String {
    let mut s = String::with_capacity(8);
    for b in &cookie[..4] {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Smaller MSS for the circuit path so the onion-stream cell + the
/// `[cookie 16][peer_tag 32]` splice envelope exactly fill one fixed
/// CircuitData cell (4096-B since the 2026-07-02 flag-day bump).
const CIRCUIT_PEER_TAG_LEN: usize = 32;
const CIRCUIT_MSS: usize = veil_onion_stream::wire::MAX_CELL
    - COOKIE_LEN
    - CIRCUIT_PEER_TAG_LEN
    - veil_onion_stream::wire::DATA_OVERHEAD;
// The onion-stream crate is transport-agnostic, so its MAX_CELL cannot
// reference veil-anonymity directly; hold the tie here where both crates are
// visible. The send path caps every splice envelope (cookie + tag + stream
// cell) at MAX_CELL, so MAX_CELL must not exceed what the circuit's fixed
// inner payload accepts. A max-size DATA envelope fills it exactly:
// COOKIE(16) + TAG(32) + DATA_OVERHEAD(16) + CIRCUIT_MSS == MAX_CELL.
const _: () =
    assert!(veil_onion_stream::wire::MAX_CELL <= veil_anonymity::circuit_data::MAX_CIRCUIT_INNER);
const CIRCUIT_INTRO_MARKER: u8 = 0xA7;
const CIRCUIT_INTRO_PLAINTEXT_MAGIC: &[u8; 16] = b"xveil-stream-v1!";
const CIRCUIT_INTRO_PLAINTEXT_LEN: usize = 16 + CIRCUIT_PEER_TAG_LEN + 32;
const CIRCUIT_INTRO_LEN: usize =
    veil_anonymity::rendezvous::INTRODUCE_OVERHEAD + CIRCUIT_INTRO_PLAINTEXT_LEN;
const CIRCUIT_HOPS: usize = 2;
// How long a pinned INBOUND circuit may sit idle (no received data) before it is
// rebuilt on a fresh path. Raised 45s -> 300s: the 45s rebuild cadence was pure
// churn now that (a) the 15s forward heartbeat keeps the circuit + its hop TCP
// sessions alive, and (b) the recipient recheck re-registers the rendezvous
// cookie every 15s (subscription TTL 600s), so neither liveness nor the relay
// registration needs a frequent circuit rebuild. Each rebuild opens a brief
// window where an introduce forwarded down the retiring generation stalls until
// the sender's retry hits the new one — device-observed as ~10-20s inbound
// stalls (desktop receiver, 234 generations/session). Fewer rebuilds = fewer
// such windows. Still bounded well under the 600s cookie TTL so a genuinely
// dead path (heartbeat failing) still rotates for path freshness.
const CIRCUIT_IDLE_REFRESH_AFTER: Duration = Duration::from_secs(300);
// A long-lived outbound circuit can black-hole after a bulk stream RTOs. The
// content layer then opens a fresh stream and sends SYNs, but idle-based refresh
// alone keeps reusing the same stale circuit because every retry updates
// `last_used`. On a new stream handshake, rotate an old circuit if it has not
// carried real DATA/ACK traffic recently. This avoids mid-stream timed rotation
// while making resume retries pick a fresh rendezvous path quickly.
const CIRCUIT_HANDSHAKE_REOPEN_AFTER: Duration = Duration::from_secs(15);
const CIRCUIT_PUBLISHED_RELAY_EXPAND_AFTER: Duration = Duration::from_secs(5);
const CIRCUIT_REFRESH_POLL: Duration = Duration::from_secs(5);
// How often the receiver sends a FORWARD keepalive heartbeat up each pinned
// inbound circuit (`veil_anonymity::circuit_data::CIRCUIT_HEARTBEAT_MAGIC`).
// The inbound circuit is otherwise receive-only, so its first-hop TCP session
// only carries traffic when the node happens to transmit for another reason;
// left idle it dies (mobile power-save / NAT rebind / VPN) and the rendezvous
// relay's downstream introduce pushes queue behind a dead socket until the
// node next sends — the measured 10–60 s delivery stalls that flushed in a
// batch. 15 s beats the ~10–20 s stalls and stays well under the session
// keepalive base (30 s, stretched ×up-to-120 in background). One tiny cell per
// circuit per interval — negligible cost. Must be a multiple-ish of
// CIRCUIT_REFRESH_POLL (5 s); the poll loop fires it on the first tick at/after
// the interval.
const CIRCUIT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const CIRCUIT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);
// Loopback splice-probe cadence inside the confirm window: give the ordinary
// CircuitBuilt ACK a short head start, then probe repeatedly (each probe is an
// independent end-to-end proof; WAN loss that eats the one-shot ACK rarely eats
// every probe in the window too).
const CIRCUIT_CONFIRM_PROBE_INITIAL_DELAY: Duration = Duration::from_millis(1_000);
const CIRCUIT_CONFIRM_PROBE_INTERVAL: Duration = Duration::from_millis(1_500);
// When some published relays failed confirmation (no ACK *and* no probe echo —
// the registration really is absent at that relay), re-run the open/register
// cycle after this much idle instead of waiting the full idle-refresh (300 s):
// the relay's PREVIOUS binding for our cookie survives at most the 600 s
// registry TTL, so a relay that keeps losing our CircuitBuild forward would
// otherwise go dark for pullers that resolve its still-published ad.
const CIRCUIT_UNCONFIRMED_RETRY_AFTER: Duration = Duration::from_secs(30);
// Inbound starvation: the receive side of this hub is provably dead while we
// keep TALKING into the network. Live incident shape (2026-07-06, reproduced
// on the bench after a long netem window): every registration confirmed, the
// 15 s heartbeats flow, retrying pulls/serves keep the circuits "active" —
// but the relay→us return leg black-holes, so idle-refresh (gated on
// idle_for, which SENDS keep resetting) never fires and the pool stays
// "healthy" forever. Manual app restart was the only cure. Trigger: we sent
// hub traffic within SEND_RECENT (real stream cells — heartbeats bypass the
// activity stamp) yet received NOTHING for STARVATION_AFTER → rebuild +
// re-register the inbound generation. generation_age must also exceed the
// threshold so a fresh generation gets a full window to deliver before it
// can be recycled (this also bounds the retry cadence while the network
// stays broken).
const CIRCUIT_INBOUND_STARVATION_AFTER: Duration = Duration::from_secs(90);
const CIRCUIT_INBOUND_STARVATION_SEND_RECENT: Duration = Duration::from_secs(20);
const STREAM_DATA_PACE_US_ENV: &str = "VEIL_ONION_STREAM_DATA_PACE_US";
const CIRCUIT_DATA_PACE_US_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_DATA_PACE_US";
const CIRCUIT_RECV_WINDOW_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_RECV_WINDOW";
const CIRCUIT_MAX_PACING_BATCH_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_MAX_PACING_BATCH";
const CIRCUIT_MAX_RETRANSMITS_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_MAX_RETRANSMITS";
const CIRCUIT_INIT_RTO_MS_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_INIT_RTO_MS";
const CIRCUIT_MIN_RTO_MS_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_MIN_RTO_MS";
const CIRCUIT_MAX_RTO_MS_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_MAX_RTO_MS";
const CIRCUIT_INIT_CWND_MSS_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_INIT_CWND_MSS";
const CIRCUIT_OUTBOUND_POOL_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_OUTBOUND_POOL";
const CIRCUIT_ACK_OUTBOUND_POOL_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_ACK_OUTBOUND_POOL";
const CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT_ENV: &str =
    "VEIL_ONION_STREAM_CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT";
const DEBUG_SUMMARY_MS_ENV: &str = "VEIL_ONION_STREAM_DEBUG_SUMMARY_MS";
const ANDROID_DEBUG_SUMMARY_MS_PROP: &str = "debug.veil.onion_stream_debug_summary_ms";
const ANDROID_INIT_RTO_MS_PROP: &str = "debug.veil.onion_stream_init_rto_ms";
const ANDROID_MIN_RTO_MS_PROP: &str = "debug.veil.onion_stream_min_rto_ms";
const ANDROID_MAX_RTO_MS_PROP: &str = "debug.veil.onion_stream_max_rto_ms";
const ANDROID_MAX_RETRANSMITS_PROP: &str = "debug.veil.onion_stream_max_retransmits";
const ANDROID_INIT_CWND_MSS_PROP: &str = "debug.veil.onion_stream_init_cwnd_mss";
const ANDROID_OUTBOUND_POOL_PROP: &str = "debug.veil.onion_stream_outbound_pool";
const ANDROID_ACK_OUTBOUND_POOL_PROP: &str = "debug.veil.onion_stream_ack_outbound_pool";
const ANDROID_BULK_ROUTE_ACTIVE_LIMIT_PROP: &str =
    "debug.veil.onion_stream_bulk_route_active_limit";
const ANDROID_MAX_PACING_BATCH_PROP: &str = "debug.veil.onion_stream_max_pacing_batch";
const ANDROID_DATA_PACE_US_PROP: &str = "debug.veil.onion_stream_data_pace_us";
const CIRCUIT_BBR_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_BBR";
const ANDROID_BBR_PROP: &str = "debug.veil.onion_stream_bbr";
/// RACK time-threshold loss detection (engine `Config::rack`), circuit-only.
/// Default ON: the SACK-count/dup-ACK detector misreads any reordering (ACK
/// jitter across route remaps, and systematically under route striping) as
/// loss; RACK declares loss by TIME past a later delivery instead.
const CIRCUIT_RACK_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_RACK";
const ANDROID_RACK_PROP: &str = "debug.veil.onion_stream_rack";
/// Floor (ms) for RACK's adaptive reordering window. Defaults to 0 on a
/// single pinned route (min-RTT/4 base + adaptation suffice) and to
/// [`DEFAULT_STRIPE_RACK_REO_FLOOR_MS`] when route striping is enabled, so
/// the FIRST striped flight already tolerates the cross-route delivery skew.
const CIRCUIT_RACK_REO_FLOOR_MS_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_RACK_REO_FLOOR_MS";
const ANDROID_RACK_REO_FLOOR_MS_PROP: &str = "debug.veil.onion_stream_rack_reo_floor_ms";
const DEFAULT_STRIPE_RACK_REO_FLOOR_MS: u32 = 1_500;
/// Stripe one bulk stream's DATA cells across up to this many distinct
/// outbound routes (distinct first-hop sessions). 1 = classic single-route
/// pinning.
///
/// ⚠️ PROVEN NOT TO WORK as a throughput lever; kept default-1 (off) as a
/// gated experiment base only. The premise was sound — the per-flow ceiling
/// is the first-hop session TCP (live: one flow ~15-17 MB/s, three parallel
/// ~29 MB/s), so one engine fanning its wire across sessions should harvest
/// the aggregate. It does not, because a SINGLE BBR/NewReno control loop
/// cannot distinguish cross-path REORDERING from loss. Two independent
/// striping layouts were measured against a clean-seed single-route baseline
/// (64 MiB, fresh rendezvous registries):
///   * contiguous chunks (seq-block per route): the head-of-line block on a
///     lagging route stalls snd_una with nothing above it to SACK -> a
///     no-SACK RTO collapses the window (sack=0, wb=0, ssthresh pinned
///     ~155 KB, ~3x slowdown).
///   * interleaved cells (round-robin): the reordering generates >=3 dup-ACKs
///     within the first RTT -> fast-retransmit recovery cuts ssthresh ~200 KB
///     -> congestion-avoidance crawl (~4x slowdown).
/// Both collapse via the loss detector misreading reordering. (Earlier notes
/// blamed rendezvous CookieClaimed; that was wrong — clean-seed runs
/// reproduced the collapse with zero registration errors.)
///
/// UPDATE (RACK, engine Config::rack default-on for circuits): the collapse
/// is GONE — with time-threshold loss detection striped runs show zero
/// spurious resends and never cut ssthresh (5-pair device A/B, 64 MiB).
/// Striping is now SAFE to enable, but stays default-1 because it did not
/// out-run single-route in healthy windows (median 14.2s vs 13.3s): the
/// chain's funnel is the receiver-side R->receiver single obfs4/TCP flow
/// (~12-14 MB/s), which one route already saturates, while striping adds a
/// reorder-window delay. It DID dodge a degraded-route window (7.5s vs
/// 36.3s), so it remains a deliberate opt-in for sender-uplink-limited or
/// flaky-route scenarios — flipping it on requires nothing else now.
const CIRCUIT_STRIPE_ROUTES_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_STRIPE_ROUTES";
const ANDROID_STRIPE_ROUTES_PROP: &str = "debug.veil.onion_stream_stripe_routes";
const DEFAULT_CIRCUIT_STRIPE_ROUTES: usize = 1;
/// Below this many cells a run is not worth splitting (per-chunk route
/// resolve/bookkeeping would dominate; reordering absorbs nothing).
const STRIPE_MIN_RUN_CELLS: usize = 32;
const DEFAULT_DATA_PACE_US: u64 = 100;
const DEFAULT_CIRCUIT_DATA_PACE_US: u64 = 50;
const MIN_DATA_PACE_US: u64 = 10;
const MAX_DATA_PACE_US: u64 = 5_000;
const DEFAULT_CIRCUIT_OUTBOUND_POOL: usize = 3;
/// How many of the (shared) outbound pool entries pure-ACK cells may SELECT
/// from. Historically 1 (ACKs pinned to pool entry #0 for a stable ACK clock),
/// which made the return leg a single point of failure with no health signal:
/// a pure ACK never RTOs, so a lossy/black-holed ACK chain is invisible to the
/// receiver — the sender stalls (snd_una frozen), RTO-retransmits, the receiver
/// re-ACKs into the same dead chain forever. Span the full pool so a cooled or
/// dead entry #0 no longer silently drops every ACK.
const DEFAULT_CIRCUIT_ACK_OUTBOUND_POOL: usize = 3;
/// Total copies of each pure-ACK cell sent over DISTINCT rendezvous routes
/// (1 = no redundancy). ACK cells are ~100 bytes vs 16 KiB DATA cells and are
/// cumulative/idempotent, so duplicating them across two return chains costs
/// <1% overhead while turning return-leg loss p into p² for the ACK clock.
/// The engine ignores regressing cumulative ACKs and (with RACK, the circuit
/// default) never enters recovery from duplicate-ACK counts, so extra copies
/// are correctness-neutral. Same relays the stream already uses — no new
/// anonymity exposure.
const CIRCUIT_ACK_REDUNDANCY_ENV: &str = "VEIL_ONION_STREAM_CIRCUIT_ACK_REDUNDANCY";
const ANDROID_ACK_REDUNDANCY_PROP: &str = "debug.veil.onion_stream_ack_redundancy";
const DEFAULT_CIRCUIT_ACK_REDUNDANCY: usize = 2;
const MAX_CIRCUIT_ACK_REDUNDANCY: usize = 4;
const DEFAULT_CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT: usize = 2;
const DEFAULT_CIRCUIT_INIT_CWND_MSS: usize = 64;
const MAX_CIRCUIT_INIT_CWND_MSS: usize = 256;
const MAX_CIRCUIT_OUTBOUND_POOL: usize = 8;
const MAX_CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT: usize = 64;
const STREAM_RENDEZVOUS_AD_FRESH_GRACE_SECS: u64 = 30;
const CIRCUIT_ROUTE_SEND_COOLDOWN: Duration = Duration::from_secs(60);
// `StreamEngine::consec_rto` resets on any cumulative ACK progress. A black-holed
// circuit can still dribble one repaired MSS per coarse RTO, so `consec_rto`
// never reaches 2 while the file transfer is effectively stuck. Count repeated
// RTOs for the SAME stream as well, but do not aggregate independent p12 range
// streams into a fake route-wide failure.
const CIRCUIT_ROUTE_NO_PROGRESS_RTO_EVENTS: u64 = 3;
// A route-level RTO is only a weak signal when the same route is actively
// carrying other DATA/ACK streams. With high range fanout (p10/p12) ACK jitter
// can produce isolated stream RTOs while the rendezvous is still healthy; cooling
// that relay immediately causes self-inflicted route storms and long tails. Give
// busy, recently-progressing routes a short grace window; when no-progress is
// confirmed, remap the affected stream without cooling/retiring the rendezvous.
const CIRCUIT_ROUTE_BUSY_RECENT_DATA_GRACE: Duration = Duration::from_secs(2);
const CIRCUIT_ROUTE_BUSY_MIN_DATA_CELLS: u64 = 1024;
const CIRCUIT_ROUTE_BUSY_RTO_EVENTS: u64 = 6;
const CIRCUIT_ROUTE_NO_PROGRESS_COOLDOWN: Duration = Duration::from_secs(20);
// Throughput-aware route shedding. A sick-but-alive chain under RACK repair
// rarely RTOs — losses get repaired by later deliveries, cwnd adapts, and the
// stream just CRAWLS (device A/B 2026-07-06: 20 MB in 183 s on one netem'd
// chain vs 15 s on a clean one), so neither consec_rto nor the no-progress
// path ever fires. Measure per-route DATA throughput over a sliding window;
// after enough consecutive windows that are BUSY (enough bytes to rule out an
// app-limited stream) yet SLOW (below the crawl floor), remap the bulk stream
// to another usable pool route — non-quarantine, rendezvous kept warm, same
// semantics as the no-progress remap. Anti-flap: per-peer shed cooldown, and
// the fresh route starts with a zeroed window streak so it gets a full
// measurement period before it can be shed again.
const CIRCUIT_ROUTE_SHED_WINDOW: Duration = Duration::from_secs(5);
// Crawl floor: clean chains against the production seeds sustain ≥1 MB/s;
// the netem'd sick chain crawled at ~115 KB/s. 256 KiB/s splits those with
// margin on both sides.
const CIRCUIT_ROUTE_SHED_FLOOR_BPS: u64 = 256 * 1024;
// Windows carrying less than this many bytes are treated as app-limited
// (chat, trickle) and never count toward the slow streak.
const CIRCUIT_ROUTE_SHED_MIN_WINDOW_BYTES: u64 = 128 * 1024;
const CIRCUIT_ROUTE_SHED_SLOW_WINDOWS: u32 = 2;
const CIRCUIT_ROUTE_SHED_COOLDOWN: Duration = Duration::from_secs(20);
// How long a route stays marked "crawling" after its last busy-but-slow
// window. The mark (a) biases route selection away from the sick chain for
// NEW streams — short serve/manifest streams otherwise keep landing on it
// via round-robin and dying on the peer's manifest timeout ("sender not
// serving", workers adapt-down) — and (b) expires on its own so a healed
// path gets a probation pick again without needing bulk traffic to prove
// itself first. A busy-and-fast window clears the mark immediately.
const CIRCUIT_ROUTE_SLOW_MARK_TTL: Duration = Duration::from_secs(60);
// Existing streams may still be using the previous published rendezvous relay
// for their ACK path after a refresh. Keep the old circuit/registration around
// long enough for a multi-megabyte transfer to drain instead of black-holing the
// in-flight stream midway through the file.
const CIRCUIT_RETIRE_GRACE: Duration = Duration::from_secs(600);

type SharedPeerTags = Arc<Mutex<HashMap<[u8; CIRCUIT_PEER_TAG_LEN], [u8; 32]>>>;
type SharedOutboundPeerTags = Arc<Mutex<HashMap<[u8; 32], [u8; CIRCUIT_PEER_TAG_LEN]>>>;
type OutboundCircuitPool = HashMap<[u8; 32], Vec<CircuitEntry>>;
type StreamRouteKey = ([u8; 32], u32, RouteClass);
type RouteCooldowns = Arc<Mutex<HashMap<[u8; 32], Instant>>>;
type FirstHopCooldowns = Arc<Mutex<HashMap<[u8; 32], Instant>>>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RouteClass {
    Bulk,
    Ack,
}

/// Deterministic 16-byte stream cookie for a node — both ends derive the peer's
/// the same way (domain-separated app-id, distinct from the chat endpoint).
fn stream_cookie(node: &[u8; 32]) -> [u8; COOKIE_LEN] {
    // v2 leaves any pre-fix registration (whose random anti-squat key cannot be
    // reproduced after a hub restart) in a different relay-registry slot. Both
    // updated peers derive the same v2 cookie immediately; no 600 s TTL wait.
    let id = veil_app::address::app_id(node, STREAM_NAMESPACE, "stream-cookie-v2");
    let mut c = [0u8; COOKIE_LEN];
    c.copy_from_slice(&id[..COOKIE_LEN]);
    c
}

fn random_peer_tag() -> [u8; CIRCUIT_PEER_TAG_LEN] {
    let mut tag = [0u8; CIRCUIT_PEER_TAG_LEN];
    OsRng.fill_bytes(&mut tag);
    tag
}

fn outbound_peer_tag(tags: &SharedOutboundPeerTags, peer: [u8; 32]) -> [u8; CIRCUIT_PEER_TAG_LEN] {
    let mut tags = tags.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(tag) = tags.get(&peer) {
        return *tag;
    }
    if tags.len() >= 4096 {
        tags.clear();
    }
    let tag = random_peer_tag();
    tags.insert(peer, tag);
    tag
}

fn stream_peer_intro_plaintext(
    sender_node: &[u8; 32],
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
) -> [u8; CIRCUIT_INTRO_PLAINTEXT_LEN] {
    let mut out = [0u8; CIRCUIT_INTRO_PLAINTEXT_LEN];
    out[..16].copy_from_slice(CIRCUIT_INTRO_PLAINTEXT_MAGIC);
    out[16..16 + CIRCUIT_PEER_TAG_LEN].copy_from_slice(peer_tag);
    out[16 + CIRCUIT_PEER_TAG_LEN..].copy_from_slice(sender_node);
    out
}

fn parse_stream_peer_intro_plaintext(
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
    plaintext: &[u8],
) -> Option<[u8; 32]> {
    if plaintext.len() != CIRCUIT_INTRO_PLAINTEXT_LEN {
        return None;
    }
    if &plaintext[..16] != CIRCUIT_INTRO_PLAINTEXT_MAGIC {
        return None;
    }
    if &plaintext[16..16 + CIRCUIT_PEER_TAG_LEN] != peer_tag {
        return None;
    }
    let mut node = [0u8; 32];
    node.copy_from_slice(&plaintext[16 + CIRCUIT_PEER_TAG_LEN..]);
    Some(node)
}

fn seal_stream_peer_intro(
    sender_node: &[u8; 32],
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
    receiver_x25519_pk: &[u8; 32],
) -> io::Result<Vec<u8>> {
    let plaintext = stream_peer_intro_plaintext(sender_node, peer_tag);
    let sealed = veil_anonymity::rendezvous::encrypt_introduce(&plaintext, receiver_x25519_pk)
        .map_err(|e| io::Error::other(format!("seal stream peer intro: {e:?}")))?;
    if sealed.len() != CIRCUIT_INTRO_LEN {
        return Err(io::Error::other(format!(
            "sealed stream peer intro length {} != {CIRCUIT_INTRO_LEN}",
            sealed.len()
        )));
    }
    Ok(sealed)
}

fn open_stream_peer_intro(
    services: &veil_node_runtime::NodeServices,
    peer_tag: &[u8; CIRCUIT_PEER_TAG_LEN],
    sealed: &[u8],
) -> Option<[u8; 32]> {
    if sealed.len() != CIRCUIT_INTRO_LEN {
        return None;
    }
    let plaintext = services.decrypt_stream_peer_intro(sealed)?;
    parse_stream_peer_intro_plaintext(peer_tag, &plaintext)
}

/// [`CellSender`] over `send_anonymous_authenticated` — the default datagram path.
struct AnonCells {
    sender: Arc<AppSender>,
    data_pacer: Arc<StreamDataPacer>,
}

impl CellSender for AnonCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        if matches!(Frame::decode(&cell), Some(Frame::Data { .. })) {
            self.data_pacer.wait(dst.node).await;
        }
        self.sender
            .send_anonymous_authenticated(dst.node, dst.app, STREAM_ENDPOINT_ID, &cell)
            .await
            .map_err(|e| io::Error::other(format!("anon stream send: {e}")))
    }
}

/// [`CellSender`] over a PINNED stateful onion circuit to a rendezvous relay R.
/// Validation cells go as `[target_cookie 16][my_node 32][stream cell]`. In
/// published mode the relay sees only `[target_cookie 16][peer_tag 32][cell]`;
/// SYN/SYN_ACK prepend one encrypted peer-intro after `peer_tag` so only the
/// receiver can map the opaque tag back to the sender's node id.
struct CircuitCells {
    services: veil_node_runtime::NodeServices,
    me: [u8; 32],
    mode: CircuitMode,
    reg_kp: Arc<veil_crypto::GeneratedKeyPair>,
    epoch: Arc<AtomicU64>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    /// Last successful stream-cell traffic through any pinned circuit owned by
    /// this hub. The inbound registration may be refreshed after a quiet period,
    /// but never while a file transfer is actively moving DATA/ACK cells.
    activity: Arc<Mutex<Instant>>,
    /// Last RECEIVED cell (feeds only — sends never move it). Input to the
    /// inbound-starvation refresh (see CIRCUIT_INBOUND_STARVATION_AFTER).
    inbound_activity: Arc<Mutex<Instant>>,
    /// Filled by the background open task once this node's receiving circuit(s)
    /// are up. Published mode keeps one registration per advertised rendezvous
    /// relay; validation mode keeps a single circuit and also uses it for sends.
    inbound_circuits: Arc<tokio::sync::Mutex<Vec<Arc<veil_node_runtime::DataCircuit>>>>,
    /// Published-ad mode opens a small outbound circuit pool per peer, normally
    /// one route per receiver rendezvous R. Each circuit also registers our
    /// stream cookie at that R so ACKs can splice back. Stream ids are then
    /// pinned to one route for their lifetime so DATA/ACK never hop between
    /// peer tags.
    outbound_circuits: Arc<tokio::sync::Mutex<OutboundCircuitPool>>,
    stream_routes: Arc<tokio::sync::Mutex<HashMap<StreamRouteKey, CircuitRoute>>>,
    next_outbound_route: Arc<Mutex<HashMap<([u8; 32], RouteClass), usize>>>,
    route_cooldowns: RouteCooldowns,
    first_hop_cooldowns: FirstHopCooldowns,
    /// Per-destination anti-flap mark for throughput shedding: a crawling
    /// bulk stream is remapped off its route at most once per
    /// [`CIRCUIT_ROUTE_SHED_COOLDOWN`] per peer.
    bulk_shed_marks: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    /// Peers for which a cold/stale outbound circuit is currently being opened
    /// in the background. A stream cell sender must never block the stream driver
    /// on circuit construction; the ARQ layer retransmits dropped cells.
    outbound_opening: Arc<tokio::sync::Mutex<HashMap<[u8; 32], Instant>>>,
    /// Shared DATA-cell pacer per destination node. Multiple onion streams to the
    /// same peer share one pinned rendezvous/circuit bottleneck; if every stream
    /// independently paces at the path ceiling, their aggregate burst still
    /// overfills the relay/session queue. This serialises DATA cells at the circuit
    /// sender boundary while leaving SYN/SYN_ACK/ACK/RST latency low.
    data_pacer: Arc<StreamDataPacer>,
    outbound_pool_target: usize,
    ack_outbound_pool_target: usize,
    /// Total copies of each pure-ACK cell across distinct rendezvous routes
    /// (see [`CIRCUIT_ACK_REDUNDANCY_ENV`]); 1 = single-copy classic.
    ack_redundancy: usize,
    /// Diagnostic counter of redundant ACK copies actually sent (sampled log).
    ack_dup_sent: Arc<AtomicU64>,
    bulk_route_active_limit: usize,
    /// Max distinct routes one bulk stream's DATA runs stripe across (see
    /// [`CIRCUIT_STRIPE_ROUTES_ENV`]); 1 = single-route pinning.
    stripe_routes: usize,
    /// Rotates the chunk->route mapping between striped runs so the pinned
    /// primary is not always the sequence head.
    stripe_rr: Arc<AtomicU64>,
    /// Published-mode peer-introductions are carried only on SYN/SYN_ACK, but
    /// the relay-side cookie mapping may later move DATA/ACK cells to a different
    /// local receive circuit after a legitimate re-registration at the same R.
    /// Keep tag→node mappings hub-wide so demux survives that circuit switch.
    peer_tags: SharedPeerTags,
    /// Published-mode outbound routes may be rebuilt mid-stream after a first-hop
    /// session closes. Non-handshake DATA/ACK cells carry only the peer tag, not
    /// a fresh encrypted intro, so a new per-route tag would be unknown to the
    /// receiver and the old stream's ACK clock would silently collapse. Keep one
    /// outbound tag per peer for this hub; SYN/SYN_ACK introduces it once, and
    /// later route refreshes reuse it.
    outbound_peer_tags: SharedOutboundPeerTags,
}

struct CircuitEntry {
    circuit: Arc<veil_node_runtime::DataCircuit>,
    rendezvous_node: [u8; 32],
    first_hop_close_generation: u64,
    peer_tag: [u8; CIRCUIT_PEER_TAG_LEN],
    receiver_x25519_pk: [u8; 32],
    opened_at: Instant,
    last_used: Instant,
    last_non_handshake: Instant,
    /// Stream ids whose SYN/SYN_ACK already used this circuit. A no-progress
    /// handshake retransmits those cells several times before the app-level
    /// manifest timeout fires; treating that retransmit as "new work on an old
    /// quiet circuit" rotated the path mid-handshake and made the accepted
    /// stream EOF before its 48-byte request arrived. New stream ids after the
    /// same quiet window still force a fresh circuit, which is the resume path.
    handshake_streams: HashSet<u32>,
    stats: Arc<CircuitRouteStats>,
}

impl CircuitEntry {
    fn route(&self) -> CircuitRoute {
        CircuitRoute {
            circuit: Arc::clone(&self.circuit),
            rendezvous_node: Some(self.rendezvous_node),
            first_hop_close_generation: self.first_hop_close_generation,
            envelope: CircuitEnvelope::ProtectedIntro {
                peer_tag: self.peer_tag,
                receiver_x25519_pk: self.receiver_x25519_pk,
            },
            stats: Some(Arc::clone(&self.stats)),
        }
    }
}

fn record_stream_route_closed(route_class: RouteClass, route: &CircuitRoute) {
    if route_class != RouteClass::Bulk {
        return;
    }
    if let Some(stats) = route.stats.as_ref() {
        let _ = stats.record_stream_close();
    }
}

#[derive(Clone)]
struct CircuitRoute {
    circuit: Arc<veil_node_runtime::DataCircuit>,
    rendezvous_node: Option<[u8; 32]>,
    first_hop_close_generation: u64,
    envelope: CircuitEnvelope,
    stats: Option<Arc<CircuitRouteStats>>,
}

struct CircuitRouteStats {
    opened_at: Instant,
    active_streams: AtomicU64,
    data_cells: AtomicU64,
    data_bytes: AtomicU64,
    control_cells: AtomicU64,
    send_failures: AtomicU64,
    rto_events: AtomicU64,
    last_data_at: Mutex<Option<Instant>>,
    stream_rtos: Mutex<HashMap<u32, StreamRtoStats>>,
    /// Sliding DATA-throughput window for slow-route shedding (see the
    /// CIRCUIT_ROUTE_SHED_* constants). Updated inline by `record_send`.
    rate_window: Mutex<RateWindow>,
    /// Consecutive finalized windows that were busy-but-slow. Read by the
    /// shed decision after each DATA send and by the selection health bias;
    /// cleared by a busy-and-fast window or by the slow-mark TTL. An idle /
    /// app-limited window leaves it untouched — a shed route goes idle
    /// immediately, and an instant reset would erase the very mark that
    /// keeps new streams off the sick chain.
    slow_windows: AtomicU32,
    /// Slow-mark expiry, as milliseconds since `opened_at` (0 = unmarked).
    /// Refreshed on every busy-but-slow window; see
    /// [`CIRCUIT_ROUTE_SLOW_MARK_TTL`].
    slow_mark_expiry_ms: AtomicU64,
}

struct RateWindow {
    started: Instant,
    bytes: u64,
}

struct StreamRtoStats {
    events: u64,
    last_snd_una: u32,
}

impl CircuitRouteStats {
    fn new(opened_at: Instant) -> Self {
        Self {
            opened_at,
            active_streams: AtomicU64::new(0),
            data_cells: AtomicU64::new(0),
            data_bytes: AtomicU64::new(0),
            control_cells: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            rto_events: AtomicU64::new(0),
            last_data_at: Mutex::new(None),
            stream_rtos: Mutex::new(HashMap::new()),
            rate_window: Mutex::new(RateWindow {
                started: opened_at,
                bytes: 0,
            }),
            slow_windows: AtomicU32::new(0),
            slow_mark_expiry_ms: AtomicU64::new(0),
        }
    }

    fn record_stream_open(&self) -> RouteStatsSnapshot {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        self.snapshot()
    }

    fn record_stream_close(&self) -> RouteStatsSnapshot {
        let _ = self
            .active_streams
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_sub(1)
            });
        self.snapshot()
    }

    fn active_streams(&self) -> u64 {
        self.active_streams.load(Ordering::Relaxed)
    }

    fn record_send(&self, is_data: bool, data_bytes: usize) -> Option<RouteStatsSnapshot> {
        if is_data {
            let data_cells = self.data_cells.fetch_add(1, Ordering::Relaxed) + 1;
            self.data_bytes
                .fetch_add(data_bytes as u64, Ordering::Relaxed);
            let now = Instant::now();
            if let Ok(mut last_data_at) = self.last_data_at.lock() {
                *last_data_at = Some(now);
            }
            self.note_rate_window(data_bytes as u64, now);
            if data_cells % 8192 == 0 {
                return Some(self.snapshot());
            }
        } else {
            self.control_cells.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    /// Accumulate DATA payload bytes into the sliding shed window; when the
    /// window elapses, finalize it into the busy-but-slow streak. Only a
    /// busy-and-FAST window (or the mark TTL) clears the streak; an idle or
    /// app-limited window leaves it as is, so the crawling mark survives the
    /// route going quiet right after its stream was shed away.
    fn note_rate_window(&self, data_bytes: u64, now: Instant) {
        let Ok(mut window) = self.rate_window.lock() else {
            return;
        };
        window.bytes = window.bytes.saturating_add(data_bytes);
        let elapsed = now.saturating_duration_since(window.started);
        if elapsed < CIRCUIT_ROUTE_SHED_WINDOW {
            return;
        }
        let busy = window.bytes >= CIRCUIT_ROUTE_SHED_MIN_WINDOW_BYTES;
        // bytes/elapsed < floor  ⇔  bytes*1000 < floor*elapsed_ms (integer-safe)
        let slow = (window.bytes as u128) * 1000
            < (CIRCUIT_ROUTE_SHED_FLOOR_BPS as u128) * elapsed.as_millis();
        window.started = now;
        window.bytes = 0;
        if busy && slow {
            // An expired mark means the old streak is stale evidence —
            // restart the count instead of resuming it.
            if !self.slow_marked(now) && self.slow_windows.load(Ordering::Relaxed) > 0 {
                self.slow_windows.store(1, Ordering::Relaxed);
            } else {
                self.slow_windows.fetch_add(1, Ordering::Relaxed);
            }
            let expiry =
                now.saturating_duration_since(self.opened_at) + CIRCUIT_ROUTE_SLOW_MARK_TTL;
            self.slow_mark_expiry_ms
                .store(expiry.as_millis() as u64, Ordering::Relaxed);
        } else if busy {
            self.slow_windows.store(0, Ordering::Relaxed);
            self.slow_mark_expiry_ms.store(0, Ordering::Relaxed);
        }
    }

    /// Active busy-but-slow streak length; 0 once the mark TTL has lapsed.
    fn slow_windows(&self, now: Instant) -> u32 {
        if self.slow_marked(now) {
            self.slow_windows.load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Is this route currently marked as crawling (recent busy-but-slow
    /// window, TTL not yet lapsed)?
    fn slow_marked(&self, now: Instant) -> bool {
        let expiry_ms = self.slow_mark_expiry_ms.load(Ordering::Relaxed);
        expiry_ms > 0
            && (now.saturating_duration_since(self.opened_at).as_millis() as u64) < expiry_ms
    }

    fn record_send_failure(&self) -> RouteStatsSnapshot {
        self.send_failures.fetch_add(1, Ordering::Relaxed);
        self.snapshot()
    }

    fn record_rto(&self, stream_id: u32, snd_una: u32) -> RouteRtoSnapshot {
        self.rto_events.fetch_add(1, Ordering::Relaxed);
        let (stream_rto_events, stream_snd_una_advanced) =
            if let Ok(mut stream_rtos) = self.stream_rtos.lock() {
                if stream_rtos.len() >= 4096 && !stream_rtos.contains_key(&stream_id) {
                    stream_rtos.clear();
                }
                let entry = stream_rtos.entry(stream_id).or_insert(StreamRtoStats {
                    events: 0,
                    last_snd_una: snd_una,
                });
                let advanced = entry.last_snd_una != snd_una;
                entry.events = entry.events.saturating_add(1);
                entry.last_snd_una = snd_una;
                (entry.events, advanced)
            } else {
                (1, false)
            };
        RouteRtoSnapshot {
            stats: self.snapshot(),
            stream_rto_events,
            stream_snd_una_advanced,
        }
    }

    fn snapshot(&self) -> RouteStatsSnapshot {
        let now = Instant::now();
        let last_data_ago = self
            .last_data_at
            .lock()
            .ok()
            .and_then(|last_data_at| last_data_at.map(|at| now.saturating_duration_since(at)));
        RouteStatsSnapshot {
            age: now.saturating_duration_since(self.opened_at),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            data_cells: self.data_cells.load(Ordering::Relaxed),
            data_bytes: self.data_bytes.load(Ordering::Relaxed),
            control_cells: self.control_cells.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
            rto_events: self.rto_events.load(Ordering::Relaxed),
            last_data_ago,
        }
    }
}

struct RouteRtoSnapshot {
    stats: RouteStatsSnapshot,
    stream_rto_events: u64,
    stream_snd_una_advanced: bool,
}

struct RouteStatsSnapshot {
    age: Duration,
    active_streams: u64,
    data_cells: u64,
    data_bytes: u64,
    control_cells: u64,
    send_failures: u64,
    rto_events: u64,
    last_data_ago: Option<Duration>,
}

impl std::fmt::Display for RouteStatsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last_data_ago_ms = self
            .last_data_ago
            .map(|duration| duration.as_millis().to_string())
            .unwrap_or_else(|| "none".to_string());
        write!(
            f,
            "age={}s active_streams={} data_cells={} data_bytes={} control_cells={} send_failures={} rto_events={} last_data_ago_ms={}",
            self.age.as_secs(),
            self.active_streams,
            self.data_cells,
            self.data_bytes,
            self.control_cells,
            self.send_failures,
            self.rto_events,
            last_data_ago_ms
        )
    }
}

fn should_defer_busy_route_no_progress(
    stats: &RouteStatsSnapshot,
    consec_rto: u32,
    stream_rto_events: u64,
) -> bool {
    let busy_route = stats.data_cells >= CIRCUIT_ROUTE_BUSY_MIN_DATA_CELLS
        || stats.control_cells >= CIRCUIT_ROUTE_BUSY_MIN_DATA_CELLS;
    if consec_rto >= 3
        || stream_rto_events >= CIRCUIT_ROUTE_BUSY_RTO_EVENTS
        || stats.send_failures > 0
        || stats.active_streams <= 1
        || !busy_route
    {
        return false;
    }
    matches!(
        stats.last_data_ago,
        Some(last_data_ago) if last_data_ago <= CIRCUIT_ROUTE_BUSY_RECENT_DATA_GRACE
    )
}

#[derive(Clone, Copy)]
enum CircuitEnvelope {
    LegacyClearSender {
        sender_node: [u8; 32],
    },
    ProtectedIntro {
        peer_tag: [u8; CIRCUIT_PEER_TAG_LEN],
        receiver_x25519_pk: [u8; 32],
    },
}

struct StreamDataPacer {
    interval: Duration,
    next_by_peer: tokio::sync::Mutex<HashMap<[u8; 32], Instant>>,
}

impl StreamDataPacer {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_by_peer: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn wait(&self, peer: [u8; 32]) {
        self.wait_n(peer, 1).await
    }

    /// Reserve `n` consecutive pacing slots with ONE schedule update and at
    /// most one park. Batched senders reserve their whole DATA run up front
    /// instead of taking the pacer lock per cell.
    async fn wait_n(&self, peer: [u8; 32], n: u32) {
        if self.interval.is_zero() || n == 0 {
            return;
        }
        // `tokio::time::sleep(100us)` is effectively a ~1ms sleep on common
        // desktop/mobile schedulers. Sleeping for every sub-ms cell silently
        // reintroduces the old one-cell-per-ms throughput ceiling. Instead,
        // reserve sub-ms slots in the shared schedule and only park once the
        // accumulated delay reaches the scheduler's millisecond granularity; the
        // stream engine's own `max_pacing_batch` still bounds the microburst.
        //
        // Token-bucket credit: the park can overshoot badly (Android coalesces
        // a 1ms sleep to several ms). Resetting the schedule to `now` after an
        // overshoot forfeited the unused slots, which quantized the whole peer
        // to burst-size cells per REAL sleep duration (~1.4 MiB/s live instead
        // of the configured rate). Let the schedule lag `now` by a bounded
        // credit so an oversleep is repaid by the next burst; the credit cap
        // keeps the burst in the same range the engine's pacing batch allows.
        let min_sleep = Duration::from_millis(1);
        let burst_credit = (self.interval * 64).max(Duration::from_millis(5));
        let delay = {
            let now = Instant::now();
            let mut next_by_peer = self.next_by_peer.lock().await;
            let next = next_by_peer.entry(peer).or_insert(now);
            let earliest = now.checked_sub(burst_credit).unwrap_or(now);
            if *next < earliest {
                *next = earliest;
            }
            let scheduled = *next;
            *next = scheduled + self.interval * n;
            scheduled.saturating_duration_since(now)
        };
        if delay >= min_sleep {
            tokio::time::sleep(delay).await;
        }
    }
}

fn stream_data_pace_interval(is_circuit: bool) -> Duration {
    let default = if is_circuit {
        DEFAULT_CIRCUIT_DATA_PACE_US
    } else {
        DEFAULT_DATA_PACE_US
    };
    let raw = if is_circuit {
        std::env::var(CIRCUIT_DATA_PACE_US_ENV)
            .or_else(|_| std::env::var(STREAM_DATA_PACE_US_ENV))
            .ok()
            .or_else(|| android_string_property(ANDROID_DATA_PACE_US_PROP))
    } else {
        std::env::var(STREAM_DATA_PACE_US_ENV).ok()
    };
    let micros = raw
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(MIN_DATA_PACE_US, MAX_DATA_PACE_US);
    Duration::from_micros(micros)
}

fn env_u32(name: &str, default: u32, min: u32, max: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn env_or_android_u64(env_name: &str, android_prop: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(env_name)
        .ok()
        .or_else(|| android_string_property(android_prop))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn env_or_android_u32(env_name: &str, android_prop: &str, default: u32, min: u32, max: u32) -> u32 {
    std::env::var(env_name)
        .ok()
        .or_else(|| android_string_property(android_prop))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn env_or_android_usize(
    env_name: &str,
    android_prop: &str,
    default: usize,
    min: usize,
    max: usize,
) -> usize {
    std::env::var(env_name)
        .ok()
        .or_else(|| android_string_property(android_prop))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

impl CellSender for CircuitCells {
    async fn send_many(
        &self,
        dst: Addr,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<()> {
        while !cells.is_empty() {
            // Gather the front run of plain DATA cells for one stream id. Every
            // other frame kind (handshake/ACK/FIN/RST) takes the scalar path,
            // which owns route-class selection and protected-intro sealing.
            let mut run_stream_id = None;
            let mut run_len = 0usize;
            for cell in cells.iter() {
                match Frame::decode(cell) {
                    Some(Frame::Data { stream_id, .. })
                        if run_stream_id.is_none_or(|sid| sid == stream_id) =>
                    {
                        run_stream_id = Some(stream_id);
                        run_len += 1;
                    }
                    _ => break,
                }
            }
            match run_stream_id {
                Some(stream_id) if run_len > 1 => {
                    self.send_data_run(dst, stream_id, run_len, cells).await?;
                }
                _ => {
                    let front = cells.front().expect("checked non-empty").clone();
                    self.send(dst, front).await?;
                    cells.pop_front();
                }
            }
        }
        Ok(())
    }

    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        let decoded = Frame::decode(&cell);
        let stream_id = decoded.as_ref().map(|frame| frame.stream_id());
        let data_payload_len = match decoded.as_ref() {
            Some(Frame::Data { payload, .. }) => payload.len(),
            _ => 0,
        };
        // Keep SYN/SYN_ACK on the bulk route: in the file-download pattern the
        // responder sends the payload after SYN_ACK, so treating SYN_ACK as
        // control-only can accidentally shrink the sender's DATA pool to 1 route.
        let route_class = match decoded {
            Some(Frame::Ack { .. }) => RouteClass::Ack,
            _ => RouteClass::Bulk,
        };
        // Redundant return-path copies for pure ACKs (see `send_ack_copies`).
        // Attempted on EVERY exit below — including no-route and stale-route,
        // where the classic path silently drops the ACK with nothing to resend
        // it: the copies are then the only thing keeping the ACK clock alive.
        let ack_copies = if route_class == RouteClass::Ack {
            self.ack_redundancy.saturating_sub(1)
        } else {
            0
        };
        let handshake_stream_id = match decoded {
            Some(Frame::Syn { stream_id, .. } | Frame::SynAck { stream_id, .. }) => Some(stream_id),
            _ => None,
        };
        let is_handshake = handshake_stream_id.is_some();
        let is_data = matches!(decoded, Some(Frame::Data { .. }));
        let Some(route) = self
            .circuit_for(dst.node, stream_id, route_class, is_handshake)
            .await?
        else {
            // Circuit not up yet — drop this cell; the ARQ/handshake RTO resends.
            if ack_copies > 0 {
                self.send_ack_copies(dst.node, None, &cell, ack_copies)
                    .await;
            }
            return Ok(());
        };
        if self.route_session_stale(&route) {
            self.mark_route_stale(dst.node, &route).await;
            // Treat stale route exactly like a dropped cell. The stream engine
            // retransmits, while route selection/opening moves to a fresh path.
            if ack_copies > 0 {
                self.send_ack_copies(dst.node, route.rendezvous_node, &cell, ack_copies)
                    .await;
            }
            return Ok(());
        }
        let env = self.stream_envelope(&dst.node, &route, &cell, is_handshake)?;
        if is_data {
            self.data_pacer.wait(dst.node).await;
        }
        if ack_copies > 0 {
            self.send_ack_copies(dst.node, route.rendezvous_node, &cell, ack_copies)
                .await;
        }
        if let Err(e) = self
            .services
            .send_circuit_cell_detailed(&route.circuit, &env)
        {
            if e == veil_node_runtime::DataCircuitSendError::QueueFull {
                // Local first-hop session TX queue is full. The encoded stream
                // cell has not entered the transport, so surface backpressure to
                // the stream driver and let it retry the same cell instead of
                // manufacturing packet loss/RTO recovery.
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "circuit first-hop TX queue full",
                ));
            }
            self.mark_route_send_failed(dst.node, &route, e).await;
            // Preserve ARQ semantics: a route enqueue failure is equivalent to a
            // dropped cell. The stream engine will retransmit and route
            // selection can pick a non-cooled path next time.
            return Ok(());
        }
        if let Some(stats) = route.stats.as_ref() {
            if let Some(snapshot) = stats.record_send(is_data, data_payload_len) {
                if let Some(relay) = route.rendezvous_node {
                    diag_node(
                        &self.me,
                        &format!(
                            "outbound route stats for {} via R={} path={} {snapshot}",
                            short_node(&dst.node),
                            short_node(&relay),
                            short_path(route.circuit.relay_path()),
                        ),
                    );
                }
            }
        }
        mark_circuit_activity(&self.activity);
        if !is_handshake {
            self.mark_outbound_non_handshake(dst.node, &route).await;
        }
        if is_data && route_class == RouteClass::Bulk {
            if let Some(stream_id) = stream_id {
                self.maybe_shed_slow_bulk_route(dst.node, stream_id, &route)
                    .await;
            }
        }
        Ok(())
    }

    async fn on_stream_data_rto(&self, dst: Addr, stream_id: u32, consec_rto: u32, snd_una: u32) {
        if self.mode != CircuitMode::PublishedRendezvous {
            return;
        }
        let route = self
            .stream_routes
            .lock()
            .await
            .get(&(dst.node, stream_id, RouteClass::Bulk))
            .cloned();
        let Some(route) = route else {
            return;
        };
        let route_rto = route
            .stats
            .as_ref()
            .map(|stats| stats.record_rto(stream_id, snd_una));
        let stream_rto_events = route_rto
            .as_ref()
            .map(|rto| rto.stream_rto_events)
            .unwrap_or(consec_rto as u64);
        if consec_rto < 2 && stream_rto_events < CIRCUIT_ROUTE_NO_PROGRESS_RTO_EVENTS {
            return;
        }
        if let Some(rto) = route_rto.as_ref() {
            if should_defer_busy_route_no_progress(&rto.stats, consec_rto, stream_rto_events) {
                if stream_rto_events == CIRCUIT_ROUTE_NO_PROGRESS_RTO_EVENTS
                    || stream_rto_events % 4 == 0
                {
                    diag_node(
                        &dst.node,
                        &format!(
                            "outbound route no-progress deferred stream={} via R={} consec_rto={} stream_rto_events={} snd_una={} snd_una_advanced={} {}",
                            stream_id,
                            route
                                .rendezvous_node
                                .map(|relay| short_node(&relay))
                                .unwrap_or_else(|| "-".to_string()),
                            consec_rto,
                            stream_rto_events,
                            snd_una,
                            rto.stream_snd_una_advanced,
                            rto.stats,
                        ),
                    );
                }
                return;
            }
        }
        self.mark_route_no_progress(
            dst.node,
            stream_id,
            &route,
            consec_rto,
            stream_rto_events,
            snd_una,
        )
        .await;
    }

    async fn on_stream_closed(&self, dst: Addr, stream_id: u32, _end: End) {
        if self.mode != CircuitMode::PublishedRendezvous {
            return;
        }
        let removed_routes = {
            let mut routes = self.stream_routes.lock().await;
            let mut removed = Vec::new();
            routes.retain(|(node, sid, route_class), route| {
                let keep = *node != dst.node || *sid != stream_id;
                if !keep {
                    removed.push((*route_class, route.clone()));
                }
                keep
            });
            removed
        };
        for (route_class, route) in removed_routes {
            record_stream_route_closed(route_class, &route);
        }
    }
}

impl CircuitCells {
    /// Build the on-wire circuit envelope for `cell` over `route`:
    /// `[cookie][sender-or-peer-tag][optional sealed intro][cell]`.
    fn stream_envelope(
        &self,
        dst_node: &[u8; 32],
        route: &CircuitRoute,
        cell: &[u8],
        is_handshake: bool,
    ) -> io::Result<Vec<u8>> {
        let cookie = stream_cookie(dst_node);
        let protected_intro_len =
            matches!(route.envelope, CircuitEnvelope::ProtectedIntro { .. }) && is_handshake;
        let mut env = Vec::with_capacity(
            COOKIE_LEN
                + CIRCUIT_PEER_TAG_LEN
                + cell.len()
                + if protected_intro_len {
                    1 + CIRCUIT_INTRO_LEN
                } else {
                    0
                },
        );
        env.extend_from_slice(&cookie);
        match route.envelope {
            CircuitEnvelope::LegacyClearSender { sender_node } => {
                env.extend_from_slice(&sender_node);
            }
            CircuitEnvelope::ProtectedIntro {
                peer_tag,
                receiver_x25519_pk,
            } => {
                env.extend_from_slice(&peer_tag);
                if is_handshake {
                    let intro = seal_stream_peer_intro(&self.me, &peer_tag, &receiver_x25519_pk)?;
                    env.push(CIRCUIT_INTRO_MARKER);
                    env.extend_from_slice(&intro);
                }
            }
        }
        env.extend_from_slice(cell);
        if env.len() > veil_onion_stream::wire::MAX_CELL {
            return Err(io::Error::other(format!(
                "circuit stream envelope too large: {} > {}",
                env.len(),
                veil_onion_stream::wire::MAX_CELL
            )));
        }
        Ok(env)
    }

    /// Send one lossy MEDIA datagram over the SAME outbound circuit pool as the
    /// reliable stream, bypassing the `Frame`/ARQ/pacing machinery entirely.
    ///
    /// The payload is prefixed with [`crate::media::MEDIA_MAGIC`] (a byte
    /// distinct from `PROTO_VER`, so the peer's [`spawn_circuit_feed`] peels it
    /// off before the stream demux). There is no retransmit, no ACK copies, and
    /// no pacing: on no-route / stale-route / `QueueFull` the datagram is
    /// silently dropped — the media codec's PLC/FEC absorbs the gap, and a
    /// late packet is worthless. Reuses the outbound pool + make-before-break
    /// refill that `circuit_for` already drives.
    ///
    /// Returns `true` if the cell entered the first-hop TX queue, `false` if it
    /// was dropped.
    async fn send_datagram(&self, dst_node: [u8; 32], payload: &[u8]) -> bool {
        // Media only exists on the published-rendezvous circuit backend; the
        // validation/datagram fallbacks have no lossy path.
        if self.mode != CircuitMode::PublishedRendezvous {
            return false;
        }
        let mut cell = Vec::with_capacity(1 + payload.len());
        cell.push(crate::media::MEDIA_MAGIC);
        cell.extend_from_slice(payload);
        // `stream_id = None`, `Bulk`, `is_handshake = false`: reuse the peer's
        // existing bulk pool without pinning a stream route. A `None` result
        // means no route is up yet — `circuit_for` has already kicked a
        // background open, so just drop this datagram (no ARQ) and let the next
        // one ride the warm pool.
        let route = match self
            .circuit_for(dst_node, None, RouteClass::Bulk, false)
            .await
        {
            Ok(Some(route)) => route,
            _ => return false,
        };
        if self.route_session_stale(&route) {
            self.mark_route_stale(dst_node, &route).await;
            return false;
        }
        // Attach the sender intro (is_handshake=true for the ENVELOPE only —
        // circuit_for above still selects a Bulk route). On a ProtectedIntro
        // circuit the peer_tag is opaque, so without the intro the receiver
        // can't map peer_tag→our node and would mis-attribute the datagram.
        // Unlike the reliable stream, a call establishes NO prior handshake on
        // this circuit (signaling rides the mailbox), so media must carry the
        // intro itself. Each cell pads to a full circuit cell regardless, so the
        // intro bytes are effectively free; the only cost is a per-cell seal
        // (negligible at media rates — optimizable to first-cell-per-route once
        // an ack path exists).
        let env = match self.stream_envelope(&dst_node, &route, &cell, true) {
            Ok(env) => env,
            // Oversized (payload > one cell) — drop; callers batch to fit.
            Err(_) => return false,
        };
        match self
            .services
            .send_circuit_cell_detailed(&route.circuit, &env)
        {
            Ok(()) => {
                mark_circuit_activity(&self.activity);
                self.mark_outbound_non_handshake(dst_node, &route).await;
                true
            }
            // First-hop TX queue full → drop-late. Media never retransmits, and
            // surfacing backpressure would only stall the codec's real-time clock.
            Err(veil_node_runtime::DataCircuitSendError::QueueFull) => false,
            Err(e) => {
                // Keep pool health honest so a dead route is reaped, exactly as
                // the stream send path does on enqueue failure.
                self.mark_route_send_failed(dst_node, &route, e).await;
                false
            }
        }
    }

    /// Best-effort redundant copies of a pure-ACK cell over up to `max_extra`
    /// pool routes whose rendezvous relay DIFFERS from the primary's (and from
    /// each other's). A pure ACK is never retransmitted by ARQ — losing it on a
    /// single sticky return chain freezes the sender's window with no feedback
    /// signal anywhere. Copies are cumulative/idempotent, ~100 B each, and ride
    /// relays the stream already uses. Never blocks the driver (`try_lock`,
    /// like [`Self::stripe_alternates`]) and never surfaces errors: the primary
    /// send path owns route-health bookkeeping.
    async fn send_ack_copies(
        &self,
        dst_node: [u8; 32],
        primary_relay: Option<[u8; 32]>,
        cell: &[u8],
        max_extra: usize,
    ) {
        if max_extra == 0 {
            return;
        }
        let cooldown_now = Instant::now();
        let cooled_relays = {
            let cooldowns = self
                .route_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.clone()
        };
        let cooled_first_hops = {
            let cooldowns = self
                .first_hop_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.clone()
        };
        let copies = {
            let Ok(circuits) = self.outbound_circuits.try_lock() else {
                return;
            };
            let Some(entries) = circuits.get(&dst_node) else {
                return;
            };
            let mut used_relays: Vec<[u8; 32]> = primary_relay.into_iter().collect();
            let mut copies = Vec::new();
            for entry in entries {
                if copies.len() >= max_extra {
                    break;
                }
                if used_relays.contains(&entry.rendezvous_node) {
                    continue;
                }
                let first_hop = entry.circuit.first_hop();
                if cooled_relays
                    .get(&entry.rendezvous_node)
                    .is_some_and(|until| *until > cooldown_now)
                    || cooled_first_hops
                        .get(&first_hop)
                        .is_some_and(|until| *until > cooldown_now)
                {
                    continue;
                }
                if !self.services.has_live_session(&first_hop) {
                    continue;
                }
                let route = entry.route();
                if self.route_session_stale(&route) {
                    continue;
                }
                used_relays.push(entry.rendezvous_node);
                copies.push(route);
            }
            copies
        };
        for alt in copies {
            let Ok(env) = self.stream_envelope(&dst_node, &alt, cell, false) else {
                continue;
            };
            if self
                .services
                .send_circuit_cell_detailed(&alt.circuit, &env)
                .is_ok()
            {
                if let Some(stats) = alt.stats.as_ref() {
                    let _ = stats.record_send(false, 0);
                }
                let sent = self.ack_dup_sent.fetch_add(1, Ordering::Relaxed);
                if sent.is_multiple_of(512) {
                    diag_node(
                        &self.me,
                        &format!(
                            "redundant ACK copy #{} for {} via R={}",
                            sent + 1,
                            short_node(&dst_node),
                            alt.rendezvous_node
                                .map(|relay| short_node(&relay))
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                    );
                }
            }
        }
    }

    /// Send a contiguous run of DATA cells for one stream over one resolved
    /// route: one route lookup, one staleness check, one pacer reservation and
    /// one activity/bookkeeping pass for the whole run. The per-cell scalar
    /// path takes 3-4 async lock acquisitions per 318-byte cell, which at
    /// 7-9k cells/s dominated the live phone sender in kernel/wake time.
    async fn send_data_run(
        &self,
        dst: Addr,
        stream_id: u32,
        run_len: usize,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<()> {
        let Some(route) = self
            .circuit_for(dst.node, Some(stream_id), RouteClass::Bulk, false)
            .await?
        else {
            // Circuit not up yet — drop the run; the stream's ARQ resends.
            cells.drain(..run_len);
            return Ok(());
        };
        if self.route_session_stale(&route) {
            self.mark_route_stale(dst.node, &route).await;
            // Stale route == dropped run: ARQ retransmits on a fresh path.
            cells.drain(..run_len);
            return Ok(());
        }
        self.data_pacer.wait_n(dst.node, run_len as u32).await;
        // Route striping: the per-flow ceiling is the first-hop session TCP,
        // so split a large run into contiguous chunks across additional
        // healthy pool routes with DISTINCT first hops. One engine keeps one
        // delivery model/reassembly; only the wire fans out. The pinned
        // primary stays the health/RTO anchor and always carries a chunk.
        let alternates = if self.stripe_routes > 1 && run_len >= STRIPE_MIN_RUN_CELLS {
            self.stripe_alternates(dst.node, &route, self.stripe_routes - 1)
                .await
        } else {
            Vec::new()
        };
        if self.stripe_routes > 1 {
            // Debug visibility: EVERY striped run, sampled non-striped runs.
            let tick = self.stripe_rr.fetch_add(1, Ordering::Relaxed);
            if !alternates.is_empty() || tick.is_multiple_of(64) {
                diag_node(
                    &self.me,
                    &format!(
                        "stripe run for {} stream={} run_len={} alternates={} primary_hop={}",
                        short_node(&dst.node),
                        stream_id,
                        run_len,
                        alternates.len(),
                        short_node(&route.circuit.first_hop()),
                    ),
                );
            }
        }
        if alternates.is_empty() {
            let (sent, err) = self.send_chunk_on_route(dst.node, &route, run_len, cells)?;
            if sent > 0 {
                mark_circuit_activity(&self.activity);
                self.mark_outbound_non_handshake(dst.node, &route).await;
            }
            if let Some(err) = err {
                return self
                    .finish_failed_chunk(dst.node, &route, err, run_len - sent, cells)
                    .await;
            }
            self.maybe_shed_slow_bulk_route(dst.node, stream_id, &route)
                .await;
            return Ok(());
        }
        let mut routes: Vec<&CircuitRoute> = Vec::with_capacity(1 + alternates.len());
        routes.push(&route);
        routes.extend(alternates.iter());
        let n = routes.len();
        // INTERLEAVE cells across routes (round-robin), do NOT hand each route a
        // contiguous seq-block. Contiguous blocks head-of-line-block the stream:
        // seq [0..k) on a fast route and [k..2k) on a slow one means snd_una
        // cannot advance past the fast route's data until the slow route
        // catches up, and if that lag exceeds the RTO the receiver has nothing
        // above the hole to SACK -> a no-SACK RTO collapses the window even
        // with ZERO packet loss (measured: sack=0, wb=0, yet ssthresh pinned at
        // ~155 KB for the whole transfer, 3x slowdown). Interleaving spreads
        // every route's cells through the seq space, so one route lagging just
        // leaves SACKable gaps that higher-seq cells from the other routes
        // expose -> fast-retransmit, not a no-SACK RTO. The receiver's oo
        // reassembly already tolerates the reordering.
        let base = (self.stripe_rr.load(Ordering::Relaxed) as usize) % n;
        // Drain the run once; dispatch cell i to route (base+i) % n.
        let run: Vec<Vec<u8>> = cells.drain(..run_len).collect();
        let cookie = stream_cookie(&dst.node);
        let mut per_route_ok = vec![true; n];
        let mut failed_routes: Vec<usize> = Vec::new();
        let mut i = 0usize;
        while i < run.len() {
            let ri = (base + i) % n;
            if !per_route_ok[ri] {
                // Route already failed this run: requeue for ARQ repair on a
                // healthy route in a later pass, skip it.
                cells.push_back(run[i].clone());
                i += 1;
                continue;
            }
            match self.send_one_cell_on_route(&cookie, routes[ri], &run[i]) {
                Ok(true) => i += 1,
                Ok(false) => {
                    // Enqueue rejected (not queue-full): mark the route dead for
                    // the rest of this run; requeue this cell for ARQ repair.
                    per_route_ok[ri] = false;
                    failed_routes.push(ri);
                    cells.push_back(run[i].clone());
                    i += 1;
                }
                Err(_) => {
                    // Local first-hop TX queue full: push this cell and the
                    // whole undelivered tail back (front, in order) so the
                    // driver retries them next poll. No manufactured loss.
                    for cell in run[i..].iter().rev() {
                        cells.push_front(cell.clone());
                    }
                    for ri in failed_routes {
                        self.mark_route_send_failed(
                            dst.node,
                            routes[ri],
                            veil_node_runtime::DataCircuitSendError::QueueFull,
                        )
                        .await;
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "circuit first-hop TX queue full (striped)",
                    ));
                }
            }
        }
        for ri in failed_routes {
            self.mark_route_send_failed(
                dst.node,
                routes[ri],
                veil_node_runtime::DataCircuitSendError::QueueFull,
            )
            .await;
        }
        mark_circuit_activity(&self.activity);
        self.mark_outbound_non_handshake(dst.node, &route).await;
        self.maybe_shed_slow_bulk_route(dst.node, stream_id, &route)
            .await;
        Ok(())
    }

    /// Send ONE already-decoded stream cell on `route`. `Ok(true)` = accepted,
    /// `Ok(false)` = route enqueue rejected (mark it), `Err(WouldBlock)` =
    /// local first-hop TX queue full (retry the exact cell).
    fn send_one_cell_on_route(
        &self,
        cookie: &[u8; COOKIE_LEN],
        route: &CircuitRoute,
        cell: &[u8],
    ) -> io::Result<bool> {
        let data_payload_len = match Frame::decode(cell) {
            Some(Frame::Data { payload, .. }) => payload.len(),
            _ => 0,
        };
        let mut env = Vec::with_capacity(COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + cell.len());
        env.extend_from_slice(cookie);
        match route.envelope {
            CircuitEnvelope::LegacyClearSender { sender_node } => {
                env.extend_from_slice(&sender_node);
            }
            CircuitEnvelope::ProtectedIntro { peer_tag, .. } => {
                env.extend_from_slice(&peer_tag);
            }
        }
        env.extend_from_slice(cell);
        if env.len() > veil_onion_stream::wire::MAX_CELL {
            return Err(io::Error::other("circuit stream envelope too large"));
        }
        match self
            .services
            .send_circuit_cell_detailed(&route.circuit, &env)
        {
            Ok(()) => {
                if let Some(stats) = route.stats.as_ref() {
                    stats.record_send(true, data_payload_len);
                }
                Ok(true)
            }
            Err(veil_node_runtime::DataCircuitSendError::QueueFull) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "circuit first-hop TX queue full",
            )),
            Err(_) => Ok(false),
        }
    }

    /// Send `count` cells from the front of `cells` on `route`. Returns how
    /// many were accepted plus the enqueue error, if one stopped the chunk
    /// early. `Err(WouldBlock)` = local first-hop TX queue full, unsent cells
    /// stay queued for the driver's retry. On a non-queue enqueue failure the
    /// caller decides how much of the tail to drop
    /// (see [`Self::finish_failed_chunk`]).
    fn send_chunk_on_route(
        &self,
        dst_node: [u8; 32],
        route: &CircuitRoute,
        count: usize,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<(usize, Option<veil_node_runtime::DataCircuitSendError>)> {
        let cookie = stream_cookie(&dst_node);
        let mut sent = 0usize;
        while sent < count {
            let cell = cells.front().expect("chunk bounded by deque len");
            let data_payload_len = match Frame::decode(cell) {
                Some(Frame::Data { payload, .. }) => payload.len(),
                _ => 0,
            };
            let mut env = Vec::with_capacity(COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + cell.len());
            env.extend_from_slice(&cookie);
            match route.envelope {
                CircuitEnvelope::LegacyClearSender { sender_node } => {
                    env.extend_from_slice(&sender_node);
                }
                CircuitEnvelope::ProtectedIntro { peer_tag, .. } => {
                    env.extend_from_slice(&peer_tag);
                }
            }
            env.extend_from_slice(cell);
            if env.len() > veil_onion_stream::wire::MAX_CELL {
                return Err(io::Error::other(format!(
                    "circuit stream envelope too large: {} > {}",
                    env.len(),
                    veil_onion_stream::wire::MAX_CELL
                )));
            }
            if let Err(e) = self
                .services
                .send_circuit_cell_detailed(&route.circuit, &env)
            {
                if e == veil_node_runtime::DataCircuitSendError::QueueFull {
                    // Sent cells are gone; the failing cell and the rest of the
                    // run stay queued for the caller's WouldBlock retry.
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "circuit first-hop TX queue full",
                    ));
                }
                return Ok((sent, Some(e)));
            }
            if let Some(stats) = route.stats.as_ref() {
                if let Some(snapshot) = stats.record_send(true, data_payload_len) {
                    if let Some(relay) = route.rendezvous_node {
                        diag_node(
                            &self.me,
                            &format!(
                                "outbound route stats for {} via R={} path={} {snapshot}",
                                short_node(&dst_node),
                                short_node(&relay),
                                short_path(route.circuit.relay_path()),
                            ),
                        );
                    }
                }
            }
            cells.pop_front();
            sent += 1;
        }
        Ok((sent, None))
    }

    /// A route rejected an enqueue mid-chunk (not queue-full): mark it and
    /// drop the chunk's remaining cells — ARQ retransmits them, and route
    /// selection moves off the cooled path.
    async fn finish_failed_chunk(
        &self,
        dst_node: [u8; 32],
        route: &CircuitRoute,
        err: veil_node_runtime::DataCircuitSendError,
        remaining: usize,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<()> {
        self.mark_route_send_failed(dst_node, route, err).await;
        cells.drain(..remaining.min(cells.len()));
        Ok(())
    }

    /// Healthy pool routes to stripe extra chunks over: distinct circuit AND
    /// distinct first hop from the primary and from each other (same first
    /// hop = same session TCP = no extra per-flow ceiling), not cooled, with
    /// a live, non-stale first-hop session.
    async fn stripe_alternates(
        &self,
        dst_node: [u8; 32],
        primary: &CircuitRoute,
        max_extra: usize,
    ) -> Vec<CircuitRoute> {
        if max_extra == 0 {
            return Vec::new();
        }
        let cooldown_now = Instant::now();
        let cooled_relays = {
            let cooldowns = self
                .route_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.clone()
        };
        let cooled_first_hops = {
            let cooldowns = self
                .first_hop_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.clone()
        };
        let mut used_first_hops = vec![primary.circuit.first_hop()];
        let mut out = Vec::new();
        // NEVER block the stream driver on the pool mutex: the background
        // opener holds it across circuit construction, and an await here
        // stalls the whole driver task (no sends, no ACK processing) for
        // hundreds of milliseconds right when the first big flight goes out —
        // live this poisoned the delivery model into a permanent crawl.
        // Contended lock == no striping for this run; the next run retries.
        let Ok(circuits) = self.outbound_circuits.try_lock() else {
            return Vec::new();
        };
        if let Some(entries) = circuits.get(&dst_node) {
            for entry in entries {
                if out.len() >= max_extra {
                    break;
                }
                let first_hop = entry.circuit.first_hop();
                if used_first_hops.contains(&first_hop) {
                    continue;
                }
                if cooled_relays
                    .get(&entry.rendezvous_node)
                    .is_some_and(|until| *until > cooldown_now)
                    || cooled_first_hops
                        .get(&first_hop)
                        .is_some_and(|until| *until > cooldown_now)
                {
                    continue;
                }
                if !self.services.has_live_session(&first_hop) {
                    continue;
                }
                let route = entry.route();
                if self.route_session_stale(&route) {
                    continue;
                }
                used_first_hops.push(first_hop);
                out.push(route);
            }
        }
        out
    }

    async fn circuit_for(
        &self,
        dst_node: [u8; 32],
        stream_id: Option<u32>,
        route_class: RouteClass,
        is_handshake: bool,
    ) -> io::Result<Option<CircuitRoute>> {
        match self.mode {
            CircuitMode::ValidationMinRouting => Ok(self
                .inbound_circuits
                .lock()
                .await
                .first()
                .cloned()
                .map(|circuit| CircuitRoute {
                    circuit,
                    rendezvous_node: None,
                    first_hop_close_generation: 0,
                    envelope: CircuitEnvelope::LegacyClearSender {
                        sender_node: self.me,
                    },
                    stats: None,
                })),
            CircuitMode::PublishedRendezvous => {
                if let Some(stream_id) = stream_id {
                    if let Some(route) = self
                        .stream_routes
                        .lock()
                        .await
                        .get(&(dst_node, stream_id, route_class))
                        .cloned()
                    {
                        return Ok(Some(route));
                    }
                }
                let route = self
                    .ensure_outbound_circuit(dst_node, stream_id, route_class, is_handshake)
                    .await?;
                if route.is_none() && route_class == RouteClass::Bulk {
                    // All currently usable bulk routes may be at their soft
                    // active-stream admission limit. Drop this SYN/DATA cell and
                    // let ARQ retry while a background refill tries to restore a
                    // wider route pool.
                    self.ensure_outbound_opening(dst_node, route_class).await;
                }
                if let (Some(stream_id), Some(route)) = (stream_id, route.clone()) {
                    let mut routes = self.stream_routes.lock().await;
                    if routes.len() >= 4096
                        && !routes.contains_key(&(dst_node, stream_id, route_class))
                    {
                        for ((_, _, old_class), old_route) in routes.drain() {
                            record_stream_route_closed(old_class, &old_route);
                        }
                    }
                    if route_class == RouteClass::Bulk {
                        if let Some(stats) = route.stats.as_ref() {
                            let _ = stats.record_stream_open();
                        }
                    }
                    routes.insert((dst_node, stream_id, route_class), route);
                }
                Ok(route)
            }
        }
    }

    async fn ensure_outbound_circuit(
        &self,
        dst_node: [u8; 32],
        stream_id: Option<u32>,
        route_class: RouteClass,
        is_handshake: bool,
    ) -> io::Result<Option<CircuitRoute>> {
        let now = Instant::now();
        let retired = {
            let mut circuits = self.outbound_circuits.lock().await;
            if let Some(entries) = circuits.get_mut(&dst_node) {
                if entries.is_empty() {
                    circuits.remove(&dst_node);
                    None
                } else if let Some(stream_id) = stream_id {
                    if let Some(entry) = entries.iter_mut().find(|entry| {
                        route_class == RouteClass::Bulk
                            && entry.handshake_streams.contains(&stream_id)
                    }) {
                        entry.last_used = now;
                        return Ok(Some(entry.route()));
                    }
                    let old_quiet = entries.iter().all(|entry| {
                        now.duration_since(entry.opened_at) >= CIRCUIT_HANDSHAKE_REOPEN_AFTER
                            && now.duration_since(entry.last_non_handshake)
                                >= CIRCUIT_HANDSHAKE_REOPEN_AFTER
                    });
                    if is_handshake && old_quiet {
                        // MAKE-BEFORE-BREAK (device-verified regression,
                        // 2026-07-06): retiring the WHOLE pool here killed the
                        // routes still carrying LIVE streams. On a real-WAN
                        // path the serve side's in-flight reply route died
                        // mid-transfer ("driver gone"), the puller timed out
                        // waiting for its manifest, retried with a NEW
                        // handshake and re-tripped this branch — a
                        // self-sustaining churn loop (20 MB transfers never
                        // completed on the production seeds while a 200 KB
                        // file could slip through between reopen cycles; a
                        // zero-RTT local mesh reopens fast enough that the
                        // loop never bites, which is why the live tests
                        // stayed green). Retire only the genuinely idle
                        // circuits; keep every route with active streams and
                        // refill the pool in the background.
                        let mut kept: Vec<CircuitEntry> = Vec::new();
                        let mut idle: Vec<CircuitEntry> = Vec::new();
                        for entry in entries.drain(..) {
                            if entry.stats.active_streams() > 0 {
                                kept.push(entry);
                            } else {
                                idle.push(entry);
                            }
                        }
                        if kept.is_empty() {
                            diag_node(
                                &self.me,
                                &format!(
                                    "outbound circuit pool handshake on old/quiet path \
                         to {} (stream={} routes={}) — reopening",
                                    short_node(&dst_node),
                                    stream_id,
                                    idle.len(),
                                ),
                            );
                            circuits.remove(&dst_node);
                            Some(idle.into_iter().map(|entry| entry.circuit).collect())
                        } else {
                            diag_node(
                                &self.me,
                                &format!(
                                    "outbound circuit pool handshake on old/quiet path \
                         to {} (stream={}) — keeping {} live route(s), retiring {} idle, \
                         refilling in background",
                                    short_node(&dst_node),
                                    stream_id,
                                    kept.len(),
                                    idle.len(),
                                ),
                            );
                            entries.extend(kept);
                            let route = self.select_outbound_route(
                                dst_node,
                                entries,
                                stream_id,
                                route_class,
                                now,
                            );
                            drop(circuits);
                            retire_circuits_later(
                                &self.services,
                                idle.into_iter().map(|entry| entry.circuit).collect(),
                            );
                            self.ensure_outbound_opening(dst_node, route_class).await;
                            if let Some(route) = route {
                                return Ok(Some(route));
                            }
                            // Every live route is momentarily unusable
                            // (cooldown / admission limit) — open a fresh
                            // handshake circuit rather than dropping the SYN.
                            return self
                                .open_outbound_for_handshake(dst_node, route_class)
                                .await;
                        }
                    } else {
                        let route = self.select_outbound_route(
                            dst_node,
                            entries,
                            stream_id,
                            route_class,
                            now,
                        );
                        return Ok(route);
                    }
                } else {
                    let idle_for = entries
                        .iter()
                        .map(|entry| now.duration_since(entry.last_used))
                        .min()
                        .unwrap_or(CIRCUIT_IDLE_REFRESH_AFTER);
                    if idle_for < CIRCUIT_IDLE_REFRESH_AFTER {
                        let route =
                            self.select_outbound_route(dst_node, entries, 0, route_class, now);
                        return Ok(route);
                    }
                    diag_node(
                        &self.me,
                        &format!(
                            "outbound circuit pool to {} idle for {}s — reopening in background",
                            short_node(&dst_node),
                            idle_for.as_secs()
                        ),
                    );
                    let entries = circuits.remove(&dst_node).unwrap_or_default();
                    Some(entries.into_iter().map(|entry| entry.circuit).collect())
                }
            } else {
                None
            }
        };
        if let Some(retired) = retired {
            retire_circuits_later(&self.services, retired);
        }
        {
            let circuits = self.outbound_circuits.lock().await;
            if let Some(entries) = circuits.get(&dst_node) {
                if let Some(entry) = entries.first() {
                    return Ok(Some(entry.route()));
                }
            }
        }

        if is_handshake {
            return self
                .open_outbound_for_handshake(dst_node, route_class)
                .await;
        }

        self.ensure_outbound_opening(dst_node, route_class).await;
        Ok(None)
    }

    fn outbound_pool_target_for(&self, route_class: RouteClass) -> usize {
        match route_class {
            RouteClass::Bulk => self.outbound_pool_target,
            RouteClass::Ack => self.ack_outbound_pool_target,
        }
        .clamp(1, MAX_CIRCUIT_OUTBOUND_POOL)
    }

    fn select_outbound_route(
        &self,
        dst_node: [u8; 32],
        entries: &mut [CircuitEntry],
        stream_id: u32,
        route_class: RouteClass,
        now: Instant,
    ) -> Option<CircuitRoute> {
        if entries.is_empty() {
            return None;
        }
        let route_count = match route_class {
            RouteClass::Bulk => entries.len(),
            RouteClass::Ack => entries.len().min(
                self.ack_outbound_pool_target
                    .clamp(1, MAX_CIRCUIT_OUTBOUND_POOL),
            ),
        };
        let cooldown_now = Instant::now();
        let cooled_relays = {
            let mut cooldowns = self
                .route_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.retain(|_, until| *until > cooldown_now);
            cooldowns.clone()
        };
        let cooled_first_hops = {
            let mut cooldowns = self
                .first_hop_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.retain(|_, until| *until > cooldown_now);
            cooldowns.clone()
        };
        let usable_indices = (0..route_count)
            .filter(|idx| {
                cooled_relays
                    .get(&entries[*idx].rendezvous_node)
                    .is_none_or(|until| *until <= cooldown_now)
                    && cooled_first_hops
                        .get(&entries[*idx].circuit.first_hop())
                        .is_none_or(|until| *until <= cooldown_now)
                    && self
                        .services
                        .has_live_session(&entries[*idx].circuit.first_hop())
            })
            .collect::<Vec<_>>();
        if usable_indices.is_empty() {
            return None;
        }
        let candidate_indices =
            if route_class == RouteClass::Bulk && self.bulk_route_active_limit > 0 {
                let under_limit = usable_indices
                    .iter()
                    .copied()
                    .filter(|idx| {
                        entries[*idx].stats.active_streams() < self.bulk_route_active_limit as u64
                    })
                    .collect::<Vec<_>>();
                if under_limit.is_empty() {
                    return None;
                }
                under_limit
            } else {
                usable_indices
            };
        // NOTE deliberately NO slow-mark bias here (tried 2026-07-06 and
        // reverted): a route that kills streams instantly (<128 KB sent, so
        // never a busy window, never marked) stayed "healthy" while the
        // merely-slow routes were marked and excluded — the filter then
        // funneled EVERY new stream into the black hole and the pull
        // serialized into single-attempt retries. Plain round-robin spreads
        // that risk; the slow mark only gates the shed TARGET choice.
        let idx = {
            let mut next = self
                .next_outbound_route
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let slot = next.entry((dst_node, route_class)).or_insert(0);
            let idx = candidate_indices[*slot % candidate_indices.len()];
            *slot = slot.wrapping_add(1);
            idx
        };
        let entry = &mut entries[idx];
        entry.last_used = now;
        if route_class == RouteClass::Bulk {
            if entry.handshake_streams.len() >= 256 && !entry.handshake_streams.contains(&stream_id)
            {
                entry.handshake_streams.clear();
            }
            entry.handshake_streams.insert(stream_id);
        }
        Some(entry.route())
    }

    fn route_session_stale(&self, route: &CircuitRoute) -> bool {
        if route.rendezvous_node.is_none() {
            return false;
        }
        let first_hop = route.circuit.first_hop();
        self.services.session_close_generation(&first_hop) != route.first_hop_close_generation
            || !self.services.has_live_session(&first_hop)
    }

    async fn mark_route_stale(&self, dst_node: [u8; 32], route: &CircuitRoute) {
        let Some(relay) = route.rendezvous_node else {
            return;
        };
        mark_rendezvous_cooldown(&self.route_cooldowns, relay, CIRCUIT_ROUTE_SEND_COOLDOWN);
        let first_hop = route.circuit.first_hop();
        mark_first_hop_cooldown(
            &self.first_hop_cooldowns,
            first_hop,
            CIRCUIT_ROUTE_SEND_COOLDOWN,
        );
        let removed_routes = {
            let mut routes = self.stream_routes.lock().await;
            let mut removed = Vec::new();
            routes.retain(|(node, _, route_class), cached| {
                let keep = *node != dst_node || cached.rendezvous_node != Some(relay);
                if !keep {
                    removed.push((*route_class, cached.clone()));
                }
                keep
            });
            removed
        };
        for (route_class, route) in removed_routes {
            record_stream_route_closed(route_class, &route);
        }
        let retired = {
            let mut circuits = self.outbound_circuits.lock().await;
            circuits.get_mut(&dst_node).and_then(|entries| {
                entries
                    .iter()
                    .position(|entry| entry.rendezvous_node == relay)
                    .map(|idx| entries.remove(idx).circuit)
            })
        };
        if let Some(retired) = retired {
            retire_circuits_later(&self.services, vec![retired]);
        }
        let stats = route
            .stats
            .as_ref()
            .map(|stats| stats.snapshot().to_string())
            .unwrap_or_else(|| "stats=none".to_string());
        diag_node(
            &self.me,
            &format!(
                "outbound route stale for {} via R={} path={} first_hop={} live={} gen={} now={} {stats} — cooled for {}s",
                short_node(&dst_node),
                short_node(&relay),
                short_path(route.circuit.relay_path()),
                short_node(&first_hop),
                self.services.has_live_session(&first_hop),
                route.first_hop_close_generation,
                self.services.session_close_generation(&first_hop),
                CIRCUIT_ROUTE_SEND_COOLDOWN.as_secs(),
            ),
        );
        self.ensure_outbound_opening(dst_node, RouteClass::Bulk)
            .await;
    }

    async fn mark_route_no_progress(
        &self,
        dst_node: [u8; 32],
        stream_id: u32,
        route: &CircuitRoute,
        consec_rto: u32,
        stream_rto_events: u64,
        snd_una: u32,
    ) {
        let Some(relay) = route.rendezvous_node else {
            return;
        };
        let first_hop = route.circuit.first_hop();
        // `consec_rto` is the STREAM's cumulative counter: it keeps climbing
        // across route remaps, so a single sick stream would otherwise walk
        // through the pool quarantining every fresh route after one RTO on it
        // (observed live as a full pool collapse: consec_rto=3/4/5 with
        // stream_rto_events=1 per route). Quarantine needs route-local
        // evidence: at least two RTO events for this stream on THIS route.
        // A dead first-hop session is still quarantined immediately.
        let route_local_evidence = stream_rto_events >= 2;
        let quarantine_route = (route_local_evidence
            && (consec_rto >= 3 || stream_rto_events >= CIRCUIT_ROUTE_NO_PROGRESS_RTO_EVENTS + 1))
            || !self.services.has_live_session(&first_hop);
        // Pool-preserving guard: on a small relay set, two concurrent
        // quarantines that each cool a rendezvous AND a first-hop can leave
        // ZERO openable routes for the whole cooldown (observed live: every
        // refill failed "first-hop cooled" for 20s and the transfer
        // flat-lined). Downgrade the cooldown scope until at least one other
        // open route stays usable; the sticky remap below still moves the
        // affected stream off this route immediately, and the relay's own
        // circuits are still retired so the refill opens FRESH circuits.
        let (cool_relay, cool_first_hop) = if quarantine_route {
            let cooldown_now = Instant::now();
            let cooled_relays = {
                let cooldowns = self
                    .route_cooldowns
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                cooldowns
                    .iter()
                    .filter(|(_, until)| **until > cooldown_now)
                    .map(|(node, _)| *node)
                    .collect::<HashSet<_>>()
            };
            let cooled_first_hops = {
                let cooldowns = self
                    .first_hop_cooldowns
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                cooldowns
                    .iter()
                    .filter(|(_, until)| **until > cooldown_now)
                    .map(|(node, _)| *node)
                    .collect::<HashSet<_>>()
            };
            let circuits = self.outbound_circuits.lock().await;
            let entries = circuits.get(&dst_node);
            let usable_besides = |block_first_hop: bool| {
                entries
                    .map(|entries| {
                        entries.iter().any(|entry| {
                            let entry_first_hop = entry.circuit.first_hop();
                            entry.rendezvous_node != relay
                                && (!block_first_hop || entry_first_hop != first_hop)
                                && !cooled_relays.contains(&entry.rendezvous_node)
                                && !cooled_first_hops.contains(&entry_first_hop)
                                && self.services.has_live_session(&entry_first_hop)
                        })
                    })
                    .unwrap_or(false)
            };
            if usable_besides(true) {
                (true, true)
            } else if usable_besides(false) {
                (true, false)
            } else {
                (false, false)
            }
        } else {
            (false, false)
        };
        let removed_routes = {
            let mut routes = self.stream_routes.lock().await;
            let mut removed = Vec::new();
            routes.retain(|(node, sid, route_class), cached| {
                let keep = if quarantine_route {
                    *node != dst_node
                        || (cached.rendezvous_node != Some(relay)
                            && (!cool_first_hop || cached.circuit.first_hop() != first_hop))
                } else {
                    *node != dst_node || *sid != stream_id || cached.rendezvous_node != Some(relay)
                };
                if !keep {
                    removed.push((*route_class, cached.clone()));
                }
                keep
            });
            removed
        };
        for (route_class, route) in removed_routes {
            record_stream_route_closed(route_class, &route);
        }
        let stats = route
            .stats
            .as_ref()
            .map(|stats| stats.snapshot().to_string())
            .unwrap_or_else(|| "stats=none".to_string());
        if quarantine_route {
            if cool_relay {
                mark_rendezvous_cooldown(
                    &self.route_cooldowns,
                    relay,
                    CIRCUIT_ROUTE_NO_PROGRESS_COOLDOWN,
                );
            }
            if cool_first_hop {
                mark_first_hop_cooldown(
                    &self.first_hop_cooldowns,
                    first_hop,
                    CIRCUIT_ROUTE_NO_PROGRESS_COOLDOWN,
                );
            }
            let retired = {
                let mut circuits = self.outbound_circuits.lock().await;
                circuits
                    .get_mut(&dst_node)
                    .map(|entries| {
                        let mut retired = Vec::new();
                        let mut idx = 0;
                        while idx < entries.len() {
                            if entries[idx].rendezvous_node == relay
                                || (cool_first_hop && entries[idx].circuit.first_hop() == first_hop)
                            {
                                retired.push(entries.remove(idx).circuit);
                            } else {
                                idx += 1;
                            }
                        }
                        retired
                    })
                    .unwrap_or_default()
            };
            if !retired.is_empty() {
                retire_circuits_later(&self.services, retired);
            }
        }
        let message = if quarantine_route {
            format!(
                "outbound route no-progress quarantine for {} stream={} via R={} path={} first_hop={} consec_rto={} stream_rto_events={} snd_una={} {stats} — cooled for {}s (relay={} first_hop={})",
                short_node(&dst_node),
                stream_id,
                short_node(&relay),
                short_path(route.circuit.relay_path()),
                short_node(&first_hop),
                consec_rto,
                stream_rto_events,
                snd_una,
                CIRCUIT_ROUTE_NO_PROGRESS_COOLDOWN.as_secs(),
                cool_relay,
                cool_first_hop,
            )
        } else {
            format!(
                "outbound stream no-progress remap for {} stream={} via R={} path={} first_hop={} consec_rto={} stream_rto_events={} snd_una={} {stats} — keeping rendezvous warm",
                short_node(&dst_node),
                stream_id,
                short_node(&relay),
                short_path(route.circuit.relay_path()),
                short_node(&first_hop),
                consec_rto,
                stream_rto_events,
                snd_una,
            )
        };
        diag_node(&self.me, &message);
        self.ensure_outbound_opening(dst_node, RouteClass::Bulk)
            .await;
    }

    /// Throughput-aware route shedding. RACK repair keeps a sick-but-alive
    /// chain making steady progress with almost no RTO events, so the
    /// no-progress/quarantine paths never fire and a bulk stream can crawl
    /// at ~100 KB/s while a clean pool route sits idle (device A/B
    /// 2026-07-06: 20 MB in 183 s on a netem'd chain vs 15 s clean). After
    /// [`CIRCUIT_ROUTE_SHED_SLOW_WINDOWS`] consecutive busy-but-slow windows
    /// on the stream's sticky route, rebind the stream DIRECTLY to the best
    /// other usable pool route — non-quarantine: the slow relay's circuit
    /// stays pooled and warm (it may be slow only for this path direction,
    /// and cooling it under a small relay set starves the pool). Anti-flap:
    /// per-peer [`CIRCUIT_ROUTE_SHED_COOLDOWN`] between sheds, and the fresh
    /// route needs its own full window streak before it can be shed.
    async fn maybe_shed_slow_bulk_route(
        &self,
        dst_node: [u8; 32],
        stream_id: u32,
        route: &CircuitRoute,
    ) {
        if self.mode != CircuitMode::PublishedRendezvous {
            return;
        }
        let Some(stats) = route.stats.as_ref() else {
            return;
        };
        let now = Instant::now();
        if stats.slow_windows(now) < CIRCUIT_ROUTE_SHED_SLOW_WINDOWS {
            return;
        }
        let Some(relay) = route.rendezvous_node else {
            return;
        };
        // Read-only cooldown probe; the mark is written only when the remap
        // actually executes, so a no-alternative pool doesn't burn it.
        {
            let marks = self
                .bulk_shed_marks
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(last) = marks.get(&dst_node) {
                if now.saturating_duration_since(*last) < CIRCUIT_ROUTE_SHED_COOLDOWN {
                    return;
                }
            }
        }
        let cooled_relays: HashSet<[u8; 32]> = {
            let cooldowns = self
                .route_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns
                .iter()
                .filter(|(_, until)| **until > now)
                .map(|(node, _)| *node)
                .collect()
        };
        let cooled_first_hops: HashSet<[u8; 32]> = {
            let cooldowns = self
                .first_hop_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns
                .iter()
                .filter(|(_, until)| **until > now)
                .map(|(node, _)| *node)
                .collect()
        };
        let slow_first_hop = route.circuit.first_hop();
        let target = {
            let circuits = self.outbound_circuits.lock().await;
            circuits.get(&dst_node).and_then(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        let entry_first_hop = entry.circuit.first_hop();
                        entry.rendezvous_node != relay
                            && !cooled_relays.contains(&entry.rendezvous_node)
                            && !cooled_first_hops.contains(&entry_first_hop)
                            && self.services.has_live_session(&entry_first_hop)
                            // A marked target is measurably crawling too —
                            // remapping onto it is pure churn (observed live
                            // as a 3d↔c92 ping-pong every shed cooldown).
                            // With no unmarked alternative, stay put and let
                            // the marks expire / the pool refill.
                            && !entry.stats.slow_marked(now)
                    })
                    // Prefer a distinct first hop (the slowness may live in
                    // the shared first-hop session), then the least-loaded
                    // route.
                    .min_by_key(|entry| {
                        (
                            entry.circuit.first_hop() == slow_first_hop,
                            entry.stats.active_streams(),
                        )
                    })
                    .map(|entry| entry.route())
            })
        };
        let Some(target) = target else {
            // No usable alternative right now: keep the streak and kick a
            // refill so the shed fires as soon as the pool widens.
            self.ensure_outbound_opening(dst_node, RouteClass::Bulk)
                .await;
            return;
        };
        let swapped = {
            let mut routes = self.stream_routes.lock().await;
            let key = (dst_node, stream_id, RouteClass::Bulk);
            // Rebind only if the stream is still pinned to the slow relay —
            // a concurrent no-progress/stale remap may already have moved it.
            match routes.get(&key) {
                Some(current) if current.rendezvous_node == Some(relay) => {
                    if let Some(new_stats) = target.stats.as_ref() {
                        let _ = new_stats.record_stream_open();
                    }
                    if let Some(old_route) = routes.insert(key, target.clone()) {
                        record_stream_route_closed(RouteClass::Bulk, &old_route);
                    }
                    true
                }
                _ => false,
            }
        };
        if !swapped {
            return;
        }
        // Deliberately KEEP the old route's slow mark: it now steers the
        // selection health bias away from the sick chain for new streams,
        // and it self-expires via CIRCUIT_ROUTE_SLOW_MARK_TTL.
        {
            let mut marks = self
                .bulk_shed_marks
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            marks.retain(|_, at| now.saturating_duration_since(*at) < CIRCUIT_ROUTE_SHED_COOLDOWN);
            marks.insert(dst_node, now);
        }
        diag_node(
            &self.me,
            &format!(
                "outbound slow-route shed for {} stream={} via R={} path={} -> R={} path={} {} — keeping rendezvous warm",
                short_node(&dst_node),
                stream_id,
                short_node(&relay),
                short_path(route.circuit.relay_path()),
                target
                    .rendezvous_node
                    .map(|r| short_node(&r))
                    .unwrap_or_else(|| "-".to_string()),
                short_path(target.circuit.relay_path()),
                stats.snapshot(),
            ),
        );
        self.ensure_outbound_opening(dst_node, RouteClass::Bulk)
            .await;
    }

    async fn mark_route_send_failed(
        &self,
        dst_node: [u8; 32],
        route: &CircuitRoute,
        err: veil_node_runtime::DataCircuitSendError,
    ) {
        let Some(relay) = route.rendezvous_node else {
            return;
        };
        let until = Instant::now() + CIRCUIT_ROUTE_SEND_COOLDOWN;
        let first_hop = route.circuit.first_hop();
        {
            let mut cooldowns = self
                .route_cooldowns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cooldowns.insert(relay, until);
        }
        mark_first_hop_cooldown(
            &self.first_hop_cooldowns,
            first_hop,
            CIRCUIT_ROUTE_SEND_COOLDOWN,
        );
        let removed_routes = {
            let mut routes = self.stream_routes.lock().await;
            let mut removed = Vec::new();
            routes.retain(|(node, _, route_class), cached| {
                let keep = *node != dst_node || cached.rendezvous_node != Some(relay);
                if !keep {
                    removed.push((*route_class, cached.clone()));
                }
                keep
            });
            removed
        };
        for (route_class, route) in removed_routes {
            record_stream_route_closed(route_class, &route);
        }
        let retired = {
            let mut circuits = self.outbound_circuits.lock().await;
            circuits.get_mut(&dst_node).and_then(|entries| {
                entries
                    .iter()
                    .position(|entry| entry.rendezvous_node == relay)
                    .map(|idx| entries.remove(idx).circuit)
            })
        };
        if let Some(retired) = retired {
            retire_circuits_later(&self.services, vec![retired]);
        }
        let stats = route
            .stats
            .as_ref()
            .map(|stats| stats.record_send_failure().to_string())
            .unwrap_or_else(|| "stats=none".to_string());
        diag_node(
            &self.me,
            &format!(
                "outbound route cooled for {} via R={} path={} {stats} for {}s after send failure: {err:?}",
                short_node(&dst_node),
                short_node(&relay),
                short_path(route.circuit.relay_path()),
                CIRCUIT_ROUTE_SEND_COOLDOWN.as_secs(),
            ),
        );
        self.ensure_outbound_opening(dst_node, RouteClass::Bulk)
            .await;
    }

    async fn mark_outbound_non_handshake(&self, dst_node: [u8; 32], route: &CircuitRoute) {
        let now = Instant::now();
        if let Some(entries) = self.outbound_circuits.lock().await.get_mut(&dst_node) {
            for entry in entries {
                if Arc::ptr_eq(&entry.circuit, &route.circuit) {
                    entry.last_used = now;
                    entry.last_non_handshake = now;
                    break;
                }
            }
        }
    }

    /// Startup/pre-transfer warm: kick the background outbound-pool open
    /// toward `dst_node` without sending anything. A freshly-restarted node's
    /// first serve/pull otherwise pays the full cold-pool price inside the
    /// peer's 25 s manifest window (attempt 1 dies, attempt 2 rides the pool
    /// the failure opened). Idempotent and cheap: `ensure_outbound_opening`
    /// debounces concurrent opens and the open task itself tops up an
    /// already-full pool as a no-op.
    async fn warm_outbound(&self, dst_node: [u8; 32]) {
        if self.mode != CircuitMode::PublishedRendezvous {
            return;
        }
        self.ensure_outbound_opening(dst_node, RouteClass::Bulk)
            .await;
    }

    async fn ensure_outbound_opening(&self, dst_node: [u8; 32], route_class: RouteClass) {
        let now = Instant::now();
        {
            let mut opening = self.outbound_opening.lock().await;
            if let Some(started) = opening.get(&dst_node) {
                // Circuit open/confirmation can legitimately take a few seconds
                // on a cold phone. Do not start a stampede of duplicate opens;
                // if a task gets wedged, allow a later retransmit to kick a new one.
                if now.duration_since(*started) < CIRCUIT_CONFIRM_TIMEOUT * 2 {
                    return;
                }
            }
            opening.insert(dst_node, now);
        }

        let services = self.services.clone();
        let me = self.me;
        let reg_kp = Arc::clone(&self.reg_kp);
        let epoch = Arc::clone(&self.epoch);
        let in_tx = self.in_tx.clone();
        let activity = Arc::clone(&self.activity);
        let inbound_activity = Arc::clone(&self.inbound_activity);
        let outbound_circuits = Arc::clone(&self.outbound_circuits);
        let outbound_opening = Arc::clone(&self.outbound_opening);
        let peer_tags = Arc::clone(&self.peer_tags);
        let outbound_peer_tags = Arc::clone(&self.outbound_peer_tags);
        let route_cooldowns = Arc::clone(&self.route_cooldowns);
        let first_hop_cooldowns = Arc::clone(&self.first_hop_cooldowns);
        let pool_target = self.outbound_pool_target_for(route_class);
        tokio::spawn(async move {
            let opened = open_outbound_circuit(
                services.clone(),
                dst_node,
                me,
                reg_kp,
                epoch,
                in_tx,
                activity,
                inbound_activity,
                outbound_circuits,
                peer_tags,
                outbound_peer_tags,
                route_cooldowns,
                first_hop_cooldowns,
                pool_target,
            )
            .await;
            outbound_opening.lock().await.remove(&dst_node);
            if let Err(e) = opened {
                diag_node(
                    &me,
                    &format!(
                        "outbound circuit open failed for {}: {e}",
                        short_node(&dst_node)
                    ),
                );
            }
        });
    }

    async fn open_outbound_for_handshake(
        &self,
        dst_node: [u8; 32],
        route_class: RouteClass,
    ) -> io::Result<Option<CircuitRoute>> {
        let now = Instant::now();
        let should_open = {
            let mut opening = self.outbound_opening.lock().await;
            if let Some(started) = opening.get(&dst_node) {
                now.duration_since(*started) >= CIRCUIT_CONFIRM_TIMEOUT * 2
            } else {
                true
            }
            .then(|| opening.insert(dst_node, now))
            .is_some()
        };

        if should_open {
            let opened = open_outbound_circuit(
                self.services.clone(),
                dst_node,
                self.me,
                Arc::clone(&self.reg_kp),
                Arc::clone(&self.epoch),
                self.in_tx.clone(),
                Arc::clone(&self.activity),
                Arc::clone(&self.inbound_activity),
                Arc::clone(&self.outbound_circuits),
                Arc::clone(&self.peer_tags),
                Arc::clone(&self.outbound_peer_tags),
                Arc::clone(&self.route_cooldowns),
                Arc::clone(&self.first_hop_cooldowns),
                self.outbound_pool_target_for(route_class),
            )
            .await;
            self.outbound_opening.lock().await.remove(&dst_node);
            if let Err(e) = opened {
                diag_node(
                    &self.me,
                    &format!(
                        "outbound circuit handshake-open failed for {}: {e}",
                        short_node(&dst_node)
                    ),
                );
            }
        } else {
            let deadline = Instant::now() + CIRCUIT_CONFIRM_TIMEOUT;
            while Instant::now() < deadline {
                if let Some(entries) = self.outbound_circuits.lock().await.get(&dst_node) {
                    if let Some(entry) = entries.first() {
                        return Ok(Some(entry.route()));
                    }
                }
                if !self.outbound_opening.lock().await.contains_key(&dst_node) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        let circuits = self.outbound_circuits.lock().await;
        Ok(circuits
            .get(&dst_node)
            .and_then(|entries| entries.first())
            .map(CircuitEntry::route))
    }
}

/// One of the two [`CellSender`] backends (gated at hub build).
enum HubCells {
    Anon(AnonCells),
    Circuit(CircuitCells),
}

impl CellSender for HubCells {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        match self {
            HubCells::Anon(c) => c.send(dst, cell).await,
            HubCells::Circuit(c) => c.send(dst, cell).await,
        }
    }

    // MUST forward: without this the trait's default cell-by-cell loop hides
    // the circuit path's batched run sender (one route resolve + one pacer
    // reserve + one bookkeeping pass per DATA run, and the route-striping
    // split). Live this silently degraded every stream back to the scalar
    // per-cell path — batching worked in unit tests (which drive
    // CircuitCells directly) but never end-to-end through the hub.
    async fn send_many(
        &self,
        dst: Addr,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<()> {
        match self {
            HubCells::Anon(c) => c.send_many(dst, cells).await,
            HubCells::Circuit(c) => c.send_many(dst, cells).await,
        }
    }

    async fn on_stream_data_rto(&self, dst: Addr, stream_id: u32, consec_rto: u32, snd_una: u32) {
        match self {
            HubCells::Anon(_) => {}
            HubCells::Circuit(c) => {
                c.on_stream_data_rto(dst, stream_id, consec_rto, snd_una)
                    .await;
            }
        }
    }

    async fn on_stream_closed(&self, dst: Addr, stream_id: u32, end: End) {
        match self {
            HubCells::Anon(_) => {}
            HubCells::Circuit(c) => c.on_stream_closed(dst, stream_id, end).await,
        }
    }
}

/// Inbound feed for the datagram path: authenticated anonymous datagrams on the
/// stream endpoint → (Addr{src_node, derived_app}, cell).
fn spawn_anon_feed(
    mut msg_rx: mpsc::Receiver<IncomingMessage>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
) {
    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            // The authenticated anonymous transport delivers src_app_id = [0;32]
            // (no sender app id) — DERIVE the peer's stream endpoint app from its
            // node id (the deterministic `app_id(node, ns, name)` both ends bind).
            let app = veil_app::address::app_id(&msg.src_node_id, STREAM_NAMESPACE, STREAM_NAME);
            let addr = Addr {
                node: msg.src_node_id,
                app,
            };
            if in_tx.send((addr, msg.data)).await.is_err() {
                break;
            }
        }
    });
}

/// Node-wide multiplexer for anonymous streams (one per node, built lazily on
/// the first open/accept). Keeps the stream endpoint bound for its lifetime.
pub struct AnonStreamHub {
    mux: Arc<StreamMux<HubCells>>,
    /// Direct handle to the cell backend for out-of-band operations
    /// (outbound-pool pre-warm) that must not ride the stream path.
    cells: Arc<HubCells>,
    _sender: Arc<AppSender>,
}

impl AnonStreamHub {
    /// Build over a freshly-bound stream endpoint's `sender` + raw inbound
    /// datagram channel `msg_rx`. `me` = this node id. MUST be called inside the
    /// tokio runtime. Uses the pinned-circuit backend by default when an embedded
    /// node is present and a rendezvous relay is resolvable (override via
    /// `VEIL_ONION_STREAM_CIRCUIT`); otherwise the datagram path (no regression).
    pub fn new(me: [u8; 32], sender: AppSender, msg_rx: mpsc::Receiver<IncomingMessage>) -> Self {
        let sender = Arc::new(sender);
        let (in_tx, in_rx) = mpsc::channel(1024);

        // Try the pinned-circuit backend (explicit opt-in) + embedded; else datagram.
        let circuit_cells = if let Some(mode) = circuit_mode() {
            try_open_circuit(me, in_tx.clone(), mode)
        } else {
            None
        };

        let (cells, mss) = match circuit_cells {
            Some(c) => (HubCells::Circuit(c), CIRCUIT_MSS),
            None => {
                // Datagram path (default / fallback): feed inbound from msg_rx.
                spawn_anon_feed(msg_rx, in_tx);
                let data_pace_interval = stream_data_pace_interval(false);
                diag_node(
                    &me,
                    &format!(
                        "datagram shared DATA pacer {}us",
                        data_pace_interval.as_micros()
                    ),
                );
                (
                    HubCells::Anon(AnonCells {
                        sender: sender.clone(),
                        data_pacer: Arc::new(StreamDataPacer::new(data_pace_interval)),
                    }),
                    veil_onion_stream::MSS,
                )
            }
        };
        // Surface which backend engaged (desktop: stderr; phone: logcat).
        let backend = match &cells {
            HubCells::Circuit(c) => match c.mode {
                CircuitMode::PublishedRendezvous => "circuit mode — published rendezvous ads",
                CircuitMode::ValidationMinRouting => "circuit mode — validation min-routing",
            },
            HubCells::Anon(_) => "datagram path (no embedded node)",
        };
        diag_node(&me, backend);

        // The onion RTT is variable and relay queues can punish coarse bursts:
        // keep the first RTO above normal jitter, pace the sender, and keep an
        // explicit receive window instead of letting cwnd grow unbounded.
        //
        // The original 1-cell/ms pacer floor capped clean transfers at ~135 KiB/s.
        // After converting both stream and circuit pacing to small millisecond
        // batches, the autonomous embedded harness reliably moves 8 MiB over
        // published rendezvous with 4 MiB × batch64 × 50us. A later 10s RTO
        // floor proved too conservative for ranged pulls: with real SRTT around
        // 150-800ms, a single lost/black-holed hole parked workers for 10→20s
        // and looked like a stack-level stop-and-wait ceiling. Keep the circuit
        // defaults quick enough to repair holes before the content-layer idle
        // timer fires, while still overrideable for hostile WAN probes.
        let is_circuit = matches!(&cells, HubCells::Circuit(_));
        let recv_window = match &cells {
            // Must cover the path BDP with probe headroom or the advertised
            // window becomes the throughput cap: post-BBR-fix a single circuit
            // stream sustains ~12 MB/s at ~150-300ms live RTT (~2-3.6 MiB of
            // flight), and the 3x-BDP STARTUP probe brushed the old 4 MiB
            // ceiling. BBR's 2x-BDP steady cap keeps the standing queue small,
            // so the larger advert costs memory only when actually in flight.
            HubCells::Circuit(_) => env_u32(
                CIRCUIT_RECV_WINDOW_ENV,
                8 * 1024 * 1024,
                (64 * 1024) as u32,
                (16 * 1024 * 1024) as u32,
            ),
            HubCells::Anon(_) => (1024 * mss) as u32,
        };
        let init_rto_ms = if is_circuit {
            env_or_android_u64(
                CIRCUIT_INIT_RTO_MS_ENV,
                ANDROID_INIT_RTO_MS_PROP,
                2_000,
                1_000,
                120_000,
            )
        } else {
            12_000
        };
        let min_rto_ms = if is_circuit {
            env_or_android_u64(
                CIRCUIT_MIN_RTO_MS_ENV,
                ANDROID_MIN_RTO_MS_PROP,
                1_000,
                500,
                120_000,
            )
        } else {
            10_000
        };
        let max_rto_ms = if is_circuit {
            env_or_android_u64(
                CIRCUIT_MAX_RTO_MS_ENV,
                ANDROID_MAX_RTO_MS_PROP,
                10_000,
                min_rto_ms,
                300_000,
            )
        } else {
            60_000
        };
        let max_retransmits = if is_circuit {
            env_or_android_u32(
                CIRCUIT_MAX_RETRANSMITS_ENV,
                ANDROID_MAX_RETRANSMITS_PROP,
                5,
                1,
                30,
            )
        } else {
            15
        };
        let init_cwnd_mss = if is_circuit {
            env_or_android_usize(
                CIRCUIT_INIT_CWND_MSS_ENV,
                ANDROID_INIT_CWND_MSS_PROP,
                DEFAULT_CIRCUIT_INIT_CWND_MSS,
                1,
                MAX_CIRCUIT_INIT_CWND_MSS,
            )
        } else {
            32
        };
        let init_cwnd = ((init_cwnd_mss * mss).min(recv_window as usize)) as u32;
        let max_pacing_batch = if is_circuit {
            // Pacing uses millisecond ticks for scheduler realism, but on
            // Android the driver timer coalesces well past 1ms, so one batch
            // per wake quantizes the whole stream to batch/wake-interval
            // (64 cells / ~12.5ms real wake = ~1.6 MiB/s live phone ceiling).
            // 256 keeps a phone sender fed across coalesced wakes; the actual
            // wire burst stays bounded by the shared circuit DATA pacer's
            // token-bucket credit, not by this engine-side budget.
            env_or_android_u32(
                CIRCUIT_MAX_PACING_BATCH_ENV,
                ANDROID_MAX_PACING_BATCH_PROP,
                256,
                1,
                512,
            )
        } else {
            4
        };
        let debug_summary_ms = if is_circuit {
            env_or_android_u64(
                DEBUG_SUMMARY_MS_ENV,
                ANDROID_DEBUG_SUMMARY_MS_PROP,
                0,
                0,
                60_000,
            )
        } else {
            0
        };
        let loss_decrease_per_mille = if is_circuit { 750 } else { 500 };
        // BBR-lite queue shaping (see engine Config::bbr). Circuit-only and
        // default ON: the loss-free pinned circuit otherwise parks a full
        // receive window in sender-side queues (live srtt ~2.3s of pure
        // queueing), which slows RTO/loss detection and route failover.
        let bbr = is_circuit && env_or_android_u32(CIRCUIT_BBR_ENV, ANDROID_BBR_PROP, 1, 0, 1) == 1;
        // RACK loss detection (see CIRCUIT_RACK_ENV). The reorder floor
        // defaults high when this hub stripes DATA across routes: adaptation
        // alone pays a spurious-resend learning tax on the first flights.
        let rack =
            is_circuit && env_or_android_u32(CIRCUIT_RACK_ENV, ANDROID_RACK_PROP, 1, 0, 1) == 1;
        let stripe_active = match &cells {
            HubCells::Circuit(c) => c.stripe_routes > 1,
            HubCells::Anon(_) => false,
        };
        let rack_reo_floor_ms = env_or_android_u32(
            CIRCUIT_RACK_REO_FLOOR_MS_ENV,
            ANDROID_RACK_REO_FLOOR_MS_PROP,
            if stripe_active {
                DEFAULT_STRIPE_RACK_REO_FLOOR_MS
            } else {
                0
            },
            0,
            60_000,
        );
        if is_circuit {
            let outbound_pool = match &cells {
                HubCells::Circuit(c) => c.outbound_pool_target,
                HubCells::Anon(_) => 1,
            };
            let ack_pool = match &cells {
                HubCells::Circuit(c) => c.ack_outbound_pool_target,
                HubCells::Anon(_) => 1,
            };
            let bulk_route_limit = match &cells {
                HubCells::Circuit(c) => c.bulk_route_active_limit,
                HubCells::Anon(_) => 0,
            };
            diag_node(
                &me,
                &format!(
                    "circuit cfg mss={mss} rwnd={recv_window} \
                 init_cwnd={init_cwnd}({init_cwnd_mss}mss) \
                 batch={max_pacing_batch} rto={init_rto_ms}/{min_rto_ms}/{max_rto_ms}ms \
                 max_retx={max_retransmits} outbound_pool={outbound_pool} ack_pool={ack_pool} \
                 bulk_route_active_limit={bulk_route_limit} \
                 loss_beta={loss_decrease_per_mille}/1000 bbr={bbr} \
                 rack={rack} rack_reo_floor={rack_reo_floor_ms}ms \
                 debug_summary={debug_summary_ms}ms",
                ),
            );
        }
        let cfg = Config {
            mss,
            init_rto_ms,
            min_rto_ms,
            max_rto_ms,
            handshake_rto_ms: 6_000,
            // On the pinned circuit path a no-ACK RTO usually means the
            // current stream/circuit went black-hole, not that a little more
            // exponential backoff will help. Fail fast and let the content layer
            // resume on a fresh stream instead of waiting ~2 minutes for its
            // payload-write idle timeout. The datagram path keeps the conservative
            // retry budget.
            max_retransmits,
            recv_window,
            init_cwnd,
            max_pacing_batch,
            rto_rewind_no_sack: is_circuit,
            loss_decrease_per_mille,
            bbr,
            // Every ACK consumes the same fixed-size circuit cell as DATA.
            // The pinned path is loss-free/in-order, so cumulative ACKs can be
            // thinned without delaying loss signalling: gaps and duplicates
            // still ACK immediately, and the timer bounds tail latency.
            ack_every: if is_circuit {
                // A little more ACK traffic buys faster loss signalling and keeps
                // SACK state fresh during relay-queue drops.
                16
            } else {
                2
            },
            ack_delay_ms: 5,
            debug_summary_ms,
            rack,
            rack_reo_floor_ms,
            ..Config::default()
        };
        let cells = Arc::new(cells);
        let mux = Arc::new(StreamMux::new(me, Arc::clone(&cells), in_rx, cfg));
        AnonStreamHub {
            mux,
            cells,
            _sender: sender,
        }
    }

    /// Open a stream to a peer (`dst` = its node id + stream-endpoint app id).
    pub fn open(&self, dst: Addr) -> OnionStream {
        self.mux.open(dst)
    }

    /// Accept the next inbound stream, or `None` if the transport closed.
    pub async fn accept(&self) -> Option<(OnionStream, Addr)> {
        self.mux.accept().await
    }

    /// Pre-warm the outbound circuit pool toward `dst_node` (no-op on the
    /// datagram backend). See `CircuitCells::warm_outbound` for why.
    pub async fn warm_outbound(&self, dst_node: [u8; 32]) {
        if let HubCells::Circuit(c) = self.cells.as_ref() {
            c.warm_outbound(dst_node).await;
        }
    }

    /// Warm the outbound circuit for a media channel to `peer`. Media reuses the
    /// reliable stream's rendezvous/pool (the hub already registers our inbound
    /// cookie and resolves the peer's ad), so this just kicks a background open
    /// of the shared bulk pool — no separate registration. No-op on the
    /// datagram fallback (media requires the embedded circuit backend).
    pub async fn media_open_channel(&self, peer: [u8; 32]) {
        if let HubCells::Circuit(c) = self.cells.as_ref() {
            c.ensure_outbound_opening(peer, RouteClass::Bulk).await;
        }
    }

    /// Send one lossy media datagram to `peer`. Returns `true` if it entered the
    /// first-hop TX queue, `false` if dropped (no route yet / stale route /
    /// `QueueFull` / datagram-fallback backend without a lossy path).
    pub async fn media_send_datagram(&self, peer: [u8; 32], payload: &[u8]) -> bool {
        if let HubCells::Circuit(c) = self.cells.as_ref() {
            c.send_datagram(peer, payload).await
        } else {
            false
        }
    }
}

/// Open the pinned inbound stream circuit, register this node's cookie, and spawn
/// the inbound feed that turns `[sender_node 32][cell]` return cells into
/// (Addr, cell). Published mode uses this node's advertised rendezvous R;
/// validation mode uses the old auto-agreed test-net R. `None` (→ datagram
/// fallback) if not embedded.
fn try_open_circuit(
    me: [u8; 32],
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    mode: CircuitMode,
) -> Option<CircuitCells> {
    // Only available with an in-process embedded node; else datagram path.
    //
    // Prefer the services published by the SAME node id as this IPC handle.
    // A single global services slot works for one embedded node, but two
    // identities in one host process otherwise race: whichever node published
    // last would drive every pinned circuit. The fallback keeps the old
    // single-node behavior for hosts that have not published keyed services.
    let services = veil_node_runtime::embedded_services_for(&me).or_else(|| {
        let latest = veil_node_runtime::embedded_services()?;
        (latest.local_node_id() == me).then_some(latest)
    })?;
    let cookie = stream_cookie(&me);
    let inbound_circuits: Arc<tokio::sync::Mutex<Vec<Arc<veil_node_runtime::DataCircuit>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let outbound_circuits = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let stream_routes = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let next_outbound_route = Arc::new(Mutex::new(HashMap::new()));
    let route_cooldowns = Arc::new(Mutex::new(HashMap::new()));
    let first_hop_cooldowns = Arc::new(Mutex::new(HashMap::new()));
    let outbound_opening = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let peer_tags: SharedPeerTags = Arc::new(Mutex::new(HashMap::new()));
    let outbound_peer_tags: SharedOutboundPeerTags = Arc::new(Mutex::new(HashMap::new()));
    let data_pace_interval = stream_data_pace_interval(true);
    let data_pacer = Arc::new(StreamDataPacer::new(data_pace_interval));
    let outbound_pool_target = env_or_android_usize(
        CIRCUIT_OUTBOUND_POOL_ENV,
        ANDROID_OUTBOUND_POOL_PROP,
        DEFAULT_CIRCUIT_OUTBOUND_POOL,
        1,
        MAX_CIRCUIT_OUTBOUND_POOL,
    );
    let ack_outbound_pool_target = env_or_android_usize(
        CIRCUIT_ACK_OUTBOUND_POOL_ENV,
        ANDROID_ACK_OUTBOUND_POOL_PROP,
        DEFAULT_CIRCUIT_ACK_OUTBOUND_POOL,
        1,
        MAX_CIRCUIT_OUTBOUND_POOL,
    )
    .min(outbound_pool_target);
    let ack_redundancy = env_or_android_usize(
        CIRCUIT_ACK_REDUNDANCY_ENV,
        ANDROID_ACK_REDUNDANCY_PROP,
        DEFAULT_CIRCUIT_ACK_REDUNDANCY,
        1,
        MAX_CIRCUIT_ACK_REDUNDANCY,
    );
    let bulk_route_active_limit = env_or_android_usize(
        CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT_ENV,
        ANDROID_BULK_ROUTE_ACTIVE_LIMIT_PROP,
        DEFAULT_CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT,
        0,
        MAX_CIRCUIT_BULK_ROUTE_ACTIVE_LIMIT,
    );
    let stripe_routes = env_or_android_usize(
        CIRCUIT_STRIPE_ROUTES_ENV,
        ANDROID_STRIPE_ROUTES_PROP,
        DEFAULT_CIRCUIT_STRIPE_ROUTES,
        1,
        MAX_CIRCUIT_OUTBOUND_POOL,
    )
    .min(outbound_pool_target);
    let activity = Arc::new(Mutex::new(Instant::now()));
    let inbound_activity = Arc::new(Mutex::new(Instant::now()));
    let reg_kp = Arc::new(services.onion_stream_registration_keypair());
    let epoch = Arc::new(AtomicU64::new(0));
    diag_node(
        &me,
        &format!(
            "circuit shared DATA pacer {}us outbound_pool={outbound_pool_target} ack_pool={ack_outbound_pool_target} ack_redundancy={ack_redundancy} bulk_route_active_limit={bulk_route_active_limit} stripe_routes={stripe_routes}",
            data_pace_interval.as_micros(),
        ),
    );
    // Open the circuit to R in the BACKGROUND (async relay-dir fetch + CircuitBuild
    // + ACK). Proactive (not lazy-on-send) so the RECEIVER is ready to take inbound
    // splices before it ever sends. Cells before it's up drop; the ARQ resends.
    //
    // Do NOT blindly rotate the pinned circuit by wall-clock time. Device traces
    // showed a 37 MB transfer running at ~1.7 MB/s until a timed refresh swapped
    // the rendezvous registration mid-stream; the sender kept pushing but the
    // receiver stopped advancing at ~54 %. Instead, refresh only after the whole
    // stream backend has been idle long enough that stale relay registrations are
    // more likely than in-flight cells.
    let circuit_slot = Arc::clone(&inbound_circuits);
    let services_bg = services.clone();
    let reg_kp_bg = Arc::clone(&reg_kp);
    let epoch_bg = Arc::clone(&epoch);
    let in_tx_bg = in_tx.clone();
    let activity_bg = Arc::clone(&activity);
    let inbound_activity_bg = Arc::clone(&inbound_activity);
    let peer_tags_bg = Arc::clone(&peer_tags);
    tokio::spawn(async move {
        // The proactive open fires at hub creation — which, on the RECEIVER, is the
        // accept loop starting right after node-arm, BEFORE any relay session is up
        // (observed on-device: connected=0 routing=3 -> NoRelays). warm only works
        // over connected relays, so RETRY with backoff until sessions establish and
        // a terminus R resolves. Cheap while connected=0 (the empty warm returns at
        // once); the loop ends on first success and the task dies with the runtime
        // on app exit, so an indefinite wait through a long pre-unlock idle is fine.
        let mut backoff_ms = 1_500u64;
        let mut attempt = 0u32;
        let mut generation = 0u64;
        // Consecutive short-pool early refreshes (see the unconfirmed-retry
        // gate in the poll loop below). Doubles the required generation age
        // per streak step so a relay that keeps failing confirmation can't
        // make the receiver storm re-register cycles; reset to 0 the moment
        // a cycle confirms its full relay set.
        let mut early_refresh_streak = 0u32;
        loop {
            attempt += 1;
            let opened =
                match open_inbound_circuits(&services_bg, me, cookie, &reg_kp_bg, &epoch_bg, mode)
                    .await
                {
                    Ok(opened) => opened,
                    Err(e) => {
                        if attempt == 1 || attempt % 15 == 0 {
                            diag_node(&me, &format!("circuit open retry #{attempt}: {e:?}"));
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = backoff_ms.saturating_mul(2).min(8_000);
                        continue;
                    }
                };

            let mut confirmed = Vec::with_capacity(opened.len());
            let mut confirmed_relays = Vec::with_capacity(opened.len());
            let mut unconfirmed_relay_count = 0usize;
            for (relay, candidate, recv_rx) in opened {
                // Inbound feed: legacy validation cells are `[sender_node 32][cell]`;
                // published cells are `[peer_tag 32][intro?][cell]`. Start it
                // BEFORE confirmation: it consumes cells arriving right after
                // the registration lands, and it recognises the loopback
                // splice-probe echo that confirms the path when the one-shot
                // CircuitBuilt ACK is lost (see confirm_circuit_with_probe).
                spawn_circuit_feed(
                    services_bg.clone(),
                    recv_rx,
                    in_tx_bg.clone(),
                    Some(Arc::clone(&activity_bg)),
                    Some(Arc::clone(&inbound_activity_bg)),
                    Arc::clone(&peer_tags_bg),
                    Some(candidate.confirmed_flag()),
                );
                // Circuit open is intentionally optimistic: it returns once
                // CircuitBuild is queued. Do not publish the handle until R has
                // accepted the cookie registration and either CircuitBuilt or a
                // loopback splice-probe echo came back.
                if !confirm_circuit_with_probe(&services_bg, &candidate, &cookie).await {
                    if let Some(relay) = relay {
                        diag_node(
                            &me,
                            &format!(
                                "inbound circuit confirmation timed out at R={} (no ACK, no probe echo) — keeping receive sink for grace",
                                short_node(&relay)
                            ),
                        );
                        unconfirmed_relay_count += 1;
                    }
                    // Even with probes, the registration can in principle be
                    // live with every echo lost. Keep the receive half alive
                    // for the normal retire grace so a late splice still lands;
                    // if the registration never landed, it stays idle and is
                    // cleaned up later.
                    retire_circuits_later(&services_bg, vec![Arc::new(candidate)]);
                    continue;
                }
                if let Some(relay) = relay {
                    services_bg.publish_stream_rendezvous_ad(relay, cookie);
                    confirmed_relays.push(relay);
                }
                confirmed.push(Arc::new(candidate));
            }

            if confirmed.is_empty() {
                if attempt == 1 || attempt % 15 == 0 {
                    diag_node(
                        &me,
                        &format!("circuit confirmation timed out on attempt #{attempt}"),
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2).min(8_000);
                continue;
            }

            let retired = {
                // MERGE the freshly confirmed circuits into the slot instead of
                // replacing it wholesale (device-verified 2026-07-06): on a
                // lossy WAN one refresh cycle often confirms only a SUBSET of
                // the pool target (1 of 3 was typical against the production
                // seeds). A blind replace then DROPPED still-live confirmed
                // registrations, so the receiver's reachable relay set jumped
                // around every cycle (R=[c92]→R=[3d]→…) and a sender's
                // circuit pool never kept a stable route — mid-transfer
                // resets plus relay cooldowns chasing a moving target.
                // Replace only the entries whose terminus relay was
                // re-confirmed THIS cycle; keep the others (a truly dead
                // registration expires at its terminus by registry TTL, and
                // the next refresh cycle retries the missing relays anyway).
                let confirmed_termini: std::collections::HashSet<[u8; 32]> = confirmed
                    .iter()
                    .filter_map(|c| c.relay_path().last().copied())
                    .collect();
                let mut slot = circuit_slot.lock().await;
                let mut retired: Vec<Arc<veil_node_runtime::DataCircuit>> = Vec::new();
                let mut next: Vec<Arc<veil_node_runtime::DataCircuit>> = Vec::new();
                for old in slot.drain(..) {
                    if old
                        .relay_path()
                        .last()
                        .is_some_and(|r| confirmed_termini.contains(r))
                    {
                        retired.push(old);
                    } else {
                        next.push(old);
                    }
                }
                next.extend(confirmed);
                *slot = next;
                retired
            };
            let generation_opened_at = Instant::now();
            generation += 1;
            backoff_ms = 1_500;
            if unconfirmed_relay_count == 0 {
                early_refresh_streak = 0;
            }
            let relay_suffix = if confirmed_relays.is_empty() {
                String::new()
            } else {
                format!(
                    " R=[{}]",
                    confirmed_relays
                        .iter()
                        .map(short_node)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            if generation == 1 {
                diag_node(
                    &me,
                    &format!(
                        "PINNED CIRCUIT opened ({mode:?}, {} registration(s), after {attempt} tries){relay_suffix}",
                        circuit_slot.lock().await.len()
                    ),
                );
            } else {
                diag_node(
                    &me,
                    &format!(
                        "PINNED CIRCUIT refreshed ({mode:?}, {} registration(s), generation {generation}){relay_suffix}",
                        circuit_slot.lock().await.len()
                    ),
                );
            }

            retire_circuits_later(&services_bg, retired);

            let mut last_heartbeat = Instant::now();
            loop {
                tokio::time::sleep(CIRCUIT_REFRESH_POLL).await;
                let now = Instant::now();
                // Keepalive: send a forward heartbeat UP each confirmed inbound
                // circuit so its first-hop TCP session (and every hop's socket
                // along the path) stays warm. Without it an idle receiver's
                // socket dies and the relay's downstream introduce push queues
                // behind a dead TCP until the receiver next transmits — the
                // on-device delivery stalls. Snapshot the Arcs so the (sync)
                // sends don't hold the slot lock; a QueueFull/NoRelays here is
                // harmless (the next tick retries, and a truly dead circuit is
                // rotated by the idle-refresh below).
                if now.saturating_duration_since(last_heartbeat) >= CIRCUIT_HEARTBEAT_INTERVAL {
                    last_heartbeat = now;
                    let circs: Vec<Arc<veil_node_runtime::DataCircuit>> =
                        circuit_slot.lock().await.iter().cloned().collect();
                    for circ in &circs {
                        let _ = services_bg.send_circuit_cell(
                            circ,
                            veil_anonymity::circuit_data::CIRCUIT_HEARTBEAT_MAGIC,
                        );
                    }
                }
                let generation_age = now.saturating_duration_since(generation_opened_at);
                let idle_for = circuit_idle_for(&activity_bg);
                if mode == CircuitMode::PublishedRendezvous {
                    let have = circuit_slot.lock().await.len();
                    let want = services_bg.local_published_rendezvous_relays().len();
                    if want > have
                        && generation_age >= CIRCUIT_PUBLISHED_RELAY_EXPAND_AFTER
                        && idle_for >= CIRCUIT_PUBLISHED_RELAY_EXPAND_AFTER
                    {
                        diag_node(
                            &me,
                            &format!(
                                "published rendezvous set expanded {have}->{want} — refreshing inbound circuits"
                            ),
                        );
                        break;
                    }
                }
                // A relay that failed confirmation outright (no ACK, no probe
                // echo) has no live binding from this cycle; its previous
                // binding survives at most the registry TTL while its ad stays
                // published. Re-run the register cycle early. Deliberately NOT
                // gated on idle: a short pool is exactly what makes transfers
                // crawl, and retrying transfers keep the circuit busy — an
                // idle gate here was a livelock (pool sat at 1/3 for tens of
                // minutes under load, device-observed 2026-07-06). Rotation is
                // safe mid-transfer because the refresh cycle MERGES: still-
                // live confirmed circuits stay in the slot and every feed
                // lands in the same in_tx. Anti-storm: the required age
                // doubles per consecutive early refresh (30s → 60s → 120s →
                // 240s, capped by the 300s idle-refresh ceiling) and resets
                // once a cycle confirms the full set.
                let unconfirmed_retry_after = CIRCUIT_UNCONFIRMED_RETRY_AFTER
                    .saturating_mul(1u32 << early_refresh_streak.min(4))
                    .min(CIRCUIT_IDLE_REFRESH_AFTER);
                if unconfirmed_relay_count > 0 && generation_age >= unconfirmed_retry_after {
                    early_refresh_streak = early_refresh_streak.saturating_add(1);
                    diag_node(
                        &me,
                        &format!(
                            "{unconfirmed_relay_count} relay registration(s) unconfirmed — early refresh to re-register (streak {early_refresh_streak}, next after {}s)",
                            unconfirmed_retry_after.as_secs()
                        ),
                    );
                    break;
                }
                // Inbound starvation: we are actively sending stream cells
                // (idle_for is fresh — and sends are what keep it fresh) yet
                // NOTHING has been received hub-wide for the whole starvation
                // window. The relay→us return legs are dead even though every
                // registration is "confirmed", and the idle-refresh below can
                // never fire because our own retries keep resetting idle_for
                // (bench-reproduced 2026-07-06 after a long netem window; the
                // live 14:00 incident needed manual client restarts for
                // exactly this state). Rebuild + re-register the generation.
                let inbound_idle = circuit_idle_for(&inbound_activity_bg);
                if generation_age >= CIRCUIT_INBOUND_STARVATION_AFTER
                    && inbound_idle >= CIRCUIT_INBOUND_STARVATION_AFTER
                    && idle_for < CIRCUIT_INBOUND_STARVATION_SEND_RECENT
                {
                    diag_node(
                        &me,
                        &format!(
                            "inbound starvation: sending (last send/recv {}s ago) but nothing received for {}s — rebuilding inbound circuits",
                            idle_for.as_secs(),
                            inbound_idle.as_secs()
                        ),
                    );
                    break;
                }
                if generation_age >= CIRCUIT_IDLE_REFRESH_AFTER
                    && idle_for >= CIRCUIT_IDLE_REFRESH_AFTER
                {
                    diag_node(
                        &me,
                        &format!(
                            "inbound circuit idle for {}s — refreshing",
                            idle_for.as_secs()
                        ),
                    );
                    break;
                }
            }
        }
    });
    Some(CircuitCells {
        services,
        me,
        mode,
        reg_kp,
        epoch,
        in_tx,
        activity,
        inbound_activity,
        inbound_circuits,
        outbound_circuits,
        stream_routes,
        next_outbound_route,
        route_cooldowns,
        first_hop_cooldowns,
        bulk_shed_marks: Arc::new(Mutex::new(HashMap::new())),
        outbound_opening,
        data_pacer,
        outbound_pool_target,
        ack_outbound_pool_target,
        ack_redundancy,
        ack_dup_sent: Arc::new(AtomicU64::new(0)),
        bulk_route_active_limit,
        stripe_routes,
        stripe_rr: Arc::new(AtomicU64::new(0)),
        peer_tags,
        outbound_peer_tags,
    })
}

type OpenedInboundCircuit = (
    Option<[u8; 32]>,
    veil_node_runtime::DataCircuit,
    mpsc::Receiver<Vec<u8>>,
);

async fn open_inbound_circuits(
    services: &veil_node_runtime::NodeServices,
    me: [u8; 32],
    cookie: [u8; COOKIE_LEN],
    reg_kp: &veil_crypto::GeneratedKeyPair,
    epoch: &AtomicU64,
    mode: CircuitMode,
) -> Result<Vec<OpenedInboundCircuit>, veil_types::AnonOnionSendError> {
    use veil_types::AnonOnionSendError;

    match mode {
        CircuitMode::ValidationMinRouting => services
            .open_stream_circuit_auto(cookie, reg_kp, epoch)
            .await
            .map(|(circuit, rx)| vec![(None, circuit, rx)]),
        CircuitMode::PublishedRendezvous => {
            let mut relays = services.local_published_rendezvous_relays();
            for relay in services.pinned_rendezvous_relays() {
                if !relays.contains(&relay) {
                    relays.push(relay);
                }
            }
            if let Ok(resolved) = services.resolve_stream_rendezvous_relays(me).await {
                for relay in resolved {
                    if !relays.contains(&relay) {
                        relays.push(relay);
                    }
                }
            }
            if relays.is_empty() {
                return Err(AnonOnionSendError::NoRendezvous);
            }

            let mut opened = Vec::with_capacity(relays.len());
            let mut last_err = AnonOnionSendError::NoRelays;
            for relay in relays {
                match services
                    .open_stream_circuit_to_rendezvous_relay(
                        relay,
                        cookie,
                        reg_kp,
                        epoch,
                        CIRCUIT_HOPS,
                    )
                    .await
                {
                    Ok((circuit, rx)) => opened.push((Some(relay), circuit, rx)),
                    Err(e) => {
                        last_err = e;
                        diag_node(
                            &me,
                            &format!(
                                "inbound published R={} open failed: {last_err:?}",
                                short_node(&relay)
                            ),
                        );
                    }
                }
            }
            if opened.is_empty() {
                Err(last_err)
            } else {
                Ok(opened)
            }
        }
    }
}

async fn open_outbound_circuit(
    services: veil_node_runtime::NodeServices,
    dst_node: [u8; 32],
    me: [u8; 32],
    reg_kp: Arc<veil_crypto::GeneratedKeyPair>,
    epoch: Arc<AtomicU64>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    activity: Arc<Mutex<Instant>>,
    inbound_activity: Arc<Mutex<Instant>>,
    outbound_circuits: Arc<tokio::sync::Mutex<OutboundCircuitPool>>,
    peer_tags: SharedPeerTags,
    outbound_peer_tags: SharedOutboundPeerTags,
    route_cooldowns: RouteCooldowns,
    first_hop_cooldowns: FirstHopCooldowns,
    pool_target: usize,
) -> Result<(), String> {
    let desired_pool_target = pool_target.clamp(1, MAX_CIRCUIT_OUTBOUND_POOL);
    let mut ads = services
        .resolve_stream_rendezvous_ads(dst_node)
        .await
        .map_err(|e| format!("resolve receiver ads: {e:?}"))?;
    let expected_stream_cookie = stream_cookie(&dst_node);
    let resolved_ads = ads.len();
    let receiver_ads = ads.clone();
    let stream_ads = ads
        .iter()
        .filter(|ad| ad.auth_cookie == expected_stream_cookie)
        .cloned()
        .collect::<Vec<_>>();
    let using_stream_cookie_ads = !stream_ads.is_empty();
    if using_stream_cookie_ads {
        let mut selected = stream_ads;
        let stream_cookie_ad_count = selected.len();
        let mut seen_relays = selected
            .iter()
            .map(|ad| ad.rendezvous_node_id)
            .collect::<HashSet<_>>();
        if selected.len() < desired_pool_target {
            for ad in receiver_ads {
                if selected.len() >= desired_pool_target {
                    break;
                }
                if seen_relays.insert(ad.rendezvous_node_id) {
                    selected.push(ad);
                }
            }
            diag_node(
                &me,
                &format!(
                    "outbound stream rendezvous supplement for {}: stream-cookie ads underfilled {}/{}; selected {} receiver ad(s)",
                    short_node(&dst_node),
                    stream_cookie_ad_count,
                    desired_pool_target,
                    selected.len()
                ),
            );
        }
        ads = selected;
    } else {
        // The circuit DATA envelope below is still addressed to
        // `stream_cookie(dst)`. The rendezvous ad is used to learn the receiver's
        // current R + X25519 intro key. In practice the normal mailbox ad can be
        // fresher/visible before the stream-cookie ad lands (or the stream ad can
        // be overwritten in the shared rendezvous slots), while the receiver has
        // already registered the stream cookie at the same pinned R. Do not fail
        // the whole bulk stream at open time; prefer matching stream ads when
        // present, otherwise fall back to the freshest receiver ads and let the
        // R-splice/ARQ prove whether that R owns the stream cookie.
        diag_node(
            &me,
            &format!(
                "outbound stream rendezvous fallback for {}: no ad cookie={} among {} ad(s); using receiver ads",
                short_node(&dst_node),
                short_cookie(&expected_stream_cookie),
                resolved_ads,
            ),
        );
    }
    let freshest_stream_valid_from = ads
        .iter()
        .map(|ad| ad.valid_from_unix)
        .max()
        .unwrap_or_default();
    let before_fresh_filter = ads.len();
    // Stream rendezvous ads are published one relay at a time, so their
    // valid_from timestamps can legitimately differ by a few seconds on a cold
    // phone or during refresh. A tiny skew window can reduce an otherwise
    // healthy outbound pool from 3/3 to 2/3 before we even attempt the third
    // route. Keep the stale-ad filter, but allow modest publication skew; older
    // receive circuits are retained for CIRCUIT_RETIRE_GRACE to protect
    // in-flight streams.
    let fresh_ads = ads
        .iter()
        .filter(|ad| {
            ad.valid_from_unix
                .saturating_add(STREAM_RENDEZVOUS_AD_FRESH_GRACE_SECS)
                >= freshest_stream_valid_from
        })
        .cloned()
        .collect::<Vec<_>>();
    let fresh_count = fresh_ads.len();
    if fresh_count >= desired_pool_target || fresh_count == 0 {
        ads = fresh_ads;
    } else {
        // A quick app restart can publish one fresh stream-cookie ad while the
        // other rendezvous relays still expose older-but-valid ads. The inbound
        // side deliberately keeps retired receive circuits alive for
        // CIRCUIT_RETIRE_GRACE, so falling back to those older ads is safer than
        // failing the whole pool open and resetting all range workers.
        diag_node(
            &me,
            &format!(
                "outbound stream rendezvous fresh filter underfilled for {} ({}/{}); retaining older valid ads",
                short_node(&dst_node),
                fresh_count,
                desired_pool_target
            ),
        );
    }
    diag_node(
        &me,
        &format!(
            "outbound stream rendezvous filter for {} cookie={} matched={} ads {}->{} fresh={}->{} max_valid_from={}",
            short_node(&dst_node),
            short_cookie(&expected_stream_cookie),
            using_stream_cookie_ads,
            resolved_ads,
            before_fresh_filter,
            before_fresh_filter,
            fresh_count,
            freshest_stream_valid_from,
        ),
    );
    let preferred = preferred_rendezvous_prefixes();
    if !preferred.is_empty() {
        let before = ads
            .iter()
            .map(|ad| short_node(&ad.rendezvous_node_id))
            .collect::<Vec<_>>()
            .join(",");
        let mut indexed = ads.into_iter().enumerate().collect::<Vec<_>>();
        indexed.sort_by_key(|(index, ad)| {
            (
                rendezvous_preference_rank(&ad.rendezvous_node_id, &preferred),
                *index,
            )
        });
        ads = indexed.into_iter().map(|(_, ad)| ad).collect();
        let after = ads
            .iter()
            .map(|ad| short_node(&ad.rendezvous_node_id))
            .collect::<Vec<_>>()
            .join(",");
        diag_node(
            &me,
            &format!(
                "outbound rendezvous preference for {} prefixes={} order {} -> {}",
                short_node(&dst_node),
                preferred.join(","),
                before,
                after
            ),
        );
    }

    let before_rank = ads
        .iter()
        .map(|ad| {
            format!(
                "{}:{}/{}",
                short_node(&ad.rendezvous_node_id),
                ad.valid_from_unix,
                ad.valid_until_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut indexed = ads.into_iter().enumerate().collect::<Vec<_>>();
    indexed.sort_by(|(left_index, left), (right_index, right)| {
        rendezvous_preference_rank(&left.rendezvous_node_id, &preferred)
            .cmp(&rendezvous_preference_rank(
                &right.rendezvous_node_id,
                &preferred,
            ))
            .then_with(|| {
                rendezvous_default_stand_rank(&left.rendezvous_node_id)
                    .cmp(&rendezvous_default_stand_rank(&right.rendezvous_node_id))
            })
            .then_with(|| left.rendezvous_node_id.cmp(&right.rendezvous_node_id))
            .then_with(|| left_index.cmp(right_index))
    });
    let mut ranked_ads = indexed.into_iter().map(|(_, ad)| ad).collect::<Vec<_>>();
    let after_rank = ranked_ads
        .iter()
        .map(|ad| {
            format!(
                "{}:{}/{}",
                short_node(&ad.rendezvous_node_id),
                ad.valid_from_unix,
                ad.valid_until_unix
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    diag_node(
        &me,
        &format!(
            "outbound rendezvous rank for {} order {} -> {}",
            short_node(&dst_node),
            before_rank,
            after_rank
        ),
    );

    let before_dedup = ranked_ads.len();
    let mut seen_relays = HashSet::new();
    ranked_ads.retain(|ad| seen_relays.insert(ad.rendezvous_node_id));
    if ranked_ads.is_empty() {
        return Err("open to receiver ad: no unique receiver rendezvous ad".to_string());
    }
    if before_dedup != ranked_ads.len() {
        diag_node(
            &me,
            &format!(
                "outbound rendezvous dedup for {} ads {}->{}",
                short_node(&dst_node),
                before_dedup,
                ranked_ads.len()
            ),
        );
    }
    let before_cooldown = ranked_ads.len();
    let cooldown_now = Instant::now();
    let cooled_relays = {
        let mut cooldowns = route_cooldowns.lock().unwrap_or_else(|p| p.into_inner());
        cooldowns.retain(|_, until| *until > cooldown_now);
        cooldowns.clone()
    };
    let cooled_first_hops = {
        let mut cooldowns = first_hop_cooldowns
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        cooldowns.retain(|_, until| *until > cooldown_now);
        cooldowns.clone()
    };
    let uncooled_ads = ranked_ads
        .iter()
        .filter(|ad| {
            cooled_relays
                .get(&ad.rendezvous_node_id)
                .is_none_or(|until| *until <= cooldown_now)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !uncooled_ads.is_empty() {
        ranked_ads = uncooled_ads;
    }
    if before_cooldown != ranked_ads.len() {
        diag_node(
            &me,
            &format!(
                "outbound rendezvous cooldown filter for {} ads {}->{}",
                short_node(&dst_node),
                before_cooldown,
                ranked_ads.len()
            ),
        );
    }
    let pool_target = desired_pool_target;
    if pool_target > 1 && ranked_ads.len() < pool_target {
        diag_node(
            &me,
            &format!(
                "outbound circuit pool degraded for {}: usable rendezvous ads {}/{pool_target}",
                short_node(&dst_node),
                ranked_ads.len(),
            ),
        );
    }
    let mut last_err = "no receiver rendezvous ad opened".to_string();
    let mut opened_entries = Vec::new();
    let peer_tag = outbound_peer_tag(&outbound_peer_tags, dst_node);
    for ad in ranked_ads {
        if opened_entries.len() >= pool_target {
            break;
        }
        let started = Instant::now();
        let (candidate, recv_rx) = match services
            .open_stream_circuit_to_rendezvous_relay(
                ad.rendezvous_node_id,
                stream_cookie(&me),
                &reg_kp,
                &epoch,
                CIRCUIT_HOPS,
            )
            .await
        {
            Ok(opened) => opened,
            Err(e) => {
                last_err = format!(
                    "R={} open failed after {}ms: {e:?}",
                    short_node(&ad.rendezvous_node_id),
                    started.elapsed().as_millis()
                );
                mark_rendezvous_cooldown(
                    &route_cooldowns,
                    ad.rendezvous_node_id,
                    CIRCUIT_ROUTE_SEND_COOLDOWN,
                );
                diag_node(&me, &format!("outbound {last_err}"));
                continue;
            }
        };

        // Start the return-cell feed immediately: it consumes early peer cells
        // AND recognises the loopback splice-probe echo used below — the open
        // above registered OUR cookie at this relay, so a probe up this
        // candidate echoes back down it exactly as on the inbound side.
        spawn_circuit_feed(
            services.clone(),
            recv_rx,
            in_tx.clone(),
            Some(Arc::clone(&activity)),
            Some(Arc::clone(&inbound_activity)),
            Arc::clone(&peer_tags),
            Some(candidate.confirmed_flag()),
        );
        if !confirm_circuit_with_probe(&services, &candidate, &stream_cookie(&me)).await {
            last_err = format!(
                "R={} confirmation timed out after {}ms (no ACK, no probe echo)",
                short_node(&ad.rendezvous_node_id),
                started.elapsed().as_millis()
            );
            mark_rendezvous_cooldown(
                &route_cooldowns,
                ad.rendezvous_node_id,
                CIRCUIT_ROUTE_SEND_COOLDOWN,
            );
            diag_node(&me, &format!("outbound {last_err}"));
            // Even with probes the registration can be live with every echo
            // lost; the feed above keeps receiving for the retire grace while
            // a later open picks a confirmed send path.
            retire_circuits_later(&services, vec![Arc::new(candidate)]);
            continue;
        }

        let candidate = Arc::new(candidate);
        let now = Instant::now();
        let first_hop = candidate.first_hop();
        if !services.has_live_session(&first_hop) {
            last_err = format!(
                "R={} path={} first-hop {} not live after confirm",
                short_node(&ad.rendezvous_node_id),
                short_path(candidate.relay_path()),
                short_node(&first_hop)
            );
            mark_first_hop_cooldown(&first_hop_cooldowns, first_hop, CIRCUIT_ROUTE_SEND_COOLDOWN);
            diag_node(&me, &format!("outbound {last_err}"));
            retire_circuits_later(&services, vec![candidate]);
            continue;
        }
        if cooled_first_hops
            .get(&first_hop)
            .is_some_and(|until| *until > now)
        {
            last_err = format!(
                "R={} path={} first-hop {} cooled",
                short_node(&ad.rendezvous_node_id),
                short_path(candidate.relay_path()),
                short_node(&first_hop)
            );
            diag_node(&me, &format!("outbound {last_err}"));
            retire_circuits_later(&services, vec![candidate]);
            continue;
        }
        if opened_entries
            .iter()
            .any(|entry: &CircuitEntry| entry.circuit.first_hop() == first_hop)
        {
            diag_node(
                &me,
                &format!(
                    "outbound R={} path={} duplicate first-hop {} — keeping as standby",
                    short_node(&ad.rendezvous_node_id),
                    short_path(candidate.relay_path()),
                    short_node(&first_hop)
                ),
            );
        }

        opened_entries.push(CircuitEntry {
            circuit: Arc::clone(&candidate),
            rendezvous_node: ad.rendezvous_node_id,
            first_hop_close_generation: services.session_close_generation(&first_hop),
            peer_tag,
            receiver_x25519_pk: ad.receiver_x25519_pk,
            opened_at: now,
            last_used: now,
            last_non_handshake: now,
            handshake_streams: HashSet::new(),
            stats: Arc::new(CircuitRouteStats::new(now)),
        });
        mark_circuit_activity(&activity);
        diag_node(
            &me,
            &format!(
                "outbound circuit ready for {} via R={} path={} open_confirm={}ms",
                short_node(&dst_node),
                short_node(&ad.rendezvous_node_id),
                short_path(candidate.relay_path()),
                started.elapsed().as_millis()
            ),
        );
    }
    if opened_entries.is_empty() {
        return Err(format!("open to receiver ad: {last_err}"));
    }
    let opened_count = opened_entries.len();
    // MAKE-BEFORE-BREAK refill (device-verified churn root, 2026-07-07): this
    // refill used to full-REPLACE the pool, retiring every prior circuit. Fired
    // by the 5 s degraded-pool poll while the pool sits at 2/3 usable ads, it
    // retired the very circuit an in-flight manifest fetch was waiting on — the
    // puller timed out (8 s), retried, re-tripped the poll, and a fresh (often
    // COLD, ~10 s full handshake) reopen churned every ~15 s. That kept
    // desktop<->phone transfers stuck at 0% for ~70 s while a small file could
    // slip between reopen cycles. Preserve prior circuits that carry a live
    // stream (active_streams>0, the signal already trusted at the handshake
    // teardown) or were just built (opened_at within the confirm window; unlike
    // last_used, opened_at is not bumped by handshake retries, so a genuinely
    // old dead route is still retired). Dedup against freshly-opened first-hops
    // and cap the pool so it cannot grow unbounded.
    let opened_first_hops: HashSet<[u8; 32]> = opened_entries
        .iter()
        .map(|entry| entry.circuit.first_hop())
        .collect();
    let merge_now = Instant::now();
    let mut pool = outbound_circuits.lock().await;
    let prior = pool.remove(&dst_node).unwrap_or_default();
    let mut retired: Vec<Arc<veil_node_runtime::DataCircuit>> = Vec::new();
    let mut merged = opened_entries;
    for entry in prior {
        let busy = entry.stats.active_streams() > 0;
        let fresh = merge_now.duration_since(entry.opened_at) < CIRCUIT_CONFIRM_TIMEOUT;
        let dup = opened_first_hops.contains(&entry.circuit.first_hop());
        if (busy || fresh) && !dup && merged.len() < MAX_CIRCUIT_OUTBOUND_POOL {
            merged.push(entry);
        } else {
            retired.push(entry.circuit);
        }
    }
    let kept_in_flight = merged.len().saturating_sub(opened_count);
    pool.insert(dst_node, merged);
    drop(pool);
    retire_circuits_later(&services, retired);
    diag_node(
        &me,
        &format!(
            "outbound circuit pool ready for {} routes={opened_count}/{pool_target} (kept {kept_in_flight} in-flight)",
            short_node(&dst_node),
        ),
    );
    Ok(())
}

async fn confirm_circuit(circuit: &veil_node_runtime::DataCircuit) -> bool {
    let confirm_deadline = tokio::time::Instant::now() + CIRCUIT_CONFIRM_TIMEOUT;
    while !circuit.is_confirmed() && tokio::time::Instant::now() < confirm_deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    circuit.is_confirmed()
}

/// Like [`confirm_circuit`], but for a circuit that carries a cookie
/// registration: while waiting for the `CircuitBuilt` ACK, periodically send a
/// loopback splice probe `[own_cookie ‖ PROBE_MAGIC]` UP the candidate. The
/// terminus binds the cookie BEFORE it emits the ACK, and the ACK is a single
/// unacknowledged return frame — on a lossy WAN it is lost regularly while the
/// binding is LIVE. Timing out on the flag alone then retires the only circuit
/// the relay will splice to (the fresher registration epoch already displaced
/// the previous binding), blackholing that relay until a later cycle
/// re-confirms — device-observed as `origin_stream ok:0 missing:N` on the
/// server plus pullers dying at `waiting manifest`. If the binding landed, the
/// terminus splices the probe back DOWN this very circuit and the feed sets the
/// same confirmed flag: a retryable, end-to-end proof over the exact splice
/// path senders use, with no relay-side changes. No ACK *and* no echo within
/// the window means the registration really is absent — retiring is correct.
async fn confirm_circuit_with_probe(
    services: &veil_node_runtime::NodeServices,
    circuit: &veil_node_runtime::DataCircuit,
    cookie: &[u8; COOKIE_LEN],
) -> bool {
    let started = tokio::time::Instant::now();
    let confirm_deadline = started + CIRCUIT_CONFIRM_TIMEOUT;
    let mut next_probe = started + CIRCUIT_CONFIRM_PROBE_INITIAL_DELAY;
    let mut probe =
        Vec::with_capacity(COOKIE_LEN + veil_anonymity::circuit_data::CIRCUIT_PROBE_MAGIC.len());
    probe.extend_from_slice(cookie);
    probe.extend_from_slice(veil_anonymity::circuit_data::CIRCUIT_PROBE_MAGIC);
    while !circuit.is_confirmed() && tokio::time::Instant::now() < confirm_deadline {
        if tokio::time::Instant::now() >= next_probe {
            // QueueFull/NoRelays are fine — the next tick simply re-probes.
            let _ = services.send_circuit_cell(circuit, &probe);
            next_probe += CIRCUIT_CONFIRM_PROBE_INTERVAL;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    circuit.is_confirmed()
}

fn spawn_circuit_feed(
    services: veil_node_runtime::NodeServices,
    mut recv_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<(Addr, Vec<u8>)>,
    activity: Option<Arc<Mutex<Instant>>>,
    inbound_activity: Option<Arc<Mutex<Instant>>>,
    peer_tags: SharedPeerTags,
    confirmed: Option<Arc<std::sync::atomic::AtomicBool>>,
) {
    tokio::spawn(async move {
        // Drain inbound bursts: the relay splice delivers many cells per
        // scheduler turn, and one activity stamp per batch is enough.
        let mut batch: Vec<Vec<u8>> = Vec::new();
        'feed: loop {
            batch.clear();
            if recv_rx.recv_many(&mut batch, 256).await == 0 {
                break;
            }
            if let Some(activity) = activity.as_ref() {
                mark_circuit_activity(activity);
            }
            // RECEIVE-only stamp for the inbound-starvation detector: sends
            // also move `activity`, so it can't distinguish "network answers
            // us" from "we keep shouting into a void".
            if let Some(inbound) = inbound_activity.as_ref() {
                mark_circuit_activity(inbound);
            }
            for framed in batch.drain(..) {
                if veil_anonymity::circuit_data::is_probe_echo(&framed) {
                    // Loopback splice-probe echo: the terminus binding is
                    // proven live end-to-end — confirm the circuit and swallow
                    // the cell (it carries no data).
                    if let Some(flag) = confirmed.as_ref() {
                        flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    continue;
                }
                if framed.len() < CIRCUIT_PEER_TAG_LEN {
                    continue;
                }
                let mut tag = [0u8; CIRCUIT_PEER_TAG_LEN];
                tag.copy_from_slice(&framed[..CIRCUIT_PEER_TAG_LEN]);
                let mut cell_offset = CIRCUIT_PEER_TAG_LEN;
                let node = if framed.get(cell_offset) == Some(&CIRCUIT_INTRO_MARKER) {
                    if framed.len() < cell_offset + 1 + CIRCUIT_INTRO_LEN {
                        continue;
                    }
                    let sealed = &framed[cell_offset + 1..cell_offset + 1 + CIRCUIT_INTRO_LEN];
                    let Some(node) = open_stream_peer_intro(&services, &tag, sealed) else {
                        continue;
                    };
                    {
                        let mut tags = peer_tags.lock().unwrap_or_else(|p| p.into_inner());
                        if tags.len() >= 4096 && !tags.contains_key(&tag) {
                            tags.clear();
                        }
                        tags.insert(tag, node);
                    }
                    cell_offset += 1 + CIRCUIT_INTRO_LEN;
                    node
                } else if let Some(node) = peer_tags
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&tag)
                    .copied()
                {
                    node
                } else {
                    // Backward-compatible validation/legacy path: the first 32 bytes
                    // are the clear sender node id rather than an opaque tag.
                    tag
                };
                if framed.len() <= cell_offset {
                    continue;
                }
                // Lossy MEDIA datagram? A leading MEDIA_MAGIC (distinct from the
                // stream `PROTO_VER`) means this cell bypasses the reliable
                // demux: peel the magic and hand the payload to the media recv
                // sink, then skip the stream path entirely. Stream and media
                // coexist on one circuit, cleanly split by this first byte.
                if framed.get(cell_offset) == Some(&crate::media::MEDIA_MAGIC) {
                    crate::media::dispatch_inbound(node, &framed[cell_offset + 1..]);
                    continue;
                }
                let app = veil_app::address::app_id(&node, STREAM_NAMESPACE, STREAM_NAME);
                let cell = framed[cell_offset..].to_vec();
                if in_tx.send((Addr { node, app }, cell)).await.is_err() {
                    break 'feed;
                }
            }
        }
    });
}

fn mark_circuit_activity(activity: &Arc<Mutex<Instant>>) {
    *activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
}

fn circuit_idle_for(activity: &Arc<Mutex<Instant>>) -> Duration {
    Instant::now().duration_since(*activity.lock().unwrap_or_else(|p| p.into_inner()))
}

fn short_node(node: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &node[..4] {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn short_path(path: &[[u8; 32]]) -> String {
    if path.is_empty() {
        return "-".to_string();
    }
    path.iter().map(short_node).collect::<Vec<_>>().join(">")
}

fn mark_rendezvous_cooldown(route_cooldowns: &RouteCooldowns, relay: [u8; 32], duration: Duration) {
    route_cooldowns
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(relay, Instant::now() + duration);
}

fn mark_first_hop_cooldown(
    first_hop_cooldowns: &FirstHopCooldowns,
    first_hop: [u8; 32],
    duration: Duration,
) {
    first_hop_cooldowns
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(first_hop, Instant::now() + duration);
}

fn retire_circuits_later(
    services: &veil_node_runtime::NodeServices,
    circuits: Vec<Arc<veil_node_runtime::DataCircuit>>,
) {
    for old in circuits {
        let old_id = old.origin_circuit_id();
        let retire_services = services.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CIRCUIT_RETIRE_GRACE).await;
            retire_services.close_data_circuit(old_id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CIRCUIT_INTRO_LEN, CIRCUIT_MSS, CIRCUIT_PEER_TAG_LEN, CircuitMode, circuit_env_value_mode,
        parse_stream_peer_intro_plaintext, stream_peer_intro_plaintext,
    };
    use veil_anonymity::circuit_register::COOKIE_LEN;
    use veil_onion_stream::wire::{DATA_OVERHEAD, Frame, MAX_CELL};

    #[test]
    fn circuit_env_is_strict_opt_in() {
        for value in [
            "1",
            "true",
            "TRUE",
            " yes ",
            "On",
            "published",
            "prod",
            "production",
        ] {
            assert_eq!(
                circuit_env_value_mode(value),
                Some(CircuitMode::PublishedRendezvous),
                "{value:?} should opt into published-rendezvous circuit mode"
            );
        }
        for value in ["validation", "legacy", "min-routing", "min_routing"] {
            assert_eq!(
                circuit_env_value_mode(value),
                Some(CircuitMode::ValidationMinRouting),
                "{value:?} should opt into validation circuit mode"
            );
        }
        for value in ["", "0", "false", "no", "off", "anything-else"] {
            assert!(
                circuit_env_value_mode(value).is_none(),
                "{value:?} should leave circuit mode off"
            );
        }
    }

    #[test]
    fn protected_circuit_envelopes_fit_one_cell_without_reducing_data_mss() {
        let payload = [0xABu8; CIRCUIT_MSS];
        let data = Frame::Data {
            stream_id: 7,
            seq: 0,
            win: 1024,
            payload: &payload,
        }
        .encode();
        assert_eq!(
            COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + data.len(),
            MAX_CELL,
            "protected DATA must still exactly fill one CircuitData inner cell"
        );
        assert_eq!(
            CIRCUIT_MSS,
            MAX_CELL - COOKIE_LEN - CIRCUIT_PEER_TAG_LEN - DATA_OVERHEAD
        );

        let syn = Frame::Syn {
            stream_id: 7,
            isn: 11,
            win: 4096,
        }
        .encode();
        let syn_ack = Frame::SynAck {
            stream_id: 7,
            isn: 13,
            win: 4096,
            ack: 11,
        }
        .encode();
        assert!(COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + 1 + CIRCUIT_INTRO_LEN + syn.len() <= MAX_CELL);
        assert!(
            COOKIE_LEN + CIRCUIT_PEER_TAG_LEN + 1 + CIRCUIT_INTRO_LEN + syn_ack.len() <= MAX_CELL
        );
    }

    #[test]
    fn stream_peer_intro_plaintext_is_bound_to_peer_tag() {
        let sender = [0x11u8; 32];
        let tag = [0x22u8; CIRCUIT_PEER_TAG_LEN];
        let plaintext = stream_peer_intro_plaintext(&sender, &tag);
        assert_eq!(
            parse_stream_peer_intro_plaintext(&tag, &plaintext),
            Some(sender)
        );

        let mut other_tag = tag;
        other_tag[0] ^= 0x01;
        assert_eq!(
            parse_stream_peer_intro_plaintext(&other_tag, &plaintext),
            None
        );

        let mut wrong_domain = plaintext;
        wrong_domain[0] ^= 0x01;
        assert_eq!(parse_stream_peer_intro_plaintext(&tag, &wrong_domain), None);
    }
}
