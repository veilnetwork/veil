//! C-FFI surface around `veilclient`.
//!
//! Exposes the veil client SDK as a stable C ABI so non-Rust hosts
//! (Flutter via `dart:ffi`, Kotlin/Swift via `cinterop`/`Cgo`) can drive
//! the network without needing a Rust-side wrapper per platform.
//!
//! # Threading & async model
//!
//! Each [`VeilHandle`] owns a private multi-threaded Tokio runtime.
//! All async work runs there; the FFI surface is synchronous (every
//! entry point either `block_on`s or spawns a detached task).
//!
//! Recv callbacks are invoked from a tokio worker thread. Hosts that
//! need to deliver back to a single-threaded UI loop must marshal
//! across the boundary themselves (in Dart, use `NativeCallable.listener`
//! so the callback wakes the isolate even from a worker thread).
//!
//! # Memory ownership
//!
//! All returned opaque pointers are owned by the caller until released
//! via the corresponding `*_close` function. Outstanding [`VeilApp`]
//! and [`VeilStreamFfi`] objects each hold a strong reference to the
//! parent runtime via an internal `Arc`, so calling [`veil_close`]
//! does not abruptly tear down the runtime — it merely releases the
//! caller's handle. The runtime is dropped only when the last app /
//! stream is closed.
//!
//! Returned C strings (error messages) are heap-allocated; the caller
//! MUST free them with [`veil_free_string`].
//!
//! Every pointer parameter is null-checked before dereference. Passing
//! a freed or invalid pointer is undefined behaviour.
//!
//! # Error model
//!
//! Fallible functions take a `char** err_out`:
//! * On error (return `!= VEIL_OK`), `*err_out` is set to a
//!   heap-allocated UTF-8 message.
//! * On success (return `VEIL_OK`), `*err_out` is normally `NULL`.
//!
//! Exception: a few calls report a fine-grained *outcome* through a
//! separate `out_status` byte while the function-level return stays
//! `VEIL_OK` (the call itself completed). For those — currently
//! `veil_join_bootstrap_uri` and `veil_create_bootstrap_invite` —
//! `*err_out` MAY be non-NULL on `VEIL_OK`, carrying the human-readable
//! detail for that `out_status` (e.g. "wrong password", or an
//! informational note on a successful join). Each such function
//! documents this on its own declaration.
//!
//! Therefore the caller's free rule is: **free `*err_out` with
//! `veil_free_string` whenever it is non-NULL, regardless of the return
//! code** — do not gate the free on `return != VEIL_OK`, or these
//! calls will leak the detail string.

#![allow(clippy::missing_safety_doc)]
// `veilclient-ffi` exposes types (`AppHandle`, `VeilClient`,
// `MailboxBlobInfo`, …) that are themselves `#[cfg(unix)]`-gated in the
// upstream `veilclient` crate (Unix-domain-socket IPC).  Mobile FFI
// builds target iOS / Android (both Unix-family), so gating the whole
// crate on `cfg(unix)` keeps the workspace `cargo check --target
// x86_64-pc-windows-gnu` gate green without breaking any actual
// downstream consumer.
#![cfg(unix)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use zeroize::Zeroizing;

// Phase 6.49 unified FFI boundary helpers.  See module-level doc for
// migration plan; new FFI fns use these directly, existing fns
// migrate opportunistically when touched.
pub(crate) mod guard;

// Embedded in-process node runtime (no `veil-cli` subprocess). Opt-in via the
// `node-embedded` cargo feature so the default client-only build stays slim.
#[cfg(feature = "node-embedded")]
mod anon_stream;
// Lossy media-datagram side channel (calls: RTP/RTCP) over the anonymous
// circuit. Rides the embedded node's circuit pool, so it shares anon_stream's
// gating.
#[cfg(feature = "node-embedded")]
mod media;
// Opt-in message-authorship signature FFI (needs veil-cfg to parse the caller's
// identity TOML — enabled by node-embedded).
#[cfg(feature = "node-embedded")]
mod identity_sign;
// Networked nickname claim/resolve (needs the in-process embedded node's
// NodeServices; the pure nickname helpers in lib.rs stay feature-free).
#[cfg(feature = "node-embedded")]
mod nickname_net;
mod node;

use libc::{size_t, ssize_t};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;
use veilclient::{
    AppHandle, AppSender, ClientError, IncomingMessage, IncomingStream, VeilClient,
    VeilStream as SdkStream,
};

/// Emit an FFI-side diagnostic without panicking if stderr is closed/broken.
pub(crate) fn ffi_diag(msg: &str) {
    #[cfg(target_os = "android")]
    log::warn!("{msg}");
    #[cfg(not(target_os = "android"))]
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "{msg}");
    }
}

// ── Status constants ─────────────────────────────────────────────────────────

/// Operation succeeded.
pub const VEIL_OK: c_int = 0;
/// Generic error (see `err_out` for detail).
pub const VEIL_ERR: c_int = -1;
/// A required pointer parameter was NULL or invalid UTF-8.
pub const VEIL_ERR_INVALID_ARG: c_int = -2;
/// The handle / app / stream has already been closed.
pub const VEIL_ERR_CLOSED: c_int = -3;
/// the FFI call was made from inside a Tokio
/// runtime worker thread (e.g. from a recv-handler callback). Calling
/// a `block_on` or `blocking_lock` FFI entry point from such a context
/// would deadlock the worker. Hosts that need to perform another FFI
/// operation from a callback must dispatch it to a different thread
/// (e.g. main UI thread, dedicated worker pool).
pub const VEIL_ERR_REENTRANT: c_int = -4;

/// hard cap on `data` byte length accepted by
/// FFI calls that allocate from caller-supplied len. Sits BELOW the daemon's
/// `MAX_FRAME_BODY` (16 MiB) by enough headroom for the largest IPC send-payload
/// fixed prefix, so the framed `body_len = FIXED_SIZE + data_len` can never
/// exceed `MAX_FRAME_BODY`. Without this margin a max-size send produced
/// `body_len > MAX_FRAME_BODY`, which `decode_header` rejects → the daemon's
/// read task `return`s and tears down the WHOLE IPC connection (all multiplexed
/// apps/streams), not just the offending send (diff-audit 2026-06-12, defect
/// M25). The largest send prefix is `SendAnonymousDirectPayload::FIXED_SIZE`
/// (136 B); 256 B of headroom covers it plus any reply-aware trailer. Also
/// keeps a huge `len` to [`veil_send`] a clean `VEIL_ERR_INVALID_ARG` rather
/// than an OOM-sized allocation.
pub const VEIL_MAX_DATA_LEN: size_t = 16 * 1024 * 1024 - 256;

// ── Internal types ───────────────────────────────────────────────────────────

/// Shared runtime + client state. Held by `Arc` so that apps and
/// streams keep the runtime alive even [`veil_close`].
struct RuntimeBundle {
    /// `ManuallyDrop` so [`RuntimeBundle`]'s `Drop` impl can choose HOW to
    /// tear the runtime down (audit U4). Dereferences transparently, so all
    /// `bundle.runtime.block_on(...)` / `.spawn(...)` call sites are unchanged.
    runtime: std::mem::ManuallyDrop<tokio::runtime::Runtime>,
    client: TokioMutex<VeilClient>,
    ///.4 P2: cached mailbox-fetch result between
    /// [`veil_mailbox_fetch_count`] (which fetches and caches) and
    /// [`veil_mailbox_fetch_into`] (which copies into caller-managed
    /// buffers and clears). Single-shot; a second fetch_count
    /// overwrites. `std::sync::Mutex` is fine — accessed only from
    /// the FFI thread, never inside the runtime.
    pending_mailbox_fetch: StdMutex<Option<Vec<veilclient::MailboxBlobInfo>>>,
}

/// Short-lived sovereign signing burst opened from a recovery phrase. The
/// derived seed never crosses the FFI boundary and is zeroized when the last
/// in-flight operation releases this handle.
pub struct VeilSovereignSigner {
    key: SovereignSignerKey,
}

enum SovereignSignerKey {
    RecoveryEd25519(zeroize::Zeroizing<[u8; 32]>),
    Bundle(veil_identity::sovereign_bundle::SovereignMaterial),
}

impl Drop for RuntimeBundle {
    fn drop(&mut self) {
        // SAFETY: `drop` runs exactly once per value; we take the Runtime out
        // of the `ManuallyDrop` here and never touch the field again.
        let rt = unsafe { std::mem::ManuallyDrop::take(&mut self.runtime) };
        if in_tokio_runtime() {
            // The last `Arc<RuntimeBundle>` is being released from INSIDE one
            // of the runtime's own worker threads — e.g. the host called
            // `veil_*_close` from a recv/event callback (those run on a
            // worker thread) and that handle/app/stream held the last Arc.
            // Dropping a multi-thread Tokio runtime in that context panics
            // ("Cannot drop a runtime in a context where blocking is not
            // allowed"); under the release `panic = "abort"` profile that
            // aborts the host process. Tear the runtime down WITHOUT blocking
            // instead — `shutdown_background` is safe to call from a worker
            // thread and does not join the current one (audit U4).
            rt.shutdown_background();
        } else {
            // Normal path: drop on a non-worker (FFI/host) thread runs the
            // default blocking shutdown, which joins the worker threads.
            drop(rt);
        }
    }
}

// ── Generational handle table (double-free / use-after-free / ABA guard) ──────
//
// Dart's GC is nondeterministic; combined with `NativeFinalizer` it is easy to
// double-close the same handle, and a host may also USE a handle on one thread
// while another closes it. A naïve `Box::from_raw` on either path reinterprets
// freed (or about-to-be-freed) memory as a live struct → UB → potential RCE.
//
// Each handle lives in a per-type generational table. The opaque `*mut T`
// handed to C is NOT a real pointer — it is an encoded `(slot_index,
// generation)` token. Callers treat it as opaque (they only pass it back or
// compare against NULL; the C type is incomplete so it cannot be dereferenced
// in well-formed C), so reinterpreting it costs no ABI / cbindgen / glue change.
//
// * Every lookup validates the generation, so a token whose slot was freed and
//   reused for a DIFFERENT handle (classic ABA) no longer matches — the prior
//   address-keyed registry could not distinguish that case.
// * The table owns an `Arc<T>`; the USE path clones the `Arc` BEFORE any async
//   work, so a concurrent `*_close` that removes the entry does not free the
//   value out from under an in-flight call — it lives until the last in-flight
//   `Arc` drops. The previous design freed the `Box` immediately on close,
//   dangling any `&*ptr` a worker thread still held.
// * A double-close / unknown / wrong-type / stale token finds no matching live
//   slot → safe no-op (close) or clean error (use); the token is never
//   dereferenced as a pointer.
//
// Residual: the generation is `u32` on 64-bit hosts (16-bit on 32-bit hosts,
// where the token itself is only 32 bits wide). After 2^32 (resp. 2^16) reuses
// of the SAME slot the generation wraps and ABA could in principle recur for
// that one slot. On 64-bit this is unreachable in practice; on legacy 32-bit
// hosts it is a far smaller window than the unconditional address-reuse ABA it
// replaces. Modern iOS/Android are 64-bit.

/// Bit split of the opaque token: slot index in the low bits, generation in the
/// high bits. 64-bit hosts get a full 32-bit generation; 32-bit hosts fall back
/// to 16/16 (see the residual note above).
#[cfg(target_pointer_width = "64")]
const HANDLE_INDEX_BITS: u32 = 32;
#[cfg(not(target_pointer_width = "64"))]
const HANDLE_INDEX_BITS: u32 = 16;
const HANDLE_INDEX_MASK: usize = (1usize << HANDLE_INDEX_BITS) - 1;

struct HandleSlot<T> {
    /// Generation of the value CURRENTLY occupying this slot. Bumped on every
    /// remove so a stale token for a prior occupant fails validation. Starts at
    /// 1 so a live token is never all-zero (which would collide with NULL).
    generation: u32,
    value: Option<Arc<T>>,
}

/// Per-type generational table mapping opaque tokens → live `Arc<T>`.
pub(crate) struct HandleTable<T> {
    slots: Vec<HandleSlot<T>>,
    free: Vec<u32>,
}

impl<T> HandleTable<T> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    fn encode(index: u32, generation: u32) -> usize {
        ((generation as usize) << HANDLE_INDEX_BITS) | (index as usize)
    }

    fn decode(token: usize) -> (u32, u32) {
        let index = (token & HANDLE_INDEX_MASK) as u32;
        let generation = (token >> HANDLE_INDEX_BITS) as u32;
        (index, generation)
    }

    /// Insert `value`, returning its opaque token. Reuses a free slot when
    /// available (carrying that slot's already-bumped generation), else grows.
    pub(crate) fn insert(table: &StdMutex<Self>, value: T) -> usize {
        let arc = Arc::new(value);
        let mut t = table.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = t.free.pop() {
            let slot = &mut t.slots[index as usize];
            slot.value = Some(arc);
            Self::encode(index, slot.generation)
        } else {
            // Check the bound in `usize` BEFORE narrowing to u32, so a
            // (physically infeasible) >u32::MAX slot count can't truncate past
            // the guard. (audit cycle-3.)
            let index = t.slots.len();
            assert!(
                index <= HANDLE_INDEX_MASK,
                "veilclient-ffi: handle table exhausted",
            );
            let index = index as u32;
            t.slots.push(HandleSlot {
                generation: 1,
                value: Some(arc),
            });
            Self::encode(index, 1)
        }
    }

    /// Clone the live `Arc` for `token`, or `None` if the token is stale /
    /// unknown / freed. Never dereferences the token as a pointer.
    pub(crate) fn get(table: &StdMutex<Self>, token: usize) -> Option<Arc<T>> {
        let (index, generation) = Self::decode(token);
        let t = table.lock().unwrap_or_else(|e| e.into_inner());
        let slot = t.slots.get(index as usize)?;
        if slot.generation != generation {
            return None;
        }
        slot.value.clone()
    }

    /// Remove and return the live `Arc` for `token`, bumping the slot's
    /// generation so the token can never validate again. `None` for a
    /// double-close / unknown / stale token — a safe no-op.
    pub(crate) fn remove(table: &StdMutex<Self>, token: usize) -> Option<Arc<T>> {
        let (index, generation) = Self::decode(token);
        let mut t = table.lock().unwrap_or_else(|e| e.into_inner());
        let slot = t.slots.get_mut(index as usize)?;
        if slot.generation != generation || slot.value.is_none() {
            return None;
        }
        let taken = slot.value.take();
        // Bump generation, keeping it nonzero so encoded tokens never collide
        // with NULL. wrapping_add handles the (practically unreachable on
        // 64-bit) overflow; skip 0 on wrap.
        slot.generation = slot.generation.wrapping_add(1);
        if slot.generation == 0 {
            slot.generation = 1;
        }
        t.free.push(index);
        taken
    }
}

fn handle_table() -> &'static StdMutex<HandleTable<VeilHandle>> {
    static T: OnceLock<StdMutex<HandleTable<VeilHandle>>> = OnceLock::new();
    T.get_or_init(|| StdMutex::new(HandleTable::new()))
}

fn app_table() -> &'static StdMutex<HandleTable<VeilApp>> {
    static T: OnceLock<StdMutex<HandleTable<VeilApp>>> = OnceLock::new();
    T.get_or_init(|| StdMutex::new(HandleTable::new()))
}

fn stream_table() -> &'static StdMutex<HandleTable<VeilStreamFfi>> {
    static T: OnceLock<StdMutex<HandleTable<VeilStreamFfi>>> = OnceLock::new();
    T.get_or_init(|| StdMutex::new(HandleTable::new()))
}

fn anon_stream_table() -> &'static StdMutex<HandleTable<VeilAnonStreamFfi>> {
    static T: OnceLock<StdMutex<HandleTable<VeilAnonStreamFfi>>> = OnceLock::new();
    T.get_or_init(|| StdMutex::new(HandleTable::new()))
}

fn sovereign_signer_table() -> &'static StdMutex<HandleTable<VeilSovereignSigner>> {
    static T: OnceLock<StdMutex<HandleTable<VeilSovereignSigner>>> = OnceLock::new();
    T.get_or_init(|| StdMutex::new(HandleTable::new()))
}

/// USE-path liveness guard: resolve a raw handle token to its live `Arc<T>`
/// BEFORE any dereference or async work, turning a use-after-close / ABA /
/// unknown / wrong-type token into a clean error return instead of UB. Binds
/// the cloned `Arc` to `$name` (usable via `Deref` exactly like the old
/// `&*ptr`). The token is validated by (index, generation) WITHOUT ever being
/// dereferenced as a pointer.
///
/// `$name`    — identifier the cloned `Arc<T>` is bound to for the rest of the fn.
/// `$table`   — the matching table (`handle_table()` / `app_table()` /
///              `stream_table()`); `$ptr` MUST have been minted by THIS table.
/// `$ptr`     — the raw token (already null-checked by the surrounding fn).
/// `$err_out` — the fn's `err_out` slot, or `ptr::null_mut()` (write_err no-ops).
/// `$ret`     — value to return on failure; MUST match the surrounding fn's
///              null-check return (`VEIL_ERR_INVALID_ARG`, `... as ssize_t`,
///              `ptr::null_mut()`, `0` …).
/// `$what`    — opaque type name for the diagnostic string.
macro_rules! get_or_return {
    ($name:ident, $table:expr, $ptr:expr, $err_out:expr, $ret:expr, $what:literal) => {
        let $name = match $crate::HandleTable::get($table, $ptr as usize) {
            Some(arc) => arc,
            None => {
                let err_out_ref = $err_out;
                unsafe {
                    $crate::write_err(
                        err_out_ref,
                        concat!($what, ": use-after-close or unknown handle"),
                    );
                }
                return $ret;
            }
        };
    };
}

/// Opaque connection handle returned by [`veil_connect`].
///
/// Wraps a strong `Arc` over [`RuntimeBundle`]; cloning an internal `Arc`
/// from this is what allows apps and streams to outlive the caller's
/// own `VeilHandle*` if they so choose (although the typical pattern
/// is to keep the handle alive for the whole session).
pub struct VeilHandle {
    bundle: Arc<RuntimeBundle>,
    /// `Some` once a push-event handler is installed via
    /// [`veil_set_event_handler`]. Aborted on
    /// [`veil_close`] or replaced on subsequent
    /// `set_event_handler` calls.
    event_task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Node-wide anonymous-stream multiplexer, built lazily on the first
    /// `veil_anon_stream_open`/`veil_anon_stream_accept` (binds a dedicated
    /// onion-stream endpoint + spawns the demux).
    anon_hub: TokioMutex<Option<Arc<anon_stream::AnonStreamHub>>>,
}

/// Opaque app endpoint.
///
/// split into a `AppSender` (always present
/// while the app is bound) and an optional `AppReceiver` (moved out
/// when `set_recv_handler` installs the recv loop). Previously we
/// stored a single `Option<AppHandle>` and `set_recv_handler` did a
/// `take`, which left `veil_send` permanently returning
/// `VEIL_ERR_CLOSED` despite the daemon-side binding still being
/// alive — directly contradicting the documented contract. Now
/// `veil_send` always works through the still-resident `AppSender`
/// regardless of whether a recv handler is installed.
pub struct VeilApp {
    bundle: Arc<RuntimeBundle>,
    sender: Arc<TokioMutex<Option<AppSender>>>,
    /// Raw inbound-DATAGRAM channel, drained by the single persistent recv
    /// task. Split out of the SDK [`AppReceiver`] (`into_parts`) so the
    /// inbound-STREAM channel can be drained independently — a `select!` over
    /// both halves of one `&mut AppReceiver` is a borrow conflict.
    msg_rx: TokioMutex<Option<mpsc::Receiver<IncomingMessage>>>,
    /// Raw inbound-STREAM channel, drained by `veil_stream_accept` (pull). A
    /// remote peer opening a byte-stream to this endpoint lands here.
    inbound_streams: TokioMutex<Option<mpsc::Receiver<IncomingStream>>>,
    /// `app_id` cached at bind time so callers can read it after the
    /// receiver has been moved into a recv loop.
    app_id: [u8; 32],
    endpoint_id: u32,
    /// `Some` once the (single, persistent) recv task is spawned; aborted on
    /// app close. Audit cycle-6 (P6): spawned at most once — `set_recv_handler`
    /// re-entry swaps `recv_cb` rather than aborting/respawning.
    recv_task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Swappable recv callback the persistent recv task dispatches to. `None`
    /// means "no handler currently installed" → messages are dropped.
    recv_cb: Arc<StdMutex<Option<RecvCbSlot>>>,
}

/// Opaque veil stream — reliable ordered byte channel.
///
/// The SDK stream is split into independent read/write halves under SEPARATE
/// mutexes (diff-audit H4): the old single `Mutex<Option<SdkStream>>` meant a
/// thread parked in `veil_stream_read` (which holds the lock across a blocking,
/// timeout-less read) blocked any concurrent `veil_stream_write` forever — a
/// half-duplex deadlock for request/response protocols. `tokio::io::split`
/// lets read and write lock disjoint halves. Dropping the struct drops both
/// halves → the underlying stream → its `Drop` sends STREAM_CLOSE.
pub struct VeilStreamFfi {
    bundle: Arc<RuntimeBundle>,
    reader: TokioMutex<Option<tokio::io::ReadHalf<SdkStream>>>,
    writer: TokioMutex<Option<tokio::io::WriteHalf<SdkStream>>>,
}

/// Handle to one ANONYMOUS reliable byte-stream (onion-routed, congestion-
/// controlled — see [`anon_stream`]). Split read/write halves so a caller can
/// read + write concurrently without one mutex deadlocking a blocking read
/// against a write.
pub struct VeilAnonStreamFfi {
    bundle: Arc<RuntimeBundle>,
    abort: veil_onion_stream::OnionAbort,
    reader: TokioMutex<Option<veil_onion_stream::OnionReader>>,
    writer: TokioMutex<Option<veil_onion_stream::OnionWriter>>,
}

/// Get-or-lazily-build this node's anonymous-stream hub (binds the dedicated
/// onion-stream endpoint once, on first use).
fn ensure_anon_hub(
    bundle: &Arc<RuntimeBundle>,
    slot: &TokioMutex<Option<Arc<anon_stream::AnonStreamHub>>>,
) -> Result<Arc<anon_stream::AnonStreamHub>, String> {
    bundle.runtime.block_on(async {
        let mut g = slot.lock().await;
        if let Some(h) = g.as_ref() {
            return Ok(h.clone());
        }
        let (me, app) = {
            let client = bundle.client.lock().await;
            let me = client
                .node_identity()
                .await
                .map_err(|e| format!("node_identity: {e}"))?
                .node_id;
            let app = client
                .bind_named(
                    anon_stream::STREAM_NAMESPACE,
                    anon_stream::STREAM_NAME,
                    anon_stream::STREAM_ENDPOINT_ID,
                )
                .await
                .map_err(|e| format!("bind onion-stream endpoint: {e}"))?;
            (me, app)
        };
        let (sender, receiver) = app.into_split();
        let (msg_rx, _streams) = receiver.into_parts();
        let hub = Arc::new(anon_stream::AnonStreamHub::new(me, sender, msg_rx));
        *g = Some(hub.clone());
        Ok(hub)
    })
}

/// Open an anonymous reliable byte-stream to a peer. `dst_app_id` is the peer's
/// onion-stream endpoint app id (`deriveAppId(peer_node, "xveil",
/// "onion-stream")` — the Dart caller derives it, mirroring `veil_stream_open`).
/// Returns NULL on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_open(
    handle: *mut VeilHandle,
    dst_node_id: *const u8,
    dst_app_id: *const u8,
    err_out: *mut *mut c_char,
) -> *mut VeilAnonStreamFfi {
    if unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_open") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "handle" => handle,
        "dst_node_id" => dst_node_id,
        "dst_app_id" => dst_app_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        ptr::null_mut(),
        "VeilHandle"
    );
    let mut node = [0u8; 32];
    let mut app = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, app.as_mut_ptr(), 32);
    }
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("anon stream open: {e}")) };
            return ptr::null_mut();
        }
    };
    let bundle = Arc::clone(&handle_live.bundle);
    // open() spawns the stream driver, so it must run inside the runtime.
    let stream = bundle
        .runtime
        .block_on(async { hub.open(veil_onion_stream::Addr { node, app }) });
    let abort = stream.abort_handle();
    let (rd, wr) = stream.into_split();
    let ffi = VeilAnonStreamFfi {
        bundle,
        abort,
        reader: TokioMutex::new(Some(rd)),
        writer: TokioMutex::new(Some(wr)),
    };
    HandleTable::insert(anon_stream_table(), ffi) as *mut VeilAnonStreamFfi
}

/// Accept the next inbound anonymous stream, or NULL on timeout (no error) /
/// error. On success writes the initiator's 32-byte node id + onion-stream app
/// id into the out params (caller-allocated, 32 B each).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_accept(
    handle: *mut VeilHandle,
    timeout_ms: u64,
    out_src_node_id: *mut u8,
    out_src_app_id: *mut u8,
    err_out: *mut *mut c_char,
) -> *mut VeilAnonStreamFfi {
    if unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_accept") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "handle" => handle,
        "out_src_node_id" => out_src_node_id,
        "out_src_app_id" => out_src_app_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        ptr::null_mut(),
        "VeilHandle"
    );
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("anon stream accept: {e}")) };
            return ptr::null_mut();
        }
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let accepted = bundle.runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), hub.accept()).await
    });
    match accepted {
        Ok(Some((stream, src))) => {
            unsafe {
                ptr::copy_nonoverlapping(src.node.as_ptr(), out_src_node_id, 32);
                ptr::copy_nonoverlapping(src.app.as_ptr(), out_src_app_id, 32);
            }
            let abort = stream.abort_handle();
            let (rd, wr) = stream.into_split();
            let ffi = VeilAnonStreamFfi {
                bundle,
                abort,
                reader: TokioMutex::new(Some(rd)),
                writer: TokioMutex::new(Some(wr)),
            };
            HandleTable::insert(anon_stream_table(), ffi) as *mut VeilAnonStreamFfi
        }
        Ok(None) => ptr::null_mut(),      // hub closed
        Err(_elapsed) => ptr::null_mut(), // timeout — caller polls again
    }
}

/// Pre-warm the anonymous-stream outbound circuit pool toward a peer.
/// Fire-and-forget: kicks the background pool open (resolve ads + open +
/// confirm) and returns immediately, so a freshly-restarted node's first
/// serve/pull does not pay the cold-pool price inside the peer's manifest
/// window. Idempotent; cheap when the pool is already up. Returns 0 on
/// dispatch, -1 on error (NULL args / dead handle / hub bind failure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_warm_peer(
    handle: *mut VeilHandle,
    dst_node_id: *const u8,
    err_out: *mut *mut c_char,
) -> i32 {
    if unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_warm_peer") }.is_err() {
        return -1;
    }
    null_check_with_default!(err_out, -1,
        "handle" => handle,
        "dst_node_id" => dst_node_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        -1,
        "VeilHandle"
    );
    let mut node = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, node.as_mut_ptr(), 32);
    }
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("anon stream warm: {e}")) };
            return -1;
        }
    };
    handle_live.bundle.runtime.spawn(async move {
        hub.warm_outbound(node).await;
    });
    0
}

// ---------------------------------------------------------------------------
// Media datagram channel (Phase 2 of calls): a lossy RTP/RTCP path over the
// anonymous onion circuit. Per-packet flow is native↔native (a C++/ObjC++
// `webrtc::Transport` shim calls `veil_media_send_datagram` and receives via
// `veil_media_set_recv_callback`); Dart drives control only (open/close). See
// `media.rs` for the wire magic + inbound registry and `veil_media_abi.h` for
// the shared header.
// ---------------------------------------------------------------------------

/// One open media channel. Holds a BOUNDED outbound queue and the drain task
/// that pumps it into the hub's lossy datagram send. Bounded because real-time
/// media must drop rather than buffer when it outpaces the circuit.
#[cfg(feature = "node-embedded")]
struct MediaChannel {
    tx_hi: mpsc::Sender<Vec<u8>>,
    tx_video: mpsc::Sender<Vec<u8>>,
    peer: [u8; 32],
    task: tokio::task::JoinHandle<()>,
}

/// Open media channels keyed by the opaque id handed to the host.
#[cfg(feature = "node-embedded")]
static MEDIA_CHANNELS: std::sync::LazyLock<StdMutex<std::collections::HashMap<u64, MediaChannel>>> =
    std::sync::LazyLock::new(|| StdMutex::new(std::collections::HashMap::new()));

/// Monotonic channel-id source (never reuses 0, which the ABI reserves for
/// "error / invalid").
#[cfg(feature = "node-embedded")]
static MEDIA_NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Outbound queue depth per media channel. Keep this bounded: media is a real-
/// time path, and a deep FIFO turns transient overload into stale audio/video.
/// Split audio/RTCP/unknown from VP8 RTP so a video keyframe burst has room
/// without putting audio behind a long video backlog.
#[cfg(feature = "node-embedded")]
const MEDIA_TX_HI_QUEUE: usize = 16;
#[cfg(feature = "node-embedded")]
const MEDIA_TX_VIDEO_QUEUE: usize = 24;

#[cfg(feature = "node-embedded")]
fn media_is_vp8_rtp(payload: &[u8]) -> bool {
    if payload.len() < 2 || (payload[0] >> 6) != 2 {
        return false;
    }
    // rtcp-mux RTCP packet types occupy the 64..=95 range. Video RTP is the
    // fixed VP8 payload type configured by veil_media_engine.cc.
    (payload[1] & 0x7f) == 96
}

#[cfg(all(test, feature = "node-embedded"))]
mod media_priority_tests {
    use super::media_is_vp8_rtp;

    #[test]
    fn media_priority_classifies_only_vp8_rtp_as_video() {
        assert!(media_is_vp8_rtp(&[0x80, 96, 0, 1]));
        assert!(media_is_vp8_rtp(&[0x80, 0x80 | 96, 0, 1]));
        assert!(!media_is_vp8_rtp(&[0x80, 111, 0, 1])); // Opus RTP.
        assert!(!media_is_vp8_rtp(&[0x80, 72, 0, 1])); // RTCP mux range.
        assert!(!media_is_vp8_rtp(&[0x40, 96, 0, 1])); // Not RTP v2.
        assert!(!media_is_vp8_rtp(&[0x80]));
    }
}

/// Open a lossy MEDIA datagram channel to `peer` over the anonymous circuit
/// (reuses the reliable stream's rendezvous/pool and warms the circuit in the
/// background). Per-packet RTP/RTCP then flows native↔native via
/// [`veil_media_send_datagram`] / [`veil_media_set_recv_callback`]. Returns an
/// opaque channel id (> 0), or 0 on error.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_open_channel(
    handle: *mut VeilHandle,
    peer_node_id: *const u8,
    err_out: *mut *mut c_char,
) -> u64 {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_open_channel") }.is_err() {
        return 0;
    }
    null_check_with_default!(err_out, 0u64,
        "handle" => handle,
        "peer_node_id" => peer_node_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        0u64,
        "VeilHandle"
    );
    let mut peer = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
    }
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("media open: {e}")) };
            return 0;
        }
    };
    let (tx_hi, mut rx_hi) = mpsc::channel::<Vec<u8>>(MEDIA_TX_HI_QUEUE);
    let (tx_video, mut rx_video) = mpsc::channel::<Vec<u8>>(MEDIA_TX_VIDEO_QUEUE);
    let send_hub = hub.clone();
    // One drain task per channel: warm the circuit, then pump queued datagrams
    // into the lossy send. `send_datagram` itself drops on QueueFull/no-route,
    // so a wedged circuit degrades to silent loss, never to a stall.
    //
    // Self-heal a stale route: the initial `media_open_channel` resolves the
    // peer's rendezvous ONCE. If the channel is opened before the peer has
    // (re)published a reachable rendezvous ad — e.g. a call whose callee is a
    // just-woken NAT'd phone that registers seconds/minutes later — that resolve
    // finds stale/absent ads, the circuit points nowhere, and EVERY datagram is
    // silently dropped for the whole call (device-observed: desktop->phone media
    // 0% while phone->desktop was fine). A run of no-route drops is the signal to
    // re-resolve: re-call `media_open_channel` (ensure_outbound_opening rebuilds
    // with a fresh resolve past its own dedup window), so we pick the peer up the
    // moment it becomes reachable instead of staying dark. Healthy sends return
    // true and reset the counter, so a flowing call pays nothing.
    const MEDIA_REWARM_EVERY_DROPS: u32 = 20;
    let task = handle_live.bundle.runtime.spawn(async move {
        send_hub.media_open_channel(peer).await;
        let mut consecutive_drops: u32 = 0;
        loop {
            let pkt = tokio::select! {
                biased;
                Some(pkt) = rx_hi.recv() => pkt,
                Some(pkt) = rx_video.recv() => pkt,
                else => break,
            };
            if send_hub.media_send_datagram(peer, &pkt).await {
                consecutive_drops = 0;
            } else {
                consecutive_drops += 1;
                if consecutive_drops % MEDIA_REWARM_EVERY_DROPS == 1 {
                    send_hub.media_open_channel(peer).await;
                }
            }
        }
    });
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                tx_video,
                peer,
                task,
            },
        );
    id
}

/// Open a lossy MEDIA datagram channel to `peer` over a direct app endpoint.
/// Outbound RTP/RTCP is sent from `app` to `(peer_node_id, peer_app_id,
/// peer_endpoint_id)`. Inbound direct media datagrams must be received by the
/// host on the same app endpoint and fed to
/// [`veil_media_dispatch_direct_datagram`].
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_open_direct_channel(
    app: *mut VeilApp,
    peer_node_id: *const u8,
    peer_app_id: *const u8,
    peer_endpoint_id: u32,
    err_out: *mut *mut c_char,
) -> u64 {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_open_direct_channel") }.is_err() {
        return 0;
    }
    null_check_with_default!(err_out, 0u64,
        "app" => app,
        "peer_node_id" => peer_node_id,
        "peer_app_id" => peer_app_id,
    );
    get_or_return!(app_ref, app_table(), app, err_out, 0u64, "VeilApp");
    let mut peer = [0u8; 32];
    let mut peer_app = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(peer_app_id, peer_app.as_mut_ptr(), 32);
    }

    let (tx_hi, mut rx_hi) = mpsc::channel::<Vec<u8>>(MEDIA_TX_HI_QUEUE);
    let (tx_video, mut rx_video) = mpsc::channel::<Vec<u8>>(MEDIA_TX_VIDEO_QUEUE);
    let sender = Arc::clone(&app_ref.sender);
    let task = app_ref.bundle.runtime.spawn(async move {
        loop {
            let pkt = tokio::select! {
                biased;
                Some(pkt) = rx_hi.recv() => pkt,
                Some(pkt) = rx_video.recv() => pkt,
                else => break,
            };
            let guard = sender.lock().await;
            let Some(sender) = guard.as_ref() else {
                break;
            };
            let _ = sender
                .send_owned(peer, peer_app, peer_endpoint_id, pkt)
                .await;
        }
    });
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                tx_video,
                peer,
                task,
            },
        );
    id
}

/// Enqueue one media datagram (RTP/RTCP) on `chan`. NON-BLOCKING: returns 0 if
/// queued, 1 if dropped (queue full / channel closing) — the caller's real-time
/// media thread must never block. Returns -1 on a NULL/zero-length payload or an
/// unknown `chan`.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_send_datagram(chan: u64, ptr: *const u8, len: size_t) -> c_int {
    if chan == 0 || ptr.is_null() || len == 0 {
        return -1;
    }
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    let map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(ch) = map.get(&chan) else {
        return -1;
    };
    let tx = if media_is_vp8_rtp(&payload) {
        &ch.tx_video
    } else {
        &ch.tx_hi
    };
    match tx.try_send(payload) {
        Ok(()) => 0,
        Err(mpsc::error::TrySendError::Full(_)) => 1,
        Err(mpsc::error::TrySendError::Closed(_)) => -1,
    }
}

/// Feed one direct-P2P media datagram received by the host on the media app
/// endpoint into the shared native media callback registry. The host is
/// responsible for authenticating/filtering the source app id before calling.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_dispatch_direct_datagram(
    peer_node_id: *const u8,
    ptr: *const u8,
    len: size_t,
) -> c_int {
    if peer_node_id.is_null() || ptr.is_null() || len == 0 {
        return -1;
    }
    let mut peer = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
    }
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    media::dispatch_inbound(peer, payload);
    0
}

/// Install the C recv callback invoked (native↔native, from a tokio worker)
/// once per inbound media datagram from `chan`'s peer, with the wire magic
/// already stripped. Replaces any prior callback; `cb == NULL` clears it.
/// Returns 0, or -1 on an unknown `chan`.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_set_recv_callback(
    chan: u64,
    cb: Option<media::MediaRecvFn>,
    ctx: *mut c_void,
) -> c_int {
    let peer = {
        let map = MEDIA_CHANNELS.lock().unwrap_or_else(|p| p.into_inner());
        match map.get(&chan) {
            Some(ch) => ch.peer,
            None => return -1,
        }
    };
    match cb {
        Some(cb) => media::set_recv_callback(peer, cb, ctx),
        None => media::clear_recv_callback(peer),
    }
    0
}

/// Close a media channel: stops the drain task, drops the outbound queue, and
/// clears the peer's recv callback. Idempotent (unknown `chan` is a no-op).
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_close_channel(chan: u64) {
    let ch = MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&chan);
    if let Some(ch) = ch {
        // Dropping `ch.tx` already closes the queue (the drain loop ends), but
        // abort to reclaim the task promptly even if it is mid-await.
        ch.task.abort();
        media::clear_recv_callback(ch.peer);
    }
}

/// Diagnostic: number of inbound media datagrams received from `peer_node_id`
/// (32 bytes) since process start. Lets a host confirm receipt without wiring a
/// cross-thread recv callback (used by the Phase 2 two-node datagram probe).
/// Returns 0 on a NULL pointer.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_recv_count(peer_node_id: *const u8) -> u64 {
    if peer_node_id.is_null() {
        return 0;
    }
    let mut peer = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(peer_node_id, peer.as_mut_ptr(), 32);
    }
    media::recv_count(peer)
}

/// Read up to `cap` bytes. Returns the count (0 = clean EOF), or a negative
/// error code (the stream was reset → the app should resume).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_read(
    stream: *mut VeilAnonStreamFfi,
    buf: *mut u8,
    cap: size_t,
    err_out: *mut *mut c_char,
) -> ssize_t {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_read") } {
        return rc as ssize_t;
    }
    if stream.is_null() || buf.is_null() {
        unsafe { write_err(err_out, "stream or buf is NULL") };
        return VEIL_ERR_INVALID_ARG as ssize_t;
    }
    if cap == 0 {
        return 0;
    }
    if cap > VEIL_MAX_DATA_LEN {
        unsafe { write_err(err_out, format!("cap {cap} exceeds VEIL_MAX_DATA_LEN")) };
        return VEIL_ERR_INVALID_ARG as ssize_t;
    }
    get_or_return!(
        stream_ref,
        anon_stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG as ssize_t,
        "VeilAnonStreamFfi"
    );
    let res: Result<usize, String> = stream_ref.bundle.runtime.block_on(async {
        let mut guard = stream_ref.reader.lock().await;
        let Some(rd) = guard.as_mut() else {
            return Err("stream closed".to_string());
        };
        let mut tmp = vec![0u8; cap];
        let n = rd.read(&mut tmp).await.map_err(|e| e.to_string())?;
        unsafe { ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
        Ok(n)
    });
    match res {
        Ok(n) => n as ssize_t,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR as ssize_t
        }
    }
}

/// Queue `len` bytes for reliable delivery. Returns `VEIL_OK` / a negative code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_write(
    stream: *mut VeilAnonStreamFfi,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_write") } {
        return rc;
    }
    null_check!(err_out, "stream" => stream);
    if data.is_null() && len > 0 {
        unsafe { write_err(err_out, "data is NULL but len > 0") };
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe { write_err(err_out, format!("data len {len} exceeds VEIL_MAX_DATA_LEN")) };
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        stream_ref,
        anon_stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilAnonStreamFfi"
    );
    let payload = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let res: Result<(), String> = stream_ref.bundle.runtime.block_on(async {
        let guard = stream_ref.writer.lock().await;
        let Some(wr) = guard.as_ref() else {
            return Err("stream closed".to_string());
        };
        wr.write_all(&payload).await.map_err(|e| e.to_string())
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR_CLOSED
        }
    }
}

/// Half-close the send direction (a FIN follows the last queued byte). The peer
/// reads EOF. Returns `VEIL_OK` / a negative code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_finish(
    stream: *mut VeilAnonStreamFfi,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_finish") } {
        return rc;
    }
    null_check!(err_out, "stream" => stream);
    get_or_return!(
        stream_ref,
        anon_stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilAnonStreamFfi"
    );
    let res: Result<(), String> = stream_ref.bundle.runtime.block_on(async {
        let guard = stream_ref.writer.lock().await;
        let Some(wr) = guard.as_ref() else {
            return Err("stream closed".to_string());
        };
        wr.finish().await.map_err(|e| e.to_string())
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR_CLOSED
        }
    }
}

/// Close + free the stream handle (idempotent, NULL-safe). This is the graceful
/// resource-release path: dropping the write half closes the command channel, so
/// the driver finishes the send direction rather than resetting normal EOF.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_close(stream: *mut VeilAnonStreamFfi) {
    if stream.is_null() {
        return;
    }
    let _ = HandleTable::remove(anon_stream_table(), stream as usize);
}

/// Abort + free the stream handle (idempotent, NULL-safe). Use for timeout /
/// retry cancellation. A Dart timeout may call this while another FFI worker is
/// blocked inside `read()`, and removing the generational handle alone does not
/// wake that already-cloned Arc. First signal the local read half, then send a
/// best-effort RST through the driver so the peer/route settle too.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_anon_stream_abort(stream: *mut VeilAnonStreamFfi) {
    if stream.is_null() {
        return;
    }
    let Some(stream_ref) = HandleTable::remove(anon_stream_table(), stream as usize) else {
        return;
    };
    stream_ref
        .abort
        .abort(veil_onion_stream::wire::reset_reason::APP);
    let bundle = Arc::clone(&stream_ref.bundle);
    let _task = bundle.runtime.spawn(async move {
        let guard = stream_ref.writer.lock().await;
        if let Some(wr) = guard.as_ref() {
            wr.abort_local(veil_onion_stream::wire::reset_reason::APP);
            wr.reset(veil_onion_stream::wire::reset_reason::APP).await;
        }
    });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

unsafe fn write_err(err_out: *mut *mut c_char, msg: impl Into<String>) {
    if err_out.is_null() {
        return;
    }
    let cs = CString::new(msg.into())
        .unwrap_or_else(|_| CString::new("<error message contained NUL>").unwrap());
    unsafe {
        *err_out = cs.into_raw();
    }
}

unsafe fn clear_err(err_out: *mut *mut c_char) {
    if !err_out.is_null() {
        unsafe {
            *err_out = ptr::null_mut();
        }
    }
}

/// Maximum length for a caller-supplied text input on the FFI boundary.
///
/// All text inputs use the explicit-length `(*const u8, len)` ABI
/// ([`slice_to_str`] / [`opt_slice_to_str`]): the length is authoritative, so
/// there is no `strnlen` scan and no "must be NUL-terminated or readable for
/// 4 KiB" footgun. This cap is a sanity/DoS bound — 4 KiB covers every
/// legitimate input shape: filesystem paths (Linux PATH_MAX = 4096), BIP-39
/// phrases (~330 B for 24 words), passwords (typically <256 B), invite URIs
/// (<1 KiB). Inputs longer than this are rejected as invalid.
const MAX_FFI_CSTR_LEN: usize = 4096;

/// Decode a REQUIRED text input from an explicit `(ptr, len)` byte pair — the
/// length-based C ABI used for every caller-supplied string.
///
/// Unlike the `strnlen` path, the length is authoritative: there is no scan and
/// no "must be NUL-terminated or readable for 4 KiB" footgun — a non-terminated
/// buffer of exactly `len` bytes is well-defined. Returns `None` when `ptr` is
/// NULL, `len` exceeds [`MAX_FFI_CSTR_LEN`], or the bytes are not valid UTF-8.
/// An empty input (`len == 0`, non-NULL `ptr`) decodes to `Some("")`; callers
/// that forbid empty validate that themselves.
///
/// # Safety
/// `ptr` is NULL, or points to a readable buffer of at least `len` bytes. No
/// NUL terminator is required or consulted.
unsafe fn slice_to_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len > MAX_FFI_CSTR_LEN {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).ok()
}

/// Tri-state decode of an OPTIONAL text input from `(ptr, len)`, for any
/// nullable string (`password`, `instance_label`, …):
///  * NULL `ptr` → `Ok(None)` (argument omitted),
///  * valid UTF-8 within [`MAX_FFI_CSTR_LEN`] → `Ok(Some(s))`,
///  * non-NULL but invalid UTF-8 or over-cap → `Err(())` (caller MUST reject,
///    never silently coerce to "omitted" — see diff-audit M26).
///
/// # Safety
/// `ptr` is NULL, or points to a readable buffer of at least `len` bytes.
unsafe fn opt_slice_to_str<'a>(ptr: *const u8, len: usize) -> Result<Option<&'a str>, ()> {
    if ptr.is_null() {
        return Ok(None);
    }
    if len > MAX_FFI_CSTR_LEN {
        return Err(());
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).map(Some).map_err(|_| ())
}

/// Non-elidable wipe of a caller-owned byte buffer at the FFI boundary.
///
/// The secret-scrub `ZeroOnDrop` guards below wipe caller buffers (BIP-39
/// phrases, passwords) that Rust never reads again. A plain `write_bytes`
/// (memset) on a never-again-read buffer is a dead store the optimizer is
/// permitted to ELIDE — defeating the very scrub the guard exists for. Writing
/// each byte through `write_volatile` forbids elision, and the `compiler_fence`
/// keeps the stores from being reordered past the guard's drop. NULL `ptr` (or
/// `len == 0`) is a no-op.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes, or be NULL.
unsafe fn volatile_wipe(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    for i in 0..len {
        unsafe { core::ptr::write_volatile(ptr.add(i), 0u8) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// detect FFI re-entry from inside a Tokio worker
/// thread (e.g. from a recv-handler callback) and refuse to proceed.
///
/// Returns `true` iff the current thread is already executing inside a
/// Tokio runtime context. Calling `runtime.block_on(...)` or
/// `tokio_mutex.blocking_lock` from such a thread would deadlock the
/// worker. Every FFI entry point that performs a synchronous
/// `block_on` must call this before doing so and surface
/// [`VEIL_ERR_REENTRANT`] when it returns `true`.
fn in_tokio_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

/// Build a tokio multi-threaded runtime sized for mobile/desktop hosts.
///
/// Worker threads = `min(cpu_count, 4)` — small enough to keep RSS low
/// on a budget Android device, large enough to overlap I/O on multi-core.
fn build_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().min(4))
        .unwrap_or(2);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .thread_name("veil-ffi")
        .build()
}

// ── Lifecycle: free string, connect, close ───────────────────────────────────

/// Free a C string returned by this library (error messages, etc.).
/// Safe to call on NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

/// Connect to an veil daemon's IPC socket and perform the APP_HELLO
/// handshake. Returns an opaque [`VeilHandle`] on success, NULL on
/// failure (with `*err_out` set).
///
/// `socket_path` is treated as an anchor — see
/// [`veilclient::VeilClient::connect`] for backend discovery rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_connect(
    socket_path: *const u8,
    socket_path_len: usize,
    err_out: *mut *mut c_char,
) -> *mut VeilHandle {
    if unsafe { guard::ffi_prelude(err_out, "veil_connect") }.is_err() {
        return ptr::null_mut();
    }
    // Explicit-length text ABI: `(ptr, len)` UTF-8, validated by `slice_to_str`
    // (None on NULL, over-cap, or invalid UTF-8) — no NUL terminator required.
    let Some(path) = (unsafe { slice_to_str(socket_path, socket_path_len) }) else {
        unsafe {
            write_err(err_out, "socket_path is NULL or not valid UTF-8");
        }
        return ptr::null_mut();
    };
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("failed to create tokio runtime: {e}"));
            }
            return ptr::null_mut();
        }
    };
    let client_res = runtime.block_on(async { VeilClient::connect(path).await });
    let client = match client_res {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("connect failed: {e}"));
            }
            return ptr::null_mut();
        }
    };
    let bundle = Arc::new(RuntimeBundle {
        runtime: std::mem::ManuallyDrop::new(runtime),
        client: TokioMutex::new(client),
        pending_mailbox_fetch: StdMutex::new(None),
    });
    HandleTable::insert(
        handle_table(),
        VeilHandle {
            bundle,
            event_task: StdMutex::new(None),
            anon_hub: TokioMutex::new(None),
        },
    ) as *mut VeilHandle
}

/// Release the handle. Outstanding apps / streams keep the runtime
/// alive via their own `Arc`; the runtime is dropped only when the last
/// reference goes away. Safe to call on NULL.
///
/// Defends against double-free. A NULL / already-freed / garbage / wrong-type
/// token is absent from the generational handle table → safe no-op; the
/// (opaque, non-pointer) token is never dereferenced (see [`HandleTable`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_close(handle: *mut VeilHandle) {
    if handle.is_null() {
        return;
    }
    // Claim the live entry from the generational table. A double-close /
    // already-freed / garbage / wrong-type token is absent → safe no-op, and
    // the (opaque) token is never dereferenced as a pointer.
    let Some(h) = HandleTable::remove(handle_table(), handle as usize) else {
        return;
    };
    if let Ok(mut guard) = h.event_task.lock()
        && let Some(task) = guard.take()
    {
        task.abort();
    }
    drop(h);
}

// ── App binding ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
unsafe fn bind_internal(
    handle: *mut VeilHandle,
    namespace: *const u8,
    namespace_len: usize,
    name: *const u8,
    name_len: usize,
    endpoint_id: u32,
    err_out: *mut *mut c_char,
    named: bool,
    capability: bool,
) -> *mut VeilApp {
    if unsafe { guard::ffi_prelude(err_out, "veil_bind") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "handle" => handle,
    );
    // namespace / name: explicit-length UTF-8 (None on NULL/over-cap/invalid).
    let Some(ns) = (unsafe { slice_to_str(namespace, namespace_len) }) else {
        unsafe {
            write_err(err_out, "namespace is NULL or invalid UTF-8");
        }
        return ptr::null_mut();
    };
    let Some(nm) = (unsafe { slice_to_str(name, name_len) }) else {
        unsafe {
            write_err(err_out, "name is NULL or invalid UTF-8");
        }
        return ptr::null_mut();
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        ptr::null_mut(),
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let bind_res: Result<AppHandle, ClientError> = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        if capability {
            client.bind_capability(ns, nm, endpoint_id).await
        } else if named {
            client.bind_named(ns, nm, endpoint_id).await
        } else {
            client.bind(ns, nm, endpoint_id).await
        }
    });
    let app_handle = match bind_res {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("bind failed: {e}"));
            }
            return ptr::null_mut();
        }
    };
    let app_id = *app_handle.app_id();
    let ep_id = app_handle.endpoint_id();
    // split immediately so `set_recv_handler` doesn't
    // need to do anything destructive to the send half.
    let (sender, receiver) = app_handle.into_split();
    // Split the receiver into its datagram + stream channels so each is drained
    // by an independent owner (recv task vs veil_stream_accept).
    let (msg_rx, inbound_streams) = receiver.into_parts();
    let app = VeilApp {
        bundle,
        sender: Arc::new(TokioMutex::new(Some(sender))),
        msg_rx: TokioMutex::new(Some(msg_rx)),
        inbound_streams: TokioMutex::new(Some(inbound_streams)),
        recv_cb: Arc::new(StdMutex::new(None)),
        app_id,
        endpoint_id: ep_id,
        recv_task: StdMutex::new(None),
    };
    HandleTable::insert(app_table(), app) as *mut VeilApp
}

/// Bind an ephemeral application endpoint. Returns NULL on failure
/// (see `*err_out`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_bind(
    handle: *mut VeilHandle,
    namespace: *const u8,
    namespace_len: usize,
    name: *const u8,
    name_len: usize,
    endpoint_id: u32,
    err_out: *mut *mut c_char,
) -> *mut VeilApp {
    unsafe {
        bind_internal(
            handle,
            namespace,
            namespace_len,
            name,
            name_len,
            endpoint_id,
            err_out,
            false,
            false,
        )
    }
}

/// Bind a well-known persistent application endpoint. Returns NULL on
/// failure (see `*err_out`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_bind_named(
    handle: *mut VeilHandle,
    namespace: *const u8,
    namespace_len: usize,
    name: *const u8,
    name_len: usize,
    endpoint_id: u32,
    err_out: *mut *mut c_char,
) -> *mut VeilApp {
    unsafe {
        bind_internal(
            handle,
            namespace,
            namespace_len,
            name,
            name_len,
            endpoint_id,
            err_out,
            true,
            false,
        )
    }
}

/// Bind a stable high-entropy capability alias whose app id is independent of
/// the local sovereign node id. Returns NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_bind_capability(
    handle: *mut VeilHandle,
    namespace: *const u8,
    namespace_len: usize,
    name: *const u8,
    name_len: usize,
    endpoint_id: u32,
    err_out: *mut *mut c_char,
) -> *mut VeilApp {
    unsafe {
        bind_internal(
            handle,
            namespace,
            namespace_len,
            name,
            name_len,
            endpoint_id,
            err_out,
            false,
            true,
        )
    }
}

/// Copy the bound `app_id` (32 bytes) into `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_app_get_app_id(app: *const VeilApp, out: *mut u8) -> c_int {
    if app.is_null() || out.is_null() {
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        app_ref,
        app_table(),
        app,
        ptr::null_mut(),
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    unsafe {
        ptr::copy_nonoverlapping(app_ref.app_id.as_ptr(), out, 32);
    }
    VEIL_OK
}

/// Return the bound endpoint id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_app_get_endpoint_id(app: *const VeilApp) -> u32 {
    if app.is_null() {
        return 0;
    }
    get_or_return!(app_ref, app_table(), app, ptr::null_mut(), 0, "VeilApp");
    app_ref.endpoint_id
}

/// Close an app endpoint. Aborts any active recv loop and releases
/// resources. Safe to call on NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_app_close(app: *mut VeilApp) {
    if app.is_null() {
        return;
    }
    // double-free / ABA / concurrent-use guard via the generational table
    // (see [`veil_close`]).
    let Some(app_box) = HandleTable::remove(app_table(), app as usize) else {
        return;
    };
    if let Ok(mut guard) = app_box.recv_task.lock()
        && let Some(task) = guard.take()
    {
        task.abort();
    }
    // `AppSender::Drop` is deliberately best-effort when no Tokio runtime is
    // entered, which is exactly the normal Dart/FFI close context. Before this
    // explicit close the local dispatch table and daemon binding survived
    // until the whole VeilClient disconnected, so rebinding a retired public-
    // capability endpoint failed with "already bound on this connection".
    let bundle = Arc::clone(&app_box.bundle);
    let sender = Arc::clone(&app_box.sender);
    bundle.runtime.block_on(async move {
        if let Some(sender) = sender.lock().await.take() {
            sender.close().await;
        }
    });
    drop(app_box);
}

// ── Datagram I/O ─────────────────────────────────────────────────────────────

/// Send a datagram from `app` to `(dst_node_id, dst_app_id, dst_endpoint_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send(
    app: *mut VeilApp,
    dst_node_id: *const u8,
    dst_app_id: *const u8,
    dst_endpoint_id: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_send") } {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
        "dst_node_id" => dst_node_id,
        "dst_app_id" => dst_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // bounds-check caller-supplied len BEFORE any
    // allocation. An untrusted caller passing usize::MAX would
    // trigger a 16 EiB Vec::with_capacity, OOM-killing the host.
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    let mut dst_node = [0u8; 32];
    let mut dst_app = [0u8; 32];
    // SAFETY: caller MUST guarantee that
    // `dst_node_id` and `dst_app_id` each point to a readable region
    // of at least 32 bytes. Both pointers are NULL-checked above;
    // the size contract is documented in the C header. Passing
    // shorter buffers is undefined behaviour — Dart wrappers (see
    // veil_flutter/lib/src/client.dart) always pass 32-byte
    // buffers obtained from `Uint8List(32)`.
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, dst_node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, dst_app.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    // send through the persistent `sender` half — set_recv_handler
    // only takes the receiver, so the sender stays addressable for the entire
    // app lifetime.
    let send_res: Result<(), ClientError> = app_ref.bundle.runtime.block_on(async {
        let inner_guard = app_ref.sender.lock().await;
        let Some(sender) = inner_guard.as_ref() else {
            return Err(ClientError::Protocol("app already closed".to_string()));
        };
        sender
            .send(dst_node, dst_app, dst_endpoint_id, &payload)
            .await
    });
    match send_res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(err_out, format!("send failed: {s}"));
            }
            // `ClientError::Protocol` renders as "protocol error: {msg}", so an
            // exact `==` never matched the closed sentinel and the signal
            // silently degraded to VEIL_ERR. Use substring match, consistent
            // with the stream-close paths (`.contains("stream already closed")`).
            if s.contains("app already closed") {
                VEIL_ERR_CLOSED
            } else {
                VEIL_ERR
            }
        }
    }
}

/// Send an AUTHENTICATED anonymous datagram from `app` to
/// `(dst_node_id, dst_app_id, dst_endpoint_id)`.
///
/// Like [`veil_send`], but routed over the onion/rendezvous transport: no
/// relay learns the sender's network location, while the recipient
/// cryptographically verifies WHO sent it. v1: one-way; fire-and-forget
/// (`VEIL_OK` means accepted + handed to the first hop, NOT delivery-
/// confirmed); the recipient must have opted in to receiving
/// (`[anonymity].receive_anonymous`). The sender node needs a sovereign
/// identity. Large messages are fragmented up to a fixed ceiling.
///
/// Because the return value reports only local acceptance, an asynchronous
/// send failure (no route, terminal NACK) surfaces LATER as an
/// `ANON_SEND_FAILED` event (diff-audit L7), not as an error return here.
/// There is no end-to-end ACK, so absence of that event is not proof of
/// delivery.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_anonymous_authenticated(
    app: *mut VeilApp,
    dst_node_id: *const u8,
    dst_app_id: *const u8,
    dst_endpoint_id: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_send_anonymous_authenticated") } {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
        "dst_node_id" => dst_node_id,
        "dst_app_id" => dst_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    let mut dst_node = [0u8; 32];
    let mut dst_app = [0u8; 32];
    // SAFETY: as in `veil_send` — caller guarantees both pointers are
    // readable for 32 bytes (NULL-checked above; size per the C header).
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, dst_node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, dst_app.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let send_res: Result<(), ClientError> = app_ref.bundle.runtime.block_on(async {
        let inner_guard = app_ref.sender.lock().await;
        let Some(sender) = inner_guard.as_ref() else {
            return Err(ClientError::Protocol("app already closed".to_string()));
        };
        sender
            .send_anonymous_authenticated(dst_node, dst_app, dst_endpoint_id, &payload)
            .await
    });
    match send_res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(err_out, format!("authenticated anonymous send failed: {s}"));
            }
            if s.contains("app already closed") {
                VEIL_ERR_CLOSED
            } else {
                VEIL_ERR
            }
        }
    }
}

/// Like [`veil_send_anonymous_authenticated`], but additionally attach a
/// one-time reply block so the recipient can answer WITHOUT either side
/// publishing a public rendezvous ad (no presence leak). The reply is delivered
/// back to `(this app, reply_endpoint_id)` and surfaces to the recipient as a
/// non-zero `reply_id` in the recv callback. Pass the endpoint you receive on
/// for `reply_endpoint_id`. Same fire-and-forget semantics as the plain
/// authenticated send.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_anonymous_authenticated_with_reply(
    app: *mut VeilApp,
    dst_node_id: *const u8,
    dst_app_id: *const u8,
    dst_endpoint_id: u32,
    reply_endpoint_id: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) =
        unsafe { guard::ffi_prelude(err_out, "veil_send_anonymous_authenticated_with_reply") }
    {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
        "dst_node_id" => dst_node_id,
        "dst_app_id" => dst_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    let mut dst_node = [0u8; 32];
    let mut dst_app = [0u8; 32];
    // SAFETY: as in `veil_send_anonymous_authenticated`.
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, dst_node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, dst_app.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let send_res: Result<(), ClientError> = app_ref.bundle.runtime.block_on(async {
        let inner_guard = app_ref.sender.lock().await;
        let Some(sender) = inner_guard.as_ref() else {
            return Err(ClientError::Protocol("app already closed".to_string()));
        };
        sender
            .send_anonymous_authenticated_with_reply(
                dst_node,
                dst_app,
                dst_endpoint_id,
                reply_endpoint_id,
                &payload,
            )
            .await
    });
    match send_res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(err_out, format!("authenticated anonymous send failed: {s}"));
            }
            if s.contains("app already closed") {
                VEIL_ERR_CLOSED
            } else {
                VEIL_ERR
            }
        }
    }
}

/// Like [`veil_send_anonymous_authenticated_with_reply`], but the caller GIVES
/// the relay's KEM key (`dst_x25519_pk`, 32 bytes) directly — so the daemon
/// routes the source-routed onion straight to `(dst_node_id, dst_x25519_pk)`
/// with NO rendezvous-ad self-resolve (the flaky lookup that returned
/// `NoRendezvous`). Still authenticated (the relay verifies the sender) and
/// still attaches a one-time reply block delivered back to
/// `(this app, reply_endpoint_id)`. This is the KEM-key-given mailbox FETCH;
/// `dst_x25519_pk` is a PUBLIC key (the relay's published KEM key). All three
/// `dst_*` arrays are 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_anonymous_authenticated_direct_with_reply(
    app: *mut VeilApp,
    dst_node_id: *const u8,
    dst_x25519_pk: *const u8,
    dst_app_id: *const u8,
    dst_endpoint_id: u32,
    reply_endpoint_id: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe {
        guard::ffi_prelude(
            err_out,
            "veil_send_anonymous_authenticated_direct_with_reply",
        )
    } {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
        "dst_node_id" => dst_node_id,
        "dst_x25519_pk" => dst_x25519_pk,
        "dst_app_id" => dst_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    let mut dst_node = [0u8; 32];
    let mut dst_x25519 = [0u8; 32];
    let mut dst_app = [0u8; 32];
    // SAFETY: all three pointers NULL-checked above; caller guarantees 32
    // readable bytes each (size per the C header).
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, dst_node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_x25519_pk, dst_x25519.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, dst_app.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let send_res: Result<(), ClientError> = app_ref.bundle.runtime.block_on(async {
        let inner_guard = app_ref.sender.lock().await;
        let Some(sender) = inner_guard.as_ref() else {
            return Err(ClientError::Protocol("app already closed".to_string()));
        };
        sender
            .send_anonymous_authenticated_direct_with_reply(
                dst_node,
                dst_x25519,
                dst_app,
                dst_endpoint_id,
                reply_endpoint_id,
                &payload,
            )
            .await
    });
    match send_res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(
                    err_out,
                    format!("authenticated anonymous direct send failed: {s}"),
                );
            }
            if s.contains("app already closed") {
                VEIL_ERR_CLOSED
            } else {
                VEIL_ERR
            }
        }
    }
}

/// Reply to a message received over the authenticated anonymous transport,
/// addressing it by the opaque `reply_id` from the recv callback. The daemon
/// routes the reply back over the original sender's rendezvous path — no public
/// ad on either side. `reply_id` is TTL-bounded daemon-side and may be replied
/// to MORE THAN ONCE until it expires (the daemon peeks the reply block, it does
/// not consume it) — deduplicate at the app layer if needed; a stale/unknown id
/// returns `VEIL_ERR` with a "reply unknown" detail. Same fire-and-forget
/// semantics as the other authenticated sends.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_reply(
    app: *mut VeilApp,
    reply_id: u64,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_send_reply") } {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if reply_id == 0 {
        unsafe {
            write_err(err_out, "reply_id is 0 (not a repliable message)");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let send_res: Result<(), ClientError> = app_ref.bundle.runtime.block_on(async {
        let inner_guard = app_ref.sender.lock().await;
        let Some(sender) = inner_guard.as_ref() else {
            return Err(ClientError::Protocol("app already closed".to_string()));
        };
        sender.reply(reply_id, &payload).await
    });
    match send_res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(err_out, format!("reply send failed: {s}"));
            }
            if s.contains("app already closed") {
                VEIL_ERR_CLOSED
            } else {
                VEIL_ERR
            }
        }
    }
}

/// Recv callback signature — invoked from a tokio worker thread.
///
/// BUFFER OWNERSHIP (cycle-7 H6): the three pointers (`src_node_id`,
/// `src_app_id`, `data`) are offsets into ONE heap buffer the callee now OWNS:
/// `src_node_id` is the base, laid out `[node_id(32) | app_id(32) | data]`. The
/// host MAY retain the pointers past this synchronous call (e.g. marshal them to
/// another thread/isolate and copy later) and MUST, exactly once per non-NULL
/// invocation, call `veil_free_buf(src_node_id, 64 + data_len)` after copying.
/// This replaces the old "valid for the call only; copy synchronously" contract
/// that a deferred host (Dart `NativeCallable.listener`) could not honour
/// without a use-after-free.
///
/// `reply_id` is a by-value scalar (NOT part of the owned buffer — it has no
/// lifetime to manage): non-zero when this message arrived over the
/// authenticated anonymous transport WITH a one-time reply block. Pass it to
/// [`veil_send_reply`] to answer without either side publishing a public
/// rendezvous ad. `0` means "not repliable".
///
/// wrapped in `Option<...>` so a NULL
/// function pointer passed from C/Swift/Kotlin is a valid `None`
/// representation that Rust matches and rejects gracefully — instead
/// of being silently treated as a valid `unsafe extern "C" fn(...)`
/// (which Rust assumes non-nullable, leading to UB on dereference
/// before `catch_unwind` could intervene).
pub type VeilRecvCb = Option<
    unsafe extern "C" fn(
        user: *mut std::ffi::c_void,
        src_node_id: *const u8, // 32 bytes
        src_app_id: *const u8,  // 32 bytes
        reply_id: u64,          // 0 = not repliable
        data: *const u8,
        len: size_t,
    ),
>;

/// A currently-installed recv callback plus its opaque `user` pointer, the
/// latter transported as `usize` so the slot is `Send` (the caller's contract
/// guarantees `user` outlives the recv loop). Audit cycle-6 (P6): the recv
/// task reads from this swappable slot each message, so `set_recv_handler` can
/// REPLACE the handler on every call by swapping the slot — fixing the bug
/// where the first call moved the receiver into the task and the second found
/// it gone (`VEIL_ERR_CLOSED`). Copied out per message so the lock is never
/// held across the C callback.
#[derive(Clone, Copy)]
struct RecvCbSlot {
    cb: unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, *const u8, u64, *const u8, size_t),
    user_addr: usize,
}

/// Install a recv handler that calls `cb` for every incoming datagram on this
/// app. Returns [`VEIL_OK`] once the handler is installed.
///
/// A single persistent recv loop runs on the runtime and dispatches to the
/// currently-installed callback. Calling `set_recv_handler` again REPLACES the
/// handler (the callback is swapped atomically; no in-flight messages are
/// lost, and the call succeeds on every invocation). [`veil_send`] continues
/// to work throughout via the bundle reference.
///
/// `user` is an opaque pointer passed to every callback invocation. The caller
/// MUST keep EVERY `user` it ever passes to `set_recv_handler` valid until
/// [`veil_app_close`] — NOT merely until the next `set_recv_handler` call.
/// Replacing the handler swaps the slot, but a message dispatch that already
/// copied the *previous* `(cb, user)` may still be running on a runtime thread
/// when the replacing call returns; that in-flight callback dereferences the
/// old `user`. There is no signal back to the caller for when such a dispatch
/// completes, so the only safe contract is "valid until close". (This is the
/// same exposure the pre-swap design had — `abort()` was never synchronous —
/// now stated precisely.)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_app_set_recv_handler(
    app: *mut VeilApp,
    cb: VeilRecvCb,
    user: *mut std::ffi::c_void,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_app_set_recv_handler") } {
        return rc;
    }
    null_check!(err_out,
        "app" => app,
    );
    // audit: callback was retyped to `Option<fn>` so NULL
    // becomes a valid `None` representation that we can detect and
    // reject gracefully — pre-fix a raw `unsafe extern "C" fn` would
    // be silently dereferenced (segfault, NOT a panic, so catch_unwind
    // could not intercept).
    let cb_fn = match cb {
        Some(f) => f,
        None => {
            unsafe {
                write_err(err_out, "callback is NULL");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilApp"
    );

    // audit cycle-6 (P6): install/replace the callback by swapping the shared
    // slot. A SINGLE persistent recv task (spawned below on the first call)
    // owns the receiver and dispatches each message to whatever callback is
    // currently in this slot. The previous design moved the receiver INTO the
    // task and aborted it on replace, so a second `set_recv_handler` found the
    // receiver gone and returned VEIL_ERR_CLOSED — breaking the documented
    // "calling set_recv_handler again replaces it" contract. Swapping the slot
    // replaces the handler on every call, with no lost in-flight messages.
    // FFI pointers are not Send, so `user` is transported as `usize`; the
    // caller's contract is that `user` outlives the recv loop.
    {
        let mut slot = app_ref.recv_cb.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(RecvCbSlot {
            cb: cb_fn,
            user_addr: user as usize,
        });
    }

    // Spawn the persistent recv task exactly once. Lock acquisition order here
    // is recv_cb (released above, line ~744) → receiver (TokioMutex) → recv_task
    // (StdMutex). The only other site that takes any of these is
    // `veil_app_close`, which takes ONLY recv_task — so there is no lock-order
    // inversion. (A future change that locks `receiver` while holding `recv_task`
    // would introduce one; keep this ordering.) If the task already exists, the
    // swap above is all that's needed.
    let mut receiver_guard = app_ref.msg_rx.blocking_lock();
    let mut task_guard = app_ref.recv_task.lock().unwrap_or_else(|e| e.into_inner());
    if task_guard.is_none() {
        let mut msg_rx = match receiver_guard.take() {
            Some(r) => r,
            None => {
                // App already closed before the first handler install. Clear the
                // slot we just wrote so no dangling (cb, user) lingers in the Arc
                // (harmless — no task reads it — but cleaner).
                *app_ref.recv_cb.lock().unwrap_or_else(|e| e.into_inner()) = None;
                unsafe {
                    write_err(err_out, "app already closed");
                }
                return VEIL_ERR_CLOSED;
            }
        };
        let cb_cell = Arc::clone(&app_ref.recv_cb);
        let task = app_ref.bundle.runtime.spawn(async move {
            while let Some(IncomingMessage {
                src_node_id,
                src_app_id,
                data,
                reply_id,
                ..
            }) = msg_rx.recv().await
            {
                // Copy the current callback out of the slot; never hold the
                // lock across the C callback.
                let Some(RecvCbSlot { cb, user_addr }) =
                    *cb_cell.lock().unwrap_or_else(|e| e.into_inner())
                else {
                    continue; // no handler currently installed — drop the frame
                };
                let user_ptr = user_addr as *mut std::ffi::c_void;
                // Best-effort catch_unwind around the host callback. NOTE: this
                // only intercepts a panic raised on the RUST side of this
                // closure — a panic/exception propagating OUT of the host `cb`
                // across the C-ABI frame is undefined behaviour that catch_unwind
                // cannot catch; the host callback MUST NOT unwind (contract).
                // Under the release `panic=abort` profile a Rust panic aborts
                // regardless, so the guard is meaningful only in unwinding
                // (dev/test) builds, where it logs + drops the message and keeps
                // the recv loop alive instead of poisoning it.
                // cycle-7 H6: the host callback may read these pointers AFTER
                // this Rust frame returns (e.g. Dart `NativeCallable.listener`
                // marshals the args to the isolate and copies them later). The
                // `data` Vec and the stack `src_*` arrays would be gone by then —
                // a use-after-free. Hand the callee ONE owned heap buffer laid
                // out `[node_id(32) | app_id(32) | data]`; the three pointers are
                // offsets into it and it stays valid until the callee calls
                // `veil_free_buf(node_id_ptr, 64 + data_len)`.
                let data_len = data.len();
                let total_len = 64 + data_len;
                let mut combined: Vec<u8> = Vec::with_capacity(total_len);
                combined.extend_from_slice(&src_node_id);
                combined.extend_from_slice(&src_app_id);
                combined.extend_from_slice(&data);
                let base: *mut u8 = Box::into_raw(combined.into_boxed_slice()).cast();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    cb(
                        user_ptr,
                        base.cast_const(),         // src_node_id (32 bytes)
                        base.add(32).cast_const(), // src_app_id  (32 bytes)
                        reply_id,                  // 0 = not repliable
                        base.add(64).cast_const(), // data        (data_len bytes)
                        data_len,
                    );
                }));
                if result.is_err() {
                    // The callee panicked before it could take ownership / free —
                    // reclaim the buffer so it doesn't leak on the dev/test
                    // unwinding path (release `panic=abort` never reaches here).
                    unsafe {
                        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                            base, total_len,
                        )));
                    }
                    ffi_diag(
                        "[veilclient-ffi] recv-handler callback panicked; \
                         frame dropped, channel kept open",
                    );
                }
            }
        });
        *task_guard = Some(task);
    }
    VEIL_OK
}

// ── Streams ──────────────────────────────────────────────────────────────────

/// Open a reliable byte-stream to a remote endpoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_stream_open(
    app: *mut VeilApp,
    dst_node_id: *const u8,
    dst_app_id: *const u8,
    dst_endpoint_id: u32,
    initial_window: u32,
    err_out: *mut *mut c_char,
) -> *mut VeilStreamFfi {
    if unsafe { guard::ffi_prelude(err_out, "veil_stream_open") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "app" => app,
        "dst_node_id" => dst_node_id,
        "dst_app_id" => dst_app_id,
    );
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        ptr::null_mut(),
        "VeilApp"
    );
    let mut dst_node = [0u8; 32];
    let mut dst_app = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, dst_node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, dst_app.as_mut_ptr(), 32);
    }
    // stream opens go through the persistent sender too.
    let stream_res = app_ref.bundle.runtime.block_on(async {
        let inner_guard = app_ref.sender.lock().await;
        let Some(sender) = inner_guard.as_ref() else {
            return Err(ClientError::Protocol("app already closed".to_string()));
        };
        sender
            .open_stream(dst_node, dst_app, dst_endpoint_id, initial_window)
            .await
    });
    let sdk_stream = match stream_res {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("stream open failed: {e}"));
            }
            return ptr::null_mut();
        }
    };
    let (rd, wr) = tokio::io::split(sdk_stream);
    let stream = VeilStreamFfi {
        bundle: Arc::clone(&app_ref.bundle),
        reader: TokioMutex::new(Some(rd)),
        writer: TokioMutex::new(Some(wr)),
    };
    HandleTable::insert(stream_table(), stream) as *mut VeilStreamFfi
}

/// Block up to `timeout_ms` for a remote peer to open an inbound byte-stream to
/// a bound endpoint. On success returns an owned stream handle (drive it with
/// `veil_stream_read`/`veil_stream_write`/`veil_stream_close`) and writes the
/// initiator's 32-byte node_id into `out_src_node_id` (caller-allocated, 32 B).
/// Returns NULL on TIMEOUT with NO error written, so the caller can poll in a
/// loop; returns NULL WITH an error on a fatal condition (app closed / the
/// inbound-stream channel went away). This is the receive-side counterpart to
/// `veil_stream_open` — without it an inbound stream is stranded in the SDK.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_stream_accept(
    app: *mut VeilApp,
    timeout_ms: u64,
    out_src_node_id: *mut u8,
    err_out: *mut *mut c_char,
) -> *mut VeilStreamFfi {
    if unsafe { guard::ffi_prelude(err_out, "veil_stream_accept") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "app" => app,
        "out_src_node_id" => out_src_node_id,
    );
    get_or_return!(
        app_ref,
        app_table(),
        app,
        err_out,
        ptr::null_mut(),
        "VeilApp"
    );
    // Drain the inbound-stream channel with a bounded wait. Holding the lock
    // across the await serializes accept calls — fine: a single accept loop owns
    // the receive side. A modest timeout lets the Dart caller poll/abort.
    let accepted = app_ref.bundle.runtime.block_on(async {
        let mut guard = app_ref.inbound_streams.lock().await;
        let Some(rx) = guard.as_mut() else {
            return Err("inbound-stream receiver gone (app closed)".to_string());
        };
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx.recv()).await {
            Ok(Some(incoming)) => Ok(Some(incoming)),
            Ok(None) => Err("inbound-stream channel closed".to_string()),
            Err(_elapsed) => Ok(None), // timeout — caller polls again
        }
    });
    match accepted {
        Ok(Some(incoming)) => {
            unsafe {
                ptr::copy_nonoverlapping(incoming.src_node_id.as_ptr(), out_src_node_id, 32);
            }
            let (rd, wr) = tokio::io::split(incoming.stream);
            let stream = VeilStreamFfi {
                bundle: Arc::clone(&app_ref.bundle),
                reader: TokioMutex::new(Some(rd)),
                writer: TokioMutex::new(Some(wr)),
            };
            HandleTable::insert(stream_table(), stream) as *mut VeilStreamFfi
        }
        Ok(None) => ptr::null_mut(), // timeout — not an error
        Err(e) => {
            unsafe {
                write_err(err_out, e);
            }
            ptr::null_mut()
        }
    }
}

/// XChaCha20-Poly1305 AEAD seal of `plaintext` under a 32-byte `key` + 24-byte
/// `nonce` (no associated data). Writes the ciphertext+tag to a freshly
/// allocated buffer (`*out_buf`/`*out_len`); free it with `veil_free_buf`. Used
/// by the host to encrypt large file blobs stored OUTSIDE the deniable container
/// under a key derived from the unlocked container — the blob is opaque
/// ciphertext at rest. Crypto stays in audited Rust; the key never persists.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_seal(
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: size_t,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_seal") } {
        return rc;
    }
    null_check!(err_out, "key" => key, "nonce" => nonce, "out_buf" => out_buf, "out_len" => out_len);
    unsafe {
        *out_buf = ptr::null_mut();
        *out_len = 0;
    }
    let pt: &[u8] = if plaintext_len == 0 {
        &[]
    } else {
        null_check!(err_out, "plaintext" => plaintext);
        unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) }
    };
    unsafe { aead_run(true, key, nonce, pt, out_buf, out_len, err_out) }
}

/// Inverse of [`veil_seal`]: XChaCha20-Poly1305 open. Fails (VEIL_ERR) on a bad
/// key/nonce/tag. Output (plaintext) buffer freed via `veil_free_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_unseal(
    key: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: size_t,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_unseal") } {
        return rc;
    }
    null_check!(err_out, "key" => key, "nonce" => nonce, "ciphertext" => ciphertext,
        "out_buf" => out_buf, "out_len" => out_len);
    unsafe {
        *out_buf = ptr::null_mut();
        *out_len = 0;
    }
    let ct = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    unsafe { aead_run(false, key, nonce, ct, out_buf, out_len, err_out) }
}

/// Shared XChaCha20-Poly1305 core for [`veil_seal`]/[`veil_unseal`]. `seal=true`
/// encrypts, `false` decrypts. Returns the result in a heap buffer.
unsafe fn aead_run(
    seal: bool,
    key: *const u8,
    nonce: *const u8,
    input: &[u8],
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let mut key_arr = [0u8; 32];
    let mut nonce_arr = [0u8; 24];
    unsafe {
        ptr::copy_nonoverlapping(key, key_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(nonce, nonce_arr.as_mut_ptr(), 24);
    }
    let cipher = XChaCha20Poly1305::new((&key_arr).into());
    let xn = XNonce::from_slice(&nonce_arr);
    let res = if seal {
        cipher.encrypt(xn, input)
    } else {
        cipher.decrypt(xn, input)
    };
    match res {
        Ok(out) => {
            let boxed: Box<[u8]> = out.into_boxed_slice();
            let len = boxed.len();
            let p = Box::into_raw(boxed) as *mut u8;
            unsafe {
                *out_buf = p;
                *out_len = len;
            }
            VEIL_OK
        }
        Err(_) => {
            unsafe {
                write_err(
                    err_out,
                    if seal {
                        "seal failed"
                    } else {
                        "unseal failed (bad key/nonce/tag)"
                    },
                );
            }
            VEIL_ERR
        }
    }
}

/// Write `len` bytes to the stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_stream_write(
    stream: *mut VeilStreamFfi,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_stream_write") } {
        return rc;
    }
    null_check!(err_out,
        "stream" => stream,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // mirror the veil_send bounds-check.
    // veil_stream_write is the streaming sibling of veil_send;
    // both copy `len` bytes from caller memory into a fresh Vec. Without
    // this guard a caller passing usize::MAX OOM-kills the host before
    // any peer-side limit applies.
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        stream_ref,
        stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilStreamFfi"
    );
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let res: std::io::Result<()> = stream_ref.bundle.runtime.block_on(async {
        // Locks only the WRITE half — independent of an in-flight read (H4).
        let mut wguard = stream_ref.writer.lock().await;
        let Some(w) = wguard.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "stream already closed",
            ));
        };
        // write_all via AsyncWrite chunks at MAX_STREAM_CHUNK + is backpressure-
        // aware (vs send_data's single unchunked frame); poll_flush is a no-op.
        w.write_all(&payload).await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(err_out, format!("stream write failed: {s}"));
            }
            if s.contains("stream already closed") {
                VEIL_ERR_CLOSED
            } else {
                VEIL_ERR
            }
        }
    }
}

/// Read up to `cap` bytes from the stream into `buf`. Returns the
/// number of bytes read, 0 on EOF, or a negative error code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_stream_read(
    stream: *mut VeilStreamFfi,
    buf: *mut u8,
    cap: size_t,
    err_out: *mut *mut c_char,
) -> ssize_t {
    // ssize_t return type — ffi_prelude returns c_int; cast at the boundary.
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_stream_read") } {
        return rc as ssize_t;
    }
    // null_check_with_default not supports ssize_t directly; inline check.
    if stream.is_null() || buf.is_null() {
        unsafe {
            write_err(err_out, "stream or buf is NULL");
        }
        return VEIL_ERR_INVALID_ARG as ssize_t;
    }
    if cap == 0 {
        return 0;
    }
    // cap pre-allocation so that
    // a malicious / buggy caller passing huge `cap` (e.g. accidentally
    // SIZE_MAX from a sentinel mismatch) cannot trigger a multi-GiB
    // allocation that hard-OOMs the host process. Mirrors the
    // existing `veil_send` cap pattern. Caller with a legitimate
    // need for a bigger buffer can call `veil_stream_read` in a
    // loop — streaming guarantees nothing about chunk boundaries
    // anyway.
    if cap > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("stream_read cap {cap} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})",),
            );
        }
        return VEIL_ERR_INVALID_ARG as ssize_t;
    }
    get_or_return!(
        stream_ref,
        stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG as ssize_t,
        "VeilStreamFfi"
    );
    let mut local_buf = vec![0u8; cap];
    let read_res: std::io::Result<usize> = stream_ref.bundle.runtime.block_on(async {
        // Locks only the READ half — a parked read no longer blocks writes (H4).
        let mut rguard = stream_ref.reader.lock().await;
        let Some(r) = rguard.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "stream already closed",
            ));
        };
        r.read(&mut local_buf).await
    });
    match read_res {
        Ok(n) => {
            // n == 0 indicates EOF per AsyncRead contract.
            if n > 0 {
                unsafe {
                    ptr::copy_nonoverlapping(local_buf.as_ptr(), buf, n);
                }
            }
            n as ssize_t
        }
        Err(e) => {
            let s = e.to_string();
            unsafe {
                write_err(err_out, format!("stream read failed: {s}"));
            }
            if s.contains("stream already closed") {
                VEIL_ERR_CLOSED as ssize_t
            } else {
                VEIL_ERR as ssize_t
            }
        }
    }
}

/// Close the stream and free its resources. Safe to call on NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_stream_close(stream: *mut VeilStreamFfi) {
    if stream.is_null() {
        return;
    }
    // Remove from the generational table (see [`veil_close`]); the returned
    // Arc (if any) drops here. In-flight calls that already cloned it keep the
    // stream alive until they finish.
    drop(HandleTable::remove(stream_table(), stream as usize));
}

// ── Mobile lifecycle events ─────────────────────────────

/// Background-mode tier values [`veil_set_background_mode`].
/// Mirrors `MobileBackgroundMode` on the wire (0/1/2 byte).
pub const VEIL_BG_FOREGROUND: c_int = 0;
pub const VEIL_BG_ACTIVE: c_int = 1;
pub const VEIL_BG_LOWPOWER: c_int = 2;

/// Network-kind values [`veil_notify_network_changed`].
pub const VEIL_NET_OFFLINE: c_int = 0;
pub const VEIL_NET_WIFI: c_int = 1;
pub const VEIL_NET_CELLULAR: c_int = 2;
pub const VEIL_NET_ETHERNET: c_int = 3;
pub const VEIL_NET_UNKNOWN: c_int = 255;

/// Push-envelope status return codes [`veil_set_push_envelope`].
/// Mirrors `SetPushEnvelopeStatus` on the wire (0/1/2 byte).
pub const VEIL_PUSH_OK: c_int = 0;
pub const VEIL_PUSH_NO_RENDEZVOUS: c_int = 1;
pub const VEIL_PUSH_TOO_LARGE: c_int = 2;

/// Wake-HMAC verdict codes returned by [`veil_verify_wake_hmac`].
/// Mirrors `veil_crypto::wake_hmac::WakePayloadVerdict` so receiver
/// plugins can branch on each failure mode separately (operators care
/// about clock-skew rate as a distinct signal from active forging).
///
/// Slice 4.3.3 of Epic 489.10.
pub const VEIL_WAKE_VERDICT_VALID: c_int = 0;
pub const VEIL_WAKE_VERDICT_TAMPERED: c_int = 1;
pub const VEIL_WAKE_VERDICT_EXPIRED: c_int = 2;
pub const VEIL_WAKE_VERDICT_MALFORMED: c_int = 3;

/// Wake-HMAC key length (32 bytes).  Pinned to
/// `veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN`.
pub const VEIL_WAKE_HMAC_KEY_LEN: size_t = 32;

/// Wake payload total wire size (72 bytes — `ts u64 BE || content_id 32
/// || hmac_tag 32`).  Pinned to `veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN`.
pub const VEIL_WAKE_PAYLOAD_LEN: size_t = 72;

///.4 P0: outcome [`veil_get_relay_x25519_pubkey`].
/// `VEIL_OK` means the daemon is relay-capable and `out_pubkey_32`
/// was populated. `VEIL_RELAY_X25519_UNAVAILABLE` means the daemon
/// is not relay-capable (operator did not opt into
/// `anonymity.relay_capable`) — apps must pick a different relay for
/// push-envelope sealing. Other negative codes are protocol errors.
pub const VEIL_RELAY_X25519_UNAVAILABLE: c_int = -10;

/// Read the daemon's relay-side X25519 public key into `out_pubkey_32`.
/// This is the seal-target for push-envelopes — apps that want to
/// register a sealed FCM/APNs token [`veil_set_push_envelope`]
/// must seal it against THIS exact key.
///
/// Returns:
/// [`VEIL_OK`] — `out_pubkey_32` populated with 32 bytes.
/// [`VEIL_RELAY_X25519_UNAVAILABLE`] — daemon is not relay-
/// capable; pick a different relay or skip push-wake.
/// other negative codes — connection/protocol errors.
///
/// Stable for the lifetime of the daemon process: the relay X25519 key
/// is persisted on disk (`<veil_dir>/device_anonymity_x25519_sk.bin`)
/// and survives restarts. Apps can cache the result.
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
/// `out_pubkey_32` must point to writable storage for at least 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_get_relay_x25519_pubkey(
    handle: *mut VeilHandle,
    out_pubkey_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_get_relay_x25519_pubkey") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_pubkey_32" => out_pubkey_32,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.node_identity().await
    });
    match res {
        Ok(id) => match id.relay_x25519_pubkey {
            Some(pk) => {
                unsafe {
                    ptr::copy_nonoverlapping(pk.as_ptr(), out_pubkey_32, 32);
                }
                VEIL_OK
            }
            None => VEIL_RELAY_X25519_UNAVAILABLE,
        },
        Err(e) => {
            unsafe {
                write_err(err_out, format!("get_relay_x25519_pubkey failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Resolve ANOTHER node's relay X25519 KEM public key by its `node_id`, over the
/// DHT. Unlike [`veil_get_relay_x25519_pubkey`] (which returns the LOCAL node's
/// own key), this asks the daemon to fetch + verify the target's signed
/// `RelayKeyRecord` against its identity document. Lets a receiver advertise an
/// always-on third-party relay as its mailbox host knowing only its node_id.
///
/// Returns:
/// [`VEIL_OK`] — `out_pubkey_32` populated with the verified 32-byte key.
/// [`VEIL_RELAY_X25519_UNAVAILABLE`] — unresolved (DHT miss / no record /
///   verification failed); the node advertises no relay key.
/// other negative codes — connection/protocol errors.
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
/// `node_id_32` must point to 32 readable bytes; `out_pubkey_32` to 32 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_lookup_relay_x25519(
    handle: *mut VeilHandle,
    node_id_32: *const u8,
    out_pubkey_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_lookup_relay_x25519") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "node_id_32" => node_id_32,
        "out_pubkey_32" => out_pubkey_32,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut node_id = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(node_id_32, node_id.as_mut_ptr(), 32);
    }
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.lookup_relay_x25519(node_id).await
    });
    match res {
        Ok(Some(pk)) => {
            unsafe {
                ptr::copy_nonoverlapping(pk.as_ptr(), out_pubkey_32, 32);
            }
            VEIL_OK
        }
        Ok(None) => VEIL_RELAY_X25519_UNAVAILABLE,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("lookup_relay_x25519 failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Register this node as a LOCATION-anonymous (onion) service: the daemon picks
/// relays, builds an onion circuit to a rendezvous relay (which never learns
/// this node's location), and publishes the ad so clients can reach this node by
/// its identity. `hop_count` is clamped to ≥ 2 by the daemon (2 = node→mid→relay).
///
/// `VEIL_OK` once the daemon accepts; `VEIL_ERR` with a detail otherwise (e.g.
/// no relays available yet — retry after a short back-off). Connection-level:
/// hosts the whole node as a service; any bound endpoint can then receive.
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_onion_service(
    handle: *mut VeilHandle,
    hop_count: u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_register_onion_service") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.register_onion_service(hop_count).await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("register_onion_service failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

fn embedded_services_for_bundle(
    bundle: &Arc<RuntimeBundle>,
) -> Result<veil_node_runtime::NodeServices, String> {
    let me = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .node_identity()
            .await
            .map(|identity| identity.node_id)
            .map_err(|e| format!("node_identity: {e}"))
    })?;
    veil_node_runtime::embedded_services_for(&me)
        .or_else(|| {
            let latest = veil_node_runtime::embedded_services()?;
            (latest.local_node_id() == me).then_some(latest)
        })
        .ok_or_else(|| "embedded node services unavailable for this handle".to_string())
}

/// Register a location-anonymous service under a caller-owned random Ed25519
/// seed rather than the node's sovereign key. The seed buffer is writable and
/// is ZEROED immediately on every post-validation path. On success writes the
/// corresponding 32-byte public service identity to `out_identity_vk`; this is
/// the only address that belongs in a public capability link. The blinded DHT
/// descriptor and rendezvous advert contain no sovereign public key/node id.
///
/// Embedded-node only: the service circuit lives in this process's node
/// runtime. Re-register the same seed after restart; registration is idempotent
/// within a descriptor period. At most the runtime's bounded hosted-service cap
/// may be active.
///
/// # Safety
/// `identity_seed_32` must point to 32 WRITABLE bytes; they are zeroized.
/// `out_identity_vk_32` must point to 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_ephemeral_onion_service_zeroize(
    handle: *mut VeilHandle,
    identity_seed_32: *mut u8,
    hop_count: u32,
    out_identity_vk_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) =
        unsafe { guard::ffi_prelude(err_out, "veil_register_ephemeral_onion_service_zeroize") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "identity_seed_32" => identity_seed_32,
        "out_identity_vk_32" => out_identity_vk_32,
    );
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    unsafe {
        ptr::copy_nonoverlapping(identity_seed_32, seed.as_mut_ptr(), 32);
        ptr::write_bytes(identity_seed_32, 0, 32);
    }
    if seed.iter().all(|byte| *byte == 0) {
        unsafe { write_err(err_out, "ephemeral service seed must not be all-zero") };
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let services = match embedded_services_for_bundle(&handle_live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    let public_key = match services.register_ephemeral_onion_service(seed, hop_count as usize) {
        Ok(public_key) => public_key,
        Err(error) => {
            unsafe {
                write_err(
                    err_out,
                    format!("register_ephemeral_onion_service failed: {error:?}"),
                )
            };
            return VEIL_ERR;
        }
    };
    unsafe { ptr::copy_nonoverlapping(public_key.as_ptr(), out_identity_vk_32, 32) };
    VEIL_OK
}

/// Stop maintaining one caller-owned ephemeral onion service. Idempotent:
/// unknown/already-withdrawn public keys return `VEIL_OK` too, so this local
/// lifecycle API never becomes a remote existence oracle. DHT ciphertext and
/// the circuit age out naturally; the host must reject capability requests as
/// soon as its encrypted registry marks the share revoked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_withdraw_ephemeral_onion_service(
    handle: *mut VeilHandle,
    identity_vk_32: *const u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_withdraw_ephemeral_onion_service") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "identity_vk_32" => identity_vk_32,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut public_key = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(identity_vk_32, public_key.as_mut_ptr(), 32) };
    let services = match embedded_services_for_bundle(&handle_live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    services.withdraw_ephemeral_onion_service(public_key);
    VEIL_OK
}

/// Register a PLAIN rendezvous-publisher entry (mailbox-by-discovery): the
/// daemon's maintenance tick signs + publishes a v5 `RendezvousAd` under THIS
/// node's real id at `rendezvous_node_id`'s rendezvous slot, advertising the
/// relay's KEM key so a sender resolving the ad (`veil_lookup_rendezvous_replicas`)
/// can anonymously deposit a mailbox PUT at the relay. Replaces any existing
/// entry with the same `(rendezvous_node_id, auth_cookie)`.
///
/// `relay_kem_algo` is the KEM tag (`0` = X25519); `relay_kem_pk` / `kem_len`
/// the relay's KEM pubkey (32-byte X25519 for algo 0; obtain a self-relay key
/// via `veil_get_relay_x25519_pubkey`). Pass `kem_len = 0` to advertise no key.
///
/// `VEIL_OK` once the daemon records the entry; `VEIL_ERR` otherwise.
///
/// # Safety
/// `handle` must be a live `VeilHandle*`. `rendezvous_node_id` must be readable
/// for 32 bytes, `auth_cookie` for 16. `relay_kem_pk` must be readable for
/// `kem_len` bytes (or NULL iff `kem_len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_rendezvous_publisher(
    handle: *mut VeilHandle,
    rendezvous_node_id: *const u8,
    auth_cookie: *const u8,
    validity_window_secs: u64,
    relay_kem_algo: u8,
    relay_kem_pk: *const u8,
    kem_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_register_rendezvous_publisher") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "rendezvous_node_id" => rendezvous_node_id,
        "auth_cookie" => auth_cookie,
    );
    if relay_kem_pk.is_null() && kem_len > 0 {
        unsafe {
            write_err(err_out, "relay_kem_pk is NULL but kem_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut node_id = [0u8; 32];
    let mut cookie = [0u8; 16];
    // SAFETY: both pointers NULL-checked; caller guarantees the documented byte
    // counts.
    unsafe {
        ptr::copy_nonoverlapping(rendezvous_node_id, node_id.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie.as_mut_ptr(), 16);
    }
    let kem_pk: Vec<u8> = if kem_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(relay_kem_pk, kem_len) }.to_vec()
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .register_rendezvous_publisher(
                node_id,
                cookie,
                validity_window_secs,
                relay_kem_algo,
                kem_pk,
            )
            .await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(
                    err_out,
                    format!("register_rendezvous_publisher failed: {e}"),
                );
            }
            VEIL_ERR
        }
    }
}

/// Send `data` to a LOCATION-anonymous (onion) service addressed by its Ed25519
/// IDENTITY key (`service_identity_vk`, 32 bytes — a `.onion`-like handle), NOT
/// its node_id. The daemon resolves the service's unlinkable per-period blinded
/// descriptor, decrypts it (the caller knows the identity), and routes the
/// message over an onion circuit. `hop_count` is clamped to ≥ 2 by the daemon.
///
/// `VEIL_OK` once the daemon hands the cell to the first hop (fire-and-forget —
/// NOT delivery-confirmed); `VEIL_ERR` with a detail otherwise (e.g. no
/// resolvable descriptor — the service is offline or hasn't published).
///
/// # Safety
/// `handle` must be a live `VeilHandle*`; `service_identity_vk` and
/// `target_app_id` must each be readable for 32 bytes; `data` must be readable
/// for `len` bytes (or NULL iff `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_to_onion_service(
    handle: *mut VeilHandle,
    service_identity_vk: *const u8,
    target_app_id: *const u8,
    target_endpoint_id: u32,
    hop_count: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_send_to_onion_service") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "service_identity_vk" => service_identity_vk,
        "target_app_id" => target_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut id_vk = [0u8; 32];
    let mut app_id = [0u8; 32];
    // SAFETY: both pointers NULL-checked above; caller guarantees 32 readable
    // bytes each (size per the C header).
    unsafe {
        ptr::copy_nonoverlapping(service_identity_vk, id_vk.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(target_app_id, app_id.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .send_to_onion_service(id_vk, app_id, target_endpoint_id, hop_count, &payload)
            .await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("send_to_onion_service failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Like [`veil_send_to_onion_service`], but UNAUTHENTICATED: the service receives
/// `src_node_id = [0;32]` and never learns who sent the message. Combined with the
/// unlinkable descriptor, neither the relays, the rendezvous relay, nor the
/// service learn the sender's location or identity. `src_app_id` (32 bytes) rides
/// inside the sealed payload for the service's app-level routing only.
///
/// # Safety
/// `handle` must be a live `VeilHandle*`; `service_identity_vk`, `target_app_id`,
/// and `src_app_id` must each be readable for 32 bytes; `data` must be readable
/// for `len` bytes (or NULL iff `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_to_onion_service_anonymous(
    handle: *mut VeilHandle,
    service_identity_vk: *const u8,
    target_app_id: *const u8,
    target_endpoint_id: u32,
    src_app_id: *const u8,
    hop_count: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_send_to_onion_service_anonymous") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "service_identity_vk" => service_identity_vk,
        "target_app_id" => target_app_id,
        "src_app_id" => src_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut id_vk = [0u8; 32];
    let mut app_id = [0u8; 32];
    let mut src_app = [0u8; 32];
    // SAFETY: all three pointers NULL-checked above; caller guarantees 32
    // readable bytes each (size per the C header).
    unsafe {
        ptr::copy_nonoverlapping(service_identity_vk, id_vk.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(target_app_id, app_id.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(src_app_id, src_app.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .send_to_onion_service_anonymous(
                id_vk,
                app_id,
                target_endpoint_id,
                src_app,
                hop_count,
                &payload,
            )
            .await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(
                    err_out,
                    format!("send_to_onion_service_anonymous failed: {e}"),
                );
            }
            VEIL_ERR
        }
    }
}

/// DIRECT (non-rendezvous) sender-anonymous send to a KNOWN peer addressed by its
/// `(target_node_id, target_x25519_pk)` (each 32 bytes). The source-routed onion
/// hides the sender's location from every relay; the receiver sees
/// `src_node_id = [0;32]` and never learns who sent it. For reaching a peer whose
/// transport node_id + anonymity x25519 the caller already knows — NOT a
/// location-anonymous service (use `veil_send_to_onion_service` for those).
/// `hop_count` is clamped to ≥ 1 by the daemon.
///
/// `VEIL_OK` once handed to the first hop (fire-and-forget, NOT delivery-
/// confirmed); `VEIL_ERR` with a detail otherwise.
///
/// # Safety
/// `handle` must be a live `VeilHandle*`; `target_node_id`, `target_x25519_pk`,
/// `target_app_id`, and `src_app_id` must each be readable for 32 bytes; `data`
/// must be readable for `len` bytes (or NULL iff `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_send_anonymous_direct(
    handle: *mut VeilHandle,
    target_node_id: *const u8,
    target_x25519_pk: *const u8,
    target_app_id: *const u8,
    target_endpoint_id: u32,
    src_app_id: *const u8,
    hop_count: u32,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_send_anonymous_direct") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "target_node_id" => target_node_id,
        "target_x25519_pk" => target_x25519_pk,
        "target_app_id" => target_app_id,
        "src_app_id" => src_app_id,
    );
    if data.is_null() && len > 0 {
        unsafe {
            write_err(err_out, "data is NULL but len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe {
            write_err(
                err_out,
                format!("data len {len} exceeds VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN})"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut node_id = [0u8; 32];
    let mut x25519_pk = [0u8; 32];
    let mut app_id = [0u8; 32];
    let mut src_app = [0u8; 32];
    // SAFETY: all four pointers NULL-checked above; caller guarantees 32 readable
    // bytes each (size per the C header).
    unsafe {
        ptr::copy_nonoverlapping(target_node_id, node_id.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(target_x25519_pk, x25519_pk.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(target_app_id, app_id.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(src_app_id, src_app.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .send_anonymous_direct(
                node_id,
                x25519_pk,
                app_id,
                target_endpoint_id,
                src_app,
                hop_count,
                &payload,
            )
            .await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("send_anonymous_direct failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

// ── Mailbox put/fetch/ack ────────────────

/// Status return codes [`veil_mailbox_put`]. Mirrors
/// `MailboxPutStatus` on the wire (0..8 byte).
pub const VEIL_MAILBOX_PUT_STORED: c_int = 0;
pub const VEIL_MAILBOX_PUT_DUPLICATE: c_int = 1;
pub const VEIL_MAILBOX_PUT_QUOTA_PER_RECEIVER: c_int = 2;
pub const VEIL_MAILBOX_PUT_QUOTA_GLOBAL: c_int = 3;
pub const VEIL_MAILBOX_PUT_RATE_LIMITED: c_int = 4;
pub const VEIL_MAILBOX_PUT_NOT_RELAY: c_int = 5;
/// relay configured with
/// `require_capability_token = true` rejected a PUT that arrived
/// without a capability token.
pub const VEIL_MAILBOX_PUT_CAPABILITY_REQUIRED: c_int = 6;
/// capability token decode or verify
/// failed (expired, wrong receiver, or bad signature).
pub const VEIL_MAILBOX_PUT_CAPABILITY_INVALID: c_int = 7;
/// per-sender byte cap exceeded.
pub const VEIL_MAILBOX_PUT_QUOTA_PER_SENDER: c_int = 8;

/// Deposit `blob` for an offline `receiver_id` at the daemon's mailbox
///. No `auth_cookie` required.
///
/// `push_envelope` / `push_envelope_len` are optional (pass NULL / 0
/// to skip). When supplied and storage succeeds, the relay fires a
/// wake-push to the receiver after this call returns.
///
/// Returns one of `VEIL_MAILBOX_PUT_*` (≥0) on a structured outcome
/// or a negative `VEIL_ERR_*` on transport / argument errors.
/// `out_evicted` (may be NULL) receives the count of older blobs the
/// relay had to evict to fit (only nonzero on `VEIL_MAILBOX_PUT_STORED`).
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
/// `receiver_id`, `content_id`, `sender_id` must each point to ≥32
/// readable bytes. `blob` must point to ≥`blob_len` readable bytes
/// (or NULL if `blob_len == 0`). `push_envelope` must point to
/// ≥`push_envelope_len` readable bytes (or NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_put(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    // Forwards to the shared body with `capability_token = None` and
    // `wake_hmac_envelope = None`. For relays running with
    // `require_capability_token = true` the daemon will reply
    // `CAPABILITY_REQUIRED` (status 6); callers that have a token should
    // use [`veil_mailbox_put_with_capability`].  Callers that forward
    // the receiver's sealed wake-HMAC envelope should use
    // [`veil_mailbox_put_with_wake_hmac`].
    unsafe {
        mailbox_put_inner(
            handle,
            receiver_id,
            content_id,
            sender_id,
            blob,
            blob_len,
            push_envelope,
            push_envelope_len,
            ptr::null(),
            0,
            ptr::null(),
            0,
            out_evicted,
            err_out,
        )
    }
}

/// `veil_mailbox_put` variant that forwards
/// a receiver-signed capability token. Required when targeting a
/// relay running with `MailboxConfig::require_capability_token = true`.
///
/// `capability_token` / `capability_token_len` are the bytes obtained
/// from the receiver's `RendezvousAd` (surfaced on the SDK side as
/// `RendezvousReplicaInfo::capability_token`). Pass `NULL` / `0` to
/// fall back to the no-token path (equivalent to calling the original
/// `veil_mailbox_put`). Maximum length is
/// [`veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES`].
///
/// All other parameters and safety contracts are identical to
/// [`veil_mailbox_put`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_put_with_capability(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    capability_token: *const u8,
    capability_token_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        mailbox_put_inner(
            handle,
            receiver_id,
            content_id,
            sender_id,
            blob,
            blob_len,
            push_envelope,
            push_envelope_len,
            capability_token,
            capability_token_len,
            ptr::null(),
            0,
            out_evicted,
            err_out,
        )
    }
}

/// `veil_mailbox_put` variant that forwards BOTH a receiver-signed
/// capability token AND the receiver's sealed wake-HMAC envelope (Epic
/// 489.10 slice 4.3.4).  This is the export a mobile sender uses to
/// forward the wake-HMAC envelope so the relay can mint a receiver-
/// verifiable wake-HMAC tag on the push.
///
/// `capability_token` / `capability_token_len` are as in
/// [`veil_mailbox_put_with_capability`] (pass `NULL` / `0` to skip).
///
/// `wake_hmac_envelope` / `wake_hmac_envelope_len` are the bytes the
/// receiver published in its `RendezvousAd` (surfaced SDK-side as
/// `RendezvousReplicaInfo::wake_hmac_envelope` and returned over the C
/// ABI by [`veil_lookup_rendezvous_replicas`]).  Pass `NULL` / `0`
/// to fall back to an unauthenticated wake (equivalent to
/// [`veil_mailbox_put_with_capability`]).  Maximum length is
/// [`veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES`]; overflow returns
/// `VEIL_ERR_INVALID_ARG`.
///
/// All other parameters and safety contracts are identical to
/// [`veil_mailbox_put`].  `wake_hmac_envelope` MUST point to
/// ≥`wake_hmac_envelope_len` readable bytes (or NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_put_with_wake_hmac(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    capability_token: *const u8,
    capability_token_len: size_t,
    wake_hmac_envelope: *const u8,
    wake_hmac_envelope_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        mailbox_put_inner(
            handle,
            receiver_id,
            content_id,
            sender_id,
            blob,
            blob_len,
            push_envelope,
            push_envelope_len,
            capability_token,
            capability_token_len,
            wake_hmac_envelope,
            wake_hmac_envelope_len,
            out_evicted,
            err_out,
        )
    }
}

/// Shared implementation for `veil_mailbox_put`,
/// `veil_mailbox_put_with_capability` and
/// `veil_mailbox_put_with_wake_hmac`.
///
/// # Safety
/// All pointer / length contracts from the public wrappers apply. This
/// helper is `unsafe` because it dereferences caller pointers; the
/// public wrappers re-document the safety surface explicitly.
#[allow(clippy::too_many_arguments)]
unsafe fn mailbox_put_inner(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    capability_token: *const u8,
    capability_token_len: size_t,
    wake_hmac_envelope: *const u8,
    wake_hmac_envelope_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_put_with_capability") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "content_id" => content_id,
        "sender_id" => sender_id,
    );
    if blob.is_null() && blob_len > 0 {
        unsafe {
            write_err(err_out, "blob is null but blob_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if push_envelope.is_null() && push_envelope_len > 0 {
        unsafe {
            write_err(err_out, "push_envelope is null but push_envelope_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if capability_token.is_null() && capability_token_len > 0 {
        unsafe {
            write_err(
                err_out,
                "capability_token is null but capability_token_len > 0",
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if wake_hmac_envelope.is_null() && wake_hmac_envelope_len > 0 {
        unsafe {
            write_err(
                err_out,
                "wake_hmac_envelope is null but wake_hmac_envelope_len > 0",
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // cap pre-allocation so that
    // a huge caller-supplied len cannot OOM the process before the
    // mailbox-layer quota check fires. Backend caps exist
    // (MAX_MAILBOX_BLOB_BYTES = 1 MiB, MAX_PUSH_ENVELOPE_BYTES =
    // 512 B), but they're enforced AFTER the slice→Vec copy here.
    // Reject up-front to avoid the copy.
    if blob_len > veilclient::MAX_MAILBOX_BLOB_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put blob_len {blob_len} exceeds MAX_MAILBOX_BLOB_BYTES ({})",
                    veilclient::MAX_MAILBOX_BLOB_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if push_envelope_len > veilclient::MAX_PUSH_ENVELOPE_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put push_envelope_len {push_envelope_len} exceeds MAX_PUSH_ENVELOPE_BYTES ({})",
                    veilclient::MAX_PUSH_ENVELOPE_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if capability_token_len > veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put capability_token_len {capability_token_len} exceeds MAX_MAILBOX_CAPABILITY_TOKEN_BYTES ({})",
                    veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if wake_hmac_envelope_len > veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put wake_hmac_envelope_len {wake_hmac_envelope_len} exceeds MAX_WAKE_HMAC_ENVELOPE_BYTES ({})",
                    veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let mut recv_arr = [0u8; 32];
    let mut content_arr = [0u8; 32];
    let mut sender_arr = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(content_id, content_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(sender_id, sender_arr.as_mut_ptr(), 32);
    }
    let blob_vec: Vec<u8> = if blob_len == 0 {
        Vec::new()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(blob, blob_len) };
        slice.to_vec()
    };
    let envelope_opt: Option<Vec<u8>> = if push_envelope_len == 0 {
        None
    } else {
        let slice = unsafe { std::slice::from_raw_parts(push_envelope, push_envelope_len) };
        Some(slice.to_vec())
    };
    let capability_opt: Option<Vec<u8>> = if capability_token_len == 0 {
        None
    } else {
        let slice = unsafe { std::slice::from_raw_parts(capability_token, capability_token_len) };
        Some(slice.to_vec())
    };
    let wake_hmac_opt: Option<Vec<u8>> = if wake_hmac_envelope_len == 0 {
        None
    } else {
        let slice =
            unsafe { std::slice::from_raw_parts(wake_hmac_envelope, wake_hmac_envelope_len) };
        Some(slice.to_vec())
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .mailbox_put(
                recv_arr,
                content_arr,
                sender_arr,
                blob_vec,
                envelope_opt,
                capability_opt,
                // .10 slice 4.3.4: forward the receiver's sealed wake-HMAC
                // envelope (surfaced SDK-side as
                // `RendezvousReplicaInfo::wake_hmac_envelope`) so the relay can
                // mint a receiver-verifiable wake-HMAC tag.  `None` when the
                // caller passed NULL / 0 — relay falls back to an
                // unauthenticated wake.  Reachable with the wake bytes only via
                // [`veil_mailbox_put_with_wake_hmac`]; the two legacy
                // exports forward `(NULL, 0)` here for ABI back-compat.
                wake_hmac_opt,
            )
            .await
    });
    match res {
        Ok(reply) => {
            if !out_evicted.is_null() {
                unsafe {
                    *out_evicted = reply.evicted;
                }
            }
            reply.status as u8 as c_int
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_put failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Serialize a replica list into the length-prefixed wire buffer
/// documented on [`veil_lookup_rendezvous_replicas`].  Factored out
/// of the `extern "C"` body so the exact byte layout can be unit-tested
/// without a live daemon (the C entry-point only adds pointer marshalling).
///
/// Layout (all integers little-endian):
///   count: u32
///   then `count` entries, each:
///     relay_node_id:          [u8; 32]
///     valid_until_unix:       u64
///     push_envelope_len:      u16, push_envelope:      [u8; len]
///     capability_token_len:   u16, capability_token:   [u8; len]
///     wake_hmac_envelope_len: u16, wake_hmac_envelope: [u8; len]
///     rendezvous_kem_algo:    u8
///     rendezvous_kem_pk_len:  u16, rendezvous_kem_pk:  [u8; len]
fn serialize_replica_buf(replicas: &[veilclient::RendezvousReplicaInfo]) -> Vec<u8> {
    // Pre-size exactly: 4-byte count header + per-entry fixed 32+8 plus
    // three u16 length prefixes (6) plus the v5 KEM trailer (1-byte algo + a
    // u16 length prefix = 3) plus each blob's bytes.
    let body: usize = replicas
        .iter()
        .map(|r| {
            32 + 8
                + 6
                + r.push_envelope.len()
                + r.capability_token.len()
                + r.wake_hmac_envelope.len()
                + 3
                + r.rendezvous_kem_pk.len()
        })
        .sum();
    let mut buf = Vec::with_capacity(4 + body);
    buf.extend_from_slice(&(replicas.len() as u32).to_le_bytes());
    for r in replicas {
        buf.extend_from_slice(&r.relay_node_id);
        buf.extend_from_slice(&r.valid_until_unix.to_le_bytes());
        for blob in [&r.push_envelope, &r.capability_token, &r.wake_hmac_envelope] {
            // The u16 length prefix is only safe because every blob is
            // backend-capped well under 64 KiB (push <= 512, cap-token <= 2048,
            // wake-HMAC <= 128). Make that invariant explicit so a future cap
            // bump that breaks it trips in debug instead of silently truncating
            // the prefix and desyncing the Dart-side parser (audit N-1).
            debug_assert!(
                blob.len() <= u16::MAX as usize,
                "replica blob len {} exceeds the u16 length prefix",
                blob.len(),
            );
            // Clamp the prefix AND the appended bytes to the SAME length so a
            // future cap bump past u16::MAX can never desync the Dart-side
            // parser: a bare `as u16` cast would wrap the prefix while still
            // writing the full blob, corrupting every subsequent entry. Self-
            // consistent truncation degrades one entry instead. Producers are
            // capped far below 64 KiB today. (audit cycle-3; matches the
            // EpidemicPayload::encode clamp pattern.)
            let len = blob.len().min(u16::MAX as usize);
            buf.extend_from_slice(&(len as u16).to_le_bytes());
            buf.extend_from_slice(&blob[..len]);
        }
        // v5 KEM trailer: 1-byte algo + u16-length-prefixed relay KEM pubkey.
        // Same self-consistent clamp as the blobs above (capped ≤ 2048 today).
        buf.push(r.rendezvous_kem_algo);
        let kem_len = r.rendezvous_kem_pk.len().min(u16::MAX as usize);
        buf.extend_from_slice(&(kem_len as u16).to_le_bytes());
        buf.extend_from_slice(&r.rendezvous_kem_pk[..kem_len]);
    }
    buf
}

/// Look up candidate mailbox-relays for `receiver_id` and return each
/// verified replica's relay id, ad-expiry, and the three sealed blobs a
/// sender forwards on the put: `push_envelope`, `capability_token`, and
/// (Epic 489.10 slice 4.3.4 — the whole point of this export) the
/// `wake_hmac_envelope`.  Round-trips to the daemon via IPC; resolves
/// the receiver's `RendezvousAd` from the local DHT cache.
///
/// `max_replicas == 0` means "all up to the daemon's cap"
/// (`MAX_RENDEZVOUS_REPLICAS = 8`; single-key publication returns ≤ 1).
///
/// On success returns [`VEIL_OK`] (0) and writes a heap-allocated,
/// length-prefixed buffer to `*out_buf` (its length to `*out_len`).  The
/// caller OWNS that buffer and MUST free it with
/// [`veil_free_replica_buf`] (NOT `free` / `veil_free_string`).
/// An empty result (no cached ad / no replicas) still returns
/// [`VEIL_OK`] with `*out_len == 4` (just the `count = 0` header) and
/// a non-NULL `*out_buf` the caller must still free.  On error returns a
/// negative `VEIL_ERR_*`, sets `*err_out`, and leaves `*out_buf =
/// NULL` / `*out_len = 0`.
///
/// Wire layout (all integers little-endian) — hand this to the Dart side:
///   count: u32
///   then `count` entries, each:
///     relay_node_id:          [u8; 32]
///     valid_until_unix:       u64
///     push_envelope_len:      u16, push_envelope:      [u8; len]
///     capability_token_len:   u16, capability_token:   [u8; len]
///     wake_hmac_envelope_len: u16, wake_hmac_envelope: [u8; len]
///     rendezvous_kem_algo:    u8
///     rendezvous_kem_pk_len:  u16, rendezvous_kem_pk:  [u8; len]
/// (Per-blob length is u16; every blob is backend-capped well under
/// 64 KiB — push ≤ 512 B, cap-token / wake-HMAC / relay-KEM-pk likewise.)
///
/// # Safety
/// `handle` MUST be a live `VeilHandle*` from `veil_connect`.
/// `receiver_id` MUST point to ≥32 readable bytes.  `out_buf` and
/// `out_len` MUST be valid, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_lookup_rendezvous_replicas(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    max_replicas: u8,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_lookup_rendezvous_replicas") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "out_buf" => out_buf,
        "out_len" => out_len,
    );
    // Initialise out-params to the empty/failure state up-front so every
    // early return leaves them well-defined (NULL / 0).
    unsafe {
        *out_buf = ptr::null_mut();
        *out_len = 0;
    }
    let mut recv_arr = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .lookup_rendezvous_replicas(recv_arr, max_replicas)
            .await
    });
    match res {
        Ok(replicas) => {
            // Hand the heap buffer to the caller as a boxed slice. Unlike
            // `Vec::shrink_to_fit` (best-effort — a size-class allocator
            // such as jemalloc may keep capacity > len), `into_boxed_slice`
            // reallocates to an allocation of EXACTLY `len` bytes, so the
            // `Box::from_raw(slice_ptr_of_len(len))` reconstruction in
            // `veil_free_replica_buf` deallocates with the matching layout.
            // This removes a latent capacity-mismatch UB that could fire
            // even when the caller passes back the correct length.
            let boxed: Box<[u8]> = serialize_replica_buf(&replicas).into_boxed_slice();
            let len = boxed.len();
            let ptr = Box::into_raw(boxed) as *mut u8;
            unsafe {
                *out_buf = ptr;
                *out_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("lookup_rendezvous_replicas failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Free a replica buffer returned by
/// [`veil_lookup_rendezvous_replicas`].  `ptr` / `len` MUST be the
/// exact `*out_buf` / `*out_len` pair that call produced — passing any
/// other pointer, or a mismatched length, is undefined behaviour.  Safe
/// to call on `ptr == NULL` (no-op).
///
/// # Safety
/// `ptr` MUST be either NULL or a pointer previously returned by
/// `veil_lookup_rendezvous_replicas` that has NOT already been freed,
/// and `len` MUST equal the length that call wrote.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_free_replica_buf(ptr: *mut u8, len: size_t) {
    if ptr.is_null() {
        return;
    }
    // The buffer was leaked from a `Box<[u8]>` of exactly `len` bytes
    // (see `veil_lookup_rendezvous_replicas`), so rebuild the fat slice
    // pointer and drop the box — this deallocates with the same layout
    // the allocation was made with.
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice));
    }
}

/// Free a callback buffer handed to a recv- or event-handler callback
/// (cycle-7 H6).  `ptr` MUST be the base pointer the callback received — for
/// recv that is the `src_node_id` pointer (the buffer is laid out
/// `[node_id(32) | app_id(32) | data]`); for events it is the `payload`
/// pointer — and `len` MUST be the buffer's total length (recv: `64 + data_len`;
/// events: `payload_len`).  Safe to call on `ptr == NULL` (no-op).
///
/// The callback contract is callee-owns-the-buffer: the host MUST call this
/// exactly once per callback invocation that received a non-NULL pointer, after
/// it has finished copying the bytes it needs. This lets the host retain the
/// pointer past the synchronous call (e.g. Dart `NativeCallable.listener`,
/// which marshals to the isolate and reads the bytes later) without a
/// use-after-free.
///
// ── Nicknames ───────────────────────────────────────────────────────────────
// Human-readable names over veil (see veil-crypto::nickname). The host mines
// PoW seeds OFF the UI isolate (a bounded, chunked, cancellable loop), then
// hands the seed set to the node to sign with the sovereign key and publish
// (brick 3). Verify + normalize + floor are pure helpers for the UI.

/// Normalize a candidate nickname. On VEIL_OK, `*out_buf`/`*out_len` hold the
/// normalized ASCII bytes (free with `veil_free_buf`); returns
/// VEIL_ERR_INVALID_ARG if the name cannot be normalized (bad charset/length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_normalize(
    name: *const u8,
    name_len: size_t,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_normalize") }.is_err() {
        return VEIL_ERR_REENTRANT;
    }
    if name.is_null() || out_buf.is_null() || out_len.is_null() {
        unsafe { write_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    let bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    let Some(s) = std::str::from_utf8(bytes).ok() else {
        unsafe { write_err(err_out, "name is not valid UTF-8") };
        return VEIL_ERR_INVALID_ARG;
    };
    match veil_crypto::nickname::normalize_name(s) {
        Some(norm) => {
            let boxed: Box<[u8]> = norm.into_bytes().into_boxed_slice();
            let len = boxed.len();
            unsafe {
                *out_buf = Box::into_raw(boxed) as *mut u8;
                *out_len = len;
            }
            VEIL_OK
        }
        None => {
            unsafe { write_err(err_out, "name is not a valid nickname") };
            VEIL_ERR_INVALID_ARG
        }
    }
}

/// The cumulative PoW weight a name of this length must carry (the anti-squat
/// floor) — the host mines until it reaches this. 0 on a bad name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_length_floor(name: *const u8, name_len: size_t) -> u64 {
    if name.is_null() {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    match std::str::from_utf8(bytes)
        .ok()
        .and_then(veil_crypto::nickname::normalize_name)
    {
        Some(n) => veil_crypto::nickname::length_weight_floor(n.chars().count()),
        None => 0,
    }
}

/// Mine PoW seeds for `name` under `owner_node_id`, continuing from
/// `prior_seeds` (a concatenation of 32-byte seeds; may be NULL/0), until the
/// cumulative weight reaches `target_weight` or `max_hashes` is spent. The
/// call is bounded by `max_hashes` — the host loops (fresh call = fresh random
/// salt) and cancels by simply not calling again, threading the returned seed
/// set back in as `prior_seeds`.
///
/// On VEIL_OK, `*out_buf`/`*out_len` hold a serialized outcome (free with
/// `veil_free_buf`): `hit_target:u8 | weight:u64 LE | hashes:u64 LE |
/// seed_count:u32 LE | seeds (count*32)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_mine(
    name: *const u8,
    name_len: size_t,
    owner_node_id: *const u8,
    prior_seeds: *const u8,
    prior_seeds_len: size_t,
    target_weight: u64,
    max_hashes: u64,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_mine") }.is_err() {
        return VEIL_ERR_REENTRANT;
    }
    if name.is_null() || owner_node_id.is_null() || out_buf.is_null() || out_len.is_null() {
        unsafe { write_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    if prior_seeds_len % 32 != 0 {
        unsafe { write_err(err_out, "prior_seeds length must be a multiple of 32") };
        return VEIL_ERR_INVALID_ARG;
    }
    let name_bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    let Some(name_str) = std::str::from_utf8(name_bytes).ok() else {
        unsafe { write_err(err_out, "name is not valid UTF-8") };
        return VEIL_ERR_INVALID_ARG;
    };
    let mut owner = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(owner_node_id, owner.as_mut_ptr(), 32) };
    let prior: Vec<[u8; 32]> = if prior_seeds.is_null() || prior_seeds_len == 0 {
        Vec::new()
    } else {
        let raw = unsafe { std::slice::from_raw_parts(prior_seeds, prior_seeds_len) };
        raw.chunks_exact(32)
            .map(|c| {
                let mut a = [0u8; 32];
                a.copy_from_slice(c);
                a
            })
            .collect()
    };
    // A fresh random salt per call so repeated host calls explore new nonces.
    let salt = {
        use rand_core::RngCore;
        rand_core::OsRng.next_u64()
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let Some(outcome) = veil_crypto::nickname::mine_seeds_continue(
        name_str,
        &owner,
        &prior,
        target_weight,
        max_hashes,
        salt,
        &cancel,
    ) else {
        unsafe { write_err(err_out, "name is not a valid nickname") };
        return VEIL_ERR_INVALID_ARG;
    };
    let mut buf = Vec::with_capacity(1 + 8 + 8 + 4 + outcome.seeds.len() * 32);
    buf.push(outcome.hit_target as u8);
    buf.extend_from_slice(&outcome.weight.to_le_bytes());
    buf.extend_from_slice(&outcome.hashes_done.to_le_bytes());
    buf.extend_from_slice(&(outcome.seeds.len() as u32).to_le_bytes());
    for s in &outcome.seeds {
        buf.extend_from_slice(s);
    }
    let boxed: Box<[u8]> = buf.into_boxed_slice();
    let len = boxed.len();
    unsafe {
        *out_buf = Box::into_raw(boxed) as *mut u8;
        *out_len = len;
    }
    VEIL_OK
}

/// Verify a serialized nickname record (from `NicknameRecord::to_bytes`).
/// Returns VEIL_OK if valid; VEIL_ERR with a reason in `err_out` otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_verify(
    record: *const u8,
    record_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_verify") }.is_err() {
        return VEIL_ERR_REENTRANT;
    }
    if record.is_null() {
        unsafe { write_err(err_out, "null record") };
        return VEIL_ERR_INVALID_ARG;
    }
    let bytes = unsafe { std::slice::from_raw_parts(record, record_len) };
    let Some(rec) = veil_crypto::nickname::NicknameRecord::from_bytes(bytes) else {
        unsafe { write_err(err_out, "record failed to parse") };
        return VEIL_ERR;
    };
    match rec.verify() {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe { write_err(err_out, format!("record invalid: {e:?}")) };
            VEIL_ERR
        }
    }
}

/// # Safety
/// `ptr` MUST be NULL or the exact base pointer a recv/event callback received
/// and has NOT already freed, and `len` MUST equal that buffer's total length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_free_buf(ptr: *mut u8, len: size_t) {
    if ptr.is_null() {
        return;
    }
    // The buffer was leaked from a `Box<[u8]>` of exactly `len` bytes in the
    // recv/event loops; rebuild the fat slice pointer and drop the box.
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice));
    }
}

/// Seal `data` for `recipient`'s `(app_id, endpoint_id)` into an offline-mailbox
/// blob (node-side E2E crypto: sign + DHT-resolve the recipient cert +
/// fan-out-encrypt). On success returns [`VEIL_OK`] and writes a heap-allocated
/// buffer to `*out_buf` (its length to `*out_len`); free it with
/// [`veil_free_buf`]. On error returns a negative `VEIL_ERR_*`, sets `*err_out`,
/// and leaves `*out_buf = NULL` / `*out_len = 0`.
///
/// `recipient` and `app_id` MUST point to ≥32 readable bytes; `data` to
/// ≥`data_len` (may be NULL iff `data_len == 0`). `out_buf` / `out_len` MUST be
/// valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_seal(
    handle: *mut VeilHandle,
    recipient: *const u8,
    app_id: *const u8,
    endpoint_id: u32,
    data: *const u8,
    data_len: size_t,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_seal") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "recipient" => recipient,
        "app_id" => app_id,
        "out_buf" => out_buf,
        "out_len" => out_len,
    );
    unsafe {
        *out_buf = ptr::null_mut();
        *out_len = 0;
    }
    let mut recipient_arr = [0u8; 32];
    let mut app_id_arr = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(recipient, recipient_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(app_id, app_id_arr.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if data_len == 0 {
        Vec::new()
    } else {
        null_check!(err_out, "data" => data);
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .mailbox_seal(recipient_arr, app_id_arr, endpoint_id, payload)
            .await
    });
    match res {
        Ok(blob) => {
            let boxed: Box<[u8]> = blob.into_boxed_slice();
            let len = boxed.len();
            let p = Box::into_raw(boxed) as *mut u8;
            unsafe {
                *out_buf = p;
                *out_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_seal failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Open + verify a fetched offline-mailbox `blob`, decrypting under our current
/// cert version `our_cert_version`. The sender is RECOVERED from the blob's
/// sidecar (the anonymous mailbox deposit carries no usable wire sender) and,
/// once crypto-verified, written to `out_sender` (32 bytes). On success returns
/// [`VEIL_OK`], writes the verified destination app id to `out_app_id` (32 bytes)
/// + endpoint id to `*out_endpoint_id`, and a heap-allocated data buffer to
/// `*out_data` (length to `*out_data_len`); free with [`veil_free_buf`].
///
/// `blob` MUST point to ≥`blob_len`. `out_sender` / `out_app_id` MUST each point
/// to ≥32 writable bytes; the other out-pointers MUST be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_open(
    handle: *mut VeilHandle,
    our_cert_version: u64,
    blob: *const u8,
    blob_len: size_t,
    out_sender: *mut u8,
    out_app_id: *mut u8,
    out_endpoint_id: *mut u32,
    out_data: *mut *mut u8,
    out_data_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_open") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_sender" => out_sender,
        "out_app_id" => out_app_id,
        "out_endpoint_id" => out_endpoint_id,
        "out_data" => out_data,
        "out_data_len" => out_data_len,
    );
    unsafe {
        *out_data = ptr::null_mut();
        *out_data_len = 0;
        *out_endpoint_id = 0;
    }
    let blob_vec: Vec<u8> = if blob_len == 0 {
        Vec::new()
    } else {
        null_check!(err_out, "blob" => blob);
        unsafe { std::slice::from_raw_parts(blob, blob_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.mailbox_open(blob_vec, our_cert_version).await
    });
    match res {
        Ok((sender_id, app_id, endpoint_id, data)) => {
            let boxed: Box<[u8]> = data.into_boxed_slice();
            let len = boxed.len();
            let p = Box::into_raw(boxed) as *mut u8;
            unsafe {
                ptr::copy_nonoverlapping(sender_id.as_ptr(), out_sender, 32);
                ptr::copy_nonoverlapping(app_id.as_ptr(), out_app_id, 32);
                *out_endpoint_id = endpoint_id;
                *out_data = p;
                *out_data_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_open failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Fetch all blobs currently stored for `receiver_id`. `auth_cookie`
/// must match a previously-registered rendezvous-publisher entry.
///
/// On success returns ≥0 (the count of blobs returned) and populates
/// `out_blobs` (allocated via `veil_mailbox_blobs_alloc`-style
/// caller-managed buffer). Apps fetch blobs into a length-aware
/// container by calling [`veil_mailbox_fetch_count`] first to size
/// their array, then [`veil_mailbox_fetch_into`] to copy.
///
/// Two-call API avoids hidden allocations through the FFI boundary —
/// callers control all memory lifetimes.
///
/// # Safety
/// `handle`, `receiver_id` (32 B), `auth_cookie` (16 B), `out_count`
/// must all be valid pointers. `out_count` receives the count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_fetch_count(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    auth_cookie: *const u8,
    out_count: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_fetch_count") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "auth_cookie" => auth_cookie,
        "out_count" => out_count,
    );
    let mut recv_arr = [0u8; 32];
    let mut cookie_arr = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie_arr.as_mut_ptr(), 16);
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.mailbox_fetch(recv_arr, cookie_arr).await
    });
    match res {
        Ok(blobs) => {
            // Stash the result on the handle for the next _into call.
            // Single-shot: the handle holds at most one pending fetch
            // result. A second fetch_count overwrites it.
            //
            // Mutex poison recovery: this is a FFI boundary — a panic
            // here would unwind across the `extern "C"` ABI and trigger
            // UB on the C-side caller (mobile SDK / chat_node). If
            // the mutex is poisoned (a previous holder panicked), we
            // adopt the inner state and continue; the stored value is
            // about to be overwritten anyway so that poison is harmless.
            let count = blobs.len();
            let mut pending = match bundle.pending_mailbox_fetch.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            *pending = Some(blobs);
            unsafe {
                *out_count = count as u32;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_fetch_count failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Mailbox blob descriptor returned by [`veil_mailbox_fetch_into`].
/// `blob` is a borrow into a buffer the caller provided to the fetch
/// call; valid until the caller frees that buffer.
#[repr(C)]
pub struct VeilMailboxBlob {
    pub sender_id: [u8; 32],
    pub content_id: [u8; 32],
    pub deposited_at: u64,
    /// Pointer into caller-provided `blob_buf` (NOT separately allocated).
    pub blob: *const u8,
    pub blob_len: u32,
    pub _reserved: u32,
}

/// Copy the most-recently-fetched blob list (cached by
/// [`veil_mailbox_fetch_count`]) into caller-provided buffers.
///
/// `descriptors_out` must point to ≥`max_descriptors` `VeilMailboxBlob`
/// slots. `blob_buf` is a contiguous byte buffer where blob payloads
/// are concatenated; descriptors' `blob` pointers index into it.
/// `blob_buf_len` must be ≥ sum of all blob_len; if too small, returns
/// `VEIL_ERR_INVALID_ARG` and the cached fetch list is kept (caller
/// can re-call with a larger buffer without re-fetching).
///
/// On success returns the count of descriptors written and clears the
/// cache.
///
/// # Safety
/// All output pointers must be writable for at least the documented
/// extents. After this call, the descriptor `blob` pointers are valid
/// only as long as `blob_buf` is alive and unmodified.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_fetch_into(
    handle: *mut VeilHandle,
    descriptors_out: *mut VeilMailboxBlob,
    max_descriptors: u32,
    blob_buf: *mut u8,
    blob_buf_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if handle.is_null() || descriptors_out.is_null() || blob_buf.is_null() {
        unsafe {
            write_err(err_out, "null pointer argument");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    // Mutex poison recovery: see fetch_count for rationale — FFI panic
    // = UB on C-side. Adopt poisoned inner state and continue.
    let mut pending = match bundle.pending_mailbox_fetch.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(blobs) = pending.take() else {
        unsafe {
            write_err(
                err_out,
                "no fetch result cached — call veil_mailbox_fetch_count first",
            );
        }
        return VEIL_ERR;
    };
    // Audit cycle-5 (FFI): fail (and restore the cache) when the caller supplies
    // fewer descriptor slots than the cached result holds, instead of silently
    // writing a prefix and discarding the rest. The required count came from a
    // prior veil_mailbox_fetch_count, so an undersized max_descriptors is a
    // caller error — mirror the blob_buf-too-small path below so the result is
    // not lost. The Dart wrapper always passes the queried count; this guards
    // direct C callers.
    if (max_descriptors as usize) < blobs.len() {
        let need = blobs.len();
        *pending = Some(blobs);
        unsafe {
            write_err(
                err_out,
                format!("max_descriptors too small: need {need}, got {max_descriptors}"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let total_bytes: usize = blobs.iter().map(|b| b.blob.len()).sum();
    let count = blobs.len();
    if total_bytes > blob_buf_len {
        // Restore cache so caller can retry with larger buffer.
        *pending = Some(blobs);
        unsafe {
            write_err(
                err_out,
                format!("blob_buf too small: need {total_bytes}, got {blob_buf_len}",),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let mut offset = 0usize;
    for (i, b) in blobs.iter().take(count).enumerate() {
        let dst_ptr = unsafe { blob_buf.add(offset) };
        if !b.blob.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(b.blob.as_ptr(), dst_ptr, b.blob.len());
            }
        }
        let descriptor = VeilMailboxBlob {
            sender_id: b.sender_id,
            content_id: b.content_id,
            deposited_at: b.deposited_at,
            blob: dst_ptr as *const u8,
            blob_len: b.blob.len() as u32,
            _reserved: 0,
        };
        unsafe {
            ptr::write(descriptors_out.add(i), descriptor);
        }
        offset += b.blob.len();
    }
    count as c_int
}

/// Acknowledge end-to-end receipt of a mailbox blob. Daemon deletes
/// the blob and frees its quota slice. Idempotent.
///
/// Returns 1 if the blob was removed, 0 if no-op (already acked /
/// not present / wrong cookie), or negative on transport error.
///
/// # Safety
/// `handle` must be a live `VeilHandle*`; `receiver_id` (32 B)
/// `content_id` (32 B), `auth_cookie` (16 B) must point to readable
/// storage of at least the documented length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_ack(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    auth_cookie: *const u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_ack") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "content_id" => content_id,
        "auth_cookie" => auth_cookie,
    );
    let mut recv_arr = [0u8; 32];
    let mut content_arr = [0u8; 32];
    let mut cookie_arr = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(content_id, content_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie_arr.as_mut_ptr(), 16);
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.mailbox_ack(recv_arr, content_arr, cookie_arr).await
    });
    match res {
        Ok(removed) => {
            if removed {
                1
            } else {
                0
            }
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_ack failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Read the daemon's own `node_id` (32 bytes) into `out`. Returns
/// [`VEIL_OK`] or a negative error code. Round-trips to the daemon
/// via the IPC `GetNodeIdentity` request — call once at app startup
/// and cache; the value never changes for the lifetime of the daemon
/// process.
///
/// Useful for displaying the user's identity in UI ("you are: 0xABC…")
/// without scraping `VEIL_LOCAL_NODE_ID` env or shelling out to
/// `veil-cli node show`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_get_node_id(
    handle: *mut VeilHandle,
    out_node_id_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_get_node_id") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_node_id_32" => out_node_id_32,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.node_identity().await
    });
    match res {
        Ok(id) => {
            unsafe {
                ptr::copy_nonoverlapping(id.node_id.as_ptr(), out_node_id_32, 32);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("get_node_id failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Snapshot of the daemon's mobile/battery state, populated by
/// `veil_get_mobile_status`. All fields are scalar wire bytes;
/// apps interpret sentinels themselves (`battery_level_pct == 100`
/// could mean "literal 100%" or "AC / unknown").
#[repr(C)]
pub struct VeilMobileStatus {
    /// 0 = Foreground / 1 = Active / 2 = LowPower.
    pub background_tier: u8,
    pub _pad1: [u8; 3],
    /// Configured `mobile.background_keepalive_multiplier`.
    pub background_keepalive_multiplier: u32,
    /// Effective background-keepalive factor RIGHT NOW.
    pub background_keepalive_factor: u32,
    /// Battery reading 0-100 (100 = AC / unknown).
    pub battery_level_pct: u8,
    /// Configured threshold for route-probe throttling (255 = disabled).
    pub low_battery_threshold_pct: u8,
    pub _pad2: [u8; 2],
    /// Configured route-probe multiplier on low-battery.
    pub low_battery_multiplier: u32,
    /// Effective route-probe factor RIGHT NOW.
    pub battery_route_probe_factor: u32,
}

/// Snapshot the daemon's current mobile/battery state into `out`.
/// Returns [`VEIL_OK`] or a negative error code. Round-trips to the
/// daemon via IPC `GetMobileStatus`; cheap (~1 ms) so apps can call
/// this every few seconds for live UI updates.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_get_mobile_status(
    handle: *mut VeilHandle,
    out: *mut VeilMobileStatus,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_get_mobile_status") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out" => out,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.mobile_status().await
    });
    match res {
        Ok(s) => {
            unsafe {
                ptr::write(
                    out,
                    VeilMobileStatus {
                        background_tier: s.background_tier,
                        _pad1: [0; 3],
                        background_keepalive_multiplier: s.background_keepalive_multiplier,
                        background_keepalive_factor: s.background_keepalive_factor,
                        battery_level_pct: s.battery_level_pct,
                        low_battery_threshold_pct: s.low_battery_threshold_pct,
                        _pad2: [0; 2],
                        low_battery_multiplier: s.low_battery_multiplier,
                        battery_route_probe_factor: s.battery_route_probe_factor,
                    },
                );
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("get_mobile_status failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Status codes returned by `veil_join_bootstrap_uri` via `out_status`.
/// Mirror `veil_proto::join_status` constants exactly.
pub const VEIL_JOIN_OK: u8 = 0;
pub const VEIL_JOIN_INVALID_URI: u8 = 1;
pub const VEIL_JOIN_PASSWORD_REQUIRED: u8 = 2;
pub const VEIL_JOIN_PASSWORD_WRONG: u8 = 3;
pub const VEIL_JOIN_SIGNATURE_INVALID: u8 = 4;
pub const VEIL_JOIN_INTERNAL_ERROR: u8 = 5;
pub const VEIL_JOIN_ALREADY_REGISTERED: u8 = 6;

/// Decode a bootstrap-invite URI and register the peer for outbound dial
///. Forwards the URI bytes to the daemon, which decodes
/// them through the standard plain / encrypted / signed-invite paths.
///
/// `uri` is `(ptr, len)` UTF-8 (no NUL terminator). `password` and
/// `expected_issuer_pk` may be NULL (for plain URIs / unsigned) — pass a NULL
/// pointer (length ignored) — or `(ptr, len)` UTF-8.
///
/// On success / `VEIL_JOIN_ALREADY_REGISTERED`, `out_node_id_32` is
/// populated with the decoded peer's node_id. On any error status it is
/// zero-filled. `out_status` always carries the wire-byte status code
/// (one of `VEIL_JOIN_*`). Returns [`VEIL_OK`] iff the IPC
/// round-trip itself succeeded; the actual decode/verify outcome lives
/// in `out_status`.
///
/// Because the outcome is in `out_status`, this call returns `VEIL_OK`
/// for *every* completed round-trip — including failure statuses
/// (`VEIL_JOIN_PASSWORD_WRONG`, …) and successes that carry an
/// informational note. In all of those cases `*err_out` is set to the
/// detail string for `out_status`, so `*err_out` may be non-NULL even
/// on `VEIL_OK`. Callers MUST free `*err_out` with `veil_free_string`
/// whenever it is non-NULL — see the crate-level "Error model".
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_join_bootstrap_uri(
    handle: *mut VeilHandle,
    uri: *const u8,
    uri_len: usize,
    password: *const u8,
    password_len: usize,
    expected_issuer_pk: *const u8,
    expected_issuer_pk_len: usize,
    out_node_id_32: *mut u8,
    out_status: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_join_bootstrap_uri") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_node_id_32" => out_node_id_32,
        "out_status" => out_status,
    );
    let Some(uri_str) = (unsafe { slice_to_str(uri, uri_len) }) else {
        unsafe {
            write_err(err_out, "uri is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };
    // M26: reject a non-NULL but non-UTF-8 password rather than silently
    // ignoring it (which would attempt a PLAIN join of an encrypted invite and
    // fail with a misleading error, or join a plain invite while pretending the
    // password mattered).
    let pw = match unsafe { opt_slice_to_str(password, password_len) } {
        Ok(p) => p,
        Err(()) => {
            unsafe {
                write_err(err_out, "password is not valid UTF-8");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    // expected_issuer_pk is optional; reject non-NULL-but-invalid rather than
    // silently dropping the issuer pin (which would skip signature checking).
    let pk = match unsafe { opt_slice_to_str(expected_issuer_pk, expected_issuer_pk_len) } {
        Ok(p) => p,
        Err(()) => {
            unsafe {
                write_err(err_out, "expected_issuer_pk is not valid UTF-8");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };

    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.join_bootstrap_uri(uri_str, pw, pk).await
    });
    match res {
        Ok(result) => {
            unsafe {
                *out_status = result.status;
                ptr::copy_nonoverlapping(result.peer_node_id.as_ptr(), out_node_id_32, 32);
                if !result.detail.is_empty() {
                    write_err(err_out, result.detail);
                }
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("join_bootstrap_uri failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Create-bootstrap-invite status codes (Epic 489.7 generator side).
/// Mirror `veil_proto::create_invite_status`.
pub const VEIL_CREATE_INVITE_OK: u8 = 0;
pub const VEIL_CREATE_INVITE_NOT_CONFIGURED: u8 = 1;
pub const VEIL_CREATE_INVITE_BAD_PASSWORD: u8 = 2;
pub const VEIL_CREATE_INVITE_INTERNAL_ERROR: u8 = 3;

/// Build a bootstrap-invite URI from the daemon's own identity and
/// listen-address config (Epic 489.7 generator side, "share my invite"
/// flow).  Output goes to a caller-owned heap-allocated UTF-8 string
/// the FFI returns through `out_uri` — caller MUST free it via
/// [`veil_free_string`] after consuming.
///
/// `password` may be `NULL` (plain `veil:bootstrap?…` URI) — pass a NULL
/// pointer (length ignored) — or `(ptr, len)` UTF-8 (encrypted `veil:pair?…`
/// envelope). Empty / whitespace-only passwords are rejected with status
/// `VEIL_CREATE_INVITE_BAD_PASSWORD` so callers can re-prompt rather
/// than emitting an envelope encrypted under a trivial key.
///
/// On non-OK status, `out_uri` is set to NULL and `err_out` (if non-NULL)
/// carries a human-readable detail message.
///
/// Returns [`VEIL_OK`] iff the IPC round-trip itself succeeded; the
/// actual outcome lives in `out_status` (one of `VEIL_CREATE_INVITE_*`).
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
/// `out_status` must be writable.  `out_uri` must be writable; on
/// success it receives a pointer to a malloc'd NUL-terminated UTF-8
/// string — caller frees with [`veil_free_string`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_create_bootstrap_invite(
    handle: *mut VeilHandle,
    password: *const u8,
    password_len: usize,
    out_status: *mut u8,
    out_uri: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_create_bootstrap_invite") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_uri" => out_uri,
    );
    unsafe {
        *out_uri = ptr::null_mut();
    }
    // M26: a non-NULL but non-UTF-8 password must be REJECTED, not coerced to
    // None (which emits a plaintext invite for a caller that asked to encrypt).
    let pw = match unsafe { opt_slice_to_str(password, password_len) } {
        Ok(p) => p,
        Err(()) => {
            unsafe {
                *out_status = VEIL_CREATE_INVITE_BAD_PASSWORD;
                write_err(
                    err_out,
                    "password is not valid UTF-8 — refusing to emit a plaintext invite".to_owned(),
                );
            }
            return VEIL_OK;
        }
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.create_bootstrap_invite(pw).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_CREATE_INVITE_OK && !reply.uri.is_empty() {
                // CString::new fails iff string contains a NUL byte —
                // bootstrap URIs are URL-safe base64 + ASCII only,
                // so this should never trigger.  Defensive guard logs +
                // returns INTERNAL_ERROR instead of panicking across the
                // FFI boundary.
                match std::ffi::CString::new(reply.uri.as_bytes()) {
                    Ok(c) => unsafe {
                        *out_uri = c.into_raw();
                    },
                    Err(e) => unsafe {
                        *out_status = VEIL_CREATE_INVITE_INTERNAL_ERROR;
                        write_err(err_out, format!("URI contains NUL byte: {e}"));
                    },
                }
            } else if !reply.detail.is_empty() {
                unsafe {
                    write_err(err_out, reply.detail);
                }
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("create_bootstrap_invite failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Peer-list iteration callback.
///
/// Invoked once per peer entry from `veil_peers_list`. All buffer
/// pointers are valid only for the duration of the call — copy out
/// anything you need to keep.
///
/// user — the opaque pointer passed to `veil_peers_list`.
/// node_id — pointer to 32 bytes; peer's identity.
/// state — wire-byte session state (see VEIL_PEER_STATE_*).
/// direction — wire-byte direction (see VEIL_PEER_DIR_*).
/// transport — UTF-8 transport URI (NOT null-terminated; use len).
/// transport_len — byte length of `transport`.
/// wrapped in `Option<...>` for safe
/// NULL-pointer rejection at the FFI boundary. See [`VeilRecvCb`]
/// docs.
pub type VeilPeerCb = Option<
    unsafe extern "C" fn(
        user: *mut std::ffi::c_void,
        node_id: *const u8,
        state: u8,
        direction: u8,
        transport: *const u8,
        transport_len: size_t,
    ),
>;

/// Wire-byte session-state values for `VeilPeerCb::state`.
pub const VEIL_PEER_STATE_CONNECTING: u8 = 0;
pub const VEIL_PEER_STATE_ACTIVE: u8 = 1;
pub const VEIL_PEER_STATE_CLOSED: u8 = 2;
pub const VEIL_PEER_STATE_UNKNOWN: u8 = 255;

/// Wire-byte direction values for `VeilPeerCb::direction`.
pub const VEIL_PEER_DIR_INBOUND: u8 = 0;
pub const VEIL_PEER_DIR_OUTBOUND: u8 = 1;

/// Snapshot the daemon's currently-active peer sessions. Calls `cb`
/// once per peer, passing `user` through unchanged. Returns
/// [`VEIL_OK`] on success or a negative error code.
///
/// The list is bounded at 256 entries server-side — apps with thousands
/// of active sessions on a relay should treat the result as a snapshot
/// (not exhaustive).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_peers_list(
    handle: *mut VeilHandle,
    cb: VeilPeerCb,
    user: *mut std::ffi::c_void,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_peers_list") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
    );
    // audit: NULL callback → Some(_) match (see VeilRecvCb).
    let cb_fn = match cb {
        Some(f) => f,
        None => {
            unsafe {
                write_err(err_out, "callback is NULL");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.peers().await
    });
    match res {
        Ok(entries) => {
            // Transport user pointer as usize so the future is Send safe.
            let user_addr = user as usize;
            let user_ptr = user_addr as *mut std::ffi::c_void;
            // wrap each callback
            // invocation in `catch_unwind`. A panic across the FFI
            // boundary is undefined behaviour (Rust's unwinder
            // doesn't cross C-ABI frames cleanly); catching here
            // turns it into a logged warning + skip the bad entry.
            // Mirrors the recv-handler / event-handler pattern shipped
            // — `veil_peers_list` was the one
            // remaining unguarded callback site.
            for entry in entries {
                let transport_bytes = entry.transport.as_bytes();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    cb_fn(
                        user_ptr,
                        entry.node_id.as_ptr(),
                        entry.state,
                        entry.direction,
                        transport_bytes.as_ptr(),
                        transport_bytes.len(),
                    );
                }));
                if result.is_err() {
                    ffi_diag(
                        "[veilclient-ffi] peers_list callback panicked; \
                         entry skipped, iteration continues",
                    );
                    // Don't abort the iteration — caller may want to
                    // see the rest of the list even if one entry's
                    // handler misbehaves.
                }
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("peers_list failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Tell the daemon what background-mode tier the app is currently in.
/// Daemon scales keepalive cadence (and, in a future revision, suspends
/// route probes on `LowPower`) so sessions survive OS-level Doze / iOS
/// background-task suspension.
///
/// `mode` must be one of `VEIL_BG_FOREGROUND`, `VEIL_BG_ACTIVE`
/// `VEIL_BG_LOWPOWER`. Returns [`VEIL_OK`] or a negative error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_set_background_mode(
    handle: *mut VeilHandle,
    mode: c_int,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_set_background_mode") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
    );
    let wire_mode = match mode {
        VEIL_BG_FOREGROUND => veilclient::MobileBackgroundMode::Foreground,
        VEIL_BG_ACTIVE => veilclient::MobileBackgroundMode::Active,
        VEIL_BG_LOWPOWER => veilclient::MobileBackgroundMode::LowPower,
        other => {
            unsafe {
                write_err(err_out, format!("invalid background mode: {other}"));
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.set_mobile_background_mode(wire_mode).await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("set_background_mode failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Tell the daemon that the local network attachment changed. Triggers
/// an eager gateway-reconnect attempt so the app doesn't have to wait
/// for the keepalive timeout to detect that warm sessions are doomed.
///
/// `kind` must be one of `VEIL_NET_*`. `mtu_hint = 0` means "use
/// default" (advisory only).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_notify_network_changed(
    handle: *mut VeilHandle,
    kind: c_int,
    mtu_hint: u16,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_notify_network_changed") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
    );
    let net_kind = match kind {
        VEIL_NET_OFFLINE => veilclient::NetworkKind::Offline,
        VEIL_NET_WIFI => veilclient::NetworkKind::Wifi,
        VEIL_NET_CELLULAR => veilclient::NetworkKind::Cellular,
        VEIL_NET_ETHERNET => veilclient::NetworkKind::Ethernet,
        VEIL_NET_UNKNOWN => veilclient::NetworkKind::Unknown,
        other => {
            unsafe {
                write_err(err_out, format!("invalid network kind: {other}"));
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.notify_network_changed(net_kind, mtu_hint).await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("notify_network_changed failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Register a sealed FCM/APNs push-token envelope on a rendezvous-publisher
/// entry.
///
/// `rendezvous_node_id` (32 bytes) and `auth_cookie` (16 bytes) must match an
/// entry the daemon has already registered via
/// `register_rendezvous_publisher_with_push`. `envelope` carries opaque
/// sealed bytes (use `veil_anonymity::push_envelope::seal_push_envelope`
/// client-side BEFORE calling this — daemon never sees raw token).
/// `envelope_len = 0` clears the registration.
///
/// Returns one of:
/// * [`VEIL_PUSH_OK`] — envelope set / cleared successfully.
/// * [`VEIL_PUSH_NO_RENDEZVOUS`] — no matching entry registered (caller
///   should call register_rendezvous_publisher_with_push first OR ignore
///   if the daemon isn't running rendezvous).
/// * [`VEIL_PUSH_TOO_LARGE`] — envelope exceeds 512 B cap.
/// * [`VEIL_ERR`] / [`VEIL_ERR_INVALID_ARG`] / [`VEIL_ERR_REENTRANT`]
///   per the standard FFI error model.
///
/// # Safety
///
/// `rendezvous_node_id` MUST point to an exactly 32-byte buffer. `auth_cookie`
/// to exactly 16. `envelope` to a buffer of length `envelope_len`. All
/// pointers may be NULL only when their corresponding length is 0. Caller
/// retains ownership of all input buffers; the function copies the envelope
/// internally (returning before write completes to the daemon's state).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_set_push_envelope(
    handle: *mut VeilHandle,
    rendezvous_node_id: *const u8,
    auth_cookie: *const u8,
    envelope: *const u8,
    envelope_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_set_push_envelope") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "rendezvous_node_id" => rendezvous_node_id,
        "auth_cookie" => auth_cookie,
    );
    if envelope_len > 0 && envelope.is_null() {
        unsafe {
            write_err(err_out, "envelope is NULL but envelope_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // cap pre-allocation so that
    // a huge `envelope_len` cannot OOM the process before reaching
    // the daemon-side `EnvelopeTooLarge` reply path. Daemon enforces
    // `MAX_PUSH_ENVELOPE_BYTES` already; we mirror it here so the
    // copy never happens for obviously-bad input.
    if envelope_len > veilclient::MAX_PUSH_ENVELOPE_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "set_push_envelope envelope_len {envelope_len} exceeds MAX_PUSH_ENVELOPE_BYTES ({})",
                    veilclient::MAX_PUSH_ENVELOPE_BYTES,
                ),
            );
        }
        return VEIL_PUSH_TOO_LARGE;
    }
    // 32-byte / 16-byte buffer SAFETY contract — caller MUST
    // pass exactly the documented buffer sizes; we copy out a fixed-size array
    // unconditionally so any miscount on the C side surfaces as a readable
    // memory bug at the call site rather than a silent corruption later.
    let mut rid_bytes = [0u8; 32];
    let mut cookie_bytes = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(rendezvous_node_id, rid_bytes.as_mut_ptr(), 32);
        std::ptr::copy_nonoverlapping(auth_cookie, cookie_bytes.as_mut_ptr(), 16);
    }
    let envelope_vec: Vec<u8> = if envelope_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(envelope, envelope_len) }.to_vec()
    };

    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .set_push_envelope(rid_bytes, cookie_bytes, envelope_vec)
            .await
    });
    match res {
        Ok(veilclient::SetPushEnvelopeStatus::Ok) => VEIL_PUSH_OK,
        Ok(veilclient::SetPushEnvelopeStatus::NoMatchingRendezvous) => VEIL_PUSH_NO_RENDEZVOUS,
        Ok(veilclient::SetPushEnvelopeStatus::EnvelopeTooLarge) => VEIL_PUSH_TOO_LARGE,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("set_push_envelope failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

// ── Push envelope sealing (Epic 489.10) ─────────────────────────

/// Per-envelope wire overhead (`eph_pk + nonce + tag`).  Pre-allocate
/// `token_len + VEIL_PUSH_ENVELOPE_OVERHEAD` bytes on the caller
/// side to receive the sealed bytes.  Mirrors
/// `veil_anonymity::push_envelope::PUSH_ENVELOPE_OVERHEAD`.
pub const VEIL_PUSH_ENVELOPE_OVERHEAD: size_t = 60;

/// Hard cap on inner token length (mirrors MAX_PUSH_TOKEN_LEN).
pub const VEIL_MAX_PUSH_TOKEN_LEN: size_t = 384;

/// Hard cap on sealed envelope length (mirrors MAX_PUSH_ENVELOPE_LEN).
pub const VEIL_MAX_PUSH_ENVELOPE_LEN: size_t = 512;

/// SHA-256 of `data` (`len` bytes) written to the caller-owned 32-byte
/// buffer `out32`.  Stateless — does not need a `VeilHandle`.  Exposed for
/// the app's content-manifest hashing: Dart's pure `package:crypto` digest
/// runs at ~35 MB/s on a phone, so hashing a large file before its offer
/// dominated the send latency; the native digest is ~30-50x faster.
/// Returns [`VEIL_OK`] or [`VEIL_ERR_INVALID_ARG`].
///
/// # Safety
///
/// `data` must point to `len` readable bytes (or be NULL only when `len`
/// is 0).  `out32` MUST point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sha256(data: *const u8, len: size_t, out32: *mut u8) -> c_int {
    use sha2::{Digest as _, Sha256};
    if out32.is_null() || (data.is_null() && len > 0) {
        return VEIL_ERR_INVALID_ARG;
    }
    let input: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let digest = Sha256::digest(input);
    unsafe {
        std::ptr::copy_nonoverlapping(digest.as_ptr(), out32, 32);
    }
    VEIL_OK
}

/// Seal a raw FCM/APNs token to the push-relay identified by a 32-byte
/// X25519 public key.  Stateless — does not need an `VeilHandle`.
/// The relay pubkey is typically obtained from `veil_get_node_id` of
/// the relay daemon (which surfaces it as
/// [`veil_get_relay_x25519_pubkey`]), then transferred OOB to the
/// sender (typically baked into the app via a build-time constant
/// per push-relay deployment).
///
/// Output goes to caller-owned buffer `out_buf` of length `out_buf_cap`.
/// On success `*out_len` receives the actual sealed length (always
/// `token_len + VEIL_PUSH_ENVELOPE_OVERHEAD`).  Returns
/// [`VEIL_OK`] / [`VEIL_PUSH_TOO_LARGE`] / [`VEIL_ERR_INVALID_ARG`]
/// / [`VEIL_ERR`].
///
/// # Safety
///
/// `token` must point to `token_len` readable bytes (or NULL if 0).
/// `relay_pk_32` MUST point to exactly 32 readable bytes.  `out_buf`
/// MUST be writable for at least `out_buf_cap` bytes.  `out_len` MUST
/// be a writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_seal_push_envelope(
    token: *const u8,
    token_len: size_t,
    relay_pk_32: *const u8,
    out_buf: *mut u8,
    out_buf_cap: size_t,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if relay_pk_32.is_null() || out_buf.is_null() || out_len.is_null() {
        unsafe {
            write_err(err_out, "null pointer argument");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if token_len > VEIL_MAX_PUSH_TOKEN_LEN {
        unsafe {
            write_err(
                err_out,
                format!(
                    "token_len {token_len} exceeds VEIL_MAX_PUSH_TOKEN_LEN ({})",
                    VEIL_MAX_PUSH_TOKEN_LEN,
                ),
            );
        }
        return VEIL_PUSH_TOO_LARGE;
    }
    if token.is_null() && token_len > 0 {
        unsafe {
            write_err(err_out, "token is NULL but token_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let needed = token_len.saturating_add(VEIL_PUSH_ENVELOPE_OVERHEAD);
    if out_buf_cap < needed {
        unsafe {
            write_err(
                err_out,
                format!("out_buf_cap {out_buf_cap} < required {needed}"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let token_slice: &[u8] = if token_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(token, token_len) }
    };
    let mut relay_pk = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(relay_pk_32, relay_pk.as_mut_ptr(), 32);
    }
    match veil_anonymity::push_envelope::seal_push_envelope(token_slice, &relay_pk) {
        Ok(sealed) => {
            unsafe {
                ptr::copy_nonoverlapping(sealed.as_ptr(), out_buf, sealed.len());
                *out_len = sealed.len();
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("seal_push_envelope failed: {e}"));
            }
            match e {
                veil_anonymity::push_envelope::PushEnvelopeError::TokenTooLarge { .. } => {
                    VEIL_PUSH_TOO_LARGE
                }
                _ => VEIL_ERR,
            }
        }
    }
}

// ── Wake-HMAC envelope IPC (Epic 489.10 slice 4.3.4) ───────────────────────

/// Upload a sealed wake-HMAC envelope to the daemon's rendezvous-publisher
/// entry matched by `(rendezvous_node_id, auth_cookie)` (Epic 489.10
/// slice 4.3.4 — analog to [`veil_set_push_envelope`]).
///
/// Empty `envelope` (`envelope_len == 0`) clears the registration —
/// the receiver falls back to the legacy rate-limited wake path.  Use
/// when toggling HMAC authentication on/off.
///
/// Returns:
/// * [`VEIL_PUSH_OK`] — envelope set / cleared successfully.
/// * [`VEIL_PUSH_NO_RENDEZVOUS`] — no matching publisher entry
///   (caller should `register_rendezvous_publisher` first).
/// * [`VEIL_PUSH_TOO_LARGE`] — `envelope_len` exceeds
///   `MAX_WAKE_HMAC_ENVELOPE_BYTES`.
/// * Other negative codes — connection / protocol errors.
///
/// # Safety
///
/// `handle` MUST be a live `VeilHandle*`.  `rendezvous_node_id`
/// MUST point to 32 readable bytes.  `auth_cookie` MUST point to 16
/// readable bytes.  `envelope` MUST point to `envelope_len` readable
/// bytes (or NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_set_wake_hmac_envelope(
    handle: *mut VeilHandle,
    rendezvous_node_id: *const u8,
    auth_cookie: *const u8,
    envelope: *const u8,
    envelope_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_set_wake_hmac_envelope") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "rendezvous_node_id" => rendezvous_node_id,
        "auth_cookie" => auth_cookie,
    );
    if envelope_len > 0 && envelope.is_null() {
        unsafe {
            write_err(err_out, "envelope is NULL but envelope_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if envelope_len > veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "set_wake_hmac_envelope envelope_len {envelope_len} exceeds MAX_WAKE_HMAC_ENVELOPE_BYTES ({})",
                    veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES,
                ),
            );
        }
        return VEIL_PUSH_TOO_LARGE;
    }
    let mut rid_bytes = [0u8; 32];
    let mut cookie_bytes = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(rendezvous_node_id, rid_bytes.as_mut_ptr(), 32);
        std::ptr::copy_nonoverlapping(auth_cookie, cookie_bytes.as_mut_ptr(), 16);
    }
    let envelope_vec: Vec<u8> = if envelope_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(envelope, envelope_len) }.to_vec()
    };

    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .set_wake_hmac_envelope(rid_bytes, cookie_bytes, envelope_vec)
            .await
    });
    match res {
        Ok(veilclient::SetWakeHmacEnvelopeStatus::Ok) => VEIL_PUSH_OK,
        Ok(veilclient::SetWakeHmacEnvelopeStatus::NoMatchingRendezvous) => VEIL_PUSH_NO_RENDEZVOUS,
        Ok(veilclient::SetWakeHmacEnvelopeStatus::EnvelopeTooLarge) => VEIL_PUSH_TOO_LARGE,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("set_wake_hmac_envelope failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

// ── Wake-HMAC primitives (Epic 489.10 slice 4.3.3) ──────────────────────────

/// Fill `out_key_32` with a fresh 32-byte wake-HMAC key from the OS CSPRNG.
///
/// Receivers generate one key per identity rotation epoch and persist it
/// platform-side (iOS Keychain / Android Keystore — sibling slice).
/// The key is sealed to the chosen push-relay via [`veil_seal_push_envelope`]
/// — same envelope shape as a push token — and embedded in the receiver's
/// rendezvous ad as `wake_hmac_envelope` (slice 4.3.2 wire bump).
///
/// # Safety
///
/// `out_key_32` MUST point to exactly 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_generate_wake_hmac_key(
    out_key_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if out_key_32.is_null() {
        unsafe {
            write_err(err_out, "out_key_32 is NULL");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let key = veil_crypto::wake_hmac::WakeHmacKey::generate();
    unsafe {
        ptr::copy_nonoverlapping(key.as_bytes().as_ptr(), out_key_32, 32);
    }
    VEIL_OK
}

/// Verify a wake-up payload delivered via OS push (FCM / APNs body).
/// Receiver's plugin calls this inside `handleWakeup` BEFORE doing any
/// expensive veil work (daemon reconnect, mailbox drain).
///
/// Returns one of [`VEIL_WAKE_VERDICT_*`] codes via `out_verdict`:
///
/// * `VALID` — payload matches; proceed to drain.
/// * `TAMPERED` — HMAC mismatch.  Silent no-op; no observable network
///   reaction (defeats presence oracle).
/// * `EXPIRED` — `ts` outside ±5-min freshness window.  Silent no-op;
///   distinguish from tampering so operators can track clock-skew
///   rate separately.
/// * `MALFORMED` — `payload_len != 72`.  Silent no-op; logs locally.
///
/// On any [`VEIL_OK`] return the verdict byte is meaningful (≤ 3).
/// Other return codes indicate input-validation errors.
///
/// # Safety
///
/// `key_32` and `receiver_id_32` MUST each point to exactly 32 readable
/// bytes.  `payload` MUST point to `payload_len` readable bytes (or
/// NULL if 0).  `out_verdict` MUST be a writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_verify_wake_hmac(
    key_32: *const u8,
    payload: *const u8,
    payload_len: size_t,
    receiver_id_32: *const u8,
    now_secs: u64,
    out_verdict: *mut c_int,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if key_32.is_null() || receiver_id_32.is_null() || out_verdict.is_null() {
        unsafe {
            write_err(err_out, "null pointer argument");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if payload.is_null() && payload_len > 0 {
        unsafe {
            write_err(err_out, "payload is NULL but payload_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // SECURITY (audit 2026-05-29, FFI hardening): a valid wake payload is
    // ALWAYS exactly 72 bytes (see WAKE_PAYLOAD_LEN / verify_wake_payload).
    // Reject any other length BEFORE constructing the slice via
    // `from_raw_parts`, so a hostile/mis-bound caller that lies about
    // `payload_len` (e.g. claims 1_000_000 over a 72-byte buffer) cannot
    // induce an out-of-bounds read.  This is behaviour-preserving: a
    // != 72 length would have produced the MALFORMED verdict anyway —
    // we just decide it without touching the (untrusted) buffer span.
    if payload_len != veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN {
        unsafe {
            *out_verdict = VEIL_WAKE_VERDICT_MALFORMED;
        }
        return VEIL_OK;
    }
    let mut key_bytes = [0u8; 32];
    let mut recv_bytes = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(key_32, key_bytes.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(receiver_id_32, recv_bytes.as_mut_ptr(), 32);
    }
    let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes(key_bytes);
    // SAFETY: payload_len == WAKE_PAYLOAD_LEN (72) verified above, and the
    // caller's `# Safety` contract guarantees `payload` points to that many
    // readable bytes; the slice span is now bounded to the fixed 72.
    let payload_slice: &[u8] = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let verdict =
        veil_crypto::wake_hmac::verify_wake_payload(&key, payload_slice, &recv_bytes, now_secs);
    let code = match verdict {
        veil_crypto::wake_hmac::WakePayloadVerdict::Valid { .. } => VEIL_WAKE_VERDICT_VALID,
        veil_crypto::wake_hmac::WakePayloadVerdict::TamperedOrForged => VEIL_WAKE_VERDICT_TAMPERED,
        veil_crypto::wake_hmac::WakePayloadVerdict::Expired { .. } => VEIL_WAKE_VERDICT_EXPIRED,
        veil_crypto::wake_hmac::WakePayloadVerdict::MalformedLength { .. } => {
            VEIL_WAKE_VERDICT_MALFORMED
        }
    };
    unsafe {
        *out_verdict = code;
    }
    VEIL_OK
}

// ── Push event stream ───────────────────────────────────────────

/// Event-kind wire bytes mirroring `veil_proto::event_kind::*`.
/// Hosts dispatch on `kind` to know how to interpret `payload`. Keep
/// in lockstep with the server-side constants — adding new kinds is
/// forward-compatible (older C consumers see an unknown kind and
/// fall back to a noop handler).
pub const VEIL_EVENT_SESSIONS_CHANGED: u8 = 0;
pub const VEIL_EVENT_MOBILE_TIER_CHANGED: u8 = 1;
pub const VEIL_EVENT_IDENTITY_ROTATED: u8 = 2;
/// Mailbox drain (fetch) completed.  Payload: `[u32 BE drained_count]`.
/// BG-handler consumers (iOS BGProcessingTask, Android background workers)
/// subscribe so they can complete precisely at drain completion instead of
/// padding to a hardcoded fallback timeout.
pub const VEIL_EVENT_MAILBOX_DRAINED: u8 = 3;
/// A mailbox relay signalled over our live session that it just stored a
/// deposit for us (in-network wake — no third-party push). Empty payload;
/// the client should drain its mailbox promptly. Best-effort hint.
pub const VEIL_EVENT_MAILBOX_WAKE: u8 = 5;

/// Push-event callback. Invoked from a tokio worker thread for every
/// `LocalAppMsg::Event` frame the daemon emits while this handler is
/// installed. `payload`+`payload_len` describe the per-kind opaque
/// bytes (see. `veil_proto::event_kind` for wire format per kind).
///
/// BUFFER OWNERSHIP (cycle-7 H6): for a non-empty payload the pointer is an
/// OWNED heap buffer the callee must free via `veil_free_buf(payload,
/// payload_len)` after copying — it MAY be retained past this synchronous call
/// (Dart `NativeCallable.listener`). An empty payload passes a NULL pointer with
/// `payload_len == 0` (nothing to free).
///
/// wrapped in `Option<...>` for safe
/// NULL-pointer rejection at the FFI boundary. See [`VeilRecvCb`]
/// docs.
pub type VeilEventCb = Option<
    unsafe extern "C" fn(
        user: *mut std::ffi::c_void,
        kind: u8,
        payload: *const u8,
        payload_len: size_t,
    ),
>;

/// Install a push-event handler on this veil connection
///. The handler runs on a private tokio task and is
/// torn down when the handle is closed or `set_event_handler` is
/// called again. Returns [`VEIL_OK`] iff a fresh handler was
/// installed; [`VEIL_ERR_INVALID_ARG`] if `handle` is NULL.
///
/// Single-subscriber semantics — calling this twice replaces the
/// previous handler (the prior task is aborted). Pass NULL `user`
/// if the C side does not need the opaque pointer; otherwise the
/// caller must keep `user` valid until the handler is replaced or
/// the handle is closed.
///
/// Threading note: the callback fires on a tokio worker thread.
/// Hosts that marshal to a single-threaded UI loop (Flutter
/// dart:ffi, Swift, Kotlin) should wrap their callback in a
/// listener-style trampoline that wakes the UI isolate/queue.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_set_event_handler(
    handle: *mut VeilHandle,
    cb: VeilEventCb,
    user: *mut std::ffi::c_void,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if handle.is_null() {
        unsafe {
            write_err(err_out, "handle is NULL");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // audit: NULL callback → Some(_) match (see VeilRecvCb).
    let cb_fn = match cb {
        Some(f) => f,
        None => {
            unsafe {
                write_err(err_out, "callback is NULL");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        h_ref,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    // Cancel any previous handler before subscribing again. A second
    // subscriber would replace the SDK-side mpsc sink anyway, but we
    // also want to drop the old task so it stops holding the runtime
    // worker and any captured pointers.
    if let Ok(mut guard) = h_ref.event_task.lock()
        && let Some(prev) = guard.take()
    {
        prev.abort();
    }
    let bundle = Arc::clone(&h_ref.bundle);
    let bundle_for_task = Arc::clone(&bundle);
    // FFI pointers are not Send — transport `user` as `usize`.
    let user_addr = user as usize;
    let task = bundle.runtime.spawn(async move {
        let bundle = bundle_for_task;
        // Subscribe inside the task so the SDK-side mpsc sender is
        // installed under the same lock that `events` takes — avoids
        // a race with simultaneous `events` callers (the doc contract
        // says single-subscriber, so racing would already be UB on
        // the consumer side, but this keeps the daemon-side behaviour
        // deterministic).
        let mut events = {
            let client = bundle.client.lock().await;
            client.events().await
        };
        while let Some(ev) = events.recv().await {
            let user_ptr = user_addr as *mut std::ffi::c_void;
            let kind = ev.kind;
            let payload_len = ev.payload.len();
            // cycle-7 H6: same use-after-free hazard as the recv loop — the host
            // callback may read `payload_ptr` after this frame returns (Dart
            // `NativeCallable.listener`). For a non-empty payload, hand the callee
            // an OWNED heap copy it frees via `veil_free_buf(payload_ptr,
            // payload_len)`; an empty payload passes NULL (nothing to free).
            let base: *mut u8 = if payload_len == 0 {
                std::ptr::null_mut()
            } else {
                Box::into_raw(ev.payload.into_boxed_slice()).cast()
            };
            // catch_unwind around the callback so
            // a panic doesn't unwind across the C-ABI frame
            // (UB). Logged and the event-stream stays alive.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                cb_fn(user_ptr, kind, base.cast_const(), payload_len);
            }));
            if result.is_err() {
                // Reclaim on the unwinding (dev/test) path so we don't leak.
                if !base.is_null() {
                    unsafe {
                        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                            base,
                            payload_len,
                        )));
                    }
                }
                ffi_diag(
                    "[veilclient-ffi] event-handler callback panicked; \
                     event dropped, stream kept open",
                );
            }
            // Loop continues until channel closes (None from recv).
        }
    });
    if let Ok(mut guard) = h_ref.event_task.lock() {
        *guard = Some(task);
    }
    VEIL_OK
}

// ── Identity restore ────────────────────────────────────────────

/// Maximum freshness window for a restored IdentityDocument — 30 days.
/// Mirrors `veil_identity::MAX_FRESHNESS_WINDOW_SECS`. Restored
/// devices typically request the full window so the doc lives through
/// the next routine document republish (default ~half-life).
pub const VEIL_DEFAULT_RESTORE_VALIDITY_SECS: u64 = 30 * 24 * 3600;

// ── zeroize-on-consume BIP-39 variants ────────────────
//
// The phrase is a SECRET (24-word master seed). These entry points take it as
// a writable `(*mut u8, len)` buffer and overwrite every byte with `0` after
// decoding — on success and on every error path — so a host that loads the
// seed via a malloc'd buffer (typical Flutter `Uint8List` / `calloc<Uint8>`)
// does not leave the plaintext lingering in the heap. Caller still owns the
// allocation and frees the (now-zeroed) buffer.
//
// (The earlier non-zeroizing `*const c_char` forms were removed in the
// explicit-length ABI migration — they left the mnemonic in caller memory.)

/// Generate a FRESH master identity phrase: a new random 32-byte master seed
/// encoded as the 24-word English mnemonic (veil master-phrase checksum). The
/// seed material lives only inside this call and zeroizes on drop — the
/// returned phrase is its ONLY representation. Flow: show it to the user for
/// the paper backup, confirm, then create the identity DETERMINISTICALLY via
/// `veil_restore_identity_from_phrase_zeroize` with this same phrase, so a
/// fresh onboarding and a later disaster-recovery restore agree on node_id.
///
/// On success writes a NUL-terminated UTF-8 phrase into `*phrase_out`; the
/// caller MUST free it with `veil_free_string`, and should zero the buffer
/// first (the Dart wrapper copies into an immutable String and scrubs the
/// native bytes — same posture as the validate/restore zeroize variants).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_generate_master_phrase(
    phrase_out: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if phrase_out.is_null() {
        unsafe {
            write_err(err_out, "phrase_out is NULL");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let seed = veil_identity::master_seed::generate_master_seed();
    let mnemonic = match veil_identity::master_seed::encode_master_seed_to_phrase(&seed) {
        Ok(m) => m,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("phrase encode failed: {e}"));
            }
            return VEIL_ERR;
        }
    };
    // The intermediate String zeroizes on drop; the CString we hand out is the
    // caller's to scrub + free (veil_free_string).
    let phrase = zeroize::Zeroizing::new(mnemonic.to_string());
    let cs = match CString::new(phrase.as_str()) {
        Ok(c) => c,
        Err(_) => {
            unsafe {
                write_err(err_out, "phrase contained NUL");
            }
            return VEIL_ERR;
        }
    };
    unsafe {
        *phrase_out = cs.into_raw();
    }
    VEIL_OK
}

/// Validate a BIP-39 master phrase, zeroizing the caller's buffer on consume.
///
/// Returns `VEIL_OK` iff the phrase is exactly 24 words from the English BIP-39
/// wordlist AND the checksum verifies. The `(phrase, phrase_len)` buffer is
/// overwritten with `0` before returning, on every path. UI uses this for live
/// feedback as the user types.
///
/// Reads the phrase, runs the same validation, and unconditionally
/// overwrites the buffer bytes with `0` before returning — regardless
/// of success or failure. Caller MUST guarantee `phrase` points to a
/// writable, NUL-terminated UTF-8 buffer (typical: malloc'd from C, or
/// `String.toNativeUtf8` in Dart).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_validate_bip39_phrase_zeroize(
    phrase: *mut u8,
    phrase_len: usize,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if phrase.is_null() {
        unsafe {
            write_err(err_out, "phrase is NULL");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Explicit-length ABI: the caller hands us the exact buffer length, so we
    // can scrub it precisely without a strnlen scan (and even if the bytes are
    // not UTF-8). Reject an over-cap length before touching memory.
    if phrase_len > MAX_FFI_CSTR_LEN {
        unsafe {
            write_err(err_out, "phrase too long (>4 KiB)");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // RAII guard: zero the WHOLE caller buffer on EVERY return path — success,
    // decode failure, or non-UTF-8 — so possibly-sensitive input never lingers.
    // Mirrors `veil_restore_identity_from_phrase_zeroize`.
    struct ZeroOnDrop {
        ptr: *mut u8,
        len: usize,
    }
    impl Drop for ZeroOnDrop {
        fn drop(&mut self) {
            unsafe { volatile_wipe(self.ptr, self.len) };
        }
    }
    let _guard = ZeroOnDrop {
        ptr: phrase,
        len: phrase_len,
    };

    // UTF-8 decode AFTER the guard is armed.
    let phrase_bytes = unsafe { std::slice::from_raw_parts(phrase as *const u8, phrase_len) };
    let phrase_str = match std::str::from_utf8(phrase_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                write_err(err_out, "phrase is not valid UTF-8");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    match veil_identity::master_seed::decode_master_seed_from_phrase(phrase_str) {
        Ok(_seed) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("invalid phrase: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Restore an identity from a BIP-39 master phrase, zeroizing the phrase on
/// consume.
///
/// Decodes `phrase` → master_seed → derives identity_sk → builds a fresh signed
/// `IdentityDocument` and writes `identity_document.bin`, `instance.toml`, and
/// `identity_sk.bin` to `veil_dir`. `instance_label` is the human-readable
/// device name (capped at 64 chars). Idempotent: same phrase + same `veil_dir`
/// regenerates the per-device key; the `node_id` (= BLAKE3(master_pk)) is stable.
///
/// `phrase` is a SECRET, passed as a writable `(*mut u8, len)` buffer that is
/// overwritten with `0` before return on EVERY path. `veil_dir` and
/// `instance_label` are non-secret `(*const u8, len)` UTF-8. Returns `VEIL_OK`
/// on success; on failure sets `*err_out` and returns `VEIL_ERR`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_restore_identity_from_phrase_zeroize(
    phrase: *mut u8,
    phrase_len: usize,
    veil_dir: *const u8,
    veil_dir_len: usize,
    instance_label: *const u8,
    instance_label_len: usize,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if phrase.is_null() {
        unsafe {
            write_err(err_out, "phrase is NULL");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Explicit-length ABI: the length is authoritative, so we scrub exactly the
    // caller's buffer with no strnlen scan. Reject over-cap before touching it.
    if phrase_len > MAX_FFI_CSTR_LEN {
        unsafe {
            write_err(err_out, "phrase too long (>4 KiB)");
        }
        return VEIL_ERR_INVALID_ARG;
    }

    // RAII guard: zero the WHOLE caller buffer no matter how this returns
    // (early return on validation error, panic, success).
    struct ZeroOnDrop {
        ptr: *mut u8,
        len: usize,
    }
    impl Drop for ZeroOnDrop {
        fn drop(&mut self) {
            unsafe { volatile_wipe(self.ptr, self.len) };
        }
    }
    let _guard = ZeroOnDrop {
        ptr: phrase,
        len: phrase_len,
    };

    // UTF-8 decode AFTER guard armed, so a non-UTF8 phrase still gets
    // scrubbed (possibly-sensitive bytes from a user input field).
    let phrase_bytes = unsafe { std::slice::from_raw_parts(phrase as *const u8, phrase_len) };
    let phrase_str = match std::str::from_utf8(phrase_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                write_err(err_out, "phrase is not valid UTF-8");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    let Some(dir_str) = (unsafe { slice_to_str(veil_dir, veil_dir_len) }) else {
        unsafe {
            write_err(err_out, "veil_dir is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };
    let Some(label_str) = (unsafe { slice_to_str(instance_label, instance_label_len) }) else {
        unsafe {
            write_err(err_out, "instance_label is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };

    let master_seed = match veil_identity::master_seed::decode_master_seed_from_phrase(phrase_str) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("decode phrase: {e}"));
            }
            return VEIL_ERR;
        }
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let opts = veil_identity::sovereign_flow::RestoreIdentityOptions {
        veil_dir: std::path::PathBuf::from(dir_str),
        master_seed,
        save_encrypted_with_password: None,
        argon2_params_override: None,
        instance_label: label_str.chars().take(64).collect::<String>(),
        pow_difficulty: 0,
        now_unix,
        valid_until_unix: now_unix + VEIL_DEFAULT_RESTORE_VALIDITY_SECS,
        algo: veil_types::SignatureAlgorithm::Ed25519,
        master_falcon_keypair_bytes: None,
    };

    match veil_identity::sovereign_flow::restore_identity(opts) {
        Ok(_output) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("restore_identity: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Restore identity AND write an encrypted master-seed backup
/// ([`veil_restore_identity_from_phrase_zeroize`] + passphrase-protected
/// `master.enc` file in `veil_dir`).
///
/// Both `phrase` AND `password` buffers are zeroed in place before this
/// function returns (on every code path — success, validation error,
/// I/O error, or panic).  Caller still owns the allocations and frees
/// them after this call.
///
/// `password` may be NULL — equivalent to calling
/// [`veil_restore_identity_from_phrase_zeroize`] without the encrypted-
/// master file.  This is provided as a convenience so consumer Flutter
/// apps can branch on "user-supplied passphrase or not" without
/// switching FFI symbols.
///
/// The Argon2id parameters are the spec-production default (64 MiB,
/// t=3, p=4).  Test code wanting cheaper KDF must use the lower-level
/// `veil_identity::sovereign_flow::restore_identity` directly with
/// `argon2_params_override`.
///
/// # Safety
/// `phrase` and (if non-NULL) `password` must each point to a writable buffer
/// of at least the given length.  `veil_dir` and `instance_label` are read-only
/// `(*const u8, len)` UTF-8.  `err_out` must be writable; on non-OK returns it
/// receives a pointer to a malloc'd UTF-8 string — caller frees with
/// [`veil_free_string`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_restore_identity_from_phrase_zeroize_with_password(
    phrase: *mut u8,
    phrase_len: usize,
    veil_dir: *const u8,
    veil_dir_len: usize,
    instance_label: *const u8,
    instance_label_len: usize,
    password: *mut u8,
    password_len: usize,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if phrase.is_null() {
        unsafe {
            write_err(err_out, "phrase is NULL");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if phrase_len > MAX_FFI_CSTR_LEN {
        unsafe {
            write_err(err_out, "phrase too long (>4 KiB)");
        }
        return VEIL_ERR_INVALID_ARG;
    }

    // RAII guard: zero both phrase + password buffers regardless of
    // return path.  Same struct as the zeroize-only variant, repeated
    // here per buffer because lengths differ.
    struct ZeroOnDrop {
        ptr: *mut u8,
        len: usize,
    }
    impl Drop for ZeroOnDrop {
        fn drop(&mut self) {
            // `volatile_wipe` is NULL-safe.
            unsafe { volatile_wipe(self.ptr, self.len) };
        }
    }

    let _phrase_guard = ZeroOnDrop {
        ptr: phrase,
        len: phrase_len,
    };

    // Read password BEFORE constructing its guard so we can copy it to an owned
    // buffer — the guard scrubs the original caller buffer after we return.
    // Audit L-15: the owned copy is wrapped in `Zeroizing` and moved into
    // `RestoreIdentityOptions.save_encrypted_with_password` (now typed
    // `Option<Zeroizing<Vec<u8>>>`), so it is scrubbed when `opts` drops inside
    // `restore_identity`. The encryption path only BORROWS the password, so this
    // owned copy is the longest-lived plaintext and must wipe itself — the
    // previous plain `Vec<u8>` left it in freed heap, defeating this function's
    // whole purpose.
    let (pw_bytes, _pw_guard) = if password.is_null() {
        (
            None,
            ZeroOnDrop {
                ptr: std::ptr::null_mut(),
                len: 0,
            },
        )
    } else {
        if password_len > MAX_FFI_CSTR_LEN {
            unsafe {
                write_err(err_out, "password too long (>4 KiB)");
            }
            return VEIL_ERR_INVALID_ARG;
        }
        let guard = ZeroOnDrop {
            ptr: password,
            len: password_len,
        };
        let pw_slice = unsafe { std::slice::from_raw_parts(password as *const u8, password_len) };
        let bytes = match std::str::from_utf8(pw_slice) {
            Ok(s) => Some(zeroize::Zeroizing::new(s.as_bytes().to_vec())),
            Err(_) => {
                unsafe {
                    write_err(err_out, "password is not valid UTF-8");
                }
                return VEIL_ERR_INVALID_ARG;
            }
        };
        (bytes, guard)
    };

    let phrase_bytes = unsafe { std::slice::from_raw_parts(phrase as *const u8, phrase_len) };
    let phrase_str = match std::str::from_utf8(phrase_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                write_err(err_out, "phrase is not valid UTF-8");
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    let Some(dir_str) = (unsafe { slice_to_str(veil_dir, veil_dir_len) }) else {
        unsafe {
            write_err(err_out, "veil_dir is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };
    let Some(label_str) = (unsafe { slice_to_str(instance_label, instance_label_len) }) else {
        unsafe {
            write_err(err_out, "instance_label is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };

    let master_seed = match veil_identity::master_seed::decode_master_seed_from_phrase(phrase_str) {
        Ok(s) => s,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("decode phrase: {e}"));
            }
            return VEIL_ERR;
        }
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let opts = veil_identity::sovereign_flow::RestoreIdentityOptions {
        veil_dir: std::path::PathBuf::from(dir_str),
        master_seed,
        save_encrypted_with_password: pw_bytes,
        argon2_params_override: None,
        instance_label: label_str.chars().take(64).collect::<String>(),
        pow_difficulty: 0,
        now_unix,
        valid_until_unix: now_unix + VEIL_DEFAULT_RESTORE_VALIDITY_SECS,
        algo: veil_types::SignatureAlgorithm::Ed25519,
        master_falcon_keypair_bytes: None,
    };

    match veil_identity::sovereign_flow::restore_identity(opts) {
        Ok(_output) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("restore_identity: {e}"));
            }
            VEIL_ERR
        }
    }
}

// ── One-burst sovereign signing FFI ────────────────────────────

/// Open a short-lived sovereign signer from a recovery phrase.
///
/// The writable phrase buffer is wiped on every path. Only an opaque handle,
/// the public key, and its node id cross back to the caller; the decoded master
/// seed and derived signing seed remain in native memory and zeroize on drop.
/// Call [`veil_sovereign_signer_close`] immediately after the membership-signing
/// burst.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_open_from_phrase_zeroize(
    phrase: *mut u8,
    phrase_len: size_t,
    out_signer: *mut *mut VeilSovereignSigner,
    out_node_id: *mut u8,
    out_node_id_cap: size_t,
    out_public_key: *mut u8,
    out_public_key_cap: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signer.is_null() {
        unsafe { *out_signer = ptr::null_mut() };
    }
    if phrase.is_null()
        || out_signer.is_null()
        || out_node_id.is_null()
        || out_public_key.is_null()
        || out_node_id_cap < 32
        || out_public_key_cap < 32
        || phrase_len > MAX_FFI_CSTR_LEN
    {
        unsafe { write_err(err_out, "invalid sovereign signer open arguments") };
        if !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let owned = zeroize::Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase as *const u8, phrase_len) }.to_vec(),
    );
    unsafe { volatile_wipe(phrase, phrase_len) };
    let phrase_str = match std::str::from_utf8(&owned) {
        Ok(s) => s,
        Err(_) => {
            unsafe { write_err(err_out, "phrase is not valid UTF-8") };
            return VEIL_ERR_INVALID_ARG;
        }
    };
    let master_seed = match veil_identity::master_seed::decode_master_seed_from_phrase(phrase_str) {
        Ok(seed) => seed,
        Err(e) => {
            unsafe { write_err(err_out, format!("invalid phrase: {e}")) };
            return VEIL_ERR;
        }
    };
    let sk_seed = veil_crypto::identity::derive_master_sk_ed25519(&master_seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let node_id = veil_crypto::identity::compute_node_id(&public_key);
    let token = HandleTable::insert(
        sovereign_signer_table(),
        VeilSovereignSigner {
            key: SovereignSignerKey::RecoveryEd25519(sk_seed),
        },
    );
    unsafe {
        ptr::copy_nonoverlapping(node_id.as_ptr(), out_node_id, 32);
        ptr::copy_nonoverlapping(public_key.as_ptr(), out_public_key, 32);
        *out_signer = token as *mut VeilSovereignSigner;
    }
    VEIL_OK
}

/// Sign one message during an open sovereign burst. The output is a raw
/// 64-byte Ed25519 signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_sign(
    signer: *mut VeilSovereignSigner,
    message: *const u8,
    message_len: size_t,
    out_signature: *mut u8,
    out_signature_cap: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if signer.is_null()
        || message.is_null()
        || message_len > VEIL_MAX_DATA_LEN
        || out_signature.is_null()
        || out_signature_cap < 64
    {
        unsafe { write_err(err_out, "invalid sovereign signer sign arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let Some(live) = HandleTable::get(sovereign_signer_table(), signer as usize) else {
        unsafe { write_err(err_out, "sovereign signer is closed or invalid") };
        return VEIL_ERR_CLOSED;
    };
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let SovereignSignerKey::RecoveryEd25519(sk_seed) = &live.key else {
        unsafe { write_err(err_out, "use variable-length signer API for bundle signer") };
        return VEIL_ERR_INVALID_ARG;
    };
    use ed25519_dalek::Signer as _;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(sk_seed);
    let signature = signing_key.sign(message).to_bytes();
    unsafe { ptr::copy_nonoverlapping(signature.as_ptr(), out_signature, 64) };
    VEIL_OK
}

/// Create a portable Ed25519+Falcon512 sovereign bundle encrypted with the
/// recovery phrase. The mutable phrase is wiped on every path. The returned
/// ciphertext buffer is freed with [`veil_free_buf`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_bundle_create_hybrid512_zeroize(
    phrase: *mut u8,
    phrase_len: size_t,
    out_bundle: *mut *mut u8,
    out_bundle_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_bundle.is_null() {
        unsafe { *out_bundle = ptr::null_mut() }
    }
    if !out_bundle_len.is_null() {
        unsafe { *out_bundle_len = 0 }
    }
    if phrase.is_null()
        || phrase_len > MAX_FFI_CSTR_LEN
        || out_bundle.is_null()
        || out_bundle_len.is_null()
    {
        if !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        unsafe { write_err(err_out, "invalid sovereign bundle create arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase.cast_const(), phrase_len) }.to_vec(),
    );
    unsafe { volatile_wipe(phrase, phrase_len) };
    match veil_identity::sovereign_bundle::create_hybrid512(&owned) {
        Ok(bundle) => {
            let boxed = bundle.into_boxed_slice();
            let len = boxed.len();
            unsafe {
                *out_bundle = Box::into_raw(boxed).cast();
                *out_bundle_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            VEIL_ERR
        }
    }
}

/// Re-wrap an existing XVSB or XVRC credential into a fresh XVRC recovery
/// certificate while preserving the exact full public key and derived node id.
/// Current-secret and new-code buffers are wiped on every path; only encrypted
/// certificate bytes return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_recovery_certificate_export_zeroize(
    bundle: *const u8,
    bundle_len: size_t,
    phrase: *mut u8,
    phrase_len: size_t,
    recovery_code: *mut u8,
    recovery_code_len: size_t,
    out_certificate: *mut *mut u8,
    out_certificate_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_certificate.is_null() {
        unsafe { *out_certificate = ptr::null_mut() }
    }
    if !out_certificate_len.is_null() {
        unsafe { *out_certificate_len = 0 }
    }
    let valid_phrase = !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN;
    let valid_code = !recovery_code.is_null() && recovery_code_len <= MAX_FFI_CSTR_LEN;
    if bundle.is_null()
        || bundle_len == 0
        || bundle_len > 16 * 1024
        || !valid_phrase
        || !valid_code
        || out_certificate.is_null()
        || out_certificate_len.is_null()
    {
        if valid_phrase {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        if valid_code {
            unsafe { volatile_wipe(recovery_code, recovery_code_len) };
        }
        unsafe { write_err(err_out, "invalid recovery certificate export arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned_phrase = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase.cast_const(), phrase_len) }.to_vec(),
    );
    let owned_code = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(recovery_code.cast_const(), recovery_code_len) }
            .to_vec(),
    );
    unsafe {
        volatile_wipe(phrase, phrase_len);
        volatile_wipe(recovery_code, recovery_code_len);
    }
    let encrypted = unsafe { std::slice::from_raw_parts(bundle, bundle_len) };
    match veil_identity::sovereign_bundle::export_recovery_certificate(
        encrypted,
        &owned_phrase,
        &owned_code,
    ) {
        Ok(certificate) => {
            let boxed = certificate.into_boxed_slice();
            let len = boxed.len();
            unsafe {
                *out_certificate = Box::into_raw(boxed).cast();
                *out_certificate_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            VEIL_ERR
        }
    }
}

/// Open an XVRC with its independent recovery code as a short-lived hybrid
/// signer. The code is wiped before return and plaintext material stays native.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_open_recovery_certificate_zeroize(
    certificate: *const u8,
    certificate_len: size_t,
    recovery_code: *mut u8,
    recovery_code_len: size_t,
    out_signer: *mut *mut VeilSovereignSigner,
    out_algorithm: *mut u8,
    out_node_id: *mut u8,
    out_node_id_cap: size_t,
    out_public_key: *mut u8,
    out_public_key_cap: size_t,
    out_public_key_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signer.is_null() {
        unsafe { *out_signer = ptr::null_mut() }
    }
    if !out_public_key_len.is_null() {
        unsafe { *out_public_key_len = 0 }
    }
    let valid_code = !recovery_code.is_null() && recovery_code_len <= MAX_FFI_CSTR_LEN;
    if certificate.is_null()
        || certificate_len == 0
        || certificate_len > 16 * 1024
        || !valid_code
        || out_signer.is_null()
        || out_algorithm.is_null()
        || out_node_id.is_null()
        || out_node_id_cap < 32
        || out_public_key.is_null()
        || out_public_key_len.is_null()
    {
        if valid_code {
            unsafe { volatile_wipe(recovery_code, recovery_code_len) };
        }
        unsafe { write_err(err_out, "invalid recovery certificate open arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned_code = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(recovery_code.cast_const(), recovery_code_len) }
            .to_vec(),
    );
    unsafe { volatile_wipe(recovery_code, recovery_code_len) };
    let encrypted = unsafe { std::slice::from_raw_parts(certificate, certificate_len) };
    let material =
        match veil_identity::sovereign_bundle::open_recovery_certificate(encrypted, &owned_code) {
            Ok(value) => value,
            Err(e) => {
                unsafe { write_err(err_out, e.to_string()) };
                return VEIL_ERR;
            }
        };
    if material.public_key.len() > out_public_key_cap {
        unsafe { write_err(err_out, "sovereign public-key output buffer too small") };
        return VEIL_ERR_INVALID_ARG;
    }
    let node_id = material.node_id();
    let algorithm = material.algorithm.wire_byte();
    let public_key_len = material.public_key.len();
    unsafe {
        ptr::copy_nonoverlapping(node_id.as_ptr(), out_node_id, 32);
        ptr::copy_nonoverlapping(material.public_key.as_ptr(), out_public_key, public_key_len);
        *out_algorithm = algorithm;
        *out_public_key_len = public_key_len;
    }
    let token = HandleTable::insert(
        sovereign_signer_table(),
        VeilSovereignSigner {
            key: SovereignSignerKey::Bundle(material),
        },
    );
    unsafe { *out_signer = token as *mut VeilSovereignSigner };
    VEIL_OK
}

/// Decrypt a local sovereign bundle and open a short-lived variable-algorithm
/// signer. Neither phrase nor plaintext key material crosses back to the host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_open_bundle_zeroize(
    bundle: *const u8,
    bundle_len: size_t,
    phrase: *mut u8,
    phrase_len: size_t,
    out_signer: *mut *mut VeilSovereignSigner,
    out_algorithm: *mut u8,
    out_node_id: *mut u8,
    out_node_id_cap: size_t,
    out_public_key: *mut u8,
    out_public_key_cap: size_t,
    out_public_key_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signer.is_null() {
        unsafe { *out_signer = ptr::null_mut() }
    }
    if !out_public_key_len.is_null() {
        unsafe { *out_public_key_len = 0 }
    }
    if bundle.is_null()
        || bundle_len == 0
        || bundle_len > 16 * 1024
        || phrase.is_null()
        || phrase_len > MAX_FFI_CSTR_LEN
        || out_signer.is_null()
        || out_algorithm.is_null()
        || out_node_id.is_null()
        || out_node_id_cap < 32
        || out_public_key.is_null()
        || out_public_key_len.is_null()
    {
        if !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        unsafe { write_err(err_out, "invalid sovereign bundle open arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned_phrase = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase.cast_const(), phrase_len) }.to_vec(),
    );
    unsafe { volatile_wipe(phrase, phrase_len) };
    let encrypted = unsafe { std::slice::from_raw_parts(bundle, bundle_len) };
    let material = match veil_identity::sovereign_bundle::open(encrypted, &owned_phrase) {
        Ok(value) => value,
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            return VEIL_ERR;
        }
    };
    if material.public_key.len() > out_public_key_cap {
        unsafe { write_err(err_out, "sovereign public-key output buffer too small") };
        return VEIL_ERR_INVALID_ARG;
    }
    let node_id = material.node_id();
    let algorithm = material.algorithm.wire_byte();
    let public_key_len = material.public_key.len();
    unsafe {
        ptr::copy_nonoverlapping(node_id.as_ptr(), out_node_id, 32);
        ptr::copy_nonoverlapping(material.public_key.as_ptr(), out_public_key, public_key_len);
        *out_algorithm = algorithm;
        *out_public_key_len = public_key_len;
    }
    let token = HandleTable::insert(
        sovereign_signer_table(),
        VeilSovereignSigner {
            key: SovereignSignerKey::Bundle(material),
        },
    );
    unsafe { *out_signer = token as *mut VeilSovereignSigner };
    VEIL_OK
}

/// Variable-length sovereign signature API. `out_signature_len` receives the
/// exact number of bytes written (64 for Ed25519, ~700-830 for hybrid-512).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_sign_into(
    signer: *mut VeilSovereignSigner,
    message: *const u8,
    message_len: size_t,
    out_signature: *mut u8,
    out_signature_cap: size_t,
    out_signature_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signature_len.is_null() {
        unsafe { *out_signature_len = 0 }
    }
    if signer.is_null()
        || message.is_null()
        || message_len > VEIL_MAX_DATA_LEN
        || out_signature.is_null()
        || out_signature_len.is_null()
    {
        unsafe { write_err(err_out, "invalid sovereign signer sign-into arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let Some(live) = HandleTable::get(sovereign_signer_table(), signer as usize) else {
        unsafe { write_err(err_out, "sovereign signer is closed or invalid") };
        return VEIL_ERR_CLOSED;
    };
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let signature = match &live.key {
        SovereignSignerKey::RecoveryEd25519(seed) => {
            use ed25519_dalek::Signer as _;
            ed25519_dalek::SigningKey::from_bytes(seed)
                .sign(message)
                .to_bytes()
                .to_vec()
        }
        SovereignSignerKey::Bundle(material) => match material.sign(message) {
            Ok(value) => value,
            Err(e) => {
                unsafe { write_err(err_out, e.to_string()) };
                return VEIL_ERR;
            }
        },
    };
    if signature.len() > out_signature_cap {
        unsafe { write_err(err_out, "sovereign signature output buffer too small") };
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        ptr::copy_nonoverlapping(signature.as_ptr(), out_signature, signature.len());
        *out_signature_len = signature.len();
    }
    VEIL_OK
}

/// Verify an algorithm-tagged sovereign signature and bind the supplied node
/// id to the full public key. Invalid signatures return VEIL_OK + false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_verify(
    algorithm: u8,
    node_id: *const u8,
    public_key: *const u8,
    public_key_len: size_t,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
    out_valid: *mut bool,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_valid.is_null() {
        unsafe { *out_valid = false }
    }
    if node_id.is_null()
        || public_key.is_null()
        || public_key_len > 4096
        || message.is_null()
        || message_len > VEIL_MAX_DATA_LEN
        || signature.is_null()
        || signature_len > 4096
        || out_valid.is_null()
    {
        unsafe { write_err(err_out, "invalid sovereign verify arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let Some(algorithm) = veil_types::SignatureAlgorithm::from_wire_byte(algorithm) else {
        return VEIL_OK;
    };
    let expected_node = unsafe { std::slice::from_raw_parts(node_id, 32) };
    let public_key = unsafe { std::slice::from_raw_parts(public_key, public_key_len) };
    if veil_crypto::identity::compute_node_id(public_key).as_slice() != expected_node {
        return VEIL_OK;
    }
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let signature = unsafe { std::slice::from_raw_parts(signature, signature_len) };
    use base64::Engine as _;
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    unsafe {
        *out_valid =
            veil_crypto::verify_message(algorithm, &public_b64, message, signature).is_ok();
    }
    VEIL_OK
}

/// Close a sovereign signing burst. Double-close and stale handles are safe
/// no-ops; the generational table prevents ABA reuse.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_close(signer: *mut VeilSovereignSigner) {
    if signer.is_null() {
        return;
    }
    drop(HandleTable::remove(
        sovereign_signer_table(),
        signer as usize,
    ));
}

// ── Multi-device pairing FFI (Epic 489.8) ──────────────────────

/// Wire-byte status codes for Source-side pairing ops.  Mirror
/// `veil_proto::pair_source_status`.
pub const VEIL_PAIR_SOURCE_OK: u8 = 0;
pub const VEIL_PAIR_SOURCE_NOT_CONFIGURED: u8 = 1;
pub const VEIL_PAIR_SOURCE_ALREADY_IN_PROGRESS: u8 = 2;
pub const VEIL_PAIR_SOURCE_INTERNAL_ERROR: u8 = 3;
pub const VEIL_PAIR_SOURCE_WRONG_STATE: u8 = 4;
pub const VEIL_PAIR_SOURCE_BAD_HELLO: u8 = 5;
pub const VEIL_PAIR_SOURCE_USER_ABORTED: u8 = 6;
pub const VEIL_PAIR_SOURCE_BAD_CONFIRM: u8 = 7;

/// Wire-byte status codes for Target-side pairing ops.  Mirror
/// `veil_proto::pair_target_status`.
pub const VEIL_PAIR_TARGET_OK: u8 = 0;
pub const VEIL_PAIR_TARGET_BAD_URI: u8 = 1;
pub const VEIL_PAIR_TARGET_EXPIRED: u8 = 2;
pub const VEIL_PAIR_TARGET_ALREADY_IN_PROGRESS: u8 = 3;
pub const VEIL_PAIR_TARGET_BAD_CERT: u8 = 4;
pub const VEIL_PAIR_TARGET_WRONG_STATE: u8 = 5;
pub const VEIL_PAIR_TARGET_INTERNAL_ERROR: u8 = 6;

/// Hard cap on ceremony frame size (mirrors
/// `veil_proto::MAX_PAIR_CEREMONY_BYTES`).  Callers can pre-
/// allocate a buffer of this size to safely receive Hello / Cert /
/// Confirm bytes without two-call sizing.
pub const VEIL_MAX_PAIR_CEREMONY_BYTES: size_t = 64 * 1024;

/// OOB code length (always 6 ASCII digits).
pub const VEIL_PAIR_OOB_CODE_LEN: size_t = 6;

/// Helper: write SDK reply detail to err_out if non-empty (treats
/// detail as advisory metadata, not a fatal-error string).  Used by
/// every pairing FFI fn so consumers get a stable surface.
unsafe fn write_pair_detail(err_out: *mut *mut c_char, detail: &str) {
    if !detail.is_empty() && !err_out.is_null() {
        unsafe {
            write_err(err_out, detail);
        }
    }
}

/// Source-side: generate a pair-invite URI + initialize ceremony.
/// On success, `*out_uri` receives a malloc'd NUL-terminated UTF-8
/// string — caller frees with [`veil_free_string`].  `password` is the
/// master_sk decryption passphrase as `(ptr, len)` UTF-8; pass a NULL pointer
/// (length ignored) for a standalone identity with no encrypted master.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_source_create_invite(
    handle: *mut VeilHandle,
    password: *const u8,
    password_len: usize,
    out_status: *mut u8,
    out_uri: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_source_create_invite") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_uri" => out_uri,
    );
    unsafe {
        *out_uri = ptr::null_mut();
    }
    // M26: reject a non-NULL but non-UTF-8 master password rather than silently
    // dropping it to None (pairing transfers master-identity material — a
    // silently-unprotected invite is even worse than the bootstrap case).
    let pw = match unsafe { opt_slice_to_str(password, password_len) } {
        Ok(p) => p,
        Err(()) => {
            unsafe {
                write_err(
                    err_out,
                    "master password is not valid UTF-8 — refusing to proceed".to_owned(),
                );
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_source_create_invite(pw).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_SOURCE_OK && !reply.uri.is_empty() {
                match std::ffi::CString::new(reply.uri.as_bytes()) {
                    Ok(c) => unsafe {
                        *out_uri = c.into_raw();
                    },
                    Err(e) => unsafe {
                        *out_status = VEIL_PAIR_SOURCE_INTERNAL_ERROR;
                        write_err(err_out, format!("URI contains NUL byte: {e}"));
                    },
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_source_create_invite failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Source-side: process Hello bytes from Target.  Returns Cert bytes
/// (via caller buffer) + 6-digit OOB code.  `out_cert_buf` must be
/// writable for ≥ `out_cert_buf_cap` bytes (recommend
/// `VEIL_MAX_PAIR_CEREMONY_BYTES` = 64 KiB so a fixed-size buffer
/// always fits the Cert).  `out_oob_6` MUST point to a 6-byte buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_source_handle_hello(
    handle: *mut VeilHandle,
    hello_bytes: *const u8,
    hello_len: size_t,
    out_status: *mut u8,
    out_oob_6: *mut u8,
    out_cert_buf: *mut u8,
    out_cert_buf_cap: size_t,
    out_cert_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_source_handle_hello") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_oob_6" => out_oob_6,
        "out_cert_buf" => out_cert_buf,
        "out_cert_len" => out_cert_len,
    );
    if hello_bytes.is_null() && hello_len > 0 {
        unsafe {
            write_err(err_out, "hello_bytes is NULL but hello_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Audit L-16: bound the caller-supplied length BEFORE `from_raw_parts(...)
    // .to_vec()`, matching every other byte-input FFI fn. An unbounded `len`
    // (mis-bound / hostile caller) would OOM-kill the host before any downstream
    // pairing-frame limit fires. 64 KiB is the documented ceremony-frame cap.
    if hello_len > VEIL_MAX_PAIR_CEREMONY_BYTES {
        unsafe {
            write_err(err_out, "hello_len exceeds VEIL_MAX_PAIR_CEREMONY_BYTES");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        ptr::write_bytes(out_oob_6, 0, 6);
        *out_cert_len = 0;
    }
    let hello = if hello_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(hello_bytes, hello_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_source_handle_hello(hello).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_SOURCE_OK {
                if reply.response_bytes.len() > out_cert_buf_cap {
                    unsafe {
                        write_err(
                            err_out,
                            format!(
                                "cert bytes {} > out_cert_buf_cap {}",
                                reply.response_bytes.len(),
                                out_cert_buf_cap,
                            ),
                        );
                        *out_status = VEIL_PAIR_SOURCE_INTERNAL_ERROR;
                    }
                } else {
                    unsafe {
                        if !reply.response_bytes.is_empty() {
                            ptr::copy_nonoverlapping(
                                reply.response_bytes.as_ptr(),
                                out_cert_buf,
                                reply.response_bytes.len(),
                            );
                        }
                        *out_cert_len = reply.response_bytes.len();
                        ptr::copy_nonoverlapping(reply.oob_code.as_ptr(), out_oob_6, 6);
                    }
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_source_handle_hello failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Source-side: process Confirm bytes — finalizes the ceremony.
///
/// Phase 6.49 exemplar: uses [`guard::ffi_prelude`] + [`null_check!`]
/// for the boundary checks so that the consistent error messages
/// land on every FFI fn after incremental migration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_source_handle_confirm(
    handle: *mut VeilHandle,
    confirm_bytes: *const u8,
    confirm_len: size_t,
    out_status: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_source_handle_confirm") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
    );
    // Conditional null check doesn't fit the uniform macro shape —
    // keep inline.  Pattern stays consistent across all FFI fns.
    if confirm_bytes.is_null() && confirm_len > 0 {
        unsafe {
            write_err(err_out, "confirm_bytes is NULL but confirm_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Audit L-16: bound the length before `from_raw_parts(...).to_vec()`.
    if confirm_len > VEIL_MAX_PAIR_CEREMONY_BYTES {
        unsafe {
            write_err(err_out, "confirm_len exceeds VEIL_MAX_PAIR_CEREMONY_BYTES");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let confirm = if confirm_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(confirm_bytes, confirm_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_source_handle_confirm(confirm).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_source_handle_confirm failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Target-side: consume scanned URI, build Hello bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_target_consume_uri(
    handle: *mut VeilHandle,
    uri: *const u8,
    uri_len: usize,
    out_status: *mut u8,
    out_hello_buf: *mut u8,
    out_hello_buf_cap: size_t,
    out_hello_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_target_consume_uri") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_hello_buf" => out_hello_buf,
        "out_hello_len" => out_hello_len,
    );
    let Some(uri_str) = (unsafe { slice_to_str(uri, uri_len) }) else {
        unsafe {
            write_err(err_out, "uri is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };
    unsafe {
        *out_hello_len = 0;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_target_consume_uri(uri_str).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_TARGET_OK {
                if reply.bytes.len() > out_hello_buf_cap {
                    unsafe {
                        write_err(
                            err_out,
                            format!(
                                "hello bytes {} > out_hello_buf_cap {}",
                                reply.bytes.len(),
                                out_hello_buf_cap,
                            ),
                        );
                        *out_status = VEIL_PAIR_TARGET_INTERNAL_ERROR;
                    }
                } else {
                    unsafe {
                        if !reply.bytes.is_empty() {
                            ptr::copy_nonoverlapping(
                                reply.bytes.as_ptr(),
                                out_hello_buf,
                                reply.bytes.len(),
                            );
                        }
                        *out_hello_len = reply.bytes.len();
                    }
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_target_consume_uri failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Target-side: process Cert bytes, return OOB code.
///
/// Phase 6.49 exemplar (second after `veil_pair_source_handle_confirm`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_target_handle_cert(
    handle: *mut VeilHandle,
    cert_bytes: *const u8,
    cert_len: size_t,
    out_status: *mut u8,
    out_oob_6: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_target_handle_cert") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_oob_6" => out_oob_6,
    );
    if cert_bytes.is_null() && cert_len > 0 {
        unsafe {
            write_err(err_out, "cert_bytes is NULL but cert_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Audit L-16: bound the length before `from_raw_parts(...).to_vec()`.
    if cert_len > VEIL_MAX_PAIR_CEREMONY_BYTES {
        unsafe {
            write_err(err_out, "cert_len exceeds VEIL_MAX_PAIR_CEREMONY_BYTES");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        ptr::write_bytes(out_oob_6, 0, 6);
    }
    let cert = if cert_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(cert_bytes, cert_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_target_handle_cert(cert).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
                if reply.status == VEIL_PAIR_TARGET_OK {
                    ptr::copy_nonoverlapping(reply.oob_code.as_ptr(), out_oob_6, 6);
                }
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_target_handle_cert failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Target-side: emit Confirm bytes based on user's OOB-compare
/// decision.  `confirmed = 1` triggers identity persistence.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_target_build_confirm(
    handle: *mut VeilHandle,
    confirmed: u8,
    out_status: *mut u8,
    out_confirm_buf: *mut u8,
    out_confirm_buf_cap: size_t,
    out_confirm_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_target_build_confirm") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_confirm_buf" => out_confirm_buf,
        "out_confirm_len" => out_confirm_len,
    );
    unsafe {
        *out_confirm_len = 0;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_target_build_confirm(confirmed != 0).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_TARGET_OK {
                if reply.bytes.len() > out_confirm_buf_cap {
                    unsafe {
                        write_err(
                            err_out,
                            format!(
                                "confirm bytes {} > out_confirm_buf_cap {}",
                                reply.bytes.len(),
                                out_confirm_buf_cap,
                            ),
                        );
                        *out_status = VEIL_PAIR_TARGET_INTERNAL_ERROR;
                    }
                } else {
                    unsafe {
                        if !reply.bytes.is_empty() {
                            ptr::copy_nonoverlapping(
                                reply.bytes.as_ptr(),
                                out_confirm_buf,
                                reply.bytes.len(),
                            );
                        }
                        *out_confirm_len = reply.bytes.len();
                    }
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_target_build_confirm failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    /// diff-audit M26 (explicit-length ABI): a non-NULL but non-UTF-8 password
    /// must NOT collapse to `None` (which silently emits a plaintext invite) —
    /// `opt_slice_to_str` must reject it.
    #[test]
    fn opt_slice_to_str_distinguishes_null_utf8_and_invalid_m26() {
        // NULL ptr → no value (length ignored), intended plain output.
        assert!(matches!(
            unsafe { opt_slice_to_str(ptr::null(), 7) },
            Ok(None)
        ));
        // Valid UTF-8 → Some.
        let ok = b"hunter2";
        assert!(matches!(
            unsafe { opt_slice_to_str(ok.as_ptr(), ok.len()) },
            Ok(Some("hunter2"))
        ));
        // Non-NULL but non-UTF-8 (0xFF) → Err — caller rejects, never coerces to
        // a plaintext-emitting None.
        let bad = [0xFFu8, 0xFE];
        assert!(matches!(
            unsafe { opt_slice_to_str(bad.as_ptr(), bad.len()) },
            Err(())
        ));
        // Over-cap length → Err (not silently dropped).
        let big = vec![b'x'; MAX_FFI_CSTR_LEN + 1];
        assert!(matches!(
            unsafe { opt_slice_to_str(big.as_ptr(), big.len()) },
            Err(())
        ));
    }

    /// `slice_to_str`: NULL, over-cap, and invalid-UTF-8 all reject; a valid
    /// non-terminated buffer of exactly `len` bytes decodes (no NUL needed).
    #[test]
    fn slice_to_str_rejects_null_overcap_and_invalid() {
        assert!(unsafe { slice_to_str(ptr::null(), 4) }.is_none());
        let good = b"obfs4-tcp://host:1"; // no NUL terminator
        assert_eq!(
            unsafe { slice_to_str(good.as_ptr(), good.len()) },
            Some("obfs4-tcp://host:1")
        );
        let bad = [0xFFu8, 0x00, 0x01];
        assert!(unsafe { slice_to_str(bad.as_ptr(), bad.len()) }.is_none());
        let big = vec![b'x'; MAX_FFI_CSTR_LEN + 1];
        assert!(unsafe { slice_to_str(big.as_ptr(), big.len()) }.is_none());
        // Exactly at cap is accepted.
        let at_cap = vec![b'a'; MAX_FFI_CSTR_LEN];
        assert!(unsafe { slice_to_str(at_cap.as_ptr(), at_cap.len()) }.is_some());
    }

    #[test]
    fn null_handle_close_is_noop() {
        unsafe {
            veil_close(ptr::null_mut());
        }
    }

    #[test]
    fn max_data_len_leaves_frame_headroom() {
        // The daemon frames an FFI send as body_len = <payload FIXED_SIZE> +
        // data_len and rejects body_len > MAX_FRAME_BODY (16 MiB), tearing down
        // the WHOLE IPC connection on overflow (diff-audit defect M25). So
        // VEIL_MAX_DATA_LEN must leave headroom for the LARGEST send-payload
        // fixed prefix. Literals mirror veil_proto::codec::MAX_FRAME_BODY and
        // SendAnonymousDirectPayload::FIXED_SIZE (the largest cap-using sender);
        // veilclient-ffi does not depend on veil-proto directly, hence the
        // documented constants here.
        const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;
        const LARGEST_SEND_PREFIX: usize = 136; // SendAnonymousDirectPayload::FIXED_SIZE
        // Asserting a compile-time-constant invariant is the whole point here —
        // this test pins that VEIL_MAX_DATA_LEN can never grow past the headroom.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                VEIL_MAX_DATA_LEN + LARGEST_SEND_PREFIX <= MAX_FRAME_BODY,
                "VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN}) + prefix ({LARGEST_SEND_PREFIX}) \
                 must stay <= MAX_FRAME_BODY ({MAX_FRAME_BODY})"
            );
        }
    }

    #[test]
    fn validate_bip39_zeroize_wipes_invalid_utf8_input() {
        // audit cycle-3: even a non-UTF-8 (so rejected) but NUL-terminated
        // writable buffer must be scrubbed — the RAII guard runs on every path.
        let mut buf: Vec<u8> = vec![0xFF, 0xFE, 0xAA]; // invalid UTF-8
        let n = buf.len();
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf.as_mut_ptr(), n, &mut err) };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert_eq!(&buf[..3], &[0, 0, 0], "content bytes must be zeroed");
        if !err.is_null() {
            unsafe { veil_free_string(err) };
        }
    }

    #[test]
    fn validate_bip39_zeroize_wipes_rejected_phrase() {
        // A valid-UTF-8 but not-a-mnemonic phrase is also wiped (was already the
        // case; guards against regression).
        let mut buf: Vec<u8> = b"not a real mnemonic".to_vec();
        let n = buf.len();
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf.as_mut_ptr(), n, &mut err) };
        assert_ne!(rc, VEIL_OK);
        assert!(
            buf.iter().all(|&b| b == 0),
            "phrase buffer must be fully zeroed"
        );
        if !err.is_null() {
            unsafe { veil_free_string(err) };
        }
    }

    /// The generational table makes a double-close a safe no-op and a stale
    /// token (slot reused by a DIFFERENT handle) fail validation, WITHOUT
    /// dereferencing the opaque token. Exercised on a local table with a cheap
    /// value type — no real handle / allocation / deref required.
    #[test]
    fn handle_table_insert_get_remove_roundtrip() {
        let table = StdMutex::new(HandleTable::<u64>::new());
        let tok = HandleTable::insert(&table, 0xABCD);
        assert_ne!(tok, 0, "a live token must never be NULL");
        assert_eq!(
            HandleTable::get(&table, tok).as_deref().copied(),
            Some(0xABCD),
            "get must return the live value"
        );
        assert_eq!(
            HandleTable::remove(&table, tok).as_deref().copied(),
            Some(0xABCD),
            "first close must claim the live entry"
        );
        assert!(
            HandleTable::get(&table, tok).is_none(),
            "use-after-close must report not-live"
        );
        assert!(
            HandleTable::remove(&table, tok).is_none(),
            "double-close must be a safe no-op"
        );
    }

    /// ABA: closing a handle and creating a new one that REUSES the freed slot
    /// must NOT let the old (stale) token address the new handle. The bumped
    /// per-slot generation makes the two tokens distinct and the stale one
    /// invalid — the property the prior address-keyed registry could not give.
    #[test]
    fn handle_table_generation_defeats_aba() {
        let table = StdMutex::new(HandleTable::<u64>::new());
        let t1 = HandleTable::insert(&table, 1);
        assert!(HandleTable::remove(&table, t1).is_some());
        // New handle reuses slot 0 with a bumped generation.
        let t2 = HandleTable::insert(&table, 2);
        assert_ne!(
            t1, t2,
            "slot reuse must yield a distinct token (new generation)"
        );
        assert!(
            HandleTable::get(&table, t1).is_none(),
            "stale token must NOT address the reused slot (ABA closed)"
        );
        assert_eq!(
            HandleTable::get(&table, t2).as_deref().copied(),
            Some(2),
            "the live token still resolves"
        );
        assert!(
            HandleTable::remove(&table, t1).is_none(),
            "stale double-close must not free the reused slot"
        );
        assert!(
            HandleTable::get(&table, t2).is_some(),
            "live handle survives a stale close of its predecessor"
        );
    }

    /// Per-type isolation: a token minted by one table must not resolve in
    /// another, so the use path rejects a cross-type token before any deref.
    #[test]
    fn handle_table_tokens_are_per_table() {
        let a = StdMutex::new(HandleTable::<u64>::new());
        let b = StdMutex::new(HandleTable::<u64>::new());
        let tok = HandleTable::insert(&a, 7);
        assert!(
            HandleTable::get(&b, tok).is_none(),
            "a token from table A must not resolve in table B"
        );
    }

    /// Audit M-2 (use path): a real USE entry point handed a token that is not
    /// live in its table — never-created, already-closed, ABA-stale, or the
    /// wrong type — must return INVALID_ARG via the liveness guard and NEVER
    /// dereference the opaque (non-pointer) token. In a unit test the global
    /// handle/app/stream tables are empty (no daemon connection), so any
    /// synthetic non-NULL token is "not live" and exercises exactly that guard.
    #[test]
    fn use_with_unknown_handle_token_returns_error_not_uaf() {
        let bogus = 0x0AF5_0001_usize as *mut VeilHandle;
        let mut out_node = [0u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_get_node_id(bogus, out_node.as_mut_ptr(), &mut err) };
        assert_eq!(
            rc, VEIL_ERR_INVALID_ARG,
            "unknown handle must return INVALID_ARG, not crash"
        );
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert_eq!(msg, "VeilHandle: use-after-close or unknown handle");
        unsafe {
            veil_free_string(err);
        }
    }

    #[test]
    fn use_with_unknown_app_token_returns_error_not_uaf() {
        let bogus = 0x0AF5_0003_usize as *mut VeilApp;
        let dst_node = [0u8; 32];
        let dst_app = [0u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        // len == 0 with valid stack dst buffers carries control past the cheap
        // arg checks straight to the liveness guard.
        let rc = unsafe {
            veil_send(
                bogus,
                dst_node.as_ptr(),
                dst_app.as_ptr(),
                0,
                ptr::null(),
                0,
                &mut err,
            )
        };
        assert_eq!(
            rc, VEIL_ERR_INVALID_ARG,
            "unknown app must return INVALID_ARG, not crash"
        );
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert_eq!(msg, "VeilApp: use-after-close or unknown handle");
        unsafe {
            veil_free_string(err);
        }
    }

    #[test]
    fn use_with_unknown_stream_token_returns_error_not_uaf() {
        let bogus = 0x0AF5_0004_usize as *mut VeilStreamFfi;
        let mut err: *mut c_char = ptr::null_mut();
        // len == 0 → no payload deref; control reaches the liveness guard.
        let rc = unsafe { veil_stream_write(bogus, ptr::null(), 0, &mut err) };
        assert_eq!(
            rc, VEIL_ERR_INVALID_ARG,
            "unknown stream must return INVALID_ARG, not crash"
        );
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert_eq!(msg, "VeilStreamFfi: use-after-close or unknown handle");
        unsafe {
            veil_free_string(err);
        }
    }

    #[test]
    fn null_string_free_is_noop() {
        unsafe {
            veil_free_string(ptr::null_mut());
        }
    }

    /// Onboarding phrase epic: a freshly generated master phrase is 24 words
    /// and round-trips through the production decoder (checksum valid) — the
    /// same phrase later drives the deterministic restore.
    #[test]
    fn generate_master_phrase_roundtrips() {
        let mut phrase: *mut c_char = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_generate_master_phrase(&mut phrase, &mut err) };
        assert_eq!(rc, VEIL_OK);
        assert!(!phrase.is_null());
        let s = unsafe { CStr::from_ptr(phrase) }
            .to_str()
            .expect("utf-8 phrase")
            .to_string();
        assert_eq!(s.split(' ').count(), 24);
        assert!(
            veil_identity::master_seed::decode_master_seed_from_phrase(&s).is_ok(),
            "generated phrase must satisfy the master-phrase checksum"
        );
        // Two calls must not collide (fresh entropy each time).
        let mut phrase2: *mut c_char = ptr::null_mut();
        let rc2 = unsafe { veil_generate_master_phrase(&mut phrase2, &mut err) };
        assert_eq!(rc2, VEIL_OK);
        let s2 = unsafe { CStr::from_ptr(phrase2) }.to_str().unwrap();
        assert_ne!(s, s2);
        unsafe {
            veil_free_string(phrase);
            veil_free_string(phrase2);
        }
    }

    #[test]
    fn generate_master_phrase_null_out_is_invalid_arg() {
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_generate_master_phrase(ptr::null_mut(), &mut err) };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        unsafe { veil_free_string(err) };
    }

    #[test]
    fn connect_to_invalid_path_returns_null() {
        let path = CString::new("/nonexistent/path/that/does/not/exist.sock").unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let h = unsafe { veil_connect(path.as_bytes().as_ptr(), path.as_bytes().len(), &mut err) };
        assert!(h.is_null());
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
        }
    }

    #[test]
    fn connect_with_null_path_returns_null() {
        let mut err: *mut c_char = ptr::null_mut();
        let h = unsafe { veil_connect(ptr::null(), 0, &mut err) };
        assert!(h.is_null());
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
        }
    }

    #[test]
    fn null_app_get_id_returns_invalid_arg() {
        let mut buf = [0u8; 32];
        let rc = unsafe { veil_app_get_app_id(ptr::null(), buf.as_mut_ptr()) };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    }

    #[test]
    fn null_app_get_endpoint_id_returns_zero() {
        let rc = unsafe { veil_app_get_endpoint_id(ptr::null()) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn null_app_close_is_noop() {
        unsafe {
            veil_app_close(ptr::null_mut());
        }
    }

    #[test]
    fn null_stream_close_is_noop() {
        unsafe {
            veil_stream_close(ptr::null_mut());
        }
    }

    #[test]
    fn null_app_send_returns_invalid_arg() {
        let dst_node = [0u8; 32];
        let dst_app = [0u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_send(
                ptr::null_mut(),
                dst_node.as_ptr(),
                dst_app.as_ptr(),
                0,
                ptr::null(),
                0,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
        }
    }

    /// every block_on / blocking_lock FFI entry
    /// point must refuse to run when called from inside a Tokio
    /// runtime worker (e.g. recv-handler callback) — a re-entrant
    /// `block_on` would park the only worker forever. We verify the
    /// guard fires by calling `veil_connect` from a tokio task; the
    /// runtime context check should trip and surface
    /// [`VEIL_ERR_REENTRANT`] / a NULL handle without ever
    /// reaching `runtime.block_on`.
    #[test]
    fn phase647_h6_connect_from_tokio_runtime_returns_reentrant() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(async {
            let path = CString::new("/tmp/veil-h6.sock").unwrap();
            let mut err: *mut c_char = ptr::null_mut();
            let h =
                unsafe { veil_connect(path.as_bytes().as_ptr(), path.as_bytes().len(), &mut err) };
            let err_string = if err.is_null() {
                String::new()
            } else {
                let s = unsafe { CStr::from_ptr(err) }
                    .to_string_lossy()
                    .into_owned();
                unsafe {
                    veil_free_string(err);
                }
                s
            };
            (h.is_null(), err_string)
        });
        assert!(
            r.0,
            "handle must be NULL when called from inside tokio runtime"
        );
        assert!(
            r.1.contains("would deadlock"),
            "err message should mention deadlock; got: {}",
            r.1
        );
    }

    /// sanity: the same call from a non-tokio thread must NOT trip
    /// the guard (otherwise the guard is broken). We can't actually
    /// connect (path is invalid), but the failure mode must be the
    /// connect-error path, not the re-entrancy path.
    #[test]
    fn phase647_h6_connect_from_plain_thread_does_not_trip_guard() {
        let path = CString::new("/nonexistent/h6.sock").unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let h = unsafe { veil_connect(path.as_bytes().as_ptr(), path.as_bytes().len(), &mut err) };
        assert!(h.is_null());
        assert!(!err.is_null());
        let s = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            veil_free_string(err);
        }
        // Real failure is "connect failed:..." — guard would say "would deadlock".
        assert!(
            !s.contains("would deadlock"),
            "guard must NOT fire on a fresh thread; got: {s}"
        );
    }

    /// zeroize-on-consume variant overwrites
    /// the caller's phrase buffer in place. After return, every byte
    /// of the original phrase must be `0` — including on the error
    /// path (invalid checksum), so a UI bug that retries with the
    /// same buffer doesn't keep the secret resident in heap.
    #[test]
    fn phase647_h8_validate_zeroize_clears_phrase_buffer_on_success() {
        let phrase = fresh_phrase();
        // Explicit-length ABI: pass the content bytes (no NUL terminator).
        let mut buf: Vec<u8> = phrase.as_bytes().to_vec();
        let n = buf.len();
        let buf_ptr = buf.as_mut_ptr();
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf_ptr, n, &mut err) };
        assert_eq!(rc, VEIL_OK);
        assert!(err.is_null());
        // Every byte must now be 0.
        assert!(
            buf.iter().all(|&b| b == 0),
            "buffer must be fully zeroed; got: {:?}",
            buf
        );
    }

    #[test]
    fn phase647_h8_validate_zeroize_clears_phrase_buffer_on_error() {
        // Crafted invalid phrase (random words but not a real BIP-39).
        let bad = std::ffi::CString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon zoo",
        )
        .unwrap();
        let mut buf: Vec<u8> = bad.as_bytes().to_vec();
        let n = buf.len();
        let buf_ptr = buf.as_mut_ptr();
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf_ptr, n, &mut err) };
        assert_eq!(rc, VEIL_ERR); // bad checksum
        if !err.is_null() {
            unsafe {
                veil_free_string(err);
            }
        }
        // Even on the error path the buffer must be zeroed.
        assert!(
            buf.iter().all(|&b| b == 0),
            "buffer must be zeroed on error path; got: {:?}",
            buf
        );
    }

    #[test]
    fn phase647_h8_validate_zeroize_rejects_null() {
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_validate_bip39_phrase_zeroize(ptr::null_mut(), 0, &mut err) };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
        }
    }

    unsafe extern "C" fn noop_event_cb(
        _user: *mut std::ffi::c_void,
        _kind: u8,
        _payload: *const u8,
        _payload_len: size_t,
    ) {
    }

    #[test]
    fn null_handle_set_event_handler_returns_invalid_arg() {
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_set_event_handler(
                ptr::null_mut(),
                Some(noop_event_cb),
                ptr::null_mut(),
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
        }
    }

    /// NULL callback (i.e. `None` after
    /// the `Option<fn>` retype) must be rejected with `VEIL_ERR_INVALID_ARG`
    /// rather than dereferenced — pre-fix this would have segfaulted.
    #[test]
    fn null_callback_set_event_handler_returns_invalid_arg() {
        // Note: passing `None` requires a live handle to exercise the
        // post-handle-check path. We use a null handle here to confirm
        // that handle check fires first; a separate test would need a
        // real VeilHandle to hit the cb-check after.
        let mut err: *mut c_char = ptr::null_mut();
        let rc =
            unsafe { veil_set_event_handler(ptr::null_mut(), None, ptr::null_mut(), &mut err) };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
        }
    }

    #[test]
    fn event_kind_constants_match_proto() {
        assert_eq!(
            VEIL_EVENT_SESSIONS_CHANGED,
            veil_proto::event_kind::SESSIONS_CHANGED
        );
        assert_eq!(
            VEIL_EVENT_MOBILE_TIER_CHANGED,
            veil_proto::event_kind::MOBILE_TIER_CHANGED
        );
        assert_eq!(
            VEIL_EVENT_IDENTITY_ROTATED,
            veil_proto::event_kind::IDENTITY_ROTATED
        );
        assert_eq!(
            VEIL_EVENT_MAILBOX_DRAINED,
            veil_proto::event_kind::MAILBOX_DRAINED
        );
    }

    // ── Wake-HMAC FFI (Epic 489.10 slice 4.3.3) ──────────────────────

    #[test]
    fn wake_hmac_constants_match_crypto() {
        assert_eq!(
            VEIL_WAKE_HMAC_KEY_LEN,
            veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN,
        );
        assert_eq!(
            VEIL_WAKE_PAYLOAD_LEN,
            veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN,
        );
        // Verdict codes are not exposed on the crypto side as integers
        // (they're a Rust enum), but this test pins the FFI mapping
        // contract: 0 = Valid, 1 = Tampered, 2 = Expired, 3 = Malformed.
        assert_eq!(VEIL_WAKE_VERDICT_VALID, 0);
        assert_eq!(VEIL_WAKE_VERDICT_TAMPERED, 1);
        assert_eq!(VEIL_WAKE_VERDICT_EXPIRED, 2);
        assert_eq!(VEIL_WAKE_VERDICT_MALFORMED, 3);
    }

    #[test]
    fn generate_wake_hmac_key_writes_32_bytes() {
        let mut buf = [0u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_generate_wake_hmac_key(buf.as_mut_ptr(), &mut err) };
        assert_eq!(rc, VEIL_OK);
        assert!(err.is_null());
        // OsRng-generated key is extremely unlikely to be all zeros.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_wake_hmac_key_rejects_null_out() {
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe { veil_generate_wake_hmac_key(ptr::null_mut(), &mut err) };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe { veil_free_string(err) };
    }

    #[test]
    fn verify_wake_hmac_accepts_well_formed_payload() {
        let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([1u8; 32]);
        let cid = [2u8; 32];
        let rid = [3u8; 32];
        let ts = 1_700_000_000u64;
        let tag = veil_crypto::wake_hmac::compute_wake_hmac(&key, ts, &cid, &rid);
        let payload = veil_crypto::wake_hmac::encode_wake_payload(ts, &cid, &tag);
        let mut verdict: c_int = -1;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_verify_wake_hmac(
                key.as_bytes().as_ptr(),
                payload.as_ptr(),
                payload.len(),
                rid.as_ptr(),
                ts + 10,
                &mut verdict,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert_eq!(verdict, VEIL_WAKE_VERDICT_VALID);
        assert!(err.is_null());
    }

    #[test]
    fn verify_wake_hmac_rejects_forged_payload_silently() {
        let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([1u8; 32]);
        let wrong_key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([2u8; 32]);
        let cid = [2u8; 32];
        let rid = [3u8; 32];
        let ts = 1_700_000_000u64;
        let forged_tag = veil_crypto::wake_hmac::compute_wake_hmac(&wrong_key, ts, &cid, &rid);
        let payload = veil_crypto::wake_hmac::encode_wake_payload(ts, &cid, &forged_tag);
        let mut verdict: c_int = -1;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_verify_wake_hmac(
                key.as_bytes().as_ptr(),
                payload.as_ptr(),
                payload.len(),
                rid.as_ptr(),
                ts + 10,
                &mut verdict,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert_eq!(verdict, VEIL_WAKE_VERDICT_TAMPERED);
    }

    #[test]
    fn verify_wake_hmac_surfaces_expired_distinct_from_tampered() {
        let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([1u8; 32]);
        let cid = [2u8; 32];
        let rid = [3u8; 32];
        let ts = 1_700_000_000u64;
        let tag = veil_crypto::wake_hmac::compute_wake_hmac(&key, ts, &cid, &rid);
        let payload = veil_crypto::wake_hmac::encode_wake_payload(ts, &cid, &tag);
        let now_far_future = ts + veil_crypto::wake_hmac::WAKE_FRESHNESS_SECS + 1;
        let mut verdict: c_int = -1;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_verify_wake_hmac(
                key.as_bytes().as_ptr(),
                payload.as_ptr(),
                payload.len(),
                rid.as_ptr(),
                now_far_future,
                &mut verdict,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert_eq!(verdict, VEIL_WAKE_VERDICT_EXPIRED);
    }

    #[test]
    fn verify_wake_hmac_rejects_malformed_length() {
        let key = [0u8; 32];
        let rid = [0u8; 32];
        let short = [0u8; VEIL_WAKE_PAYLOAD_LEN - 1];
        let mut verdict: c_int = -1;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_verify_wake_hmac(
                key.as_ptr(),
                short.as_ptr(),
                short.len(),
                rid.as_ptr(),
                1_700_000_000,
                &mut verdict,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert_eq!(verdict, VEIL_WAKE_VERDICT_MALFORMED);
    }

    #[test]
    fn verify_wake_hmac_rejects_null_args() {
        let key = [0u8; 32];
        let mut verdict: c_int = -1;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_verify_wake_hmac(
                ptr::null(),
                ptr::null(),
                0,
                key.as_ptr(),
                0,
                &mut verdict,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe { veil_free_string(err) };
    }

    // ── BIP-39 restore FFI ───────────────────────────────────────

    fn fresh_phrase() -> std::ffi::CString {
        // Generate a fresh master_seed and convert to its BIP-39 phrase.
        // This guarantees the phrase is well-formed (24 words, valid
        // checksum) without hardcoding a secret in the test.
        let seed = veil_identity::master_seed::generate_master_seed();
        let mnemonic =
            veil_identity::master_seed::encode_master_seed_to_phrase(&seed).expect("seed → phrase");
        std::ffi::CString::new(mnemonic.to_string()).unwrap()
    }

    #[test]
    fn sovereign_signer_is_one_burst_phrase_bound_and_zeroizing() {
        let phrase = fresh_phrase();
        let mut phrase_buf = phrase.as_bytes().to_vec();
        let phrase_len = phrase_buf.len();
        let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
        let mut node_id = [0u8; 32];
        let mut public_key = [0u8; 32];
        let mut err: *mut c_char = ptr::null_mut();

        let rc = unsafe {
            veil_sovereign_signer_open_from_phrase_zeroize(
                phrase_buf.as_mut_ptr(),
                phrase_len,
                &mut signer,
                node_id.as_mut_ptr(),
                node_id.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert!(err.is_null());
        assert!(!signer.is_null());
        assert!(phrase_buf.iter().all(|byte| *byte == 0));
        assert_eq!(node_id, veil_crypto::identity::compute_node_id(&public_key));

        let message = b"xveil-device-membership-v2";
        let mut signature = [0u8; 64];
        let rc = unsafe {
            veil_sovereign_signer_sign(
                signer,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert!(err.is_null());
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .expect("valid sovereign public key")
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .expect("signature verifies against exported public key");

        unsafe { veil_sovereign_signer_close(signer) };
        let rc = unsafe {
            veil_sovereign_signer_sign(
                signer,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR_CLOSED);
        assert!(!err.is_null());
        unsafe {
            veil_free_string(err);
            veil_sovereign_signer_close(signer);
        }
    }

    #[test]
    fn sovereign_signer_rejects_invalid_phrase_after_wiping_it() {
        let mut phrase_buf = b"not a recovery phrase".to_vec();
        let phrase_len = phrase_buf.len();
        let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
        let mut node_id = [0u8; 32];
        let mut public_key = [0u8; 32];
        let mut err: *mut c_char = ptr::null_mut();

        let rc = unsafe {
            veil_sovereign_signer_open_from_phrase_zeroize(
                phrase_buf.as_mut_ptr(),
                phrase_len,
                &mut signer,
                node_id.as_mut_ptr(),
                node_id.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR);
        assert!(signer.is_null());
        assert!(phrase_buf.iter().all(|byte| *byte == 0));
        assert!(!err.is_null());
        unsafe { veil_free_string(err) };
    }

    #[test]
    fn sovereign_hybrid_bundle_ffi_round_trip_is_variable_length_and_zeroizing() {
        let phrase = fresh_phrase();
        let mut create_phrase = phrase.as_bytes().to_vec();
        let create_len = create_phrase.len();
        let mut bundle_ptr: *mut u8 = ptr::null_mut();
        let mut bundle_len = 0usize;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_sovereign_bundle_create_hybrid512_zeroize(
                create_phrase.as_mut_ptr(),
                create_len,
                &mut bundle_ptr,
                &mut bundle_len,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert!(err.is_null());
        assert!(create_phrase.iter().all(|byte| *byte == 0));
        assert!(!bundle_ptr.is_null());
        let bundle = unsafe { std::slice::from_raw_parts(bundle_ptr, bundle_len) };

        let mut open_phrase = phrase.as_bytes().to_vec();
        let open_len = open_phrase.len();
        let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
        let mut algorithm = 0u8;
        let mut node_id = [0u8; 32];
        let mut public_key = [0u8; 1024];
        let mut public_key_len = 0usize;
        let rc = unsafe {
            veil_sovereign_signer_open_bundle_zeroize(
                bundle.as_ptr(),
                bundle.len(),
                open_phrase.as_mut_ptr(),
                open_len,
                &mut signer,
                &mut algorithm,
                node_id.as_mut_ptr(),
                node_id.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut public_key_len,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert!(err.is_null());
        assert!(open_phrase.iter().all(|byte| *byte == 0));
        assert_eq!(
            algorithm,
            veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid.wire_byte()
        );
        assert_eq!(public_key_len, 929);
        assert_eq!(
            node_id,
            veil_crypto::identity::compute_node_id(&public_key[..public_key_len])
        );

        let message = b"xveil-sovereign-hybrid-probe";
        let mut signature = [0u8; 1024];
        let mut signature_len = 0usize;
        let rc = unsafe {
            veil_sovereign_signer_sign_into(
                signer,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut signature_len,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert!(signature_len > 64);
        let mut valid = false;
        let rc = unsafe {
            veil_sovereign_verify(
                algorithm,
                node_id.as_ptr(),
                public_key.as_ptr(),
                public_key_len,
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature_len,
                &mut valid,
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_OK);
        assert!(valid);

        unsafe {
            veil_sovereign_signer_close(signer);
            veil_free_buf(bundle_ptr, bundle_len);
        }
    }

    #[test]
    fn sovereign_recovery_certificate_ffi_preserves_node_id_and_wipes_codes() {
        let phrase = fresh_phrase();
        let mut create_phrase = phrase.as_bytes().to_vec();
        let create_len = create_phrase.len();
        let mut bundle_ptr: *mut u8 = ptr::null_mut();
        let mut bundle_len = 0usize;
        let mut err: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe {
                veil_sovereign_bundle_create_hybrid512_zeroize(
                    create_phrase.as_mut_ptr(),
                    create_len,
                    &mut bundle_ptr,
                    &mut bundle_len,
                    &mut err,
                )
            },
            VEIL_OK
        );

        let mut export_phrase = phrase.as_bytes().to_vec();
        let export_phrase_len = export_phrase.len();
        let mut export_code = b"xvrc-ffi-code-with-more-than-thirty-two-randomish-bytes".to_vec();
        let export_code_len = export_code.len();
        let mut certificate_ptr: *mut u8 = ptr::null_mut();
        let mut certificate_len = 0usize;
        assert_eq!(
            unsafe {
                veil_sovereign_recovery_certificate_export_zeroize(
                    bundle_ptr,
                    bundle_len,
                    export_phrase.as_mut_ptr(),
                    export_phrase_len,
                    export_code.as_mut_ptr(),
                    export_code_len,
                    &mut certificate_ptr,
                    &mut certificate_len,
                    &mut err,
                )
            },
            VEIL_OK
        );
        assert!(err.is_null());
        assert!(export_phrase.iter().all(|byte| *byte == 0));
        assert!(export_code.iter().all(|byte| *byte == 0));
        let certificate =
            unsafe { std::slice::from_raw_parts(certificate_ptr.cast_const(), certificate_len) };
        assert_eq!(&certificate[..4], b"XVRC");

        let mut open_code = b"xvrc-ffi-code-with-more-than-thirty-two-randomish-bytes".to_vec();
        let open_code_len = open_code.len();
        let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
        let mut algorithm = 0u8;
        let mut node_id = [0u8; 32];
        let mut public_key = [0u8; 1024];
        let mut public_key_len = 0usize;
        assert_eq!(
            unsafe {
                veil_sovereign_signer_open_recovery_certificate_zeroize(
                    certificate.as_ptr(),
                    certificate.len(),
                    open_code.as_mut_ptr(),
                    open_code_len,
                    &mut signer,
                    &mut algorithm,
                    node_id.as_mut_ptr(),
                    node_id.len(),
                    public_key.as_mut_ptr(),
                    public_key.len(),
                    &mut public_key_len,
                    &mut err,
                )
            },
            VEIL_OK
        );
        assert!(err.is_null());
        assert!(open_code.iter().all(|byte| *byte == 0));
        assert_eq!(public_key_len, 929);
        assert_eq!(
            node_id,
            veil_crypto::identity::compute_node_id(&public_key[..public_key_len])
        );
        assert_eq!(&certificate[6..38], &node_id);

        unsafe {
            veil_sovereign_signer_close(signer);
            veil_free_buf(certificate_ptr, certificate_len);
            veil_free_buf(bundle_ptr, bundle_len);
        }
    }

    // (validate accept/garbage/null are covered by the `phase647_h8_*` zeroize
    // tests above; the non-zeroize `veil_validate_bip39_phrase` was removed in
    // the explicit-length ABI migration.)

    #[test]
    fn epic489_8_restore_writes_identity_files() {
        // End-to-end: valid phrase + tempdir → produces signed identity
        // document + instance file + identity_sk on disk. Uses the zeroize
        // restore variant (explicit-length ABI; the phrase buffer is wiped).
        let dir = tempfile::tempdir().expect("tempdir");
        let phrase = fresh_phrase();
        let mut pbuf = phrase.as_bytes().to_vec();
        let pbuf_len = pbuf.len();
        let dir_s = dir.path().to_str().unwrap();
        let label = "test-device";
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_restore_identity_from_phrase_zeroize(
                pbuf.as_mut_ptr(),
                pbuf_len,
                dir_s.as_ptr(),
                dir_s.len(),
                label.as_ptr(),
                label.len(),
                &mut err,
            )
        };
        if rc != VEIL_OK {
            let detail = unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() };
            unsafe {
                veil_free_string(err);
            }
            panic!("restore failed: {detail}");
        }
        assert!(
            dir.path().join("identity_document.bin").exists(),
            "identity_document.bin must be written"
        );
    }

    #[test]
    fn epic489_8_restore_same_phrase_yields_same_node_id() {
        // Critical: BIP-39 → master_seed → master_pk → node_id is
        // DETERMINISTIC. Restoring on Device A and Device B from the
        // same phrase MUST give the same node_id (that's the whole
        // point of identity recovery). Each zeroize call wipes its buffer,
        // so we materialize a fresh phrase buffer per device.
        let phrase = fresh_phrase();
        let label = "dev";

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let dir_a_s = dir_a.path().to_str().unwrap();
        let dir_b_s = dir_b.path().to_str().unwrap();
        let mut err: *mut c_char = ptr::null_mut();

        let mut pbuf_a = phrase.as_bytes().to_vec();
        let pbuf_a_len = pbuf_a.len();
        let rc_a = unsafe {
            veil_restore_identity_from_phrase_zeroize(
                pbuf_a.as_mut_ptr(),
                pbuf_a_len,
                dir_a_s.as_ptr(),
                dir_a_s.len(),
                label.as_ptr(),
                label.len(),
                &mut err,
            )
        };
        assert_eq!(rc_a, VEIL_OK);
        let mut pbuf_b = phrase.as_bytes().to_vec();
        let pbuf_b_len = pbuf_b.len();
        let rc_b = unsafe {
            veil_restore_identity_from_phrase_zeroize(
                pbuf_b.as_mut_ptr(),
                pbuf_b_len,
                dir_b_s.as_ptr(),
                dir_b_s.len(),
                label.as_ptr(),
                label.len(),
                &mut err,
            )
        };
        assert_eq!(rc_b, VEIL_OK);

        // Both files start with the same node_id field (first 32 bytes
        // after magic "ID" + version + master_algo). We just
        // byte-compare the node_id range, not decode the full document.
        let bytes_a = std::fs::read(dir_a.path().join("identity_document.bin")).unwrap();
        let bytes_b = std::fs::read(dir_b.path().join("identity_document.bin")).unwrap();
        // Magic "ID" (2) + version (1) + master_algo (1) = 4 byte prefix
        // before node_id.
        assert_eq!(
            &bytes_a[4..36],
            &bytes_b[4..36],
            "same phrase MUST produce same node_id (BIP-39 deterministic)"
        );
    }

    // ── Wake-HMAC put + replica-lookup FFI (Epic 489.10 slice 4.3.4) ──

    /// `veil_mailbox_put_with_wake_hmac` must exist with the full arg
    /// set (incl. the wake bytes) and reject a NULL handle up-front with
    /// `VEIL_ERR_INVALID_ARG` — i.e. the wake-arg slot is wired through
    /// without needing a live daemon. Compile-time presence of the symbol
    /// with this exact signature is itself part of what we're asserting.
    #[test]
    fn mailbox_put_with_wake_hmac_rejects_null_handle() {
        let id = [7u8; 32];
        let wake = [0xABu8; 16];
        let mut err: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_mailbox_put_with_wake_hmac(
                ptr::null_mut(), // handle
                id.as_ptr(),     // receiver_id
                id.as_ptr(),     // content_id
                id.as_ptr(),     // sender_id
                ptr::null(),     // blob
                0,
                ptr::null(), // push_envelope
                0,
                ptr::null(), // capability_token
                0,
                wake.as_ptr(), // wake_hmac_envelope
                wake.len(),
                ptr::null_mut(), // out_evicted
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe { veil_free_string(err) };
    }

    /// The legacy `veil_mailbox_put` / `_with_capability` exports must
    /// keep their original ABI — same arg arity, same NULL-handle
    /// rejection. (A signature drift would fail to compile here.)
    #[test]
    fn legacy_mailbox_put_exports_keep_abi() {
        let id = [5u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        let rc1 = unsafe {
            veil_mailbox_put(
                ptr::null_mut(),
                id.as_ptr(),
                id.as_ptr(),
                id.as_ptr(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut err,
            )
        };
        assert_eq!(rc1, VEIL_ERR_INVALID_ARG);
        unsafe { veil_free_string(err) };
        err = ptr::null_mut();
        let rc2 = unsafe {
            veil_mailbox_put_with_capability(
                ptr::null_mut(),
                id.as_ptr(),
                id.as_ptr(),
                id.as_ptr(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                &mut err,
            )
        };
        assert_eq!(rc2, VEIL_ERR_INVALID_ARG);
        unsafe { veil_free_string(err) };
    }

    /// `veil_lookup_rendezvous_replicas` must reject NULL out-params
    /// up-front and leave them in the documented empty/failure state.
    #[test]
    fn lookup_rendezvous_replicas_rejects_null_out_params() {
        let id = [9u8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        // NULL handle → INVALID_ARG (null_check! fires before any deref).
        let rc = unsafe {
            veil_lookup_rendezvous_replicas(
                ptr::null_mut(),
                id.as_ptr(),
                0,
                ptr::null_mut(), // out_buf
                ptr::null_mut(), // out_len
                &mut err,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert!(!err.is_null());
        unsafe { veil_free_string(err) };
    }

    /// `veil_free_replica_buf(NULL, _)` is a documented no-op.
    #[test]
    fn free_replica_buf_null_is_noop() {
        unsafe {
            veil_free_replica_buf(ptr::null_mut(), 0);
            veil_free_replica_buf(ptr::null_mut(), 9999);
        }
    }

    /// Independent parser for the replica wire layout documented on
    /// `veil_lookup_rendezvous_replicas` — decodes back to
    /// `(relay_node_id, valid_until, push, cap, wake)` tuples WITHOUT
    /// reusing the serializer, so a layout change in either direction
    /// fails the round-trip.
    #[allow(clippy::type_complexity)]
    fn parse_replica_buf(
        buf: &[u8],
    ) -> Vec<([u8; 32], u64, Vec<u8>, Vec<u8>, Vec<u8>, u8, Vec<u8>)> {
        let mut off = 0usize;
        let take = |buf: &[u8], off: &mut usize, n: usize| -> Vec<u8> {
            let out = buf[*off..*off + n].to_vec();
            *off += n;
            out
        };
        let count = u32::from_le_bytes(take(buf, &mut off, 4).try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut rid = [0u8; 32];
            rid.copy_from_slice(&take(buf, &mut off, 32));
            let valid = u64::from_le_bytes(take(buf, &mut off, 8).try_into().unwrap());
            let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(3);
            for _ in 0..3 {
                let len = u16::from_le_bytes(take(buf, &mut off, 2).try_into().unwrap()) as usize;
                blobs.push(take(buf, &mut off, len));
            }
            let wake = blobs.pop().unwrap();
            let cap = blobs.pop().unwrap();
            let push = blobs.pop().unwrap();
            // v5 KEM trailer: algo byte + u16-len-prefixed pubkey.
            let kem_algo = take(buf, &mut off, 1)[0];
            let kem_len = u16::from_le_bytes(take(buf, &mut off, 2).try_into().unwrap()) as usize;
            let kem_pk = take(buf, &mut off, kem_len);
            out.push((rid, valid, push, cap, wake, kem_algo, kem_pk));
        }
        assert_eq!(off, buf.len(), "no trailing bytes in replica buffer");
        out
    }

    #[test]
    fn serialize_replica_buf_roundtrips_layout() {
        let replicas = vec![
            veilclient::RendezvousReplicaInfo {
                relay_node_id: [0x11; 32],
                valid_until_unix: 1_700_000_000,
                push_envelope: vec![1, 2, 3, 4, 5],
                capability_token: vec![9, 8, 7],
                wake_hmac_envelope: vec![0xAA, 0xBB],
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: vec![0xCC, 0xDD, 0xEE],
            },
            // Second entry exercises empty blobs (all len-prefixes 0, incl. KEM).
            veilclient::RendezvousReplicaInfo {
                relay_node_id: [0x22; 32],
                valid_until_unix: 0,
                push_envelope: vec![],
                capability_token: vec![],
                wake_hmac_envelope: vec![],
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: vec![],
            },
        ];
        let buf = serialize_replica_buf(&replicas);
        // count(4) + entry0 (32+8 + (2+5)+(2+3)+(2+2) + 1+(2+3))
        //          + entry1 (32+8 + 2+2+2 + 1+2)
        let expected_len = 4 + (32 + 8 + 7 + 5 + 4 + 1 + 5) + (32 + 8 + 2 + 2 + 2 + 1 + 2);
        assert_eq!(buf.len(), expected_len, "exact serialized length");

        let parsed = parse_replica_buf(&buf);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, [0x11; 32]);
        assert_eq!(parsed[0].1, 1_700_000_000);
        assert_eq!(parsed[0].2, vec![1, 2, 3, 4, 5]);
        assert_eq!(parsed[0].3, vec![9, 8, 7]);
        assert_eq!(parsed[0].4, vec![0xAA, 0xBB]);
        assert_eq!(parsed[0].5, 0);
        assert_eq!(parsed[0].6, vec![0xCC, 0xDD, 0xEE]);
        assert_eq!(parsed[1].0, [0x22; 32]);
        assert_eq!(parsed[1].1, 0);
        assert!(parsed[1].2.is_empty());
        assert!(parsed[1].3.is_empty());
        assert!(parsed[1].4.is_empty());
        assert_eq!(parsed[1].5, 0);
        assert!(parsed[1].6.is_empty());
    }

    #[test]
    fn serialize_replica_buf_empty_is_count_header_only() {
        let buf = serialize_replica_buf(&[]);
        assert_eq!(
            buf,
            vec![0, 0, 0, 0],
            "empty list = u32 count 0, nothing else"
        );
        // And it round-trips back to an empty parse.
        assert!(parse_replica_buf(&buf).is_empty());
    }

    /// The (ptr, len) the C entry-point leaks must be reconstructable by
    /// `veil_free_replica_buf` with no leak/double-free. Mirror the
    /// shrink_to_fit + forget + from_raw_parts dance the export performs.
    #[test]
    fn replica_buf_leak_then_free_roundtrips() {
        let replicas = vec![veilclient::RendezvousReplicaInfo {
            relay_node_id: [0x33; 32],
            valid_until_unix: 42,
            push_envelope: vec![0; 10],
            capability_token: vec![1; 4],
            wake_hmac_envelope: vec![2; 6],
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![3; 8],
        }];
        let mut buf = serialize_replica_buf(&replicas);
        buf.shrink_to_fit();
        let len = buf.len();
        let ptr = buf.as_mut_ptr();
        std::mem::forget(buf);
        // Caller would parse here; we just confirm the free path is sound
        // (run under `cargo test` / Miri this proves no double-free / leak).
        unsafe { veil_free_replica_buf(ptr, len) };
    }

    #[test]
    fn ephemeral_service_registration_zeroizes_seed_before_dead_handle_error() {
        let mut seed = [0xA5u8; 32];
        let mut public_key = [0u8; 32];
        let mut error: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_register_ephemeral_onion_service_zeroize(
                1usize as *mut VeilHandle,
                seed.as_mut_ptr(),
                3,
                public_key.as_mut_ptr(),
                &mut error,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert_eq!(seed, [0u8; 32], "writable caller seed is always scrubbed");
        assert!(!error.is_null());
        unsafe { veil_free_string(error) };
    }

    #[test]
    fn ephemeral_service_registration_rejects_zero_seed_after_scrub() {
        let mut seed = [0u8; 32];
        let mut public_key = [0u8; 32];
        let mut error: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            veil_register_ephemeral_onion_service_zeroize(
                1usize as *mut VeilHandle,
                seed.as_mut_ptr(),
                3,
                public_key.as_mut_ptr(),
                &mut error,
            )
        };
        assert_eq!(rc, VEIL_ERR_INVALID_ARG);
        assert_eq!(seed, [0u8; 32]);
        assert!(!error.is_null());
        unsafe { veil_free_string(error) };
    }
}
