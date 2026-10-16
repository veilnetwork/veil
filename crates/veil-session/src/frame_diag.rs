//! Name the code path that emits a given outbound frame.
//!
//! A frame that leaves the process is the one thing that cannot be argued
//! with, and a backtrace taken at the moment it leaves names the caller
//! without anybody guessing. This exists because reading the code did not
//! answer the question and could not have: on a leaf advertising
//! `NO_DHT_SERVICE`, ~100 distinct keys of incoming `Store` arrived every
//! fifteen seconds — 80% of everything it received — while every sender path
//! that could be read either filtered its candidates or never fired. The hook
//! named the caller in one run.
//!
//! `VEIL_DIAG_FRAME_METADATA` accepts the same selectors and records at most
//! 20,000 enqueue/response observations per process: destination prefix, frame
//! family/type, request id and length only. It has no payload head or backtrace
//! and is useful for size/timing correlation in an owned performance stand.
//! It is separate from the caller/backtrace diagnostic below and off by default.
//!
//! # Using it
//!
//! Set `VEIL_DIAG_FRAME` to a comma-separated list of `family[/type]`
//! selectors; unset means off and costs one relaxed load per outbound frame.
//!
//! ```text
//! VEIL_DIAG_FRAME=2/2    # discovery / STORE — what found the store flood
//! VEIL_DIAG_FRAME=2      # the whole discovery family (STORE + FIND_NODE…)
//! VEIL_DIAG_FRAME=2/2,3  # discovery/STORE plus everything in family 3
//! VEIL_DIAG_FRAME='*'    # everything, on a busy node a firehose
//! ```
//!
//! Numbers are the wire values from [`veil_proto::header`] — deliberately not
//! re-spelled here as names, because a second spelling is a second thing to
//! keep in step with the protocol.
//!
//! Output goes through `log` at INFO on target `veil::frame_diag`, so a
//! deployed node's existing sink carries it and the env var is the only lever
//! an operator has to find. Making the level the second lever would mean a
//! diagnostic that is switched on and still silent.
//!
//! ⛔ **`veil-cli node run` daemonises by default.** The hook then lives in a
//! different process than the one you set the variable for, and you get
//! silence while traffic flows. Pass `--foreground`.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// One selector: a family, and either a specific message type or all of them.
type Selector = (u8, Option<u16>);

static FILTER: OnceLock<Option<Vec<Selector>>> = OnceLock::new();
static SEEN: AtomicU64 = AtomicU64::new(0);
static METADATA_FILTER: OnceLock<Option<Vec<Selector>>> = OnceLock::new();
static METADATA_SEEN: AtomicU64 = AtomicU64::new(0);
static CHUNKS: OnceLock<bool> = OnceLock::new();
static CHUNKS_SEEN: AtomicU64 = AtomicU64::new(0);

/// Private stand correlation of opaque Forward fragments, independently of
/// the expensive backtrace hook. Off by default; no payloads, keys or source
/// roles are recorded. This never changes routing or admission.
pub fn note_chunk_body(stage: &str, node: Option<&[u8; 32]>, body: &[u8]) {
    if !*CHUNKS.get_or_init(|| std::env::var("VEIL_DIAG_CHUNKS").is_ok_and(|v| v == "1")) {
        return;
    }
    // A legitimate chunk fits comfortably here; avoid cloning arbitrary huge
    // envelopes merely because a diagnostic was enabled.
    if body.len() > 8192 || CHUNKS_SEEN.load(Ordering::Relaxed) >= 100_000 {
        return;
    }
    let Ok(forward) = veil_proto::delivery::ForwardPayload::decode(body) else {
        return;
    };
    if forward.envelope.payload.first() != Some(&veil_proto::delivery::CHUNKED_ENVELOPE_MARKER) {
        return;
    }
    let Ok(chunk) = veil_proto::delivery::ChunkedEnvelopePayload::decode(&forward.envelope.payload)
    else {
        return;
    };
    if CHUNKS_SEEN.fetch_add(1, Ordering::Relaxed) >= 100_000 {
        return;
    }
    // Host wall clock, for correlation inside an owned same-host fixture only.
    // Never a cross-device one-way latency measurement or a wire timestamp.
    let at_unix_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u64::MAX as u128) as u64;
    log::info!(
        "delivery.chunk_trace stage={stage} at_unix_us={at_unix_us} node={} hop={} origin={} transfer={} content={} index={} count={} bytes={} age_secs={} ttl_secs={}",
        node.map_or_else(|| "-".to_owned(), |n| hex_prefix(n, 4)),
        hex_prefix(&forward.next_hop_node_id, 4),
        hex_prefix(&forward.envelope.sender_node_id, 4),
        hex_prefix(&chunk.transfer_id, 16),
        hex_prefix(&chunk.orig_content_id, 8),
        chunk.chunk_index,
        chunk.chunk_count,
        chunk.data.len(),
        (at_unix_us / 1_000_000).saturating_sub(forward.envelope.created_at),
        forward.envelope.ttl_secs,
    );
}

pub fn note_chunk_frame(stage: &str, frame: &[u8]) {
    note_chunk_frame_at(stage, None, frame);
}

/// Record the selecting session's local node without attributing a source role.
pub fn note_chunk_frame_at(stage: &str, node: Option<&[u8; 32]>, frame: &[u8]) {
    if !*CHUNKS.get_or_init(|| std::env::var("VEIL_DIAG_CHUNKS").is_ok_and(|v| v == "1")) {
        return;
    }
    if family_and_type(frame)
        != Some((
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        ))
    {
        return;
    }
    note_chunk_body(stage, node, &frame[veil_proto::header::HEADER_SIZE..]);
}

/// First `LOUD` matches get a full backtrace; after that one in `EVERY` does,
/// so a busy node stays readable but the stream never goes fully silent.
const LOUD: u64 = 40;
const EVERY: u64 = 500;

/// `None` when the spec selects nothing — an empty or wholly unparsable value
/// leaves the hook off rather than quietly widening to everything.
fn parse_filter(spec: &str) -> Option<Vec<Selector>> {
    if spec.trim() == "*" {
        return Some(Vec::new()); // empty list = match every family
    }
    let selectors: Vec<Selector> = spec
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            let (family, msg_type) = match part.split_once('/') {
                Some((f, t)) => (f.trim(), Some(t.trim())),
                None => (part, None),
            };
            let family: u8 = family.parse().ok()?;
            let msg_type = match msg_type {
                Some("*") | None => None,
                Some(t) => Some(t.parse::<u16>().ok()?),
            };
            Some((family, msg_type))
        })
        .collect();
    if selectors.is_empty() {
        None
    } else {
        Some(selectors)
    }
}

fn filter() -> Option<&'static Vec<Selector>> {
    FILTER
        .get_or_init(|| {
            std::env::var("VEIL_DIAG_FRAME")
                .ok()
                .as_deref()
                .and_then(parse_filter)
        })
        .as_ref()
}

/// Does this (family, type) pair match? An empty selector list is `*`.
fn selected(selectors: &[Selector], family: u8, msg_type: u16) -> bool {
    selectors.is_empty()
        || selectors
            .iter()
            .any(|(f, t)| *f == family && t.is_none_or(|t| t == msg_type))
}

/// Note one outbound frame.
///
/// Every cost lives behind the env-var gate: with `VEIL_DIAG_FRAME` unset the
/// call is a relaxed load of an initialised `OnceLock` and a return. That
/// placement is the point — a probe whose work happens before its own gate
/// slows the node down whether or not anybody asked for it.
pub fn note_outbound(dest: &[u8; 32], frame: &[u8], via: &str) {
    note_metadata(dest, frame, via);
    let Some(selectors) = filter() else {
        return;
    };
    let Some((family, msg_type)) = family_and_type(frame) else {
        return;
    };
    if !selected(selectors, family, msg_type) {
        return;
    }

    let n = SEEN.fetch_add(1, Ordering::Relaxed);
    let loud = n < LOUD || n.is_multiple_of(EVERY);
    // For a STORE the first 32 body bytes are the key; for anything else this
    // is simply the head of the body, which is still the cheapest way to tell
    // two otherwise identical frames apart.
    let head = hex_prefix(
        frame
            .get(veil_proto::header::HEADER_SIZE..)
            .unwrap_or_default(),
        6,
    );
    let dst = hex_prefix(dest, 4);
    if loud {
        log::info!(
            target: "veil::frame_diag",
            "n={n} via={via} dst={dst} family={family} type={msg_type} head={head} len={}\n{}",
            frame.len(),
            std::backtrace::Backtrace::force_capture()
        );
    } else {
        log::info!(
            target: "veil::frame_diag",
            "n={n} via={via} dst={dst} family={family} type={msg_type} head={head} len={}",
            frame.len()
        );
    }
}

/// Optional bounded frame-size correlation without payloads or backtraces.
/// These generic observations are attempts, not confirmed queue admission.
pub(crate) fn note_metadata(dest: &[u8; 32], frame: &[u8], via: &str) {
    if let Some(observation) = prepare_metadata(None, dest, frame, via) {
        observation.emit();
    }
}

pub(crate) fn note_metadata_at(node: &[u8; 32], dest: &[u8; 32], frame: &[u8], via: &str) {
    if let Some(observation) = prepare_metadata(Some(node), dest, frame, via) {
        observation.emit();
    }
}

/// Capture small owned metadata before a frame is consumed, but emit only
/// after successful handoff. Disabled diagnostics neither clone nor hash it.
pub(crate) fn prepare_metadata(
    node: Option<&[u8; 32]>,
    dest: &[u8; 32],
    frame: &[u8],
    via: &str,
) -> Option<FrameMetadata> {
    let selectors = METADATA_FILTER
        .get_or_init(|| {
            std::env::var("VEIL_DIAG_FRAME_METADATA")
                .ok()
                .as_deref()
                .and_then(parse_filter)
        })
        .as_ref()?;
    let (family, msg_type) = family_and_type(frame)?;
    if !selected(selectors, family, msg_type) || METADATA_SEEN.load(Ordering::Relaxed) >= 20_000 {
        return None;
    }
    Some(FrameMetadata {
        node: node.map(|id| id[..4].try_into().expect("node prefix")),
        dest: dest[..4].try_into().expect("destination prefix"),
        via: via.to_owned(),
        family,
        msg_type,
        request: u32::from_be_bytes(frame[20..24].try_into().expect("checked header")),
        bytes: frame.len(),
        fingerprint: blake3::hash(frame).as_bytes()[..8]
            .try_into()
            .expect("hash prefix"),
    })
}

pub(crate) struct FrameMetadata {
    node: Option<[u8; 4]>,
    dest: [u8; 4],
    via: String,
    family: u8,
    msg_type: u16,
    request: u32,
    bytes: usize,
    fingerprint: [u8; 8],
}

impl FrameMetadata {
    pub(crate) fn emit(self) {
        if METADATA_SEEN.fetch_add(1, Ordering::Relaxed) >= 20_000 {
            return;
        }
        let at_unix_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();
        log::info!(
            target: "veil::frame_metadata",
            "at_unix_us={at_unix_us} via={} node={} dst={} family={} type={} request={} len={} frame={}",
            self.via, self.node.map_or_else(|| "-".to_owned(), |id| hex_prefix(&id, 4)),
            hex_prefix(&self.dest, 4), self.family, self.msg_type, self.request,
            self.bytes, hex_prefix(&self.fingerprint, 8),
        );
    }
}

/// Family at byte 5, message type big-endian at 6..8. `None` for anything too
/// short to carry a header. Pinned to the protocol's own encoder by
/// `the_header_offsets_match_the_protocol_encoder`, so a layout change reddens
/// a test instead of silently pointing the filter at the wrong bytes.
pub(crate) fn family_and_type(frame: &[u8]) -> Option<(u8, u16)> {
    if frame.len() < veil_proto::header::HEADER_SIZE {
        return None;
    }
    Some((frame[5], u16::from_be_bytes([frame[6], frame[7]])))
}

fn hex_prefix(bytes: &[u8], take: usize) -> String {
    use std::fmt::Write as _;
    bytes.iter().take(take).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_family_and_type_pair_selects_only_that_pair() {
        let f = parse_filter("2/2").unwrap();
        assert!(selected(&f, 2, 2));
        assert!(
            !selected(&f, 2, 3),
            "same family, other type must not match"
        );
        assert!(
            !selected(&f, 3, 2),
            "same type, other family must not match"
        );
    }

    #[test]
    fn a_bare_family_selects_every_type_in_it() {
        let f = parse_filter("2").unwrap();
        assert!(selected(&f, 2, 2));
        assert!(selected(&f, 2, 9));
        assert!(!selected(&f, 3, 2));
    }

    #[test]
    fn a_star_selects_everything() {
        let f = parse_filter("*").unwrap();
        assert!(selected(&f, 0, 0));
        assert!(selected(&f, 7, 400));
    }

    #[test]
    fn several_selectors_are_a_union() {
        let f = parse_filter("2/2,3").unwrap();
        assert!(selected(&f, 2, 2));
        assert!(!selected(&f, 2, 5));
        assert!(selected(&f, 3, 5));
    }

    /// An unusable spec must leave the hook OFF. Widening to `*` on a typo
    /// would turn a fat-fingered variable on a production seed into a
    /// firehose, which is the opposite of what the operator asked for.
    #[test]
    fn an_unparsable_spec_disables_the_hook() {
        assert!(parse_filter("").is_none());
        assert!(parse_filter("discovery/store").is_none());
        assert!(parse_filter("  ").is_none());
    }

    /// A frame shorter than a header must not index past its end.
    #[test]
    fn a_runt_frame_is_ignored() {
        assert_eq!(family_and_type(&[0u8; 3]), None);
        note_outbound(&[0u8; 32], &[0u8; 3], "test");
    }

    /// The two byte offsets this hook reads are the protocol's, not mine.
    ///
    /// They were carried over from a stderr probe that was proven live, and
    /// nothing else in this file would notice if the header ever moved them.
    /// Break-check: read byte 4 instead of 5 and this reddens.
    #[test]
    fn the_header_offsets_match_the_protocol_encoder() {
        let hdr = veil_proto::header::FrameHeader::new(2, 2);
        let bytes = veil_proto::codec::encode_header(&hdr);
        assert_eq!(family_and_type(&bytes), Some((2, 2)));

        let hdr = veil_proto::header::FrameHeader::new(7, 0x0134);
        let bytes = veil_proto::codec::encode_header(&hdr);
        assert_eq!(
            family_and_type(&bytes),
            Some((7, 0x0134)),
            "a multi-byte message type must survive the big-endian read"
        );
    }
}
