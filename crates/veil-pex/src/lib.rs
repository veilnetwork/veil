//! Peer Exchange (PEX) —.
//!
//! Random-walk based transport discovery so nodes can establish direct
//! connections instead of relying exclusively on relay chains.
//!
//! extraction: lifted from `veilcore::node::pex` into its own
//! Tier-3 crate so the discovery subsystem stays free of session/dispatcher
//! concretes. Cross-crate boundaries are crossed via three trait surfaces:
//!
//! [`veil_types::FrameBroadcaster`] — outbound frames + active-peer
//! enumeration (production adapter `SessionTxBroadcaster`).
//! [`PexLogger`] — `info` / `warn` events, implemented by veilcore's
//! `NodeLogger`.
//! [`PexDispatchOutcome`] — the strict subset of `DispatchResult` PEX
//! actually returns to its central caller; translated at the boundary
//! in `veilcore::node::dispatcher::mod`.
//!
//! `PexConfig` is mirrored in `veil_types::PexConfig`; `cfg::model`
//! re-exports for existing call sites.

pub mod dispatcher;
pub mod initiator;

use veil_proto::pex::{PexChallenge, PexResult};

pub use dispatcher::PexDispatcher;
pub use initiator::{PexConnectTx, PexState, spawn_pex_initiator};

/// Build a wire frame for a PEX message (shared by dispatcher and initiator).
pub fn encode_pex_frame(msg: veil_proto::family::PexMsg, body: &[u8]) -> Vec<u8> {
    use veil_proto::{
        HEADER_SIZE,
        codec::encode_header,
        family::FrameFamily,
        header::{FrameHeader, TrafficClass},
    };
    let mut hdr = FrameHeader::new(FrameFamily::PeerExchange as u8, msg as u16);
    hdr.body_len = body.len() as u32;
    hdr.set_priority(TrafficClass::Background as u8);
    let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
    frame.extend_from_slice(&encode_header(&hdr));
    frame.extend_from_slice(body);
    frame
}

/// Events forwarded from the PEX dispatcher to the initiator task.
#[derive(Debug)]
pub enum PexEvent {
    /// A remote node sent us a PoW challenge in response to our walk.
    Challenge {
        challenge: PexChallenge,
        from_peer: [u8; 32],
    },
    /// A remote node sent us peer addresses after we solved their challenge.
    Result {
        result: PexResult,
        from_peer: [u8; 32],
    },
}

/// Logger surface for the PEX dispatcher and initiator. Implemented by
/// `veilcore::node::observability::NodeLogger` via a tiny bridge so the
/// PEX crate stays free of observability concretes.
pub trait PexLogger: Send + Sync {
    fn info(&self, event: &str, message: &str);
    fn warn(&self, event: &str, message: &str);
}

/// Outcome of dispatching one PEX frame, returned to veilcore's central
/// `FrameDispatcher` and translated there into the broader `DispatchResult`.
///
/// The `Response` variant carries an already-encoded PEX frame (not just the
/// body) — veilcore's response-encoding path doesn't add any wrapping
/// for PEX traffic, so the encoded bytes flow straight to the peer.
#[derive(Debug)]
pub enum PexDispatchOutcome {
    /// Send these bytes back to the originating peer.
    Response(Vec<u8>),
    /// Frame was handled silently; no response.
    NoResponse,
    /// Frame was rejected as malformed/abusive; caller records a violation.
    Violation(String),
}
