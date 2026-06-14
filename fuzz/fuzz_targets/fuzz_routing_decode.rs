//! Fuzz target for routing-plane payload decode functions.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::routing::{
    PowAcceptPayload, PowChallengePayload, PowResponsePayload,
    RouteAnnouncePayload, RouteAnnounceAliasedPayload,
    RouteRequestPayload, RouteResponsePayload,
    RouteWithdrawPayload, RouteWithdrawAliasedPayload,
};

fuzz_target!(|data: &[u8]| {
    let _ = RouteAnnouncePayload::decode(data);
    let _ = RouteAnnounceAliasedPayload::decode(data);
    let _ = RouteWithdrawPayload::decode(data);
    let _ = RouteWithdrawAliasedPayload::decode(data);
    let _ = RouteRequestPayload::decode(data);
    let _ = RouteResponsePayload::decode(data);
    let _ = PowChallengePayload::decode(data);
    let _ = PowResponsePayload::decode(data);
    let _ = PowAcceptPayload::decode(data);
});
