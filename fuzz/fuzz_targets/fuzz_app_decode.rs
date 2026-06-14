//! Fuzz target for application-plane payload decode functions.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::app::{
    AppClosePayload, AppDataPayload, AppOpenPayload, AppReceiptPayload,
    AppRtDataPayload, AppSendPayload, AppWindowUpdatePayload,
};

fuzz_target!(|data: &[u8]| {
    let _ = AppOpenPayload::decode(data);
    let _ = AppDataPayload::decode(data);
    let _ = AppClosePayload::decode(data);
    let _ = AppSendPayload::decode(data);
    let _ = AppReceiptPayload::decode(data);
    let _ = AppWindowUpdatePayload::decode(data);
    let _ = AppRtDataPayload::decode(data);
});
