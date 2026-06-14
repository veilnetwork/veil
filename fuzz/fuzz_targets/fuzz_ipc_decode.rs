//! Fuzz target for IPC-plane payload decode functions.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::ipc::{
    AppBindErrPayload, AppBindOkPayload, AppBindPayload, AppDeliverPayload,
    AppIpcHelloErrPayload, AppIpcHelloOkPayload, AppIpcHelloPayload,
    AppIpcSendPayload, AppUnbindPayload, StreamClosePayload, StreamDataPayload,
    StreamOpenErrPayload, StreamOpenOkPayload, StreamOpenPayload,
    StreamWindowPayload,
};

fuzz_target!(|data: &[u8]| {
    let _ = AppIpcHelloPayload::decode(data);
    let _ = AppIpcHelloOkPayload::decode(data);
    let _ = AppIpcHelloErrPayload::decode(data);
    let _ = AppBindPayload::decode(data);
    let _ = AppBindOkPayload::decode(data);
    let _ = AppBindErrPayload::decode(data);
    let _ = AppUnbindPayload::decode(data);
    let _ = AppDeliverPayload::decode(data);
    let _ = AppIpcSendPayload::decode(data);
    let _ = StreamOpenPayload::decode(data);
    let _ = StreamOpenOkPayload::decode(data);
    let _ = StreamOpenErrPayload::decode(data);
    let _ = StreamDataPayload::decode(data);
    let _ = StreamClosePayload::decode(data);
    let _ = StreamWindowPayload::decode(data);
});
