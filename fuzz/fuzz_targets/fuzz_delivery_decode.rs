//! Fuzz target for delivery-plane payload decode functions.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::delivery::{
    DeliveryEnvelope, DeliveryStatusPayload, ForwardPayload,
    MailboxAckPayload, MailboxFetchPayload, MailboxFetchResponse, MailboxPutPayload,
};

fuzz_target!(|data: &[u8]| {
    let _ = DeliveryEnvelope::decode(data);
    let _ = DeliveryStatusPayload::decode(data);
    let _ = ForwardPayload::decode(data);
    let _ = MailboxAckPayload::decode(data);
    let _ = MailboxFetchPayload::decode(data);
    let _ = MailboxFetchResponse::decode(data);
    let _ = MailboxPutPayload::decode(data);
});
