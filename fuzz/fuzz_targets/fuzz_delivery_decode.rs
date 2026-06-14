//! Fuzz target for delivery-plane + mailbox/outbox IPC payload decoders.
//!
//! (audit cycle-10) The previous version imported Mailbox* types from
//! `proto::delivery`, where they no longer live (they moved to `proto::ipc`),
//! plus a `MailboxFetchResponse` that no longer exists — so this target failed
//! to compile and the delivery-plane fuzz surface was dark. Re-point the
//! imports and cover the outbox decoders too.
#![no_main]
use libfuzzer_sys::fuzz_target;

use veilcore::proto::delivery::{DeliveryEnvelope, DeliveryStatusPayload, ForwardPayload};
use veilcore::proto::ipc::{
    MailboxAckPayload, MailboxFetchPayload, MailboxPutPayload, OutboxAckPayload,
    OutboxFindMissingPayload, OutboxPutPayload,
};

fuzz_target!(|data: &[u8]| {
    let _ = DeliveryEnvelope::decode(data);
    let _ = DeliveryStatusPayload::decode(data);
    let _ = ForwardPayload::decode(data);
    let _ = MailboxPutPayload::decode(data);
    let _ = MailboxFetchPayload::decode(data);
    let _ = MailboxAckPayload::decode(data);
    let _ = OutboxPutPayload::decode(data);
    let _ = OutboxFindMissingPayload::decode(data);
    let _ = OutboxAckPayload::decode(data);
});
