//! Audio feedback on an independent endpoint writer and generic control flow.
//! Sealed cells retain their existing primary cipher and remote media inbox.
use super::*;

/// Install a sender-only binding of the same media app on a separate IPC
/// connection. RTP never waits for this queue or sender lock. No peer feature
/// negotiation is needed: the ciphertext and RTCP body format are unchanged.
/// Anonymous channels retain their existing circuit path; close/reopen to
/// replace a sender. The caller owns the binding until channel close.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_set_feedback_sender(
    chan: u64,
    app: *mut VeilApp,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_channel_set_feedback_sender") }.is_err() {
        return -1;
    }
    null_check_with_default!(err_out, -1, "app" => app);
    get_or_return!(app_ref, app_table(), app, err_out, -1, "VeilApp");
    let mut channels = MEDIA_CHANNELS.write().unwrap_or_else(|p| p.into_inner());
    let Some(channel) = channels.get_mut(&chan) else {
        unsafe { write_err(err_out, "unknown media channel") };
        return -1;
    };
    if channel.sender_app_id != Some(app_ref.app_id) || channel.routes.is_some() {
        unsafe {
            write_err(
                err_out,
                "feedback sender requires the same direct/relay app identity",
            )
        };
        return -1;
    }
    if channel.feedback_task.is_some() {
        unsafe { write_err(err_out, "feedback sender already configured") };
        return -1;
    }
    let Some((peer_app, peer_endpoint)) = channel.control_destination else {
        return -1;
    };
    let (tx, rx) = mpsc::channel(16);
    let sender = Arc::clone(&app_ref.sender);
    let cipher = Arc::clone(&channel.cipher);
    let peer = channel.peer;
    let relay = channel.relay_stats.is_some();
    let seq = channel.direct_seq.clone();
    let batching = channel
        .batching
        .as_ref()
        .expect("direct/relay batching")
        .clone();
    let task = app_ref.bundle.runtime.spawn(drain_media_packets_on_plane(
        rx,
        batching,
        cipher,
        relay,
        Some(media::LocalMediaPlane::Primary),
        move |cell| {
            let sender = Arc::clone(&sender);
            let seq = seq.clone();
            async move {
                let Some(guard) = cell.sealed.lock_while_fresh(&sender).await else {
                    return true;
                };
                let Some(sender) = guard.as_ref() else {
                    return false;
                };
                let deadline = cell
                    .sealed
                    .local_deadline()
                    .expect("feedback packet deadline");
                media::trace_sealed_cell("feedback_send", &peer, cell.sealed.as_bytes());
                if relay {
                    let _ = sender
                        .send_short_control_sealed_before_owned(
                            peer,
                            peer_app,
                            peer_endpoint,
                            cell.sealed.into_vec(),
                            deadline,
                        )
                        .await;
                } else {
                    let _ = sender
                        .send_short_control_datagram_before(
                            peer,
                            peer_app,
                            peer_endpoint,
                            seq.as_ref()
                                .expect("direct sequence")
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                            cell.sealed.as_bytes(),
                            deadline,
                        )
                        .await;
                }
                true
            }
        },
    ));
    *channel
        .ingress
        .feedback_tx
        .write()
        .unwrap_or_else(|p| p.into_inner()) = Some(tx);
    channel.feedback_task = Some(task);
    0
}
