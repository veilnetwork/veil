use super::*;
use tokio::io::AsyncReadExt;
use veil_crypto::session_cipher::SessionCipher;
use veil_proto::session::{DetachPayload, detach_reason};

async fn write_encrypted(
    client: &mut DuplexStream,
    cipher: &mut SessionCipher,
    family: u8,
    message: u16,
    body: &[u8],
) {
    let aad = aad_for_plaintext(family, message, body.len());
    let encrypted = cipher.seal(body, &aad).unwrap();
    write_frame(client, family, message, &encrypted).await;
}

// The peer intentionally retains its socket: EOF, keepalive and an OS timeout
// must not be needed after an authenticated "node is going down" notice.
#[tokio::test(start_paused = true)]
async fn shutdown_detach_retires_a_runner_without_waiting_for_eof() {
    let (mut client, server) = tokio::io::duplex(65_536);
    let (mut runner, _swap) = make_swap_runner(server);
    let key = [0x45; 32];
    runner.crypto.rx_cipher = Some(SessionCipher::new(&key, true));
    runner.crypto.tx_cipher = Some(SessionCipher::new(&key, true));
    let mut peer_tx = SessionCipher::new(&key, true);
    let mut task = tokio::spawn(async move { runner.run().await });
    write_encrypted(
        &mut client,
        &mut peer_tx,
        FrameFamily::Session as u8,
        SessionMsg::Detach as u16,
        &DetachPayload {
            reason: detach_reason::SHUTDOWN,
        }
        .encode(),
    )
    .await;
    // Virtual time bounds a missing state transition; this is not a latency
    // target. Both liveness timers in make_swap_runner are disabled.
    let ended = tokio::time::timeout(std::time::Duration::from_secs(1), &mut task).await;
    if ended.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(
        ended.is_ok(),
        "SHUTDOWN left the old session eligible for sends"
    );
    let mut byte = [0];
    assert_eq!(client.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn ordinary_detach_and_migration_keep_the_session_usable() {
    for reason in [
        detach_reason::NORMAL,
        detach_reason::MIGRATING,
        detach_reason::ERROR,
        255,
    ] {
        let (mut client, server) = tokio::io::duplex(65_536);
        let (mut runner, _swap) = make_swap_runner(server);
        let key = [0x46; 32];
        runner.crypto.rx_cipher = Some(SessionCipher::new(&key, true));
        runner.crypto.tx_cipher = Some(SessionCipher::new(&key, true));
        let mut peer_tx = SessionCipher::new(&key, true);
        let mut peer_rx = SessionCipher::new(&key, true);
        let task = tokio::spawn(async move { runner.run().await });
        write_encrypted(
            &mut client,
            &mut peer_tx,
            FrameFamily::Session as u8,
            SessionMsg::Detach as u16,
            &DetachPayload { reason }.encode(),
        )
        .await;
        write_encrypted(
            &mut client,
            &mut peer_tx,
            FrameFamily::Control as u8,
            ControlMsg::Ping as u16,
            &[],
        )
        .await;
        let header = read_pong_header(&mut client).await;
        assert_eq!(header.family, FrameFamily::Control as u8);
        assert_eq!(header.msg_type, ControlMsg::Pong as u16);
        let mut encrypted = vec![0; header.body_len as usize];
        client.read_exact(&mut encrypted).await.unwrap();
        let aad = veil_proto::codec::frame_aad(&header);
        assert!(peer_rx.open(&encrypted, &aad).unwrap().is_empty());
        drop(client);
        task.await.unwrap();
    }
}
