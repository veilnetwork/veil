use super::write_with_progress_timeout;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn partial_progress_preserves_blob_beyond_one_idle_timeout() {
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let started = tokio::time::Instant::now();
    let send = tokio::spawn(async move {
        write_with_progress_timeout(&mut writer, b"abcdef", Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap();
        // Retain the transport until the final byte is received.
        writer
    });
    let mut received = Vec::new();
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut byte = [0];
        reader.read_exact(&mut byte).await.unwrap();
        received.extend_from_slice(&byte);
    }
    let _writer = send.await.unwrap();
    assert_eq!(received, b"abcdef");
    assert!(started.elapsed() > Duration::from_secs(2));
}

#[tokio::test]
async fn blocked_partial_write_still_expires_without_progress() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    assert!(
        write_with_progress_timeout(&mut writer, b"ab", Duration::from_millis(50))
            .await
            .is_err()
    );
}
