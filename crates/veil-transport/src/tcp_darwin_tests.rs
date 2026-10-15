use super::*;
use std::{io, os::fd::AsRawFd, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Public Darwin TCP option, verified against the platform SDK's netinet/tcp.h.
const NOTSENT_LOWAT: libc::c_int = 0x201;

fn integer_option(stream: &impl AsRawFd, level: i32, option: i32) -> i32 {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: the descriptor is borrowed and both output buffers are live.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            level,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    assert_eq!(size as usize, std::mem::size_of_val(&value));
    value
}

#[tokio::test]
async fn darwin_configures_unsent_threshold_for_both_directions() {
    let listener = bind_tcp_with_reuseaddr("127.0.0.1", 0).await.unwrap();
    let ctx = TransportContext::for_debug().unwrap();
    let (client, peer) = tokio::join!(
        connect_tcp_stream("127.0.0.1", listener.local_addr().unwrap().port(), &ctx),
        listener.accept(),
    );
    let client = client.unwrap();
    let peer = peer.unwrap().0;
    configure_accepted_tcp(&peer, true, None).unwrap();
    assert_eq!(
        integer_option(&client, libc::IPPROTO_TCP, NOTSENT_LOWAT),
        4096
    );
    assert_eq!(
        integer_option(&peer, libc::IPPROTO_TCP, NOTSENT_LOWAT),
        4096
    );
}

#[tokio::test]
async fn darwin_stalled_reader_bounds_buffered_writes_and_reliable_data_resumes() {
    let listener = bind_tcp_with_reuseaddr("127.0.0.1", 0).await.unwrap();
    SockRef::from(&listener).set_recv_buffer_size(4096).unwrap();
    let ctx = TransportContext::for_debug().unwrap();
    let (client, peer) = tokio::join!(
        connect_tcp_stream("127.0.0.1", listener.local_addr().unwrap().port(), &ctx),
        listener.accept(),
    );
    let mut client = crate::tcp_write_gate::gate(client.unwrap(), |tcp| tcp);
    let mut peer = peer.unwrap().0;
    configure_accepted_tcp(&peer, true, None).unwrap();
    SockRef::from(&peer).set_recv_buffer_size(4096).unwrap();
    let mut written = 0;
    let payload = [0x5a; 1200];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(10), client.write(&payload)).await {
            Ok(Ok(0)) => panic!("write made no progress"),
            Ok(Ok(count)) => written += count,
            Ok(Err(error)) => panic!("write failed: {error}"),
            Err(_) => {}
        }
    }
    // Let local ACKs settle while application reads remain stopped. SO_NWRITE
    // includes in-flight bytes; do not call this an exact unsent counter or a
    // general bound for remote links. This is a closed-window loopback control.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let queued = integer_option(&client, libc::SOL_SOCKET, libc::SO_NWRITE);
    eprintln!("Darwin blocked reader: written={written} settled_socket_bytes={queued}");
    drop(client);
    let mut received = Vec::new();
    timeout(Duration::from_secs(5), peer.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert!(
        written > 0 && queued > 0,
        "must exercise kernel backpressure"
    );
    assert_eq!(received.len(), written);
    assert!(received.iter().all(|byte| *byte == 0x5a));
    assert!(
        queued <= 8192,
        "settled socket backlog reached {queued} bytes"
    );
}

#[tokio::test]
async fn darwin_partial_and_vectored_writes_preserve_large_payloads() {
    let listener = bind_tcp_with_reuseaddr("127.0.0.1", 0).await.unwrap();
    let ctx = TransportContext::for_debug().unwrap();
    let (client, peer) = tokio::join!(
        connect_tcp_stream("127.0.0.1", listener.local_addr().unwrap().port(), &ctx),
        listener.accept(),
    );
    let mut client = crate::tcp_write_gate::gate(client.unwrap(), |tcp| tcp);
    let mut peer = peer.unwrap().0;
    let reading = tokio::spawn(async move {
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let payload: Vec<u8> = (0..128 * 1024).map(|n| (n % 251) as u8).collect();
    let first = client.write(&payload).await.unwrap();
    assert!(first > 0 && first <= 4096, "must exercise a partial write");
    client.write_all(&payload[first..]).await.unwrap();
    let vectors = [
        std::io::IoSlice::new(&[]),
        std::io::IoSlice::new(&payload[..32000]),
        std::io::IoSlice::new(&payload[32000..]),
    ];
    let first = client.write_vectored(&vectors).await.unwrap();
    assert!(first > 0 && first <= 4096);
    client.write_all(&payload[first..]).await.unwrap();
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();
    drop(client);
    let bytes = timeout(Duration::from_secs(5), reading)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, [payload.as_slice(), payload.as_slice()].concat());
}
