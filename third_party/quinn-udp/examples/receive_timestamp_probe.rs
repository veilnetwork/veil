//! Real loopback verification on Linux/Android, without application identities.
use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use std::{
    io::IoSliceMut,
    net::UdpSocket,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx = UdpSocketState::new((&receiver).into()).unwrap();
    let tx = UdpSocketState::new((&sender).into()).unwrap();
    let destination = receiver.local_addr().unwrap();
    let send = |data: &[u8]| {
        let before = now_ns();
        tx.try_send(
            (&sender).into(),
            &Transmit {
                destination,
                ecn: Some(EcnCodepoint::Ect0),
                contents: data,
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap();
        (before, now_ns())
    };
    let read = || {
        let mut a = [0u8; 2048];
        let mut b = [0u8; 2048];
        let mut bufs = [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)];
        let mut meta = [RecvMeta::default(); 2];
        let count = rx.recv((&receiver).into(), &mut bufs, &mut meta).unwrap();
        let payloads: Vec<Vec<u8>> = bufs
            .iter()
            .zip(meta.iter())
            .take(count)
            .map(|(b, m)| b[..m.len].to_vec())
            .collect();
        (count, meta, payloads, now_ns())
    };
    send(b"default-off");
    let (count, meta, payload, _) = read();
    assert_eq!(count, 1);
    assert_eq!(payload[0], b"default-off");
    assert_eq!(meta[0].kernel_recv_unix_ns, None);
    assert_eq!(meta[0].ecn, Some(EcnCodepoint::Ect0));
    rx.set_receive_timestamp_trace((&receiver).into(), true);
    let first = send(b"first");
    thread::sleep(Duration::from_millis(30));
    let second = send(b"second");
    thread::sleep(Duration::from_millis(140));
    let (count, meta, payload, read_at) = read();
    assert_eq!(count, 2);
    assert_eq!(payload, vec![b"first".to_vec(), b"second".to_vec()]);
    let mut residence_ms = Vec::new();
    for (m, sent) in meta.iter().zip([first, second]) {
        let kernel = m
            .kernel_recv_unix_ns
            .expect("real kernel receive timestamp required");
        assert!(kernel >= sent.0.saturating_sub(1_000_000));
        assert!(
            kernel <= sent.1 + 5_000_000,
            "timestamp was fabricated at delayed application read"
        );
        assert!(read_at >= kernel + 100_000_000);
        assert_eq!(m.ecn, Some(EcnCodepoint::Ect0));
        assert!(m.dst_ip.is_some());
        residence_ms.push((read_at - kernel) / 1_000_000);
    }
    rx.set_receive_timestamp_trace((&receiver).into(), false);
    send(b"disabled-again");
    let (count, meta, payload, _) = read();
    assert_eq!(count, 1);
    assert_eq!(payload[0], b"disabled-again");
    assert_eq!(meta[0].kernel_recv_unix_ns, None);
    println!("{{\"default_off\":true,\"enabled_kernel_timestamps\":2,\"kernel_to_read_ms\":{:?},\"payload_ecn_destination_preserved\":true,\"disabled_again\":true}}", residence_ms);
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    println!("unsupported platform: no kernel timestamp test");
}
