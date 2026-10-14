use super::*;
use crate::client::{DispatchTable, IpcWriterFrame, SharedWriter, run_writer_task};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use veil_proto::ipc::AppIpcSendPayload;
use veil_proto::{codec::decode_header, header::HEADER_SIZE};

fn sender(writer: SharedWriter) -> AppSender {
    AppSender {
        app_id: [7; 32],
        endpoint_id: 9,
        writer,
        dispatch: Arc::new(Mutex::new(DispatchTable::new())),
        unbind_on_drop: false,
    }
}

#[tokio::test(start_paused = true)]
async fn whole_source_work_has_one_ipc_deadline_and_legacy_fallback() {
    use veil_proto::ipc_lossy_batch::LocalLossyBatchPayload;
    let cell = [
        veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.as_slice(),
        &[7; 100],
    ]
    .concat();
    for upgraded in [false, true] {
        let (tx, mut rx) = mpsc::channel::<IpcWriterFrame>(4);
        let writer = SharedWriter::new(tx).with_local_lossy_work(upgraded);
        let sender = sender(writer.clone());
        assert!(
            sender
                .send_relay_media_batch_before_owned(
                    2,
                    [8; 32],
                    [9; 32],
                    10,
                    vec![cell.clone(); 3],
                    tokio::time::Instant::now() + Duration::from_millis(200),
                    None
                )
                .await
                .unwrap()
        );
        assert_eq!(rx.len(), if upgraded { 1 } else { 3 });
        let bytes = rx.recv().await.unwrap();
        let header = decode_header(&bytes).unwrap();
        assert_eq!(veil_proto::ipc::ipc_local_source_lane(&header), 2);
        if upgraded {
            assert_eq!(header.msg_type, LocalAppMsg::AppIpcLossyBatch as u16);
            let batch = LocalLossyBatchPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
            assert_eq!(batch.cells, vec![cell.clone(); 3]);
            assert_eq!(batch.source_app, [7; 32]);
            writer
                .write_frame(LocalAppMsg::StreamClose as u16, &[])
                .await
                .unwrap();
            writer
                .write_frame(LocalAppMsg::StreamClose as u16, &[])
                .await
                .unwrap();
            writer
                .write_frame(LocalAppMsg::StreamClose as u16, &[])
                .await
                .unwrap();
            writer
                .write_frame(LocalAppMsg::StreamClose as u16, &[])
                .await
                .unwrap();
            assert!(
                !sender
                    .send_relay_media_batch_before_owned(
                        2,
                        [8; 32],
                        [9; 32],
                        10,
                        vec![cell.clone(); 3],
                        tokio::time::Instant::now() + Duration::from_millis(200),
                        None
                    )
                    .await
                    .unwrap()
            );
            assert_eq!(rx.len(), 4, "expired whole work cannot publish a prefix");
        } else {
            assert_eq!(header.msg_type, LocalAppMsg::AppIpcSend as u16);
            assert_eq!(
                &*AppIpcSendPayload::decode(&bytes[HEADER_SIZE..])
                    .unwrap()
                    .data,
                &cell
            );
        }
    }
}

async fn direct(sender: &AppSender, seq: u32, deadline: tokio::time::Instant) -> bool {
    sender
        .send_rt_data_on_local_lane_before(
            0,
            [8; 32],
            [9; 32],
            10,
            seq,
            42,
            0,
            0,
            &[seq as u8; 64],
            deadline,
        )
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn full_ipc_admission_expires_media_without_consuming_reliable_capacity() {
    let (tx, mut rx) = mpsc::channel::<IpcWriterFrame>(1);
    let writer = SharedWriter::new(tx);
    let sender = sender(writer.clone());
    writer
        .write_frame(LocalAppMsg::StreamClose as u16, &7u32.to_be_bytes())
        .await
        .unwrap();
    let at = tokio::time::Instant::now() + Duration::from_millis(200);
    assert!(!direct(&sender, 1, at).await);
    let expirations = Arc::new(std::sync::atomic::AtomicU64::new(0));
    assert!(
        !sender
            .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                0,
                [8; 32],
                [9; 32],
                10,
                b"admission expired".to_vec(),
                tokio::time::Instant::now() + Duration::from_millis(200),
                Some(Arc::clone(&expirations)),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        expirations.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "admission failure is reported to the caller, not counted twice"
    );
    assert_eq!(rx.len(), 1, "media cannot displace reliable admission");
    let frame = rx.recv().await.unwrap();
    assert_eq!(
        decode_header(&frame).unwrap().msg_type,
        LocalAppMsg::StreamClose as u16
    );
    assert_eq!(&frame[HEADER_SIZE..], &7u32.to_be_bytes());
    assert!(
        direct(
            &sender,
            2,
            tokio::time::Instant::now() + Duration::from_millis(200)
        )
        .await
    );
    let fresh = rx.recv().await.unwrap();
    assert_eq!(
        AppIpcRtSendPayload::decode(&fresh[HEADER_SIZE..])
            .unwrap()
            .seq,
        2
    );
    drop(rx);
    assert!(matches!(
        sender
            .send_rt_data_on_local_lane_before(
                0,
                [8; 32],
                [9; 32],
                10,
                3,
                42,
                0,
                0,
                b"fresh",
                tokio::time::Instant::now() + Duration::from_millis(200),
            )
            .await,
        Err(ClientError::ConnectionClosed)
    ));
}

/// Real writer task and SDK encoders over a byte stream with a 13-byte buffer:
/// expiry occurs after a partial header is committed. It must finish that
/// frame, drop later expired frames even within its drained batch, and preserve
/// reliable data, fresh direct/relay media, FIFO and clean EOF.
#[tokio::test(start_paused = true)]
async fn ipc_recovery_finishes_partial_frames_and_sheds_only_unstarted_expired_media() {
    let expirations = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<IpcWriterFrame>(16);
    let writer = SharedWriter::new(tx);
    let sender = sender(writer.clone());
    let at = tokio::time::Instant::now() + Duration::from_millis(200);
    assert!(direct(&sender, 1, at).await);
    assert!(direct(&sender, 2, at).await);
    assert!(
        sender
            .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                2,
                [8; 32],
                [9; 32],
                10,
                b"stale sealed cell".to_vec(),
                at,
                Some(Arc::clone(&expirations)),
            )
            .await
            .unwrap()
    );
    writer
        .write_app_ipc_send_owned(&[8; 32], &[7; 32], &[9; 32], 10, 0, b"kept reliable")
        .await
        .unwrap();
    let (stream, mut receiver) = tokio::io::duplex(13);
    let task = tokio::spawn(run_writer_task(stream, rx));
    let mut prefix = [0; 13];
    receiver.read_exact(&mut prefix).await.unwrap();
    tokio::time::advance(Duration::from_millis(210)).await;
    assert!(!task.is_finished(), "expiry truncated a started IPC frame");
    let fresh_at = tokio::time::Instant::now() + Duration::from_millis(200);
    assert!(direct(&sender, 3, fresh_at).await);
    assert!(
        sender
            .send_relay_media_sealed_on_local_lane_before_tracked_owned(
                2,
                [8; 32],
                [9; 32],
                10,
                b"fresh sealed cell".to_vec(),
                fresh_at,
                Some(Arc::clone(&expirations)),
            )
            .await
            .unwrap()
    );
    drop(sender);
    drop(writer);
    let mut bytes = prefix.to_vec();
    receiver.read_to_end(&mut bytes).await.unwrap();
    task.await.unwrap();
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let header = decode_header(&bytes).unwrap();
        let end = HEADER_SIZE + header.body_len as usize;
        assert!(
            end <= bytes.len(),
            "partial IPC body remained after recovery"
        );
        frames.push((header, bytes[HEADER_SIZE..end].to_vec()));
        bytes.drain(..end);
    }
    assert_eq!(frames.len(), 4, "stale SDK media was replayed");
    assert_eq!(
        expirations.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "only the tracked, admitted-but-expired relay cell is counted"
    );
    for (index, seq) in [(0, 1), (2, 3)] {
        assert_eq!(frames[index].0.msg_type, LocalAppMsg::AppRtSend as u16);
        let data = AppIpcRtSendPayload::decode(&frames[index].1).unwrap();
        assert_eq!(data.seq, seq);
        assert_eq!(data.data, [seq as u8; 64]);
    }
    for (index, expected, flags) in [
        (1, b"kept reliable".as_slice(), 0),
        (
            3,
            b"fresh sealed cell".as_slice(),
            veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED,
        ),
    ] {
        assert_eq!(frames[index].0.msg_type, LocalAppMsg::AppIpcSend as u16);
        let data = veil_proto::ipc::AppIpcSendPayload::decode(&frames[index].1).unwrap();
        assert_eq!(
            u32::from_be_bytes(frames[index].1[100..104].try_into().unwrap()),
            flags
        );
        assert_eq!(data.data.as_ref(), expected);
    }
    assert_eq!(frames[3].0.priority(), 2);
    assert_eq!(
        frames[3].0.flags,
        veil_proto::ipc::IPC_HEADER_EXPLICIT_LOCAL_LANE | 2
    );
}

#[tokio::test(start_paused = true)]
async fn short_control_flags_and_deadlines_stay_in_local_ipc() {
    let (tx, mut rx) = mpsc::channel::<IpcWriterFrame>(2);
    let source = sender(SharedWriter::new(tx));
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    let body = [
        veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.as_slice(),
        &[7; 32],
    ]
    .concat();
    source
        .send_short_control_datagram_before([8; 32], [9; 32], 13, 7, &body, deadline)
        .await
        .unwrap();
    let frame = rx.recv().await.unwrap();
    let header = decode_header(&frame).unwrap();
    assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
    assert_ne!(header.flags & veil_proto::ipc::IPC_HEADER_SHORT_DATAGRAM, 0);
    let payload = veil_proto::AppIpcRtSendPayload::decode(&frame[HEADER_SIZE..]).unwrap();
    assert_eq!(payload.data, body);
    source
        .send_short_control_sealed_before_owned([8; 32], [9; 32], 13, body.clone(), deadline)
        .await
        .unwrap();
    let frame = rx.recv().await.unwrap();
    let flags = u32::from_be_bytes(
        frame[HEADER_SIZE + 100..HEADER_SIZE + 104]
            .try_into()
            .unwrap(),
    );
    assert_ne!(
        flags & veil_proto::ipc::IPC_SEND_FLAG_LOCAL_SHORT_CONTROL,
        0
    );
    assert_eq!(
        flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT,
        0
    );
    tokio::time::advance(Duration::from_millis(201)).await;
    assert!(
        !source
            .send_short_control_datagram_before([8; 32], [9; 32], 13, 7, &body, deadline)
            .await
            .unwrap()
    );
    assert!(rx.try_recv().is_err());
}
