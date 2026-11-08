//! Actual ordinary/carrier queue outcomes, not inferred from missing selection.
use super::*;

struct NoDirectSend;
impl veil_anonymity::circuit_carrier::DatagramCarrier for NoDirectSend {
    fn try_send(
        &self,
        _: &[u8; 32],
        _: &[u8],
        _: &mut dyn FnMut(usize) -> bool,
    ) -> veil_anonymity::circuit_carrier::CarrierSend {
        panic!("queue admission must never transmit directly")
    }
}

#[test]
fn queue_outcomes_follow_actual_admission_behind_operator_gate() {
    const CHILD: &str = "VEIL_TEST_OPAQUE_QUEUE_ADMISSION";
    if let Ok(expected) = std::env::var(CHILD) {
        static EVENTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        struct Sink;
        impl log::Log for Sink {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &log::Record<'_>) {
                if record.target().ends_with("opaque_forward_trace") {
                    EVENTS.lock().unwrap().push(record.args().to_string());
                }
            }
            fn flush(&self) {}
        }
        static SINK: Sink = Sink;
        log::set_logger(&SINK).unwrap();
        log::set_max_level(log::LevelFilter::Info);
        let payload = b"PRIVATE_OPAQUE_QUEUE_CANARY";
        let peer = [2; 32];
        let body = veil_proto::delivery::ForwardPayload {
            next_hop_node_id: peer,
            relay_hops: 1,
            delivery_attempt: None,
            traffic_class: None,
            envelope: veil_proto::delivery::DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any(peer),
                sender_node_id: [3; 32],
                src_app_id: [4; 32],
                app_id: [5; 32],
                endpoint_id: 6,
                content_id: [7; 32],
                created_at: 8,
                ttl_secs: 30,
                payload: payload.to_vec(),
                trace_id: 9,
                require_ack: false,
            },
        }
        .encode();
        let mut header = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );
        header.body_len = body.len() as u32;
        let mut frame = veil_proto::codec::encode_header(&header).to_vec();
        frame.extend_from_slice(&body);
        let mut registry = SessionTxRegistry::with_capacity(1);
        let carrier: Arc<dyn veil_anonymity::circuit_carrier::DatagramCarrier> =
            Arc::new(NoDirectSend);
        assert_eq!(
            registry.send_to_result(&peer, INTERACTIVE, frame.clone()),
            Err(SendToError::Missing)
        );
        let mut receiver = registry.register(peer);
        assert_eq!(
            registry.send_to_result(&peer, INTERACTIVE, frame.clone()),
            Ok(())
        );
        assert_eq!(
            registry.send_to_on_carrier_result(&peer, frame.clone(), Arc::downgrade(&carrier)),
            Err(SendToError::Full)
        );
        let received = receiver.try_recv().unwrap();
        assert_eq!(received.0, INTERACTIVE);
        assert_eq!(&received.1[..], &frame);
        assert_eq!(
            registry.send_to_on_carrier_result(&peer, frame.clone(), Arc::downgrade(&carrier)),
            Ok(())
        );
        assert_eq!(&receiver.try_recv().unwrap().1[..], &frame);
        drop(receiver);
        assert_eq!(
            registry.send_to_result(&peer, INTERACTIVE, frame.clone()),
            Err(SendToError::Closed)
        );
        // Ordinary malformed bytes may still enter an ordinary queue, but do
        // not gain an opaque-payload observation from the diagnostic parser.
        let mut malformed = frame.clone();
        malformed.pop();
        assert_eq!(
            registry.send_to_result(&peer, INTERACTIVE, malformed),
            Err(SendToError::Closed)
        );
        let events = EVENTS.lock().unwrap().clone();
        if expected == "1" {
            assert_eq!(events.len(), 5, "real queue outcomes were not observed");
            use sha2::Digest;
            let digest = veil_util::hex_str(&sha2::Sha256::digest(payload));
            for (event, outcome) in events
                .iter()
                .zip(["missing", "accepted", "full", "accepted", "closed"])
            {
                assert!(event.contains("stage=queue_admission "));
                assert!(event.contains(&format!("outcome={outcome} ")));
                assert!(event.contains(&format!("opaque_sha256={digest} ")));
                assert!(event.contains("node=- "));
                assert!(event.contains("peer=02020202 "));
                assert!(!event.contains("PRIVATE_"));
            }
        } else {
            assert!(events.is_empty(), "disabled/invalid gate emitted metadata");
        }
        return;
    }
    for (setting, expected) in [
        (None, "0"),
        (Some("0"), "0"),
        (Some("1"), "1"),
        (Some("true"), "0"),
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "tx_registry::admission_trace_tests::queue_outcomes_follow_actual_admission_behind_operator_gate", "--nocapture"])
            .env(CHILD, expected).env_remove("VEIL_DIAG_OPAQUE_FORWARD");
        if let Some(setting) = setting {
            command.env("VEIL_DIAG_OPAQUE_FORWARD", setting);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test")
                && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
