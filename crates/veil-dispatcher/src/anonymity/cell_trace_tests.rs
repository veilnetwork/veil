//! A process-isolated investigation fixture: no process-global env mutation,
//! network, sleeps, app data or public relays. Real dispatcher and TX queues.
use super::*;
use rand_core::OsRng;
use std::path::Path;

#[test]
fn scoped_cell_trace_joins_splice_return_and_missing_then_reconnect() {
    if std::env::var_os("VEIL_CIRCUIT_TRACE_FIXTURE").is_some() {
        exercise(Path::new(
            &std::env::var_os("VEIL_CIRCUIT_TRACE_FIXTURE").unwrap(),
        ));
        return;
    }
    use rand_core::RngCore;
    let dir = std::env::temp_dir().join(format!("veil-cell-trace-{:016x}", OsRng.next_u64()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir).unwrap();
    let mut hash = blake3::Hasher::new_keyed(&[7; 32]);
    hash.update(b"veil-circuit-prefix-v1");
    hash.update(&[42; 32]);
    let policy = format!(
        "key {}\nlocal\nprefix {}\npeer {}\n",
        "07".repeat(32),
        veil_util::hex_str(&hash.finalize().as_bytes()[..16]),
        "05".repeat(32),
    );
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(dir.join("policy"))
        .unwrap()
        .write_all(policy.as_bytes())
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "anonymity::cell_trace_tests::scoped_cell_trace_joins_splice_return_and_missing_then_reconnect", "--nocapture"])
        .env("VEIL_CIRCUIT_TRACE_FILE", dir.join("policy"))
        .env("VEIL_CIRCUIT_TRACE_FIXTURE", &dir)
        .output().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        status.status.success(),
        "isolated fixture failed: {}\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}

fn exercise(dir: &Path) {
    use veil_anonymity::{
        circuit_data::{CircuitCellBytes, Direction, apply_layers, read_payload},
        circuit_setup::CircuitInstall,
        circuit_table::CircuitTable,
        circuit_wire::CircuitDataPayload,
    };
    use veil_observability::NodeLogger;
    use veil_session::tx_registry::SessionTxRegistry;
    use veil_types::{LogFormat, LogLevel, LogsConfig};
    let phone = [5; 32];
    let middle = [8; 32];
    let rendezvous = [9; 32];
    let size = CircuitCellBytes::legacy();
    let install = |cid_in, cid_out, key| CircuitInstall {
        circuit_id_in: cid_in,
        circuit_id_out: cid_out,
        circuit_key: key,
        cell_bytes: size,
    };
    let mut r = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
    r.logger = NodeLogger::from_parts(
        LogsConfig::File,
        Some(&dir.join("r.log")),
        LogLevel::Info,
        LogFormat::Text,
    )
    .unwrap()
    .into();
    let rt = CircuitTable::new();
    let r_state = rt
        .install(&install(33, 0, [2; 32]), middle, None, circuit_now_unix())
        .unwrap();
    let mut r_tx = SessionTxRegistry::new();
    let mut to_middle = r_tx.register(NodeId::from(middle));
    r.session_tx_registry = Some(Arc::new(std::sync::RwLock::new(r_tx)));

    let mut m = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
    m.logger = NodeLogger::from_parts(
        LogsConfig::File,
        Some(&dir.join("m.log")),
        LogLevel::Info,
        LogFormat::Text,
    )
    .unwrap()
    .into();
    let mt = Arc::new(CircuitTable::new());
    mt.install(
        &install(11, 33, [1; 32]),
        phone,
        Some(rendezvous),
        circuit_now_unix(),
    )
    .unwrap();
    m.circuit_table = Some(mt);
    let tx = Arc::new(std::sync::RwLock::new(SessionTxRegistry::new()));
    m.session_tx_registry = Some(Arc::clone(&tx));

    // Arbitrary opaque bytes, not a relay-side stream/media interpretation.
    let mut opaque = vec![42; 32];
    opaque.extend_from_slice(b"selected synthetic range: never print these bytes");
    let source = veil_anonymity::circuit_trace::local(&opaque).unwrap();
    assert!(veil_anonymity::circuit_trace::selected(&[43; 120]).is_none());
    assert!(veil_anonymity::circuit_trace::peer(&[6; 32]).is_none());

    for (index, transport) in [RelayChainMsg::CircuitData, RelayChainMsg::CircuitDatagram]
        .into_iter()
        .enumerate()
    {
        // A last-hop Missing does not change the source's opaque bytes. ARQ
        // retransmission must allocate a NEW outer sequence at the splice.
        assert!(r.splice_stream_cell(&r_state, &opaque, transport));
        let (_, frame) = to_middle.try_recv().unwrap();
        let body = &frame[veil_proto::HEADER_SIZE..];
        let first = CircuitDataPayload::decode(body).unwrap();
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, transport as u16);
        hdr.body_len = body.len() as u32;
        m.dispatch_relay_chain(&hdr, body, NodeId::from(rendezvous));
        let mut to_phone = tx.write().unwrap().register(NodeId::from(phone));
        // Same outer cell is a replay, even after the peer reconnects.
        m.dispatch_relay_chain(&hdr, body, NodeId::from(rendezvous));
        assert!(to_phone.try_recv().is_err());
        assert!(r.splice_stream_cell(&r_state, &opaque, transport));
        let (_, frame) = to_middle.try_recv().unwrap();
        let body = &frame[veil_proto::HEADER_SIZE..];
        let second = CircuitDataPayload::decode(body).unwrap();
        assert!(second.seq > first.seq);
        m.dispatch_relay_chain(&hdr, body, NodeId::from(rendezvous));
        let (_, delivered) = to_phone.try_recv().unwrap();
        let cell = CircuitDataPayload::decode(&delivered[veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!((cell.circuit_id, cell.seq), (11, second.seq));
        let mut opened = cell.ciphertext;
        apply_layers(
            &[[1; 32], [2; 32]],
            Direction::Return,
            cell.seq,
            &mut opened,
        )
        .unwrap();
        assert_eq!(read_payload(&opened).unwrap(), opaque);
        tx.write().unwrap().unregister(&phone);

        // Join ONLY same-host mappings and stable wire fields, not timestamps.
        let r_log = std::fs::read_to_string(dir.join("r.log")).unwrap();
        let m_log = std::fs::read_to_string(dir.join("m.log")).unwrap();
        let trace: Vec<_> = r_log
            .lines()
            .chain(m_log.lines())
            .filter(|l| l.contains("anonymity.circuit.trace."))
            .collect();
        let seq = index as u32 * 2 + 1;
        assert!(trace.iter().any(|l| l.contains("trace.splice")
            && l.contains(&format!("token={}", source.token))
            && l.contains(&format!("out_cid=33 seq={seq} "))));
        assert!(trace.iter().any(|l| l.contains("trace.return")
            && l.contains(&format!("in_cid=33 out_cid=11 seq={seq} accepted=false"))));
        assert!(trace.iter().any(|l| l.contains("trace.egress")
            && l.contains(&format!("out_cid=11 seq={seq} result=Err(Missing)"))));
        assert!(trace.iter().any(|l| l.contains("trace.egress")
            && l.contains(&format!("out_cid=11 seq={} result=Ok(())", seq + 1))));
        for line in trace {
            assert!(!line.contains("selected synthetic"));
            assert!(!line.contains(&"07".repeat(32)));
            assert!(!line.contains(&"05".repeat(32)));
            assert!(!line.contains(&"2a".repeat(32)));
        }
    }
}
