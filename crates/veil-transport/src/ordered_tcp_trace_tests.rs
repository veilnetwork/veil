//! Join actual ordered writers to their TCP handshake/socket observations.
//! This tests transport observability, not OVL1 identity authorization.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{Transport, TransportContext, TransportUri, obfs4_tcp::Obfs4TcpTransport};

static EVENTS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
struct Sink;
impl log::Log for Sink {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        EVENTS
            .lock()
            .unwrap()
            .push((record.target().to_owned(), record.args().to_string()));
    }
    fn flush(&self) {}
}
static SINK: Sink = Sink;

fn field(row: &str, key: &str) -> u64 {
    row.split_whitespace()
        .find_map(|v| v.strip_prefix(key))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn ordered_writer_links_real_socket_without_exposing_plaintext() {
    const CHILD: &str = "VEIL_TEST_ORDERED_TCP_BINDING";
    if let Ok(expected) = std::env::var(CHILD) {
        log::set_logger(&SINK).unwrap();
        log::set_max_level(log::LevelFilter::Info);
        let rt = std::env::var("VEIL_RT_TRACE").as_deref() == Ok("1");
        let records = std::env::var("VEIL_DIAG_ORDERED_RECORDS").as_deref() == Ok("1");
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                let mut context = TransportContext::for_debug().unwrap();
                context.obfs4_psk = Some(Arc::new([0x47; 32]));
                let context = Arc::new(context);
                let listener = Obfs4TcpTransport.bind(&TransportUri::Obfs4Tcp {
                    host: "127.0.0.1".into(), port: 0,
                }, context.clone()).await.unwrap();
                let port = listener.local_addr().rsplit(':').next().unwrap().parse().unwrap();
                let uri = TransportUri::Obfs4Tcp { host: "127.0.0.1".into(), port };
                let mut planes = Vec::new();
                let mut expected_bindings = Vec::new();
                for _ in 0..2 {
                    let (client, server) = tokio::join!(
                        Obfs4TcpTransport.connect(&uri, context.clone()), listener.accept());
                    let (client, server) = (client.unwrap(), server.unwrap());
                    let client_port = client.peer_meta().local_addr.unwrap().port();
                    let a = crate::ordered_records::OrderedRecordPlane::new(client.into_stream().unwrap());
                    let b = crate::ordered_records::OrderedRecordPlane::new(server.into_stream().unwrap());
                    let child = a.handle().local_trace_id();
                    assert_eq!(child != 0, records);
                    // Two records on the same plane must not produce two bindings.
                    for payload in [b"PRIVATE_ORDERED_ONE".as_slice(), b"PRIVATE_ORDERED_TWO"] {
                        a.handle().send(payload).unwrap();
                        assert_eq!(b.handle().recv().await.unwrap(), payload);
                    }
                    expected_bindings.push((child, client_port));
                    planes.push((a, b));
                }
                // Plain writes in the caller's task must not inherit an idle
                // record writer's context or get classified as that child.
                let (client, server) = tokio::join!(
                    Obfs4TcpTransport.connect(&uri, context.clone()), listener.accept());
                let mut client = client.unwrap().into_stream().unwrap();
                let mut server = server.unwrap().into_stream().unwrap();
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                client.write_all(b"PRIVATE_ORDERED_UNSCOPED").await.unwrap();
                client.flush().await.unwrap();
                let mut received = [0; 24];
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"PRIVATE_ORDERED_UNSCOPED");
                let rows = EVENTS.lock().unwrap().clone();
                let bindings: Vec<_> = rows.iter().filter(|(target, _)| target == "transport.tcp_trace.ordered_child").collect();
                assert_eq!(bindings.len(), if expected == "linked" { 2 } else { 0 },
                    "each physical writer needs one binding only when both operator gates are on");
                let mut connections = std::collections::HashSet::new();
                for (child, client_port) in expected_bindings {
                    if !rt || !records { continue; }
                    let matching: Vec<_> = bindings.iter().filter(|(_, text)| field(text, "child_local=") == child).collect();
                    assert_eq!(matching.len(), 1);
                    let row = &matching[0].1;
                    let connection = field(row, "connection=");
                    assert!(connections.insert(connection));
                    assert!(row.contains(&format!("local_port: {client_port},")));
                    // The writer ID is the actual handshake's ID, not a second
                    // counter guessed to be the same from timing or port alone.
                    let handshake: Vec<_> = rows.iter().filter(|(_, text)|
                        text.contains("tcp_handshake ") && text.contains("side=Client outcome=complete ") &&
                        text.contains(&format!("local_port: {client_port},"))).collect();
                    assert_eq!(handshake.len(), 1);
                    assert_eq!(field(&handshake[0].1, "connection="), connection);
                }
                assert!(rows.iter().all(|(_, text)| !text.contains("PRIVATE_ORDERED_")));
                for (_, text) in bindings {
                    assert!(!text.contains("127.0.0.1"));
                    assert!(!text.contains("record_sha256"));
                    assert!(!text.contains("priority"));
                }
                drop(planes);
            }).await.unwrap();
        });
        return;
    }
    for (rt, records, expected) in [
        (None, None, "off"),
        (Some("1"), Some("0"), "off"),
        (Some("0"), Some("1"), "off"),
        (Some("1"), Some("1"), "linked"),
        (Some("true"), Some("true"), "off"),
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "tcp_trace::ordered_binding_tests::ordered_writer_links_real_socket_without_exposing_plaintext", "--nocapture"])
            .env(CHILD, expected).env_remove("VEIL_RT_TRACE").env_remove("VEIL_DIAG_ORDERED_RECORDS");
        if let Some(value) = rt {
            command.env("VEIL_RT_TRACE", value);
        }
        if let Some(value) = records {
            command.env("VEIL_DIAG_ORDERED_RECORDS", value);
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("running 1 test")
                && stdout.contains("1 passed; 0 failed"),
            "{}{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
